/*
    Copyright 2025 MydriaTech AB

    Licensed under the Apache License 2.0 with Free world makers exception
    1.0.0 (the "License"); you may not use this file except in compliance with
    the License. You should have obtained a copy of the License with the source
    or binary distribution in file named

        LICENSE-Apache-2.0-with-FWM-Exception-1.0.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

//! Certificate chain revocation status monitoring.

use crossbeam_skiplist::SkipMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use upkit_common::x509::cert::parse::CertificateParser;
use upkit_common::x509::crl::parse::CrlParser;
use upkit_common::x509::crl::validate::CertificateCrlValidator;
use upkit_common::x509::ocsp::build::OcspRequest;
use upkit_common::x509::ocsp::parse::OcspResponseParser;
use upkit_common::x509::ocsp::validate::CertificateOcspValidator;
use upkit_http_client::HttpClient;
use upkit_http_client::HttpClientErrorKind;

/// Cached revocation status for a certificate
pub enum MonitoredRevocationInfo {
    /// Revocation status should have been available, but is missing.
    Missing,
    /// No known revocation status checking method was defined in this
    /// certificate.
    NotDefinedInCertificate,
    /// Revocation status from this certificate is available as a CRL.
    Crl {
        /// DER encoded Certificate Revocation List (CRL).
        encoded: Vec<u8>,
    },
    /// Revocation status from this certificate is available as an OCSP response.
    OcspResponse {
        /// DER encoded OCSP response.
        encoded: Vec<u8>,
    },
}

/// Wraps a certificate chain and monitores each certificates revocation status
/// using either OCSP or CRLs.
pub struct MonitoredChain {
    #[doc(hidden)]
    parsed_certificate_chain: Vec<CertificateParser>,
    #[doc(hidden)]
    encoded_certificate_chain: Vec<Vec<u8>>,
    #[doc(hidden)]
    track_certificate_status: AtomicBool,
    #[doc(hidden)]
    encoded_crl_by_fp: SkipMap<String, Vec<u8>>,
    #[doc(hidden)]
    encoded_ocsp_by_fp: SkipMap<String, Vec<u8>>,
    #[doc(hidden)]
    supported_message_digest_oid: Vec<u32>,
    #[doc(hidden)]
    http_client: HttpClient,
}

impl MonitoredChain {
    /// Return a new instance from the provided encoded certificate chain.
    ///
    /// Invoke [Self::track_chain_status()] to start monitoring status.
    pub fn new(
        encoded_certificate_chain: Vec<Vec<u8>>,
        supported_message_digest_oid: &[u32],
    ) -> Arc<Self> {
        let parsed_certificate_chain = encoded_certificate_chain
            .iter()
            .map(|encoded_certificate| CertificateParser::from_bytes(encoded_certificate).unwrap())
            .collect::<Vec<_>>();
        Arc::new(Self {
            parsed_certificate_chain,
            encoded_certificate_chain,
            track_certificate_status: AtomicBool::new(false),
            encoded_crl_by_fp: SkipMap::default(),
            encoded_ocsp_by_fp: SkipMap::default(),
            supported_message_digest_oid: supported_message_digest_oid.to_vec(),
            http_client: HttpClient::new(),
        })
    }

    /// Return a reference to the encoded version of the monitored chain.
    pub fn get_encoded_certificate_chain(self: &Arc<Self>) -> &[Vec<u8>] {
        &self.encoded_certificate_chain
    }

    /// Return a reference to the parsed version of the monitored chain.
    pub fn get_parsed_certificate_chain(self: &Arc<Self>) -> &[CertificateParser] {
        &self.parsed_certificate_chain
    }

    /// Return revocation info for a certificate in the monitored chain.
    pub fn get_revocation_info(
        self: &Arc<Self>,
        certificate_fingerprint: &str,
    ) -> MonitoredRevocationInfo {
        let ocsp_repsonse = self
            .encoded_ocsp_by_fp
            .get(certificate_fingerprint)
            .map(|entry| entry.value().to_vec());
        let crl = self
            .encoded_crl_by_fp
            .get(certificate_fingerprint)
            .map(|entry| entry.value().to_vec());
        if ocsp_repsonse.as_ref().is_some_and(|value| value.is_empty())
            && crl.as_ref().is_some_and(|value| value.is_empty())
        {
            return MonitoredRevocationInfo::NotDefinedInCertificate;
        }
        if ocsp_repsonse
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        {
            return MonitoredRevocationInfo::OcspResponse {
                encoded: ocsp_repsonse.unwrap().to_vec(),
            };
        }
        if crl.as_ref().is_some_and(|value| !value.is_empty()) {
            return MonitoredRevocationInfo::Crl {
                encoded: crl.unwrap().to_vec(),
            };
        }
        // Revocation info was defined in cert, but none was available at this time.
        MonitoredRevocationInfo::Missing
    }

    /// Start tracking revocation status of the certificates in this chain.
    pub async fn track_chain_status(self: Arc<Self>, min_query_interval_seconds: u64) -> Arc<Self> {
        if !self
            .track_certificate_status
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            let mut reversed_chain = self.parsed_certificate_chain.clone();
            reversed_chain.reverse();
            // Tracking was not enabled before. Start doing it!
            let mut issuer = None;
            for cp in &reversed_chain {
                let self_clone = Arc::clone(&self);
                let cp_clone = cp.clone();
                let issuer_clone = issuer.unwrap_or(cp).clone();
                tokio::spawn(async move {
                    self_clone
                        .track_certificate_status(
                            &cp_clone,
                            &issuer_clone,
                            min_query_interval_seconds,
                        )
                        .await;
                })
                .await
                .unwrap();
                issuer = Some(cp);
            }
            // Wait for revocation status to not be "Missing" for each cert (undefined is fine)
            for cp in &reversed_chain {
                while let MonitoredRevocationInfo::Missing =
                    self.get_revocation_info(cp.fingerprint())
                {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                }
            }
        }
        self
    }

    /// Stop tracking of certificate status
    pub fn stop_tracking(self: &Arc<Self>) {
        self.track_certificate_status
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Track status of a specific certificate.
    async fn track_certificate_status(
        self: &Arc<Self>,
        cp: &CertificateParser,
        issuer: &CertificateParser,
        min_query_interval_seconds: u64,
    ) {
        let ocsp_uri = cp.get_authority_information_access_ocsp_uri();
        let cdp = cp.get_crl_distribution_point();
        let fp = cp.fingerprint();
        if ocsp_uri.is_none() {
            self.encoded_ocsp_by_fp.insert(fp.to_owned(), vec![]);
        } else {
            // Spawn OCSP update checker
            let cert_clone = cp.clone();
            let issuer_clone = issuer.clone();
            let self_clone = Arc::clone(self);
            tokio::spawn(async move {
                self_clone
                    .update_checker_ocsp(&cert_clone, &issuer_clone, min_query_interval_seconds)
                    .await;
            })
            .await
            .unwrap();
        }
        if cdp.is_none() {
            self.encoded_crl_by_fp.insert(fp.to_owned(), vec![]);
            if ocsp_uri.is_none() {
                log::debug!(
                    "No revocation info is available for certificate with fingerprint '{fp}'"
                );
                return;
            }
        }
        // Always keep a fresh CRL for redundancy if OCSP goes down.
        self.update_checker_crl(cp, issuer, min_query_interval_seconds)
            .await;
    }

    /// Track revocation status of a specific certificate using OCSP.
    async fn update_checker_ocsp(
        self: &Arc<Self>,
        cert: &CertificateParser,
        issuer: &CertificateParser,
        min_query_interval_seconds: u64,
    ) {
        while self
            .track_certificate_status
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            // Get OCSP URL
            if let Some(ocsp_uri) = cert.get_authority_information_access_ocsp_uri() {
                let encoded_ocsp_response = self.make_ocsp_request(&ocsp_uri, cert, issuer, true);
                if let Some(encoded_ocsp_response) = encoded_ocsp_response {
                    match OcspResponseParser::from_bytes(&encoded_ocsp_response) {
                        Ok(ocsp_response) => {
                            if let Err(e) =
                                CertificateOcspValidator::validate_issuance(issuer, &ocsp_response)
                            {
                                log::warn!("Failed to parse OCSP response: {e:?}");
                            } else {
                                // Almost there.. check that the OCSP response contains info for the leaf and that it is valid for the entire interval
                                if let Some(single_response) = ocsp_response
                                    .get_single_response_by_serial_number(
                                        &cert.get_encoded_issuer(),
                                        &cert.get_serial_number(),
                                    )
                                {
                                    if let Some(next_update) = single_response.get_next_update() {
                                        let now = upkit_common::util::time::now_epoch_micros();
                                        if now + min_query_interval_seconds * 2 < next_update {
                                            // Confirmed that we have an OCSP response we can cache
                                            self.encoded_ocsp_by_fp.insert(
                                                cert.fingerprint().to_owned(),
                                                encoded_ocsp_response,
                                            );
                                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                                next_update - now,
                                            ))
                                            .await;
                                            continue;
                                        } else {
                                            log::warn!("OCSP response does not live long enough. Will not cache this.");
                                        }
                                    } else {
                                        log::warn!("OCSP response is missing nextUpdate which means that newer updates are available all the time. Will not cache this.");
                                    }
                                } else {
                                    log::warn!(
                                        "OCSP response was not for the current leaf certificate."
                                    );
                                }
                            }
                        }
                        Err(e) => log::warn!("Failed to parse OCSP response: {e:?}"),
                    }
                }
                // The current one might still be good for some time
                if let Some(Ok(current)) = self
                    .encoded_ocsp_by_fp
                    .get(cert.fingerprint())
                    .map(|entry| OcspResponseParser::from_bytes(entry.value()))
                {
                    if let Some(single_response) = current.get_single_response_by_serial_number(
                        &cert.get_encoded_issuer(),
                        &cert.get_serial_number(),
                    ) {
                        let next_update = single_response.get_next_update().unwrap();
                        let now = upkit_common::util::time::now_epoch_micros();
                        if now + 4 < next_update {
                            // There is still some validity left, give it another chance
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                (next_update - now) / 2,
                            ))
                            .await;
                            continue;
                        }
                    }
                }
                // Remove any existing
                self.encoded_ocsp_by_fp.remove(cert.fingerprint());
                // Wait 60 seconds before retrying after failure (trade-off: hammer OCSP vs quick recovery after outage)
                tokio::time::sleep(tokio::time::Duration::from_millis(60_000)).await;
            }
        }
    }

    /// Query the specified OCSP responder to get the `cert` revocation status.
    fn make_ocsp_request(
        &self,
        ocsp_uri: &str,
        cert: &CertificateParser,
        issuer: &CertificateParser,
        include_nonce: bool,
    ) -> Option<Vec<u8>> {
        log::debug!("Will query OCSP responder '{ocsp_uri}'.");
        let ocsp_request = OcspRequest::new(
            cert,
            issuer,
            &self.supported_message_digest_oid,
            include_nonce,
        );
        let encoded_ocsp_request = ocsp_request.as_bytes();
        if !include_nonce {
            // Query OCSP responder using HTTP GET first.
            match self.http_client.ocsp_get(ocsp_uri, encoded_ocsp_request) {
                Ok(encoded_ocsp_response) => return Some(encoded_ocsp_response),
                Err(e) => match e.kind() {
                    HttpClientErrorKind::TooLargeForHttpGet => {
                        log::debug!("Request is not suitable for OCSP GET (will try POST): {e:?}");
                    }
                    _other => {
                        log::debug!(
                            "Failed to query OCSP responder using HTTP GET (will try POST): {e:?}"
                        );
                    }
                },
            }
        }
        self.http_client
            .ocsp_post(ocsp_uri, encoded_ocsp_request)
            .map_err(|e| {
                log::warn!("Failed to query OCSP responder '{ocsp_uri}': {e:?}");
            })
            .ok()
    }

    /// Track revocation status of a specific certificate using CRL.
    async fn update_checker_crl(
        self: &Arc<Self>,
        cert: &CertificateParser,
        issuer: &CertificateParser,
        min_query_interval_seconds: u64,
    ) {
        if let Some(cdp) = cert.get_crl_distribution_point() {
            let mut crl_number = None;
            let mut last_update = 0;
            while self
                .track_certificate_status
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                let encoded_crl = self.http_client.crl_download(&cdp).unwrap();
                // Parse CRL
                let crl = CrlParser::from_bytes(&encoded_crl).unwrap();
                // Validate that CRL was signed by the issuer
                if let Err(e) = CertificateCrlValidator::validate_crl_issuance(
                    issuer,
                    Some(cdp.to_owned()),
                    &crl,
                ) {
                    log::info!("Certificate validation using CRL failed: {e:?}");
                    // Try again every after 10 minutes
                    tokio::time::sleep(tokio::time::Duration::from_secs(10 * 60)).await;
                } else {
                    if last_update > crl.get_this_update() {
                        // Not a newer CRL! Retry again when we are allowed to.
                    }
                    if let Some(crl_number_new) = crl.get_crl_number() {
                        if crl_number
                            .as_ref()
                            .is_none_or(|crl_number| crl_number < &crl_number_new)
                        {
                            // Confirmed that we have a newer CRL
                            self.encoded_crl_by_fp
                                .insert(cert.fingerprint().to_owned(), encoded_crl);
                            last_update = crl.get_this_update();
                            crl_number = Some(crl_number_new);
                            log::debug!(
                                "New CRL #{} retrieved for certificate with fingerprint '{}'.",
                                crl_number.as_ref().unwrap(),
                                cert.fingerprint()
                            );
                        } else {
                            // Not a newer CRL! Retry again when we are allowed to.
                        }
                    }
                    // Load the latest CRL
                    let crl = CrlParser::from_bytes(
                        &self
                            .encoded_crl_by_fp
                            .get(cert.fingerprint())
                            .map(|entry| entry.value().clone())
                            .unwrap(),
                    )
                    .unwrap();
                    if let Some(next_update) = crl.get_next_update() {
                        let this_update = crl.get_this_update();
                        let next_update = std::cmp::max(next_update, this_update);
                        let duration = next_update - this_update;
                        let now = upkit_common::util::time::now_epoch_micros();
                        // Start by checking after 1/2 time, then 3/4 time, then 7/8 etc..
                        let mut x = duration;
                        while x >= min_query_interval_seconds && next_update - x < now {
                            x /= 2;
                        }
                        let time_of_next_check = std::cmp::max(next_update - x, now);
                        let time_to_next_check_seconds = time_of_next_check - now;
                        log::debug!("Will sleep {time_to_next_check_seconds} seconds before attempting next CRL download.");
                        tokio::time::sleep(tokio::time::Duration::from_secs(
                            time_to_next_check_seconds,
                        ))
                        .await;
                    } else {
                        // Fallback to checking every 30 minutes
                        tokio::time::sleep(tokio::time::Duration::from_secs(30 * 60)).await;
                    }
                }
                // todo if expiration is before `min_query_interval_seconds`
                //      warn + remove any existing from cache
                // todo: else update local cache
                tokio::time::sleep(tokio::time::Duration::from_millis(10_000)).await;
            }
        }
    }

    /// Wait for leaf certificate to expire or any certificate in the monitored
    /// chain to be revoked.
    ///
    /// Since an issued certificate cannot be valid longer than the issuer, it
    /// is sufficient to monitor the leaf for expiration.
    pub async fn await_leaf_expiration_or_chain_revocation(
        self: &Arc<Self>,
        expiration_margin_seconds: u64,
    ) {
        let self_clone1 = Arc::clone(self);
        let self_clone2 = Arc::clone(self);
        tokio::select! {
            _ = async move {
                //  Return when it is time to renew leaf certificate
                let signing_cert = self_clone1.parsed_certificate_chain.first().unwrap();
                let validity = signing_cert.get_validity();
                let now_seconds = upkit_common::util::time::now_epoch_seconds();
                // If private key usage period is in use this has priority.
                let not_after = signing_cert.get_private_key_usage_period().and_then(|pkup|pkup.get_not_after()).unwrap_or(validity.get_not_after());
                if now_seconds > not_after-expiration_margin_seconds {
                    log::debug!("Certificate will be unusable for signing within {expiration_margin_seconds} seconds.");
                    return;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(not_after - now_seconds - expiration_margin_seconds)).await;
                log::debug!("Certificate will be unusable for signing within {expiration_margin_seconds} seconds. (Wake-up.)");
            } => {},
            _ = async move {
                //  Return if any of the certificates in the TS siging chain has been revoked.
                let mut chain = self_clone2.parsed_certificate_chain.clone();
                chain.reverse();
                let mut all_ok = true;
                while all_ok {
                    let mut previous = None;
                    for cp in &chain {
                        match self_clone2.get_revocation_info(cp.fingerprint()) {
                            MonitoredRevocationInfo::OcspResponse { encoded } => {
                                log::debug!("Checking revocation status of cert using cached OCSP response.");
                                let ocsp_response = OcspResponseParser::from_bytes(&encoded).unwrap();
                                let issuer = previous.unwrap_or(cp);
                                let leaf = cp;
                                match CertificateOcspValidator::validate(issuer, leaf, &ocsp_response, upkit_common::util::time::now_epoch_micros()) {
                                    Ok(Some(reason)) => {
                                        log::debug!("Detected revoked certificate. reason: {reason:?}");
                                        all_ok = false;
                                    },
                                    Ok(None) => {},
                                    Err(e) => {
                                        log::info!("OCSP based certificate validation failed: {e:?}");
                                        all_ok = false;
                                    }
                                }
                            },
                            MonitoredRevocationInfo::Crl { encoded } => {
                                log::debug!("Checking revocation status of cert using cached CRL.");
                                let crl = CrlParser::from_bytes(&encoded).unwrap();
                                let issuer = previous.unwrap_or(cp);
                                let leaf = cp;
                                //let _serno = cp.get_serial_number();
                                match CertificateCrlValidator::validate(issuer, leaf, &crl, upkit_common::util::time::now_epoch_micros()) {
                                    Ok(Some(reason)) => {
                                        log::debug!("Detected revoked certificate. reason: {reason:?}");
                                        all_ok = false;
                                    },
                                    Ok(None) => {},
                                    Err(e) => {
                                        log::info!("CRL based certificate validation failed: {e:?}");
                                        all_ok = false;
                                    }
                                }
                            },
                            _other => {}
                        }
                        previous = Some(cp);
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(10_000)).await;
                }
            } => {},
        }
    }
}
