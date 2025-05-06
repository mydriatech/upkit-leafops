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

//! [EnrollmentProvider] using the CMP protocol.

use std::sync::Arc;
use tyst::traits::se::PrivateKey;
use tyst::traits::se::PublicKey;
use upkit_common::x509::cert::types::WellKnownAttribute;
use upkit_common::x509::cert::validate::CertificatePathValidator;
use upkit_common::x509::cmp::build::PkiMessage;
use upkit_common::x509::cmp::types::InitializationRequest;
use upkit_common::x509::cmp::types::PkiBody;
use upkit_enprov::CertificateEnrollmentOptions;
use upkit_enprov::EnrollmentConnection;
use upkit_enprov::EnrollmentCredentials;
use upkit_enprov::EnrollmentProvider;

/** [EnrollmentProvider] using the Certificate Management Protocol (CMP)
protocol.

This implementation will use CMP's InitializationRequest protected by a shared
secret with PBMAC1.
*/
pub struct CmpProvider {
    options: CertificateEnrollmentOptions,
}

impl CmpProvider {
    fn cmp_over_http(
        endpoint_url: &str,
        pki_message: &PkiMessage,
    ) -> Result<PkiMessage, Box<dyn std::error::Error>> {
        log::trace!(
            "request pki_message: {}",
            tyst::encdec::base64::encode(&pki_message.as_bytes())
        );
        Ok(ureq::post(endpoint_url)
            .content_type("application/pkixcmp")
            .send(pki_message.as_bytes())?
            .body_mut()
            .read_to_vec()
            .map(|encoded_pki_message| {
                log::trace!(
                    "response pki_message: {}",
                    tyst::encdec::base64::encode(&encoded_pki_message)
                );
                PkiMessage::from_bytes(&encoded_pki_message)
            })?)
    }
}

impl EnrollmentProvider for CmpProvider {
    fn with_options(options: &CertificateEnrollmentOptions) -> Arc<Self> {
        Arc::new(Self {
            options: options.to_owned(),
        })
    }

    fn enroll_from_key_pair(
        &self,
        signing_algorithm_oid: &[u32],
        public_key: &dyn PublicKey,
        private_key: &dyn PrivateKey,
    ) -> Vec<Vec<u8>> {
        log::debug!("Enrolling for a new certificate using CMP provider.");
        let (dn, sans) = upkit_common::x509::cert::build::util::split_by_identity_fragment_type(
            &self.options.identity,
        );
        let endpoint_base_url;
        if let Some(EnrollmentConnection::BaseUrl { base_url }) = &self.options.service {
            endpoint_base_url = base_url.to_owned();
        } else {
            log::warn!("No base URL provided. Unable to connect to service.");
            return vec![];
        }
        let shared_secret;
        if let Some(EnrollmentCredentials::SharedSecret { secret }) = &self.options.credentials {
            shared_secret = secret;
        } else {
            log::warn!("No shared secret provided. Unable to authenticate request.");
            return vec![];
        }
        let cn = dn
            .rnds()
            .iter()
            .find_map(|rdn| {
                rdn.iter().find_map(|idf| {
                    if idf.name.eq(&WellKnownAttribute::CommonName.as_name()) {
                        Some(idf.value.to_owned())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or("upkit-leafops CMP client".to_string());
        let request = PkiMessage::with_shared_secret(
            InitializationRequest::new(
                public_key,
                None,
                dn,
                &sans,
                // Let the CA decide EKUs
                &[],
            )
            .sign_pop(signing_algorithm_oid, private_key)
            .to_pki_body(),
            &cn,
            None,
            shared_secret.as_bytes(),
        );
        let endpoint_url = format!("{endpoint_base_url}/{}", self.options.template);
        match Self::cmp_over_http(&endpoint_url, &request) {
            Ok(response) => {
                if let Err(e) = response.validate_response_nonce(&request) {
                    log::warn!("{e}");
                    return vec![];
                }
                match response.get_pki_body() {
                    Ok(PkiBody::Ip(initialization_response)) => {
                        if let Err(e) =
                            response.validate_with_shared_secret(shared_secret.as_bytes())
                        {
                            log::warn!("{e}");
                            return vec![];
                        }
                        // Extract certs
                        let mut bag_of_certs =
                            vec![initialization_response.get_certificate().to_owned()];
                        initialization_response
                            .get_ca_certificates()
                            .iter()
                            .for_each(|ca_cert| bag_of_certs.push(ca_cert.to_owned()));
                        let chain = CertificatePathValidator::get_ordered_chain_from_bag_of_certs(
                            &bag_of_certs,
                        )
                        .unwrap();
                        return chain
                            .iter()
                            .map(|cp| cp.to_bytes().unwrap())
                            .collect::<Vec<_>>();
                    }
                    Ok(PkiBody::Error(error_message)) => {
                        log::warn!("CMP protocol error: {error_message}");
                    }
                    Ok(_other) => {
                        log::warn!(
                            "Unexpected PKIBody response with tag {}",
                            response.get_pki_body_tag()
                        );
                    }
                    Err(e) => {
                        log::warn!("CMP processing error: {e}");
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed CMP protocol request: {e}");
            }
        }
        vec![]
    }
}
