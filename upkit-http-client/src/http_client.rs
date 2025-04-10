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

//! HTTP client for PKI leaf operations.

mod http_client_error;

pub use http_client_error::HttpClientError;
pub use http_client_error::HttpClientErrorKind;
use std::time::Duration;

/// HTTP client abstraction for PKI leaf operations.
pub struct HttpClient {
    agent: ureq::Agent,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient {
    /// Return a new instance.
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(5)))
                .build()
                .into(),
        }
    }

    /// Download a CRL from the provided CDP.
    ///
    /// NOTE: Ensure that URL comes from a trusted source. For example,
    /// validate the certificate is issued by trusted and uncompromised issuer
    /// before using any URLs in the certificate.
    pub fn crl_download(&self, cdp: &str) -> Result<Vec<u8>, HttpClientError> {
        if log::log_enabled!(log::Level::Debug) {
            log::debug!("Initializing download of CRL from '{cdp}'.");
        }
        self.http_get(cdp)
    }

    /// Perform OCSP GET request
    /// ([RFC 5019](https://www.rfc-editor.org/rfc/rfc5019)).
    pub fn ocsp_get(
        &self,
        ocsp_url: &str,
        ocsp_request: &[u8],
    ) -> Result<Vec<u8>, HttpClientError> {
        // https://www.rfc-editor.org/rfc/rfc6960.html#appendix-A.1
        // GET {url}/{url-encoding of base-64 encoding of the DER encoding of the OCSPRequest}
        let ocsp_request_b64 = tyst::encdec::base64::encode_url(ocsp_request, true);
        let ocsp_url_with_request = if ocsp_url.ends_with('/') {
            format!("{ocsp_url}{ocsp_request_b64}")
        } else {
            format!("{ocsp_url}/{ocsp_request_b64}")
        };
        // https://www.rfc-editor.org/rfc/rfc5019#section-5 -> max 255 bytes
        if ocsp_url_with_request.len() > 255 {
            Err(HttpClientErrorKind::TooLargeForHttpGet.error_with_msg(&format!("Request of {} bytes is too large for OCSP GET. (The whole url has a 255 byte limit.)", ocsp_url_with_request.len())))?
        }
        self.http_get(&ocsp_url_with_request)
        // The main purpose of the HTTP cache headers for OCSP GET is to allow a
        // rather simple web cache in front of the OCSP responsder to behave
        // in a useful way.. we don't really trust them and should check the
        // content of the signed response instead...
    }

    /// Perform OCSP POST request
    /// ([RFC 6960](https://www.rfc-editor.org/rfc/rfc6960#appendix-A.1)).
    ///
    /// NOTE: Ensure that URL comes from a trusted source. For example,
    /// validate the certificate is issued by trusted and uncompromised issuer
    /// before using any URLs in the certificate.
    pub fn ocsp_post(
        &self,
        ocsp_url: &str,
        ocsp_request: &[u8],
    ) -> Result<Vec<u8>, HttpClientError> {
        self.http_post(ocsp_url, "application/ocsp-request", ocsp_request)
    }

    /// Perform HTTP GET request on the target URL.
    fn http_get(&self, url: &str) -> Result<Vec<u8>, HttpClientError> {
        self.agent
            .get(url)
            .call()
            .map_err(|e| HttpClientErrorKind::Failure.error_with_msg(&format!("{e:?}")))
            .and_then(Self::assert_response_success)?
            .body_mut()
            .read_to_vec()
            .map_err(|e| HttpClientErrorKind::Failure.error_with_msg(&format!("{e:?}")))
    }

    /// Perform HTTP POST request on the target URL.
    fn http_post(
        &self,
        url: &str,
        content_type: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, HttpClientError> {
        self.agent
            .post(url)
            .content_type(content_type)
            //.header("Authorization", "example-token")
            .send(data)
            .map_err(|e| HttpClientErrorKind::Failure.error_with_msg(&format!("{e:?}")))
            .and_then(Self::assert_response_success)?
            .body_mut()
            .read_to_vec()
            .map_err(|e| HttpClientErrorKind::Failure.error_with_msg(&format!("{e:?}")))
    }

    /// Assert that HTTP response code is in the 200-299 interval and error out
    /// with [HttpClientErrorKind::HttpErrorCode] otherwise.
    fn assert_response_success(
        response: ureq::http::Response<ureq::Body>,
    ) -> Result<ureq::http::Response<ureq::Body>, HttpClientError> {
        let status = response.status();
        if !status.is_success() {
            let status_code = status.as_u16();
            Err(HttpClientErrorKind::HttpErrorCode(status_code)
                .error_with_msg(&format!("HTTP GET failed with status code {status_code}.")))?
        }
        Ok(response)
    }
}
