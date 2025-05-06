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

use tyst::Tyst;
use upkit_common::util::testing::*;
use upkit_common::x509::cert::parse::CertificateParser;
use upkit_common::x509::cert::types::IdentityFragment;
use upkit_common::x509::cert::types::WellKnownAttribute;
use upkit_common::x509::cert::types::WellKnownGeneralName;
use upkit_leafops::enprov::CertificateEnrollmentOptions;
use upkit_leafops::enprov::CertificateEnrollmentProvider;
use upkit_leafops::enprov::EnrollmentProvider;

#[test]
fn test_self_signed_provider() {
    initialize_env_logger();
    let options = CertificateEnrollmentOptions {
        provider: "self_signed".to_string(),
        template: "server".to_string(),
        credentials: None,
        identity: vec![
            IdentityFragment {
                name: WellKnownAttribute::CommonName.as_name(),
                value: "www.example.org".to_string(),
            },
            IdentityFragment {
                name: WellKnownGeneralName::DnsName.as_name(),
                value: "www.example.org".to_string(),
            },
        ],
        service: None,
        trust: None,
    };
    log::debug!("options: {options}");
    // ML-DSA-44: 2.16.840.1.101.3.4.17
    let signing_algorithm_oid = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
    let mut se = Tyst::instance()
        .ses()
        .by_oid(&tyst::encdec::oid::as_string(signing_algorithm_oid))
        .unwrap();
    let (public_key, private_key) = se.generate_key_pair();
    let enrollment_provider = CertificateEnrollmentProvider::with_options(&options);
    let encoded_certificate_chain = enrollment_provider.enroll_from_key_pair(
        signing_algorithm_oid,
        public_key.as_ref(),
        private_key.as_ref(),
    );
    let encoded_certificate = encoded_certificate_chain.first().unwrap();
    let certificate = CertificateParser::from_bytes(&encoded_certificate).unwrap();
    log::debug!("Enrolled for self-signed certificate.");
    log::debug!(
        "  Subject:      {}",
        serde_json::to_string(&certificate.get_subject().unwrap()).unwrap()
    );
    log::debug!(
        "  Issuer:       {}",
        serde_json::to_string(&certificate.get_issuer().unwrap()).unwrap()
    );
    log::debug!("  SerialNumber: {:x?}", certificate.get_serial_number());
}
