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

//! [EnrollmentProvider] that can create a self-signed certificate for testing.

use tyst::traits::se::PrivateKey;
use tyst::traits::se::PublicKey;
use tyst::Tyst;
use upkit_common::x509::cert::build::NoSignatureTbsCertificate;
use upkit_common::x509::cert::extensions::BasicConstraints;
use upkit_common::x509::cert::extensions::ExtendedKeyUsage;
use upkit_common::x509::cert::extensions::Extensions;
use upkit_common::x509::cert::extensions::KeyUsage;
use upkit_enprov::CertificateEnrollmentOptions;
use upkit_enprov::EnrollmentProvider;

/// [EnrollmentProvider] that can create a self-signed certificate for testing.
#[derive(Default)]
pub struct SelfSignedProvider {}

impl EnrollmentProvider for SelfSignedProvider {
    fn enroll_from_key_pair(
        &self,
        signing_algorithm_oid: &[u32],
        public_key: &dyn PublicKey,
        private_key: &dyn PrivateKey,
        options: &CertificateEnrollmentOptions,
    ) -> Vec<Vec<u8>> {
        log::info!("Enrolling for a new certificate using self-signed provider.");
        let sing_algo_oid_str = tyst::encdec::oid::as_string(signing_algorithm_oid);
        let mut se = Tyst::instance().ses().by_oid(&sing_algo_oid_str).unwrap();
        let (subject, an) = upkit_common::x509::cert::build::util::split_by_identity_fragment_type(
            &options.identity,
        );
        let mut extensions = Extensions::default();
        extensions.add_subject_alternative_name(&an, subject.is_empty());
        // Self-signed: issuer = subject
        extensions.add_issuer_alternative_name(&an);
        match options.template.as_str() {
            "timestamping" => {
                log::debug!("Using demo template 'timestamping'. ExtendedKeyUsage::PkixTimeStamping will be added.");
                extensions.add_extended_key_usage(&[ExtendedKeyUsage::PkixTimeStamping]);
            }
            "server" => {
                log::debug!(
                    "Using demo template 'server'. ExtendedKeyUsage::PkixServerAuth will be added."
                );
                extensions.add_extended_key_usage(&[ExtendedKeyUsage::PkixServerAuth]);
            }
            other => {
                log::debug!("Unknown certificate self-signed demo template '{other}'. No EKU will be added.");
            }
        }
        // Self-signed: This is not a CA cert.
        extensions.add_key_usage(&[KeyUsage::DigitalSignature]);
        // Self-signed: This is basically a CA with no sub-CAs (or leafs)
        extensions.add_basic_constraints(&BasicConstraints::new_leaf());
        let not_after_epoch_seconds = upkit_common::util::time::now_epoch_seconds() + 3600;
        let unsigned_tbs_certificate = NoSignatureTbsCertificate::new(
            subject.clone(),
            not_after_epoch_seconds,
            subject,
            public_key,
            extensions,
        );
        let algorithm_identifier = se.get_algorithm_identifier().unwrap();
        let data =
            unsigned_tbs_certificate.with_signature_algorithm_as_bytes(&algorithm_identifier);
        let signature = se.sign(private_key, &data).unwrap();
        let signed_certificate =
            unsigned_tbs_certificate.to_certificate_bytes(&algorithm_identifier, signature);
        vec![signed_certificate]
    }
}
