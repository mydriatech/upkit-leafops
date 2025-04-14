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

//! Aggregation of [EnrollmentProvider]s.

use std::sync::Arc;
use tyst::traits::se::PrivateKey;
use tyst::traits::se::PublicKey;
pub use upkit_enprov::*;
use upkit_enprov_selfsigned::SelfSignedProvider;

/// Provides [EnrollmentProvider] implementation selection by name.
pub struct CertificateEnrollmentProvider {
    provider: Arc<dyn EnrollmentProvider>,
}

impl CertificateEnrollmentProvider {
    /// Return a new instance of the named [EnrollmentProvider] implementation.
    pub fn new(provider_name: &str, enrollment_trust: &EnrollmentTrust) -> Arc<Self> {
        let provider = match provider_name {
            "self_signed" => {
                if !EnrollmentTrust::External.eq(enrollment_trust) {
                    log::debug!("Only 'external' enrollment trust makes sense for '{provider_name}'. Ignoring parameter.");
                }
                Arc::new(SelfSignedProvider::default())
            }
            unknown_provider => panic!("Unknown provider '{unknown_provider}'."),
        };
        Arc::new(Self { provider })
    }
}

impl EnrollmentProvider for CertificateEnrollmentProvider {
    fn enroll_from_key_pair(
        &self,
        signing_algorithm_oid: &[u32],
        public_key: &dyn PublicKey,
        private_key: &dyn PrivateKey,
        options: &CertificateEnrollmentOptions,
    ) -> Vec<Vec<u8>> {
        self.provider
            .enroll_from_key_pair(signing_algorithm_oid, public_key, private_key, options)
    }
}
