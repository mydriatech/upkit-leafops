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

//! Enrollment provider interface and its dependencies.

use tyst::traits::se::PrivateKey;
use tyst::traits::se::PublicKey;
use upkit_common::x509::cert::types::IdentityFragment;

/// Certificate enrollment credentials.
#[derive(Clone, Debug)]
pub enum EnrollmentCredentials {
    /// Communication is secured by means outside the control of this app.
    ExternalResponsibility,
    /// The provider will use a shared secret to bootstrap enrollment.
    SharedSecret {
        /// An encoded shared secret.
        secret: Vec<u8>,
    },
}

/// Certificate enrollment options.
#[derive(Clone, Debug)]
pub struct CertificateEnrollmentOptions {
    /// Context specific identifier for how to construct the leaf certificate.
    pub template: String,
    /// See [EnrollmentCredentials].
    pub credentials: EnrollmentCredentials,
    /// A list of `IdentityFragment`s that together identifies the end entity.
    pub requested_identity: Vec<IdentityFragment>,
}

/// Enrollment provider trait (interface).
pub trait EnrollmentProvider: Sync + Send {
    /// Enroll for a new certificate from the provided key pair and enrollment
    /// options.
    ///
    /// The returned chain is ordered with the leaf certificate matching the
    /// public key first.
    ///
    /// The private key may or may not be used, depending on the enrollment
    /// protocol implemented by the provider.
    fn enroll_from_key_pair(
        &self,
        signing_algorithm_oid: &[u32],
        public_key: &dyn PublicKey,
        private_key: &dyn PrivateKey,
        options: &CertificateEnrollmentOptions,
    ) -> Vec<Vec<u8>>;

    // TODO: Send a PoP to revocation service to prevent automatical "on hold" revocation of the cert
    //fn keep_alive(&self, signing_algorithm_oid: &[u32], public_key: &dyn PublicKey, private_key: &dyn PrivateKey, options: &CertificateEnrollmentOptions) -> bool;
}
