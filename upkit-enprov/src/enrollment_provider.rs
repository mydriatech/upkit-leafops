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

use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;
use serde_with::skip_serializing_none;
use tyst::traits::se::PrivateKey;
use tyst::traits::se::PublicKey;
use upkit_common::x509::cert::types::IdentityFragment;

/// Certificate enrollment credentials.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentCredentials {
    /// Communication is secured by means outside the control of this app.
    External,
    /// The provider will use a shared secret to bootstrap enrollment.
    SharedSecret {
        /// An encoded shared secret.
        secret: Vec<u8>,
    },
}

/// Certificate enrollment options.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CertificateEnrollmentOptions {
    /// Context specific identifier for how to construct the leaf certificate.
    pub template: String,
    /// See [EnrollmentCredentials].
    pub credentials: EnrollmentCredentials,
    /// A list of `IdentityFragment`s to request that together identifies the
    /// end entity.
    pub identity: Vec<IdentityFragment>,
}

/// Certificate enrollment connection settings.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentConnection {
    /// Communication requires no configuration.
    External,
    /// A connection URL.
    BaseUrl {
        /// The connection URL.
        base_url: String,
    },
}

/// Certificate enrollment provider trust.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentTrust {
    /// Communication is trusted by means outside the control of this app.
    External,
    /// The provider will trust signatures that lead up to one of the trust
    /// anchor certificates.
    TrustAnchors {
        /// Encoded trusted certificates.
        anchors: Vec<Vec<u8>>,
    },
    /// The provider will trust signatures that lead up to a trust anchor
    /// certificate whos encoded certificate fingerprint matches one of these.
    ///
    /// Defaults to using SHA3-512 to fingerprint any certificate.
    TrustedFingerprints {
        /// Encoded trusted certificates.
        fingerprints: Vec<Vec<u8>>,
    },
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
