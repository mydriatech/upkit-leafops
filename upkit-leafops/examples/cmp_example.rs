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

//! Example of Certificate Management Protocol initial enrollment.

use tyst::Tyst;
use upkit_common::x509::cert::parse::CertificateParser;
use upkit_common::x509::cert::types::IdentityFragment;
use upkit_common::x509::cert::types::WellKnownAttribute;
use upkit_common::x509::cert::types::WellKnownGeneralName;
use upkit_leafops::enprov::CertificateEnrollmentOptions;
use upkit_leafops::enprov::CertificateEnrollmentProvider;
use upkit_leafops::enprov::EnrollmentConnection;
use upkit_leafops::enprov::EnrollmentCredentials;
use upkit_leafops::enprov::EnrollmentProvider;

/** Example of Certificate Management Protocol initial enrollment.

This is suitable for bootstrapping a client from a shared secret and asymmetric
key pair with minimal configuration, since no preconfigured trust anchor is
required.

From [RFC 4210 5.3.2](https://www.rfc-editor.org/rfc/rfc4210#section-5.3.2):

```text
   Note that if the PKI Message Protection is "shared secret information" ...
   then any certificate transported in the caPubs field may be directly trusted
   as a root CA certificate by the initiator.
```
*/
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(base_url) = std::env::args().nth(1) {
        let profile = if let Some(profile) = std::env::args().nth(2) {
            profile
        } else {
            "test".to_string()
        };
        let shared_secret = if let Some(shared_secret) = std::env::args().nth(3) {
            shared_secret
        } else {
            "foobar123".to_string()
        };
        // ML-DSA-44: 2.16.840.1.101.3.4.3.18 -> [2, 16, 840, 1, 101, 3, 4, 3, 17]
        // ML-DSA-65: 2.16.840.1.101.3.4.3.18 -> [2, 16, 840, 1, 101, 3, 4, 3, 18]
        // Ed25519: 1.3.101.112 -> [1, 3, 101, 112]
        let signing_algorithm_oid = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
        let mut se = Tyst::instance()
            .ses()
            .by_oid(&tyst::encdec::oid::as_string(signing_algorithm_oid))
            .unwrap();
        let (public_key, private_key) = se.generate_key_pair();
        let options = CertificateEnrollmentOptions {
            provider: "cmp".to_string(),
            template: profile,
            credentials: Some(EnrollmentCredentials::SharedSecret { shared_secret }),
            identity: vec![
                IdentityFragment::new_unchecked(
                    &WellKnownAttribute::CommonName.as_name(),
                    &format!("Requested common name {}", get_random_number()),
                ),
                IdentityFragment::new_unchecked(
                    &WellKnownGeneralName::Rfc822Name.as_name(),
                    "no-reply@example.com",
                ),
            ],
            service: Some(EnrollmentConnection::BaseUrl { base_url }),
            trust: None,
        };
        println!("Enrollment options: {options}");
        let cep = CertificateEnrollmentProvider::with_options(&options);
        let encoded_chain = cep.enroll_from_key_pair(
            signing_algorithm_oid,
            public_key.as_ref(),
            private_key.as_ref(),
        );
        for (i, encoded_certificate) in encoded_chain.iter().enumerate() {
            let cert = CertificateParser::from_bytes(encoded_certificate).unwrap();
            println!("  {i}: {}", serde_json::to_string(&cert.get_subject()?)?);
        }
    } else {
        println!(
            "
Missing API URL. Run with:

    cargo run --example cmp_example -- http://127.0.0.1:8080/ejbca/publicweb/cmp [profile a.k.a. alias] [shared secret]
or
    cargo run --example cmp_example -- https://ca.example.com/.well-known/cmp/p [profile] [shared secret]

Defaults

  template:      test
  shared secret: foobar123
"
        );
    }
    Ok(())
}

fn get_random_number() -> u128 {
    let mut random_number = [0u8; size_of::<u128>()];
    Tyst::instance().prng_fill_with_random(None, &mut random_number);
    u128::from_be_bytes(random_number)
}
