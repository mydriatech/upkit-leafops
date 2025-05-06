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
use upkit_common::x509::cert::extensions::ExtendedKeyUsage;
use upkit_common::x509::cert::types::IdentityFragment;
use upkit_common::x509::cert::types::WellKnownAttribute;
use upkit_common::x509::cert::types::WellKnownGeneralName;
use upkit_common::x509::cert::validate::CertificatePathValidator;
use upkit_common::x509::cmp::build::PkiMessage;
use upkit_common::x509::cmp::types::InitializationRequest;
use upkit_common::x509::cmp::types::PkiBody;

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
    if let Some(endpoint) = std::env::args().nth(1) {
        let shared_secret = if let Some(shared_secret) = std::env::args().nth(2) {
            shared_secret.as_bytes().to_vec()
        } else {
            b"foobar123".to_vec()
        };
        // ML-DSA-44: 2.16.840.1.101.3.4.3.18 -> [2, 16, 840, 1, 101, 3, 4, 3, 17]
        // ML-DSA-65: 2.16.840.1.101.3.4.3.18 -> [2, 16, 840, 1, 101, 3, 4, 3, 18]
        // Ed25519: 1.3.101.112 -> [1, 3, 101, 112]
        let signature_algorithm_oid = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
        let signature_algorithm_oid_str = tyst::encdec::oid::as_string(signature_algorithm_oid);
        let mut se = Tyst::instance()
            .ses()
            .by_oid(&signature_algorithm_oid_str)
            .unwrap();
        let (public_key, private_key) = se.generate_key_pair();
        let mut random_number = [0u8; size_of::<u128>()];
        Tyst::instance().prng_fill_with_random(None, &mut random_number);
        let random_number = u128::from_be_bytes(random_number).to_string();
        let (dn, sans) = upkit_common::x509::cert::build::util::split_by_identity_fragment_type(&[
            IdentityFragment::new_unchecked(
                &WellKnownAttribute::CommonName.as_name(),
                &format!("Requested common name {random_number}"),
            ),
            IdentityFragment::new_unchecked(
                &WellKnownGeneralName::Rfc822Name.as_name(),
                "no-reply@example.com",
            ),
        ]);
        let initialization_request = InitializationRequest::new(
            public_key.as_ref(),
            None,
            dn,
            &sans,
            &[ExtendedKeyUsage::PkixClientAuth],
        )
        .sign_pop(signature_algorithm_oid, private_key.as_ref())
        .to_pki_body();

        let request = PkiMessage::with_shared_secret(
            initialization_request,
            "cmp_example_client",
            None,
            &shared_secret,
        );
        // Request
        let response = cmp_over_http(&endpoint, &request)?;
        // Handle response
        response.validate_response_nonce(&request)?;
        match response.get_pki_body()? {
            PkiBody::Ip(initialization_response) => {
                response.validate_with_shared_secret(&shared_secret)?;
                // Extract certs
                let mut bag_of_certs = vec![initialization_response.get_certificate().to_owned()];
                initialization_response
                    .get_ca_certificates()
                    .iter()
                    .for_each(|ca_cert| bag_of_certs.push(ca_cert.to_owned()));
                let chain =
                    CertificatePathValidator::get_ordered_chain_from_bag_of_certs(&bag_of_certs)?;
                println!("Chain leading up to a trusted root (since shared secret authentication was used):");
                for (i, cert) in chain.iter().enumerate() {
                    println!("  {i}: {}", serde_json::to_string(&cert.get_subject()?)?);
                }
            }
            PkiBody::Error(error_message) => {
                println!("Error: {error_message}");
                return Ok(());
            }
            _other => {
                println!(
                    "Unexpected PKIBody response with tag {}",
                    response.get_pki_body_tag()
                );
                return Ok(());
            }
        }
    } else {
        println!(
            "
Missing API URL. Run with:

    cargo run --example cmp_example -- http://127.0.0.1:8080/ejbca/publicweb/cmp/test [shared secret, default: foobar123]
or
    cargo run --example cmp_example -- https://ca.example.com/.well-known/cmp/p/test [shared secret, default: foobar123]

"
        );
    }
    Ok(())
}

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
