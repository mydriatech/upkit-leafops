# UPKIT Leaf Ops

Opinionated [Public Key Infrastructure (PKI)](https://en.wikipedia.org/wiki/Public_key_infrastructure)
utility library for [Rust](https://www.rust-lang.org/).

Leaf operations refers to end entity tasks like enrollment, renewal and self-revocation.


## UPKIT

This repository is part of the Ultimate Public Key Infrastructure Toolkit
(UPKIT).

The complexity of Public Key Infrastructures (PKIs), digital certificates and
applied cryptography can be complicated to work with.

UPKIT reduces the exposed complexity so you can focus on what you really wanted
to do instead. See the "Limitations" section below for additional details.

## Features

* Certificate enrollment using one of the following:
    * Built in self-signed certificate provider for testing.
    * Certificate Management Protocol (CMP) PBMAC1 protected `InitializationRequest`.
    * (more will be added here)
* Monitor revocation status of all certificates in a chain.

## Quick start

Add the following to `Cargo.toml`:

```text
[dependencies]
upkit_leafops = { git = "https://github.com/mydriatech/upkit-leafops.git", branch = "main" }
```

### Self signed

See [`test_self_signed.rs`](upkit-leafops/tests/test_self_signed.rs) for an
example of enrolling for a self-signed certificate using the enrollment provider.

### Certificate Management Protocol

The CMP [example](upkit-leafops/examples/cmp_example.rs) can be tested with
`docker.io/keyfactor/ejbca-ce:9.1.1`. Configure a CMP "alias" `test` in RA mode with
HMAC authentication `foobar123`. Add the CA certificate to `caPubs` for a more
realistic experience of bootstrapping a client with minimal configuration.

```text
cargo run --example cmp_example -- http://127.0.0.1:8080/ejbca/publicweb/cmp/test foobar123
```


## Limitations

Reducing complexity might have excluded your favorite feature.
Open a new Issue and state your case.


## License

[Apache License 2.0 with Free world makers exception 1.0.0](LICENSE-Apache-2.0-with-FWM-Exception-1.0.0)

The intent of this license to

* Allow makers, innovators, integrators and engineers to do what they do best without blockers.
* Give commercial and non-commercial entities in the free world a competitive advantage.
* Support a long-term sustainable business model where no "open core" or "community edition" is ever needed.

## Governance model

This projects uses the [Benevolent Dictator Governance Model](http://oss-watch.ac.uk/resources/benevolentdictatorgovernancemodel) (site only seem to support plain HTTP).

See also [Code of Conduct](CODE_OF_CONDUCT.md) and [Contributing](CONTRIBUTING.md).
