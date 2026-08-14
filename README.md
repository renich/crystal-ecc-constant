# crystal-ecc-constant

[![CI](https://gitlab.com/renich/crystal-ecc-constant/badges/master/pipeline.svg)](https://gitlab.com/renich/crystal-ecc-constant/-/pipelines)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A high-performance, strictly constant-time **Elliptic Curve Cryptography (ECC)** implementation for [Crystal](https://crystal-lang.org/), binding directly to [libsodium](https://doc.libsodium.org/) for Ed25519 digital signatures and X25519 ECDH key exchange.

## Features

- **Ed25519 Digital Signatures**: Detached digital signature generation and verification.
- **X25519 Diffie-Hellman Key Exchange**: Fast ECDH shared secret derivation with single-consumption semantics.
- **Constant-Time Comparison**: Secure buffer comparisons using `sodium_memcmp` to mitigate timing attacks.
- **Strict Memory Safety & Lifetime Tracking**: Private keys and shared secrets reside in pinned secure memory (`sodium_malloc`) and are automatically zeroed and freed upon disposal.
- **Defensive Type Design**: Reference wrappers prevent shallow-copy double-free vulnerabilities.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  crystal-ecc-constant:
    github: renich/crystal-ecc-constant
    version: ~> 0.1.1
```

Then run:

```bash
shards install
```

Make sure `libsodium` development headers are installed on your host (e.g. `dnf install libsodium-devel` on Fedora).

## Usage

```crystal
require "crystal-ecc-constant"

# Initialize libsodium
Crystal::Ecc::Constant::Sodium.init

# Ed25519 Signing & Verification
keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
message = "Strictly FIDO2 assertion payload".to_slice

signature = keypair.sign(message)
is_valid = Crystal::Ecc::Constant::Sodium.verify_ed25519(keypair.public_key, message, signature)
puts "Signature valid: #{is_valid}"

keypair.dispose

# X25519 ECDH Key Exchange
alice = Crystal::Ecc::Constant::X25519KeyPair.generate
bob = Crystal::Ecc::Constant::X25519KeyPair.generate

alice_secret = alice.diffie_hellman(bob.public_key).consume
bob_secret = bob.diffie_hellman(alice.public_key).consume

puts "Secrets match: #{Crystal::Ecc::Constant::Sodium.constant_time_equal?(alice_secret, bob_secret)}"

alice.dispose
bob.dispose
```

## Development & Verification

Build targets and test suites are managed via GNU Make:

```bash
make all      # Runs linting (Ameba & Flaw) and the full test suite
make test     # Executes crystal spec
make lint     # Executes Ameba static analysis and Flaw scanner
make docs     # Generates API documentation into docs/technical/api
```

## Documentation

- **API Documentation**: Generated HTML docs located at [`docs/technical/api/`](docs/technical/api/index.html).
- **Technical Specification**: [`docs/technical/spec.rst`](docs/technical/spec.rst)
- **Project Roadmap**: [`docs/project/roadmap.rst`](docs/project/roadmap.rst)
- **Changelog**: [`CHANGELOG.rst`](CHANGELOG.rst)
- **Code of Honor**: [`docs/technical/CODE_OF_HONOR.rst`](docs/technical/CODE_OF_HONOR.rst)

## License

This project is licensed under the **GNU Affero General Public License v3.0 or later** ([AGPL-3.0-or-later](LICENSE)).
