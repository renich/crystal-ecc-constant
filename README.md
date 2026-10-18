# crystal-ecc-constant

[![CI](https://gitlab.com/renich/crystal-ecc-constant/badges/master/pipeline.svg)](https://gitlab.com/renich/crystal-ecc-constant/-/pipelines)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A high-performance, strictly constant-time **Elliptic Curve Cryptography (ECC)** implementation for [Crystal](https://crystal-lang.org/), binding directly to [libsodium](https://doc.libsodium.org/) for Ed25519 digital signatures and X25519 ECDH key exchange.

## Features

- **Ed25519 Digital Signatures**: Detached digital signature generation and verification.
- **Deterministic Key Derivation**: Derive Ed25519 and X25519 keypairs from 32-byte cryptographic seeds (`from_seed`).
- **X25519 Diffie-Hellman Key Exchange**: Fast ECDH shared secret derivation with block-scoped memory sanitization or copy-on-consume semantics.
- **Constant-Time Comparison**: Secure buffer comparisons using `sodium_memcmp` to eliminate timing side-channels.
- **Strict Memory Safety & Lifetime Tracking**: Private keys and shared secrets reside in pinned secure memory (`sodium_malloc`) with guard pages and read-only page protection (`sodium_mprotect_readonly`), explicitly sanitized via `sodium_memzero` upon disposal.
- **Multithreading Concurrency**: Protected via Crystal 1.21 `Sync::Mutex` and atomic initialization.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  crystal-ecc-constant:
    gitlab: renich/crystal-ecc-constant
    version: ~> 0.2.0
```

Then run:

```bash
shards install
```

Make sure `libsodium` development headers are installed on your host (e.g. `dnf install libsodium-devel` on Fedora).

## Usage

```crystal
require "crystal-ecc-constant"

# Initialize libsodium (thread-safe, idempotent)
Crystal::Ecc::Constant::Sodium.init

# Ed25519 Signing & Verification
keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
message = "Strictly FIDO2 assertion payload".to_slice

signature = keypair.sign(message)
is_valid = keypair.verify(message, signature)
puts "Signature valid: #{is_valid}"

keypair.dispose

# Deterministic Seed Derivation
seed = Random::Secure.random_bytes(32)
persistent_key = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)
persistent_key.dispose

# X25519 ECDH Key Exchange (Block-Scoped Consumption)
alice = Crystal::Ecc::Constant::X25519KeyPair.generate
bob = Crystal::Ecc::Constant::X25519KeyPair.generate

alice.diffie_hellman(bob.public_key).consume do |alice_secret|
  bob.diffie_hellman(alice.public_key).consume do |bob_secret|
    matched = Crystal::Ecc::Constant::Sodium.constant_time_equal?(alice_secret, bob_secret)
    puts "Secrets match: #{matched}"
  end
end

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
- **White Paper**: [`docs/whitepaper.rst`](docs/whitepaper.rst)
- **Project Roadmap**: [`docs/project/roadmap.rst`](docs/project/roadmap.rst)
- **Changelog**: [`CHANGELOG.rst`](CHANGELOG.rst)
- **Code of Honor**: [`docs/technical/CODE_OF_HONOR.rst`](docs/technical/CODE_OF_HONOR.rst)

## License

This project is licensed under the **GNU Affero General Public License v3.0 or later** ([AGPL-3.0-or-later](LICENSE)).
