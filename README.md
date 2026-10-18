# crystal-ecc-constant

[![Version](https://img.shields.io/badge/version-v0.2.1-blue.svg?style=flat-square)](https://gitlab.com/renich/crystal-ecc-constant/-/releases)
[![Crystal](https://img.shields.io/badge/crystal-%3E%3D%201.21.0-black.svg?style=flat-square&logo=crystal&logoColor=white)](https://crystal-lang.org/)
[![CI](https://gitlab.com/renich/crystal-ecc-constant/badges/master/pipeline.svg)](https://gitlab.com/renich/crystal-ecc-constant/-/pipelines)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![License: FDL v1.3](https://img.shields.io/badge/Docs_License-GFDL_v1.3-blue.svg)](LICENSE-DOCS)

A high-assurance, strictly constant-time **Elliptic Curve Cryptography** shard for [Crystal](https://crystal-lang.org/), binding directly to [libsodium](https://doc.libsodium.org/) for Ed25519 digital signatures and X25519 ECDH key agreement with complete garbage collector secret isolation.

## Features

- **Ed25519 Digital Signatures**: Detached digital signature generation (`Ed25519KeyPair#sign`) and constant-time verification (`PublicKey#verify_ed25519`, `Ed25519KeyPair#verify`, `Sodium.verify_ed25519`).
- **Deterministic Key Derivation**: Derive Ed25519 and X25519 keypairs from 32-byte cryptographic seeds (`from_seed`).
- **X25519 Diffie-Hellman Key Agreement**: Curve25519 scalar multiplication with weak peer public key rejection and single-use `SharedSecret` handles supporting block-scoped zeroization or copy-on-consume semantics.
- **Constant-Time Comparison**: Timing-safe buffer comparisons via `Sodium.constant_time_equal?` backed by `sodium_memcmp`.
- **Pinned Secure Memory & Hardware Page Protection**: Private keys and unconsumed shared secrets reside in `libsodium` secure memory (`sodium_malloc`) with guard pages and read-only page permissions (`sodium_mprotect_readonly`), unlocked (`sodium_mprotect_readwrite`) and wiped (`sodium_memzero`) upon disposal.
- **Multithreading Concurrency**: Protected across all FFI spans via Crystal 1.21 `Sync::Mutex` and atomic initialization (`Atomic(Bool)`).

## Installation

Add `crystal-ecc-constant` to your application's `shard.yml`:

```yaml
dependencies:
  crystal-ecc-constant:
    gitlab: renich/crystal-ecc-constant
    version: ~> 0.2.1
```

Then run:

```bash
shards install
```

Make sure `libsodium` development headers are installed on your host (for example, `sudo dnf install libsodium-devel` on Fedora Linux).

## Usage

```crystal
require "crystal-ecc-constant"

# Initialize libsodium (thread-safe, idempotent, verifies major version >= 10)
Crystal::Ecc::Constant::Sodium.init

# Ed25519 Signing & Verification
keypair = Crystal::Ecc::Constant::Ed25519KeyPair.generate
begin
  message = "Strictly FIDO2 assertion payload".to_slice
  signature = keypair.sign(message)
  puts "Signature valid: #{keypair.verify(message, signature)}"
ensure
  keypair.dispose
end

# Deterministic Seed Derivation
seed = Random::Secure.random_bytes(32)
persistent_key = Crystal::Ecc::Constant::Ed25519KeyPair.from_seed(seed)
persistent_key.dispose

# X25519 ECDH Key Exchange (Block-Scoped Consumption)
alice = Crystal::Ecc::Constant::X25519KeyPair.generate
bob = Crystal::Ecc::Constant::X25519KeyPair.generate
begin
  alice.diffie_hellman(bob.public_key).consume do |alice_secret|
    bob.diffie_hellman(alice.public_key).consume do |bob_secret|
      matched = Crystal::Ecc::Constant::Sodium.constant_time_equal?(alice_secret, bob_secret)
      puts "Secrets match: #{matched}"
    end
  end
ensure
  alice.dispose
  bob.dispose
end
```

## Build System Targets

| Target | Description |
| :--- | :--- |
| `make all` | Runs static analysis (`lint`), documentation linting (`doc-check`), and the test suite (`test`) |
| `make test` | Executes the spec test suite (`crystal spec`) |
| `make lint` | Runs `crystal tool format --check`, Ameba static analysis, and Flaw SAST scanner |
| `make doc-check` | Lints all reStructuredText documentation using `crstlint -r .` and `rstcheck` |
| `make docs` | Generates Crystal API docs (`docs/technical/api`) and builds the Sphinx `dirhtml` portal (`docs/build/dirhtml`) |
| `make clean` | Removes build artifacts and generated documentation |

## Documentation

Full architectural blueprints, functional specifications, and operational playbooks are maintained under [`docs/`](docs/index.rst):

| Guide | Scope & Highlights | Entry Point |
| :--- | :--- | :--- |
| **Business & Strategy** | Cryptographic security problem statement, ROI metrics, and user personas. | [Business Specs](docs/business/spec.rst) |
| **Functional Specifications** | Requirements `[FUNC-001]`–`[FUNC-005]` and behavioral contracts. | [Functional Specs](docs/functional/spec.rst) |
| **Technical Architecture** | Secure memory isolation model, FFI bindings, coding standards, and threat model. | [Technical Specs](docs/technical/spec.rst) |
| **Release Playbook** | SemVer, Keep a Changelog, and GPG-signed GitLab release steps. | [Release Procedure](docs/technical/specs/release-procedure.rst) |
| **Architecture Decisions** | Immutable records of architectural decisions and security trade-offs. | [ADR Index](docs/adrs/index.rst) |
| **Project Roadmap** | Phased milestone tracking, delivery roadmaps, and audit logs. | [Project Roadmap](docs/project/roadmap.rst) |
| **User Guides** | Installation, usage examples, and exception handling. | [User Manual](docs/user/index.rst) |
| **Crystal API Reference** | Compiler-generated API documentation (`make docs`). | `docs/technical/api/index.html` |

## Contributing & Code of Honor

All contributions must adhere to the [Universal Code of Honor](CODE_OF_HONOR.rst) and [Contributing Guidelines](CONTRIBUTING.rst).

## License

- **Software**: GNU Affero General Public License v3.0 or later ([LICENSE](LICENSE)).
- **Documentation**: GNU Free Documentation License v1.3 or later ([LICENSE-DOCS](LICENSE-DOCS)).
