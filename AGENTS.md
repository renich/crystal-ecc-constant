# Agent Architecture & Maintenance Knowledge

This repository was co-developed and orchestrated by the Google Antigravity Agent Orchestrator and Rénich Bon Ćirić.
This document serves as a persistent memory and maintenance guide for the project, detailing the architecture, design decisions, and strict protocols established during development.

## Project Domain: Constant-Time Elliptic Curve Cryptography

### Domain-Specific Knowledge
- Uses reference-semantic `class` handles (`PrivateKeyPointer`, `Ed25519KeyPair`, `X25519KeyPair`, `SharedSecret`) synchronized by `Sync::Mutex` to prevent Double-Free and TOCTOU Use-After-Free conditions, while `PublicKey` and `Signature` are immutable value `struct` types.
- Isolates all secret material in `libsodium` secure memory (`sodium_malloc` and `sodium_mprotect_readonly`) outside the Crystal GC heap.
- Timing attacks are mitigated by constant-time algorithms and `sodium_memcmp`.

## Maintenance Protocols

To ensure the codebase remains exemplary, any future modifications or agent orchestrations MUST adhere to the following established knowledge:

### 1. Build & Dependencies
- **System Libraries**: This project compiles directly against system `libsodium`.
  - **Fedora/RHEL**: Requires `sudo dnf install -y libsodium-devel`.
  - **Alpine (CI/CD)**: Requires `apk add --no-cache make git libsodium-dev pcre2-dev yaml-dev yaml-static`.
- **Build System**: The project explicitly uses a `GNUmakefile` for orchestration (`make all`, `make test`, `make lint`, `make doc-check`, `make docs`, `make install`).
- **Deployment**: The `make install` target is fully compliant with FHS 3 standards (defaulting to `/usr/local/share/doc/crystal-ecc-constant`).

### 2. Testing & Quality Assurance
- **TDD Requirement**: Code MUST be written alongside functional and adversarial tests.
- **Coverage**: Total coverage must remain strictly `> 80%`.
- **Environment**: Tests must run identically on local Fedora environments and Alpine CI containers.

### 3. Linting & Formatting
- **No Suppressions**: Do not suppress linter errors (`# ameba:disable` or `# flaw:disable`).
- **Line Length**: `Layout/LineLength` in `.ameba.yml` is configured to `120` characters.
- **Formatting**: Always execute `crystal tool format src spec` and `make all` before committing.
- **Documentation Linting**: All `.rst` files must pass `crstlint -r .` and `rstcheck` with zero warnings.

## Code of Honor
The entire AI orchestration pipeline and generated codebase is bound to and respects the [Code of Honor](CODE_OF_HONOR.rst) drafted by Rénich Bon Ćirić.

## Disclosures
- **Co-developed-by**: Gemini AI <renich+gemini@woralelandia.com>
- **Signed-off-by**: Rénich Bon Ćirić <renich@woralelandia.com>
