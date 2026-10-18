=============
User Personas
=============

Primary Stakeholders
--------------------

* **Security and Cryptographic Systems Engineer**: Requires constant-time Ed25519 digital signatures and X25519 ECDH key agreement backed by ``libsodium`` secure memory without garbage collector leakage.
* **Crystal Application Developer**: Requires ergonomic keypair generation, deterministic seed derivation, defensive slice immutability, and clear ``SodiumError`` and ``ArgumentError`` contracts.
* **Autonomous AI Coding Agent**: Requires explicit memory lifecycle semantics, zero linter suppressions, and comprehensive specifications to integrate cryptographic operations safely.
* **FOSS Maintainer**: Needs reproducible ``GNUmakefile`` build targets, automated Sphinx and Crystal API documentation generation, and GPG-signed release workflows.
