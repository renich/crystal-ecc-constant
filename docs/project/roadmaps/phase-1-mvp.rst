============
Phase 1: MVP
============

Timeline and Objectives
-----------------------

Deliver the core constant-time Ed25519 and X25519 cryptographic shard backed by ``libsodium`` secure memory, reference-semantic key handles, and adversarial spec coverage.

Milestones and Deliverables
---------------------------

* **Milestone 1.1: Core Cryptographic Primitives and Secure Memory** (Fulfills ``[FUNC-001]``, ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-004]``):

  - [x] ``LibSodium`` C ABI bindings for initialization, Ed25519, X25519, ``sodium_memcmp``, and ``sodium_malloc``.
  - [x] ``PrivateKeyPointer`` and ``SharedSecret`` reference wrappers with ``sodium_mprotect_readonly`` and ``Sync::Mutex`` synchronization.
  - [x] ``Ed25519KeyPair`` and ``X25519KeyPair`` random generation, deterministic 32-byte seed derivation, signing, verification, and ECDH key agreement.
  - [x] Immutable ``PublicKey`` and ``Signature`` value structs with defensive byte copying.

* **Milestone 1.2: Build System and Quality Automation** (Fulfills ``[FUNC-005]``):

  - [x] Standard ``GNUmakefile`` with ``all``, ``test``, ``lint``, ``doc-check``, and ``docs`` targets.
  - [x] Zero-suppression Ameba and Flaw SAST verification.
  - [x] Complete Sphinx documentation portal and Crystal API reference generation.
