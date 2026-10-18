======================
Implementation Details
======================

Implementation Highlights
=========================

* Thread-safe initialization utilizing ``Atomic(Bool)`` and ``Sync::Mutex`` double-checked locking.
* Runtime version verification ensuring ``libsodium`` major library version is at least ``10`` (libsodium 1.0.18+).
* Proper utilization of FFI types, explicitly using ``UInt64`` for message and signature length parameters.
* Reference-semantic ``class`` wrappers (``PrivateKeyPointer``, ``Ed25519KeyPair``, ``X25519KeyPair``, ``SharedSecret``) combined with ``Sync::Mutex`` synchronization prevent double-free and TOCTOU Use-After-Free vulnerabilities across concurrent fibers and threads.
* Hardware page protection via ``sodium_mprotect_readonly`` while keys and shared secrets are at rest, transitioning to ``sodium_mprotect_readwrite`` only during initialization and deterministic ``sodium_memzero`` disposal.

Testing Requirements
====================

Before production deployment, the module rigorously enforces:

* **Unit tests**: Coverage for every public type and method, including seed validation, size validation, weak public key rejection, and defensive copy immutability.
* **Adversarial and concurrency tests**: Multi-fiber parallel signing, idempotent disposal, and post-disposal access guards.
* **Static analysis**: Zero warnings under ``ameba --all`` and ``flaw scan .``.
* **Constant-time verification**: Utilizing ``sodium_memcmp`` for all secret and public key comparisons.
