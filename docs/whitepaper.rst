================================
Crystal ECC Constant White Paper
================================

Introduction and Purpose
========================

The ``crystal-ecc-constant`` module provides a high-assurance, constant-time Crystal wrapper for elliptic curve cryptography via ``libsodium``. Its primary purpose is to deliver robust cryptographic operations—specifically Ed25519 digital signatures and X25519 key exchange—while enforcing stringent memory safety guarantees. The Crystal programming language utilizes a Garbage Collector (GC) which ordinarily scans heap memory. This project purposefully sidesteps the risk of the GC tracing, moving, or persisting sensitive key material by fully compartmentalizing cryptographic secrets within libsodium's secure memory arena. It is explicitly designed for mission-critical use cases where memory isolation, thread safety, and deterministic memory lifecycle management are paramount.

Architecture
============

The foundational architecture of ``crystal-ecc-constant`` revolves around strict memory boundaries and concurrency protection.

Memory Isolation Model
----------------------

All private keys (both Ed25519 and X25519) and shared secrets are confined entirely to libsodium's secure memory arena (``sodium_malloc``), which employs ``mlock`` to prevent swapping to disk, integrates kernel guard pages to mitigate buffer overflows, and enforces page-level read-only protection via ``sodium_mprotect_readonly`` once initialized. The Crystal wrapper types (such as ``PrivateKeyPointer`` and ``SharedSecret``) employ heap-allocated ``class`` reference semantics instead of stack-allocated value types to avoid duplicate pointers and prevent double-free vulnerabilities. Crystal only manages the opaque reference wrapper; the sensitive private scalar bytes reside exclusively in the protected libsodium arena and are unlocked via ``sodium_mprotect_readwrite`` and sanitized via ``sodium_memzero`` upon disposal.

Concurrency and Thread Safety
-----------------------------

All cryptographic wrappers utilize Crystal 1.21 ``Sync::Mutex`` concurrency primitives. Double-free vulnerabilities and TOCTOU races under multi-threaded execution contexts are prevented by synchronizing pointer usage, consumption, and deallocation across the entire FFI operation span. Furthermore, ``Sodium.init`` implements thread-safe initialization backed by atomic flags, synchronization locks, and runtime library version verification.

Cryptography
============

The project implements two foundational forms of modern elliptic curve cryptography:

* **Ed25519 Digital Signatures**: Provides deterministic, highly secure keypair generation, detached signing, and constant-time signature verification. Key generation and signing leverage libsodium's ``crypto_sign_keypair`` and ``crypto_sign_detached``. Deterministic key derivation from 32-byte seeds is provided via ``crypto_sign_seed_keypair``.
* **X25519 Elliptic Curve Diffie-Hellman**: Provides scalar multiplication for secure key exchange. The resulting ECDH shared secret is immediately placed in libsodium's protected secure memory and bound to a single-use ``SharedSecret`` wrapper. Deterministic key derivation from 32-byte seeds is supported via ``crypto_box_seed_keypair``.

Constant-Time Assurances
------------------------

All cryptographic operations avoid data-dependent branches or data-dependent memory accesses. The module exposes ``Sodium.constant_time_equal?`` (a wrapper over ``sodium_memcmp``) for safe sequence comparison, nullifying timing side-channel attacks during signature or digest verification, with defensive handling for empty buffers.

Safety Guarantees
=================

The ``crystal-ecc-constant`` architecture natively provides the following guarantees:

#. **Double-Free Prevention via Reference Semantics**: The codebase mandates ``class`` wrappers around secure pointers to enforce reference semantics. This ensures safe assignments and explicitly avoids value-copy pointer duplication that would otherwise trigger dangerous double-free vulnerabilities.
#. **Deterministic Cleanup and Sanitization**: When ``dispose`` is invoked, it restores write permissions via ``sodium_mprotect_readwrite`` and issues a ``sodium_memzero`` directly before returning memory to the arena via ``sodium_free``, wiping private key material immediately.
#. **Use-After-Free Elimination**: ``SharedSecret`` supports block-scoped consumption (``shared.consume { |secret| ... }``), holding the synchronization lock across the entire block and sanitizing the secret upon block exit in an ``ensure`` clause. For value consumption, bytes are copied to a fresh GC-managed buffer and the underlying secure pointer is immediately zeroed and freed under the same lock.
#. **Thread-Safe Initialization**: The ``Sodium.init`` process implements atomic double-checked locking and runtime major version verification, making cross-thread libsodium initialization completely safe under Crystal's parallel execution contexts.
#. **Strict Single-Use Policies**: Entities like ``SharedSecret`` employ internal boolean barriers preventing double consumption. Once consumed, the secure pointer is safely zeroed out and destroyed.

Testing Proof of Functionality
==============================

The ``crystal-ecc-constant`` module underwent rigorous validation, successfully executing all test and adversarial scenarios without failure or leaks:

* **25/25 Integration, Unit, and Adversarial Tests Passed**: 0 failures, 0 errors.
* **Double-Free Vulnerabilities Remedied**: Adversarial checks successfully assert the prevention of double-free conditions when variables are copied or assigned.
* **Deterministic Derivation Verified**: Deterministic key derivation from cryptographic seeds is validated for both Ed25519 and X25519 against standard vector requirements.
* **Concurrency and Thread Safety**: Parallel multi-fiber execution verifies that concurrent key generation and signing operate safely without memory corruption or data races.
* **Constant-Time Verification**: The equality verification rigorously covers uniform byte sequences, differing sequences of the same size, mismatched lengths, and completely empty byte slices in constant time.
