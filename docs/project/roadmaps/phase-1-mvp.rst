==============================================
Phase 1: Constant-Time ECC & Memory Safety MVP
==============================================

:Status: Completed
:Target Version: 0.1.0

Overview
========

Implement constant-time Elliptic Curve Cryptography bindings to libsodium, providing Ed25519 digital signatures and X25519 Diffie-Hellman key exchange with strict memory encapsulation.

Milestones & Deliverables
=========================

* **[ECC-001] LibSodium FFI Bindings**: Bind core functions (``crypto_sign_*``, ``crypto_box_*``, ``crypto_scalarmult``, ``sodium_memcmp``, ``sodium_malloc``, ``sodium_free``).
* **[ECC-002] Ed25519 Detached Signatures**: Implement ``Ed25519KeyPair`` with detached signing and signature verification.
* **[ECC-003] X25519 ECDH Key Exchange**: Implement ``X25519KeyPair`` and ``SharedSecret`` with one-time consumption semantics.
* **[ECC-004] Memory Safety & Lifetime Management**: Ensure private key pointers and shared secrets are pinned in secure memory and wiped upon disposal.
* **[ECC-005] Constant-Time Comparisons**: Implement ``Sodium.constant_time_equal?`` wrapping ``sodium_memcmp``.
