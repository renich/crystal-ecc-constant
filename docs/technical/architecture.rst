============
Architecture
============

The ``crystal-ecc-constant`` module provides a robust architecture for elliptic curve cryptography, focusing strictly on memory isolation, avoiding Garbage Collector (GC) secret exposure, and securely utilizing ``libsodium``.

Memory Isolation and GC Safety
==============================

To prevent the Crystal Garbage Collector from scanning or copying sensitive key material and to eliminate double-free vulnerabilities on assignment, the library enforces strict memory isolation combined with reference-semantic wrappers.

Key Design Decisions
--------------------

* Use ``class`` reference wrappers (``PrivateKeyPointer``, ``Ed25519KeyPair``, ``X25519KeyPair``, ``SharedSecret``) for secret-bearing handles so variable assignment never duplicates raw ``sodium_malloc`` pointers or causes double-free bugs, while ``PublicKey`` and ``Signature`` are value ``struct`` types.
* Allocate all secret material in ``libsodium`` secure memory via ``sodium_malloc`` (backed by ``mlock`` and guard pages) and lock pages read-only via ``sodium_mprotect_readonly`` after initialization.
* Synchronize all pointer access, consumption, and disposal with Crystal 1.21 ``Sync::Mutex`` locks across the entire FFI execution span (``PrivateKeyPointer#with_pointer``, ``SharedSecret#with_unsafe_ptr``, and ``SharedSecret#consume``) to eliminate TOCTOU Use-After-Free races.
* Explicit memory disposal via ``dispose`` unlocks pages with ``sodium_mprotect_readwrite``, wipes secret bytes via ``sodium_memzero``, and frees the region via ``sodium_free``.
* ``PublicKey#bytes``, ``PublicKey#to_bytes``, ``Signature#bytes``, and ``Signature#to_bytes`` always return a defensive copy of the underlying slice to prevent external in-place mutation.

Core Cryptographic Modules
==========================

Ed25519 and X25519
------------------

* **Ed25519**: Implements ``Ed25519KeyPair`` for random generation, deterministic 32-byte seed derivation, detached signing, and verification.
* **X25519**: Implements ``X25519KeyPair`` for random generation, deterministic 32-byte seed derivation, and ECDH (``diffie_hellman``) with weak public key rejection.
* **SharedSecret**: A single-use reference wrapper for the 32-byte ECDH shared secret supporting both block-scoped zero-copy consumption and copy-on-consume semantics.

Initialization and Security
===========================

* **Double-Checked Locking**: The ``Sodium.init`` method utilizes ``Atomic(Bool)`` and ``Sync::Mutex`` double-checked locking for thread-safe initialization.
* **Version Enforcement**: A minimum ``libsodium`` major library version (``>= 10``, corresponding to libsodium 1.0.18+) is verified at initialization.
* **Constant-Time Utilities**: Includes ``Sodium.constant_time_equal?`` backed by ``sodium_memcmp`` to prevent timing side-channels.
