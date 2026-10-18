=====================
Architecture Overview
=====================

Requirement Mapping
-------------------

Fulfills ``[FUNC-001]``, ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-004]``.

Introduction and Purpose
------------------------

``crystal-ecc-constant`` provides a high-assurance, constant-time Crystal wrapper for elliptic curve cryptography via ``libsodium``. Its primary purpose is to deliver Ed25519 digital signatures and X25519 Diffie-Hellman key agreement while enforcing strict memory safety guarantees. Because Crystal's garbage collector scans managed heap memory, this shard isolates all sensitive cryptographic scalars inside ``libsodium``'s secure memory arena so the GC never scans, moves, or retains copies of private keys or shared secrets.

Library Layout and Namespaces
-----------------------------

The library source is organized under the ``Crystal::Ecc::Constant`` namespace:

* **``src/crystal-ecc-constant.cr``**: Shard entrypoint and semantic ``VERSION`` constant definition.
* **``src/crystal-ecc-constant/lib_sodium.cr``**: Low-level C ABI bindings (``LibSodium``) for initialization, Ed25519, X25519, constant-time comparison, and ``sodium_malloc`` page protection.
* **``src/crystal-ecc-constant/types.cr``**: ``SodiumError`` exception class and immutable ``PublicKey`` (32 bytes) and ``Signature`` (64 bytes) value structs with defensive copy accessors.
* **``src/crystal-ecc-constant/sodium.cr``**: ``Sodium`` struct providing thread-safe atomic initialization, runtime ``libsodium`` major version validation (``>= 10``), and ``constant_time_equal?``.
* **``src/crystal-ecc-constant/secure_memory.cr``**: ``PrivateKeyPointer`` and ``SharedSecret`` reference classes managing ``sodium_malloc`` allocations, ``sodium_mprotect_readonly`` hardware page locks, ``Sync::Mutex`` concurrency guards, and deterministic ``sodium_memzero`` disposal.
* **``src/crystal-ecc-constant/ed25519.cr``**: ``Ed25519KeyPair`` class supporting random generation, 32-byte seed derivation, detached signing, and verification.
* **``src/crystal-ecc-constant/x25519.cr``**: ``X25519KeyPair`` class supporting random generation, 32-byte seed derivation, and ECDH shared secret derivation.

Memory Isolation Model
----------------------

All private keys (Ed25519 64-byte secret keys and X25519 32-byte scalars) and ECDH shared secrets (32 bytes) are confined to ``libsodium``'s secure memory arena (``sodium_malloc``), which uses ``mlock`` to prevent swapping to disk, places guard pages around allocations to trap buffer overflows, and enforces page-level read-only permissions via ``sodium_mprotect_readonly`` once initialized.

.. code-block:: text

   +---------------------------------------------------------------+
   | Crystal Reference Handle Layer                                |
   |  - PrivateKeyPointer, Ed25519KeyPair, X25519KeyPair (class)   |
   |  - SharedSecret (class)                                       |
   |  - PublicKey, Signature (immutable value structs)             |
   |  - Sync::Mutex guards entire FFI usage and disposal spans     |
   +---------------------------------------------------------------+
                                 |
                                 v
   +---------------------------------------------------------------+
   | libsodium Secure Memory Arena (mlock + mprotect + guard)      |
   |  - Private keys (Ed25519 64 bytes, X25519 32 bytes)           |
   |  - Shared secrets (X25519 32 bytes)                           |
   |  - Marked READONLY via sodium_mprotect_readonly after write   |
   +---------------------------------------------------------------+

The Crystal wrapper types (``PrivateKeyPointer``, ``Ed25519KeyPair``, ``X25519KeyPair``, and ``SharedSecret``) use heap-allocated ``class`` reference semantics rather than stack-allocated ``struct`` value semantics. Passing a keypair or pointer handle across methods copies only the object reference, preventing raw pointer duplication and double-free vulnerabilities.

GC Boundary and Concurrency Rules
---------------------------------

#. **No Secret Material in GC Heap**: Private keys and unconsumed shared secrets reside exclusively in ``sodium_malloc`` regions. Public keys and signatures reside in value structs that return defensive copies via ``#bytes`` and ``#to_bytes`` while exposing ``protected def raw_bytes`` internally for zero-copy FFI verification.
#. **Mutex-Synchronized Pointer Lifetimes**: ``PrivateKeyPointer#with_pointer``, ``SharedSecret#with_unsafe_ptr``, and ``SharedSecret#consume`` hold ``@mutex.synchronize`` across the entire FFI call or consumption block so concurrent ``dispose`` calls on other fibers cannot trigger a TOCTOU Use-After-Free.
#. **Hardware Page Protection Lifecycle**:

   * ``sodium_malloc``: Allocate in the secure arena with read-write permissions.
   * Populate the key or shared secret via FFI.
   * ``sodium_mprotect_readonly``: Lock memory pages to read-only while at rest and during read-only cryptographic operations.
   * ``sodium_mprotect_readwrite``: Restore write permissions under lock immediately prior to zeroization.
   * ``sodium_memzero``: Deterministically wipe secret bytes before freeing.
   * ``sodium_free``: Return pages to the ``libsodium`` arena.

Cryptographic Primitives and Constant-Time Assurances
-----------------------------------------------------

* **Ed25519 Digital Signatures**: Implements RFC 8032 keypair generation (``crypto_sign_keypair``), deterministic 32-byte seed derivation (``crypto_sign_seed_keypair``), detached signing (``crypto_sign_detached``), and constant-time verification (``crypto_sign_verify_detached``).
* **X25519 Elliptic Curve Diffie-Hellman**: Implements RFC 7748 keypair generation (``crypto_box_keypair``), deterministic 32-byte seed derivation (``crypto_box_seed_keypair``), and scalar multiplication (``crypto_scalarmult``). All-zero or weak peer public keys cause ``crypto_scalarmult`` to return non-zero, immediately disposing the target buffer and raising ``SodiumError``.
* **Constant-Time Equality**: ``Sodium.constant_time_equal?`` wraps ``sodium_memcmp`` for timing-safe buffer comparisons and safely handles empty byte slices without invoking FFI with null pointers.

FFI Bindings and Runtime Initialization
---------------------------------------

``Sodium.init`` uses double-checked locking with ``Atomic(Bool)`` and ``Sync::Mutex`` to guarantee thread-safe initialization under Crystal 1.21 parallel execution contexts. During initialization, ``Sodium.init`` verifies that ``LibSodium.sodium_library_version_major >= 10`` (corresponding to ``libsodium >= 1.0.18``), raising ``SodiumError`` if an incompatible runtime library is detected.
