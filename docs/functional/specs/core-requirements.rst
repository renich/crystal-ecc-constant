=================
Core Requirements
=================

Functional Requirements
-----------------------

* **[FUNC-001] Ed25519 Digital Signatures**:
  The shard must provide random keypair generation (``Ed25519KeyPair.generate``), deterministic 32-byte seed derivation (``Ed25519KeyPair.from_seed``), 64-byte detached message signing (``Ed25519KeyPair#sign``), and constant-time detached signature verification (``PublicKey#verify_ed25519``, ``Ed25519KeyPair#verify``, and ``Sodium.verify_ed25519``).

* **[FUNC-002] X25519 Diffie-Hellman Key Agreement**:
  The shard must provide random keypair generation (``X25519KeyPair.generate``), deterministic 32-byte seed derivation (``X25519KeyPair.from_seed``), and Curve25519 scalar multiplication (``X25519KeyPair#diffie_hellman``) that rejects weak public keys and returns a single-use ``SharedSecret``.

* **[FUNC-003] Pinned Secure Memory and Hardware Page Protection**:
  All private keys (``PrivateKeyPointer``) and shared secrets (``SharedSecret``) must be allocated in ``libsodium``'s ``sodium_malloc`` arena, locked read-only via ``sodium_mprotect_readonly`` while at rest, synchronized with ``Sync::Mutex`` across FFI boundaries, and deterministically wiped via ``sodium_memzero`` prior to ``sodium_free``.

* **[FUNC-004] Constant-Time Utilities and Defensive Value Types**:
  The shard must expose ``Sodium.constant_time_equal?`` backed by ``sodium_memcmp`` with safe empty-slice handling, and enforce defensive byte slice copying on immutable ``PublicKey`` and ``Signature`` value structs.

* **[FUNC-005] Automated Documentation and Release**:
  The project must build Sphinx documentation alongside compiler-generated Crystal API reference docs and support deterministic verification via ``GNUmakefile`` targets.
