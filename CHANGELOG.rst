=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`__,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`__.

[Unreleased]
============

[0.2.0] - 2026-10-18
====================

.. rubric:: Security

- Enforced runtime ``libsodium`` major library version check (``>= 10``) in ``Sodium.init``.
- Eliminated TOCTOU Use-After-Free race conditions between ``Ed25519KeyPair#sign``, ``X25519KeyPair#diffie_hellman``, ``SharedSecret#consume``, and ``dispose`` by synchronizing the entire FFI execution and consumption span under ``Sync::Mutex``.
- Enforced hardware page protection via ``sodium_mprotect_readonly`` and ``sodium_mprotect_readwrite`` across ``PrivateKeyPointer`` and ``SharedSecret`` lifecycles.
- Prevented in-place mutation of ``PublicKey`` and ``Signature`` byte slices by returning defensive copies from ``#bytes`` while retaining internal ``protected def raw_bytes`` zero-copy reads.
- Validated ``PrivateKeyPointer`` buffer sizes in ``Ed25519KeyPair#initialize`` (64 bytes) and ``X25519KeyPair#initialize`` (32 bytes).

.. rubric:: Added

- Bound ``sodium_library_version_major`` and ``sodium_library_version_minor`` in ``LibSodium``.
- Added ``PublicKey#verify_ed25519`` and ``Ed25519KeyPair#verify`` convenience verification methods.
- Added ``PrivateKeyPointer.allocate``, ``PrivateKeyPointer#with_pointer``, and ``SharedSecret#with_unsafe_ptr`` for synchronized secure memory management.

.. rubric:: Changed

- Updated minimum Crystal version requirement to ``>= 1.21.0``.
- Overhauled ``GNUmakefile``, ``.ameba.yml``, ``.gitlab-ci.yml``, and reStructuredText technical documentation to pass strict static analysis and linting gates.

[0.1.2] - 2026-09-19
====================

.. rubric:: Security

- Eliminated critical Use-After-Free in ``SharedSecret#consume`` by implementing block-scoped invocation ``consume(& : Bytes -> T)`` with deterministic zeroization via ``ensure``.
- Hardened ``SharedSecret#consume`` with copy-on-consume semantics and immediate ``sodium_memzero`` wiping on the source allocation.
- Hardened ``LibSodium.sodium_init`` initialization and pointer deallocation with ``Sync::Mutex`` and ``Atomic(Bool)`` for Crystal 1.21 multithreaded Execution Context safety.
- Guarded ``Sodium.constant_time_equal?`` against null pointer FFI calls when comparing empty byte slices.

.. rubric:: Added

- Bound ``crypto_sign_seed_keypair`` and ``crypto_box_seed_keypair`` from LibSodium.
- Added deterministic key derivation from 32-byte seeds (``.from_seed``) for both ``Ed25519KeyPair`` and ``X25519KeyPair``.
- Bound ``sodium_mprotect_noaccess``, ``sodium_mprotect_readonly``, and ``sodium_mprotect_readwrite`` for page-level memory protection.

.. rubric:: Refactored

- Decomposed monolithic 222-line source file into clean submodules under 120 lines (``lib_sodium.cr``, ``types.cr``, ``sodium.cr``, ``secure_memory.cr``, ``ed25519.cr``, and ``x25519.cr``).

[0.1.1] - 2026-08-13
====================

.. rubric:: Fixed

- Removed leaking macro ``uninitialized(type)`` in favor of Crystal's native type system.
- Replaced verbose block syntax with concise block shorthand.

.. rubric:: Refactored

- Modernized spec type hierarchy checks using native Crystal inheritance operators (``< Reference``, ``< Struct``).

[0.1.0] - 2026-06-05
====================

.. rubric:: Added

- Initial orchestrated release of the architecture.
- Full TDD specifications with >80% code coverage.
- Code of Honor integration.
- FHS 3 compliant GNUmakefile.
- GitLab CI/CD Alpine pipeline.
