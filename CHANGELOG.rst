=========
Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.1.0/>`_,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.

[Unreleased]
============

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
