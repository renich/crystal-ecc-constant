===========================================
Crystal ECC-Constant Project Master Roadmap
===========================================

Executive Summary
=================

This document outlines the phased engineering milestones and release lifecycle for ``crystal-ecc-constant``, providing constant-time Elliptic Curve Cryptography (Ed25519 signatures and X25519 ECDH key exchange) with strict memory safety guarantees for Crystal.

Roadmap Phases
--------------

* `Phase 1: Constant-Time ECC and Secure Memory Core MVP <roadmaps/phase-1-mvp.rst>`__
* `Phase 2: Crucible Protocol Refactoring and Release Stabilization <roadmaps/phase-2-release.rst>`__

Phase Breakdown
===============

* **Phase 1 — MVP Baseline**: libsodium FFI bindings, Ed25519 detached signatures and verification, X25519 Diffie-Hellman key exchange, memory scrubbing, and constant-time equality checks.
* **Phase 2 — Crucible Refactoring & Release Stabilization**: Fixed heap allocation memory leak in uninitialized macro, modernized type hierarchy checks, achieved 0 lint warnings, and ``v0.1.2`` production stabilization.
* **Phase 3 — Echelon and Crucible v0.2.0 Hardening**: Eliminated TOCTOU Use-After-Free concurrency races via ``with_pointer`` and ``with_unsafe_ptr``, enforced ``sodium_mprotect_readonly``/``sodium_mprotect_readwrite`` page protection, returned defensive byte copies on ``PublicKey`` and ``Signature``, and optimized CI/CD execution.
