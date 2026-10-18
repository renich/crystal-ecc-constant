====================
Phase 2: Enhancement
====================

Timeline and Objectives
-----------------------

Harden concurrency guarantees, eliminate TOCTOU race conditions across FFI boundaries, enforce hardware page protection, and align the documentation portal and build system with the ``init/lib`` standard.

Milestones and Deliverables
---------------------------

* **Milestone 2.1: Crucible and Echelon Security Hardening**:

  - [x] Synchronize entire FFI execution and consumption spans under ``Sync::Mutex`` via ``PrivateKeyPointer#with_pointer`` and ``SharedSecret#with_unsafe_ptr``.
  - [x] Enforce ``sodium_mprotect_readonly`` and ``sodium_mprotect_readwrite`` hardware page transitions.
  - [x] Enforce runtime ``libsodium`` major version check (``>= 10``) in ``Sodium.init``.
  - [x] Return defensive byte slice copies from ``PublicKey`` and ``Signature`` accessors.

* **Milestone 2.2: Documentation Portal and Build Alignment**:

  - [x] Full Sphinx documentation portal (``docs/``) covering business, functional, technical, ADR, roadmap, and user specifications.
  - [x] Automated ``crstlint`` and ``rstcheck`` documentation linting gates in ``GNUmakefile``.
