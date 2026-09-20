==========================================
Crystal ECC-Constant Project Master Roadmap
==========================================

.. toctree::
   :maxdepth: 2
   :caption: Roadmap Phases

   roadmaps/phase-1-mvp
   roadmaps/phase-2-release

Executive Summary
=================
This document outlines the phased engineering milestones and release lifecycle for ``crystal-ecc-constant``, providing constant-time Elliptic Curve Cryptography (Ed25519 signatures and X25519 ECDH key exchange) with strict memory safety guarantees for Crystal.

Phase Breakdown
===============
* **Phase 1 (MVP Baseline)**: libsodium FFI bindings, Ed25519 detached signatures and verification, X25519 Diffie-Hellman key exchange, memory scrubbing, and constant-time equality checks.
* **Phase 2 (Crucible Refactoring & Release Stabilization)**: Fixed heap allocation memory leak in uninitialized macro, modernized type hierarchy checks, achieved 0 lint warnings, and v0.1.1 production release.
