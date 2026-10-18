==================================
Crystal ECC Constant Documentation
==================================

**Constant-Time Ed25519 Digital Signatures and X25519 ECDH Key Agreement in Guarded Memory.**

Welcome to the official documentation portal for ``crystal-ecc-constant``.

Documentation Architecture
--------------------------

.. list-table::
   :widths: 25 45 30
   :header-rows: 1

   * - Guide
     - Purpose & Scope
     - Entrypoint
   * - **Business & Strategy**
     - Strategic vision, cryptographic security goals, and user personas.
     - :doc:`Business Specifications <business/spec>`
   * - **Functional Specifications**
     - Requirements ``[FUNC-001]`` through ``[FUNC-007]``, behavioral contracts, and interfaces.
     - :doc:`Functional Specifications <functional/spec>`
   * - **Technical Architecture**
     - Specifications ``[TECH-001]`` through ``[TECH-007]``, memory isolation model, threat model, and release strategy.
     - :doc:`Technical Architecture <technical/spec>`
   * - **Architecture Decisions**
     - Immutable Architecture Decision Records and trade-off analyses.
     - :doc:`Architecture Decisions <adrs/index>`
   * - **Project Roadmap**
     - Dependency-tracked phased milestones, critical path analysis, and audit records.
     - :doc:`Project Roadmap <project/roadmap>`
   * - **User Guides**
     - Integration guides, code examples, and API tutorials.
     - :doc:`User Manual <user/index>`
   * - **Crystal API Reference**
     - Compiler-generated API documentation covering all classes, structs, and modules.
     - `Crystal API Reference <technical/api/index.html>`__

.. toctree::
   :maxdepth: 2
   :caption: Documentation Suite

   business/spec
   functional/spec
   technical/spec
   adrs/index
   project/roadmap
   user/index

Indices and Tables
------------------

* :ref:`genindex`
* :ref:`search`
