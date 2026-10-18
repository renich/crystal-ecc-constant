====================================
Contributing to Crystal ECC Constant
====================================

Thank you for your interest in contributing to ``crystal-ecc-constant``. We welcome contributions from human engineers and autonomous agents who share our commitment to software excellence, cryptographic security rigor, and empirical verification.

Code of Honor
=============

All contributors must uphold the principles defined in `CODE_OF_HONOR.rst <CODE_OF_HONOR.rst>`__. We build resilient, well-tested software, demand intellectual honesty, operate transparently, and verify all library behaviors empirically.

Development Workflow
====================

Prerequisites
-------------

* `Crystal <https://crystal-lang.org/>`__ (``>= 1.21.0``)
* ``libsodium`` development headers (``libsodium-devel`` on Fedora Linux)
* `GNU Make <https://www.gnu.org/software/make/>`__
* `cRSTLint <https://gitlab.com/renich/crstlint>`__ and ``rstcheck`` for documentation linting

Setting Up the Workspace
------------------------

#. Clone the repository:

   .. code-block:: bash

      git clone git@gitlab.com:renich/crystal-ecc-constant.git
      cd crystal-ecc-constant

#. Build linter dependencies:

   .. code-block:: bash

      make deps

#. Verify the test suite, static analysis, and documentation linting:

   .. code-block:: bash

      make check

Testing and Quality Standards
=============================

We adhere strictly to Test-Driven Development and the principle of **Do Not Assume; Always Verify**.

Running Checks
--------------

* **Run test suite**:

   .. code-block:: bash

      make test

* **Run static linters** (Ameba and Flaw):

   .. code-block:: bash

      make lint

* **Validate RST Documentation**:

   .. code-block:: bash

      make doc-check

Git Commit Standards
====================

We enforce the Conventional Commits specification:

* ``feat(ed25519): add deterministic seed keypair derivation``
* ``fix(memory): synchronize pointer disposal under Sync::Mutex``
* ``docs(adrs): record decision on libsodium guarded memory isolation``
* ``test(spec): add multi-fiber concurrency stress specs``

All commits must be signed and authored with full technical ownership.
