================
Coding Standards
================

Requirement Mapping
-------------------

Fulfills ``[FUNC-004]``, ``[FUNC-005]``.

Technical Specification
-----------------------

* **[TECH-004] Static Analysis, Constant-Time Comparison, and Concurrency Discipline** (Fulfills ``[FUNC-004]``, ``[FUNC-005]``):
  All library code must enforce strict static analysis, constant-time byte comparison, and thread-safe FFI concurrency primitives across Crystal 1.21 execution contexts.

Core Directives
---------------

#. **Strict Static Analysis**:
   Full default rule sets for Ameba and Flaw are enabled. Global or inline rule suppression (``# ameba:disable`` or ``# flaw:disable``) is strictly prohibited across ``src/`` and ``spec/``.

#. **Defensive Nil Handling**:
   Never call ``.not_nil!``. Use explicit type narrowing with ``if``, ``case``, or ``.try``, and validate all FFI pointer allocations with ``.null?`` checks.

#. **Constant-Time Equality**:
   ``Sodium.constant_time_equal?`` wraps ``LibSodium.sodium_memcmp`` for constant-time slice comparison, returning ``true`` when both slices are empty without passing null pointers to C and returning ``false`` when lengths differ. ``PublicKey#==`` and ``Signature#==`` delegate exclusively to ``Sodium.constant_time_equal?``.

#. **Crystal 1.21 Concurrency Primitives**:
   Use ``Sync::Mutex`` (``require "sync/mutex"``) and ``Atomic(Bool)`` to synchronize ``Sodium.init`` double-checked locking (verifying ``sodium_library_version_major >= 10``) and FFI pointer lifetimes across ``Fiber::ExecutionContext::Parallel`` worker threads.

#. **Line Length and Module Granularity**:
   Maximum line length is 120 characters (``Layout/LineLength: MaxLength: 120`` in ``.ameba.yml``), and source files remain modularized by domain responsibility.

#. **API Doc Comments**:
   Every public class, struct, module, constant, and method must include comprehensive Markdown doc comments for ``crystal docs``.
