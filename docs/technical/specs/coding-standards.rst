================
Coding Standards
================

Requirement Mapping
-------------------

Fulfills ``[FUNC-001]``, ``[FUNC-002]``, ``[FUNC-003]``, ``[FUNC-004]``.

Core Directives
---------------

#. **Strict Static Analysis**:
   Full default rule sets for Ameba and Flaw are enabled. Global or inline rule suppression (``# ameba:disable`` or ``# flaw:disable``) is strictly prohibited across ``src/`` and ``spec/``.

#. **Defensive Nil Handling**:
   Never call ``.not_nil!``. Use explicit type narrowing with ``if``, ``case``, or ``.try``, and validate all FFI pointer allocations with ``.null?`` checks.

#. **Crystal 1.21 Concurrency Primitives**:
   Use ``Sync::Mutex`` (``require "sync/mutex"``) and ``Atomic(Bool)`` to synchronize FFI pointer lifetimes across multi-threaded execution contexts.

#. **Line Length**:
   Maximum line length is 120 characters (``Layout/LineLength: MaxLength: 120`` in ``.ameba.yml``).

#. **API Doc Comments**:
   Every public class, struct, module, constant, and method must include comprehensive Markdown doc comments for ``crystal docs``.
