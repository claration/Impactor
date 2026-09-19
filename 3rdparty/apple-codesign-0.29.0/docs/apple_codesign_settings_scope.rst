.. _apple_codesign_settings_scope:

===============
Settings Scopes
===============

Various signing settings and configuration settings can be *scoped* to a
specific path or pattern. This is accomplished using a mini language/syntax,
which is described by this document.

A *scoping string* is syntax that denotes a path or entity to apply
a setting to.

The following *scoping string* syntax is defined:

``<string>``
   e.g. ``path/to.file``. Applies to content at a given path.

   This is probably the most common scoping syntax.

   The string is a bundle-relative path to a signable entity (a Mach-O
   binary, a nested bundle, etc). e.g. ``Contents/MacOS/extra-bin``.

   If the path belongs to a nested bundle, settings with this scope will
   apply to all signable entities in the bundle.

``main``
   Applies to the main entity being signed and to nested/children entities.

``@<integer>``
   e.g. ``@0`` or ``@1``. Applies to Mach-O binaries within a universal/fat
   binary at the specified index. ``0`` means the first Mach-O in a universal
   binary.

``@[cpu_type=<integer>]``
   e.g. ``@[cpu_type=7]``. Applies to a Mach-O within a universal binary targeting
   a numbered CPU architecture, using the numeric constants as defined by Mach-O.

``@[cpu_type=<string>]``
   e.g. ``@[cpu_type=x86_64]``. Applies to a Mach-O within a universal binary
   targeting a CPU architecture identified by a string. See below for the set of
   recognized architecture names.

``<string>@<integer>`` ``<string>@[cpu_type=<integer|string>]``
   These syntax are an extension of the ``<string>`` and various ``@*`` syntax
   above. They allow you to target a specified Mach-O binary within a universal
   Mach-O at a given path.

   Like the ``<string>`` syntax, if the path matches a bundle, the setting applies
   to all Mach-O binaries in that bundle.

Architecture Names
------------------

* ``arm``
* ``arm64``
* ``arm64_32``
* ``x86_64``
