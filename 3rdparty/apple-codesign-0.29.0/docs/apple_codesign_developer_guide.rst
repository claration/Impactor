.. _apple_codesign_developer_guide:

===============
Developer Guide
===============

If you are familiar with Rust, hacking on the ``apple-codesign`` crate should
feel like any other Rust crate. But there are a few things to watch out for:

* The ``smartcard`` crate feature isn't enabled by default because it pulls in
  library dependencies on Linux that aren't always present. We recommend testing
  with ``--all-features`` to ensure all code in the crate is exercised.
* There is some conditional code when running on macOS. We've tried to isolate
  that code to the ``macos`` file/module so changes are more obvious.
* When running tests on macOS, some tests call out to Apple tools (like
  ``csreq``). Non-standard system installs or 3rd party tools on PATH may
  confuse tests. (We generally consider these bugs in the tests and if you
  see a test failure due to a runtime environment issue, please file a bug or
  send a patch to fix.)

Desire for Determinism and Reproducibility
==========================================

As much code and behavior should be deterministic and bit-for-bit reproducible as
possible. There are some obvious cases where bits will disagree (such as time-stamp
tokens from remote timestamp servers). But we strive for the same data inputs to
produce the same output as much as possible. Unless it can't be avoided due to the
fundamental nature of an operation (such as a random/remote operation), we consider
non-determinism to be a bug.

Desire for Compliance with Apple Tooling
========================================

We bias towards Apple's official tooling to define behavior.

Generally, if our implementation behaves differently from Apple's official
tooling in a meaningful way (definition of *meaningful* is subject to
interpretation), the default behavior should be to treat this as a bug.
If deviation is desirable, the justifications should be documented. Ideally
in this documentation tree or in inline code comments. But commit messages
are also fine. The important thing is we leave a breadcrumb trail of known
deviations and why they exist.

There are plenty of valid reasons to deviate from behavior of Apple's tooling.
We purposefully let present and future project maintainers interpret *valid
reasons* as they want.
