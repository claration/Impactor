.. _apple_codesign_rcodesign_signing:

===============================
Signing with ``rcodesign sign``
===============================

The ``rcodesign sign`` command is used to sign a filesystem path.

If you simply ``rcodesign sign <path>``, it will attempt to create an ad-hoc
signature (read: no code signing certificate), rewriting the file/directory
in place. Arguments like ``--p12-file``, ``pem-file``, and ``--smartcard-slot``
can be used to sign with a code signing certificate/key.

Nested Signing By Default
=========================

One of the areas where ``rcodesign sign`` varies from Apple's ``codesign`` is
that we recursively sign entities by default. e.g. if you sign a bundle, we'll
recursively sign nested bundles/frameworks and Mach-O binaries inside that bundle
unless told otherwise.

Unlike Apple's ``codesign``, ``rcodesign`` has a signing settings mechanism
that allows you to scope settings to particular paths. This gives you low-level
control over how every binary, bundle, and even individual Macho-O within a
universal Macho-O binary are signed. Whereas ``codesign`` requires N invocations
with N different settings configurations, ``rcodesign`` can perform the same
operation in a single invocation.

Simple Examples
===============

To sign a Mach-O executable::

    rcodesign sign \
      --p12-file developer-id.p12 --p12-password-file ~/.certificate-password \
      --code-signature-flags runtime \
      path/to/executable

To sign an ``.app`` bundle (and all Mach-O binaries inside)::

   rcodesign sign \
     --p12-file developer-id.p12 --p12-password-file ~/.certificate-password \
     path/to/My.app

To sign a DMG image::

   rcodesign sign \
     --p12-file developer-id.p12 --p12-password-file ~/.certificate-password \
     path/to/app.dmg

To sign a ``.pkg`` installer::

   rcodesign sign \
    --p12-file developer-id-installer.p12 --p12-password-file ~/.certificate-password \
    path/to/installer.pkg