.. _apple_codesign_rcodesign_notarizing:

==========================================
Notarizing and Stapling with ``rcodesign``
==========================================

Submit Notarizations with ``notary-submit``
===========================================

You can notarize a signed asset via ``rcodesign notary-submit``.

Notarization requires an App Store Connect API Key. See
:ref:`apple_codesign_app_store_connect_api_key` for instructions on how
to obtain one.

Assuming you used ``rcodesign encode-app-store-connect-api-key`` to produce
a JSON file with all the API Key information, simply specify ``--api-key-file``
to define the path to this JSON file.

To notarize an already signed asset::

    rcodesign notary-submit \
      --api-key-file ~/.appstoreconnect/key.json \
      path/to/file/to/notarize

By default ``notarize-submit`` just uploads the asset to Apple. To wait
on its notarization result, add ``--wait``::

    rcodesign notary-submit \
      --api-key-file ~/.appstoreconnect/key.json \
      --wait \
      path/to/file/to/notarize

Or to wait and automatically staple the file if notarization was successful::

    rcodesign notary-submit \
      --api-key-file ~/.appstoreconnect/key.json \
      --staple \
      path/to/file/to/notarize

Stapling With ``staple``
========================

If an asset was already notarized, you can attempt to *staple* (read: attach)
the *notarization ticket* to that entity via the ``staple`` command::

    rcodesign staple path/to/file/to/staple

.. tip::

   It is possible to staple any asset, not just those notarized by you.

Checking on Submitted Notarizations
===================================

Notarization is an asynchronous process: you first submit an asset to Apple then
you wait for an indefinite amount of time (often a few dozen seconds) for
Apple's servers to scan the asset and issue a notarization ticket.

If a notarization operation is interrupted or if you want to check on its
status, there are a few support commands to query Apple's servers.

``notary-list`` will list the most recent submitted notarization requests.
This command will print a list of submission IDs, dates, and a brief status
of each one.::

   rcodesign notary-list --api-key-file ~/.appstoreconnect/key.json

``notary-wait`` can be used to wait on a previously submitted notarization
request to finish::

   rcodesign notary-wait \
     --api-key-file ~/.appstoreconnect/key.json \
     <submission ID>

Here, ``<submission ID>`` is an identifier issued by Apple and printed when
running ``rcodesign notary-list`` or ``rcodesign notary-submit``.

``notary-log`` can be used to retrieve the notarization log for a submission
identifier::

   rcodesign notary-log \
     --api-key-file ~/.appstoreconnect/key.json \
     <submission ID>

.. _apple_codesign_notarization_problems:

Common Notarization Problems
============================

Notarization can fail for a myriad of reasons. On software that hasn't been
successfully notarized before and on untested release pipeline, notarization
failures before success are somewhat expected.

Apple's requirements for notarization are enumerated at
`Notarizing macOS software before distribution <https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution>`_.

The sections below document common notarization failures and how to mitigate
them. They somewhat mirror Apple's official guidance at
`Resolving common notarization issues <https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues>`_,
which we highly recommend you read before this documentation.

.. _apple_codesign_notarization_for_notarization:

Using `sign --for-notarization`
-------------------------------

The ``rcodesign sign`` command has a ``--for-notarization`` argument that
attempts to engage *Apple notarization compatibility mode*.

When this flag is used:

* The signing configuration is validated for notarization compatibility.
* Signing settings are automatically changed to help ensure notarization compatibility.

This flag is best effort. If you encounter notarization failures when using
this flag that you think could be automatically detected or prevented,
please consider filing a bug report.

Usage example::

   rcodesign sign \
     --for-notarization \
     --pem-source developer-id-application.pem \
     MyApp.app

.. _apple_codesign_notarization_problem_apple_first:

Notarize with Apple Tooling First
---------------------------------

For applications that haven't been notarized before or when debugging issues
with notarization, we highly recommend using Apple's official tooling and
workflows for notarizing from a macOS machine before attempting to debug
notarization with ``rcodesign``.

This is because notarization and its errors can be challenging to work through.
Having an existence proof that a piece of software can be notarized with Apple's
tooling proves that software is capable of passing notarization. It means that
failures in ``rcodesign`` notarization are due to invoking ``rcodesign``
incorrectly or due to a bug in ``rcodesign``.

We highly recommend reading Apple's notarization documentation (linked above)
when debugging notarization failures.

.. _apple_codesign_notarization_problem_hardened_runtime:

Hardened Runtime Not Enabled
----------------------------

The hardened runtime needs to be enabled to pass notarization. If you don't
have the hardened runtime enabled, notarization has been known to fail with
the error: ``The executable does not have the hardened runtime enabled.``

To enable the hardened runtime with ``rcodesign sign``, the ``runtime``
code signature flag must be enabled via the ``--code-signature-flags`` argument.
e.g.::

   rcodesign sign \
      --code-signature-flags runtime \
      MyApp.app

``--code-signature-flags`` only applies to the _main_ entity being signed by
default. If you are signing an application bundle with multiple binaries, for
example, you will need to use the _scoped_ syntax to ``--code-signature-flags``
to specify code signature flags for each additional path being signed. e.g.::

   rcodesign sign \
     --code-signature-flags runtime \
     --code-signature-flags Contents/MacOS/additional-binary:runtime \
     MyApp.app

For complex bundles consisting of several binaries or nested bundles, this
can grow quite cumbersome and it is easy to forget to annotate a binary,
especially if new files appear in the bundles. For complex signing scenarios,
we recommend using :ref:`configuration files <apple_codesign_config_files>` to
define the signing settings.

.. _apple_codesign_notarization_problem_signing_key:

Incorrect Signing Certificate
-----------------------------

Another common notarization problem is not signing with an Apple issued signing
certificate or not using the appropriate certificate for signing a particular
entity.

See Apple's `Use a valid Developer ID certificate <https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues#3087721>`_
for more.
