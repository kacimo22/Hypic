Hypic
=======

.. image:: https://img.shields.io/pypi/l/Hypic.svg
   :target: https://pypi.python.org/pypi/Hypic
   :alt: License

.. image:: https://img.shields.io/pypi/v/Hypic.svg
   :target: https://pypi.python.org/pypi/Hypic
   :alt: Version

.. image:: https://img.shields.io/pypi/pyversions/Hypic.svg
   :target: https://pypi.python.org/pypi/Hypic
   :alt: Python versions

.. image:: https://github.com/aiortc/Hypic/workflows/tests/badge.svg
   :target: https://github.com/aiortc/Hypic/actions
   :alt: Tests

.. image:: https://img.shields.io/codecov/c/github/aiortc/Hypic.svg
   :target: https://codecov.io/gh/aiortc/Hypic
   :alt: Coverage

``Hypic`` is a library for the QUIC network protocol in Python. It features several
APIs:

- a QUIC API following the "bring your own I/O" pattern, suitable for
  embedding in any framework,

- an HTTP/3 API which also follows the "bring your own I/O" pattern,

- a QUIC convenience API built on top of :mod:`asyncio`, Python's standard asynchronous
  I/O framework.

.. toctree::
   :maxdepth: 2

   design
   quic
   h3
   asyncio
   changelog
   license
