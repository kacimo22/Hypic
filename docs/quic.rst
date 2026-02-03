QUIC API
========

The QUIC API performs no I/O on its own, leaving this to the API user.
This allows you to integrate QUIC in any Python application, regardless of
the concurrency model you are using.

Connection
----------

.. automodule:: Hypic.quic.connection

    .. autoclass:: QuicConnection
        :members:


Configuration
-------------

.. automodule:: Hypic.quic.configuration

    .. autoclass:: QuicConfiguration
        :members:

.. automodule:: Hypic.quic.logger

    .. autoclass:: QuicLogger
        :members:

Events
------

.. automodule:: Hypic.quic.events

    .. autoclass:: QuicEvent
        :members:

    .. autoclass:: ConnectionTerminated
        :members:

    .. autoclass:: HandshakeCompleted
        :members:

    .. autoclass:: PingAcknowledged
        :members:

    .. autoclass:: StopSendingReceived
        :members:

    .. autoclass:: StreamDataReceived
        :members:

    .. autoclass:: StreamReset
        :members:
