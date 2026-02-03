from docutils import nodes
from docutils.parsers.rst import Directive
from docutils.statemachine import StringList


class HypicTransmit(Directive):
    def run(self):
        content = StringList(
            [
                ".. note::",
                "    After calling this method you need to call the QUIC connection "
                ":meth:`~Hypic.quic.connection.QuicConnection.datagrams_to_send` "
                "method to retrieve data which needs to be sent over the network. "
                "If you are using the :doc:`asyncio API <asyncio>`, calling the "
                ":meth:`~Hypic.asyncio.QuicConnectionProtocol.transmit` method "
                "will do it for you.",
            ]
        )
        node = nodes.paragraph()
        self.state.nested_parse(content, 0, node)
        return [node]


def setup(app):
    app.add_directive("Hypic_transmit", HypicTransmit)

    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
