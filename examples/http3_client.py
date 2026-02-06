import argparse
import asyncio
import logging
# logging.disable(logging.CRITICAL)

import os
import pickle
import ssl
import time
from collections import deque
from typing import BinaryIO, Callable, Deque, Dict, List, Optional, Union, cast, Tuple
from urllib.parse import urlparse

import Hypic
import wsproto
import wsproto.events
from Hypic.asyncio.client import connect
from Hypic.asyncio.protocol import QuicConnectionProtocol
from Hypic.h0.connection import H0_ALPN, H0Connection
from Hypic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from Hypic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from Hypic.quic.configuration import QuicConfiguration
from Hypic.quic.events import QuicEvent
from Hypic.quic.logger import QuicFileLogger
from Hypic.quic.packet import QuicProtocolVersion
from Hypic.tls import CipherSuite, SessionTicket, ExtensionType

try:
    import uvloop
except ImportError:
    uvloop = None

logger = logging.getLogger("client")

HttpConnection = Union[H0Connection, H3Connection]

USER_AGENT = "Hypic/" + Hypic.__version__
ticket: Optional[SessionTicket] = None
pq_enable=False

class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)

        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme


class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}

        self.content = content
        self.headers = headers
        self.method = method
        self.url = url


class WebSocket:
    def __init__(
        self, http: HttpConnection, stream_id: int, transmit: Callable[[], None]
    ) -> None:
        self.http = http
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.stream_id = stream_id
        self.subprotocol: Optional[str] = None
        self.transmit = transmit
        self.websocket = wsproto.Connection(wsproto.ConnectionType.CLIENT)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        """
        Perform the closing handshake.
        """
        data = self.websocket.send(
            wsproto.events.CloseConnection(code=code, reason=reason)
        )
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=True)
        self.transmit()

    async def recv(self) -> str:
        """
        Receive the next message.
        """
        return await self.queue.get()

    async def send(self, message: str) -> None:
        """
        Send a message.
        """
        assert isinstance(message, str)

        data = self.websocket.send(wsproto.events.TextMessage(data=message))
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=False)
        self.transmit()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            for header, value in event.headers:
                if header == b"sec-websocket-protocol":
                    self.subprotocol = value.decode()
        elif isinstance(event, DataReceived):
            self.websocket.receive_data(event.data)

        for ws_event in self.websocket.events():
            self.websocket_event_received(ws_event)

    def websocket_event_received(self, event: wsproto.events.Event) -> None:
        if isinstance(event, wsproto.events.TextMessage):
            self.queue.put_nowait(event.data)

total_bytes_received = 0     # Total bytes received over the wire
class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        #track
        self.total_received_bytes = 0
        self.handshake_complete_time = None

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: Optional[HttpConnection] = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._websockets: Dict[int, WebSocket] = {}

        if self._quic.configuration.alpn_protocols[0].startswith("hq-"):
            self._http = H0Connection(self._quic)
        else:
            self._http = H3Connection(self._quic)

    async def get(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        """
        Perform a GET request.
        """
        return await self._request(
            HttpRequest(method="GET", url=URL(url), headers=headers)
        )

    async def post(
        self, url: str, data: bytes, headers: Optional[Dict] = None
    ) -> Deque[H3Event]:
        """
        Perform a POST request.
        """
        return await self._request(
            HttpRequest(method="POST", url=URL(url), content=data, headers=headers)
        )

    async def websocket(
        self, url: str, subprotocols: Optional[List[str]] = None
    ) -> WebSocket:
        """
        Open a WebSocket.
        """
        request = HttpRequest(method="CONNECT", url=URL(url))
        stream_id = self._quic.get_next_available_stream_id()
        websocket = WebSocket(
            http=self._http, stream_id=stream_id, transmit=self.transmit
        )

        self._websockets[stream_id] = websocket

        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
            (b":protocol", b"websocket"),
            (b"user-agent", USER_AGENT.encode()),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append(
                (b"sec-websocket-protocol", ", ".join(subprotocols).encode())
            )
        self._http.send_headers(stream_id=stream_id, headers=headers)

        self.transmit()

        return websocket

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

            elif stream_id in self._websockets:
                # websocket
                websocket = self._websockets[stream_id]
                websocket.http_event_received(event)

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        # Track received bytes
        if hasattr(event, 'data') and event.data:
            global total_bytes_received
            self.total_received_bytes += len(event.data)
            total_bytes_received += len(event.data)

        if type(event).__name__ == 'HandshakeCompleted':
            self.handshake_complete_time = time.perf_counter_ns()

        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    def get_handshake_time_ms(self, start_time_ns: float) -> Optional[float]:
        """Calculate handshake time if completed"""
        if self.handshake_complete_time:
            return (self.handshake_complete_time - start_time_ns) / 1_000_000
        return None

    async def _request(self, request: HttpRequest) -> Deque[H3Event]:
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.authority.encode()),
                (b":path", request.url.full_path.encode()),
                (b"user-agent", USER_AGENT.encode()),
            ]
            + [(k.encode(), v.encode()) for (k, v) in request.headers.items()],
            end_stream=not request.content,
        )
        if request.content:
            self._http.send_data(
                stream_id=stream_id, data=request.content, end_stream=True
            )

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)


async def perform_http_request(
    client: HttpClient,
    url: str,
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
    handshake_time_ms: Optional[float] = None  
) -> None:
    # Get baseline RECEIVED bytes BEFORE this request
    rx_before = client.total_received_bytes

    # perform request
    start = time.perf_counter_ns()

    if data is not None:
        data_bytes = data.encode()
        http_events = await client.post(
            url,
            data=data_bytes,
            headers={
                "content-length": str(len(data_bytes)),
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        method = "POST"
    else:
        http_events = await client.get(url)
        method = "GET"
    # Calculate time in milliseconds for precision
    request_time_ns = time.perf_counter_ns() - start
    request_time_ms = request_time_ns / 1_000_000

    # Get received bytes AFTER this request
    rx_after = client.total_received_bytes

    # Calculate download bytes FOR THIS REQUEST ONLY
    download_bytes = rx_after - rx_before

    # Calculate goodput (application layer data)
    app_bytes = 0
    for http_event in http_events:
        if isinstance(http_event, DataReceived):
            app_bytes += len(http_event.data)

    metrics = {
        'method': method,
        'url': url,
        'app_bytes': app_bytes,
        'total_received_bytes': download_bytes,
        'request_time_ms': request_time_ms,
    }

    if request_time_ms > 0:
        # Convert nanoseconds to seconds for rate calculations
        request_time_seconds = request_time_ns / 1_000_000_000

        # 1. Download Goodput (application data rate, EXCLUDING handshake)
        metrics['download_goodput_mbps'] = (app_bytes * 8) / request_time_seconds / 1_000_000

        # 2. Download Throughput (total received data rate, EXCLUDING handshake)
        metrics['download_throughput_mbps'] = (download_bytes * 8) / request_time_seconds / 1_000_000

        # 3. Protocol Overhead Percentage
        if download_bytes > 0:
            metrics['protocol_overhead_percent'] = ((download_bytes - app_bytes) / download_bytes) * 100
        else:
            metrics['protocol_overhead_percent'] = 0

        # 4. Effective metrics (INCLUDING handshake if provided)
        if handshake_time_ms is not None:
            total_time_ms = handshake_time_ms + request_time_ms
            total_time_seconds = total_time_ms / 1000

            # Effective Goodput (including handshake)
            metrics['effective_goodput_mbps'] = (app_bytes * 8) / total_time_seconds / 1_000_000

            # Effective Throughput (including handshake)
            metrics['effective_throughput_mbps'] = (download_bytes * 8) / total_time_seconds / 1_000_000

            # Handshake Impact Percentage
            metrics['handshake_impact_percent'] = (handshake_time_ms / total_time_ms) * 100

            # Goodput Reduction due to handshake
            if metrics['download_goodput_mbps'] > 0:
                metrics['goodput_reduction_percent'] = (
                        (metrics['download_goodput_mbps'] - metrics['effective_goodput_mbps']) /
                        metrics['download_goodput_mbps'] * 100
                )
            else:
                metrics['goodput_reduction_percent'] = 0
    else:
        # Handle zero time case
        metrics.update({
            'download_goodput_mbps': 0,
            'download_throughput_mbps': 0,
            'protocol_overhead_percent': 0,
        })
        if handshake_time_ms is not None:
            metrics.update({
                'effective_goodput_mbps': 0,
                'effective_throughput_mbps': 0,
                'handshake_impact_percent': 100 if handshake_time_ms > 0 else 0,
                'goodput_reduction_percent': 0,
            })

        # Enhanced logging
    logger.info(f"\n📊 {method} {urlparse(url).path}")
    logger.info(f"   App data: {app_bytes:,} bytes")
    logger.info(f"   Total received: {download_bytes:,} bytes")
    logger.info(f"   Download Goodput: {metrics.get('download_goodput_mbps', 0):.3f} Mbps")
    logger.info(f"   Download Throughput: {metrics.get('download_throughput_mbps', 0):.3f} Mbps")
    logger.info(f"   Protocol Overhead: {metrics.get('protocol_overhead_percent', 0):.1f}%")

    if handshake_time_ms is not None:
        logger.info(f"   Handshake time: {handshake_time_ms:.1f} ms")
        logger.info(f"   Effective Goodput: {metrics.get('effective_goodput_mbps', 0):.3f} Mbps")
        logger.info(f"   Handshake Impact: {metrics.get('handshake_impact_percent', 0):.1f}%")
        logger.info(f"   Goodput Reduction: {metrics.get('goodput_reduction_percent', 0):.1f}%")

    # output response
    if output_dir is not None:
        output_path = os.path.join(
            output_dir, os.path.basename(urlparse(url).path) or "index.html"
        )
        with open(output_path, "wb") as output_file:
            write_response(
                http_events=http_events, include=include, output_file=output_file
            )

    return metrics


def process_http_pushes(
    client: HttpClient,
    include: bool,
    output_dir: Optional[str],
) -> None:
    for _, http_events in client.pushes.items():
        method = ""
        octets = 0
        path = ""
        for http_event in http_events:
            if isinstance(http_event, DataReceived):
                octets += len(http_event.data)
            elif isinstance(http_event, PushPromiseReceived):
                for header, value in http_event.headers:
                    if header == b":method":
                        method = value.decode()
                    elif header == b":path":
                        path = value.decode()
        logger.info(f"Push received for %s %s : %s bytes", method, path, octets)

        # output response
        if output_dir is not None:
            output_path = os.path.join(
                output_dir, os.path.basename(path) or "index.html"
            )
            with open(output_path, "wb") as output_file:
                write_response(
                    http_events=http_events, include=include, output_file=output_file
                )


def write_response(
    http_events: Deque[H3Event], output_file: BinaryIO, include: bool
) -> None:
    for http_event in http_events:
        if isinstance(http_event, HeadersReceived) and include:
            headers = b""
            for k, v in http_event.headers:
                headers += k + b": " + v + b"\r\n"
            if headers:
                output_file.write(headers + b"\r\n")
        elif isinstance(http_event, DataReceived):
            output_file.write(http_event.data)



TICKET_PATH = "session_ticket.bin"

def save_session_ticket(ticket: SessionTicket) -> None:
    """
    Save the ticket and update saved_time. If this is the first saved ticket,
    initialize first_full_time to now (recording first communication).
    This function is intended to be used as Hypic's session_ticket_handler callback.
    """
    now = int(time.time())
    data = None
    if os.path.exists(TICKET_PATH):
        try:
            with open(TICKET_PATH, "rb") as f:
                data = pickle.load(f)
        except Exception:
            data = None

    enable_pq = None
    for ext_type, ext_value in ticket.other_extensions:
        if ext_type == ExtensionType.PQ_KEY_SHARE:
            enable_pq = True
            break



    if not data:
        # first time we get a ticket: mark first_full_time
        data = {
            "ticket": ticket,
            "first_full_time": now,
            "saved_time": now,
            "enable_pq": enable_pq
        }
    else:
        # update ticket and saved_time, but keep the original first_full_time unchanged
        data["ticket"] = ticket
        data["saved_time"] = now
        data["enable_pq"] = enable_pq

    with open(TICKET_PATH, "wb") as f:
        pickle.dump(data, f)

def load_session_ticket(TICKET_PATH, MAX_RPQH_PERIOD) -> Tuple[Optional[SessionTicket], Optional[bool]]:
    """
    Load the ticket object if it exists and if the policy says resume is allowed.
    Return:
      - SessionTicket object if client SHOULD attempt resumed handshake (ticket present and first_full_time within MAX_FIRST_PERIOD)
      - False if the client must perform a fresh (initial) handshake (no ticket or period expired)
    The client can call this before building ClientHello and deciding whether to include PSK.
    """
    if not os.path.exists(TICKET_PATH):
        logger.error("[client] No stored ticket found -> will perform initial PQ handshake")
        return None, False

    try:
        with open(TICKET_PATH, "rb") as f:
            data = pickle.load(f)
    except Exception:
        logger.error("[client] Failed to read ticket file -> delete and perform initial handshake")
        try:
            os.remove(TICKET_PATH)
        except Exception:
            pass
        return None, False

    now = int(time.time())
    first = data.get("first_full_time", None)
    ticket = data.get("ticket", None)
    ticket_enable_pq=data.get("enable_pq", None)


    if first is None:
        # If for some reason first_full_time is missing, treat as initial required
        logger.info("[client] first_full_time missing -> perform initial PQ handshake")
        return ticket, False

    if not ticket_enable_pq:
        return ticket, False

    age = now - first
    if age > MAX_RPQH_PERIOD and pq_enable:
        # more than allowed period since first initial handshake -> force initial handshake
        logging.info(f"First_full_time = {age}s > {MAX_RPQH_PERIOD}s -> Initial PQ Handshake")
        delete_session_ticket()
        return None, False

    # else OK to attempt resumed handshake
    logger.info(f"First_full_time = {age}s -> Resumed PQ Handshake") if pq_enable else None
    # delete_session_ticket()
    return ticket, True


def delete_session_ticket() -> None:
    if os.path.exists(TICKET_PATH):
        try:
            os.remove(TICKET_PATH)
        except Exception as exc:
            raise exc


async def main(
    configuration: QuicConfiguration,
    urls: List[str],
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
    local_port: int,
    zero_rtt: bool,
) -> None:
    # parse URL
    parsed = urlparse(urls[0])
    assert parsed.scheme in (
        "https",
        "wss",
    ), "Only https:// or wss:// URLs are supported."
    host = parsed.hostname
    if parsed.port is not None:
        port = parsed.port
    else:
        port = 443

    # check validity of 2nd urls and later.
    for i in range(1, len(urls)):
        _p = urlparse(urls[i])

        # fill in if empty
        _scheme = _p.scheme or parsed.scheme
        _host = _p.hostname or host
        _port = _p.port or port

        assert _scheme == parsed.scheme, "URL scheme doesn't match"
        assert _host == host, "URL hostname doesn't match"
        assert _port == port, "URL port doesn't match"

        # reconstruct url with new hostname and port
        _p = _p._replace(scheme=_scheme)
        _p = _p._replace(netloc="{}:{}".format(_host, _port))
        _p = urlparse(_p.geturl())
        urls[i] = _p.geturl()

    handshake_start = time.perf_counter_ns()

    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
        session_ticket_handler=save_session_ticket,
        local_port=local_port,
        wait_connected=not zero_rtt,
    ) as client:
        client = cast(HttpClient, client)

        precise_time = client.get_handshake_time_ms(handshake_start)
        handshake_time_ms = precise_time or ((time.perf_counter_ns() - handshake_start) / 1_000_000)


        if parsed.scheme == "wss":
            ws = await client.websocket(urls[0], subprotocols=["chat", "superchat"])

            # send some messages and receive reply
            for i in range(2):
                message = "Hello {}, WebSocket!".format(i)
                print("> " + message)
                await ws.send(message)

                message = await ws.recv()
                print("< " + message)

            await ws.close()
        else:
            # perform request
            coros = [
                perform_http_request(
                    client=client,
                    url=url,
                    data=data,
                    include=include,
                    output_dir=output_dir,
                    handshake_time_ms=handshake_time_ms,
                )
                for url in urls
            ]
            await asyncio.gather(*coros)

            # process http pushes
            process_http_pushes(client=client, include=include, output_dir=output_dir)
        client.close(error_code=ErrorCode.H3_NO_ERROR)


if __name__ == "__main__":
    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(description="HTTP/3 client")
    parser.add_argument(
        "url", type=str, nargs="+", help="the URL to query (must be HTTPS)"
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument(
        "--certificate",
        type=str,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "--cipher-suites",
        type=str,
        help=(
            "only advertise the given cipher suites, e.g. `AES_256_GCM_SHA384,"
            "CHACHA20_POLY1305_SHA256`"
        ),
    )
    parser.add_argument(
        "--congestion-control-algorithm",
        type=str,
        default="reno",
        help="use the specified congestion control algorithm",
    )
    parser.add_argument(
        "-d", "--data", type=str, help="send the specified data in a POST request"
    )
    parser.add_argument(
        "-i",
        "--include",
        action="store_true",
        help="include the HTTP response headers in the output",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "--legacy-http",
        action="store_true",
        help="use HTTP/0.9",
    )
    parser.add_argument(
        "--max-data",
        type=int,
        help="connection-wide flow control limit (default: %d)" % defaults.max_data,
    )
    parser.add_argument(
        "--max-stream-data",
        type=int,
        help="per-stream flow control limit (default: %d)" % defaults.max_stream_data,
    )
    parser.add_argument(
        "--negotiate-v2",
        action="store_true",
        help="start with QUIC v1 and try to negotiate QUIC v2",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        help="write downloaded files to this directory",
    )
    parser.add_argument(
        "--private-key",
        type=str,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s", "--session-ticket",
        nargs="?",
        const=TICKET_PATH,
        default=None,
        help="Session ticket file (default: session_ticket.bin)"
    )
    # Max RPQH period
    parser.add_argument(
        "--max-rpqh-period",
        type=int,
        default=60,
        help="Maximum RPQH validity period in seconds (default: 60; used only if session_ticket is enabled)"
    )

    parser.add_argument(
        "--enable-pq",
        nargs="?",  # optional value
        const="KYBER512",  # default if just --enable-pq is used
        default=False,  # default if flag not given
        help="Enable post-quantum KEM. Optionally provide version, e.g., --enable-pq KYBER1024. Default is KYBER768."
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=0,
        help="local port to bind for connections",
    )
    parser.add_argument(
        "--max-datagram-size",
        type=int,
        default=defaults.max_datagram_size,
        help="maximum datagram size to send, excluding UDP or IP overhead",
    )
    parser.add_argument(
        "--zero-rtt", action="store_true", help="try to send requests using 0-RTT"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.output_dir is not None and not os.path.isdir(args.output_dir):
        raise Exception("%s is not a directory" % args.output_dir)

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H0_ALPN if args.legacy_http else H3_ALPN,
        congestion_control_algorithm=args.congestion_control_algorithm,
        max_datagram_size=args.max_datagram_size,
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.cipher_suites:
        configuration.cipher_suites = [
            CipherSuite[s] for s in args.cipher_suites.split(",")
        ]
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.max_data:
        configuration.max_data = args.max_data
    if args.max_stream_data:
        configuration.max_stream_data = args.max_stream_data
    if args.negotiate_v2:
        configuration.original_version = QuicProtocolVersion.VERSION_1
        configuration.supported_versions = [
            QuicProtocolVersion.VERSION_2,
            QuicProtocolVersion.VERSION_1,
        ]
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")

    if args.enable_pq:
        pq_enable = True
        configuration.enable_pq = True
        configuration.pq_kem = (
            args.enable_pq.upper()
        )
    else:
        configuration.enable_pq = False
        configuration.pq_kem = None

    if args.session_ticket:
        ticket, VALID_TIME_RPQH = load_session_ticket(args.session_ticket, args.max_rpqh_period)
        if ticket:
            configuration.session_ticket = ticket
            configuration.VALID_TIME_RPQH = VALID_TIME_RPQH
    else:
        configuration.session_ticket = None
        configuration.MAX_RPQH_PERIOD = None

    # load SSL certificate and key
    if args.certificate is not None:
        configuration.load_cert_chain(args.certificate, args.private_key)

    if uvloop is not None:
        uvloop.install()
    asyncio.run(
        main(
            configuration=configuration,
            urls=args.url,
            data=args.data,
            include=args.include,
            output_dir=args.output_dir,
            local_port=args.local_port,
            zero_rtt=args.zero_rtt,
        )
    )
