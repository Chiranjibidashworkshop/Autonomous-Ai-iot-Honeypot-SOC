from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

from .models import HoneypotEvent

LOGGER = logging.getLogger(__name__)
Emit = Callable[[HoneypotEvent], Awaitable[None]]


async def safe_close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
        # Normal for scanners/clients that disconnect immediately.
        pass


class BaseListener:
    def __init__(self, bind: str, port: int, persona: str, emit: Emit) -> None:
        self.bind = bind
        self.port = port
        self.persona = persona
        self.emit = emit


class HTTPListener(BaseListener):
    async def start(self) -> None:
        server = await asyncio.start_server(self.handle, self.bind, self.port)
        LOGGER.info("HTTP honeypot listening on %s:%s", self.bind, self.port)
        async with server:
            await server.serve_forever()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
            src_ip, src_port = peer[0], peer[1]
            try:
                data = await asyncio.wait_for(reader.read(8192), timeout=5)
            except asyncio.TimeoutError:
                data = b""
            text = data.decode("utf-8", errors="replace")
            first_line = text.splitlines()[0] if text.splitlines() else ""
            parts = first_line.split()
            method = parts[0] if parts else "UNKNOWN"
            path = parts[1] if len(parts) > 1 else "/"
            event = HoneypotEvent(
                src_ip, src_port, "HTTP", self.port, "http_request", self.persona,
                len(data), 0, 1 if method in {"POST", "PUT", "DELETE"} else 0, 1,
                path, first_line[:500]
            )
            await self.emit(event)
            body = (
                f"<html><head><title>{self.persona} IoT Console</title></head>"
                f"<body style='font-family:Arial'><h1>{self.persona} management interface</h1>"
                f"<p>Firmware: 2.3.17</p><p>Status: OK</p><p>Device ID: EDGE-{self.port}</p></body></html>"
            )
            resp = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(body.encode())}\r\nConnection: close\r\n\r\n{body}"
            writer.write(resp.encode())
            await writer.drain()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass
        finally:
            await safe_close(writer)


class BannerListener(BaseListener):
    def __init__(self, *args: Any, banner: str, protocol: str, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.banner = banner
        self.protocol = protocol

    async def start(self) -> None:
        server = await asyncio.start_server(self.handle, self.bind, self.port)
        LOGGER.info("%s honeypot listening on %s:%s", self.protocol, self.bind, self.port)
        async with server:
            await server.serve_forever()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
            src_ip, src_port = peer[0], peer[1]
            writer.write(self.banner.encode())
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=5)
            except asyncio.TimeoutError:
                data = b""
            command = data.decode("utf-8", errors="replace").strip()
            failed_auth = 1 if command.lower().startswith(("login", "user ", "pass ", "admin")) else 0
            event = HoneypotEvent(
                src_ip, src_port, self.protocol, self.port, "session", self.persona,
                len(data), len(self.banner.encode()), failed_auth, 1 if command else 0, "", command[:500]
            )
            await self.emit(event)
            if self.protocol == "TELNET":
                writer.write(b"login: admin\r\npassword: \r\nLogin incorrect\r\n")
            elif self.protocol == "FTP":
                writer.write(b"530 Login incorrect\r\n")
            else:
                writer.write(b"Permission denied\r\n")
            await writer.drain()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass
        finally:
            await safe_close(writer)


class MQTTListener(BaseListener):
    async def start(self) -> None:
        server = await asyncio.start_server(self.handle, self.bind, self.port)
        LOGGER.info("MQTT honeypot listening on %s:%s", self.bind, self.port)
        async with server:
            await server.serve_forever()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
            src_ip, src_port = peer[0], peer[1]
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=4)
            except asyncio.TimeoutError:
                data = b""
            packet_type = (data[0] >> 4) if data else 0
            event_type = "mqtt_connect" if packet_type == 1 else "mqtt_packet"
            event = HoneypotEvent(src_ip, src_port, "MQTT", self.port, event_type, self.persona, len(data), 4, 1 if packet_type == 1 else 0, 1 if data else 0, "", f"packet_type={packet_type}")
            await self.emit(event)
            writer.write(b"\x20\x02\x00\x00")
            await writer.drain()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass
        finally:
            await safe_close(writer)
