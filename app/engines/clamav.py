import socket
import struct
import time
from pathlib import Path

from app.config import Settings
from app.engines.base import ScanEngine
from app.models.schemas import EngineResult, EngineStatus


class ClamAVEngine(ScanEngine):
    """Scan files via clamd INSTREAM protocol over TCP."""

    name = "clamav"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._host = settings.clamav_host
        self._port = settings.clamav_port
        self._timeout = settings.clamav_timeout_seconds

    @property
    def enabled(self) -> bool:
        return self._settings.clamav_enabled

    def healthcheck(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        try:
            reply = self._send_command(b"PING")
            ok = reply.strip().upper() == "PONG"
            if not ok:
                return False, reply.strip() or "empty reply"
            version = self.version_info()
            detail = "PONG"
            if version:
                detail = f"PONG; {version}"
            return True, detail
        except OSError as exc:
            return False, str(exc)

    def version_info(self) -> str | None:
        """Return clamd VERSION string (includes signature DB epoch when available)."""
        if not self.enabled:
            return None
        try:
            reply = self._send_command(b"VERSION")
            text = reply.strip()
            return text or None
        except OSError:
            return None

    def scan(self, file_path: Path) -> EngineResult:
        started = time.perf_counter()
        if not self.enabled:
            return EngineResult(
                name=self.name,
                status=EngineStatus.skipped,
                details="ClamAV disabled by configuration",
                duration_ms=0,
            )

        try:
            reply = self._instream(file_path)
            duration_ms = int((time.perf_counter() - started) * 1000)
            return self._parse_reply(reply, duration_ms)
        except OSError as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=str(exc),
                duration_ms=duration_ms,
            )

    def _parse_reply(self, reply: str, duration_ms: int) -> EngineResult:
        text = reply.strip()
        # Typical: "stream: OK" or "stream: Win.Trojan.X FOUND"
        if text.endswith("OK"):
            return EngineResult(
                name=self.name,
                status=EngineStatus.clean,
                details=text,
                duration_ms=duration_ms,
            )
        if "FOUND" in text:
            threat = text
            if ":" in text:
                threat = text.split(":", 1)[1].replace("FOUND", "").strip()
            return EngineResult(
                name=self.name,
                status=EngineStatus.infected,
                threats=[threat] if threat else [text],
                details=text,
                duration_ms=duration_ms,
            )
        if "ERROR" in text.upper():
            return EngineResult(
                name=self.name,
                status=EngineStatus.error,
                details=text,
                duration_ms=duration_ms,
            )
        return EngineResult(
            name=self.name,
            status=EngineStatus.error,
            details=f"Unexpected ClamAV reply: {text}",
            duration_ms=duration_ms,
        )

    def _instream(self, file_path: Path) -> str:
        chunk_size = 2048
        with socket.create_connection((self._host, self._port), timeout=self._timeout) as sock:
            sock.settimeout(self._timeout)
            sock.sendall(b"zINSTREAM\0")
            with file_path.open("rb") as handle:
                while True:
                    chunk = handle.read(chunk_size)
                    if not chunk:
                        break
                    sock.sendall(struct.pack(">I", len(chunk)) + chunk)
            sock.sendall(struct.pack(">I", 0))
            data = self._recv_all(sock)
        return data.decode("utf-8", errors="replace")

    def _send_command(self, command: bytes) -> str:
        payload = command if command.endswith(b"\0") else command + b"\0"
        with socket.create_connection((self._host, self._port), timeout=self._timeout) as sock:
            sock.settimeout(self._timeout)
            sock.sendall(payload)
            data = self._recv_all(sock)
        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _recv_all(sock: socket.socket) -> bytes:
        chunks: list[bytes] = []
        while True:
            try:
                part = sock.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            chunks.append(part)
            if b"\0" in part or part.endswith(b"\n"):
                break
        return b"".join(chunks).rstrip(b"\0\n")
