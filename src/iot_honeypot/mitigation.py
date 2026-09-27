from __future__ import annotations

import ipaddress
import subprocess
import threading
import time
from dataclasses import dataclass


@dataclass
class MitigationResult:
    action: str
    applied: bool
    message: str


class IPTablesMitigator:
    CHAIN = "IOT_HONEYPOT_AUTO"

    def __init__(self, enabled: bool, dry_run: bool, block_seconds: int, allow_private: bool, whitelist: str):
        self.enabled = enabled
        self.dry_run = dry_run
        self.block_seconds = block_seconds
        self.allow_private = allow_private
        self.whitelist = self._parse_networks(whitelist)
        self.expiries: dict[str, float] = {}
        self._ensure_chain()
        self.thread = threading.Thread(target=self._reaper, daemon=True)
        self.thread.start()

    @staticmethod
    def _parse_networks(text: str) -> list[ipaddress._BaseNetwork]:
        out = []
        for item in [x.strip() for x in text.split(",") if x.strip()]:
            try:
                out.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                try:
                    out.append(ipaddress.ip_network(f"{item}/32"))
                except ValueError:
                    continue
        return out

    def _protected(self, ip: str) -> bool:
        try:
            obj = ipaddress.ip_address(ip)
            if obj.version != 4:
                return True
            if not self.allow_private and (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_reserved):
                return True
            return any(obj in net for net in self.whitelist)
        except ValueError:
            return True

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, capture_output=True, text=True, timeout=4, check=False)

    def _ensure_chain(self) -> None:
        if not self.enabled or self.dry_run:
            return
        check = self._run(["iptables", "-S", self.CHAIN])
        if check.returncode != 0:
            self._run(["iptables", "-N", self.CHAIN])
        jump_check = self._run(["iptables", "-C", "INPUT", "-j", self.CHAIN])
        if jump_check.returncode != 0:
            self._run(["iptables", "-I", "INPUT", "1", "-j", self.CHAIN])

    def block(self, ip: str, reason: str) -> MitigationResult:
        if self._protected(ip):
            return MitigationResult("BLOCK_SKIPPED", False, "Protected/local/allowlisted source")
        if not self.enabled:
            return MitigationResult("BLOCK", False, "Mitigation disabled")
        if self.dry_run:
            return MitigationResult("BLOCK", False, f"DRY_RUN: would block {ip}; reason={reason}")
        try:
            check = self._run(["iptables", "-C", self.CHAIN, "-s", ip, "-j", "DROP"])
            if check.returncode != 0:
                result = self._run(["iptables", "-I", self.CHAIN, "1", "-s", ip, "-j", "DROP"])
                if result.returncode != 0:
                    return MitigationResult("BLOCK_FAILED", False, result.stderr.strip() or "iptables failed")
            self.expiries[ip] = time.time() + self.block_seconds
            return MitigationResult("BLOCK", True, f"Blocked {ip} for about {self.block_seconds}s")
        except (OSError, subprocess.SubprocessError) as exc:
            return MitigationResult("BLOCK_FAILED", False, str(exc))

    def unblock(self, ip: str) -> None:
        if not self.enabled or self.dry_run:
            return
        self._run(["iptables", "-D", self.CHAIN, "-s", ip, "-j", "DROP"])

    def _reaper(self) -> None:
        while True:
            now = time.time()
            expired = [ip for ip, exp in self.expiries.items() if exp <= now]
            for ip in expired:
                self.unblock(ip)
                self.expiries.pop(ip, None)
            time.sleep(5)
