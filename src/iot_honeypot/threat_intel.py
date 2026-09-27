from __future__ import annotations

import ipaddress
import time
from typing import Any

import requests


DEMO_INTEL = {
    "198.51.100.10": {"country": "United States", "city": "New York", "asn": "AS64500", "org": "Demo Threat Research Lab", "abuse_score": 91, "reports": 144, "lat": 40.7128, "lon": -74.0060},
    "198.51.100.20": {"country": "China", "city": "Beijing", "asn": "AS64501", "org": "Synthetic Edge Botnet", "abuse_score": 84, "reports": 93, "lat": 39.9042, "lon": 116.4074},
    "198.51.100.30": {"country": "Russia", "city": "Moscow", "asn": "AS64502", "org": "Synthetic Credential Crew", "abuse_score": 78, "reports": 81, "lat": 55.7558, "lon": 37.6173},
    "203.0.113.40": {"country": "Germany", "city": "Berlin", "asn": "AS64503", "org": "Synthetic Scanner Network", "abuse_score": 62, "reports": 51, "lat": 52.5200, "lon": 13.4050},
    "203.0.113.50": {"country": "Singapore", "city": "Singapore", "asn": "AS64504", "org": "Synthetic IoT Lab", "abuse_score": 71, "reports": 64, "lat": 1.3521, "lon": 103.8198},
    "192.0.2.60": {"country": "India", "city": "Bengaluru", "asn": "AS64505", "org": "Synthetic Red Team Lab", "abuse_score": 55, "reports": 38, "lat": 12.9716, "lon": 77.5946},
    "192.0.2.70": {"country": "Brazil", "city": "Sao Paulo", "asn": "AS64506", "org": "Synthetic Probe Network", "abuse_score": 69, "reports": 44, "lat": -23.5505, "lon": -46.6333},
    "192.0.2.80": {"country": "Netherlands", "city": "Amsterdam", "asn": "AS64507", "org": "Synthetic C2 Research", "abuse_score": 73, "reports": 59, "lat": 52.3676, "lon": 4.9041},
}


class ThreatIntel:
    def __init__(self, abuseipdb_key: str = "", virustotal_key: str = "", geo_enabled: bool = True, demo_mode: bool = False):
        self.abuseipdb_key = abuseipdb_key
        self.virustotal_key = virustotal_key
        self.geo_enabled = geo_enabled
        self.demo_mode = demo_mode
        self.cache: dict[str, tuple[float, dict[str, Any]]] = {}

    @staticmethod
    def safe_target(ip: str) -> bool:
        try:
            obj = ipaddress.ip_address(ip)
            return obj.version == 4 and not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_reserved)
        except ValueError:
            return False

    def lookup(self, ip: str) -> dict[str, Any]:
        if self.demo_mode and ip in DEMO_INTEL:
            x = DEMO_INTEL[ip]
            return {
                "ip": ip,
                "scope": "synthetic_demo",
                "demo": True,
                "abuse_score": x["abuse_score"],
                "abuse_total_reports": x["reports"],
                "vt_malicious": max(2, x["abuse_score"] // 15),
                "vt_suspicious": max(1, x["abuse_score"] // 30),
                "geo": {"country": x["country"], "city": x["city"], "asn": x["asn"], "org": x["org"], "lat": x["lat"], "lon": x["lon"]},
                "sources": ["Synthetic TI", "Demo GeoIP"],
            }

        if not self.safe_target(ip):
            return {"ip": ip, "scope": "local_or_reserved", "abuse_score": 0, "sources": []}

        cached = self.cache.get(ip)
        if cached and time.time() - cached[0] < 600:
            return cached[1]
        result: dict[str, Any] = {"ip": ip, "abuse_score": 0, "sources": []}

        if self.geo_enabled:
            try:
                r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
                if r.ok:
                    data = r.json()
                    result["geo"] = {
                        "country": data.get("country_name"),
                        "city": data.get("city"),
                        "asn": data.get("asn"),
                        "org": data.get("org"),
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude"),
                    }
                    result["sources"].append("ipapi.co")
            except requests.RequestException:
                pass

        if self.abuseipdb_key:
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    timeout=5,
                )
                if r.ok:
                    data = r.json().get("data", {})
                    result["abuse_score"] = int(data.get("abuseConfidenceScore", 0) or 0)
                    result["abuse_total_reports"] = int(data.get("totalReports", 0) or 0)
                    result["sources"].append("AbuseIPDB")
            except requests.RequestException:
                pass

        if self.virustotal_key:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": self.virustotal_key},
                    timeout=5,
                )
                if r.ok:
                    attrs = r.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    result["vt_malicious"] = int(stats.get("malicious", 0) or 0)
                    result["vt_suspicious"] = int(stats.get("suspicious", 0) or 0)
                    result["sources"].append("VirusTotal")
            except requests.RequestException:
                pass

        self.cache[ip] = (time.time(), result)
        return result
