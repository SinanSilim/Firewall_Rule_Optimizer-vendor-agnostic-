#!/usr/bin/env python3
"""
Firewall Rule Optimizer (Vendor‑Agnostic)
=========================================

A practical, single‑file Python tool to **ingest firewall rule exports** from
multiple vendors (FortiGate, Palo Alto, Cisco ASA/FTD, Check Point), **normalize**
them to a common model, run **optimizations/health checks**, and produce a
**human‑readable report** with actionable recommendations.

Key capabilities
----------------
- **Parsers / Adapters** (CSV/JSON) for common exports:
  - FortiGate policy CSV export (PolicyID, SrcAddr, DstAddr, Service, Action, Log, Disabled, Comment, UUID, Hit Count)
  - Palo Alto CSV export (name, source, destination, application, service, action, log-setting, disabled, hit-count)
  - Cisco ASA/FTD ACL CSV (access-list like rows: src, dst, protocol/port, action, hits)
  - Check Point CSV export (Source, Destination, Services & Applications, Action, Enabled, Hits)
  - **Generic** CSV with columns: id, name, src, dst, service, action, disabled, log, hits, position
- **Object map support** (optional JSON/YAML): resolve named objects/groups to IPs/CIDRs and services.
- **Normalization** to vendor-agnostic schema (Rule model), including:
  - IP/network sets (IPv4/IPv6), wildcards (any), service ranges with protocol
  - Rule position (order), action (allow/deny), disabled/log flags, hit counts
- **Analyses**:
  - Duplicate rules (exact match)
  - Shadowed rules (earlier superset covering later rule)
  - Redundant subsets (same action, later rule fully covered by earlier specific rules)
  - Over‑permissive (any‑any‑any allow)
  - Broad networks (e.g., /0, /8, /16 configurable)
  - Unused rules (hit count == 0)
  - Disabled rules inventory
  - Logging gaps (allow rules with logging disabled)
  - Merge opportunities (same action/contexts, services or networks can be collapsed)
- **Outputs**:
  - Pretty **Markdown** and/or **HTML** report
  - **CSV** of findings (issue_id, severity, vendor, rule_id, description, recommendation)
  - **Normalized JSON** of rules (for downstream tooling)

Usage examples
--------------
1) Basic run with two files and auto‑detected vendors:
   
   python firewall_rule_optimizer.py \
       --in rules_fgt.csv:fortigate --in rules_pan.csv:panos \
       --out-dir out --report html,md,csv,json \
       --broad-prefix4 8 --broad-prefix6 32 --min-shadow-depth 1

2) With object map (resolve named objects/groups):
   
   python firewall_rule_optimizer.py \
       --in rules_cp.csv:checkpoint --objects objects.yaml \
       --out-dir out --report md

3) Generic CSV:
   
   python firewall_rule_optimizer.py --in rules_generic.csv:generic --out-dir out

Generic CSV columns (minimal):
  id,name,src,dst,service,action,disabled,log,hits,position
- src/dst can be comma‑separated (CIDR/IP/object names resolved via object map)
- service forms: "any" | "tcp/80" | "udp/53" | "tcp/1000-2000" | named (e.g., HTTP, DNS)

Notes
-----
- This tool is intentionally conservative: it **never modifies** device configs.
  It only suggests optimizations; always review before applying.
- Works with Python 3.9+ (uses ipaddress, argparse, json, csv; PyYAML optional).

"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import html
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# Optional YAML support for object maps
try:
    import yaml  # type: ignore
except Exception:
    yaml = None

# ----------------------------- Models --------------------------------------

@dataclass(frozen=True)
class ServiceRange:
    proto: str  # "tcp" | "udp" | "any"
    start: int  # inclusive
    end: int    # inclusive

    def __post_init__(self):
        object.__setattr__(self, "proto", self.proto.lower())
        if self.proto not in {"tcp", "udp", "any"}:
            raise ValueError(f"Invalid proto: {self.proto}")
        if not (0 <= self.start <= 65535 and 0 <= self.end <= 65535 and self.start <= self.end):
            raise ValueError("Invalid port range")

    def covers(self, other: "ServiceRange") -> bool:
        if self.proto == "any":
            return True
        if other.proto == "any":
            return False
        return self.proto == other.proto and self.start <= other.start and self.end >= other.end

    def overlaps(self, other: "ServiceRange") -> bool:
        if self.proto == "any" or other.proto == "any":
            return True
        if self.proto != other.proto:
            return False
        return not (self.end < other.start or other.end < self.start)

    def merged_with(self, other: "ServiceRange") -> Optional["ServiceRange"]:
        if self.proto != other.proto:
            return None
        if max(self.start, other.start) <= min(self.end, other.end) + 1:
            return ServiceRange(self.proto, min(self.start, other.start), max(self.end, other.end))
        return None

    def to_str(self) -> str:
        if self.proto == "any":
            return "any"
        return f"{self.proto}/{self.start}" if self.start == self.end else f"{self.proto}/{self.start}-{self.end}"


ANY4 = ipaddress.ip_network("0.0.0.0/0")
ANY6 = ipaddress.ip_network("::/0")


def _is_any_net(n: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
    return int(n.network_address) == 0 and n.prefixlen == 0


@dataclass
class Rule:
    rule_id: str
    name: str
    vendor: str
    src_nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]
    dst_nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]
    services: List[ServiceRange]
    action: str  # allow|deny (accept/drop/reset)
    disabled: bool = False
    log: Optional[bool] = None
    hits: Optional[int] = None
    position: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)

    def is_any_any_any(self) -> bool:
        return all(_is_any_net(n) for n in self.src_nets) and \
               all(_is_any_net(n) for n in self.dst_nets) and \
               any(s.proto == "any" for s in self.services)


# ---------------------------- Object Map -----------------------------------

class ObjectMap:
    """Resolve object names to networks/services.

    YAML/JSON structure example:
    
    networks:
      HQ_LAN: ["10.0.0.0/24", "10.0.1.0/24"]
      ANY: ["0.0.0.0/0", "::/0"]
    services:
      HTTP: ["tcp/80"]
      DNS: ["tcp/53", "udp/53"]
    """

    def __init__(self, data: Dict[str, Any]):
        self.nets: Dict[str, List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]] = {}
        self.svcs: Dict[str, List[ServiceRange]] = {}
        for k, vals in (data.get("networks") or {}).items():
            self.nets[k.lower()] = [parse_network(v) for v in _ensure_list(vals)]
        for k, vals in (data.get("services") or {}).items():
            self.svcs[k.lower()] = [parse_service(v) for v in _ensure_list(vals)]

    @staticmethod
    def load(path: Optional[Path]) -> Optional["ObjectMap"]:
        if not path:
            return None
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yml", ".yaml"}:
            if yaml is None:
                raise RuntimeError("PyYAML not installed; cannot load YAML object map")
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        return ObjectMap(data)

    def resolve_networks(self, token: str) -> Optional[List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]:
        return self.nets.get(token.lower())

    def resolve_services(self, token: str) -> Optional[List[ServiceRange]]:
        return self.svcs.get(token.lower())


# ---------------------------- Parsing Utils --------------------------------

KNOWN_SERVICE_ALIASES: Dict[str, List[str]] = {
    "http": ["tcp/80"],
    "https": ["tcp/443"],
    "ssh": ["tcp/22"],
    "rdp": ["tcp/3389"],
    "dns": ["udp/53", "tcp/53"],
    "smtp": ["tcp/25"],
    "smtps": ["tcp/465"],
    "imap": ["tcp/143"],
    "imaps": ["tcp/993"],
    "pop3": ["tcp/110"],
    "pop3s": ["tcp/995"],
    "mysql": ["tcp/3306"],
    "mssql": ["tcp/1433"],
    "postgres": ["tcp/5432"],
    "ntp": ["udp/123"],
    "ldap": ["tcp/389"],
    "ldaps": ["tcp/636"],
}


def _ensure_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, (list, tuple, set)):
        return list(x)
    return [x]


def parse_network(token: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    t = token.strip()
    if t.lower() in {"any", "*"}:
        return ANY4  # callers will typically add ANY6 as well where needed
    try:
        # treat single IP as /32 or /128
        if "/" not in t:
            try:
                ip = ipaddress.ip_address(t)
                if isinstance(ip, ipaddress.IPv4Address):
                    return ipaddress.ip_network(f"{t}/32")
                else:
                    return ipaddress.ip_network(f"{t}/128")
            except Exception:
                pass
        return ipaddress.ip_network(t, strict=False)
    except Exception as e:
        raise ValueError(f"Invalid network token: {token!r}: {e}")


def parse_service(token: str, objmap: Optional[ObjectMap] = None) -> ServiceRange:
    t = str(token).strip().lower()
    if objmap:
        svc = objmap.resolve_services(t)
        if svc:
            # take first if multiple; callers can expand repeatedly
            return svc[0]
    if t in {"any", "*", "all"}:
        return ServiceRange("any", 0, 65535)
    if t in KNOWN_SERVICE_ALIASES:
        # Return first alias as representative; expansion handled elsewhere
        alias = KNOWN_SERVICE_ALIASES[t][0]
        return parse_service(alias)
    m = re.match(r"^(tcp|udp)\/(\d+)(?:-(\d+))?$", t)
    if m:
        proto = m.group(1)
        p1 = int(m.group(2))
        p2 = int(m.group(3) or m.group(2))
        return ServiceRange(proto, p1, p2)
    raise ValueError(f"Unsupported service token: {token!r}")


def expand_services(tokens: Sequence[str], objmap: Optional[ObjectMap]) -> List[ServiceRange]:
    svcs: List[ServiceRange] = []
    for tok in tokens:
        tok = tok.strip()
        # resolve named bundle -> list
        if objmap and (resolved := objmap.resolve_services(tok)):
            svcs.extend(resolved)
            continue
        if tok.lower() in KNOWN_SERVICE_ALIASES:
            svcs.extend(parse_service(x) for x in KNOWN_SERVICE_ALIASES[tok.lower()])
            continue
        svcs.append(parse_service(tok, objmap))
    return collapse_service_ranges(svcs)


def collapse_service_ranges(ranges: List[ServiceRange]) -> List[ServiceRange]:
    by_proto: Dict[str, List[ServiceRange]] = defaultdict(list)
    for r in ranges:
        by_proto[r.proto].append(r)
    out: List[ServiceRange] = []
    for proto, lst in by_proto.items():
        lst = sorted(lst, key=lambda r: (r.start, r.end))
        cur: Optional[ServiceRange] = None
        for r in lst:
            if cur is None:
                cur = r
            else:
                merged = cur.merged_with(r)
                if merged:
                    cur = merged
                else:
                    out.append(cur)
                    cur = r
        if cur:
            out.append(cur)
    # if both tcp any and udp any -> any
    if any(r.proto == "any" for r in out):
        return [ServiceRange("any", 0, 65535)]
    return out


def expand_networks(tokens: Sequence[str], objmap: Optional[ObjectMap]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    nets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    for tok in tokens:
        tok = tok.strip()
        if tok == "":
            continue
        if objmap and (resolved := objmap.resolve_networks(tok)):
            nets.extend(resolved)
        else:
            nets.append(parse_network(tok))
    # Add ANY6 if ANY4 present and there wasn't explicit v6
    has_any4 = any(isinstance(n, ipaddress.IPv4Network) and _is_any_net(n) for n in nets)
    has_v6 = any(isinstance(n, ipaddress.IPv6Network) for n in nets)
    if has_any4 and not has_v6:
        nets.append(ANY6)
    # collapse
    v4 = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]
    v4 = list(ipaddress.collapse_addresses(v4))
    v6 = list(ipaddress.collapse_addresses(v6))
    return v4 + v6


# ---------------------------- Vendor Adapters -------------------------------

class BaseAdapter:
    vendor = "generic"

    def parse(self, path: Path, objmap: Optional[ObjectMap]) -> List[Rule]:
        raise NotImplementedError

    @staticmethod
    def _split_list(cell: str) -> List[str]:
        if cell is None:
            return []
        # Split on comma or semicolon, strip quotes/spaces
        parts = re.split(r"[;,]", str(cell))
        return [p.strip().strip('"\'') for p in parts if p.strip()]


class GenericCSVAdapter(BaseAdapter):
    vendor = "generic"

    def parse(self, path: Path, objmap: Optional[ObjectMap]) -> List[Rule]:
        rules: List[Rule] = []
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            pos = 0
            for row in reader:
                pos += 1
                rid = str(row.get("id") or f"{path.name}#{pos}")
                name = row.get("name") or rid
                src = expand_networks(self._split_list(row.get("src") or "any"), objmap)
                dst = expand_networks(self._split_list(row.get("dst") or "any"), objmap)
                svc = expand_services(self._split_list(row.get("service") or "any"), objmap)
                action = (row.get("action") or "allow").lower()
                disabled = str(row.get("disabled") or "false").lower() in {"true", "yes", "1"}
                log_val = row.get("log")
                log = None if log_val is None else str(log_val).lower() in {"true", "yes", "1"}
                hits = None
                if row.get("hits") not in (None, ""):
                    try:
                        hits = int(row.get("hits"))
                    except Exception:
                        hits = None
                try:
                    position = int(row.get("position") or pos)
                except Exception:
                    position = pos
                rules.append(Rule(rid, name, self.vendor, src, dst, svc, action, disabled, log, hits, position, row))
        return rules


class FortiGateCSVAdapter(BaseAdapter):
    vendor = "fortigate"

    def parse(self, path: Path, objmap: Optional[ObjectMap]) -> List[Rule]:
        rules: List[Rule] = []
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            pos = 0
            for row in reader:
                pos += 1
                rid = str(row.get("PolicyID") or row.get("id") or f"{path.name}#{pos}")
                name = row.get("Name") or row.get("name") or rid
                src = expand_networks(self._split_list(row.get("SrcAddr") or row.get("srcaddr") or row.get("src") or "any"), objmap)
                dst = expand_networks(self._split_list(row.get("DstAddr") or row.get("dstaddr") or row.get("dst") or "any"), objmap)
                svc = expand_services(self._split_list(row.get("Service") or row.get("service") or "any"), objmap)
                action = (row.get("Action") or row.get("action") or "accept").lower()
                action = "allow" if action in {"accept", "allow", "permit"} else "deny"
                disabled = str(row.get("Status") or row.get("disabled") or "enable").lower() in {"disable", "disabled", "true", "1"}
                log = None
                if (lv := (row.get("LogTraffic") or row.get("log"))):
                    log = str(lv).lower() not in {"disable", "disabled", "false", "0"}
                hits = None
                if (hv := row.get("Hit Count") or row.get("hit_count") or row.get("hits")):
                    try:
                        hits = int(hv)
                    except Exception:
                        hits = None
                try:
                    position = int(row.get("Seq#") or row.get("position") or pos)
                except Exception:
                    position = pos
                rules.append(Rule(rid, name, self.vendor, src, dst, svc, action, disabled, log, hits, position, row))
        return rules


class PANOSCSVAdapter(BaseAdapter):
    vendor = "panos"

    def parse(self, path: Path, objmap: Optional[ObjectMap]) -> List[Rule]:
        rules: List[Rule] = []
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            pos = 0
            for row in reader:
                pos += 1
                rid = str(row.get("name") or row.get("id") or f"{path.name}#{pos}")
                name = row.get("name") or rid
                src = expand_networks(self._split_list(row.get("source") or "any"), objmap)
                dst = expand_networks(self._split_list(row.get("destination") or "any"), objmap)
                # PAN-OS has application column; here we only use service
                svc_tokens = self._split_list(row.get("service") or "any")
                if "application-default" in [t.lower() for t in svc_tokens]:
                    # Treat as named defaults; keep as any to avoid false negatives
                    svcs = [ServiceRange("any", 0, 65535)]
                else:
                    svcs = expand_services(svc_tokens, objmap)
                action = (row.get("action") or "allow").lower()
                action = "allow" if action in {"allow", "accept", "permit"} else "deny"
                disabled = str(row.get("disabled") or "false").lower() in {"yes", "true", "1"}
                log = None
                if (lv := (row.get("log-setting") or row.get("log") or None)) is not None:
                    log = str(lv).strip() != "" and str(lv).lower() not in {"none", "no", "false", "0"}
                hits = None
                if (hv := row.get("hit-count") or row.get("hits")):
                    try:
                        hits = int(hv)
                    except Exception:
                        hits = None
                rules.append(Rule(rid, name, self.vendor, src, dst, svcs, action, disabled, log, hits, pos, row))
        return rules


class CiscoCSVAdapter(BaseAdapter):
    vendor = "cisco"

    def parse(self, path: Path, objmap: Optional[ObjectMap]) -> List[Rule]:
        rules: List[Rule] = []
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            pos = 0
            for row in reader:
                pos += 1
                rid = str(row.get("id") or f"{path.name}#{pos}")
                name = row.get("name") or rid
                src = expand_networks(self._split_list(row.get("src") or row.get("source") or "any"), objmap)
                dst = expand_networks(self._split_list(row.get("dst") or row.get("destination") or "any"), objmap)
                proto = (row.get("protocol") or "").lower()
                port = (row.get("port") or row.get("dport") or row.get("service") or "any")
                svc_tokens: List[str]
                if proto in {"tcp", "udp"} and port and port != "any":
                    svc_tokens = [f"{proto}/{port}"]
                else:
                    svc_tokens = self._split_list(row.get("service") or "any")
                svcs = expand_services(svc_tokens, objmap)
                action = (row.get("action") or "permit").lower()
                action = "allow" if action in {"permit", "allow", "accept"} else "deny"
                disabled = str(row.get("disabled") or "false").lower() in {"true", "1", "yes"}
                log = None
                if (lv := (row.get("log") or None)) is not None:
                    log = str(lv).lower() in {"true", "1", "yes"}
                hits = None
                if (hv := row.get("hits") or row.get("hit-count")):
                    try:
                        hits = int(hv)
                    except Exception:
                        hits = None
                rules.append(Rule(rid, name, self.vendor, src, dst, svcs, action, disabled, log, hits, pos, row))
        return rules


class CheckPointCSVAdapter(BaseAdapter):
    vendor = "checkpoint"

    def parse(self, path: Path, objmap: Optional[ObjectMap]) -> List[Rule]:
        rules: List[Rule] = []
        with path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            pos = 0
            for row in reader:
                pos += 1
                rid = str(row.get("Name") or row.get("Rule Number") or row.get("id") or f"{path.name}#{pos}")
                name = row.get("Name") or rid
                src = expand_networks(self._split_list(row.get("Source") or row.get("src") or "Any"), objmap)
                dst = expand_networks(self._split_list(row.get("Destination") or row.get("dst") or "Any"), objmap)
                svc_tokens = self._split_list(row.get("Services & Applications") or row.get("service") or "Any")
                svcs = expand_services(svc_tokens, objmap)
                action = (row.get("Action") or "Accept").lower()
                action = "allow" if action in {"accept", "allow", "permit"} else "deny"
                enabled = str(row.get("Enabled") or row.get("enabled") or "true").lower() in {"true", "yes", "1"}
                disabled = not enabled
                log = None
                if (lv := (row.get("Track") or row.get("log"))):
                    log = str(lv).lower() not in {"none", "no", "false", "0"}
                hits = None
                if (hv := row.get("Hits") or row.get("hit-count") or row.get("hits")):
                    try:
                        hits = int(hv)
                    except Exception:
                        hits = None
                rules.append(Rule(rid, name, self.vendor, src, dst, svcs, action, disabled, log, hits, pos, row))
        return rules


ADAPTERS = {
    "generic": GenericCSVAdapter(),
    "fortigate": FortiGateCSVAdapter(),
    "panos": PANOSCSVAdapter(),
    "cisco": CiscoCSVAdapter(),
    "checkpoint": CheckPointCSVAdapter(),
}

# ---------------------------- Analysis Engine ------------------------------

@dataclass
class Finding:
    issue_id: str
    severity: str  # info|low|medium|high|critical
    vendor: str
    rule_ids: List[str]
    title: str
    description: str
    recommendation: str


def networks_cover(a: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
                   b: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]) -> bool:
    """Return True if set A covers set B (every n in B is subset of some in A)."""
    for nb in b:
        if not any(na.version == nb.version and nb.subnet_of(na) for na in a):
            return False
    return True


def services_cover(a: List[ServiceRange], b: List[ServiceRange]) -> bool:
    for sb in b:
        if not any(sa.covers(sb) for sa in a):
            return False
    return True


def rules_equal(a: Rule, b: Rule) -> bool:
    return a.action == b.action and \
           networks_cover(a.src_nets, b.src_nets) and networks_cover(b.src_nets, a.src_nets) and \
           networks_cover(a.dst_nets, b.dst_nets) and networks_cover(b.dst_nets, a.dst_nets) and \
           services_cover(a.services, b.services) and services_cover(b.services, a.services)


def find_duplicates(rules: List[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    seen: List[Rule] = []
    for r in rules:
        for s in seen:
            if rules_equal(r, s) and r.action == s.action and not r.disabled and not s.disabled:
                findings.append(Finding(
                    issue_id=f"DUPLICATE::{r.rule_id}::{s.rule_id}",
                    severity="medium",
                    vendor=r.vendor,
                    rule_ids=[s.rule_id, r.rule_id],
                    title="Duplicate rule",
                    description=f"Rule {r.rule_id} duplicates {s.rule_id} (same match & action).",
                    recommendation=f"Delete {r.rule_id} or consolidate comments; keep earlier rule {s.rule_id}.",
                ))
                break
        seen.append(r)
    return findings


def find_shadowed(rules: List[Rule], *, min_depth: int = 1) -> List[Finding]:
    """Rules fully covered by earlier rules (any action), making them ineffective.
    min_depth: how many positions earlier must the covering rule be (>=1)."""
    findings: List[Finding] = []
    # Sort by position (ascending)
    rules_sorted = sorted(rules, key=lambda r: r.position)
    for idx, r in enumerate(rules_sorted):
        for j in range(0, idx - min_depth + 1):
            prev = rules_sorted[j]
            if prev.disabled:
                continue
            if networks_cover(prev.src_nets, r.src_nets) and \
               networks_cover(prev.dst_nets, r.dst_nets) and \
               services_cover(prev.services, r.services):
                findings.append(Finding(
                    issue_id=f"SHADOW::{r.rule_id}<-{prev.rule_id}",
                    severity="high" if prev.action != r.action else "medium",
                    vendor=r.vendor,
                    rule_ids=[prev.rule_id, r.rule_id],
                    title="Shadowed rule",
                    description=(
                        f"Rule {r.rule_id} is fully covered by earlier rule {prev.rule_id} "
                        f"(prev action {prev.action}, this {r.action})."
                    ),
                    recommendation=f"Disable/remove {r.rule_id} or move above {prev.rule_id} if intentional.",
                ))
                break
    return findings


def find_over_permissive(rules: List[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    for r in rules:
        if not r.disabled and r.action == "allow" and r.is_any_any_any():
            findings.append(Finding(
                issue_id=f"ANYANY::{r.rule_id}",
                severity="critical",
                vendor=r.vendor,
                rule_ids=[r.rule_id],
                title="Over‑permissive allow (any‑any‑any)",
                description=f"Rule {r.rule_id} allows from ANY to ANY on ANY service.",
                recommendation="Tighten sources/destinations/services or restrict by zones and add logging.",
            ))
    return findings


def find_broad_networks(rules: List[Rule], *, broad4: int = 8, broad6: int = 32) -> List[Finding]:
    findings: List[Finding] = []
    for r in rules:
        if r.disabled:
            continue
        for side, nets in (("source", r.src_nets), ("destination", r.dst_nets)):
            for n in nets:
                if isinstance(n, ipaddress.IPv4Network) and n.prefixlen <= broad4:
                    findings.append(Finding(
                        issue_id=f"BROAD::{r.rule_id}::{side}::{n}",
                        severity="medium",
                        vendor=r.vendor,
                        rule_ids=[r.rule_id],
                        title=f"Broad IPv4 {side} network ({n})",
                        description=f"Rule {r.rule_id} uses broad network {n} on {side}.",
                        recommendation=f"Split/limit {n} to smaller CIDRs or specific hosts where possible.",
                    ))
                if isinstance(n, ipaddress.IPv6Network) and n.prefixlen <= broad6:
                    findings.append(Finding(
                        issue_id=f"BROAD6::{r.rule_id}::{side}::{n}",
                        severity="medium",
                        vendor=r.vendor,
                        rule_ids=[r.rule_id],
                        title=f"Broad IPv6 {side} network ({n})",
                        description=f"Rule {r.rule_id} uses broad IPv6 network {n} on {side}.",
                        recommendation=f"Split/limit {n} to narrower prefixes.",
                    ))
    return findings


def find_unused(rules: List[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    for r in rules:
        if r.disabled:
            continue
        if r.hits is not None and r.hits == 0:
            findings.append(Finding(
                issue_id=f"UNUSED::{r.rule_id}",
                severity="low",
                vendor=r.vendor,
                rule_ids=[r.rule_id],
                title="Unused rule (0 hits)",
                description=f"Rule {r.rule_id} shows zero hits in export.",
                recommendation="Review and remove if not required or set to disabled.",
            ))
    return findings


def find_logging_gaps(rules: List[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    for r in rules:
        if r.disabled:
            continue
        if r.action == "allow" and (r.log is False or r.log is None):
            findings.append(Finding(
                issue_id=f"NOLOG::{r.rule_id}",
                severity="low",
                vendor=r.vendor,
                rule_ids=[r.rule_id],
                title="Logging not enabled on allow",
                description=f"Rule {r.rule_id} allows traffic but logging is not enabled or undefined.",
                recommendation="Enable logging for visibility and incident response.",
            ))
    return findings


def merge_opportunities(rules: List[Rule]) -> List[Finding]:
    """Suggest merging rules that share action and one side fully equal while the
    other side can be safely collapsed (e.g., identical src/dst & adjacent services).
    Conservative heuristic: same action, not disabled, identical src & dst sets,
    services that can be represented as fewer ranges.
    """
    findings: List[Finding] = []
    # Group by (vendor, action, src, dst)
    buckets: Dict[Tuple[str, str, str, str], List[Rule]] = defaultdict(list)
    for r in rules:
        if r.disabled:
            continue
        src_key = ",".join(sorted(str(n) for n in r.src_nets))
        dst_key = ",".join(sorted(str(n) for n in r.dst_nets))
        buckets[(r.vendor, r.action, src_key, dst_key)].append(r)

    for key, lst in buckets.items():
        if len(lst) < 2:
            continue
        # Attempt to collapse services across rules
        all_svcs: List[ServiceRange] = []
        for r in lst:
            all_svcs.extend(r.services)
        collapsed = collapse_service_ranges(all_svcs)
        # If collapsed is strictly fewer than total segments across rules, propose merge
        total_segments = sum(1 for r in lst for _ in r.services)
        if len(collapsed) < total_segments:
            rule_ids = [r.rule_id for r in lst]
            rec_svc = ", ".join(s.to_str() for s in collapsed)
            findings.append(Finding(
                issue_id=f"MERGE::{'+'.join(rule_ids)}",
                severity="info",
                vendor=lst[0].vendor,
                rule_ids=rule_ids,
                title="Merge opportunity (services)",
                description=f"Rules {', '.join(rule_ids)} share same src/dst/action; services can be collapsed.",
                recommendation=f"Consolidate into a single rule with services: {rec_svc}.",
            ))
    return findings


# ---------------------------- Reporting ------------------------------------

def write_csv_findings(findings: List[Finding], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["issue_id", "severity", "vendor", "rule_ids", "title", "description", "recommendation"])
        for f in findings:
            w.writerow([f.issue_id, f.severity, f.vendor, ";".join(f.rule_ids), f.title, f.description, f.recommendation])


def write_json_rules(rules: List[Rule], path: Path) -> None:
    def svc_to_dict(s: ServiceRange) -> Dict[str, Any]:
        return dataclasses.asdict(s)
    data = []
    for r in rules:
        data.append({
            "rule_id": r.rule_id,
            "name": r.name,
            "vendor": r.vendor,
            "src": [str(n) for n in r.src_nets],
            "dst": [str(n) for n in r.dst_nets],
            "services": [svc_to_dict(s) for s in r.services],
            "action": r.action,
            "disabled": r.disabled,
            "log": r.log,
            "hits": r.hits,
            "position": r.position,
        })
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_markdown(findings: List[Finding], rules: List[Rule], path: Path) -> None:
    lines: List[str] = []
    lines.append(f"# Firewall Rule Optimizer Report\n")
    lines.append(f"Generated: {dt.datetime.now().isoformat()}\n")
    lines.append(f"Total rules: {len(rules)}  ")
    lines.append(f"Findings: {len(findings)}\n")

    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    findings_sorted = sorted(findings, key=lambda f: (sev_order.get(f.severity, 99), f.vendor, f.issue_id))

    # Summary table
    counts = defaultdict(int)
    for f in findings_sorted:
        counts[f.severity] += 1
    if findings_sorted:
        lines.append("## Summary by severity\n")
        lines.append("| Severity | Count |\n|---|---:|")
        for s in ["critical","high","medium","low","info"]:
            lines.append(f"| {s} | {counts.get(s,0)} |")
        lines.append("")

    lines.append("## Findings\n")
    for f in findings_sorted:
        lines.append(f"### {f.title} ({f.severity.upper()})\n")
        lines.append(f"**Issue ID:** {f.issue_id}  ")
        lines.append(f"**Vendor:** {f.vendor}  ")
        lines.append(f"**Rule IDs:** {', '.join(f.rule_ids)}  ")
        lines.append("")
        lines.append(f"{f.description}\n")
        lines.append(f"**Recommendation:** {f.recommendation}\n")
        lines.append("---\n")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_html(findings: List[Finding], rules: List[Rule], path: Path) -> None:
    def esc(x: str) -> str:
        return html.escape(x)
    sev_color = {
        "critical":"#8B0000",
        "high":"#B22222",
        "medium":"#DAA520",
        "low":"#2E8B57",
        "info":"#1E90FF",
    }
    counts = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1
    parts = []
    parts.append("<html><head><meta charset='utf-8'><title>Firewall Rule Optimizer Report</title>" \
                 "<style>body{font-family:system-ui,Segoe UI,Arial;line-height:1.4;margin:24px} .card{border:1px solid #ddd;border-radius:10px;padding:16px;margin:12px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)} .pill{display:inline-block;padding:2px 8px;border-radius:999px;color:white;font-size:12px;margin-left:8px} table{border-collapse:collapse} th,td{border:1px solid #eee;padding:6px 10px} th{background:#fafafa}</style></head><body>")
    parts.append(f"<h1>Firewall Rule Optimizer Report</h1><p>Generated: {esc(dt.datetime.now().isoformat())}</p>")
    parts.append(f"<p>Total rules: <b>{len(rules)}</b> • Findings: <b>{len(findings)}</b></p>")
    parts.append("<h2>Summary by severity</h2><table><tr><th>Severity</th><th>Count</th></tr>")
    for s in ["critical","high","medium","low","info"]:
        parts.append(f"<tr><td>{esc(s.title())}</td><td style='text-align:right'>{counts.get(s,0)}</td></tr>")
    parts.append("</table>")

    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    for f in sorted(findings, key=lambda f: (sev_order.get(f.severity, 99), f.vendor, f.issue_id)):
        color = sev_color.get(f.severity, "#555")
        parts.append("<div class='card'>")
        parts.append(f"<h3>{esc(f.title)} <span class='pill' style='background:{color}'>{esc(f.severity.upper())}</span></h3>")
        parts.append(f"<p><b>Issue ID:</b> {esc(f.issue_id)}<br><b>Vendor:</b> {esc(f.vendor)}<br><b>Rule IDs:</b> {esc(', '.join(f.rule_ids))}</p>")
        parts.append(f"<p>{esc(f.description)}</p>")
        parts.append(f"<p><b>Recommendation:</b> {esc(f.recommendation)}</p>")
        parts.append("</div>")
    parts.append("</body></html>")
    path.write_text("".join(parts), encoding="utf-8")


# ---------------------------- Orchestration --------------------------------

VENDOR_HELP = "+".join(ADAPTERS.keys())


def load_rules(inputs: List[Tuple[Path, str]], objmap: Optional[ObjectMap]) -> List[Rule]:
    rules: List[Rule] = []
    for path, vendor in inputs:
        adapter = ADAPTERS.get(vendor.lower())
        if not adapter:
            raise ValueError(f"Unknown vendor '{vendor}'. Known: {', '.join(ADAPTERS.keys())}")
        rules.extend(adapter.parse(path, objmap))
    # Normalize positions relative to overall order
    for i, r in enumerate(rules, 1):
        if r.position <= 0:
            r.position = i
    return rules


def run_analyses(rules: List[Rule], *, broad4: int, broad6: int, min_shadow_depth: int) -> List[Finding]:
    findings: List[Finding] = []
    # Run in order of severity signal
    findings.extend(find_over_permissive(rules))
    findings.extend(find_shadowed(rules, min_depth=min_shadow_depth))
    findings.extend(find_duplicates(rules))
    findings.extend(find_broad_networks(rules, broad4=broad4, broad6=broad6))
    findings.extend(find_unused(rules))
    findings.extend(find_logging_gaps(rules))
    findings.extend(merge_opportunities(rules))
    return findings


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Vendor‑agnostic firewall rule optimizer & analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--in", dest="inputs", action="append", required=True,
                   help=f"Input file with vendor suffix: PATH:{{{','.join(ADAPTERS.keys())}}}")
    p.add_argument("--objects", dest="objects", default=None,
                   help="Optional object map (JSON/YAML) to resolve named objects/groups")
    p.add_argument("--out-dir", dest="out_dir", default="out", help="Output folder")
    p.add_argument("--report", dest="report", default="md,html,csv,json",
                   help="Comma‑separated outputs: md,html,csv,json")
    p.add_argument("--broad-prefix4", dest="broad4", type=int, default=8,
                   help="IPv4 'broad network' threshold (prefixlen <= this is flagged)")
    p.add_argument("--broad-prefix6", dest="broad6", type=int, default=32,
                   help="IPv6 'broad network' threshold")
    p.add_argument("--min-shadow-depth", dest="min_shadow", type=int, default=1,
                   help="How many positions earlier must the covering rule be to flag shadowing")

    args = p.parse_args(argv)

    # Parse inputs
    inputs: List[Tuple[Path, str]] = []
    for spec in args.inputs:
        if ":" not in spec:
            p.error("--in requires PATH:vendor (e.g., rules.csv:fortigate)")
        path_s, vendor = spec.rsplit(":", 1)
        path = Path(path_s)
        if not path.exists():
            p.error(f"Input not found: {path}")
        if vendor.lower() not in ADAPTERS:
            p.error(f"Unknown vendor '{vendor}'. Use one of: {', '.join(ADAPTERS.keys())}")
        inputs.append((path, vendor))

    objmap = ObjectMap.load(Path(args.objects)) if args.objects else None

    rules = load_rules(inputs, objmap)

    findings = run_analyses(rules, broad4=args.broad4, broad6=args.broad6, min_shadow_depth=args.min_shadow)

    # Outputs
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    report_kinds = {x.strip().lower() for x in (args.report or "").split(",") if x.strip()}
    if not report_kinds:
        report_kinds = {"md"}

    if "csv" in report_kinds:
        write_csv_findings(findings, out_dir / "findings.csv")
    if "json" in report_kinds:
        write_json_rules(rules, out_dir / "rules_normalized.json")
    if "md" in report_kinds:
        write_markdown(findings, rules, out_dir / "report.md")
    if "html" in report_kinds:
        write_html(findings, rules, out_dir / "report.html")

    print(f"Parsed rules: {len(rules)}")
    print(f"Findings: {len(findings)}")
    print(f"Outputs written to: {out_dir.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
