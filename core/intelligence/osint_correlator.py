#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔍  SIREN OSINT CORRELATOR — Cross-Source Intelligence Fusion  🔍            ██
██                                                                                ██
██  Correlação de inteligência cross-source para enriquecimento de alvos.         ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Identity resolution — liga email, username, domain, IP ao mesmo entity   ██
██    • Breach correlation — verifica exposição em breaches conhecidos            ██
██    • Technology fingerprint — enrichment via passive DNS, cert transparency   ██
██    • Social graph — mapeia relações entre entidades                           ██
██    • Timeline reconstruction — ordena eventos cross-source                    ██
██    • Risk scoring — pontuação de risco baseada em exposure data               ██
██                                                                                ██
██  Fontes (passivas, sem interação direta):                                     ██
██    • DNS records & passive DNS                                                ██
██    • Certificate Transparency logs                                            ██
██    • WHOIS data                                                               ██
██    • Public breach databases (HIBP-style)                                     ██
██    • Technology fingerprints (Wappalyzer-style)                               ██
██    • Public code repositories (GitHub/GitLab dorking patterns)                ██
██                                                                                ██
██  "SIREN não vê apenas o alvo — vê o ECOSSISTEMA."                             ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Deque, Dict, FrozenSet, List, Optional, Set, Tuple, Union

logger = logging.getLogger("siren.intelligence.osint_correlator")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

THREAD_POOL_SIZE = 4
MAX_ENTITY_CACHE = 50_000
IDENTITY_MERGE_THRESHOLD = 0.70
TIMELINE_MAX_EVENTS = 100_000


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class EntityType(Enum):
    """Types of OSINT entities."""
    DOMAIN = auto()
    SUBDOMAIN = auto()
    IP_ADDRESS = auto()
    EMAIL = auto()
    USERNAME = auto()
    ORGANIZATION = auto()
    PERSON = auto()
    CERTIFICATE = auto()
    TECHNOLOGY = auto()
    PORT_SERVICE = auto()
    ASN = auto()
    NAMESERVER = auto()
    CODE_REPO = auto()
    SOCIAL_PROFILE = auto()
    PHONE = auto()


class SourceType(Enum):
    """Intelligence source types."""
    DNS_RECORD = auto()
    PASSIVE_DNS = auto()
    CERT_TRANSPARENCY = auto()
    WHOIS = auto()
    BREACH_DB = auto()
    TECH_FINGERPRINT = auto()
    CODE_SEARCH = auto()
    SOCIAL_MEDIA = auto()
    SHODAN_CENSYS = auto()
    MANUAL_INPUT = auto()
    SCAN_RESULT = auto()
    PUBLIC_RECORD = auto()


class RelationType(Enum):
    """Relationship types between entities."""
    RESOLVES_TO = auto()       # domain → IP
    HAS_SUBDOMAIN = auto()     # domain → subdomain
    REGISTERED_BY = auto()     # domain → email/org
    HOSTS = auto()             # IP → domain/service
    USES_TECH = auto()         # domain → technology
    HAS_CERT = auto()          # domain → certificate
    SHARES_IP = auto()         # domain ↔ domain (same IP)
    SHARES_NAMESERVER = auto() # domain ↔ domain
    SHARES_CERT = auto()       # domain ↔ domain (SAN)
    LINKS_TO = auto()          # generic association
    OWNED_BY = auto()          # entity → org/person
    EXPOSED_IN = auto()        # email → breach
    AUTHORED_BY = auto()       # code_repo → person
    MEMBER_OF = auto()         # person → organization
    PART_OF_ASN = auto()       # IP → ASN


class ConfidenceLevel(Enum):
    """Confidence in a piece of intelligence."""
    CONFIRMED = auto()    # Verified from multiple sources
    HIGH = auto()         # Strong single source
    MEDIUM = auto()       # Plausible, needs verification
    LOW = auto()          # Weak signal
    SPECULATIVE = auto()  # Inference only


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class OSINTEntity:
    """An entity in the OSINT graph."""
    entity_id: str
    entity_type: EntityType
    value: str                               # The actual value (domain, email, IP, etc.)
    metadata: Dict[str, Any] = field(default_factory=dict)
    sources: Set[SourceType] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    tags: Set[str] = field(default_factory=set)
    risk_score: float = 0.0                  # [0, 1]
    aliases: Set[str] = field(default_factory=set)

    def merge_from(self, other: OSINTEntity) -> None:
        """Merge another entity's data into this one."""
        self.sources.update(other.sources)
        self.tags.update(other.tags)
        self.aliases.update(other.aliases)
        self.aliases.add(other.value)
        self.metadata.update(other.metadata)
        self.last_seen = max(self.last_seen, other.last_seen)
        self.first_seen = min(self.first_seen, other.first_seen)
        # Upgrade confidence if other is higher
        confidence_order = [
            ConfidenceLevel.SPECULATIVE, ConfidenceLevel.LOW,
            ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH,
            ConfidenceLevel.CONFIRMED,
        ]
        if confidence_order.index(other.confidence) > confidence_order.index(self.confidence):
            self.confidence = other.confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.name,
            "value": self.value,
            "metadata": self.metadata,
            "sources": [s.name for s in self.sources],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": self.confidence.name,
            "tags": list(self.tags),
            "risk_score": self.risk_score,
            "aliases": list(self.aliases),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> OSINTEntity:
        return cls(
            entity_id=d["entity_id"],
            entity_type=EntityType[d["entity_type"]],
            value=d["value"],
            metadata=d.get("metadata", {}),
            sources={SourceType[s] for s in d.get("sources", [])},
            first_seen=d.get("first_seen", 0.0),
            last_seen=d.get("last_seen", 0.0),
            confidence=ConfidenceLevel[d.get("confidence", "MEDIUM")],
            tags=set(d.get("tags", [])),
            risk_score=d.get("risk_score", 0.0),
            aliases=set(d.get("aliases", [])),
        )


@dataclass
class OSINTRelation:
    """A relationship between two OSINT entities."""
    relation_id: str
    source_entity_id: str
    target_entity_id: str
    relation_type: RelationType
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    source: SourceType = SourceType.MANUAL_INPUT
    metadata: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    weight: float = 1.0  # Strength of the relationship

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relation_id": self.relation_id,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "relation_type": self.relation_type.name,
            "confidence": self.confidence.name,
            "source": self.source.name,
            "metadata": self.metadata,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "weight": self.weight,
        }


@dataclass
class TimelineEvent:
    """A timestamped event in the OSINT timeline."""
    event_id: str
    timestamp: float
    entity_id: str
    event_type: str                # "domain_registered", "cert_issued", "breach_detected", etc.
    description: str
    source: SourceType
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "entity_id": self.entity_id,
            "event_type": self.event_type,
            "description": self.description,
            "source": self.source.name,
            "metadata": self.metadata,
        }


@dataclass
class BreachRecord:
    """Record of a breach exposure."""
    breach_name: str
    breach_date: str
    data_types: List[str] = field(default_factory=list)  # email, password, name, etc.
    record_count: int = 0
    source_url: str = ""
    is_verified: bool = False
    is_sensitive: bool = False


@dataclass
class DorkPattern:
    """A search dorking pattern for code/info discovery."""
    pattern_id: str
    platform: str          # github, gitlab, google, shodan
    query_template: str    # Template with {domain}, {org}, {email} placeholders
    category: str          # credentials, config, keys, internal, etc.
    severity: str          # critical, high, medium, low
    description: str = ""

    def render(self, **kwargs: str) -> str:
        """Render the query template with actual values."""
        result = self.query_template
        for key, value in kwargs.items():
            result = result.replace(f"{{{key}}}", value)
        return result


# ════════════════════════════════════════════════════════════════════════════════
# IDENTITY RESOLVER — Link entities to same real-world identity
# ════════════════════════════════════════════════════════════════════════════════

class IdentityResolver:
    """
    Resolves multiple entity references to the same real-world identity.

    Uses transitivity: if A ↔ B and B ↔ C, then A ↔ C.
    Implements Union-Find for efficient identity clustering.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._parent: Dict[str, str] = {}
        self._rank: Dict[str, int] = {}
        self._identity_data: Dict[str, Set[str]] = defaultdict(set)  # root → all members

    def add_entity(self, entity_id: str) -> None:
        """Register an entity."""
        with self._lock:
            if entity_id not in self._parent:
                self._parent[entity_id] = entity_id
                self._rank[entity_id] = 0

    def link(self, entity_a: str, entity_b: str) -> None:
        """Link two entities as belonging to the same identity."""
        with self._lock:
            self.add_entity(entity_a)
            self.add_entity(entity_b)
            root_a = self._find(entity_a)
            root_b = self._find(entity_b)
            if root_a == root_b:
                return
            # Union by rank
            if self._rank[root_a] < self._rank[root_b]:
                self._parent[root_a] = root_b
            elif self._rank[root_a] > self._rank[root_b]:
                self._parent[root_b] = root_a
            else:
                self._parent[root_b] = root_a
                self._rank[root_a] += 1

    def are_same_identity(self, entity_a: str, entity_b: str) -> bool:
        """Check if two entities are the same identity."""
        with self._lock:
            if entity_a not in self._parent or entity_b not in self._parent:
                return False
            return self._find(entity_a) == self._find(entity_b)

    def get_identity_group(self, entity_id: str) -> Set[str]:
        """Get all entities in the same identity group."""
        with self._lock:
            if entity_id not in self._parent:
                return set()
            root = self._find(entity_id)
            group: Set[str] = set()
            for eid, _ in self._parent.items():
                if self._find(eid) == root:
                    group.add(eid)
            return group

    def get_all_groups(self) -> List[Set[str]]:
        """Get all identity groups."""
        with self._lock:
            groups: Dict[str, Set[str]] = defaultdict(set)
            for eid in self._parent:
                root = self._find(eid)
                groups[root].add(eid)
            return [g for g in groups.values() if len(g) > 1]

    def _find(self, entity_id: str) -> str:
        """Find root with path compression."""
        if self._parent[entity_id] != entity_id:
            self._parent[entity_id] = self._find(self._parent[entity_id])
        return self._parent[entity_id]


# ════════════════════════════════════════════════════════════════════════════════
# DORK ENGINE — Code & info dorking patterns
# ════════════════════════════════════════════════════════════════════════════════

class DorkEngine:
    """
    Generates dorking queries for multiple platforms.
    Does NOT execute queries — generates patterns for the user/scanner.
    """

    # Built-in dork patterns
    PATTERNS: List[DorkPattern] = [
        # GitHub dorks
        DorkPattern("gh_passwd", "github", '"{domain}" password OR passwd OR pwd', "credentials", "critical", "Passwords in code"),
        DorkPattern("gh_apikey", "github", '"{domain}" api_key OR apikey OR api_secret', "keys", "critical", "API keys in code"),
        DorkPattern("gh_aws", "github", '"{domain}" AKIA OR aws_secret_access_key', "keys", "critical", "AWS keys in code"),
        DorkPattern("gh_token", "github", '"{domain}" token OR bearer OR authorization', "keys", "high", "Tokens in code"),
        DorkPattern("gh_config", "github", '"{domain}" filename:.env OR filename:.ini OR filename:.conf', "config", "high", "Config files"),
        DorkPattern("gh_sql", "github", '"{domain}" filename:.sql "INSERT INTO" OR "CREATE TABLE"', "internal", "high", "SQL dumps"),
        DorkPattern("gh_private", "github", '"{domain}" "BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY"', "keys", "critical", "Private keys"),
        DorkPattern("gh_internal", "github", '"{domain}" internal OR staging OR dev OR test', "internal", "medium", "Internal references"),
        DorkPattern("gh_jwt", "github", '"{domain}" jwt_secret OR JWT_KEY OR jwt.sign', "keys", "critical", "JWT secrets"),
        DorkPattern("gh_db", "github", '"{domain}" DATABASE_URL OR MONGO_URI OR REDIS_URL', "config", "critical", "DB connection strings"),
        # Shodan dorks
        DorkPattern("sh_default", "shodan", 'hostname:"{domain}" "default password"', "credentials", "high", "Default credentials"),
        DorkPattern("sh_elastic", "shodan", 'hostname:"{domain}" port:9200 "elasticsearch"', "misconfig", "high", "Open Elasticsearch"),
        DorkPattern("sh_mongo", "shodan", 'hostname:"{domain}" port:27017 "MongoDB"', "misconfig", "high", "Open MongoDB"),
        DorkPattern("sh_redis", "shodan", 'hostname:"{domain}" port:6379', "misconfig", "high", "Open Redis"),
        DorkPattern("sh_jenkins", "shodan", 'hostname:"{domain}" "X-Jenkins" "200 OK"', "misconfig", "high", "Open Jenkins"),
        # Google dorks
        DorkPattern("gg_login", "google", 'site:{domain} inurl:login OR inurl:admin OR inurl:panel', "internal", "medium", "Login pages"),
        DorkPattern("gg_filetype", "google", 'site:{domain} filetype:pdf OR filetype:xlsx OR filetype:docx', "internal", "low", "Documents"),
        DorkPattern("gg_dir", "google", 'site:{domain} intitle:"index of" OR intitle:"directory listing"', "misconfig", "high", "Directory listings"),
        DorkPattern("gg_error", "google", 'site:{domain} "error" OR "exception" OR "stack trace"', "internal", "medium", "Error pages"),
        DorkPattern("gg_backup", "google", 'site:{domain} filetype:bak OR filetype:old OR filetype:sql', "internal", "high", "Backup files"),
    ]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._custom_patterns: List[DorkPattern] = []

    def add_pattern(self, pattern: DorkPattern) -> None:
        with self._lock:
            self._custom_patterns.append(pattern)

    def generate_dorks(
        self,
        domain: str = "",
        org: str = "",
        email: str = "",
        platform: Optional[str] = None,
        category: Optional[str] = None,
        min_severity: str = "low",
    ) -> List[Dict[str, str]]:
        """Generate all matching dork queries."""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_sev = severity_order.get(min_severity, 1)

        all_patterns = self.PATTERNS + self._custom_patterns
        results: List[Dict[str, str]] = []

        for p in all_patterns:
            if platform and p.platform != platform:
                continue
            if category and p.category != category:
                continue
            if severity_order.get(p.severity, 0) < min_sev:
                continue

            query = p.render(domain=domain, org=org, email=email)
            # Skip if all placeholders are empty
            if "{" in query:
                continue
            results.append({
                "pattern_id": p.pattern_id,
                "platform": p.platform,
                "query": query,
                "category": p.category,
                "severity": p.severity,
                "description": p.description,
            })

        return results


# ════════════════════════════════════════════════════════════════════════════════
# BREACH CORRELATOR — Known breach exposure analysis
# ════════════════════════════════════════════════════════════════════════════════

class BreachCorrelator:
    """
    Correlates entities against known breach data patterns.
    Does NOT access external databases — works with locally provided data.
    """

    # Known major breach signatures (public knowledge)
    KNOWN_BREACHES: Dict[str, BreachRecord] = {
        "linkedin_2012": BreachRecord(
            "LinkedIn 2012", "2012-06-05",
            ["email", "password_hash"], 164_611_595,
        ),
        "adobe_2013": BreachRecord(
            "Adobe 2013", "2013-10-04",
            ["email", "password_encrypted", "name"], 152_445_165,
        ),
        "collection_1": BreachRecord(
            "Collection #1", "2019-01-17",
            ["email", "password"], 772_904_991,
        ),
        "facebook_2019": BreachRecord(
            "Facebook 2019", "2019-04-02",
            ["phone", "name", "email", "location"], 533_000_000,
        ),
        "yahoo_2013": BreachRecord(
            "Yahoo 2013-2014", "2013-08-01",
            ["email", "password_hash", "name", "phone", "security_qa"], 3_000_000_000,
        ),
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._local_breach_data: Dict[str, List[str]] = {}  # email_hash → breach_names

    def add_breach_data(self, email_hash: str, breach_names: List[str]) -> None:
        """Add locally obtained breach data (e.g., from HIBP API results)."""
        with self._lock:
            existing = self._local_breach_data.get(email_hash, [])
            existing.extend(breach_names)
            self._local_breach_data[email_hash] = list(set(existing))

    def check_email_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze breach risk for an email domain (pattern-based, not actual lookup)."""
        analysis: Dict[str, Any] = {
            "domain": domain,
            "risk_factors": [],
            "recommendations": [],
        }

        # Age-based risk (older domains more likely breached)
        analysis["risk_factors"].append(
            "Organization email domain — employees may have breached credentials"
        )
        analysis["recommendations"].append(
            "Check email addresses against HIBP or similar breach notification service"
        )
        analysis["recommendations"].append(
            "Verify credential reuse via password spray with known breach patterns"
        )

        return analysis

    def compute_exposure_score(self, breaches: List[str]) -> float:
        """Compute exposure risk score based on breach list."""
        if not breaches:
            return 0.0
        score = 0.0
        for breach_name in breaches:
            for key, record in self.KNOWN_BREACHES.items():
                if key in breach_name.lower() or breach_name.lower() in record.breach_name.lower():
                    # Weight by data types exposed
                    if "password" in str(record.data_types):
                        score += 0.3
                    if "email" in record.data_types:
                        score += 0.1
                    if "phone" in record.data_types:
                        score += 0.1
                    if record.is_sensitive:
                        score += 0.2
                    break
            else:
                score += 0.15  # Unknown breach, moderate risk
        return min(1.0, score)


# ════════════════════════════════════════════════════════════════════════════════
# TECH ENRICHMENT — Technology stack enrichment from passive data
# ════════════════════════════════════════════════════════════════════════════════

class TechEnrichment:
    """
    Enriches target profiles with technology information from passive sources.
    Analyzes HTTP headers, DNS records, certificate data, etc.
    """

    # Header → technology mapping
    HEADER_SIGNATURES: Dict[str, Dict[str, str]] = {
        "server": {
            "apache": "Apache HTTP Server",
            "nginx": "Nginx",
            "iis": "Microsoft IIS",
            "cloudflare": "Cloudflare",
            "litespeed": "LiteSpeed",
            "openresty": "OpenResty (Nginx)",
            "gunicorn": "Gunicorn (Python)",
            "uvicorn": "Uvicorn (Python ASGI)",
        },
        "x-powered-by": {
            "php": "PHP",
            "asp.net": "ASP.NET",
            "express": "Express.js",
            "next.js": "Next.js",
            "nuxt": "Nuxt.js",
            "django": "Django",
            "flask": "Flask",
            "rails": "Ruby on Rails",
            "spring": "Spring Framework",
            "laravel": "Laravel",
        },
        "x-generator": {
            "wordpress": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
            "ghost": "Ghost CMS",
            "hugo": "Hugo (Static Site)",
        },
    }

    # CNAME patterns → CDN/hosting detection
    CNAME_SIGNATURES: Dict[str, str] = {
        "cloudfront.net": "AWS CloudFront",
        "amazonaws.com": "AWS",
        "azurewebsites.net": "Azure App Service",
        "azure-api.net": "Azure API Management",
        "cloudflare.com": "Cloudflare",
        "fastly.net": "Fastly CDN",
        "akamaiedge.net": "Akamai CDN",
        "googleapis.com": "Google Cloud",
        "firebaseapp.com": "Firebase",
        "herokuapp.com": "Heroku",
        "netlify.app": "Netlify",
        "vercel.app": "Vercel",
        "github.io": "GitHub Pages",
        "shopify.com": "Shopify",
        "wpengine.com": "WP Engine",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()

    def analyze_headers(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Extract technologies from HTTP response headers."""
        techs: List[Dict[str, str]] = []
        for header_name, signatures in self.HEADER_SIGNATURES.items():
            value = headers.get(header_name, "").lower()
            if not value:
                # Try case-insensitive header lookup
                for h, v in headers.items():
                    if h.lower() == header_name:
                        value = v.lower()
                        break
            if value:
                for sig, tech_name in signatures.items():
                    if sig in value:
                        techs.append({
                            "technology": tech_name,
                            "source": f"header:{header_name}",
                            "raw_value": value,
                            "confidence": "high",
                        })
        # Security headers analysis
        security_headers = [
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options",
            "x-xss-protection", "referrer-policy",
            "permissions-policy",
        ]
        present = sum(1 for h in security_headers if any(
            k.lower() == h for k in headers
        ))
        techs.append({
            "technology": f"security_headers:{present}/{len(security_headers)}",
            "source": "header_analysis",
            "raw_value": f"{present} of {len(security_headers)} present",
            "confidence": "confirmed",
        })
        return techs

    def analyze_cname(self, cname_records: List[str]) -> List[Dict[str, str]]:
        """Detect CDN/hosting from CNAME records."""
        techs: List[Dict[str, str]] = []
        for cname in cname_records:
            cname_lower = cname.lower()
            for pattern, provider in self.CNAME_SIGNATURES.items():
                if pattern in cname_lower:
                    techs.append({
                        "technology": provider,
                        "source": "cname",
                        "raw_value": cname,
                        "confidence": "confirmed",
                    })
                    break
        return techs

    def analyze_cert(self, cert_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract intelligence from certificate data."""
        techs: List[Dict[str, str]] = []
        issuer = cert_data.get("issuer", "").lower()
        san = cert_data.get("san", [])

        # CA identification
        ca_map = {
            "let's encrypt": "Let's Encrypt (Free SSL)",
            "digicert": "DigiCert (Enterprise SSL)",
            "sectigo": "Sectigo/Comodo",
            "godaddy": "GoDaddy",
            "amazon": "AWS Certificate Manager",
            "google trust": "Google Trust Services",
            "cloudflare": "Cloudflare SSL",
        }
        for pattern, ca_name in ca_map.items():
            if pattern in issuer:
                techs.append({
                    "technology": ca_name,
                    "source": "certificate_issuer",
                    "raw_value": issuer,
                    "confidence": "confirmed",
                })
                break

        # SAN analysis — additional domains
        if len(san) > 1:
            techs.append({
                "technology": f"multi_domain_cert:{len(san)}_domains",
                "source": "certificate_san",
                "raw_value": ", ".join(san[:5]),
                "confidence": "confirmed",
            })

        return techs


# ════════════════════════════════════════════════════════════════════════════════
# OSINT GRAPH — The cross-source intelligence graph
# ════════════════════════════════════════════════════════════════════════════════

class OSINTGraph:
    """
    Thread-safe directed graph for OSINT entity relationships.
    Supports graph traversal, clustering, and pattern detection.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entities: Dict[str, OSINTEntity] = {}
        self._relations: Dict[str, OSINTRelation] = {}
        self._adjacency: Dict[str, List[str]] = defaultdict(list)  # entity_id → [relation_ids]
        self._reverse_adj: Dict[str, List[str]] = defaultdict(list)  # target_id → [relation_ids]

    def add_entity(self, entity: OSINTEntity) -> str:
        """Add or update an entity. Returns entity_id."""
        with self._lock:
            existing = self._entities.get(entity.entity_id)
            if existing:
                existing.merge_from(entity)
                return existing.entity_id
            self._entities[entity.entity_id] = entity
            return entity.entity_id

    def add_relation(self, relation: OSINTRelation) -> str:
        """Add a relationship. Returns relation_id."""
        with self._lock:
            self._relations[relation.relation_id] = relation
            self._adjacency[relation.source_entity_id].append(relation.relation_id)
            self._reverse_adj[relation.target_entity_id].append(relation.relation_id)
            return relation.relation_id

    def get_entity(self, entity_id: str) -> Optional[OSINTEntity]:
        with self._lock:
            return self._entities.get(entity_id)

    def get_entity_by_value(self, value: str) -> Optional[OSINTEntity]:
        """Find entity by its value (domain, email, IP, etc.)."""
        with self._lock:
            for entity in self._entities.values():
                if entity.value == value or value in entity.aliases:
                    return entity
        return None

    def get_neighbors(self, entity_id: str, relation_type: Optional[RelationType] = None) -> List[Tuple[OSINTEntity, OSINTRelation]]:
        """Get all entities connected to this one (outgoing)."""
        with self._lock:
            results: List[Tuple[OSINTEntity, OSINTRelation]] = []
            for rel_id in self._adjacency.get(entity_id, []):
                rel = self._relations.get(rel_id)
                if rel and (relation_type is None or rel.relation_type == relation_type):
                    target = self._entities.get(rel.target_entity_id)
                    if target:
                        results.append((target, rel))
            return results

    def get_incoming(self, entity_id: str) -> List[Tuple[OSINTEntity, OSINTRelation]]:
        """Get all entities pointing to this one (incoming)."""
        with self._lock:
            results: List[Tuple[OSINTEntity, OSINTRelation]] = []
            for rel_id in self._reverse_adj.get(entity_id, []):
                rel = self._relations.get(rel_id)
                if rel:
                    source = self._entities.get(rel.source_entity_id)
                    if source:
                        results.append((source, rel))
            return results

    def bfs(self, start_id: str, max_depth: int = 3) -> Dict[str, int]:
        """BFS from entity, returns {entity_id: depth}."""
        with self._lock:
            visited: Dict[str, int] = {start_id: 0}
            queue: deque = deque([(start_id, 0)])
            while queue:
                current, depth = queue.popleft()
                if depth >= max_depth:
                    continue
                for rel_id in self._adjacency.get(current, []):
                    rel = self._relations.get(rel_id)
                    if rel and rel.target_entity_id not in visited:
                        visited[rel.target_entity_id] = depth + 1
                        queue.append((rel.target_entity_id, depth + 1))
                for rel_id in self._reverse_adj.get(current, []):
                    rel = self._relations.get(rel_id)
                    if rel and rel.source_entity_id not in visited:
                        visited[rel.source_entity_id] = depth + 1
                        queue.append((rel.source_entity_id, depth + 1))
            return visited

    def find_shared_infrastructure(self) -> List[Dict[str, Any]]:
        """Find domains sharing infrastructure (IP, nameserver, cert)."""
        with self._lock:
            shared: Dict[str, List[str]] = defaultdict(list)
            for rel in self._relations.values():
                if rel.relation_type in (
                    RelationType.SHARES_IP,
                    RelationType.SHARES_NAMESERVER,
                    RelationType.SHARES_CERT,
                ):
                    key = f"{rel.relation_type.name}:{rel.target_entity_id}"
                    shared[key].append(rel.source_entity_id)

            results: List[Dict[str, Any]] = []
            for key, entities in shared.items():
                if len(entities) > 1:
                    rtype, target = key.split(":", 1)
                    results.append({
                        "type": rtype,
                        "shared_resource": target,
                        "entities": entities,
                        "count": len(entities),
                    })
            return results

    def get_attack_surface(self, root_domain: str) -> Dict[str, Any]:
        """Build attack surface map from a root domain."""
        with self._lock:
            entity = self.get_entity_by_value(root_domain)
            if not entity:
                return {"error": "Domain not found in graph"}

            reachable = self.bfs(entity.entity_id, max_depth=4)
            surface: Dict[str, List[Dict[str, str]]] = defaultdict(list)

            for eid, depth in reachable.items():
                e = self._entities.get(eid)
                if e:
                    surface[e.entity_type.name].append({
                        "value": e.value,
                        "depth": str(depth),
                        "risk_score": str(e.risk_score),
                        "confidence": e.confidence.name,
                    })

            return {
                "root_domain": root_domain,
                "total_entities": len(reachable),
                "surface": dict(surface),
            }

    def entity_count(self) -> int:
        with self._lock:
            return len(self._entities)

    def relation_count(self) -> int:
        with self._lock:
            return len(self._relations)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "entities": {k: v.to_dict() for k, v in self._entities.items()},
                "relations": {k: v.to_dict() for k, v in self._relations.items()},
            }


# ════════════════════════════════════════════════════════════════════════════════
# SIREN OSINT CORRELATOR — Main orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenOSINTCorrelator:
    """
    Main orchestrator for OSINT correlation.

    Coordinates:
    - Entity extraction and graph building
    - Identity resolution across sources
    - Dorking query generation
    - Breach exposure analysis
    - Technology enrichment
    - Timeline reconstruction
    - Attack surface mapping
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._graph = OSINTGraph()
        self._identity_resolver = IdentityResolver()
        self._dork_engine = DorkEngine()
        self._breach_correlator = BreachCorrelator()
        self._tech_enrichment = TechEnrichment()
        self._timeline: Deque[TimelineEvent] = deque(maxlen=TIMELINE_MAX_EVENTS)
        self._executor = ThreadPoolExecutor(
            max_workers=THREAD_POOL_SIZE,
            thread_name_prefix="siren-osint",
        )
        self._entity_counter = 0

    def ingest_domain(
        self,
        domain: str,
        subdomains: Optional[List[str]] = None,
        dns_records: Optional[Dict[str, List[str]]] = None,
        whois_data: Optional[Dict[str, Any]] = None,
        cert_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Ingest domain intelligence from multiple sources.
        Builds entity graph, resolves identities, enriches technology.
        """
        with self._lock:
            results: Dict[str, Any] = {"domain": domain, "entities_created": 0, "relations_created": 0}

            # 1) Core domain entity
            domain_entity = self._create_entity(EntityType.DOMAIN, domain, {SourceType.SCAN_RESULT})
            self._graph.add_entity(domain_entity)
            results["entities_created"] += 1

            # 2) Subdomains
            if subdomains:
                for sub in subdomains:
                    sub_entity = self._create_entity(EntityType.SUBDOMAIN, sub, {SourceType.DNS_RECORD})
                    self._graph.add_entity(sub_entity)
                    rel = self._create_relation(
                        domain_entity.entity_id, sub_entity.entity_id,
                        RelationType.HAS_SUBDOMAIN, SourceType.DNS_RECORD,
                    )
                    self._graph.add_relation(rel)
                    results["entities_created"] += 1
                    results["relations_created"] += 1

            # 3) DNS records
            if dns_records:
                for record_type, values in dns_records.items():
                    for val in values:
                        if record_type.upper() in ("A", "AAAA"):
                            ip_entity = self._create_entity(EntityType.IP_ADDRESS, val, {SourceType.DNS_RECORD})
                            self._graph.add_entity(ip_entity)
                            rel = self._create_relation(
                                domain_entity.entity_id, ip_entity.entity_id,
                                RelationType.RESOLVES_TO, SourceType.DNS_RECORD,
                            )
                            self._graph.add_relation(rel)
                            results["entities_created"] += 1
                            results["relations_created"] += 1
                        elif record_type.upper() == "CNAME":
                            techs = self._tech_enrichment.analyze_cname([val])
                            for tech in techs:
                                tech_entity = self._create_entity(
                                    EntityType.TECHNOLOGY, tech["technology"],
                                    {SourceType.DNS_RECORD},
                                )
                                self._graph.add_entity(tech_entity)
                                rel = self._create_relation(
                                    domain_entity.entity_id, tech_entity.entity_id,
                                    RelationType.USES_TECH, SourceType.DNS_RECORD,
                                )
                                self._graph.add_relation(rel)
                                results["entities_created"] += 1
                                results["relations_created"] += 1
                        elif record_type.upper() in ("NS",):
                            ns_entity = self._create_entity(EntityType.NAMESERVER, val, {SourceType.DNS_RECORD})
                            self._graph.add_entity(ns_entity)
                            rel = self._create_relation(
                                domain_entity.entity_id, ns_entity.entity_id,
                                RelationType.SHARES_NAMESERVER, SourceType.DNS_RECORD,
                            )
                            self._graph.add_relation(rel)
                            results["entities_created"] += 1
                            results["relations_created"] += 1
                        elif record_type.upper() == "MX":
                            # MX reveals mail infrastructure
                            mx_entity = self._create_entity(EntityType.DOMAIN, val, {SourceType.DNS_RECORD})
                            mx_entity.tags.add("mail_server")
                            self._graph.add_entity(mx_entity)
                            results["entities_created"] += 1

            # 4) WHOIS data
            if whois_data:
                registrant_email = whois_data.get("registrant_email", "")
                registrant_org = whois_data.get("registrant_org", "")
                if registrant_email and registrant_email != "REDACTED":
                    email_entity = self._create_entity(
                        EntityType.EMAIL, registrant_email, {SourceType.WHOIS},
                    )
                    self._graph.add_entity(email_entity)
                    rel = self._create_relation(
                        domain_entity.entity_id, email_entity.entity_id,
                        RelationType.REGISTERED_BY, SourceType.WHOIS,
                    )
                    self._graph.add_relation(rel)
                    self._identity_resolver.add_entity(email_entity.entity_id)
                    results["entities_created"] += 1
                    results["relations_created"] += 1

                if registrant_org:
                    org_entity = self._create_entity(
                        EntityType.ORGANIZATION, registrant_org, {SourceType.WHOIS},
                    )
                    self._graph.add_entity(org_entity)
                    rel = self._create_relation(
                        domain_entity.entity_id, org_entity.entity_id,
                        RelationType.OWNED_BY, SourceType.WHOIS,
                    )
                    self._graph.add_relation(rel)
                    results["entities_created"] += 1
                    results["relations_created"] += 1

                # Timeline: domain registration
                reg_date = whois_data.get("creation_date")
                if reg_date:
                    self._add_timeline_event(
                        domain_entity.entity_id, "domain_registered",
                        f"Domain {domain} registered", SourceType.WHOIS,
                    )

            # 5) Certificate data
            if cert_data:
                techs = self._tech_enrichment.analyze_cert(cert_data)
                for tech in techs:
                    tech_entity = self._create_entity(
                        EntityType.TECHNOLOGY, tech["technology"],
                        {SourceType.CERT_TRANSPARENCY},
                    )
                    self._graph.add_entity(tech_entity)
                    results["entities_created"] += 1

                # SAN domains as related entities
                san = cert_data.get("san", [])
                for san_domain in san:
                    if san_domain != domain:
                        san_entity = self._create_entity(
                            EntityType.DOMAIN, san_domain,
                            {SourceType.CERT_TRANSPARENCY},
                        )
                        self._graph.add_entity(san_entity)
                        rel = self._create_relation(
                            domain_entity.entity_id, san_entity.entity_id,
                            RelationType.SHARES_CERT, SourceType.CERT_TRANSPARENCY,
                        )
                        self._graph.add_relation(rel)
                        results["entities_created"] += 1
                        results["relations_created"] += 1

            # 6) HTTP headers tech enrichment
            if headers:
                techs = self._tech_enrichment.analyze_headers(headers)
                for tech in techs:
                    tech_entity = self._create_entity(
                        EntityType.TECHNOLOGY, tech["technology"],
                        {SourceType.TECH_FINGERPRINT},
                    )
                    self._graph.add_entity(tech_entity)
                    rel = self._create_relation(
                        domain_entity.entity_id, tech_entity.entity_id,
                        RelationType.USES_TECH, SourceType.TECH_FINGERPRINT,
                    )
                    self._graph.add_relation(rel)
                    results["entities_created"] += 1
                    results["relations_created"] += 1

            return results

    def generate_dorks(
        self, domain: str, org: str = "", email: str = "",
        platform: Optional[str] = None, min_severity: str = "medium",
    ) -> List[Dict[str, str]]:
        """Generate dorking queries for a target."""
        return self._dork_engine.generate_dorks(
            domain=domain, org=org, email=email,
            platform=platform, min_severity=min_severity,
        )

    def get_attack_surface(self, domain: str) -> Dict[str, Any]:
        """Get full attack surface map for a domain."""
        return self._graph.get_attack_surface(domain)

    def find_shared_infrastructure(self) -> List[Dict[str, Any]]:
        """Find shared infrastructure across targets."""
        return self._graph.find_shared_infrastructure()

    def get_timeline(self, entity_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get timeline of events, optionally filtered by entity."""
        events = list(self._timeline)
        if entity_id:
            events = [e for e in events if e.entity_id == entity_id]
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return [e.to_dict() for e in events[:limit]]

    def get_identity_groups(self) -> List[Set[str]]:
        """Get all resolved identity groups."""
        return self._identity_resolver.get_all_groups()

    def get_stats(self) -> Dict[str, int]:
        """Get OSINT graph statistics."""
        return {
            "entities": self._graph.entity_count(),
            "relations": self._graph.relation_count(),
            "timeline_events": len(self._timeline),
            "identity_groups": len(self._identity_resolver.get_all_groups()),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph": self._graph.to_dict(),
            "timeline": [e.to_dict() for e in self._timeline],
            "stats": self.get_stats(),
        }

    # ── Private helpers ─────────────────────────────────────────────────────

    def _create_entity(
        self, etype: EntityType, value: str, sources: Set[SourceType],
    ) -> OSINTEntity:
        self._entity_counter += 1
        eid = hashlib.md5(f"{etype.name}:{value}".encode()).hexdigest()[:16]
        return OSINTEntity(
            entity_id=eid,
            entity_type=etype,
            value=value,
            sources=sources,
        )

    def _create_relation(
        self, source_id: str, target_id: str,
        rtype: RelationType, source: SourceType,
    ) -> OSINTRelation:
        rid = hashlib.md5(
            f"{source_id}:{target_id}:{rtype.name}".encode()
        ).hexdigest()[:16]
        return OSINTRelation(
            relation_id=rid,
            source_entity_id=source_id,
            target_entity_id=target_id,
            relation_type=rtype,
            source=source,
        )

    def _add_timeline_event(
        self, entity_id: str, event_type: str,
        description: str, source: SourceType,
    ) -> None:
        eid = hashlib.md5(
            f"{entity_id}:{event_type}:{time.time()}".encode()
        ).hexdigest()[:16]
        event = TimelineEvent(
            event_id=eid,
            timestamp=time.time(),
            entity_id=entity_id,
            event_type=event_type,
            description=description,
            source=source,
        )
        self._timeline.append(event)
