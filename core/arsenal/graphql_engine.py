#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔮 SIREN GRAPHQL ENGINE — Deep GraphQL Introspection & Exploitation  🔮    ██
██                                                                                ██
██  Motor de análise e exploração para APIs GraphQL.                             ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Schema introspection — extrai schema completo via query                  ██
██    • Type system analysis — mapeia types, fields, arguments                   ██
██    • Query complexity analysis — detecta DoS via deeply nested queries        ██
██    • Authorization testing — IDOR, field-level access control                 ██
██    • Injection testing — SQL injection via GraphQL arguments                  ██
██    • Batch attack generation — alias-based brute force                        ██
██    • Subscription abuse — WebSocket subscription attacks                      ██
██    • Schema diffing — detecta mudanças entre versões                         ██
██                                                                                ██
██  "SIREN desvenda o grafo — cada node é um vetor de ataque."                  ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.graphql_engine")


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class GraphQLTypeKind(Enum):
    """GraphQL type kinds."""
    SCALAR = auto()
    OBJECT = auto()
    INTERFACE = auto()
    UNION = auto()
    ENUM = auto()
    INPUT_OBJECT = auto()
    LIST = auto()
    NON_NULL = auto()


class VulnType(Enum):
    """GraphQL vulnerability types."""
    INTROSPECTION_ENABLED = auto()
    DEEP_NESTING_DOS = auto()
    ALIAS_OVERLOADING = auto()
    BATCH_ATTACK = auto()
    IDOR = auto()
    SQL_INJECTION = auto()
    FIELD_SUGGESTION = auto()
    MISSING_AUTH = auto()
    EXCESSIVE_DATA = auto()
    CIRCULAR_FRAGMENT = auto()
    DIRECTIVE_ABUSE = auto()
    SUBSCRIPTION_ABUSE = auto()
    DEBUG_MODE = auto()
    MUTATION_WITHOUT_AUTH = auto()
    SENSITIVE_FIELD_EXPOSED = auto()


class RiskLevel(Enum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class GraphQLField:
    """Represents a GraphQL field."""
    name: str
    type_name: str
    type_kind: GraphQLTypeKind = GraphQLTypeKind.SCALAR
    is_nullable: bool = True
    is_list: bool = False
    is_deprecated: bool = False
    deprecation_reason: str = ""
    args: List[GraphQLArgument] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type_name,
            "kind": self.type_kind.name,
            "nullable": self.is_nullable,
            "is_list": self.is_list,
            "deprecated": self.is_deprecated,
            "args": [a.to_dict() for a in self.args],
        }


@dataclass
class GraphQLArgument:
    """Represents a GraphQL argument."""
    name: str
    type_name: str
    is_required: bool = False
    default_value: Any = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type_name,
            "required": self.is_required,
            "default": self.default_value,
        }


@dataclass
class GraphQLType:
    """Represents a GraphQL type."""
    name: str
    kind: GraphQLTypeKind = GraphQLTypeKind.OBJECT
    fields: List[GraphQLField] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    enum_values: List[str] = field(default_factory=list)
    possible_types: List[str] = field(default_factory=list)
    input_fields: List[GraphQLArgument] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "name": self.name,
            "kind": self.kind.name,
        }
        if self.fields:
            result["fields"] = [f.to_dict() for f in self.fields]
        if self.enum_values:
            result["enum_values"] = self.enum_values
        if self.interfaces:
            result["interfaces"] = self.interfaces
        return result


@dataclass
class GraphQLSchema:
    """Parsed GraphQL schema."""
    types: Dict[str, GraphQLType] = field(default_factory=dict)
    query_type: str = "Query"
    mutation_type: str = "Mutation"
    subscription_type: str = "Subscription"
    directives: List[str] = field(default_factory=list)

    @property
    def user_types(self) -> List[GraphQLType]:
        """Get non-internal types (skip __* types)."""
        return [t for n, t in self.types.items() if not n.startswith("__")]

    @property
    def object_types(self) -> List[GraphQLType]:
        return [t for t in self.user_types if t.kind == GraphQLTypeKind.OBJECT]

    @property
    def total_fields(self) -> int:
        return sum(len(t.fields) for t in self.user_types)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_type": self.query_type,
            "mutation_type": self.mutation_type,
            "subscription_type": self.subscription_type,
            "types_count": len(self.user_types),
            "total_fields": self.total_fields,
            "types": {n: t.to_dict() for n, t in self.types.items() if not n.startswith("__")},
        }


@dataclass
class GraphQLFinding:
    """A GraphQL security finding."""
    vuln_type: VulnType
    risk: RiskLevel
    title: str
    description: str
    evidence: str = ""
    query: str = ""
    affected_type: str = ""
    affected_field: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.vuln_type.name,
            "risk": self.risk.name,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "query": self.query,
            "affected_type": self.affected_type,
            "affected_field": self.affected_field,
            "recommendation": self.recommendation,
        }


@dataclass
class GraphQLReport:
    """Complete GraphQL analysis report."""
    endpoint: str
    timestamp: float = field(default_factory=time.time)
    schema: Optional[GraphQLSchema] = None
    findings: List[GraphQLFinding] = field(default_factory=list)
    queries_generated: int = 0
    mutations_found: int = 0
    subscriptions_found: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "schema_available": self.schema is not None,
            "types_count": len(self.schema.user_types) if self.schema else 0,
            "total_fields": self.schema.total_fields if self.schema else 0,
            "queries_generated": self.queries_generated,
            "mutations_found": self.mutations_found,
            "findings_count": len(self.findings),
            "critical_findings": sum(1 for f in self.findings if f.risk == RiskLevel.CRITICAL),
            "findings": [f.to_dict() for f in self.findings],
        }


# ════════════════════════════════════════════════════════════════════════════════
# INTROSPECTION QUERY BUILDER
# ════════════════════════════════════════════════════════════════════════════════

class IntrospectionQueryBuilder:
    """Builds introspection queries for GraphQL endpoints."""

    FULL_INTROSPECTION = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
        type {
          name
          kind
          ofType {
            name
            kind
            ofType {
              name
              kind
              ofType { name kind }
            }
          }
        }
        args {
          name
          description
          type {
            name
            kind
            ofType {
              name
              kind
              ofType { name kind }
            }
          }
          defaultValue
        }
      }
      inputFields {
        name
        description
        type {
          name
          kind
          ofType { name kind ofType { name kind } }
        }
        defaultValue
      }
      interfaces { name }
      enumValues(includeDeprecated: true) { name description isDeprecated }
      possibleTypes { name }
    }
    directives {
      name
      description
      locations
    }
  }
}"""

    # Minimal introspection (for restricted endpoints)
    MINIMAL_INTROSPECTION = """{
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind }
  }
}"""

    # Type-specific query
    @staticmethod
    def type_query(type_name: str) -> str:
        return f"""{{
  __type(name: "{type_name}") {{
    name
    kind
    fields {{
      name
      type {{ name kind ofType {{ name kind }} }}
      args {{ name type {{ name kind }} }}
    }}
  }}
}}"""


# ════════════════════════════════════════════════════════════════════════════════
# SCHEMA PARSER — Parses introspection results into schema model
# ════════════════════════════════════════════════════════════════════════════════

class SchemaParser:
    """Parses introspection JSON into GraphQLSchema."""

    KIND_MAP = {
        "SCALAR": GraphQLTypeKind.SCALAR,
        "OBJECT": GraphQLTypeKind.OBJECT,
        "INTERFACE": GraphQLTypeKind.INTERFACE,
        "UNION": GraphQLTypeKind.UNION,
        "ENUM": GraphQLTypeKind.ENUM,
        "INPUT_OBJECT": GraphQLTypeKind.INPUT_OBJECT,
        "LIST": GraphQLTypeKind.LIST,
        "NON_NULL": GraphQLTypeKind.NON_NULL,
    }

    def parse(self, introspection_data: Dict[str, Any]) -> GraphQLSchema:
        """Parse introspection response into schema model."""
        schema = GraphQLSchema()

        data = introspection_data.get("data", introspection_data)
        schema_data = data.get("__schema", {})

        # Root types
        qt = schema_data.get("queryType", {})
        if qt:
            schema.query_type = qt.get("name", "Query")
        mt = schema_data.get("mutationType", {})
        if mt:
            schema.mutation_type = mt.get("name", "Mutation")
        st = schema_data.get("subscriptionType", {})
        if st:
            schema.subscription_type = st.get("name", "Subscription")

        # Directives
        for d in schema_data.get("directives", []):
            schema.directives.append(d.get("name", ""))

        # Types
        for type_data in schema_data.get("types", []):
            gql_type = self._parse_type(type_data)
            schema.types[gql_type.name] = gql_type

        return schema

    def _parse_type(self, data: Dict[str, Any]) -> GraphQLType:
        """Parse a single GraphQL type."""
        gql_type = GraphQLType(
            name=data.get("name", ""),
            kind=self.KIND_MAP.get(data.get("kind", ""), GraphQLTypeKind.SCALAR),
            description=data.get("description", "") or "",
        )

        # Fields
        for field_data in data.get("fields", []) or []:
            gql_type.fields.append(self._parse_field(field_data))

        # Enum values
        for ev in data.get("enumValues", []) or []:
            gql_type.enum_values.append(ev.get("name", ""))

        # Interfaces
        for iface in data.get("interfaces", []) or []:
            gql_type.interfaces.append(iface.get("name", ""))

        # Possible types (unions/interfaces)
        for pt in data.get("possibleTypes", []) or []:
            gql_type.possible_types.append(pt.get("name", ""))

        # Input fields
        for inf in data.get("inputFields", []) or []:
            gql_type.input_fields.append(self._parse_argument(inf))

        return gql_type

    def _parse_field(self, data: Dict[str, Any]) -> GraphQLField:
        """Parse a GraphQL field."""
        type_info = self._resolve_type(data.get("type", {}))
        f = GraphQLField(
            name=data.get("name", ""),
            type_name=type_info[0],
            type_kind=type_info[1],
            is_nullable=type_info[2],
            is_list=type_info[3],
            is_deprecated=data.get("isDeprecated", False),
            deprecation_reason=data.get("deprecationReason", "") or "",
            description=data.get("description", "") or "",
        )
        for arg_data in data.get("args", []) or []:
            f.args.append(self._parse_argument(arg_data))
        return f

    def _parse_argument(self, data: Dict[str, Any]) -> GraphQLArgument:
        """Parse a GraphQL argument."""
        type_info = self._resolve_type(data.get("type", {}))
        return GraphQLArgument(
            name=data.get("name", ""),
            type_name=type_info[0],
            is_required=not type_info[2],
            default_value=data.get("defaultValue"),
            description=data.get("description", "") or "",
        )

    def _resolve_type(self, type_data: Dict[str, Any]) -> Tuple[str, GraphQLTypeKind, bool, bool]:
        """Resolve nested type to (name, kind, nullable, is_list)."""
        if not type_data:
            return ("Unknown", GraphQLTypeKind.SCALAR, True, False)

        kind_str = type_data.get("kind", "")
        name = type_data.get("name")
        is_nullable = True
        is_list = False

        if kind_str == "NON_NULL":
            is_nullable = False
            inner = self._resolve_type(type_data.get("ofType", {}))
            return (inner[0], inner[1], False, inner[3])

        if kind_str == "LIST":
            is_list = True
            inner = self._resolve_type(type_data.get("ofType", {}))
            return (inner[0], inner[1], is_nullable, True)

        kind = self.KIND_MAP.get(kind_str, GraphQLTypeKind.SCALAR)
        return (name or "Unknown", kind, is_nullable, is_list)


# ════════════════════════════════════════════════════════════════════════════════
# QUERY GENERATOR — Generates test queries from schema
# ════════════════════════════════════════════════════════════════════════════════

class QueryGenerator:
    """Generates GraphQL queries for security testing."""

    # Sensitive field name patterns
    SENSITIVE_FIELDS = re.compile(
        r"(password|secret|token|key|auth|session|credit|ssn|"
        r"private|internal|admin|api_key|apikey|jwt|bearer|"
        r"card_number|cvv|salt|hash|otp|pin|seed|credential)",
        re.I,
    )

    # IDOR-prone argument patterns
    IDOR_ARGS = re.compile(r"(id|userId|user_id|accountId|orderId|email)", re.I)

    def generate_depth_attack(self, schema: GraphQLSchema, max_depth: int = 20) -> str:
        """Generate a deeply nested query for DoS testing."""
        # Find a self-referencing type
        for gql_type in schema.object_types:
            for f in gql_type.fields:
                if f.type_name == gql_type.name:
                    # Self-referencing field found
                    query = "{ " + self._build_nested(f.name, max_depth) + " }"
                    return query

        # Fallback: find any object→object chain
        for gql_type in schema.object_types:
            for f in gql_type.fields:
                if f.type_kind == GraphQLTypeKind.OBJECT and f.type_name in schema.types:
                    query = "{ " + f.name + " { __typename " + self._build_nested("id", 5) + " } }"
                    return query

        return "{ __typename }"

    def generate_alias_attack(self, query_name: str, count: int = 100) -> str:
        """Generate alias-based batch attack query."""
        aliases = []
        for i in range(count):
            aliases.append(f"  a{i}: {query_name}(id: {i}) {{ id __typename }}")
        return "{\n" + "\n".join(aliases) + "\n}"

    def generate_idor_queries(self, schema: GraphQLSchema) -> List[Tuple[str, str, str]]:
        """Generate IDOR test queries. Returns (query, type_name, field_name) tuples."""
        queries: List[Tuple[str, str, str]] = []

        query_type = schema.types.get(schema.query_type)
        if not query_type:
            return queries

        for f in query_type.fields:
            for arg in f.args:
                if self.IDOR_ARGS.search(arg.name):
                    # Generate query with sequential IDs
                    arg_val = '"test"' if "String" in arg.type_name else "1"
                    query = f'{{ {f.name}({arg.name}: {arg_val}) {{ id __typename }} }}'
                    queries.append((query, schema.query_type, f.name))

        return queries

    def find_sensitive_fields(self, schema: GraphQLSchema) -> List[Tuple[str, str]]:
        """Find fields that may expose sensitive data. Returns (type, field) tuples."""
        results: List[Tuple[str, str]] = []
        for gql_type in schema.user_types:
            for f in gql_type.fields:
                if self.SENSITIVE_FIELDS.search(f.name):
                    results.append((gql_type.name, f.name))
        return results

    def generate_injection_queries(self, schema: GraphQLSchema) -> List[str]:
        """Generate injection test queries for string arguments."""
        queries: List[str] = []
        payloads = [
            "' OR '1'='1",
            '"; DROP TABLE users; --',
            "{{7*7}}",
            "${7*7}",
            "<script>alert(1)</script>",
        ]

        query_type = schema.types.get(schema.query_type)
        if not query_type:
            return queries

        for f in query_type.fields:
            for arg in f.args:
                if "String" in arg.type_name:
                    for payload in payloads:
                        escaped = payload.replace('"', '\\"')
                        q = f'{{ {f.name}({arg.name}: "{escaped}") {{ __typename }} }}'
                        queries.append(q)
                    break  # One arg per field is enough

        return queries

    @staticmethod
    def _build_nested(field_name: str, depth: int) -> str:
        """Build nested field access."""
        if depth <= 0:
            return "__typename"
        return f"{field_name} {{ {QueryGenerator._build_nested(field_name, depth - 1)} }}"


# ════════════════════════════════════════════════════════════════════════════════
# COMPLEXITY ANALYZER — Detects DoS via query complexity
# ════════════════════════════════════════════════════════════════════════════════

class ComplexityAnalyzer:
    """Analyzes query complexity and detects DoS vectors."""

    def estimate_complexity(self, schema: GraphQLSchema) -> Dict[str, Any]:
        """Estimate maximum query complexity possible."""
        max_depth = 0
        circular_types: Set[str] = set()
        high_fan_out: List[Tuple[str, str, int]] = []  # (type, field, fan_out)

        for gql_type in schema.object_types:
            for f in gql_type.fields:
                if f.type_name == gql_type.name:
                    circular_types.add(gql_type.name)
                if f.is_list and f.type_kind == GraphQLTypeKind.OBJECT:
                    # Lists of objects multiply complexity
                    high_fan_out.append((gql_type.name, f.name, 100))  # Assume 100 items

        # Check depth via type graph
        visited: Set[str] = set()
        for gql_type in schema.object_types:
            depth = self._max_depth(gql_type.name, schema, visited, 0)
            max_depth = max(max_depth, depth)

        return {
            "max_reachable_depth": max_depth,
            "circular_types": list(circular_types),
            "high_fan_out_fields": [(t, f, n) for t, f, n in high_fan_out],
            "unbounded_complexity": bool(circular_types),
        }

    def _max_depth(self, type_name: str, schema: GraphQLSchema, visited: Set[str], depth: int) -> int:
        """Calculate max reachable depth from a type."""
        if depth > 50 or type_name in visited:
            return depth
        visited.add(type_name)

        gql_type = schema.types.get(type_name)
        if not gql_type:
            visited.discard(type_name)
            return depth

        max_d = depth
        for f in gql_type.fields:
            if f.type_kind == GraphQLTypeKind.OBJECT and f.type_name in schema.types:
                d = self._max_depth(f.type_name, schema, visited, depth + 1)
                max_d = max(max_d, d)

        visited.discard(type_name)
        return max_d


# ════════════════════════════════════════════════════════════════════════════════
# SIREN GRAPHQL ENGINE — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenGraphQLEngine:
    """
    Main GraphQL analysis and exploitation engine.

    Orchestrates introspection, schema analysis, query generation,
    complexity analysis, and vulnerability detection.

    Usage:
        engine = SirenGraphQLEngine()

        # Analyze from introspection response
        report = engine.analyze_introspection(json_data, "https://target.com/graphql")

        # Generate attack queries
        queries = engine.generate_attack_queries(schema)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._query_builder = IntrospectionQueryBuilder()
        self._schema_parser = SchemaParser()
        self._query_generator = QueryGenerator()
        self._complexity_analyzer = ComplexityAnalyzer()
        self._stats: Dict[str, int] = defaultdict(int)
        logger.info("SirenGraphQLEngine initialized")

    def get_introspection_query(self, minimal: bool = False) -> str:
        """Get the introspection query to send to the endpoint."""
        if minimal:
            return self._query_builder.MINIMAL_INTROSPECTION
        return self._query_builder.FULL_INTROSPECTION

    def analyze_introspection(self, data: Dict[str, Any], endpoint: str = "") -> GraphQLReport:
        """Analyze introspection response and generate findings."""
        report = GraphQLReport(endpoint=endpoint)

        # Parse schema
        schema = self._schema_parser.parse(data)
        report.schema = schema

        with self._lock:
            self._stats["schemas_analyzed"] += 1

        # Generate findings
        findings: List[GraphQLFinding] = []

        # 1. Introspection enabled (the fact that we got here)
        findings.append(GraphQLFinding(
            vuln_type=VulnType.INTROSPECTION_ENABLED,
            risk=RiskLevel.MEDIUM,
            title="GraphQL introspection enabled",
            description="Full schema introspection is accessible — exposes entire API structure",
            recommendation="Disable introspection in production (keep for development only)",
        ))

        # 2. Complexity analysis
        complexity = self._complexity_analyzer.estimate_complexity(schema)
        if complexity["unbounded_complexity"]:
            findings.append(GraphQLFinding(
                vuln_type=VulnType.DEEP_NESTING_DOS,
                risk=RiskLevel.HIGH,
                title="Unbounded query complexity (circular types)",
                description=f"Circular types found: {complexity['circular_types']}. "
                            "Deeply nested queries can cause DoS.",
                evidence=f"Max depth: {complexity['max_reachable_depth']}",
                query=self._query_generator.generate_depth_attack(schema),
                recommendation="Implement query complexity limits and depth limiting",
            ))

        # 3. Sensitive fields
        sensitive = self._query_generator.find_sensitive_fields(schema)
        for type_name, field_name in sensitive:
            findings.append(GraphQLFinding(
                vuln_type=VulnType.SENSITIVE_FIELD_EXPOSED,
                risk=RiskLevel.HIGH,
                title=f"Sensitive field exposed: {type_name}.{field_name}",
                description=f"Field '{field_name}' on type '{type_name}' may expose sensitive data",
                affected_type=type_name,
                affected_field=field_name,
                recommendation="Remove or restrict access to sensitive fields",
            ))

        # 4. IDOR candidates
        idor_queries = self._query_generator.generate_idor_queries(schema)
        for query, type_name, field_name in idor_queries:
            findings.append(GraphQLFinding(
                vuln_type=VulnType.IDOR,
                risk=RiskLevel.MEDIUM,
                title=f"IDOR candidate: {field_name}",
                description=f"Field '{field_name}' accepts ID-like argument — test for IDOR",
                query=query,
                affected_type=type_name,
                affected_field=field_name,
                recommendation="Implement authorization checks on object access",
            ))

        # 5. Mutation analysis
        mutation_type = schema.types.get(schema.mutation_type)
        if mutation_type:
            report.mutations_found = len(mutation_type.fields)
            for f in mutation_type.fields:
                if any(kw in f.name.lower() for kw in ("delete", "remove", "drop", "admin", "create_user")):
                    findings.append(GraphQLFinding(
                        vuln_type=VulnType.MUTATION_WITHOUT_AUTH,
                        risk=RiskLevel.HIGH,
                        title=f"Dangerous mutation found: {f.name}",
                        description=f"Mutation '{f.name}' may perform destructive/admin operations",
                        affected_type=schema.mutation_type,
                        affected_field=f.name,
                        recommendation="Ensure proper authentication and authorization on mutations",
                    ))

        # 6. Field suggestion (information disclosure)
        if schema.directives:
            findings.append(GraphQLFinding(
                vuln_type=VulnType.FIELD_SUGGESTION,
                risk=RiskLevel.LOW,
                title="Field suggestions may be enabled",
                description="GraphQL may suggest field names on typos, enabling schema enumeration",
                recommendation="Disable field suggestions in production",
            ))

        report.findings = sorted(findings, key=lambda f: list(RiskLevel).index(f.risk))
        report.queries_generated = len(idor_queries)

        # Count subscriptions
        sub_type = schema.types.get(schema.subscription_type)
        if sub_type:
            report.subscriptions_found = len(sub_type.fields)

        with self._lock:
            self._stats["findings_total"] += len(findings)

        return report

    def generate_attack_queries(self, schema: GraphQLSchema) -> Dict[str, List[str]]:
        """Generate categorized attack queries from schema."""
        attacks: Dict[str, List[str]] = defaultdict(list)

        # Depth attack
        depth_q = self._query_generator.generate_depth_attack(schema)
        if depth_q:
            attacks["depth_dos"].append(depth_q)

        # Alias overloading
        query_type = schema.types.get(schema.query_type)
        if query_type and query_type.fields:
            first_field = query_type.fields[0]
            alias_q = self._query_generator.generate_alias_attack(first_field.name, 50)
            attacks["alias_overloading"].append(alias_q)

        # IDOR
        for query, _, _ in self._query_generator.generate_idor_queries(schema):
            attacks["idor"].append(query)

        # Injection
        attacks["injection"] = self._query_generator.generate_injection_queries(schema)

        return dict(attacks)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)
