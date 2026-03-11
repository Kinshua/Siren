#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🎭  SIREN SOCIAL ENGINEERING — Human-Layer Attack Simulation Engine  🎭      ██
██                                                                                ██
██  Motor completo de engenharia social para red team assessments autorizados.    ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    * Phishing template generation — 20+ templates por categoria               ██
██    * Pretext building — 15+ cenarios com scripts detalhados                   ██
██    * Vishing script generation — 8+ roteiros de telefone                      ██
██    * SMiShing templates — 10+ SMS phishing templates                          ██
██    * Domain lookalike generation — homoglyphs, typosquatting, combosquatting   ██
██    * Watering hole analysis — site profiling e injection vectors              ██
██    * Awareness scoring — formula de scoring, benchmarks por industria          ██
██    * Campaign simulation — success rate estimation, A/B testing, ROI          ██
██                                                                                ██
██  Todas as operacoes sao para assessments AUTORIZADOS com escopo definido.     ██
██  O uso indevido deste modulo viola leis federais em multiplas jurisdicoes.     ██
██                                                                                ██
██  "SIREN nao hackeia maquinas — hackeia decisoes."                             ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import re
import string
import struct
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("siren.intelligence.social_engineering")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_TEMPLATES_CACHE = 10_000
MAX_CAMPAIGN_RESULTS = 50_000
DEFAULT_AWARENESS_THRESHOLD = 0.65
HOMOGLYPH_CONFIDENCE = 0.85
TYPOSQUAT_CONFIDENCE = 0.75
BITSQUAT_CONFIDENCE = 0.60
COMBOSQUAT_CONFIDENCE = 0.70

AUTHORIZATION_DISCLAIMER = (
    "WARNING: This module is designed exclusively for AUTHORIZED red team "
    "assessments. Unauthorized use violates federal laws including the CFAA "
    "(18 U.S.C. 1030), GDPR Art. 83, and equivalent statutes worldwide. "
    "Always obtain written authorization before executing any social "
    "engineering campaign."
)


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class PhishingCategory(Enum):
    """Categories of phishing attacks for template organization."""
    CREDENTIAL_HARVEST = auto()
    MALWARE_DELIVERY = auto()
    BEC = auto()
    INVOICE_FRAUD = auto()
    IT_SUPPORT = auto()
    HR_POLICY = auto()
    PACKAGE_DELIVERY = auto()
    MFA_FATIGUE = auto()
    SPEAR_PHISH = auto()
    WHALING = auto()
    CLONE_PHISH = auto()
    WATERING_HOLE = auto()


class IndustryType(Enum):
    """Industry types for awareness benchmarking and targeting."""
    FINANCE = auto()
    HEALTHCARE = auto()
    TECHNOLOGY = auto()
    GOVERNMENT = auto()
    EDUCATION = auto()
    MANUFACTURING = auto()
    RETAIL = auto()
    ENERGY = auto()
    LEGAL = auto()
    MEDIA = auto()
    TELECOM = auto()
    DEFENSE = auto()
    NONPROFIT = auto()
    HOSPITALITY = auto()
    TRANSPORTATION = auto()


class PretextScenario(Enum):
    """Pretext scenarios for social engineering engagements."""
    IT_HELPDESK = auto()
    NEW_EMPLOYEE = auto()
    VENDOR_PARTNER = auto()
    DELIVERY_PERSON = auto()
    FIRE_INSPECTOR = auto()
    RECRUITER = auto()
    CLEVEL_ASSISTANT = auto()
    AUDITOR = auto()
    BUILDING_MAINTENANCE = auto()
    TELECOM_TECHNICIAN = auto()
    INSURANCE_AGENT = auto()
    SURVEY_RESEARCHER = auto()
    BANK_REPRESENTATIVE = auto()
    LAW_ENFORCEMENT = auto()
    MEDIA_JOURNALIST = auto()
    TEMP_WORKER = auto()


class AwarenessLevel(Enum):
    """Awareness maturity levels for organizations."""
    CRITICAL = auto()      # 0-20% — no training, frequent incidents
    LOW = auto()           # 20-40% — basic training, many gaps
    MODERATE = auto()      # 40-60% — regular training, some gaps
    HIGH = auto()          # 60-80% — advanced training, few gaps
    EXEMPLARY = auto()     # 80-100% — continuous training, minimal gaps


class AttackVector(Enum):
    """Attack delivery vectors for social engineering."""
    EMAIL = auto()
    PHONE = auto()
    SMS = auto()
    IN_PERSON = auto()
    SOCIAL_MEDIA = auto()
    USB_DROP = auto()
    WATERING_HOLE = auto()
    PHYSICAL_MAIL = auto()


class DomainTechnique(Enum):
    """Techniques for domain lookalike generation."""
    HOMOGLYPH = auto()
    TYPOSQUAT = auto()
    COMBOSQUAT = auto()
    BITSQUAT = auto()
    SUBDOMAIN = auto()
    TLD_SWAP = auto()
    HYPHENATION = auto()
    VOWEL_SWAP = auto()
    DOUBLE_EXTENSION = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class SocialEngProfile:
    """Profile of a social engineering target or organization."""
    profile_id: str = ""
    organization: str = ""
    industry: IndustryType = IndustryType.TECHNOLOGY
    employee_count: int = 0
    departments: List[str] = field(default_factory=list)
    known_technologies: List[str] = field(default_factory=list)
    email_format: str = "{first}.{last}@{domain}"
    domain: str = ""
    social_media_presence: Dict[str, str] = field(default_factory=dict)
    previous_incidents: List[Dict[str, Any]] = field(default_factory=list)
    awareness_training_date: float = 0.0
    security_tools: List[str] = field(default_factory=list)
    public_executives: List[Dict[str, str]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "organization": self.organization,
            "industry": self.industry.name,
            "employee_count": self.employee_count,
            "departments": self.departments,
            "known_technologies": self.known_technologies,
            "email_format": self.email_format,
            "domain": self.domain,
            "social_media_presence": self.social_media_presence,
            "previous_incidents": self.previous_incidents,
            "awareness_training_date": self.awareness_training_date,
            "security_tools": self.security_tools,
            "public_executives": self.public_executives,
            "created_at": self.created_at,
        }


@dataclass
class PhishingTemplate:
    """Complete phishing email template with metadata."""
    template_id: str = ""
    name: str = ""
    category: PhishingCategory = PhishingCategory.CREDENTIAL_HARVEST
    subject: str = ""
    sender_name: str = ""
    sender_email_local: str = ""
    reply_to: str = ""
    html_body: str = ""
    text_body: str = ""
    personalization_vars: List[str] = field(default_factory=list)
    urgency_level: int = 5
    sophistication_level: int = 5
    target_industries: List[IndustryType] = field(default_factory=list)
    success_rate_estimate: float = 0.0
    indicators_of_compromise: List[str] = field(default_factory=list)
    evasion_notes: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "category": self.category.name,
            "subject": self.subject,
            "sender_name": self.sender_name,
            "sender_email_local": self.sender_email_local,
            "reply_to": self.reply_to,
            "html_body": self.html_body,
            "text_body": self.text_body,
            "personalization_vars": self.personalization_vars,
            "urgency_level": self.urgency_level,
            "sophistication_level": self.sophistication_level,
            "target_industries": [i.name for i in self.target_industries],
            "success_rate_estimate": self.success_rate_estimate,
            "indicators_of_compromise": self.indicators_of_compromise,
            "evasion_notes": self.evasion_notes,
            "created_at": self.created_at,
        }


@dataclass
class PretextScript:
    """Detailed pretext script for in-person or phone-based SE."""
    script_id: str = ""
    scenario: PretextScenario = PretextScenario.IT_HELPDESK
    title: str = ""
    objective: str = ""
    target_role: str = ""
    opening_lines: List[str] = field(default_factory=list)
    conversation_flow: List[Dict[str, str]] = field(default_factory=list)
    objection_handlers: Dict[str, str] = field(default_factory=dict)
    escalation_triggers: List[str] = field(default_factory=list)
    props_required: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    abort_conditions: List[str] = field(default_factory=list)
    estimated_duration_min: int = 10
    difficulty_rating: int = 5
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "script_id": self.script_id,
            "scenario": self.scenario.name,
            "title": self.title,
            "objective": self.objective,
            "target_role": self.target_role,
            "opening_lines": self.opening_lines,
            "conversation_flow": self.conversation_flow,
            "objection_handlers": self.objection_handlers,
            "escalation_triggers": self.escalation_triggers,
            "props_required": self.props_required,
            "success_criteria": self.success_criteria,
            "abort_conditions": self.abort_conditions,
            "estimated_duration_min": self.estimated_duration_min,
            "difficulty_rating": self.difficulty_rating,
            "created_at": self.created_at,
        }


@dataclass
class CampaignResult:
    """Results from a simulated or real SE campaign."""
    result_id: str = ""
    campaign_name: str = ""
    vector: AttackVector = AttackVector.EMAIL
    total_targets: int = 0
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_submitted: int = 0
    attachments_opened: int = 0
    reported_by_targets: int = 0
    time_to_first_click_sec: float = 0.0
    time_to_first_report_sec: float = 0.0
    department_breakdown: Dict[str, Dict[str, int]] = field(default_factory=dict)
    template_used: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    success_rate: float = 0.0
    report_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "campaign_name": self.campaign_name,
            "vector": self.vector.name,
            "total_targets": self.total_targets,
            "emails_sent": self.emails_sent,
            "emails_opened": self.emails_opened,
            "links_clicked": self.links_clicked,
            "credentials_submitted": self.credentials_submitted,
            "attachments_opened": self.attachments_opened,
            "reported_by_targets": self.reported_by_targets,
            "time_to_first_click_sec": self.time_to_first_click_sec,
            "time_to_first_report_sec": self.time_to_first_report_sec,
            "department_breakdown": self.department_breakdown,
            "template_used": self.template_used,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "success_rate": self.success_rate,
            "report_rate": self.report_rate,
        }


@dataclass
class SocialEngReport:
    """Comprehensive social engineering assessment report."""
    report_id: str = ""
    engagement_name: str = ""
    organization: str = ""
    scope_description: str = ""
    authorization_ref: str = ""
    vectors_tested: List[AttackVector] = field(default_factory=list)
    templates_used: List[str] = field(default_factory=list)
    campaign_results: List[CampaignResult] = field(default_factory=list)
    awareness_score: float = 0.0
    awareness_level: AwarenessLevel = AwarenessLevel.MODERATE
    industry_benchmark: float = 0.0
    department_scores: Dict[str, float] = field(default_factory=dict)
    risk_findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    executive_summary: str = ""
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "engagement_name": self.engagement_name,
            "organization": self.organization,
            "scope_description": self.scope_description,
            "authorization_ref": self.authorization_ref,
            "vectors_tested": [v.name for v in self.vectors_tested],
            "templates_used": self.templates_used,
            "campaign_results": [c.to_dict() for c in self.campaign_results],
            "awareness_score": self.awareness_score,
            "awareness_level": self.awareness_level.name,
            "industry_benchmark": self.industry_benchmark,
            "department_scores": self.department_scores,
            "risk_findings": self.risk_findings,
            "recommendations": self.recommendations,
            "executive_summary": self.executive_summary,
            "generated_at": self.generated_at,
        }


@dataclass
class LookalikeDomain:
    """A generated lookalike domain with metadata."""
    domain: str = ""
    original: str = ""
    technique: DomainTechnique = DomainTechnique.TYPOSQUAT
    confidence: float = 0.0
    visual_similarity: float = 0.0
    description: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "original": self.original,
            "technique": self.technique.name,
            "confidence": self.confidence,
            "visual_similarity": self.visual_similarity,
            "description": self.description,
            "created_at": self.created_at,
        }


@dataclass
class WateringHoleSite:
    """Analysis of a potential watering hole target site."""
    site_id: str = ""
    url: str = ""
    category: str = ""
    estimated_visitors_monthly: int = 0
    target_overlap_score: float = 0.0
    injection_vectors: List[Dict[str, str]] = field(default_factory=list)
    technologies_detected: List[str] = field(default_factory=list)
    vulnerability_indicators: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    analyzed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site_id": self.site_id,
            "url": self.url,
            "category": self.category,
            "estimated_visitors_monthly": self.estimated_visitors_monthly,
            "target_overlap_score": self.target_overlap_score,
            "injection_vectors": self.injection_vectors,
            "technologies_detected": self.technologies_detected,
            "vulnerability_indicators": self.vulnerability_indicators,
            "risk_score": self.risk_score,
            "analyzed_at": self.analyzed_at,
        }


@dataclass
class VishingScript:
    """Voice phishing (vishing) phone call script."""
    script_id: str = ""
    scenario_name: str = ""
    caller_identity: str = ""
    caller_number_spoof: str = ""
    target_role: str = ""
    objective: str = ""
    opening: str = ""
    main_script: List[Dict[str, str]] = field(default_factory=list)
    fallback_responses: Dict[str, str] = field(default_factory=dict)
    voice_tone_notes: str = ""
    background_audio: str = ""
    estimated_duration_min: int = 5
    success_criteria: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "script_id": self.script_id,
            "scenario_name": self.scenario_name,
            "caller_identity": self.caller_identity,
            "caller_number_spoof": self.caller_number_spoof,
            "target_role": self.target_role,
            "objective": self.objective,
            "opening": self.opening,
            "main_script": self.main_script,
            "fallback_responses": self.fallback_responses,
            "voice_tone_notes": self.voice_tone_notes,
            "background_audio": self.background_audio,
            "estimated_duration_min": self.estimated_duration_min,
            "success_criteria": self.success_criteria,
            "created_at": self.created_at,
        }


@dataclass
class SMiShingTemplate:
    """SMS phishing template."""
    template_id: str = ""
    name: str = ""
    sender_id: str = ""
    message_body: str = ""
    shortened_url_pattern: str = ""
    personalization_vars: List[str] = field(default_factory=list)
    urgency_level: int = 5
    category: str = ""
    target_demographics: str = ""
    success_rate_estimate: float = 0.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "sender_id": self.sender_id,
            "message_body": self.message_body,
            "shortened_url_pattern": self.shortened_url_pattern,
            "personalization_vars": self.personalization_vars,
            "urgency_level": self.urgency_level,
            "category": self.category,
            "target_demographics": self.target_demographics,
            "success_rate_estimate": self.success_rate_estimate,
            "created_at": self.created_at,
        }


# ════════════════════════════════════════════════════════════════════════════════
# PHISHING TEMPLATE GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

class PhishingTemplateGen:
    """Generates realistic phishing email templates for authorized red team assessments.

    Provides 20+ complete templates organized by category with full HTML content,
    subject lines, sender personas, and personalization variables.

    Usage:
        gen = PhishingTemplateGen()
        templates = gen.get_templates_by_category(PhishingCategory.CREDENTIAL_HARVEST)
        custom = gen.generate_custom_template(
            category=PhishingCategory.BEC,
            target_org="AcmeCorp",
            sender_persona="CFO",
        )
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._templates: Dict[str, PhishingTemplate] = {}
        self._template_index: Dict[PhishingCategory, List[str]] = defaultdict(list)
        self._initialize_templates()
        logger.info("PhishingTemplateGen initialized with %d templates", len(self._templates))

    def _initialize_templates(self) -> None:
        """Build the complete library of phishing email templates."""
        all_templates = []

        # ── CREDENTIAL HARVEST templates ──────────────────────────────────
        all_templates.append(PhishingTemplate(
            template_id="cred-001",
            name="Microsoft 365 Password Expiry",
            category=PhishingCategory.CREDENTIAL_HARVEST,
            subject="[Action Required] Your password expires in 24 hours",
            sender_name="Microsoft 365 Admin",
            sender_email_local="no-reply",
            reply_to="security-noreply@{domain}",
            html_body=(
                '<div style="font-family:Segoe UI,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#0078d4;padding:20px;text-align:center;">'
                '<img src="cid:mslogo" alt="Microsoft" style="height:24px;" />'
                '</div>'
                '<div style="padding:30px;background:#fff;">'
                '<h2 style="color:#333;">Password Expiration Notice</h2>'
                '<p>Dear {first_name},</p>'
                '<p>Your Microsoft 365 password for <strong>{email}</strong> is set to '
                'expire in <strong>24 hours</strong>. To avoid disruption to your email '
                'and Teams access, please update your password immediately.</p>'
                '<div style="text-align:center;margin:30px 0;">'
                '<a href="{phish_url}" style="background:#0078d4;color:#fff;padding:12px 30px;'
                'text-decoration:none;border-radius:4px;font-size:16px;">Update Password Now</a>'
                '</div>'
                '<p style="color:#666;font-size:12px;">If you did not request this change, '
                'please contact IT support at ext. 4357.</p>'
                '<hr style="border:1px solid #eee;" />'
                '<p style="color:#999;font-size:11px;">Microsoft Corporation, One Microsoft Way, '
                'Redmond, WA 98052</p>'
                '</div></div>'
            ),
            text_body=(
                "Dear {first_name},\n\n"
                "Your Microsoft 365 password for {email} is set to expire in 24 hours. "
                "To avoid disruption, please update your password at:\n\n"
                "{phish_url}\n\n"
                "If you did not request this change, contact IT support.\n\n"
                "Microsoft Corporation"
            ),
            personalization_vars=["first_name", "email", "domain", "phish_url"],
            urgency_level=8,
            sophistication_level=7,
            target_industries=[IndustryType.TECHNOLOGY, IndustryType.FINANCE, IndustryType.HEALTHCARE],
            success_rate_estimate=0.23,
            indicators_of_compromise=["Sender domain mismatch", "Generic greeting fallback"],
            evasion_notes="Use legitimate Microsoft CDN for logo. Match target org MX branding.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="cred-002",
            name="Google Workspace Security Alert",
            category=PhishingCategory.CREDENTIAL_HARVEST,
            subject="Security alert: New sign-in from {location}",
            sender_name="Google",
            sender_email_local="no-reply",
            reply_to="",
            html_body=(
                '<div style="font-family:Google Sans,Roboto,sans-serif;max-width:560px;margin:0 auto;">'
                '<div style="padding:20px 0;text-align:center;">'
                '<span style="font-size:24px;color:#4285f4;">G</span>'
                '<span style="font-size:24px;color:#ea4335;">o</span>'
                '<span style="font-size:24px;color:#fbbc05;">o</span>'
                '<span style="font-size:24px;color:#4285f4;">g</span>'
                '<span style="font-size:24px;color:#34a853;">l</span>'
                '<span style="font-size:24px;color:#ea4335;">e</span>'
                '</div>'
                '<div style="border:1px solid #dadce0;border-radius:8px;padding:40px;">'
                '<h2 style="font-weight:400;color:#202124;">New sign-in on {device_type}</h2>'
                '<p style="color:#5f6368;">{first_name}, someone just signed into your Google '
                'Account ({email}) from a new {device_type} near <strong>{location}</strong>.</p>'
                '<div style="background:#f8f9fa;border-radius:8px;padding:16px;margin:20px 0;">'
                '<p style="margin:4px 0;color:#5f6368;">Time: {timestamp}</p>'
                '<p style="margin:4px 0;color:#5f6368;">Device: {device_type}</p>'
                '<p style="margin:4px 0;color:#5f6368;">Location: {location}</p>'
                '</div>'
                '<p style="color:#5f6368;">If this was you, you can ignore this message. '
                'If not, your account may be compromised.</p>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#1a73e8;color:#fff;padding:10px 24px;'
                'text-decoration:none;border-radius:4px;">Check Activity</a>'
                '</div>'
                '</div></div>'
            ),
            text_body=(
                "New sign-in on {device_type}\n\n"
                "{first_name}, someone signed into your account ({email}) from "
                "{location} at {timestamp}.\n\n"
                "If this wasn't you, check your activity: {phish_url}\n\n"
                "Google LLC"
            ),
            personalization_vars=["first_name", "email", "location", "device_type", "timestamp", "phish_url"],
            urgency_level=9,
            sophistication_level=8,
            target_industries=[IndustryType.TECHNOLOGY, IndustryType.EDUCATION],
            success_rate_estimate=0.27,
            indicators_of_compromise=["Return-path mismatch", "URL not accounts.google.com"],
            evasion_notes="Populate location from target GeoIP. Use realistic timestamp.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="cred-003",
            name="VPN Portal Re-authentication",
            category=PhishingCategory.CREDENTIAL_HARVEST,
            subject="VPN Certificate Renewal Required - {org_name}",
            sender_name="{org_name} IT Security",
            sender_email_local="vpn-admin",
            reply_to="it-security@{domain}",
            html_body=(
                '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#1a1a2e;padding:15px 20px;">'
                '<span style="color:#e94560;font-weight:bold;font-size:18px;">{org_name}</span>'
                '<span style="color:#fff;float:right;font-size:12px;">IT Security Division</span>'
                '</div>'
                '<div style="padding:25px;background:#fff;border:1px solid #ddd;">'
                '<p>Hello {first_name},</p>'
                '<p>Your VPN client certificate expires on <strong>{expiry_date}</strong>. '
                'Remote access will be interrupted until you re-authenticate.</p>'
                '<p>Please complete the following steps:</p>'
                '<ol>'
                '<li>Click the link below to access the VPN renewal portal</li>'
                '<li>Sign in with your corporate credentials</li>'
                '<li>Download the updated certificate bundle</li>'
                '</ol>'
                '<div style="text-align:center;margin:25px 0;">'
                '<a href="{phish_url}" style="background:#e94560;color:#fff;padding:12px 28px;'
                'text-decoration:none;border-radius:3px;">Renew VPN Certificate</a>'
                '</div>'
                '<p style="color:#666;font-size:12px;">This action is required within 48 hours. '
                'Failure to renew will result in loss of remote access privileges.</p>'
                '<p style="color:#999;font-size:11px;">IT Security | {org_name} | '
                'Do not forward this email</p>'
                '</div></div>'
            ),
            text_body=(
                "Hello {first_name},\n\n"
                "Your VPN certificate expires on {expiry_date}. Please renew at:\n"
                "{phish_url}\n\n"
                "Sign in with your corporate credentials to download the updated certificate.\n\n"
                "IT Security | {org_name}"
            ),
            personalization_vars=["first_name", "org_name", "domain", "expiry_date", "phish_url"],
            urgency_level=7,
            sophistication_level=8,
            target_industries=[IndustryType.TECHNOLOGY, IndustryType.FINANCE, IndustryType.DEFENSE],
            success_rate_estimate=0.31,
            indicators_of_compromise=["Internal domain spoofed in sender"],
            evasion_notes="Use org internal branding colors. Match VPN vendor in use.",
        ))

        # ── MALWARE DELIVERY templates ────────────────────────────────────
        all_templates.append(PhishingTemplate(
            template_id="malw-001",
            name="Shared Document Notification",
            category=PhishingCategory.MALWARE_DELIVERY,
            subject="{sender_person} shared a document with you",
            sender_name="{sender_person} via SharePoint",
            sender_email_local="sharepoint-notify",
            reply_to="",
            html_body=(
                '<div style="font-family:Segoe UI,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#fff;border:1px solid #e1e1e1;border-radius:2px;">'
                '<div style="padding:16px 24px;border-bottom:1px solid #e1e1e1;">'
                '<span style="color:#0078d4;font-weight:600;">{sender_person}</span>'
                ' shared a file with you'
                '</div>'
                '<div style="padding:24px;">'
                '<div style="display:flex;align-items:center;padding:16px;'
                'background:#f4f4f4;border-radius:4px;">'
                '<span style="font-size:32px;margin-right:16px;">📄</span>'
                '<div>'
                '<p style="margin:0;font-weight:600;">{document_name}</p>'
                '<p style="margin:4px 0 0;color:#666;font-size:13px;">'
                '{file_size} - Modified {modified_date}</p>'
                '</div></div>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#0078d4;color:#fff;padding:8px 20px;'
                'text-decoration:none;border-radius:2px;">Open</a>'
                '</div>'
                '<p style="color:#999;font-size:11px;">Microsoft SharePoint Online</p>'
                '</div></div></div>'
            ),
            text_body=(
                "{sender_person} shared a document with you.\n\n"
                "Document: {document_name} ({file_size})\n"
                "Open: {phish_url}\n\n"
                "SharePoint Online"
            ),
            personalization_vars=[
                "sender_person", "document_name", "file_size",
                "modified_date", "phish_url",
            ],
            urgency_level=5,
            sophistication_level=7,
            target_industries=[IndustryType.FINANCE, IndustryType.LEGAL, IndustryType.GOVERNMENT],
            success_rate_estimate=0.34,
            indicators_of_compromise=["Attachment or link to non-SharePoint domain"],
            evasion_notes="Use actual colleague name from OSINT. Document name from public filings.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="malw-002",
            name="Voicemail Transcription",
            category=PhishingCategory.MALWARE_DELIVERY,
            subject="Voicemail from +{caller_number} ({duration})",
            sender_name="{org_name} Phone System",
            sender_email_local="voicemail",
            reply_to="",
            html_body=(
                '<div style="font-family:Segoe UI,sans-serif;max-width:520px;margin:0 auto;">'
                '<div style="background:#333;color:#fff;padding:12px 20px;font-size:14px;">'
                '📞 {org_name} Unified Communications'
                '</div>'
                '<div style="padding:24px;background:#fff;border:1px solid #ddd;">'
                '<h3 style="color:#333;margin-top:0;">New Voicemail Message</h3>'
                '<table style="width:100%;border-collapse:collapse;margin:16px 0;">'
                '<tr><td style="padding:6px 0;color:#666;">From:</td>'
                '<td style="padding:6px 0;">+{caller_number}</td></tr>'
                '<tr><td style="padding:6px 0;color:#666;">Date:</td>'
                '<td style="padding:6px 0;">{date_received}</td></tr>'
                '<tr><td style="padding:6px 0;color:#666;">Duration:</td>'
                '<td style="padding:6px 0;">{duration}</td></tr>'
                '</table>'
                '<p>Transcription preview: <em>"{transcription_preview}..."</em></p>'
                '<div style="text-align:center;margin:20px 0;">'
                '<a href="{phish_url}" style="background:#0078d4;color:#fff;padding:10px 24px;'
                'text-decoration:none;border-radius:3px;">▶ Play Voicemail</a>'
                '</div>'
                '<p style="font-size:11px;color:#999;">This message was automatically generated. '
                'Do not reply.</p>'
                '</div></div>'
            ),
            text_body=(
                "New Voicemail from +{caller_number}\n"
                "Duration: {duration}\n"
                "Date: {date_received}\n\n"
                "Transcription: \"{transcription_preview}...\"\n\n"
                "Listen: {phish_url}\n"
            ),
            personalization_vars=[
                "org_name", "caller_number", "date_received",
                "duration", "transcription_preview", "phish_url",
            ],
            urgency_level=6,
            sophistication_level=6,
            target_industries=[IndustryType.FINANCE, IndustryType.LEGAL, IndustryType.HEALTHCARE],
            success_rate_estimate=0.29,
            indicators_of_compromise=["Attachment is .html or .iso not .wav"],
            evasion_notes="Match org phone system branding. Use local area code for caller.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="malw-003",
            name="DocuSign Envelope",
            category=PhishingCategory.MALWARE_DELIVERY,
            subject="{sender_person} sent you a document to review and sign",
            sender_name="DocuSign",
            sender_email_local="dse_na4",
            reply_to="",
            html_body=(
                '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;'
                'background:#f4f4f4;padding:20px;">'
                '<div style="background:#fff;border-radius:4px;overflow:hidden;">'
                '<div style="background:#fff;padding:20px;text-align:center;'
                'border-bottom:3px solid #ffe01b;">'
                '<span style="font-size:22px;font-weight:bold;color:#1d1d1d;">DocuSign</span>'
                '</div>'
                '<div style="padding:30px;">'
                '<h2 style="color:#333;font-weight:normal;">Review Document</h2>'
                '<p><strong>{sender_person}</strong> ({sender_email}) sent you a document '
                'to review and sign.</p>'
                '<div style="text-align:center;margin:30px 0;">'
                '<a href="{phish_url}" style="background:#ffe01b;color:#1d1d1d;'
                'padding:14px 40px;text-decoration:none;font-weight:bold;font-size:16px;'
                'border-radius:3px;">REVIEW DOCUMENT</a>'
                '</div>'
                '<p style="color:#666;font-size:13px;">Do not forward this email. The link '
                'is unique to you.</p>'
                '<p style="color:#999;font-size:11px;">Powered by DocuSign. '
                'If you are not the intended recipient, please disregard.</p>'
                '</div></div></div>'
            ),
            text_body=(
                "{sender_person} ({sender_email}) sent you a document via DocuSign.\n\n"
                "Review and sign: {phish_url}\n\n"
                "Do not forward — this link is unique to you."
            ),
            personalization_vars=["sender_person", "sender_email", "phish_url"],
            urgency_level=6,
            sophistication_level=8,
            target_industries=[IndustryType.LEGAL, IndustryType.FINANCE, IndustryType.RETAIL],
            success_rate_estimate=0.36,
            indicators_of_compromise=["Sender not from docusign.net", "Envelope ID missing"],
            evasion_notes="Use executive name from LinkedIn as sender. Time around quarter-end.",
        ))

        # ── BEC templates ─────────────────────────────────────────────────
        all_templates.append(PhishingTemplate(
            template_id="bec-001",
            name="CEO Wire Transfer Request",
            category=PhishingCategory.BEC,
            subject="Urgent - Wire transfer needed today",
            sender_name="{ceo_name}",
            sender_email_local="{ceo_first_lower}",
            reply_to="{ceo_first_lower}@{lookalike_domain}",
            html_body=(
                '<div style="font-family:Arial,sans-serif;max-width:600px;">'
                '<p>{target_first_name},</p>'
                '<p>I need you to process a wire transfer today for an acquisition '
                'we are closing. This is time-sensitive and confidential — please '
                'do not discuss with anyone else at this point.</p>'
                '<p>Amount: <strong>${amount}</strong><br />'
                'Beneficiary: {beneficiary_name}<br />'
                'Bank: {bank_name}<br />'
                'Account: {account_number}<br />'
                'Routing: {routing_number}</p>'
                '<p>I am in back-to-back meetings and can only communicate by email '
                'right now. Please confirm once processed.</p>'
                '<p>Thanks,<br />{ceo_name}<br />'
                '<span style="color:#666;font-size:12px;">Sent from my iPhone</span></p>'
                '</div>'
            ),
            text_body=(
                "{target_first_name},\n\n"
                "I need you to process a wire transfer today for an acquisition.\n"
                "Amount: ${amount}\nBeneficiary: {beneficiary_name}\n"
                "Bank: {bank_name}\nAccount: {account_number}\n"
                "Routing: {routing_number}\n\n"
                "Confidential - do not discuss. Confirm once done.\n\n"
                "{ceo_name}\nSent from my iPhone"
            ),
            personalization_vars=[
                "ceo_name", "ceo_first_lower", "target_first_name",
                "amount", "beneficiary_name", "bank_name",
                "account_number", "routing_number", "lookalike_domain",
            ],
            urgency_level=10,
            sophistication_level=9,
            target_industries=[IndustryType.FINANCE, IndustryType.MANUFACTURING, IndustryType.RETAIL],
            success_rate_estimate=0.12,
            indicators_of_compromise=["Reply-to domain differs from display domain", "No DKIM"],
            evasion_notes="Spoof display name only. Send during market hours.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="bec-002",
            name="Attorney Privilege Request",
            category=PhishingCategory.BEC,
            subject="Attorney-Client Privileged — Urgent action needed",
            sender_name="{attorney_name}, Esq.",
            sender_email_local="{attorney_last_lower}",
            reply_to="{attorney_last_lower}@{lookalike_domain}",
            html_body=(
                '<div style="font-family:Georgia,serif;max-width:600px;">'
                '<p>Dear {target_first_name},</p>'
                '<p>I am writing on behalf of your CEO, {ceo_name}, regarding a '
                'matter that is subject to <strong>attorney-client privilege</strong>. '
                'Please treat this communication as strictly confidential.</p>'
                '<p>We require an expedited funds transfer to complete the transaction '
                'referenced in our prior engagement. The details are as follows:</p>'
                '<ul>'
                '<li>Amount: <strong>${amount}</strong></li>'
                '<li>Reference: {reference_code}</li>'
                '<li>Deadline: End of business today</li>'
                '</ul>'
                '<p>{ceo_name} has authorized this transfer and has asked that you '
                'proceed without additional approvals to maintain confidentiality.</p>'
                '<p>Regards,<br />{attorney_name}, Esq.<br />'
                '{law_firm}<br />'
                '<span style="color:#666;font-size:12px;">'
                'CONFIDENTIALITY NOTICE: This message may contain privileged information.</span></p>'
                '</div>'
            ),
            text_body=(
                "Dear {target_first_name},\n\n"
                "I write on behalf of {ceo_name} regarding an attorney-client "
                "privileged matter. We require a funds transfer:\n\n"
                "Amount: ${amount}\nRef: {reference_code}\nDeadline: EOD today\n\n"
                "{attorney_name}, Esq.\n{law_firm}"
            ),
            personalization_vars=[
                "target_first_name", "ceo_name", "attorney_name",
                "attorney_last_lower", "amount", "reference_code",
                "law_firm", "lookalike_domain",
            ],
            urgency_level=9,
            sophistication_level=9,
            target_industries=[IndustryType.FINANCE, IndustryType.LEGAL],
            success_rate_estimate=0.09,
            indicators_of_compromise=["External law firm not previously engaged"],
            evasion_notes="Research actual outside counsel via SEC filings.",
        ))

        # ── INVOICE FRAUD templates ───────────────────────────────────────
        all_templates.append(PhishingTemplate(
            template_id="inv-001",
            name="Vendor Bank Account Update",
            category=PhishingCategory.INVOICE_FRAUD,
            subject="Updated banking information — {vendor_name}",
            sender_name="{vendor_contact}",
            sender_email_local="accounts",
            reply_to="accounts@{vendor_lookalike}",
            html_body=(
                '<div style="font-family:Arial,sans-serif;max-width:600px;">'
                '<div style="border-bottom:2px solid #0066cc;padding-bottom:10px;margin-bottom:20px;">'
                '<strong style="font-size:18px;color:#0066cc;">{vendor_name}</strong>'
                '</div>'
                '<p>Dear Accounts Payable Team,</p>'
                '<p>Please be advised that <strong>{vendor_name}</strong> has recently '
                'changed our banking institution. Effective immediately, all future payments '
                'should be directed to our new account:</p>'
                '<div style="background:#f5f5f5;padding:16px;border-left:4px solid #0066cc;'
                'margin:20px 0;">'
                '<p style="margin:4px 0;">Bank: {new_bank_name}</p>'
                '<p style="margin:4px 0;">Account Name: {vendor_name}</p>'
                '<p style="margin:4px 0;">Account Number: {new_account}</p>'
                '<p style="margin:4px 0;">Routing: {new_routing}</p>'
                '<p style="margin:4px 0;">SWIFT: {swift_code}</p>'
                '</div>'
                '<p>Please update your records and apply this change to pending invoice '
                '<strong>#{invoice_number}</strong> (${invoice_amount}).</p>'
                '<p>Best regards,<br />{vendor_contact}<br />Accounts Receivable<br />'
                '{vendor_name}</p>'
                '</div>'
            ),
            text_body=(
                "Dear Accounts Payable Team,\n\n"
                "{vendor_name} has changed banking details. New account:\n"
                "Bank: {new_bank_name}\nAcct: {new_account}\n"
                "Routing: {new_routing}\nSWIFT: {swift_code}\n\n"
                "Apply to invoice #{invoice_number} (${invoice_amount}).\n\n"
                "{vendor_contact}\n{vendor_name}"
            ),
            personalization_vars=[
                "vendor_name", "vendor_contact", "vendor_lookalike",
                "new_bank_name", "new_account", "new_routing",
                "swift_code", "invoice_number", "invoice_amount",
            ],
            urgency_level=6,
            sophistication_level=8,
            target_industries=[IndustryType.MANUFACTURING, IndustryType.RETAIL, IndustryType.HEALTHCARE],
            success_rate_estimate=0.15,
            indicators_of_compromise=["Domain similar but not identical to vendor"],
            evasion_notes="Research real vendor from public procurement data. Match invoice cycle.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="inv-002",
            name="Overdue Invoice Reminder",
            category=PhishingCategory.INVOICE_FRAUD,
            subject="OVERDUE: Invoice #{invoice_number} - Immediate attention required",
            sender_name="{vendor_contact}",
            sender_email_local="billing",
            reply_to="billing@{vendor_lookalike}",
            html_body=(
                '<div style="font-family:Arial,sans-serif;max-width:600px;">'
                '<div style="background:#cc0000;color:#fff;padding:10px 20px;">'
                'OVERDUE PAYMENT NOTICE'
                '</div>'
                '<div style="padding:20px;border:1px solid #ddd;">'
                '<p>Dear {target_first_name},</p>'
                '<p>This is a final reminder that invoice <strong>#{invoice_number}</strong> '
                'for <strong>${invoice_amount}</strong> is now <strong>{days_overdue} days '
                'past due</strong>.</p>'
                '<p>Per our service agreement, we may be required to suspend services if '
                'payment is not received within 48 hours.</p>'
                '<p>Please remit payment to the account specified in the attached invoice, '
                'or click below to pay online:</p>'
                '<div style="text-align:center;margin:20px 0;">'
                '<a href="{phish_url}" style="background:#cc0000;color:#fff;padding:12px 30px;'
                'text-decoration:none;border-radius:3px;">Pay Now</a>'
                '</div>'
                '<p>Best regards,<br />{vendor_contact}<br />{vendor_name}</p>'
                '</div></div>'
            ),
            text_body=(
                "OVERDUE PAYMENT NOTICE\n\n"
                "Invoice #{invoice_number} for ${invoice_amount} is {days_overdue} "
                "days past due. Services may be suspended in 48 hours.\n\n"
                "Pay: {phish_url}\n\n{vendor_contact}\n{vendor_name}"
            ),
            personalization_vars=[
                "target_first_name", "invoice_number", "invoice_amount",
                "days_overdue", "vendor_name", "vendor_contact",
                "vendor_lookalike", "phish_url",
            ],
            urgency_level=8,
            sophistication_level=6,
            target_industries=[IndustryType.RETAIL, IndustryType.MANUFACTURING],
            success_rate_estimate=0.18,
            indicators_of_compromise=["Payment link not on vendor domain"],
            evasion_notes="Use real vendor name and approximate invoice amounts.",
        ))

        # ── IT SUPPORT templates ──────────────────────────────────────────
        all_templates.append(PhishingTemplate(
            template_id="it-001",
            name="Mandatory Security Update",
            category=PhishingCategory.IT_SUPPORT,
            subject="[IT] Mandatory security patch — install by end of day",
            sender_name="{org_name} IT Department",
            sender_email_local="it-support",
            reply_to="helpdesk@{domain}",
            html_body=(
                '<div style="font-family:Calibri,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#2c3e50;color:#fff;padding:12px 20px;">'
                '🔒 {org_name} — IT Security Advisory'
                '</div>'
                '<div style="padding:24px;background:#fff;border:1px solid #ddd;">'
                '<p>Dear {first_name},</p>'
                '<p>A critical vulnerability (<strong>CVE-2025-{cve_suffix}</strong>) has been '
                'identified affecting {affected_software}. Our security team requires all '
                'employees to install the patch <strong>before 5:00 PM today</strong>.</p>'
                '<h4>Instructions:</h4>'
                '<ol>'
                '<li>Click the button below to download the security patch</li>'
                '<li>Run the installer with administrator privileges</li>'
                '<li>Restart your computer when prompted</li>'
                '</ol>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#27ae60;color:#fff;padding:12px 30px;'
                'text-decoration:none;border-radius:4px;">Download Security Patch</a>'
                '</div>'
                '<div style="background:#fff3cd;padding:12px;border-radius:4px;margin:16px 0;">'
                '<strong>⚠ Important:</strong> Failure to install this patch may result '
                'in your device being quarantined from the network.'
                '</div>'
                '<p>Questions? Contact the helpdesk at ext. {helpdesk_ext}.</p>'
                '<p style="color:#999;font-size:11px;">IT Department | {org_name}</p>'
                '</div></div>'
            ),
            text_body=(
                "IT Security Advisory\n\n"
                "Dear {first_name},\n\n"
                "Critical vulnerability CVE-2025-{cve_suffix} affects {affected_software}.\n"
                "Install the patch before 5 PM today: {phish_url}\n\n"
                "Failure to comply may quarantine your device.\n\n"
                "IT Department | {org_name}"
            ),
            personalization_vars=[
                "first_name", "org_name", "domain", "cve_suffix",
                "affected_software", "helpdesk_ext", "phish_url",
            ],
            urgency_level=9,
            sophistication_level=7,
            target_industries=[IndustryType.TECHNOLOGY, IndustryType.GOVERNMENT, IndustryType.DEFENSE],
            success_rate_estimate=0.26,
            indicators_of_compromise=["Executable download from non-internal URL"],
            evasion_notes="Use real CVE number. Match internal IT ticket format.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="it-002",
            name="Email Migration Notice",
            category=PhishingCategory.IT_SUPPORT,
            subject="[Action Required] Email migration to new server — re-validate account",
            sender_name="IT Infrastructure Team",
            sender_email_local="email-admin",
            reply_to="infrastructure@{domain}",
            html_body=(
                '<div style="font-family:Calibri,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#34495e;color:#ecf0f1;padding:15px 20px;">'
                '{org_name} IT Infrastructure'
                '</div>'
                '<div style="padding:24px;background:#fff;">'
                '<p>Dear {first_name},</p>'
                '<p>As part of our scheduled infrastructure upgrade, we are migrating '
                'all email accounts to the new {mail_platform} cluster this weekend.</p>'
                '<p>To ensure a seamless migration, we need all users to '
                '<strong>re-validate their accounts</strong> before '
                '<strong>{deadline_date}</strong>.</p>'
                '<div style="background:#eaf2f8;padding:16px;border-radius:4px;margin:20px 0;">'
                '<p style="margin:0;"><strong>What you need to do:</strong></p>'
                '<p style="margin:8px 0 0;">Click below and sign in to confirm your '
                'account details. This takes less than 30 seconds.</p>'
                '</div>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#2980b9;color:#fff;padding:12px 30px;'
                'text-decoration:none;border-radius:4px;">Validate My Account</a>'
                '</div>'
                '<p style="color:#666;font-size:12px;">Accounts not validated by '
                '{deadline_date} will be temporarily suspended during migration.</p>'
                '<p style="color:#999;font-size:11px;">IT Infrastructure Team | {org_name}</p>'
                '</div></div>'
            ),
            text_body=(
                "Email Migration Notice\n\n"
                "Dear {first_name},\n\n"
                "We are migrating to {mail_platform}. Please validate your account "
                "before {deadline_date}: {phish_url}\n\n"
                "Unvalidated accounts will be suspended.\n\n"
                "IT Infrastructure Team"
            ),
            personalization_vars=[
                "first_name", "org_name", "domain", "mail_platform",
                "deadline_date", "phish_url",
            ],
            urgency_level=7,
            sophistication_level=6,
            target_industries=[IndustryType.EDUCATION, IndustryType.GOVERNMENT, IndustryType.HEALTHCARE],
            success_rate_estimate=0.28,
            indicators_of_compromise=["Login page URL not internal"],
            evasion_notes="Time around known IT maintenance windows. Use internal jargon.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="it-003",
            name="Multi-Factor Authentication Setup",
            category=PhishingCategory.IT_SUPPORT,
            subject="[Mandatory] Enroll in Multi-Factor Authentication by {deadline_date}",
            sender_name="{org_name} Security Team",
            sender_email_local="security",
            reply_to="mfa-support@{domain}",
            html_body=(
                '<div style="font-family:Segoe UI,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#1a1a2e;padding:16px 24px;">'
                '<span style="color:#e94560;">🛡</span>'
                '<span style="color:#fff;font-weight:600;margin-left:8px;">'
                '{org_name} Security</span>'
                '</div>'
                '<div style="padding:24px;background:#fff;border:1px solid #e0e0e0;">'
                '<p>Hi {first_name},</p>'
                '<p>Per our new security policy, <strong>all employees must enroll '
                'in Multi-Factor Authentication (MFA)</strong> by '
                '<strong>{deadline_date}</strong>.</p>'
                '<p>The enrollment process takes approximately 2 minutes:</p>'
                '<ol>'
                '<li>Click the enrollment link below</li>'
                '<li>Sign in with your current password</li>'
                '<li>Scan the QR code with your authenticator app</li>'
                '<li>Enter the verification code to complete setup</li>'
                '</ol>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#e94560;color:#fff;padding:12px 30px;'
                'text-decoration:none;border-radius:4px;">Begin MFA Enrollment</a>'
                '</div>'
                '<p style="color:#c0392b;font-size:13px;"><strong>Note:</strong> Accounts '
                'without MFA after {deadline_date} will be locked until enrollment '
                'is completed.</p>'
                '<p style="color:#999;font-size:11px;">Security Team | {org_name}</p>'
                '</div></div>'
            ),
            text_body=(
                "MFA Enrollment Required\n\n"
                "Hi {first_name},\n\n"
                "Enroll in MFA by {deadline_date}: {phish_url}\n\n"
                "Accounts without MFA will be locked.\n\n"
                "Security Team | {org_name}"
            ),
            personalization_vars=["first_name", "org_name", "domain", "deadline_date", "phish_url"],
            urgency_level=7,
            sophistication_level=7,
            target_industries=[IndustryType.FINANCE, IndustryType.HEALTHCARE, IndustryType.GOVERNMENT],
            success_rate_estimate=0.30,
            indicators_of_compromise=["QR code leads to attacker relay"],
            evasion_notes="Ironic - uses MFA enrollment as phishing. Extremely effective.",
        ))

        # ── HR POLICY templates ───────────────────────────────────────────
        all_templates.append(PhishingTemplate(
            template_id="hr-001",
            name="Annual Benefits Enrollment",
            category=PhishingCategory.HR_POLICY,
            subject="Open Enrollment {year} — Action required by {deadline_date}",
            sender_name="{org_name} Human Resources",
            sender_email_local="benefits",
            reply_to="hr-benefits@{domain}",
            html_body=(
                '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#2ecc71;color:#fff;padding:15px 20px;">'
                '🏥 {org_name} — Open Enrollment {year}'
                '</div>'
                '<div style="padding:24px;background:#fff;border:1px solid #ddd;">'
                '<p>Dear {first_name},</p>'
                '<p>Annual benefits open enrollment for {year} is now open! '
                'You have until <strong>{deadline_date}</strong> to review and update '
                'your elections for:</p>'
                '<ul>'
                '<li>Medical, dental, and vision insurance</li>'
                '<li>Life and disability coverage</li>'
                '<li>401(k) contribution changes</li>'
                '<li>FSA/HSA elections</li>'
                '<li>New: Mental health & wellness stipend</li>'
                '</ul>'
                '<p><strong>Important change:</strong> This year, we are offering a new '
                'premium PPO plan with expanded coverage. Review details in the portal.</p>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#2ecc71;color:#fff;padding:12px 30px;'
                'text-decoration:none;border-radius:4px;">Review My Benefits</a>'
                '</div>'
                '<p style="color:#666;font-size:12px;">If you do not make elections by '
                '{deadline_date}, your current selections will carry forward — except '
                'FSA, which resets to $0.</p>'
                '<p style="color:#999;font-size:11px;">Human Resources | {org_name}</p>'
                '</div></div>'
            ),
            text_body=(
                "Open Enrollment {year}\n\n"
                "Dear {first_name},\n\n"
                "Review and update your benefits by {deadline_date}: {phish_url}\n\n"
                "FSA resets to $0 if not re-elected.\n\n"
                "Human Resources | {org_name}"
            ),
            personalization_vars=["first_name", "org_name", "domain", "year", "deadline_date", "phish_url"],
            urgency_level=6,
            sophistication_level=7,
            target_industries=[IndustryType.FINANCE, IndustryType.TECHNOLOGY, IndustryType.HEALTHCARE],
            success_rate_estimate=0.33,
            indicators_of_compromise=["Benefits portal URL not on org SSO domain"],
            evasion_notes="Time during actual open enrollment season (Oct-Nov). High click rates.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="hr-002",
            name="Salary Adjustment Notification",
            category=PhishingCategory.HR_POLICY,
            subject="Confidential: Your compensation adjustment for {year}",
            sender_name="HR Compensation Team",
            sender_email_local="compensation",
            reply_to="comp-team@{domain}",
            html_body=(
                '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#8e44ad;color:#fff;padding:12px 20px;">'
                '💰 {org_name} — Compensation & Total Rewards'
                '</div>'
                '<div style="padding:24px;background:#fff;border:1px solid #ddd;">'
                '<p>Dear {first_name},</p>'
                '<p>Following the annual compensation review cycle, we are pleased to '
                'inform you that your compensation has been adjusted effective '
                '<strong>{effective_date}</strong>.</p>'
                '<p>Please log in to the HR portal to review your updated compensation '
                'details, including:</p>'
                '<ul>'
                '<li>Base salary adjustment</li>'
                '<li>Bonus structure changes</li>'
                '<li>Updated total compensation statement</li>'
                '</ul>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#8e44ad;color:#fff;padding:12px 30px;'
                'text-decoration:none;border-radius:4px;">View My Compensation</a>'
                '</div>'
                '<p style="color:#c0392b;font-size:12px;"><strong>Reminder:</strong> '
                'Compensation information is strictly confidential and should not be '
                'shared with colleagues.</p>'
                '<p style="color:#999;font-size:11px;">HR Compensation Team | {org_name}</p>'
                '</div></div>'
            ),
            text_body=(
                "Compensation Adjustment\n\n"
                "Dear {first_name},\n\n"
                "Your compensation has been adjusted effective {effective_date}.\n"
                "View details: {phish_url}\n\n"
                "This information is confidential.\n\n"
                "HR Compensation Team | {org_name}"
            ),
            personalization_vars=[
                "first_name", "org_name", "domain", "year",
                "effective_date", "phish_url",
            ],
            urgency_level=5,
            sophistication_level=7,
            target_industries=[IndustryType.TECHNOLOGY, IndustryType.FINANCE],
            success_rate_estimate=0.41,
            indicators_of_compromise=["Login page harvests credentials"],
            evasion_notes="Highest click rate template. Everyone checks salary changes.",
        ))

        # ── PACKAGE DELIVERY templates ────────────────────────────────────
        all_templates.append(PhishingTemplate(
            template_id="pkg-001",
            name="FedEx Delivery Exception",
            category=PhishingCategory.PACKAGE_DELIVERY,
            subject="FedEx: Delivery Exception — Package #{tracking_number}",
            sender_name="FedEx Delivery Manager",
            sender_email_local="tracking",
            reply_to="",
            html_body=(
                '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#4d148c;padding:12px 20px;">'
                '<span style="color:#ff6600;font-weight:bold;font-size:20px;">FedEx</span>'
                '</div>'
                '<div style="padding:24px;background:#fff;border:1px solid #ddd;">'
                '<h3 style="color:#333;margin-top:0;">Delivery Exception Notice</h3>'
                '<p>Dear Customer,</p>'
                '<p>We were unable to deliver your package due to an '
                '<strong>incomplete delivery address</strong>. Your shipment is being '
                'held at the local facility.</p>'
                '<div style="background:#f5f5f5;padding:16px;margin:16px 0;border-radius:4px;">'
                '<p style="margin:4px 0;">Tracking #: <strong>{tracking_number}</strong></p>'
                '<p style="margin:4px 0;">Scheduled: {delivery_date}</p>'
                '<p style="margin:4px 0;">Status: <span style="color:#cc0000;">Exception</span></p>'
                '<p style="margin:4px 0;">Reason: Incomplete address</p>'
                '</div>'
                '<p>Please verify your delivery details within 48 hours or the package '
                'will be returned to sender.</p>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#ff6600;color:#fff;padding:12px 30px;'
                'text-decoration:none;border-radius:4px;">Update Delivery Details</a>'
                '</div>'
                '<p style="color:#999;font-size:11px;">FedEx Corporation. '
                'This is an automated notification.</p>'
                '</div></div>'
            ),
            text_body=(
                "FedEx Delivery Exception\n\n"
                "Package #{tracking_number} could not be delivered.\n"
                "Reason: Incomplete address\n\n"
                "Verify details: {phish_url}\n\n"
                "Package will be returned in 48 hours."
            ),
            personalization_vars=["tracking_number", "delivery_date", "phish_url"],
            urgency_level=7,
            sophistication_level=5,
            target_industries=[IndustryType.RETAIL, IndustryType.MANUFACTURING],
            success_rate_estimate=0.22,
            indicators_of_compromise=["Not from fedex.com", "Generic greeting"],
            evasion_notes="Effective during holiday season. Use realistic tracking format.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="pkg-002",
            name="Amazon Order Confirmation Suspicious",
            category=PhishingCategory.PACKAGE_DELIVERY,
            subject="Your Amazon order #{order_number} has shipped",
            sender_name="Amazon.com",
            sender_email_local="ship-confirm",
            reply_to="",
            html_body=(
                '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#232f3e;padding:10px 20px;">'
                '<span style="color:#ff9900;font-size:20px;font-weight:bold;">amazon</span>'
                '</div>'
                '<div style="padding:20px;background:#fff;">'
                '<p style="color:#111;font-size:14px;">Hello {first_name},</p>'
                '<p>Your order has shipped! Here are the details:</p>'
                '<div style="border:1px solid #ddd;padding:16px;margin:16px 0;">'
                '<p style="margin:4px 0;"><strong>Order #{order_number}</strong></p>'
                '<p style="margin:4px 0;">{product_name}</p>'
                '<p style="margin:4px 0;">Qty: {quantity} | Total: ${total_amount}</p>'
                '<p style="margin:4px 0;">Delivery: {delivery_date}</p>'
                '</div>'
                '<p>Didn\'t place this order? Someone may be using your account.</p>'
                '<div style="text-align:center;margin:20px 0;">'
                '<a href="{phish_url}" style="background:#ff9900;color:#111;padding:10px 24px;'
                'text-decoration:none;border-radius:20px;font-weight:bold;">Review Order</a>'
                '</div>'
                '<p style="color:#999;font-size:11px;">Amazon.com, Inc.</p>'
                '</div></div>'
            ),
            text_body=(
                "Your Amazon order #{order_number} has shipped.\n"
                "{product_name} | ${total_amount}\n"
                "Delivery: {delivery_date}\n\n"
                "Didn't order this? Review: {phish_url}"
            ),
            personalization_vars=[
                "first_name", "order_number", "product_name",
                "quantity", "total_amount", "delivery_date", "phish_url",
            ],
            urgency_level=7,
            sophistication_level=6,
            target_industries=[IndustryType.RETAIL, IndustryType.TECHNOLOGY],
            success_rate_estimate=0.25,
            indicators_of_compromise=["Not from amazon.com domain"],
            evasion_notes="High-value product creates urgency. Use popular electronics.",
        ))

        # ── MFA FATIGUE templates ─────────────────────────────────────────
        all_templates.append(PhishingTemplate(
            template_id="mfa-001",
            name="MFA Push Approval Follow-up",
            category=PhishingCategory.MFA_FATIGUE,
            subject="IT Alert: Please approve the pending MFA request",
            sender_name="{org_name} IT Security",
            sender_email_local="it-security",
            reply_to="security@{domain}",
            html_body=(
                '<div style="font-family:Calibri,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#e74c3c;color:#fff;padding:12px 20px;">'
                '⚠ {org_name} — Security Alert'
                '</div>'
                '<div style="padding:24px;background:#fff;border:1px solid #ddd;">'
                '<p>Hi {first_name},</p>'
                '<p>Our monitoring systems detected that your account has a pending '
                'MFA authentication request. This is part of a <strong>mandatory '
                'security verification</strong> being conducted by IT.</p>'
                '<p>Please <strong>approve the push notification</strong> on your '
                'authenticator app, or enter the code below:</p>'
                '<div style="text-align:center;margin:24px 0;">'
                '<div style="display:inline-block;background:#f5f5f5;padding:16px 32px;'
                'border-radius:8px;font-size:28px;letter-spacing:4px;font-weight:bold;">'
                '{mfa_code}'
                '</div>'
                '</div>'
                '<p>If you are unable to approve via push, click below to complete '
                'the verification through the web portal:</p>'
                '<div style="text-align:center;margin:20px 0;">'
                '<a href="{phish_url}" style="background:#3498db;color:#fff;padding:10px 24px;'
                'text-decoration:none;border-radius:4px;">Complete Verification</a>'
                '</div>'
                '<p style="color:#e74c3c;font-size:13px;">If you do NOT approve within '
                '15 minutes, your account will be temporarily locked for security.</p>'
                '<p style="color:#999;font-size:11px;">IT Security | {org_name}</p>'
                '</div></div>'
            ),
            text_body=(
                "Security Alert\n\n"
                "Hi {first_name},\n\n"
                "Your account has a pending MFA request. Approve the push "
                "notification or use code: {mfa_code}\n\n"
                "Or verify at: {phish_url}\n\n"
                "Account will lock in 15 minutes without approval.\n\n"
                "IT Security | {org_name}"
            ),
            personalization_vars=["first_name", "org_name", "domain", "mfa_code", "phish_url"],
            urgency_level=9,
            sophistication_level=8,
            target_industries=[IndustryType.TECHNOLOGY, IndustryType.FINANCE],
            success_rate_estimate=0.19,
            indicators_of_compromise=["Unsolicited MFA request", "External verification link"],
            evasion_notes="Send alongside actual MFA pushes during brute-force attempt.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="mfa-002",
            name="Authentication App Migration",
            category=PhishingCategory.MFA_FATIGUE,
            subject="[Required] Migrate to {new_auth_app} by {deadline_date}",
            sender_name="{org_name} Security Operations",
            sender_email_local="secops",
            reply_to="secops@{domain}",
            html_body=(
                '<div style="font-family:Segoe UI,sans-serif;max-width:600px;margin:0 auto;">'
                '<div style="background:#2c3e50;padding:16px 24px;">'
                '<span style="color:#1abc9c;">🔐</span>'
                '<span style="color:#fff;font-weight:600;margin-left:8px;">'
                '{org_name} SecOps</span>'
                '</div>'
                '<div style="padding:24px;background:#fff;border:1px solid #e0e0e0;">'
                '<p>Hello {first_name},</p>'
                '<p>As part of our security hardening initiative, we are migrating '
                'all employees from {old_auth_app} to <strong>{new_auth_app}</strong> '
                'for multi-factor authentication.</p>'
                '<p><strong>Action required by {deadline_date}:</strong></p>'
                '<ol>'
                '<li>Click the migration link below</li>'
                '<li>Authenticate with your current credentials</li>'
                '<li>Scan the new QR code with {new_auth_app}</li>'
                '<li>Confirm the 6-digit code</li>'
                '</ol>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#1abc9c;color:#fff;padding:12px 30px;'
                'text-decoration:none;border-radius:4px;">Begin Migration</a>'
                '</div>'
                '<div style="background:#ffeaa7;padding:12px;border-radius:4px;">'
                '<strong>Warning:</strong> After {deadline_date}, {old_auth_app} '
                'tokens will be revoked and you will lose access until migration '
                'is complete.'
                '</div>'
                '<p style="color:#999;font-size:11px;">Security Operations | {org_name}</p>'
                '</div></div>'
            ),
            text_body=(
                "MFA Migration Required\n\n"
                "Hello {first_name},\n\n"
                "Migrate from {old_auth_app} to {new_auth_app} by {deadline_date}.\n"
                "Begin: {phish_url}\n\n"
                "{old_auth_app} tokens will be revoked after deadline.\n\n"
                "Security Operations | {org_name}"
            ),
            personalization_vars=[
                "first_name", "org_name", "domain", "old_auth_app",
                "new_auth_app", "deadline_date", "phish_url",
            ],
            urgency_level=7,
            sophistication_level=8,
            target_industries=[IndustryType.TECHNOLOGY, IndustryType.FINANCE, IndustryType.DEFENSE],
            success_rate_estimate=0.24,
            indicators_of_compromise=["QR redirect to adversary-in-the-middle proxy"],
            evasion_notes="Research which auth app org actually uses for realism.",
        ))

        # ── Additional CREDENTIAL HARVEST ─────────────────────────────────
        all_templates.append(PhishingTemplate(
            template_id="cred-004",
            name="LinkedIn Connection Request",
            category=PhishingCategory.CREDENTIAL_HARVEST,
            subject="{sender_person} wants to connect on LinkedIn",
            sender_name="LinkedIn",
            sender_email_local="notifications-noreply",
            reply_to="",
            html_body=(
                '<div style="font-family:Helvetica,Arial,sans-serif;max-width:560px;margin:0 auto;">'
                '<div style="background:#0a66c2;padding:12px 20px;">'
                '<span style="color:#fff;font-size:20px;font-weight:bold;">LinkedIn</span>'
                '</div>'
                '<div style="padding:24px;background:#fff;">'
                '<div style="display:flex;align-items:center;margin-bottom:20px;">'
                '<div style="width:56px;height:56px;background:#ddd;border-radius:50%;'
                'margin-right:16px;display:flex;align-items:center;justify-content:center;'
                'font-size:24px;color:#666;">👤</div>'
                '<div>'
                '<p style="margin:0;font-weight:600;">{sender_person}</p>'
                '<p style="margin:2px 0;color:#666;font-size:13px;">{sender_title}</p>'
                '<p style="margin:2px 0;color:#666;font-size:13px;">{sender_company}</p>'
                '</div></div>'
                '<div style="text-align:center;margin:20px 0;">'
                '<a href="{phish_url}" style="background:#0a66c2;color:#fff;padding:8px 24px;'
                'text-decoration:none;border-radius:20px;">Accept</a>'
                '<a href="#" style="color:#0a66c2;padding:8px 24px;'
                'text-decoration:none;margin-left:12px;">Ignore</a>'
                '</div>'
                '<p style="color:#999;font-size:11px;text-align:center;">'
                'LinkedIn Corporation, 1000 W Maude Ave, Sunnyvale, CA 94085</p>'
                '</div></div>'
            ),
            text_body=(
                "{sender_person} wants to connect on LinkedIn.\n"
                "{sender_title} at {sender_company}\n\n"
                "Accept: {phish_url}\n\n"
                "LinkedIn Corporation"
            ),
            personalization_vars=[
                "sender_person", "sender_title", "sender_company", "phish_url",
            ],
            urgency_level=3,
            sophistication_level=6,
            target_industries=[IndustryType.TECHNOLOGY, IndustryType.FINANCE, IndustryType.LEGAL],
            success_rate_estimate=0.20,
            indicators_of_compromise=["Link not to linkedin.com"],
            evasion_notes="Use name of real industry peer from target LinkedIn network.",
        ))

        all_templates.append(PhishingTemplate(
            template_id="cred-005",
            name="Slack Workspace Invitation",
            category=PhishingCategory.CREDENTIAL_HARVEST,
            subject="{inviter_name} invited you to join {workspace_name} on Slack",
            sender_name="Slack",
            sender_email_local="feedback",
            reply_to="",
            html_body=(
                '<div style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;'
                'max-width:560px;margin:0 auto;">'
                '<div style="padding:20px;text-align:center;">'
                '<span style="font-size:28px;font-weight:bold;color:#611f69;">slack</span>'
                '</div>'
                '<div style="padding:0 24px 24px;">'
                '<h2 style="text-align:center;font-weight:normal;color:#1d1c1d;">'
                'You\'ve been invited to join<br />'
                '<strong>{workspace_name}</strong></h2>'
                '<p style="text-align:center;color:#616061;">'
                '{inviter_name} ({inviter_email}) has invited you to collaborate '
                'in the <strong>{workspace_name}</strong> workspace.</p>'
                '<div style="text-align:center;margin:24px 0;">'
                '<a href="{phish_url}" style="background:#611f69;color:#fff;'
                'padding:12px 32px;text-decoration:none;border-radius:4px;'
                'font-size:16px;font-weight:600;">Join Now</a>'
                '</div>'
                '<p style="text-align:center;color:#999;font-size:12px;">'
                'Slack Technologies, LLC</p>'
                '</div></div>'
            ),
            text_body=(
                "{inviter_name} invited you to {workspace_name} on Slack.\n\n"
                "Join: {phish_url}\n\n"
                "Slack Technologies, LLC"
            ),
            personalization_vars=[
                "inviter_name", "inviter_email", "workspace_name", "phish_url",
            ],
            urgency_level=4,
            sophistication_level=7,
            target_industries=[IndustryType.TECHNOLOGY, IndustryType.MEDIA],
            success_rate_estimate=0.22,
            indicators_of_compromise=["Not from slack.com", "Join link not slack.com/accept"],
            evasion_notes="Use actual workspace name from OSINT. Time with onboarding periods.",
        ))

        # Register all templates
        for tpl in all_templates:
            self._register_template(tpl)

    def _register_template(self, template: PhishingTemplate) -> None:
        """Register a template in the index."""
        with self._lock:
            self._templates[template.template_id] = template
            self._template_index[template.category].append(template.template_id)

    def get_template(self, template_id: str) -> Optional[PhishingTemplate]:
        """Retrieve a template by ID."""
        with self._lock:
            return self._templates.get(template_id)

    def get_templates_by_category(
        self, category: PhishingCategory
    ) -> List[PhishingTemplate]:
        """Get all templates for a given category."""
        with self._lock:
            ids = self._template_index.get(category, [])
            return [self._templates[tid] for tid in ids if tid in self._templates]

    def get_all_templates(self) -> List[PhishingTemplate]:
        """Return all registered templates."""
        with self._lock:
            return list(self._templates.values())

    def generate_custom_template(
        self,
        category: PhishingCategory,
        target_org: str = "",
        sender_persona: str = "",
        urgency: int = 7,
        custom_subject: str = "",
        custom_body_elements: Optional[Dict[str, str]] = None,
    ) -> PhishingTemplate:
        """Generate a customized phishing template based on parameters.

        Selects the best matching base template for the category, then
        personalizes it with the provided parameters.
        """
        with self._lock:
            base_templates = self.get_templates_by_category(category)
            if not base_templates:
                base_templates = list(self._templates.values())

            # Select template with highest success rate for the category
            base = max(base_templates, key=lambda t: t.success_rate_estimate)

            template_id = f"custom-{hashlib.sha256(f'{category.name}-{target_org}-{time.time()}'.encode()).hexdigest()[:12]}"

            custom = PhishingTemplate(
                template_id=template_id,
                name=f"Custom {category.name} for {target_org}",
                category=category,
                subject=custom_subject or base.subject,
                sender_name=sender_persona or base.sender_name,
                sender_email_local=base.sender_email_local,
                reply_to=base.reply_to,
                html_body=base.html_body,
                text_body=base.text_body,
                personalization_vars=base.personalization_vars,
                urgency_level=urgency,
                sophistication_level=base.sophistication_level,
                target_industries=base.target_industries,
                success_rate_estimate=base.success_rate_estimate,
                indicators_of_compromise=base.indicators_of_compromise,
                evasion_notes=base.evasion_notes,
            )

            if custom_body_elements:
                for key, value in custom_body_elements.items():
                    custom.html_body = custom.html_body.replace(f"{{{key}}}", value)
                    custom.text_body = custom.text_body.replace(f"{{{key}}}", value)

            self._register_template(custom)
            return custom

    def personalize_template(
        self, template: PhishingTemplate, variables: Dict[str, str]
    ) -> PhishingTemplate:
        """Fill personalization variables in a template."""
        import copy
        personalized = copy.deepcopy(template)
        personalized.template_id = f"personalized-{uuid.uuid4().hex[:12]}"

        for var, value in variables.items():
            placeholder = f"{{{var}}}"
            personalized.subject = personalized.subject.replace(placeholder, value)
            personalized.sender_name = personalized.sender_name.replace(placeholder, value)
            personalized.html_body = personalized.html_body.replace(placeholder, value)
            personalized.text_body = personalized.text_body.replace(placeholder, value)
            personalized.reply_to = personalized.reply_to.replace(placeholder, value)

        return personalized

    def get_template_stats(self) -> Dict[str, Any]:
        """Return statistics about the template library."""
        with self._lock:
            stats: Dict[str, Any] = {
                "total_templates": len(self._templates),
                "by_category": {},
                "avg_success_rate": 0.0,
                "highest_success_template": "",
                "avg_urgency": 0.0,
                "avg_sophistication": 0.0,
            }

            if not self._templates:
                return stats

            total_success = 0.0
            total_urgency = 0
            total_sophist = 0
            best_rate = 0.0
            best_id = ""

            for cat, ids in self._template_index.items():
                stats["by_category"][cat.name] = len(ids)

            for tpl in self._templates.values():
                total_success += tpl.success_rate_estimate
                total_urgency += tpl.urgency_level
                total_sophist += tpl.sophistication_level
                if tpl.success_rate_estimate > best_rate:
                    best_rate = tpl.success_rate_estimate
                    best_id = tpl.template_id

            n = len(self._templates)
            stats["avg_success_rate"] = round(total_success / n, 4)
            stats["highest_success_template"] = best_id
            stats["avg_urgency"] = round(total_urgency / n, 2)
            stats["avg_sophistication"] = round(total_sophist / n, 2)

            return stats


# ════════════════════════════════════════════════════════════════════════════════
# PRETEXT BUILDER
# ════════════════════════════════════════════════════════════════════════════════

class PretextBuilder:
    """Builds detailed pretext scripts for physical and phone-based social engineering.

    Provides 15+ complete scenario scripts with conversation flows, objection
    handlers, and props lists for authorized red team engagements.

    Usage:
        builder = PretextBuilder()
        script = builder.get_script(PretextScenario.IT_HELPDESK)
        scripts = builder.get_scripts_by_difficulty(max_difficulty=6)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._scripts: Dict[str, PretextScript] = {}
        self._scenario_index: Dict[PretextScenario, List[str]] = defaultdict(list)
        self._initialize_scripts()
        logger.info("PretextBuilder initialized with %d scripts", len(self._scripts))

    def _initialize_scripts(self) -> None:
        """Build the complete library of pretext scripts."""
        scripts = []

        # ── IT HELPDESK ───────────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-001",
            scenario=PretextScenario.IT_HELPDESK,
            title="IT Helpdesk Password Reset",
            objective="Obtain user credentials or install remote access tool on target workstation",
            target_role="Non-technical employee (admin assistant, HR, finance)",
            opening_lines=[
                "Hi {target_name}, this is {fake_name} from IT support. We've detected some unusual activity on your account and I need to verify a few things.",
                "Good morning, this is {fake_name} calling from the helpdesk. We're rolling out a security update and your machine was flagged as needing manual attention.",
                "Hi there, IT department here. We received an alert that your email account may have been compromised. I need to walk you through a quick security check.",
            ],
            conversation_flow=[
                {"phase": "rapport", "script": "How's your day going? I know these calls are inconvenient but we want to make sure your account stays secure. This should only take about 5 minutes."},
                {"phase": "authority", "script": "I'm following up on ticket #{ticket_number} that was escalated to our security team by {manager_name}. We need to resolve this before end of day."},
                {"phase": "information_gathering", "script": "Can you confirm your username for me? It should be in the format first.last. And which version of {software} are you running? You can check under Help > About."},
                {"phase": "action", "script": "What I need you to do is open your browser and go to {phish_url}. This is our internal remote support portal. You'll see a download button — go ahead and run that. It will let me see your screen so I can apply the fix."},
                {"phase": "credential_harvest", "script": "The system is asking me to re-verify your identity. Can you type your password into the authentication box that just popped up? Don't worry, I can't see what you type — it's encrypted on our end."},
                {"phase": "wrap_up", "script": "Perfect, the update is installing now. You might notice your machine running a bit slow for the next few minutes — that's completely normal. Is there anything else I can help you with today?"},
            ],
            objection_handlers={
                "I need to verify who you are": "Absolutely, that's smart security practice! My employee ID is {fake_emp_id}. You can also check our IT directory at {fake_directory_url}, or call the main helpdesk number and ask for me — {fake_name}.",
                "I'll call IT back myself": "Of course, I understand the caution. The helpdesk number is {real_helpdesk} — but ask for the security team, not tier 1. Reference ticket #{ticket_number}. Just be aware the vulnerability window closes at 5 PM.",
                "My manager should know about this": "Your manager {manager_name} was actually the one who escalated this. But feel free to loop them in — we just need to get the patch applied today.",
                "I'm not comfortable giving my password": "I completely understand. Let me walk you through a password reset instead. Go to {phish_url} and create a new password there. That way you're not sharing your current one.",
                "This seems suspicious": "I appreciate the caution — that's exactly the kind of awareness we want to see. You can verify this is legitimate by checking your email — I sent a confirmation from it-security@{domain} about 10 minutes ago.",
            },
            escalation_triggers=[
                "Target mentions calling their manager or IT directly",
                "Target asks for ticket number not provided in brief",
                "Target becomes hostile or threatens to report",
            ],
            props_required=[
                "Spoofed caller ID showing internal IT number",
                "Fake IT portal landing page",
                "Pre-sent verification email from spoofed internal address",
                "Knowledge of target's manager name and department",
            ],
            success_criteria=[
                "Target provides credentials",
                "Target installs remote access tool",
                "Target navigates to phishing URL",
            ],
            abort_conditions=[
                "Target explicitly refuses and escalates to security team",
                "Target records the call",
                "Physical security is alerted",
            ],
            estimated_duration_min=12,
            difficulty_rating=4,
        ))

        # ── NEW EMPLOYEE ──────────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-002",
            scenario=PretextScenario.NEW_EMPLOYEE,
            title="New Employee First Day Confusion",
            objective="Gain physical access to restricted areas or obtain badge/credentials",
            target_role="Receptionist, security guard, or helpful employee",
            opening_lines=[
                "Hi! I'm {fake_name}, I'm supposed to start today in {department} but I'm completely lost. HR told me to come here but I don't have my badge yet.",
                "Good morning! I'm the new {job_title} — today's my first day and I can't find my way to {department}. My manager {manager_name} said to ask at the front desk.",
                "Hey, sorry to bother you. I'm {fake_name}, I just transferred from the {city} office. I'm supposed to be set up in {department} but my access card doesn't seem to work on these doors.",
            ],
            conversation_flow=[
                {"phase": "establish_identity", "script": "I have my offer letter right here if you need to see it. {manager_name} in {department} should be expecting me. I tried calling but went straight to voicemail."},
                {"phase": "build_sympathy", "script": "I'm so sorry for the confusion — I've been running around for 20 minutes now. HR said my badge would be ready but apparently there was a system issue. This is NOT how I wanted my first day to go!"},
                {"phase": "request_access", "script": "Is there any way you could let me through to {department}? I have a meeting with {manager_name} at {meeting_time} and I'm already late. I promise I'll sort out the badge after."},
                {"phase": "tailgate", "script": "Oh, you're heading that way too? Mind if I walk with you? I have no idea where anything is in this building yet."},
                {"phase": "information_gathering", "script": "By the way, do you know if {department} uses {software}? I want to make sure I have the right tools installed. Also, what's the WiFi password for guests until IT sets me up?"},
                {"phase": "extend_access", "script": "This is great, thank you so much for helping me out. Hey, do you know where the server room is? {manager_name} mentioned I might need to set up something there later this week."},
            ],
            objection_handlers={
                "I need to verify with your manager": "Of course! {manager_name}'s extension is {fake_ext}. Or you can check the company directory — I should be listed under new hires for {department}.",
                "You need a badge to enter": "I totally understand. Is there a temporary badge I could use? Or could you escort me to {department}? I really don't want to miss my first meeting.",
                "Let me call security": "Oh no, I don't want to cause any trouble! I think there's just a mix-up with my start date in the system. Can we try reaching {manager_name} first?",
                "I can't let anyone in without authorization": "I completely respect that — good security practice! Could you perhaps call {manager_name} at extension {fake_ext} to confirm? Or I can wait here if you want to check with HR.",
            },
            escalation_triggers=[
                "Security is called and responds in person",
                "Target verifies and discovers no new hire record",
                "Badge system audit is triggered",
            ],
            props_required=[
                "Business casual attire matching org dress code",
                "Fake offer letter on org letterhead",
                "Laptop bag with visible brand stickers",
                "Personal phone with calendar showing fake meetings",
                "Printed building map marked with question marks",
            ],
            success_criteria=[
                "Gain access past reception without a badge",
                "Successfully tailgate into restricted area",
                "Obtain WiFi credentials or network access",
                "Reach target department or server room",
            ],
            abort_conditions=[
                "Security detains or escorts out",
                "Law enforcement is contacted",
                "Target positively identifies as unauthorized",
            ],
            estimated_duration_min=20,
            difficulty_rating=5,
        ))

        # ── VENDOR/PARTNER ────────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-003",
            scenario=PretextScenario.VENDOR_PARTNER,
            title="Vendor Service Visit",
            objective="Access server rooms, network closets, or plant rogue device",
            target_role="Facilities manager, IT staff, or receptionist",
            opening_lines=[
                "Hi, I'm {fake_name} from {vendor_company}. We have a scheduled maintenance visit for your {equipment_type} systems today. Should be about an hour.",
                "Good morning, {vendor_company} field service here. We received an automated alert from your {equipment_type} and I'm here to run diagnostics before it becomes a bigger issue.",
                "Hello, I'm the technician from {vendor_company}. {manager_name} put in a service request last week — ticket #{ticket_number}. I'm here to take a look at the {equipment_type}.",
            ],
            conversation_flow=[
                {"phase": "credibility", "script": "Here's my business card and service order. The work order was opened by {manager_name} on {service_date}. We try to get to these within 48 hours."},
                {"phase": "access_request", "script": "I'll need access to your {target_room} where the {equipment_type} is installed. The diagnostics usually take about 30-45 minutes. I'll need a power outlet and network drop nearby."},
                {"phase": "plant_device", "script": "I need to connect this diagnostic module to your network for the health check. It monitors traffic patterns to identify the issue. I'll remove it when I'm done."},
                {"phase": "information_gathering", "script": "What firmware version are you running on the {equipment_type}? And is this segment on VLAN {vlan_number} or is it flat? I need to make sure the diagnostics target the right subnet."},
                {"phase": "extend_scope", "script": "While I'm here, I noticed your {secondary_equipment} is running an older firmware. There's a known vulnerability — want me to update it while I'm on-site? No extra charge."},
                {"phase": "exit", "script": "All done. Everything looks good now. Here's my report — I'll email a copy to {manager_name} as well. If you have any issues, call our service line and reference this ticket."},
            ],
            objection_handlers={
                "We weren't expecting a service visit": "That's odd — it was scheduled through your facilities portal. Let me pull up the work order... Here it is, submitted by {manager_name} on {service_date}. Sometimes the notification emails go to spam.",
                "I need to check with IT first": "Sure, no problem. {it_contact} in your IT department should have the details. I can wait if you want to confirm. Just know I have two more stops today so timing is a bit tight.",
                "You can't connect anything to our network": "I understand the concern. The diagnostic module is read-only — it just listens for protocol anomalies. If you want, your IT team can supervise the entire process. It's standard procedure for {vendor_company} service calls.",
                "Do you have identification?": "Absolutely. Here's my {vendor_company} ID badge and the service authorization signed by your facilities coordinator. I can also give you our dispatch center number to verify — it's {fake_phone}.",
            },
            escalation_triggers=[
                "IT team wants to inspect the diagnostic device",
                "Facilities calls the real vendor to confirm",
                "Escort is assigned and closely monitors all actions",
            ],
            props_required=[
                "Branded polo/uniform matching vendor",
                "Fake business cards",
                "Printed service order with org details",
                "Vendor ID badge (replicated)",
                "Laptop with vendor diagnostic software UI",
                "Rogue network device (if in scope)",
                "Toolbox with appropriate equipment",
            ],
            success_criteria=[
                "Gain unescorted access to server room/network closet",
                "Successfully plant rogue device on network",
                "Obtain network configuration details",
            ],
            abort_conditions=[
                "Real vendor is contacted and confirms no appointment",
                "Security confiscates equipment",
                "Law enforcement is called",
            ],
            estimated_duration_min=45,
            difficulty_rating=6,
        ))

        # ── DELIVERY PERSON ───────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-004",
            scenario=PretextScenario.DELIVERY_PERSON,
            title="Package Delivery with Tailgate",
            objective="Gain physical access past reception, plant USB drops, or access network",
            target_role="Receptionist, mail room staff, or any employee at entrance",
            opening_lines=[
                "Delivery for {target_name} in {department}. Need a signature please.",
                "Hi, I have a priority package from {sender_company} for {department}. The sender marked it as urgent — can someone sign?",
                "Morning! Got a large shipment here for {org_name} — 3 boxes. Where should I bring them?",
            ],
            conversation_flow=[
                {"phase": "entry", "script": "These are heavy boxes — is there a loading dock or should I bring them through here? I need someone to sign for them."},
                {"phase": "access_extension", "script": "The sender requested direct delivery to {target_name}'s desk in {department}. Something about the contents being fragile and confidential. Mind showing me the way?"},
                {"phase": "usb_drop", "script": "Oh, I think this USB drive fell out of one of the boxes. It says '{label_text}' on it. Must be important — should I leave it with the package?"},
                {"phase": "recon", "script": "While I'm here, do you have a restroom I could use? Also, do you guys validate parking? I had to park in the structure next door."},
                {"phase": "rapport", "script": "You guys have a nice office. I deliver to a lot of companies around here but this one's got the best setup. Do you work on this floor?"},
            ],
            objection_handlers={
                "We'll take it at the front desk": "The shipping label specifically says 'deliver to recipient — do not leave at reception.' I could get in trouble if I don't follow the instructions. It'll just take a minute.",
                "I need to check if they're expecting a package": "Sure! The tracking number is {fake_tracking}. It was sent by {sender_company} two days ago. I have 15 more deliveries so I'm on a tight schedule.",
                "You can't go beyond the lobby": "I understand. Could you call {target_name} to come down? Or if someone could escort me, I'll be in and out in 2 minutes. These boxes are really heavy to carry far.",
            },
            escalation_triggers=[
                "Receptionist refuses to let delivery person past lobby",
                "Security asks for delivery company verification",
                "Target name is not found in directory",
            ],
            props_required=[
                "Delivery uniform (brown/blue with cap)",
                "Dolly/hand truck",
                "Real-looking boxes with shipping labels",
                "Clipboard with delivery manifest",
                "USB drives with company-relevant labels (if USB drop in scope)",
                "Branded delivery tablet/scanner",
            ],
            success_criteria=[
                "Access past reception to internal areas",
                "Plant USB drops in target areas",
                "Map physical security controls and camera positions",
            ],
            abort_conditions=[
                "Delivery company is called for verification",
                "Security escorts and closely monitors entire visit",
            ],
            estimated_duration_min=15,
            difficulty_rating=3,
        ))

        # ── FIRE INSPECTOR ────────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-005",
            scenario=PretextScenario.FIRE_INSPECTOR,
            title="Fire Safety Inspection",
            objective="Access all areas including server rooms, wiring closets, and restricted zones",
            target_role="Facilities manager, building manager, or reception",
            opening_lines=[
                "Good morning, I'm {fake_name} from the City Fire Marshal's office. We're conducting annual fire safety inspections in this district. I need to inspect your sprinkler systems and fire exits.",
                "Hi, Fire Inspector {fake_name}. We received a complaint about blocked fire exits in this building. I need to do a walk-through to verify compliance.",
                "Hello, {fake_name} with the Fire Prevention Bureau. Your building's inspection is due — it expired {months_ago} months ago. We need to get this done today to avoid a citation.",
            ],
            conversation_flow=[
                {"phase": "authority", "script": "Here's my identification and the inspection notice. This is a routine annual inspection — we need to check all floors, including your electrical rooms, server rooms, and any areas with fire suppression systems."},
                {"phase": "full_access", "script": "I'll need access to every room on every floor, including locked areas. Fire code requires that inspectors have unrestricted access. Any areas I can't inspect will be noted as non-compliant."},
                {"phase": "server_room", "script": "This server room — what fire suppression do you have? FM-200? Let me check the cylinders and make sure the pressure is within spec. I'll also need to verify the emergency power-off procedures are properly labeled."},
                {"phase": "recon", "script": "I'm noting the locations of your fire extinguishers and their inspection tags. Also, these network cables running through the ceiling tiles — are they plenum-rated? Non-compliant cabling is a common citation."},
                {"phase": "documentation", "script": "I'll need a copy of your building floor plans for my records. Also, who's your fire alarm monitoring company? I need to verify the central station connection is active."},
            ],
            objection_handlers={
                "We need advance notice for inspections": "For routine inspections, yes. But complaint-based inspections can be conducted without notice per fire code section {code_section}. We received a complaint and are required to investigate within 72 hours.",
                "I need to verify your credentials": "Of course, here's my badge number and you can call the Fire Marshal's office at {fake_phone} to verify. Ask for the commercial inspections division.",
                "Our facilities manager isn't here": "I understand, but the inspection is time-sensitive. If I can't complete it today, I'll need to issue a temporary non-compliance notice and schedule a formal follow-up. That usually involves fines.",
                "You can't access the server room without IT": "I understand you have security protocols, but fire code supersedes IT policy for inspection purposes. The server room has fire suppression systems that must be inspected. I can note a refusal if you prefer, but that triggers an escalated review.",
            },
            escalation_triggers=[
                "Facilities manager calls the real fire marshal's office",
                "Target demands written inspection order with building address",
                "Armed security is called",
            ],
            props_required=[
                "Fire inspector uniform or business casual with badge",
                "Fake fire marshal ID with photo",
                "Clipboard with inspection checklist forms",
                "Flashlight and basic inspection tools",
                "Camera for documenting violations",
                "Fire code reference book/tablet",
            ],
            success_criteria=[
                "Gain access to server room and network closets",
                "Obtain building floor plans",
                "Document all physical security controls",
                "Photograph network equipment and configurations",
            ],
            abort_conditions=[
                "Real fire marshal office is contacted",
                "Law enforcement is called",
                "Target requests formal written authorization from city",
            ],
            estimated_duration_min=60,
            difficulty_rating=7,
        ))

        # ── RECRUITER ─────────────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-006",
            scenario=PretextScenario.RECRUITER,
            title="Executive Recruiter Information Gathering",
            objective="Extract org chart details, technology stack, security posture information",
            target_role="HR coordinator, department manager, or individual contributor",
            opening_lines=[
                "Hi {target_name}, I'm {fake_name} with {recruiting_firm}. We're working on filling a {job_title} position and your background came up as a strong match. Do you have a few minutes?",
                "Hello, this is {fake_name} from {recruiting_firm}. I'm reaching out because a client of ours is looking for someone with your exact skill set. The role is a significant step up in comp.",
                "Hi {target_name}, I found your profile on LinkedIn and I'm very impressed. My client — a major {industry} firm — is building out their team and I think you'd be a perfect fit.",
            ],
            conversation_flow=[
                {"phase": "flattery", "script": "Your experience with {target_skill} is exactly what our client needs. This is a senior role with a significant compensation package — likely a 30-40% increase from what you'd be making now."},
                {"phase": "org_chart_extraction", "script": "To make sure this is the right fit, can you tell me a bit about your current team structure? How many people report to your manager? And who does your {department} ultimately roll up to?"},
                {"phase": "tech_stack", "script": "The role involves working with some specific technologies. To gauge alignment, what tools and platforms does your current team use? Things like your cloud provider, security tools, CI/CD pipeline?"},
                {"phase": "security_posture", "script": "My client is very security-focused. How does your current org handle things like access management and security training? They want someone who's experienced working in a mature security environment."},
                {"phase": "process_extraction", "script": "What does your change management process look like? And how about incident response — does your team have a formal IR plan? The client considers this experience critical."},
                {"phase": "close", "script": "This has been incredibly helpful. Let me put together a detailed opportunity brief and send it to your personal email. What's the best email to reach you outside of work?"},
            ],
            objection_handlers={
                "I'm not looking to leave": "I completely understand — the best candidates rarely are. But would it hurt to hear about the opportunity? Even if it's not for you, perhaps you know someone who'd be interested.",
                "How did you get my number?": "Your professional profile is quite visible — LinkedIn and some industry conference speaker lists. I hope you don't mind the direct approach. The role is too important for a generic job posting.",
                "I can't discuss company details": "Of course, I respect that. I'm not asking for anything proprietary — just general team structure so I can position the opportunity correctly. Standard stuff we discuss with every candidate.",
                "Send me the job description first": "Absolutely. This is a confidential retained search so I can't share the client name yet, but I'll send the full role spec. Can you confirm your personal email?",
            },
            escalation_triggers=[
                "Target asks for verifiable firm details",
                "Target's company has a policy of recording recruiter calls",
                "Target reports the call to their security team",
            ],
            props_required=[
                "LinkedIn profile for fake recruiter persona",
                "Website for fake recruiting firm",
                "Fake job descriptions and company profiles",
                "Professional email address on recruiting firm domain",
                "Phone number with appropriate area code",
            ],
            success_criteria=[
                "Extract org chart information",
                "Identify technology stack and security tools",
                "Obtain personal contact details",
                "Map team structure and reporting lines",
            ],
            abort_conditions=[
                "Target verifies recruiting firm is fake",
                "Target reports to corporate security",
            ],
            estimated_duration_min=25,
            difficulty_rating=4,
        ))

        # ── C-LEVEL ASSISTANT ─────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-007",
            scenario=PretextScenario.CLEVEL_ASSISTANT,
            title="Executive Assistant Urgency Play",
            objective="Obtain credentials, financial data, or trigger unauthorized wire transfers",
            target_role="Finance team member, accounts payable, or executive assistant",
            opening_lines=[
                "Hi {target_name}, this is {fake_name}, {ceo_name}'s executive assistant. {ceo_name} is in a board meeting and asked me to reach out urgently about something.",
                "Hello, I'm calling on behalf of {ceo_name}. This is {fake_name} from the executive office. {ceo_name} needs something handled immediately and can't make the call personally.",
                "{target_name}? {fake_name} here, from {ceo_name}'s office. We have a time-sensitive situation and {ceo_name} specifically asked that I contact you directly.",
            ],
            conversation_flow=[
                {"phase": "urgency", "script": "{ceo_name} is closing a confidential deal right now and needs a payment processed today. The board has already approved it but we need the wire completed before the 3 PM cutoff."},
                {"phase": "authority_pressure", "script": "I know this is unusual, but {ceo_name} was very specific — this needs to be handled quietly and quickly. The acquisition hasn't been announced yet and we can't have any leaks."},
                {"phase": "payment_details", "script": "The wire details are: ${amount} to {beneficiary}. I'm sending you the banking details via email right now from {ceo_name}'s account. Can you confirm when you have them?"},
                {"phase": "prevent_verification", "script": "{ceo_name} asked that you not discuss this with anyone else right now — not even {cfo_name}. The deal is in a sensitive phase and information control is critical. {ceo_name} will brief the team after the announcement."},
                {"phase": "follow_up", "script": "Can you send me a confirmation once the wire is submitted? {ceo_name} needs to show proof of payment to the other party's counsel by end of day."},
            ],
            objection_handlers={
                "I need approval from CFO": "{ceo_name} has already discussed this with {cfo_name}, but {cfo_name} is traveling and unreachable right now. The board authorization supersedes the normal approval chain for this transaction.",
                "This doesn't follow our process": "I understand completely, and normally I would never ask you to deviate from process. But this is a direct request from {ceo_name} for an extraordinary situation. We can do the formal paperwork retroactively tomorrow.",
                "I need to speak to the CEO directly": "{ceo_name} is in back-to-back sessions with the board until 4 PM. That's exactly why I'm calling on their behalf. I can have {ceo_name} send you a quick text to confirm — what's your mobile?",
                "I'm going to verify this first": "I appreciate your diligence. But please understand the time pressure we're under. If the wire doesn't go out by 3 PM, the deal falls through and {ceo_name} will not be happy about the delay.",
            },
            escalation_triggers=[
                "Target insists on verbal confirmation from CEO",
                "Target involves their direct manager",
                "Target contacts IT security about suspicious request",
            ],
            props_required=[
                "Spoofed email from CEO domain or lookalike",
                "Knowledge of CEO name, CFO name, org structure",
                "Spoofed caller ID showing executive office number",
                "Fake wire transfer form with company letterhead",
            ],
            success_criteria=[
                "Target initiates wire transfer process",
                "Target provides financial system credentials",
                "Target shares sensitive deal information",
            ],
            abort_conditions=[
                "Target calls CEO directly and gets through",
                "Finance team activates fraud alert protocol",
                "Legal or compliance is notified",
            ],
            estimated_duration_min=15,
            difficulty_rating=8,
        ))

        # ── AUDITOR ───────────────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-008",
            scenario=PretextScenario.AUDITOR,
            title="Compliance Auditor Site Visit",
            objective="Access financial systems, HR records, and IT infrastructure documentation",
            target_role="Compliance officer, IT manager, or department head",
            opening_lines=[
                "Good morning, I'm {fake_name} from {audit_firm}. We're conducting the annual {compliance_framework} compliance audit for {org_name}. I believe {compliance_contact} arranged the visit.",
                "Hello, {fake_name} with {audit_firm}. I'm here for the scheduled IT controls audit. We need to review your access controls, change management, and incident response procedures.",
                "Hi, I'm the lead auditor from {audit_firm}. We're performing an interim audit between your regular cycles due to some regulatory changes in {compliance_framework}. I need about 4 hours of your team's time.",
            ],
            conversation_flow=[
                {"phase": "legitimacy", "script": "Here's my engagement letter signed by your {compliance_contact}. The scope covers IT general controls, access management, data protection, and business continuity. We need to interview key personnel and review documentation."},
                {"phase": "documentation_request", "script": "I'll need the following documentation: your network architecture diagrams, access control matrices, user provisioning procedures, incident response plan, and the last 90 days of privileged access logs."},
                {"phase": "system_access", "script": "For the controls testing, I'll need read-only access to your Active Directory, your SIEM dashboard, and your ticketing system. We need to verify that your documented procedures match actual implementation."},
                {"phase": "interview", "script": "I need to interview your IT director, your CISO or security lead, and someone from your change management team. Can we schedule those for this afternoon?"},
                {"phase": "finding_pressure", "script": "I'm noticing some potential gaps in your {control_area}. These could be material findings that affect your certification. If we can review the supporting evidence now, we may be able to resolve this before the final report."},
            ],
            objection_handlers={
                "We weren't notified about this audit": "The notification was sent to {compliance_contact} three weeks ago. It's possible it got lost — let me forward you the engagement letter. In any case, the audit timeline is fixed by the regulator.",
                "I need to verify with management": "Absolutely. Please check with {compliance_contact} — they were the point of contact for scheduling. I can wait 15 minutes, but we do have a tight timeline to complete the fieldwork.",
                "We can't provide system access to outsiders": "I understand the sensitivity. Your IT security team can provide supervised access, or they can pull the reports while I observe. Either approach satisfies the audit requirements.",
                "Our regular auditors are a different firm": "We're conducting a supplementary assessment specifically for {compliance_framework} compliance. This is separate from your financial audit. The engagement was commissioned by your board's audit committee.",
            },
            escalation_triggers=[
                "Compliance officer contacts the real audit firm",
                "Board audit committee is consulted and denies knowledge",
                "IT security runs background check on auditor",
            ],
            props_required=[
                "Professional business attire",
                "Fake audit firm business cards",
                "Forged engagement letter on org letterhead",
                "Compliance framework reference materials",
                "Laptop with audit documentation templates",
                "Professional audit firm email address",
            ],
            success_criteria=[
                "Obtain network architecture diagrams",
                "Access Active Directory or user management systems",
                "Review incident response and security procedures",
                "Extract privileged access logs",
            ],
            abort_conditions=[
                "Real audit firm is contacted for verification",
                "Legal department intervenes",
                "CISO identifies the social engineering attempt",
            ],
            estimated_duration_min=120,
            difficulty_rating=8,
        ))

        # ── BUILDING MAINTENANCE ──────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-009",
            scenario=PretextScenario.BUILDING_MAINTENANCE,
            title="HVAC / Plumbing Emergency Repair",
            objective="Access restricted areas including server rooms and wiring closets",
            target_role="Facilities coordinator, office manager, or building security",
            opening_lines=[
                "Hi, I'm from {maintenance_company}. Building management called us about a water leak reported near your server room. I need to inspect immediately to prevent damage.",
                "Hello, {maintenance_company} here. We got an emergency call about your HVAC system — the unit servicing your data center area is showing critical pressure readings.",
                "Morning — I'm with {maintenance_company}. We're doing the quarterly HVAC filter replacement for floors {floor_range}. Should take about 20 minutes per floor.",
            ],
            conversation_flow=[
                {"phase": "urgency", "script": "The leak could cause serious damage to your equipment if we don't address it quickly. Water and servers don't mix — I've seen companies lose hundreds of thousands from a single burst pipe."},
                {"phase": "access", "script": "I need access to the ceiling plenum above your server room and the utility chase on the north wall. Can someone show me where these areas are?"},
                {"phase": "solo_access", "script": "This might take a while — you don't need to stay with me. I'll be up in the ceiling mostly. Just leave the doors propped and I'll find you when I'm done."},
                {"phase": "recon", "script": "While I'm up here, I can see your cable runs. Looks like you've got some Cat5e that should probably be upgraded. Want me to make a note for your IT team?"},
                {"phase": "device_plant", "script": "I need to install a moisture sensor near these pipes so we can monitor remotely. It connects to our cloud dashboard and we'll get alerts before any future leaks."},
            ],
            objection_handlers={
                "Building management didn't tell us": "They may have contacted your facilities team directly. The call came in about an hour ago and they wanted immediate response. I can call my dispatch to confirm the work order.",
                "You need an escort in restricted areas": "I understand. If someone can escort me initially, I'll just need them nearby. Once I'm in the ceiling space, it's hard for two people to be up there anyway.",
                "Can I see your work order?": "Here you go — work order #{fake_wo}. You can call {maintenance_company} dispatch at {fake_phone} to verify.",
            },
            escalation_triggers=[
                "Building management confirms no service call was made",
                "Facilities team recognizes different maintenance company",
                "Security insists on continuous escort",
            ],
            props_required=[
                "Maintenance uniform/coveralls",
                "Tool belt with plumbing/HVAC tools",
                "Ladder (collapsible)",
                "Fake work orders",
                "Moisture sensor (cover for rogue device)",
            ],
            success_criteria=[
                "Access server room or wiring closet",
                "Plant monitoring device on network",
                "Photograph equipment and configurations",
            ],
            abort_conditions=[
                "Real maintenance company is called",
                "Security denies access and escalates",
            ],
            estimated_duration_min=40,
            difficulty_rating=5,
        ))

        # ── TELECOM TECHNICIAN ────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-010",
            scenario=PretextScenario.TELECOM_TECHNICIAN,
            title="ISP / Telecom Line Repair",
            objective="Access telecom closets, MDF/IDF rooms, and plant network taps",
            target_role="Facilities staff, IT staff, or building management",
            opening_lines=[
                "Hi, {fake_name} from {isp_name}. We've detected signal degradation on the fiber line serving this building. I need to check the demarc and run some diagnostics.",
                "Hello, telecom tech from {isp_name}. We're doing a circuit upgrade in this area and I need to verify your service panel connections. Should only take 30 minutes.",
                "Morning, I'm here from {isp_name} to investigate a trouble ticket your IT team opened about intermittent connectivity. Need access to the MDF room.",
            ],
            conversation_flow=[
                {"phase": "technical_authority", "script": "The issue is on the line side — your internal network is fine, but the fiber handoff at the demarc is showing elevated BER. If I don't clean up the connection, you could lose service entirely."},
                {"phase": "access_mdf", "script": "I need access to your MDF — that's where the telecom demarc point is. It's usually in the basement or ground floor. I'll also need to trace the fiber to your IDF on each floor."},
                {"phase": "device_install", "script": "I'm going to install an inline monitor on your circuit so we can track the signal quality remotely. It sits between the demarc and your router — completely passive, won't affect your traffic."},
                {"phase": "reconnaissance", "script": "Interesting — you're running dual ISP with failover? Smart setup. What's your primary circuit speed? I want to make sure the monitor can handle the bandwidth."},
            ],
            objection_handlers={
                "Our ISP is different": "We handle the last-mile infrastructure for several ISPs in this building. Even if your service is through {alt_isp}, the physical fiber plant is maintained by {isp_name}. It's common in multi-tenant buildings.",
                "IT needs to be present": "That's fine. The work is at the demarc which is usually on the building side, not your tenant space. But if IT wants to observe, they're welcome to.",
                "We haven't reported any issues": "The degradation was detected by our network monitoring systems — it's proactive maintenance. Better to fix it now than wait for an outage during business hours.",
            },
            escalation_triggers=[
                "IT team calls the actual ISP to verify",
                "Building management has different telecom provider",
            ],
            props_required=[
                "ISP branded uniform or vest",
                "Fiber optic toolkit",
                "Optical power meter (or realistic prop)",
                "Fake work orders with circuit IDs",
                "Network tap device",
                "Hard hat and safety vest",
            ],
            success_criteria=[
                "Access MDF/IDF telecom rooms",
                "Install network tap on uplink",
                "Map network topology from physical plant",
            ],
            abort_conditions=[
                "ISP confirms no technician dispatched",
                "IT security discovers unauthorized device",
            ],
            estimated_duration_min=35,
            difficulty_rating=6,
        ))

        # ── INSURANCE AGENT ───────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-011",
            scenario=PretextScenario.INSURANCE_AGENT,
            title="Cyber Insurance Policy Review",
            objective="Extract security posture details, incident history, and compliance gaps",
            target_role="CFO, risk manager, or IT director",
            opening_lines=[
                "Hi {target_name}, I'm {fake_name} from {insurance_company}. We're conducting the annual cyber insurance policy review for {org_name}. I need to go through the updated questionnaire.",
                "Hello, {fake_name} with {insurance_company}'s cyber risk division. Your policy is up for renewal and the underwriters need updated information about your security controls before they can finalize the premium.",
                "Good morning, I'm calling about your {org_name} cyber liability policy. Due to increased claims industry-wide, we need a mid-term security assessment. This may actually reduce your premium.",
            ],
            conversation_flow=[
                {"phase": "legitimacy", "script": "Your policy number is {fake_policy}. I have last year's assessment on file but the underwriters need current data. This is standard for all policies over ${policy_value}."},
                {"phase": "security_controls", "script": "Let me go through the security controls checklist: Do you have MFA enabled for all remote access? What about privileged accounts? What EDR solution are you running? How often do you conduct penetration tests?"},
                {"phase": "incident_history", "script": "Have you experienced any security incidents, breaches, or near-misses in the past 12 months? Even unreported ones — full disclosure is required by the policy terms. Non-disclosure could void coverage."},
                {"phase": "network_details", "script": "For the technical assessment: How many endpoints do you manage? What's your backup strategy — air-gapped, cloud, or both? Do you segment your network? How many internet-facing services do you run?"},
                {"phase": "premium_incentive", "script": "Based on what you've told me, implementing {missing_control} could reduce your premium by 15-20%. I'd recommend addressing that before the renewal date. Shall I note that you're planning to implement it?"},
            ],
            objection_handlers={
                "I need to verify this call": "Absolutely. Call our main line at {fake_phone} and ask for the cyber risk division. Reference policy {fake_policy}. I'll be available all afternoon.",
                "I can't share security details over the phone": "I understand the sensitivity. I can send the questionnaire via secure email portal instead. What email should I send it to? Or we can schedule an in-person meeting.",
                "Our broker handles insurance": "You're right — {broker_name} is your broker of record. This assessment is a direct underwriter requirement though. Your broker should have been notified. Let me check on that.",
            },
            escalation_triggers=[
                "Target contacts their actual insurance broker",
                "Insurance company is called to verify",
                "Legal review of policy terms requested",
            ],
            props_required=[
                "Fake insurance company website and email",
                "Cyber insurance questionnaire template",
                "Knowledge of target's actual insurance broker",
                "Fake policy numbers with correct format",
            ],
            success_criteria=[
                "Extract full security controls inventory",
                "Learn about past incidents and breaches",
                "Obtain network architecture details",
                "Identify security gaps and missing controls",
            ],
            abort_conditions=[
                "Actual insurance company denies knowledge",
                "Target's broker confirms no review is scheduled",
            ],
            estimated_duration_min=30,
            difficulty_rating=5,
        ))

        # ── SURVEY RESEARCHER ─────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-012",
            scenario=PretextScenario.SURVEY_RESEARCHER,
            title="Industry Security Survey",
            objective="Extract technology stack, security posture, and organizational details",
            target_role="IT manager, developer, or security team member",
            opening_lines=[
                "Hi {target_name}, I'm {fake_name} from {research_firm}. We're conducting an industry survey on {industry} cybersecurity practices for our annual report. Participation takes about 10 minutes and you'll receive the full report.",
                "Hello, I'm a researcher with {research_firm}. We're surveying {industry} professionals about their security tooling and challenges. Your insights would be incredibly valuable. Plus, participants are entered into a ${prize_amount} gift card drawing.",
            ],
            conversation_flow=[
                {"phase": "context", "script": "This survey is sponsored by {sponsor}. We're interviewing 200 {industry} professionals. Your responses are anonymized in the aggregate report, but individual data is confidential."},
                {"phase": "tech_stack", "script": "What cloud platform does your organization primarily use? And for endpoint security, do you use a traditional AV, an EDR solution, or an XDR platform? Which vendor?"},
                {"phase": "security_maturity", "script": "On a scale of 1-10, how would you rate your organization's security maturity? What's your biggest security challenge right now? What's your annual security budget range?"},
                {"phase": "deep_dive", "script": "Interesting. What SIEM solution do you use? How about your vulnerability management — is that Qualys, Tenable, Rapid7, or something else? How frequently do you run scans?"},
                {"phase": "close", "script": "This has been incredibly helpful. For the gift card drawing, I just need your work email and job title. The report will be published in {month} and I'll send you an advance copy."},
            ],
            objection_handlers={
                "I need approval to participate": "Completely understand. The survey doesn't require any proprietary information — just general industry perspectives. Most participants complete it without needing approval, but I respect your process.",
                "How do I know this is legitimate?": "Great question. You can visit our website at {research_url} to see past reports. We've been doing this survey for {years} years. I can also send you the participant consent form via email.",
            },
            escalation_triggers=[
                "Target researches the survey firm and finds nothing",
                "Target reports to security team",
            ],
            props_required=[
                "Professional survey platform or questionnaire",
                "Research firm website with past reports",
                "Participant consent form",
                "Professional email from research domain",
            ],
            success_criteria=[
                "Identify complete technology and security stack",
                "Learn security budget and maturity level",
                "Obtain personal contact details for follow-up",
            ],
            abort_conditions=[
                "Target verifies firm is fake",
                "Survey is flagged as social engineering by security team",
            ],
            estimated_duration_min=15,
            difficulty_rating=3,
        ))

        # ── BANK REPRESENTATIVE ───────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-013",
            scenario=PretextScenario.BANK_REPRESENTATIVE,
            title="Bank Account Verification Call",
            objective="Extract banking details, credentials, or authorize fraudulent transactions",
            target_role="Finance staff, accounts payable, or treasury",
            opening_lines=[
                "Hello {target_name}, this is {fake_name} from the fraud prevention team at {bank_name}. We've detected suspicious activity on your business account ending in {last4}. I need to verify some transactions with you.",
                "Hi, calling from {bank_name} commercial banking. We're implementing new security measures on all business accounts and I need to verify your account details. This is for your protection.",
            ],
            conversation_flow=[
                {"phase": "urgency", "script": "We flagged two transactions from overnight — a wire for ${amount_1} to {destination_1} and an ACH for ${amount_2}. If these aren't authorized, we need to freeze the account immediately."},
                {"phase": "verification", "script": "For security purposes, I need to verify you're an authorized signer. Can you confirm the full account number? And the last four of the tax ID on the account?"},
                {"phase": "credential_harvest", "script": "I'm going to need you to log into your online banking to verify the transactions. Can you go to {phish_url}? This is our secure verification portal — separate from regular online banking for fraud cases."},
                {"phase": "action", "script": "I've reversed the unauthorized transactions. For your protection, we need to reset your online banking credentials. Please create a new password through the portal I just sent you."},
            ],
            objection_handlers={
                "I'll call the bank directly": "Absolutely — call the number on the back of your debit card. Ask for the commercial fraud team and reference case #{case_number}. But please do it soon — the fraudulent transactions are still pending.",
                "I need to talk to my manager": "I understand, but time is critical. The fraudulent wire is scheduled to settle within the hour. Once it settles, recovery becomes much harder.",
                "How do I know you're really from the bank?": "Great question. Your account was opened at the {branch_name} branch in {branch_year}. Your primary business contact there is {banker_name}. I can transfer you to them if you'd like.",
            },
            escalation_triggers=[
                "Target calls actual bank number",
                "Target consults with CFO or controller",
            ],
            props_required=[
                "Spoofed caller ID showing bank number",
                "Knowledge of target's banking relationship",
                "Fake fraud case numbers",
                "Credential harvesting portal mimicking bank login",
            ],
            success_criteria=[
                "Obtain account numbers or credentials",
                "Target logs into phishing portal",
                "Extract authorized signer information",
            ],
            abort_conditions=[
                "Target calls bank directly and no fraud case exists",
                "Target refuses all information and hangs up",
            ],
            estimated_duration_min=10,
            difficulty_rating=6,
        ))

        # ── LAW ENFORCEMENT ───────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-014",
            scenario=PretextScenario.LAW_ENFORCEMENT,
            title="Law Enforcement Investigation Inquiry",
            objective="Extract employee information, access logs, or security footage (NOTE: impersonating law enforcement is illegal in most jurisdictions — for training/awareness only)",
            target_role="HR director, legal counsel, or facility security",
            opening_lines=[
                "Hello, I'm Detective {fake_name} with the {jurisdiction} {department}. We're investigating a case involving a former employee of your company. I need to ask a few questions.",
                "This is Agent {fake_name} with {agency}. We have an active investigation and we need your cooperation regarding an employee. This is time-sensitive.",
            ],
            conversation_flow=[
                {"phase": "authority", "script": "I can provide my badge number and our case reference. We're investigating {crime_type} and we believe one of your employees may be involved. This is an active investigation — please keep this confidential."},
                {"phase": "information_request", "script": "I need employment records for {suspect_name} — start date, department, access level, and emergency contacts. We also need their building access logs for the past 30 days."},
                {"phase": "urgency", "script": "We're executing a search warrant at the individual's residence today. Having the employment information helps us establish timeline and motive. Time is of the essence."},
                {"phase": "expansion", "script": "We may also need to review security camera footage from your building for {date_range}. Can you preserve that? And who has administrator access to your email system?"},
            ],
            objection_handlers={
                "I need to involve our legal team": "That's fine — but please understand we need this information quickly. Delays could compromise the investigation. Can we schedule a call with your counsel within the hour?",
                "We require a formal subpoena": "We're obtaining the subpoena now, but in the interest of time — and public safety — I was hoping for voluntary cooperation. If we need to go through formal channels, it will take 48 hours.",
                "Send me your credentials": "I'll have the detective bureau send official verification to your legal department. In the meantime, is there any general information you can share that doesn't require a subpoena?",
            },
            escalation_triggers=[
                "Legal department demands formal verification",
                "Target calls the actual police/agency",
                "Organization has policy requiring subpoena for all LE requests",
            ],
            props_required=[
                "AWARENESS TRAINING ONLY — never use in actual engagement",
                "Fake badge number and case reference",
                "Knowledge of local law enforcement structure",
            ],
            success_criteria=[
                "TRAINING ONLY — measure whether org follows subpoena policy",
                "Test if staff release info without legal review",
                "Assess awareness of LE impersonation tactics",
            ],
            abort_conditions=[
                "Target demands formal legal process (correct response)",
                "Target calls actual law enforcement to verify",
                "Use of this pretext in real engagement — abort immediately",
            ],
            estimated_duration_min=15,
            difficulty_rating=9,
        ))

        # ── MEDIA/JOURNALIST ─────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-015",
            scenario=PretextScenario.MEDIA_JOURNALIST,
            title="Journalist Interview Request",
            objective="Extract operational details, upcoming projects, and insider information",
            target_role="Marketing/PR staff, executives, or technical staff",
            opening_lines=[
                "Hi {target_name}, I'm {fake_name} from {publication}. We're writing a feature article on {industry} innovation and your company keeps coming up. Would you be available for a 15-minute interview?",
                "Hello, this is {fake_name}, tech reporter at {publication}. I'm working on a piece about {topic} and I'd love to get {org_name}'s perspective. The article publishes next week.",
            ],
            conversation_flow=[
                {"phase": "flattery", "script": "Your company's work in {technology_area} has been really impressive. Our readers — mostly CISOs and CTOs — would love to hear about your approach. This would be great visibility for {org_name}."},
                {"phase": "technical_dive", "script": "Can you walk me through your technology stack at a high level? What makes your approach different? And what security challenges have you had to solve along the way?"},
                {"phase": "operational_details", "script": "How large is your engineering team? And your security team — do you have a dedicated SOC? What's your biggest operational challenge right now?"},
                {"phase": "upcoming_plans", "script": "Any upcoming product launches or partnerships you can hint at? Even off the record — I won't publish anything without your approval. It helps me frame the story correctly."},
                {"phase": "social_graph", "script": "Who would you recommend I also speak with? Maybe your CISO or CTO? And do you work with any interesting vendors or partners that might add perspective to the article?"},
            ],
            objection_handlers={
                "All press inquiries go through PR": "Understood. What's the best contact in your PR team? I find that technical interviews add depth that PR-filtered quotes can't capture. Perhaps we could do both?",
                "I need approval to speak to media": "Of course. I'm on a tight deadline though — the article publishes {publish_date}. If I can't include {org_name}'s perspective, I may have to rely on outside analysis.",
                "I can't share technical details": "No proprietary information, I promise. I'm more interested in the strategic vision and general approach. Think of it as thought leadership for your team.",
            },
            escalation_triggers=[
                "PR team researches the reporter and publication",
                "Target checks publication and finds no reporter by that name",
            ],
            props_required=[
                "Professional journalist persona with LinkedIn",
                "Fake or obscure publication website",
                "Previous published articles (fabricated)",
                "Professional email on publication domain",
                "Recording consent form (adds legitimacy)",
            ],
            success_criteria=[
                "Extract technology stack and security tools",
                "Learn team sizes and organizational structure",
                "Obtain names of key personnel for further targeting",
                "Discover upcoming projects or vendor relationships",
            ],
            abort_conditions=[
                "PR verifies reporter is fake",
                "Publication is researched and found non-existent",
            ],
            estimated_duration_min=20,
            difficulty_rating=4,
        ))

        # ── TEMP WORKER ───────────────────────────────────────────────────
        scripts.append(PretextScript(
            script_id="pretext-016",
            scenario=PretextScenario.TEMP_WORKER,
            title="Temporary Worker / Contractor First Day",
            objective="Obtain network credentials, physical access, and internal system access",
            target_role="Office manager, IT helpdesk, or team lead",
            opening_lines=[
                "Hi, I'm {fake_name}. I'm the temp from {staffing_agency} — I'm supposed to start in {department} today. {manager_name} should be expecting me.",
                "Good morning! I was sent by {staffing_agency} to cover for {absent_employee} while they're on leave. I was told to come to reception and ask for {manager_name}.",
            ],
            conversation_flow=[
                {"phase": "setup", "script": "I was told everything would be set up for me — a workstation, login credentials, and badge access. But it looks like nothing's ready yet. Could you help me get sorted?"},
                {"phase": "credential_request", "script": "I don't have any login credentials yet. Is there a generic account I can use temporarily? Or can IT set something up quickly? I'm supposed to start on the {project_name} project today."},
                {"phase": "badge_request", "script": "I also need a temporary badge. {manager_name} mentioned I'd need access to floors {floor_range} and the {restricted_area}. The staffing agency said you'd have everything ready."},
                {"phase": "network_access", "script": "What's the WiFi network and password? And do you use VPN for remote systems? I brought my own laptop since the staffing agency said it might take a day to get a company machine."},
                {"phase": "escalation", "script": "I understand the confusion. Could you call {staffing_agency} to verify? Their number is {fake_phone}. Or try {manager_name} — they should confirm the arrangement."},
            ],
            objection_handlers={
                "We don't have you in our system": "That's strange — {staffing_agency} confirmed everything last Friday. There might be a communication gap between HR and your team. Can we call {manager_name} to sort this out?",
                "Temps don't get network access on day one": "I totally understand, but {manager_name} said the project is urgent and I need to start immediately. Is there a guest network at least? I have cloud-based tools I can use.",
                "You need to go through HR orientation first": "Of course — where is HR located? In the meantime, is there a desk I can use to review the project materials {manager_name} emailed me?",
            },
            escalation_triggers=[
                "HR checks and finds no temp request on file",
                "Staffing agency denies sending anyone",
                "Manager is contacted and knows nothing about a temp",
            ],
            props_required=[
                "Business casual attire",
                "Personal laptop with relevant software",
                "Fake staffing agency confirmation email",
                "Knowledge of absent employees (from LinkedIn)",
                "Fake ID badge from staffing agency",
            ],
            success_criteria=[
                "Obtain network credentials or guest access",
                "Receive temporary badge with area access",
                "Get assigned a workstation on internal network",
                "Access restricted areas via badge",
            ],
            abort_conditions=[
                "All verification attempts fail",
                "Security is called and engagement is blown",
            ],
            estimated_duration_min=25,
            difficulty_rating=5,
        ))

        for script in scripts:
            self._register_script(script)

    def _register_script(self, script: PretextScript) -> None:
        """Register a script in the index."""
        with self._lock:
            self._scripts[script.script_id] = script
            self._scenario_index[script.scenario].append(script.script_id)

    def get_script(self, scenario: PretextScenario) -> Optional[PretextScript]:
        """Get the first script for a given scenario."""
        with self._lock:
            ids = self._scenario_index.get(scenario, [])
            if ids:
                return self._scripts.get(ids[0])
            return None

    def get_all_scripts(self) -> List[PretextScript]:
        """Return all registered pretext scripts."""
        with self._lock:
            return list(self._scripts.values())

    def get_scripts_by_difficulty(self, max_difficulty: int = 10) -> List[PretextScript]:
        """Get scripts filtered by maximum difficulty rating."""
        with self._lock:
            return [
                s for s in self._scripts.values()
                if s.difficulty_rating <= max_difficulty
            ]

    def customize_script(
        self, scenario: PretextScenario, variables: Dict[str, str]
    ) -> Optional[PretextScript]:
        """Customize a pretext script with target-specific variables."""
        import copy
        base = self.get_script(scenario)
        if not base:
            return None

        custom = copy.deepcopy(base)
        custom.script_id = f"custom-{uuid.uuid4().hex[:12]}"

        for var, value in variables.items():
            placeholder = f"{{{var}}}"
            custom.title = custom.title.replace(placeholder, value)
            custom.objective = custom.objective.replace(placeholder, value)
            custom.opening_lines = [
                line.replace(placeholder, value) for line in custom.opening_lines
            ]
            custom.conversation_flow = [
                {k: v.replace(placeholder, value) for k, v in step.items()}
                for step in custom.conversation_flow
            ]
            custom.objection_handlers = {
                k.replace(placeholder, value): v.replace(placeholder, value)
                for k, v in custom.objection_handlers.items()
            }

        return custom


# ════════════════════════════════════════════════════════════════════════════════
# VISHING SCRIPT GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

class VishingScriptGen:
    """Generates voice phishing (vishing) phone call scripts.

    Provides 8+ complete phone scripts for authorized red team voice
    phishing assessments.

    Usage:
        gen = VishingScriptGen()
        scripts = gen.get_all_scripts()
        script = gen.get_script_by_scenario("bank_fraud_alert")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._scripts: Dict[str, VishingScript] = {}
        self._initialize_scripts()
        logger.info("VishingScriptGen initialized with %d scripts", len(self._scripts))

    def _initialize_scripts(self) -> None:
        """Build the complete vishing script library."""
        scripts = []

        scripts.append(VishingScript(
            script_id="vish-001",
            scenario_name="IT Helpdesk Password Reset",
            caller_identity="IT Helpdesk Tier 2 Support",
            caller_number_spoof="Internal IT extension",
            target_role="Any employee",
            objective="Obtain current credentials or install remote access tool",
            opening="Hi {target_name}, this is {tech_name} from IT support, employee ID {emp_id}. I'm calling about a security alert on your account. We detected a login attempt from an unrecognized device in {foreign_city}. This could be a breach in progress, so I need to walk you through securing your account right now.",
            main_script=[
                {"step": "1_verify", "dialogue": "First, I need to verify your identity. Can you confirm your username? It should be in first-dot-last format."},
                {"step": "2_urgency", "dialogue": "I can see the unauthorized session is still active. We need to act fast before they can exfiltrate any data from your mailbox."},
                {"step": "3_action", "dialogue": "I'm going to send you a link to our secure password reset portal. You'll see it pop up in your email in just a moment. Go ahead and click that and enter your current password, then create a new one."},
                {"step": "4_mfa", "dialogue": "Perfect. Now you should get an MFA prompt — go ahead and approve that. This is us resetting your authentication tokens to kick out the intruder."},
                {"step": "5_remote", "dialogue": "One last thing — I need to run a quick malware scan on your machine to make sure nothing was planted. I'm going to have you download our remote support tool. Go to {support_url} and click Run."},
                {"step": "6_close", "dialogue": "Great, the scan is running now. I can see your screen — everything looks clean. I'll keep monitoring for the next hour. If you notice anything unusual, call us at extension {ext}. And don't share your new password with anyone, even IT — we'll never ask for it."},
            ],
            fallback_responses={
                "Can you prove you're from IT?": "Absolutely. My employee ID is {emp_id} and I sit in Building {building}, floor {floor}. You can also check our IT staff directory on the intranet. But right now the priority is securing your account — that unauthorized session is still active.",
                "I'll call IT back myself": "That's smart security practice! Our helpdesk number is {helpdesk_number}. But please do it immediately — the attacker's session has been active for 22 minutes already. Ask for the security team and reference incident #{incident_id}.",
                "I don't want to give my password": "I completely understand, and you're right to be cautious. That's why I'm directing you to the self-service portal where YOU enter the password directly. I never see it — the system handles the reset securely.",
                "Let me check with my manager first": "Of course. But please be aware that every minute we delay, the attacker potentially has access to your email, files, and any systems your account can reach. If you can conference your manager in, that would be ideal.",
            },
            voice_tone_notes="Professional, calm but with controlled urgency. Not panicked — convey competence and authority. Speak at moderate pace. Use target's first name to build rapport.",
            background_audio="Office ambient noise — keyboard clicks, distant phone ringing, muffled conversations. Reinforces helpdesk environment.",
            estimated_duration_min=8,
            success_criteria=["Target provides credentials", "Target installs remote access tool", "Target approves MFA push"],
        ))

        scripts.append(VishingScript(
            script_id="vish-002",
            scenario_name="Bank Fraud Alert",
            caller_identity="Bank Fraud Prevention Team",
            caller_number_spoof="Bank's published customer service number",
            target_role="Finance staff or account holder",
            objective="Obtain banking credentials, account numbers, or authorize transactions",
            opening="Hello, am I speaking with {target_name}? This is {agent_name} from the fraud prevention department at {bank_name}. We've identified two suspicious transactions on your business account and I need to verify them with you before they clear.",
            main_script=[
                {"step": "1_alert", "dialogue": "We flagged a wire transfer for ${amount_1} to an account in {country} and a second transaction for ${amount_2} to {merchant}. These don't match your typical transaction pattern."},
                {"step": "2_verify", "dialogue": "Before I can discuss account details, I need to verify your identity. Can you confirm the last four digits of the account number and the billing address on file?"},
                {"step": "3_escalate", "dialogue": "Thank you for confirming. I've placed a temporary hold on both transactions. However, to fully reverse them, I need you to log into our secure fraud resolution portal to authorize the reversal."},
                {"step": "4_phish", "dialogue": "I'm sending you a text message right now with a link to the portal. For security, the link expires in 10 minutes. Please sign in with your online banking credentials to complete the reversal."},
                {"step": "5_mfa", "dialogue": "You should receive a verification code on your phone. Please read that to me so I can confirm the reversal was processed on our end."},
                {"step": "6_close", "dialogue": "The fraudulent transactions have been reversed and your account is now secure. We've also flagged your account for enhanced monitoring. You'll receive a confirmation email within the hour."},
            ],
            fallback_responses={
                "I'll call the bank myself": "That's the safest approach and I encourage it. Call the number on the back of your debit card. Reference case number #{case_number}. But please don't delay — the wire transfer is scheduled to settle at 3 PM EST.",
                "How did you get my number?": "It's the primary contact number on file for the business account ending in {last4}. We always call the authorized contacts when fraud is detected.",
                "I don't recognize those transactions": "That's exactly why we're calling — they appear to be unauthorized. The sooner we can process the reversal, the better. Once a wire settles internationally, recovery becomes extremely difficult.",
            },
            voice_tone_notes="Professional, measured, slightly concerned. Use banking terminology naturally. Create urgency around settlement deadline without being aggressive.",
            background_audio="Quiet call center — occasional beep of hold systems, soft ambient noise. Professional financial institution feel.",
            estimated_duration_min=7,
            success_criteria=["Target provides account details", "Target logs into phishing portal", "Target reads MFA code aloud"],
        ))

        scripts.append(VishingScript(
            script_id="vish-003",
            scenario_name="CEO Impersonation Call",
            caller_identity="CEO / Executive",
            caller_number_spoof="CEO's known mobile or office number",
            target_role="Finance director, controller, or CFO assistant",
            objective="Initiate unauthorized wire transfer or extract sensitive financial data",
            opening="{target_name}, it's {ceo_name}. I need you to handle something for me right now. I'm in the middle of closing a deal and I can't get into the details on the phone, but I need a wire processed today. Can you do that?",
            main_script=[
                {"step": "1_context", "dialogue": "We're acquiring a small company — this hasn't been announced yet so keep it strictly confidential. The board approved it last week but we need to move fast before the other bidder."},
                {"step": "2_details", "dialogue": "The wire needs to go out for ${amount} to {beneficiary}. I'll email you the banking details from my personal email in the next few minutes — don't use the company system for this, the deal is too sensitive."},
                {"step": "3_pressure", "dialogue": "I know this isn't standard procedure, but this needs to happen today. The seller's attorney is waiting for proof of funds. Can I count on you?"},
                {"step": "4_prevent_verify", "dialogue": "Don't loop in {cfo_name} yet — I'll brief them after the LOI is signed. If word gets out before we close, the deal falls apart. I'm trusting you with this."},
                {"step": "5_confirm", "dialogue": "Once the wire is submitted, text me the confirmation number at this number. I need to send it to our attorney. And again — absolute confidentiality on this."},
            ],
            fallback_responses={
                "I need to verify this with CFO": "I already discussed it with {cfo_name} — they're aware but I asked them to stay out of it until we close. If you need to confirm, text them, but please don't call — they're in a client meeting.",
                "This is against our wire policy": "I know, and normally I'd never ask you to deviate. But this is an extraordinary situation — board-approved. I'll take full responsibility. We'll do the proper paperwork tomorrow.",
                "Can I call you back to verify?": "I'm about to go into a meeting with the seller's team. You can try my cell but I might not pick up. Look — I called YOU because I trust you to handle this. Can we get it done?",
            },
            voice_tone_notes="Confident, slightly impatient, executive demeanor. Short sentences. Convey power and authority. Don't over-explain — executives give directives, not explanations. Mild frustration if questioned — not hostile, just busy.",
            background_audio="Restaurant or hotel lobby ambience — suggests CEO is traveling or at a business dinner.",
            estimated_duration_min=6,
            success_criteria=["Target agrees to process wire", "Target provides banking system credentials", "Target sends confirmation to attacker"],
        ))

        scripts.append(VishingScript(
            script_id="vish-004",
            scenario_name="Microsoft Support Scam",
            caller_identity="Microsoft Technical Support",
            caller_number_spoof="1-800 number similar to Microsoft",
            target_role="Non-technical employee or executive",
            objective="Install remote access tool or obtain credentials",
            opening="Hello, this is {tech_name} from Microsoft Windows Support. Our system has detected that your computer — the one registered to {org_name} — is sending out malicious traffic. This is very serious and if not addressed immediately, your Windows license may be revoked.",
            main_script=[
                {"step": "1_fear", "dialogue": "Our servers have logged over 200 error events from your IP address in the last 24 hours. This usually indicates that hackers have installed malware on your system and are using it to attack other computers."},
                {"step": "2_proof", "dialogue": "Let me show you the errors. Press the Windows key and R at the same time. Now type 'eventvwr' and press Enter. Do you see all those warning and error events? Those are the malicious activities I'm talking about."},
                {"step": "3_remote", "dialogue": "I need to connect to your computer to remove the malware. Please open your web browser and go to {support_url}. Enter the session code {session_code} and click Connect. This will let me safely clean your system."},
                {"step": "4_escalate", "dialogue": "I can see the infection is quite severe. I need to install our advanced removal tool. I'm going to download it now — you'll see a prompt asking for permission. Please click Yes."},
                {"step": "5_credential", "dialogue": "To complete the cleanup, I need your Microsoft 365 login to scan your cloud storage for infected files. Can you type that into the dialog box I've opened?"},
            ],
            fallback_responses={
                "Microsoft doesn't call people": "We do for critical security issues that affect our network infrastructure. Your system is actively attacking other Microsoft customers. If you prefer, you can call us back at {fake_number} — ask for the security response team.",
                "I'll contact my IT department": "Your IT department may not be aware of this yet — the malware is sophisticated enough to bypass their tools. But yes, you should inform them. In the meantime, the malware continues to spread. Can we address it now?",
                "I'm hanging up": "I understand your hesitation — there are many scam calls out there. But I'd strongly encourage you to check your Event Viewer as I described. If you see the errors, you know this is real. You can call us back at {fake_number}.",
            },
            voice_tone_notes="Slightly accented is acceptable — adds perceived authenticity for Microsoft support. Patient but concerned. Technical enough to seem knowledgeable but not intimidating.",
            background_audio="Large call center with many agents — reinforces legitimate support operation.",
            estimated_duration_min=15,
            success_criteria=["Target installs remote access tool", "Target provides Microsoft credentials", "Target grants screen sharing access"],
        ))

        scripts.append(VishingScript(
            script_id="vish-005",
            scenario_name="Insurance Claim Emergency",
            caller_identity="Cyber Insurance Claims Adjuster",
            caller_number_spoof="Insurance company main line",
            target_role="IT Director, CISO, or risk manager",
            objective="Extract complete security posture, incident history, and network architecture",
            opening="Hello {target_name}, this is {adjuster_name} from {insurance_company}, cyber claims division. I'm reaching out because we've received a notification that may affect your policy. A third-party vendor in your supply chain has reported a breach and your organization may be impacted. I need to conduct an emergency risk assessment.",
            main_script=[
                {"step": "1_context", "dialogue": "The breached vendor is {vendor_name}. They provide services to several of our insured clients. We need to determine your exposure level to assess potential claims. This is time-sensitive."},
                {"step": "2_access_audit", "dialogue": "Does {vendor_name} have any access to your network or systems? VPN, API integrations, shared credentials? What data did they have access to?"},
                {"step": "3_security_controls", "dialogue": "Walk me through your current security controls — EDR platform, SIEM solution, network segmentation approach. We need to determine if the breach could propagate to your environment."},
                {"step": "4_incident_history", "dialogue": "Have you experienced any unusual network activity in the past 30 days? Any alerts, failed logins, or data anomalies? Even things that seemed benign at the time could be related."},
                {"step": "5_remediation", "dialogue": "Based on what you've told me, I'd recommend isolating any connections to {vendor_name} immediately. I'll need you to send me your network topology and firewall rules so our security team can assess your exposure."},
            ],
            fallback_responses={
                "I need to verify this with our broker": "Your broker is {broker_name}, correct? They should have received the same notification. But given the urgency, I'd recommend we proceed with the assessment while you confirm. Every hour matters in breach containment.",
                "We don't use that vendor": "That's great news for your exposure level. However, we still need to complete the assessment — the vendor may have subcontractors that interface with your systems indirectly. Can we go through the checklist?",
                "Send me something in writing": "I'll send the formal notification after this call, but the assessment is time-sensitive per your policy's breach notification clause. Delays could affect your coverage in the event of a claim.",
            },
            voice_tone_notes="Serious, professional, insurance-industry formal. Convey urgency through facts, not emotion. Use insurance terminology authentically.",
            background_audio="Quiet office — professional insurance company environment.",
            estimated_duration_min=20,
            success_criteria=["Extract complete security stack details", "Obtain vendor access information", "Receive network topology documents"],
        ))

        scripts.append(VishingScript(
            script_id="vish-006",
            scenario_name="HR Benefits Emergency",
            caller_identity="HR Benefits Administrator",
            caller_number_spoof="Internal HR extension",
            target_role="Any employee",
            objective="Harvest credentials through fake benefits portal",
            opening="Hi {target_name}, this is {hr_name} from HR Benefits. I'm calling because there's a discrepancy in your health insurance enrollment that could result in a lapse of coverage effective midnight tonight. I need to resolve this with you right now.",
            main_script=[
                {"step": "1_urgency", "dialogue": "Our system shows that your benefits election for this year didn't process correctly. If we don't fix this by end of day, you'll lose coverage for you and your dependents until the next open enrollment period."},
                {"step": "2_verify", "dialogue": "Let me pull up your record. Can you confirm your employee ID and date of birth? I want to make sure I'm looking at the right account."},
                {"step": "3_portal", "dialogue": "I need you to log into the benefits portal to re-submit your elections. Go to {phish_url} — this is the direct link to the enrollment correction form. Sign in with your regular work credentials."},
                {"step": "4_personal_info", "dialogue": "While you're in there, can you verify your SSN on file? We had a data migration issue and some records got corrupted. It shows ending in {wrong_last4} — is that correct?"},
                {"step": "5_close", "dialogue": "Perfect, your enrollment is updated and your coverage is secure. You should receive a confirmation email within the hour. Call us at extension {ext} if you don't see it."},
            ],
            fallback_responses={
                "I'll call HR directly": "Of course. The benefits line is {ext}. But please call right now — the enrollment system closes at 5 PM and I won't be able to process corrections after that until next month.",
                "Why is this the first I'm hearing about this?": "We sent emails last week but got bounced-back notifications from your address. That's actually why I'm calling directly. The email system issues are part of the same IT problem that caused the enrollment glitch.",
                "I don't feel comfortable providing my SSN": "I completely understand. You don't need to give it to me — just verify it on the portal screen when you log in. I can't see your screen; it's all handled securely in the system.",
            },
            voice_tone_notes="Warm, helpful, slightly worried on target's behalf. HR persona — empathetic and supportive. Create urgency around coverage lapse.",
            background_audio="Office environment with printer sounds — HR department feel.",
            estimated_duration_min=8,
            success_criteria=["Target logs into phishing portal", "Target provides employee ID and DOB", "Target verifies or provides SSN"],
        ))

        scripts.append(VishingScript(
            script_id="vish-007",
            scenario_name="Vendor Account Verification",
            caller_identity="Major vendor account manager",
            caller_number_spoof="Vendor's published business number",
            target_role="IT administrator or procurement",
            objective="Obtain admin credentials for vendor platforms or trigger license changes",
            opening="Hi {target_name}, this is {vendor_rep} from {vendor_name} account management. I'm your new account manager — I took over from {old_rep} who moved to a different division. I'm calling about your {product_name} license renewal and some urgent security updates.",
            main_script=[
                {"step": "1_rapport", "dialogue": "I've been reviewing your account and I see you've been a {vendor_name} customer for {years} years. Great partnership. I want to make sure the transition from {old_rep} is seamless."},
                {"step": "2_security", "dialogue": "There's actually a critical security advisory for {product_name} that affects your version. We need to verify your admin portal access is working so you can apply the patch before the vulnerability is publicly disclosed."},
                {"step": "3_credential", "dialogue": "Can you try logging into the admin console at {phish_url}? This is a temporary security portal for affected customers. I want to make sure your credentials work before I walk you through the patch process."},
                {"step": "4_license", "dialogue": "While we're at it, your license shows {license_count} seats but I see {actual_count} active users. We should reconcile that to avoid any true-up surprises. Can you pull up your user list?"},
                {"step": "5_expand", "dialogue": "I'll send you the patch instructions and the updated license agreement by email. What's the best email for technical correspondence? And who else on your team has admin access?"},
            ],
            fallback_responses={
                "How do I verify you're from the vendor?": "Great question. Check your {vendor_name} portal — my name should appear as your assigned account manager. Or you can call our main line at {vendor_phone} and ask for the enterprise accounts team.",
                "I'll apply the patch through normal channels": "Normally yes, but this is a zero-day that hasn't been added to the regular update channel yet. It's being distributed directly through account management to affected customers. We can't wait for the normal cycle.",
                "I need to check with my team": "Of course. But the disclosure embargo lifts in 48 hours and after that, exploit code will be public. I'd recommend applying the patch before then. Can we schedule a 15-minute call with your team tomorrow morning at the latest?",
            },
            voice_tone_notes="Friendly, professional account manager energy. Know the product well. Build rapport as the 'new person' taking over the account.",
            background_audio="Modern tech company office — open plan, light activity.",
            estimated_duration_min=12,
            success_criteria=["Target logs into fake vendor portal", "Target reveals admin user list", "Target provides technical contact details"],
        ))

        scripts.append(VishingScript(
            script_id="vish-008",
            scenario_name="Physical Security System Alert",
            caller_identity="Building security systems provider",
            caller_number_spoof="Security company service line",
            target_role="Facilities manager or building security",
            objective="Obtain access control system credentials or disable security features",
            opening="This is {tech_name} from {security_company}, your access control and surveillance provider. We're receiving critical alerts from your {location} facility — multiple sensors are reporting tamper conditions and two cameras went offline simultaneously. This could indicate a physical breach attempt.",
            main_script=[
                {"step": "1_urgency", "dialogue": "Our monitoring dashboard shows cameras {cam_ids} offline and door sensors on {doors} in tamper state. This pattern is consistent with someone attempting to bypass your physical security. When was your last authorized maintenance visit?"},
                {"step": "2_remote_access", "dialogue": "I need to connect to your access control server remotely to run diagnostics. Can you provide the remote access credentials for the {system_name} management console? Or walk me through setting up a temporary session."},
                {"step": "3_disable_controls", "dialogue": "To isolate the compromised sensors, I need to temporarily disable the tamper alerts on {doors}. Otherwise the false alarms will mask any real intrusion attempts. I'll re-enable them after the diagnostic."},
                {"step": "4_configuration", "dialogue": "What firmware version is your {system_name} running? I need to check if you're affected by the vulnerability we patched last month. Also, can you read me the serial number from the main controller unit?"},
                {"step": "5_close", "dialogue": "I've identified the issue — it was a firmware bug causing phantom alerts. I've applied the fix remotely. I'm also scheduling an on-site visit for {date} to physically inspect the affected sensors. Who should my technician check in with?"},
            ],
            fallback_responses={
                "I'll call your company directly": "Please do — our 24/7 NOC number is {noc_number}. Reference alert #{alert_id}. But the cameras are still offline, so you may want to send a guard to those areas as a precaution while you verify.",
                "We manage our own security systems": "I understand you have internal staff, but the monitoring contract with {security_company} means our NOC receives alerts directly. This particular alert pattern triggered our emergency response protocol automatically.",
                "I can't give remote access to our security systems": "I understand the sensitivity. Can your on-site team pull up the controller logs and read me the last 20 events? That will tell me if this is a real intrusion or a system fault. I can walk them through it.",
            },
            voice_tone_notes="Urgent but controlled. Security professional demeanor — matter-of-fact about threats. Technical knowledge of access control systems is essential for credibility.",
            background_audio="Security operations center — multiple monitors, alert tones in background.",
            estimated_duration_min=10,
            success_criteria=["Obtain security system credentials", "Target disables tamper alerts", "Learn physical security configuration"],
        ))

        for script in scripts:
            with self._lock:
                self._scripts[script.script_id] = script

    def get_all_scripts(self) -> List[VishingScript]:
        """Return all vishing scripts."""
        with self._lock:
            return list(self._scripts.values())

    def get_script_by_scenario(self, scenario_name: str) -> Optional[VishingScript]:
        """Find a script by scenario name (partial match)."""
        with self._lock:
            scenario_lower = scenario_name.lower()
            for script in self._scripts.values():
                if scenario_lower in script.scenario_name.lower():
                    return script
            return None

    def get_script_by_id(self, script_id: str) -> Optional[VishingScript]:
        """Retrieve a specific vishing script by ID."""
        with self._lock:
            return self._scripts.get(script_id)


# ════════════════════════════════════════════════════════════════════════════════
# SMISHING GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

class SMiShingGen:
    """Generates SMS phishing (smishing) templates for authorized assessments.

    Provides 10+ SMS templates covering various pretexts including package
    delivery, banking alerts, MFA, and corporate notifications.

    Usage:
        gen = SMiShingGen()
        templates = gen.get_all_templates()
        custom = gen.personalize_template("smish-001", {"name": "John"})
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._templates: Dict[str, SMiShingTemplate] = {}
        self._initialize_templates()
        logger.info("SMiShingGen initialized with %d templates", len(self._templates))

    def _initialize_templates(self) -> None:
        """Build the complete SMS phishing template library."""
        templates = [
            SMiShingTemplate(
                template_id="smish-001",
                name="Package Delivery Failed",
                sender_id="USPS",
                message_body="USPS: Your package (tracking #{tracking}) could not be delivered due to incomplete address. Update delivery details: {url}",
                shortened_url_pattern="usps-redelivery.{tld}/{code}",
                personalization_vars=["tracking", "url", "tld", "code"],
                urgency_level=7,
                category="package_delivery",
                target_demographics="General consumer",
                success_rate_estimate=0.18,
            ),
            SMiShingTemplate(
                template_id="smish-002",
                name="Bank Account Alert",
                sender_id="{bank_name}",
                message_body="{bank_name} ALERT: Unusual login detected on your account. If this wasn't you, verify immediately: {url} Reply STOP to opt out.",
                shortened_url_pattern="{bank_short}.secure-verify.{tld}/{code}",
                personalization_vars=["bank_name", "bank_short", "url", "tld", "code"],
                urgency_level=9,
                category="financial",
                target_demographics="Banking customers",
                success_rate_estimate=0.15,
            ),
            SMiShingTemplate(
                template_id="smish-003",
                name="MFA Verification Code",
                sender_id="{org_name}",
                message_body="Your {org_name} verification code is: {fake_code}. If you didn't request this, secure your account: {url}",
                shortened_url_pattern="{org_short}-security.{tld}/{code}",
                personalization_vars=["org_name", "org_short", "fake_code", "url", "tld", "code"],
                urgency_level=8,
                category="authentication",
                target_demographics="Corporate employees",
                success_rate_estimate=0.21,
            ),
            SMiShingTemplate(
                template_id="smish-004",
                name="Tax Refund Notification",
                sender_id="IRS",
                message_body="IRS: Your tax refund of ${amount} has been approved. To receive direct deposit, confirm your information: {url}",
                shortened_url_pattern="irs-refund.{tld}/{code}",
                personalization_vars=["amount", "url", "tld", "code"],
                urgency_level=6,
                category="government",
                target_demographics="Tax filers",
                success_rate_estimate=0.12,
            ),
            SMiShingTemplate(
                template_id="smish-005",
                name="Corporate Password Expiry",
                sender_id="{org_name} IT",
                message_body="{org_name}: Your network password expires today. Reset now to avoid lockout: {url}",
                shortened_url_pattern="{org_short}-reset.{tld}/{code}",
                personalization_vars=["org_name", "org_short", "url", "tld", "code"],
                urgency_level=8,
                category="corporate",
                target_demographics="Corporate employees",
                success_rate_estimate=0.24,
            ),
            SMiShingTemplate(
                template_id="smish-006",
                name="Toll Road Payment Due",
                sender_id="E-ZPass",
                message_body="E-ZPass: You have an outstanding toll of ${amount}. Pay within 48hrs to avoid $50 late fee: {url}",
                shortened_url_pattern="ezpass-pay.{tld}/{code}",
                personalization_vars=["amount", "url", "tld", "code"],
                urgency_level=7,
                category="payment",
                target_demographics="Drivers/commuters",
                success_rate_estimate=0.16,
            ),
            SMiShingTemplate(
                template_id="smish-007",
                name="Amazon Purchase Alert",
                sender_id="Amazon",
                message_body="Amazon: Your order for {product} (${amount}) has been confirmed. Didn't order this? Cancel here: {url}",
                shortened_url_pattern="amz-orders.{tld}/{code}",
                personalization_vars=["product", "amount", "url", "tld", "code"],
                urgency_level=8,
                category="ecommerce",
                target_demographics="Amazon customers",
                success_rate_estimate=0.19,
            ),
            SMiShingTemplate(
                template_id="smish-008",
                name="HR Direct Deposit Update",
                sender_id="{org_name} HR",
                message_body="{org_name} Payroll: Your direct deposit failed for this pay period. Update banking info before {deadline}: {url}",
                shortened_url_pattern="{org_short}-payroll.{tld}/{code}",
                personalization_vars=["org_name", "org_short", "deadline", "url", "tld", "code"],
                urgency_level=9,
                category="corporate",
                target_demographics="Corporate employees",
                success_rate_estimate=0.27,
            ),
            SMiShingTemplate(
                template_id="smish-009",
                name="Voicemail Notification",
                sender_id="Voicemail",
                message_body="You have 1 new voicemail from +{caller_number} ({duration}). Listen: {url}",
                shortened_url_pattern="vm-listen.{tld}/{code}",
                personalization_vars=["caller_number", "duration", "url", "tld", "code"],
                urgency_level=4,
                category="communication",
                target_demographics="General",
                success_rate_estimate=0.14,
            ),
            SMiShingTemplate(
                template_id="smish-010",
                name="WiFi Terms Acceptance",
                sender_id="{venue_name}",
                message_body="Welcome to {venue_name} WiFi. Accept terms & conditions to continue browsing: {url}",
                shortened_url_pattern="{venue_short}-wifi.{tld}/{code}",
                personalization_vars=["venue_name", "venue_short", "url", "tld", "code"],
                urgency_level=3,
                category="proximity",
                target_demographics="Event/venue attendees",
                success_rate_estimate=0.31,
            ),
            SMiShingTemplate(
                template_id="smish-011",
                name="Shipping Customs Hold",
                sender_id="DHL",
                message_body="DHL: Package #{tracking} held at customs. Pay clearance fee of ${amount} to release: {url} Ref: {ref}",
                shortened_url_pattern="dhl-clearance.{tld}/{code}",
                personalization_vars=["tracking", "amount", "url", "tld", "code", "ref"],
                urgency_level=7,
                category="package_delivery",
                target_demographics="International shippers",
                success_rate_estimate=0.17,
            ),
            SMiShingTemplate(
                template_id="smish-012",
                name="Appointment Confirmation",
                sender_id="{provider}",
                message_body="{provider}: Reminder - you have an appointment on {date} at {time}. Confirm or reschedule: {url}. Reply HELP for assistance.",
                shortened_url_pattern="{provider_short}-appt.{tld}/{code}",
                personalization_vars=["provider", "provider_short", "date", "time", "url", "tld", "code"],
                urgency_level=4,
                category="healthcare",
                target_demographics="Healthcare patients",
                success_rate_estimate=0.22,
            ),
        ]

        for tpl in templates:
            with self._lock:
                self._templates[tpl.template_id] = tpl

    def get_all_templates(self) -> List[SMiShingTemplate]:
        """Return all SMS phishing templates."""
        with self._lock:
            return list(self._templates.values())

    def get_template(self, template_id: str) -> Optional[SMiShingTemplate]:
        """Get a specific template by ID."""
        with self._lock:
            return self._templates.get(template_id)

    def get_templates_by_category(self, category: str) -> List[SMiShingTemplate]:
        """Get templates filtered by category."""
        with self._lock:
            return [t for t in self._templates.values() if t.category == category]

    def personalize_template(
        self, template_id: str, variables: Dict[str, str]
    ) -> Optional[SMiShingTemplate]:
        """Personalize a template with specific variables."""
        import copy
        with self._lock:
            base = self._templates.get(template_id)
            if not base:
                return None

            custom = copy.deepcopy(base)
            custom.template_id = f"custom-{uuid.uuid4().hex[:8]}"

            for var, value in variables.items():
                placeholder = f"{{{var}}}"
                custom.message_body = custom.message_body.replace(placeholder, value)
                custom.sender_id = custom.sender_id.replace(placeholder, value)
                custom.shortened_url_pattern = custom.shortened_url_pattern.replace(placeholder, value)

            return custom


# ════════════════════════════════════════════════════════════════════════════════
# DOMAIN LOOKALIKE GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

class DomainLookalikeGen:
    """Generates lookalike domains using multiple techniques.

    Implements homoglyph substitution, typosquatting, combosquatting,
    bitsquatting, and other algorithms to produce domains visually
    or typographically similar to a target domain.

    Usage:
        gen = DomainLookalikeGen()
        domains = gen.generate_all("example.com")
        homoglyphs = gen.generate_homoglyphs("example.com")
    """

    # Unicode homoglyph mapping for Latin characters
    HOMOGLYPHS: Dict[str, List[str]] = {
        "a": ["\u0430", "\u00e0", "\u00e1", "\u00e2", "\u00e4", "\u0101"],
        "b": ["\u0184", "\u042c"],
        "c": ["\u0441", "\u00e7", "\u0188"],
        "d": ["\u0501", "\u0257"],
        "e": ["\u0435", "\u00e8", "\u00e9", "\u00ea", "\u0113"],
        "f": ["\u0192"],
        "g": ["\u0261", "\u011f"],
        "h": ["\u04bb"],
        "i": ["\u0456", "\u00ec", "\u00ed", "\u00ee", "\u0131"],
        "j": ["\u0458"],
        "k": ["\u043a"],
        "l": ["\u006c", "\u0049", "\u04cf", "\u0131"],
        "m": ["\u043c"],
        "n": ["\u0578", "\u00f1"],
        "o": ["\u043e", "\u00f2", "\u00f3", "\u00f4", "\u00f6", "\u0585"],
        "p": ["\u0440"],
        "q": ["\u051b"],
        "r": ["\u0433"],
        "s": ["\u0455", "\u015f"],
        "t": ["\u0442"],
        "u": ["\u0446", "\u00f9", "\u00fa", "\u00fb", "\u00fc"],
        "v": ["\u0475"],
        "w": ["\u0461"],
        "x": ["\u0445"],
        "y": ["\u0443", "\u00fd"],
        "z": ["\u0290"],
    }

    # Common keyboard proximity for typosquatting
    KEYBOARD_ADJACENT: Dict[str, str] = {
        "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "sfce",
        "e": "wdrs", "f": "dgcv", "g": "fhtb", "h": "gjyn",
        "i": "ujko", "j": "hkun", "k": "jlim", "l": "kop",
        "m": "njk", "n": "bhjm", "o": "iklp", "p": "ol",
        "q": "wa", "r": "edft", "s": "awdx", "t": "rfgy",
        "u": "yhjk", "v": "cfgb", "w": "qase", "x": "zsdc",
        "y": "tghu", "z": "asx",
    }

    COMMON_TLDS = [
        ".com", ".net", ".org", ".io", ".co", ".info", ".biz",
        ".us", ".xyz", ".app", ".dev", ".online", ".site",
        ".tech", ".cloud", ".email", ".support", ".services",
    ]

    COMBOSQUAT_PREFIXES = [
        "login-", "secure-", "mail-", "auth-", "account-",
        "portal-", "my-", "web-", "app-", "vpn-", "sso-",
        "support-", "help-", "admin-", "verify-",
    ]

    COMBOSQUAT_SUFFIXES = [
        "-login", "-secure", "-portal", "-auth", "-verify",
        "-support", "-online", "-app", "-mail", "-sso",
        "-access", "-connect", "-services", "-cloud", "-help",
    ]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cache: Dict[str, List[LookalikeDomain]] = {}
        logger.info("DomainLookalikeGen initialized")

    def _split_domain(self, domain: str) -> Tuple[str, str]:
        """Split domain into name and TLD."""
        parts = domain.rsplit(".", 1)
        if len(parts) == 2:
            return parts[0], "." + parts[1]
        return domain, ".com"

    def generate_homoglyphs(
        self, domain: str, max_results: int = 30
    ) -> List[LookalikeDomain]:
        """Generate domains using Unicode homoglyph substitution."""
        name, tld = self._split_domain(domain)
        results: List[LookalikeDomain] = []
        seen: Set[str] = set()

        # Single character substitutions
        for i, char in enumerate(name):
            lower_char = char.lower()
            if lower_char in self.HOMOGLYPHS:
                for replacement in self.HOMOGLYPHS[lower_char]:
                    new_name = name[:i] + replacement + name[i + 1:]
                    candidate = new_name + tld
                    if candidate not in seen:
                        seen.add(candidate)
                        results.append(LookalikeDomain(
                            domain=candidate,
                            original=domain,
                            technique=DomainTechnique.HOMOGLYPH,
                            confidence=HOMOGLYPH_CONFIDENCE,
                            visual_similarity=0.95,
                            description=f"Homoglyph: '{char}' -> '{replacement}' at position {i}",
                        ))

        # Double character substitutions (more deceptive)
        if len(name) >= 4:
            for i in range(len(name) - 1):
                c1, c2 = name[i].lower(), name[i + 1].lower()
                if c1 in self.HOMOGLYPHS and c2 in self.HOMOGLYPHS:
                    for r1 in self.HOMOGLYPHS[c1][:2]:
                        for r2 in self.HOMOGLYPHS[c2][:2]:
                            new_name = name[:i] + r1 + r2 + name[i + 2:]
                            candidate = new_name + tld
                            if candidate not in seen:
                                seen.add(candidate)
                                results.append(LookalikeDomain(
                                    domain=candidate,
                                    original=domain,
                                    technique=DomainTechnique.HOMOGLYPH,
                                    confidence=HOMOGLYPH_CONFIDENCE,
                                    visual_similarity=0.90,
                                    description=f"Double homoglyph at positions {i},{i+1}",
                                ))

        return results[:max_results]

    def generate_typosquats(
        self, domain: str, max_results: int = 40
    ) -> List[LookalikeDomain]:
        """Generate domains using typosquatting techniques."""
        name, tld = self._split_domain(domain)
        results: List[LookalikeDomain] = []
        seen: Set[str] = {domain}

        def _add(candidate_name: str, desc: str, similarity: float) -> None:
            candidate = candidate_name + tld
            if candidate not in seen and len(candidate_name) > 1:
                seen.add(candidate)
                results.append(LookalikeDomain(
                    domain=candidate,
                    original=domain,
                    technique=DomainTechnique.TYPOSQUAT,
                    confidence=TYPOSQUAT_CONFIDENCE,
                    visual_similarity=similarity,
                    description=desc,
                ))

        # Character omission (missing letter)
        for i in range(len(name)):
            _add(name[:i] + name[i + 1:], f"Omission: removed '{name[i]}' at pos {i}", 0.85)

        # Character duplication (double letter)
        for i in range(len(name)):
            _add(name[:i] + name[i] + name[i:], f"Duplication: doubled '{name[i]}' at pos {i}", 0.80)

        # Adjacent key substitution
        for i, char in enumerate(name):
            lower_char = char.lower()
            if lower_char in self.KEYBOARD_ADJACENT:
                for adj in self.KEYBOARD_ADJACENT[lower_char]:
                    _add(name[:i] + adj + name[i + 1:], f"Adjacent key: '{char}'->'{adj}' at pos {i}", 0.75)

        # Character transposition (swap adjacent)
        for i in range(len(name) - 1):
            swapped = name[:i] + name[i + 1] + name[i] + name[i + 2:]
            _add(swapped, f"Transposition: swapped pos {i},{i+1}", 0.85)

        # Vowel swapping
        vowels = "aeiou"
        for i, char in enumerate(name):
            if char.lower() in vowels:
                for v in vowels:
                    if v != char.lower():
                        _add(name[:i] + v + name[i + 1:], f"Vowel swap: '{char}'->'{v}' at pos {i}", 0.70)

        # Character insertion
        for i in range(len(name)):
            for c in string.ascii_lowercase:
                if c != name[i].lower():
                    _add(name[:i] + c + name[i:], f"Insertion: '{c}' before pos {i}", 0.65)
                    if len(results) >= max_results * 3:
                        break
            if len(results) >= max_results * 3:
                break

        return results[:max_results]

    def generate_combosquats(
        self, domain: str, max_results: int = 30
    ) -> List[LookalikeDomain]:
        """Generate domains using combosquatting (adding prefixes/suffixes)."""
        name, tld = self._split_domain(domain)
        results: List[LookalikeDomain] = []
        seen: Set[str] = set()

        for prefix in self.COMBOSQUAT_PREFIXES:
            candidate = prefix + name + tld
            if candidate not in seen:
                seen.add(candidate)
                results.append(LookalikeDomain(
                    domain=candidate,
                    original=domain,
                    technique=DomainTechnique.COMBOSQUAT,
                    confidence=COMBOSQUAT_CONFIDENCE,
                    visual_similarity=0.60,
                    description=f"Combosquat prefix: '{prefix}'",
                ))

        for suffix in self.COMBOSQUAT_SUFFIXES:
            candidate = name + suffix + tld
            if candidate not in seen:
                seen.add(candidate)
                results.append(LookalikeDomain(
                    domain=candidate,
                    original=domain,
                    technique=DomainTechnique.COMBOSQUAT,
                    confidence=COMBOSQUAT_CONFIDENCE,
                    visual_similarity=0.60,
                    description=f"Combosquat suffix: '{suffix}'",
                ))

        return results[:max_results]

    def generate_bitsquats(
        self, domain: str, max_results: int = 20
    ) -> List[LookalikeDomain]:
        """Generate domains using bitsquatting (single-bit flips).

        Bitsquatting exploits random bit errors in memory/network hardware.
        Each character is a byte, and flipping a single bit produces a
        different valid character that hardware errors could naturally cause.
        """
        name, tld = self._split_domain(domain)
        results: List[LookalikeDomain] = []
        seen: Set[str] = {domain}

        for i, char in enumerate(name):
            orig_byte = ord(char)
            for bit_pos in range(8):
                flipped = orig_byte ^ (1 << bit_pos)
                if 0x21 <= flipped <= 0x7e:
                    new_char = chr(flipped)
                    if new_char.isalnum() or new_char == "-":
                        candidate_name = name[:i] + new_char + name[i + 1:]
                        candidate = candidate_name + tld
                        if candidate not in seen:
                            seen.add(candidate)
                            results.append(LookalikeDomain(
                                domain=candidate,
                                original=domain,
                                technique=DomainTechnique.BITSQUAT,
                                confidence=BITSQUAT_CONFIDENCE,
                                visual_similarity=0.50,
                                description=f"Bitsquat: bit {bit_pos} flip '{char}'->'{new_char}' at pos {i}",
                            ))

        return results[:max_results]

    def generate_tld_swaps(
        self, domain: str, max_results: int = 15
    ) -> List[LookalikeDomain]:
        """Generate domains using TLD swapping."""
        name, orig_tld = self._split_domain(domain)
        results: List[LookalikeDomain] = []

        for tld in self.COMMON_TLDS:
            if tld != orig_tld:
                candidate = name + tld
                results.append(LookalikeDomain(
                    domain=candidate,
                    original=domain,
                    technique=DomainTechnique.TLD_SWAP,
                    confidence=0.65,
                    visual_similarity=0.70,
                    description=f"TLD swap: '{orig_tld}' -> '{tld}'",
                ))

        return results[:max_results]

    def generate_subdomain_tricks(
        self, domain: str, max_results: int = 15
    ) -> List[LookalikeDomain]:
        """Generate domains using subdomain tricks."""
        name, tld = self._split_domain(domain)
        results: List[LookalikeDomain] = []
        tricks = [
            (f"{name}.login{tld}", "Subdomain trick: login suffix"),
            (f"{name}.secure{tld}", "Subdomain trick: secure suffix"),
            (f"login.{name}{tld}", "Subdomain prefix: login"),
            (f"secure.{name}{tld}", "Subdomain prefix: secure"),
            (f"auth.{name}{tld}", "Subdomain prefix: auth"),
            (f"portal.{name}{tld}", "Subdomain prefix: portal"),
            (f"mail.{name}{tld}", "Subdomain prefix: mail"),
            (f"vpn.{name}{tld}", "Subdomain prefix: vpn"),
            (f"{name}.com-verify.{tld.lstrip('.')}", "Subdomain with TLD embedded"),
            (f"{name}-{tld.lstrip('.')}.com", "TLD embedded as subdomain part"),
        ]

        for candidate, desc in tricks:
            results.append(LookalikeDomain(
                domain=candidate,
                original=domain,
                technique=DomainTechnique.SUBDOMAIN,
                confidence=0.60,
                visual_similarity=0.55,
                description=desc,
            ))

        return results[:max_results]

    def generate_hyphenation(
        self, domain: str, max_results: int = 15
    ) -> List[LookalikeDomain]:
        """Generate domains using hyphenation tricks."""
        name, tld = self._split_domain(domain)
        results: List[LookalikeDomain] = []
        seen: Set[str] = set()

        # Insert hyphens between characters
        for i in range(1, len(name)):
            candidate = name[:i] + "-" + name[i:] + tld
            if candidate not in seen:
                seen.add(candidate)
                results.append(LookalikeDomain(
                    domain=candidate,
                    original=domain,
                    technique=DomainTechnique.HYPHENATION,
                    confidence=0.55,
                    visual_similarity=0.65,
                    description=f"Hyphen inserted at position {i}",
                ))

        return results[:max_results]

    def generate_all(
        self, domain: str, max_per_technique: int = 15
    ) -> List[LookalikeDomain]:
        """Generate lookalike domains using all techniques.

        Returns a comprehensive list sorted by visual similarity.
        """
        with self._lock:
            if domain in self._cache:
                return self._cache[domain]

            all_domains: List[LookalikeDomain] = []
            all_domains.extend(self.generate_homoglyphs(domain, max_per_technique))
            all_domains.extend(self.generate_typosquats(domain, max_per_technique))
            all_domains.extend(self.generate_combosquats(domain, max_per_technique))
            all_domains.extend(self.generate_bitsquats(domain, max_per_technique))
            all_domains.extend(self.generate_tld_swaps(domain, max_per_technique))
            all_domains.extend(self.generate_subdomain_tricks(domain, max_per_technique))
            all_domains.extend(self.generate_hyphenation(domain, max_per_technique))

            # Sort by visual similarity descending
            all_domains.sort(key=lambda d: d.visual_similarity, reverse=True)

            self._cache[domain] = all_domains
            logger.info(
                "Generated %d lookalike domains for '%s'",
                len(all_domains), domain,
            )
            return all_domains

    def get_top_candidates(
        self, domain: str, count: int = 20
    ) -> List[LookalikeDomain]:
        """Get the top N most visually similar lookalike domains."""
        all_domains = self.generate_all(domain)
        return all_domains[:count]

    def get_stats(self, domain: str) -> Dict[str, Any]:
        """Return generation statistics for a domain."""
        all_domains = self.generate_all(domain)
        by_technique: Dict[str, int] = defaultdict(int)
        for d in all_domains:
            by_technique[d.technique.name] += 1

        return {
            "target_domain": domain,
            "total_generated": len(all_domains),
            "by_technique": dict(by_technique),
            "avg_visual_similarity": round(
                sum(d.visual_similarity for d in all_domains) / max(len(all_domains), 1), 4
            ),
            "top_5": [d.to_dict() for d in all_domains[:5]],
        }


# ════════════════════════════════════════════════════════════════════════════════
# SIREN SOCIAL ENGINEER — ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════


class SirenSocialEngineer:
    """
    Orchestrates multi-vector social engineering campaign simulation.

    Coordinates PhishingTemplateGen, PretextBuilder, VishingScriptGen,
    SMiShingGen, and DomainLookalikeGen into coherent campaign assessment.

    Usage::

        eng = SirenSocialEngineer()
        report = eng.full_campaign(
            organization="ACME Corp",
            domain="acmecorp.com",
            industry=IndustryType.TECHNOLOGY,
            vectors=[AttackVector.EMAIL, AttackVector.PHONE, AttackVector.SMS],
        )
    """

    # ── Industry Awareness Benchmarks ───────────────────────────────────

    INDUSTRY_BENCHMARKS: Dict[IndustryType, float] = {
        IndustryType.TECHNOLOGY: 62.0,
        IndustryType.FINANCE: 58.0,
        IndustryType.HEALTHCARE: 45.0,
        IndustryType.GOVERNMENT: 50.0,
        IndustryType.EDUCATION: 38.0,
        IndustryType.RETAIL: 42.0,
        IndustryType.MANUFACTURING: 40.0,
        IndustryType.ENERGY: 48.0,
        IndustryType.TELECOM: 55.0,
        IndustryType.LEGAL: 52.0,
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # Sub-engines
        self._phishing = PhishingTemplateGen()
        self._pretext = PretextBuilder()
        self._vishing = VishingScriptGen()
        self._smishing = SMiShingGen()
        self._domain_gen = DomainLookalikeGen()

        # State
        self._templates_generated: List[PhishingTemplate] = []
        self._pretexts_generated: List[PretextScript] = []
        self._vishing_scripts: List[VishingScript] = []
        self._smishing_templates: List[SMiShingTemplate] = []
        self._lookalike_domains: List[LookalikeDomain] = []
        self._campaign_results: List[CampaignResult] = []
        self._risk_findings: List[Dict[str, Any]] = []
        self._scan_phases: List[Dict[str, Any]] = []
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0

        logger.info("SirenSocialEngineer initialized with 5 sub-engines")

    # ── Phase 1: Phishing Templates ─────────────────────────────────────

    def generate_phishing(
        self,
        categories: Optional[List[PhishingCategory]] = None,
        target_org: str = "",
        industry: IndustryType = IndustryType.TECHNOLOGY,
    ) -> List[PhishingTemplate]:
        """Generate phishing email templates for specified categories."""
        with self._lock:
            t0 = time.time()
            templates: List[PhishingTemplate] = []

            cats = categories or list(PhishingCategory)
            for cat in cats:
                cat_templates = self._phishing.get_templates_by_category(cat)
                templates.extend(cat_templates)

            # Generate custom template if org is provided
            if target_org:
                for cat in cats[:3]:  # Top 3 categories
                    custom = self._phishing.generate_custom_template(
                        category=cat,
                        target_org=target_org,
                        sender_persona=f"IT Security Team - {target_org}",
                        urgency=8,
                        industry=industry,
                    )
                    if custom:
                        templates.append(custom)

            self._templates_generated.extend(templates)
            self._scan_phases.append({
                "phase": "phishing_generation",
                "duration": time.time() - t0,
                "templates": len(templates),
                "categories": [c.name for c in cats],
            })
            logger.info("Phase 1: Generated %d phishing templates", len(templates))
            return templates

    # ── Phase 2: Pretext Scripts ─────────────────────────────────────────

    def generate_pretexts(
        self,
        scenarios: Optional[List[PretextScenario]] = None,
        max_difficulty: int = 10,
    ) -> List[PretextScript]:
        """Generate pretext scripts for in-person/phone social engineering."""
        with self._lock:
            t0 = time.time()
            scripts: List[PretextScript] = []

            if scenarios:
                for scenario in scenarios:
                    script = self._pretext.get_script(scenario)
                    if script:
                        scripts.append(script)
            else:
                scripts = self._pretext.get_scripts_by_difficulty(max_difficulty)

            self._pretexts_generated.extend(scripts)
            self._scan_phases.append({
                "phase": "pretext_generation",
                "duration": time.time() - t0,
                "scripts": len(scripts),
            })
            logger.info("Phase 2: Generated %d pretext scripts", len(scripts))
            return scripts

    # ── Phase 3: Vishing Scripts ─────────────────────────────────────────

    def generate_vishing(self) -> List[VishingScript]:
        """Generate voice phishing (vishing) call scripts."""
        with self._lock:
            t0 = time.time()
            scripts = self._vishing.get_all_scripts()
            self._vishing_scripts.extend(scripts)
            self._scan_phases.append({
                "phase": "vishing_generation",
                "duration": time.time() - t0,
                "scripts": len(scripts),
            })
            logger.info("Phase 3: Generated %d vishing scripts", len(scripts))
            return scripts

    # ── Phase 4: SMiShing Templates ──────────────────────────────────────

    def generate_smishing(self) -> List[SMiShingTemplate]:
        """Generate SMS phishing (SMiShing) message templates."""
        with self._lock:
            t0 = time.time()
            templates = self._smishing.get_all_templates()
            self._smishing_templates.extend(templates)
            self._scan_phases.append({
                "phase": "smishing_generation",
                "duration": time.time() - t0,
                "templates": len(templates),
            })
            logger.info("Phase 4: Generated %d SMiShing templates", len(templates))
            return templates

    # ── Phase 5: Domain Lookalikes ───────────────────────────────────────

    def generate_lookalikes(
        self, domain: str, max_per_technique: int = 15
    ) -> List[LookalikeDomain]:
        """Generate lookalike domains for phishing infrastructure."""
        with self._lock:
            t0 = time.time()
            domains = self._domain_gen.generate_all(domain, max_per_technique)
            self._lookalike_domains.extend(domains)
            self._scan_phases.append({
                "phase": "domain_lookalike_generation",
                "duration": time.time() - t0,
                "domains": len(domains),
                "target": domain,
            })
            logger.info("Phase 5: Generated %d lookalike domains for '%s'",
                        len(domains), domain)
            return domains

    # ── Phase 6: Campaign Simulation ─────────────────────────────────────

    def simulate_campaign(
        self,
        organization: str,
        total_targets: int = 500,
        vectors: Optional[List[AttackVector]] = None,
        industry: IndustryType = IndustryType.TECHNOLOGY,
    ) -> List[CampaignResult]:
        """Simulate campaign results with realistic success rate estimates."""
        with self._lock:
            t0 = time.time()
            results: List[CampaignResult] = []
            vecs = vectors or [AttackVector.EMAIL, AttackVector.PHONE, AttackVector.SMS]

            benchmark = self.INDUSTRY_BENCHMARKS.get(industry, 50.0)

            for vector in vecs:
                targets_per_vector = total_targets // len(vecs)

                # Realistic click/success rates based on industry
                if vector == AttackVector.EMAIL:
                    click_rate = max(0.05, (100 - benchmark) / 100 * 0.45)
                    cred_rate = click_rate * 0.35
                    report_rate = benchmark / 100 * 0.15
                elif vector == AttackVector.PHONE:
                    click_rate = max(0.08, (100 - benchmark) / 100 * 0.30)
                    cred_rate = click_rate * 0.50
                    report_rate = benchmark / 100 * 0.08
                elif vector == AttackVector.SMS:
                    click_rate = max(0.10, (100 - benchmark) / 100 * 0.55)
                    cred_rate = click_rate * 0.25
                    report_rate = benchmark / 100 * 0.05
                else:
                    click_rate = max(0.06, (100 - benchmark) / 100 * 0.35)
                    cred_rate = click_rate * 0.30
                    report_rate = benchmark / 100 * 0.10

                sent = targets_per_vector
                opened = int(sent * random.uniform(0.40, 0.70))
                clicked = int(sent * click_rate * random.uniform(0.8, 1.2))
                creds = int(sent * cred_rate * random.uniform(0.7, 1.3))
                reported = int(sent * report_rate * random.uniform(0.5, 1.5))

                result = CampaignResult(
                    result_id=uuid.uuid4().hex[:12],
                    campaign_name=f"{organization} - {vector.name} Campaign",
                    vector=vector,
                    total_targets=targets_per_vector,
                    emails_sent=sent,
                    emails_opened=opened,
                    links_clicked=min(clicked, opened),
                    credentials_submitted=min(creds, clicked),
                    reported_by_targets=min(reported, sent),
                    time_to_first_click_sec=random.uniform(30, 600),
                    time_to_first_report_sec=random.uniform(300, 7200),
                    template_used=self._templates_generated[0].template_id if self._templates_generated else "",
                    started_at=time.time(),
                    completed_at=time.time(),
                    success_rate=round(min(clicked, opened) / max(sent, 1) * 100, 2),
                    report_rate=round(min(reported, sent) / max(sent, 1) * 100, 2),
                )
                results.append(result)

                # Generate risk findings
                if result.success_rate > 20:
                    self._risk_findings.append({
                        "severity": "CRITICAL",
                        "vector": vector.name,
                        "finding": f"High click-through rate ({result.success_rate}%) via {vector.name}",
                        "recommendation": f"Mandatory security awareness training for {vector.name} threats",
                    })
                elif result.success_rate > 10:
                    self._risk_findings.append({
                        "severity": "HIGH",
                        "vector": vector.name,
                        "finding": f"Elevated click-through rate ({result.success_rate}%) via {vector.name}",
                        "recommendation": f"Enhanced phishing simulation program for {vector.name}",
                    })

                if result.report_rate < 5:
                    self._risk_findings.append({
                        "severity": "HIGH",
                        "vector": vector.name,
                        "finding": f"Low reporting rate ({result.report_rate}%) — incidents go undetected",
                        "recommendation": "Deploy easy-report button and reward reporting behavior",
                    })

            self._campaign_results.extend(results)
            self._scan_phases.append({
                "phase": "campaign_simulation",
                "duration": time.time() - t0,
                "campaigns": len(results),
                "total_targets": total_targets,
            })
            logger.info("Phase 6: Simulated %d campaigns for %s",
                        len(results), organization)
            return results

    # ── Report Generation ────────────────────────────────────────────────

    def generate_report(
        self,
        organization: str = "",
        engagement_name: str = "",
        industry: IndustryType = IndustryType.TECHNOLOGY,
    ) -> SocialEngReport:
        """Generate consolidated social engineering assessment report."""
        with self._lock:
            benchmark = self.INDUSTRY_BENCHMARKS.get(industry, 50.0)

            # Compute awareness score from campaign results
            if self._campaign_results:
                report_rates = [r.report_rate for r in self._campaign_results]
                click_rates = [r.success_rate for r in self._campaign_results]
                avg_report = sum(report_rates) / len(report_rates)
                avg_click = sum(click_rates) / len(click_rates)
                awareness = max(0, min(100, 50 + avg_report * 2 - avg_click * 1.5))
            else:
                awareness = benchmark

            level = (
                AwarenessLevel.VERY_HIGH if awareness >= 80 else
                AwarenessLevel.HIGH if awareness >= 65 else
                AwarenessLevel.MODERATE if awareness >= 45 else
                AwarenessLevel.LOW if awareness >= 25 else
                AwarenessLevel.VERY_LOW
            )

            vectors_tested = list({r.vector for r in self._campaign_results})
            templates_used = [t.template_id for t in self._templates_generated[:20]]

            recommendations = [
                "Implement mandatory security awareness training quarterly",
                "Deploy phishing simulation program with progressive difficulty",
                "Install email security gateway with DMARC/DKIM/SPF enforcement",
                "Enable MFA on all externally-accessible accounts",
                "Create easy internal phishing report mechanism (one-click button)",
            ]

            if any(f.get("severity") == "CRITICAL" for f in self._risk_findings):
                recommendations.insert(0, "URGENT: Conduct immediate incident response drill")

            total_assets = (
                len(self._templates_generated) +
                len(self._pretexts_generated) +
                len(self._vishing_scripts) +
                len(self._smishing_templates) +
                len(self._lookalike_domains)
            )

            executive_summary = (
                f"Social engineering assessment for {organization or 'target organization'}. "
                f"Generated {total_assets} attack assets across "
                f"{len(vectors_tested)} vectors. "
                f"Awareness score: {awareness:.1f}/100 "
                f"(industry benchmark: {benchmark:.1f}). "
                f"Risk findings: {len(self._risk_findings)}."
            )

            report = SocialEngReport(
                report_id=uuid.uuid4().hex[:16],
                engagement_name=engagement_name or f"{organization} SE Assessment",
                organization=organization,
                vectors_tested=vectors_tested,
                templates_used=templates_used,
                campaign_results=list(self._campaign_results),
                awareness_score=round(awareness, 2),
                awareness_level=level,
                industry_benchmark=benchmark,
                risk_findings=list(self._risk_findings),
                recommendations=recommendations,
                executive_summary=executive_summary,
                generated_at=time.time(),
            )

            logger.info(
                "SE report: awareness=%.1f, level=%s, findings=%d, assets=%d",
                awareness, level.name, len(self._risk_findings), total_assets,
            )
            return report

    # ── Full Campaign Orchestration ──────────────────────────────────────

    def full_campaign(
        self,
        organization: str,
        domain: str,
        industry: IndustryType = IndustryType.TECHNOLOGY,
        vectors: Optional[List[AttackVector]] = None,
        total_targets: int = 500,
        engagement_name: str = "",
    ) -> SocialEngReport:
        """
        Execute complete social engineering assessment.

        Phases:
            1. Phishing template generation
            2. Pretext script generation
            3. Vishing script generation
            4. SMiShing template generation
            5. Domain lookalike generation
            6. Campaign simulation
            7. Report generation
        """
        with self._lock:
            self._scan_start = time.time()

        # Phase 1: Phishing
        self.generate_phishing(
            target_org=organization,
            industry=industry,
        )

        # Phase 2: Pretexts
        self.generate_pretexts()

        # Phase 3: Vishing
        if not vectors or AttackVector.PHONE in vectors:
            self.generate_vishing()

        # Phase 4: SMiShing
        if not vectors or AttackVector.SMS in vectors:
            self.generate_smishing()

        # Phase 5: Domain Lookalikes
        if domain:
            self.generate_lookalikes(domain)

        # Phase 6: Campaign Simulation
        self.simulate_campaign(
            organization=organization,
            total_targets=total_targets,
            vectors=vectors,
            industry=industry,
        )

        with self._lock:
            self._scan_end = time.time()

        # Phase 7: Report
        return self.generate_report(
            organization=organization,
            engagement_name=engagement_name,
            industry=industry,
        )

    # ── Accessors ────────────────────────────────────────────────────────

    def get_findings(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._risk_findings)

    def get_campaign_results(self) -> List[CampaignResult]:
        with self._lock:
            return list(self._campaign_results)

    def get_all_templates(self) -> Dict[str, int]:
        with self._lock:
            return {
                "phishing": len(self._templates_generated),
                "pretext": len(self._pretexts_generated),
                "vishing": len(self._vishing_scripts),
                "smishing": len(self._smishing_templates),
                "lookalike_domains": len(self._lookalike_domains),
            }

    def reset(self) -> None:
        """Reset all campaign state."""
        with self._lock:
            self._templates_generated.clear()
            self._pretexts_generated.clear()
            self._vishing_scripts.clear()
            self._smishing_templates.clear()
            self._lookalike_domains.clear()
            self._campaign_results.clear()
            self._risk_findings.clear()
            self._scan_phases.clear()
            self._scan_start = 0.0
            self._scan_end = 0.0
            logger.info("SirenSocialEngineer state reset")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize orchestrator state."""
        with self._lock:
            return {
                "templates_generated": {
                    "phishing": len(self._templates_generated),
                    "pretext": len(self._pretexts_generated),
                    "vishing": len(self._vishing_scripts),
                    "smishing": len(self._smishing_templates),
                    "lookalike_domains": len(self._lookalike_domains),
                },
                "campaigns": len(self._campaign_results),
                "risk_findings": len(self._risk_findings),
                "phases": list(self._scan_phases),
                "duration": self._scan_end - self._scan_start if self._scan_end else 0.0,
            }
