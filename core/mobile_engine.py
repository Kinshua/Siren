#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  📱  SIREN MOBILE ENGINE — Core Infrastructure for App Security Testing  📱   ██
██                                                                                ██
██  Motor central para testes de seguranca em aplicativos moveis                  ██
██  (Android/iOS). Gerencia ADB, Frida, dispositivos, APK/IPA.                   ██
██                                                                                ██
██  Features:                                                                     ██
██    • ADB Bridge — full device communication & command execution               ██
██    • Device Manager — multi-device orchestration & health check               ██
██    • Frida Engine — process injection, JS script execution, hooking           ██
██    • APK Handler — extract, decode, repack, sign, install                     ██
██    • IPA Handler — extract, analyze, resign (macOS only)                      ██
██    • Logcat Parser — real-time log analysis & pattern detection               ██
██    • Traffic Capture — pcap + mitmproxy integration                           ██
██    • Screenshot & Screen Recording — evidence collection                      ██
██    • App Lifecycle — install/uninstall/start/stop/clear/backup                ██
██    • Emulator Manager — AVD create/start/snapshot                             ██
██    • Root & Jailbreak Detection — detect & bypass root checks                 ██
██    • Keystore & Certificate Management                                         ██
██                                                                                ██
██  "O primeiro contato com o alvo mobile. Nenhum app esta seguro."              ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import base64
import enum
import hashlib
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree

logger = logging.getLogger("siren.mobile")


# ════════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ════════════════════════════════════════════════════════════════════════════


class Platform(enum.Enum):
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class DeviceState(enum.Enum):
    CONNECTED = "connected"
    OFFLINE = "offline"
    UNAUTHORIZED = "unauthorized"
    RECOVERY = "recovery"
    BOOTING = "booting"
    UNKNOWN = "unknown"


class AppState(enum.Enum):
    INSTALLED = "installed"
    RUNNING = "running"
    STOPPED = "stopped"
    NOT_INSTALLED = "not_installed"
    CRASHED = "crashed"


class SecurityLevel(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RootStatus(enum.Enum):
    ROOTED = "rooted"
    NOT_ROOTED = "not_rooted"
    UNKNOWN = "unknown"


DANGEROUS_PERMISSIONS = frozenset(
    {
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.BODY_SENSORS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.POST_NOTIFICATIONS",
    }
)

OWASP_MOBILE_TOP10 = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication / Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}


# ════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class DeviceInfo:
    serial: str
    platform: Platform = Platform.UNKNOWN
    state: DeviceState = DeviceState.UNKNOWN
    model: str = ""
    manufacturer: str = ""
    android_version: str = ""
    api_level: int = 0
    ios_version: str = ""
    build_number: str = ""
    cpu_abi: str = ""
    screen_resolution: str = ""
    is_emulator: bool = False
    root_status: RootStatus = RootStatus.UNKNOWN
    disk_free_mb: int = 0
    ram_total_mb: int = 0
    battery_level: int = -1
    wifi_connected: bool = False
    usb_debugging: bool = True
    frida_server_running: bool = False
    installed_packages: List[str] = field(default_factory=list)


@dataclass
class APKInfo:
    path: str = ""
    package_name: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    compile_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    exported_components: List[str] = field(default_factory=list)
    intent_filters: List[Dict[str, Any]] = field(default_factory=list)
    meta_data: Dict[str, str] = field(default_factory=dict)
    signing_info: Dict[str, Any] = field(default_factory=dict)
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext: bool = False
    network_security_config: Optional[str] = None
    native_libs: List[str] = field(default_factory=list)
    dex_count: int = 0
    total_size_bytes: int = 0
    sha256: str = ""
    dangerous_permissions: List[str] = field(default_factory=list)
    deeplinks: List[str] = field(default_factory=list)
    custom_schemes: List[str] = field(default_factory=list)


@dataclass
class IPAInfo:
    path: str = ""
    bundle_id: str = ""
    bundle_name: str = ""
    version: str = ""
    build: str = ""
    min_ios: str = ""
    entitlements: Dict[str, Any] = field(default_factory=dict)
    url_schemes: List[str] = field(default_factory=list)
    universal_links: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    allows_arbitrary_loads: bool = False
    has_app_transport_security: bool = True
    signing_info: Dict[str, Any] = field(default_factory=dict)
    total_size_bytes: int = 0
    sha256: str = ""


@dataclass
class LogcatEntry:
    timestamp: str = ""
    pid: int = 0
    tid: int = 0
    level: str = ""
    tag: str = ""
    message: str = ""


@dataclass
class MobileFinding:
    title: str = ""
    severity: SecurityLevel = SecurityLevel.INFO
    owasp_category: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    component: str = ""
    cwe: str = ""
    cvss: float = 0.0
    poc: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: List[str] = field(default_factory=list)


@dataclass
class TrafficCapture:
    request_url: str = ""
    method: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    tls_version: str = ""
    cert_pinning_bypassed: bool = False
    timestamp: str = ""
    duration_ms: float = 0.0


# ════════════════════════════════════════════════════════════════════════════
# ADB BRIDGE — Full Android Debug Bridge Interface
# ════════════════════════════════════════════════════════════════════════════


class ADBBridge:
    """Full ADB interface — command execution, file transfer, app management."""

    def __init__(self, adb_path: Optional[str] = None) -> None:
        self.adb_path = adb_path or self._find_adb()
        self._connected_serial: Optional[str] = None
        self._command_timeout = 30
        self._transfer_timeout = 120

    def _find_adb(self) -> str:
        """Find ADB binary in standard locations."""
        candidates = [
            shutil.which("adb"),
        ]
        android_home = os.environ.get("ANDROID_HOME") or os.environ.get(
            "ANDROID_SDK_ROOT", ""
        )
        if android_home:
            candidates.append(os.path.join(android_home, "platform-tools", "adb"))
            candidates.append(os.path.join(android_home, "platform-tools", "adb.exe"))
        local_sdk = Path.home() / "Android" / "Sdk" / "platform-tools"
        candidates.append(str(local_sdk / "adb"))
        candidates.append(str(local_sdk / "adb.exe"))

        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return "adb"

    async def execute(
        self,
        *args: str,
        serial: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[int, str, str]:
        """Execute ADB command and return (returncode, stdout, stderr)."""
        cmd = [self.adb_path]
        target = serial or self._connected_serial
        if target:
            cmd.extend(["-s", target])
        cmd.extend(args)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            t = timeout or self._command_timeout
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=t)
            rc = proc.returncode or 0
            return (
                rc,
                stdout_b.decode("utf-8", errors="replace"),
                stderr_b.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            logger.warning("ADB command timed out: %s", " ".join(args))
            try:
                proc.kill()
            except Exception:
                pass
            return -1, "", "timeout"
        except FileNotFoundError:
            return -1, "", f"ADB not found at {self.adb_path}"

    async def shell(
        self,
        command: str,
        serial: Optional[str] = None,
        timeout: Optional[int] = None,
        as_root: bool = False,
    ) -> Tuple[int, str]:
        """Execute shell command on device."""
        if as_root:
            command = f"su -c '{command}'"
        rc, out, err = await self.execute(
            "shell", command, serial=serial, timeout=timeout
        )
        return rc, out.strip()

    async def list_devices(self) -> List[DeviceInfo]:
        """List all connected devices with detailed info."""
        rc, out, _ = await self.execute("devices", "-l")
        if rc != 0:
            return []

        devices = []
        for line in out.strip().splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            serial = parts[0]
            state_str = parts[1]

            state_map = {
                "device": DeviceState.CONNECTED,
                "offline": DeviceState.OFFLINE,
                "unauthorized": DeviceState.UNAUTHORIZED,
                "recovery": DeviceState.RECOVERY,
                "bootloader": DeviceState.BOOTING,
            }
            state = state_map.get(state_str, DeviceState.UNKNOWN)

            info = DeviceInfo(
                serial=serial,
                platform=Platform.ANDROID,
                state=state,
            )

            # Parse extras (model:xxx, product:xxx, etc.)
            for part in parts[2:]:
                if ":" in part:
                    key, val = part.split(":", 1)
                    if key == "model":
                        info.model = val
                    elif key == "product":
                        info.manufacturer = val

            if state == DeviceState.CONNECTED:
                await self._enrich_device_info(info)

            devices.append(info)

        return devices

    async def _enrich_device_info(self, info: DeviceInfo) -> None:
        """Fetch detailed properties from connected device."""
        props = {
            "ro.build.version.release": "android_version",
            "ro.build.version.sdk": "api_level",
            "ro.product.cpu.abi": "cpu_abi",
            "ro.product.manufacturer": "manufacturer",
            "ro.product.model": "model",
            "ro.build.display.id": "build_number",
        }
        for prop, attr in props.items():
            _, val = await self.shell(f"getprop {prop}", serial=info.serial)
            if val:
                if attr == "api_level":
                    try:
                        info.api_level = int(val)
                    except ValueError:
                        pass
                else:
                    setattr(info, attr, val)

        # Screen resolution
        _, res = await self.shell("wm size", serial=info.serial)
        m = re.search(r"(\d+x\d+)", res)
        if m:
            info.screen_resolution = m.group(1)

        # Emulator detection
        _, fingerprint = await self.shell(
            "getprop ro.build.fingerprint", serial=info.serial
        )
        info.is_emulator = any(
            x in fingerprint.lower()
            for x in ("generic", "sdk", "emulator", "goldfish", "ranchu")
        ) or info.serial.startswith("emulator-")

        # Root detection
        info.root_status = await self._check_root(info.serial)

        # Battery
        _, batt = await self.shell("dumpsys battery", serial=info.serial)
        m = re.search(r"level:\s*(\d+)", batt)
        if m:
            info.battery_level = int(m.group(1))

        # Frida server check
        _, frida_ps = await self.shell("ps -A | grep frida", serial=info.serial)
        info.frida_server_running = "frida" in frida_ps.lower()

    async def _check_root(self, serial: str) -> RootStatus:
        """Comprehensive root detection."""
        checks = [
            ("which su", lambda o: o.strip() != ""),
            ("ls /system/app/Superuser.apk", lambda o: "No such" not in o),
            ("ls /system/xbin/su", lambda o: "No such" not in o),
            ("ls /data/local/tmp/frida-server", lambda o: "No such" not in o),
            ("getprop ro.build.tags", lambda o: "test-keys" in o),
            (
                "pm list packages | grep -i supersu",
                lambda o: "supersu" in o.lower(),
            ),
            (
                "pm list packages | grep -i magisk",
                lambda o: "magisk" in o.lower(),
            ),
            (
                "pm list packages | grep com.topjohnwu.magisk",
                lambda o: "magisk" in o.lower(),
            ),
        ]
        for cmd, check in checks:
            _, out = await self.shell(cmd, serial=serial)
            if check(out):
                return RootStatus.ROOTED
        return RootStatus.NOT_ROOTED

    async def install_apk(
        self,
        apk_path: str,
        serial: Optional[str] = None,
        flags: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """Install APK on device."""
        args = ["install"]
        if flags:
            args.extend(flags)
        else:
            args.extend(["-r", "-t", "-g"])
        args.append(apk_path)
        rc, out, err = await self.execute(
            *args, serial=serial, timeout=self._transfer_timeout
        )
        success = rc == 0 and "Success" in out
        return success, out if success else err

    async def uninstall_package(
        self, package: str, serial: Optional[str] = None, keep_data: bool = False
    ) -> Tuple[bool, str]:
        """Uninstall package from device."""
        args = ["uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package)
        rc, out, err = await self.execute(*args, serial=serial)
        return rc == 0, out or err

    async def pull_file(
        self,
        remote: str,
        local: str,
        serial: Optional[str] = None,
    ) -> bool:
        """Pull file from device."""
        rc, _, _ = await self.execute(
            "pull", remote, local, serial=serial, timeout=self._transfer_timeout
        )
        return rc == 0

    async def push_file(
        self,
        local: str,
        remote: str,
        serial: Optional[str] = None,
    ) -> bool:
        """Push file to device."""
        rc, _, _ = await self.execute(
            "push", local, remote, serial=serial, timeout=self._transfer_timeout
        )
        return rc == 0

    async def forward_port(
        self,
        local_port: int,
        remote_port: int,
        serial: Optional[str] = None,
    ) -> bool:
        """Forward local TCP port to device."""
        rc, _, _ = await self.execute(
            "forward",
            f"tcp:{local_port}",
            f"tcp:{remote_port}",
            serial=serial,
        )
        return rc == 0

    async def reverse_port(
        self,
        remote_port: int,
        local_port: int,
        serial: Optional[str] = None,
    ) -> bool:
        """Reverse forward: device port to local."""
        rc, _, _ = await self.execute(
            "reverse",
            f"tcp:{remote_port}",
            f"tcp:{local_port}",
            serial=serial,
        )
        return rc == 0

    async def clear_app_data(self, package: str, serial: Optional[str] = None) -> bool:
        """Clear all data for an application."""
        rc, _ = await self.shell(f"pm clear {package}", serial=serial)
        return rc == 0

    async def force_stop(self, package: str, serial: Optional[str] = None) -> bool:
        """Force stop an application."""
        rc, _ = await self.shell(f"am force-stop {package}", serial=serial)
        return rc == 0

    async def start_activity(
        self,
        package: str,
        activity: Optional[str] = None,
        extras: Optional[Dict[str, str]] = None,
        serial: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Start an activity via am start."""
        if activity:
            component = f"{package}/{activity}"
        else:
            # Launch main activity
            component = package
        cmd = (
            f"am start -n {component}"
            if activity
            else f"monkey -p {package} -c android.intent.category.LAUNCHER 1"
        )
        if extras and activity:
            for k, v in extras.items():
                cmd += f" --es {k} {v}"
        rc, out = await self.shell(cmd, serial=serial)
        return rc == 0, out

    async def send_broadcast(
        self,
        action: str,
        extras: Optional[Dict[str, str]] = None,
        serial: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Send a broadcast intent."""
        cmd = f"am broadcast -a {action}"
        if extras:
            for k, v in extras.items():
                cmd += f" --es {k} {v}"
        rc, out = await self.shell(cmd, serial=serial)
        return rc == 0, out

    async def start_service(
        self, package: str, service: str, serial: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Start a service."""
        rc, out = await self.shell(
            f"am startservice -n {package}/{service}", serial=serial
        )
        return rc == 0, out

    async def get_installed_packages(
        self,
        serial: Optional[str] = None,
        third_party_only: bool = True,
    ) -> List[str]:
        """List installed packages."""
        flag = "-3" if third_party_only else ""
        _, out = await self.shell(f"pm list packages {flag}", serial=serial)
        packages = []
        for line in out.splitlines():
            if line.startswith("package:"):
                packages.append(line[8:].strip())
        return packages

    async def get_app_path(
        self, package: str, serial: Optional[str] = None
    ) -> Optional[str]:
        """Get APK path for installed package."""
        _, out = await self.shell(f"pm path {package}", serial=serial)
        if out.startswith("package:"):
            return out[8:].strip()
        return None

    async def dump_app_data(
        self,
        package: str,
        output_dir: str,
        serial: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dump all accessible app data (requires root or debuggable app)."""
        result: Dict[str, Any] = {
            "shared_prefs": [],
            "databases": [],
            "files": [],
            "cache": [],
        }
        base = f"/data/data/{package}"

        dirs_to_check = {
            "shared_prefs": f"{base}/shared_prefs/",
            "databases": f"{base}/databases/",
            "files": f"{base}/files/",
            "cache": f"{base}/cache/",
        }

        os.makedirs(output_dir, exist_ok=True)

        for category, remote_dir in dirs_to_check.items():
            rc, listing = await self.shell(f"ls -la {remote_dir}", serial=serial)
            if rc != 0:
                # Try with root
                rc, listing = await self.shell(
                    f"ls -la {remote_dir}", serial=serial, as_root=True
                )
            if rc == 0:
                for line in listing.splitlines():
                    parts = line.split()
                    if len(parts) >= 8 and not parts[-1].startswith("."):
                        fname = parts[-1]
                        remote_path = f"{remote_dir}{fname}"
                        local_path = os.path.join(output_dir, category, fname)
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        pulled = await self.pull_file(
                            remote_path, local_path, serial=serial
                        )
                        if pulled:
                            result[category].append(
                                {"file": fname, "local": local_path}
                            )

        return result

    async def screenshot(self, output_path: str, serial: Optional[str] = None) -> bool:
        """Take screenshot from device."""
        remote = "/sdcard/siren_screenshot.png"
        _, _ = await self.shell(f"screencap -p {remote}", serial=serial)
        success = await self.pull_file(remote, output_path, serial=serial)
        await self.shell(f"rm {remote}", serial=serial)
        return success

    async def record_screen(
        self, output_path: str, duration_seconds: int = 10, serial: Optional[str] = None
    ) -> bool:
        """Record device screen."""
        remote = "/sdcard/siren_recording.mp4"
        await self.shell(
            f"screenrecord --time-limit {duration_seconds} {remote}",
            serial=serial,
            timeout=duration_seconds + 10,
        )
        success = await self.pull_file(remote, output_path, serial=serial)
        await self.shell(f"rm {remote}", serial=serial)
        return success

    async def get_logcat(
        self,
        package: Optional[str] = None,
        lines: int = 500,
        serial: Optional[str] = None,
    ) -> List[LogcatEntry]:
        """Get parsed logcat entries."""
        cmd = f"logcat -d -v time -t {lines}"
        if package:
            # Get PID first
            _, pid_out = await self.shell(f"pidof {package}", serial=serial)
            if pid_out.strip():
                cmd += f" --pid={pid_out.strip()}"
        _, out = await self.shell(cmd, serial=serial)

        entries = []
        pattern = re.compile(
            r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
            r"(\d+)\s+(\d+)\s+([VDIWEF])\s+"
            r"(\S+)\s*:\s*(.*)"
        )
        for line in out.splitlines():
            m = pattern.match(line)
            if m:
                entries.append(
                    LogcatEntry(
                        timestamp=m.group(1),
                        pid=int(m.group(2)),
                        tid=int(m.group(3)),
                        level=m.group(4),
                        tag=m.group(5),
                        message=m.group(6),
                    )
                )
        return entries

    async def check_selinux(self, serial: Optional[str] = None) -> str:
        """Check SELinux status."""
        _, out = await self.shell("getenforce", serial=serial)
        return out.strip().lower()

    async def list_running_processes(
        self, serial: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """List running processes."""
        _, out = await self.shell("ps -A -o PID,USER,NAME", serial=serial)
        procs = []
        for line in out.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) >= 3:
                procs.append({"pid": parts[0], "user": parts[1], "name": parts[2]})
        return procs

    async def get_network_info(self, serial: Optional[str] = None) -> Dict[str, Any]:
        """Get device network configuration."""
        result: Dict[str, Any] = {}
        _, ifconfig = await self.shell("ifconfig 2>/dev/null || ip addr", serial=serial)
        result["interfaces"] = ifconfig

        _, netstat = await self.shell(
            "netstat -tlnp 2>/dev/null || ss -tlnp", serial=serial
        )
        result["listening_ports"] = netstat

        _, dns = await self.shell("getprop net.dns1", serial=serial)
        result["dns"] = dns.strip()

        _, wifi = await self.shell("dumpsys wifi | grep 'mWifiInfo'", serial=serial)
        result["wifi_info"] = wifi.strip()

        return result

    async def set_proxy(
        self,
        host: str,
        port: int,
        serial: Optional[str] = None,
    ) -> bool:
        """Set HTTP proxy on device (for traffic interception)."""
        rc, _ = await self.shell(
            f"settings put global http_proxy {host}:{port}", serial=serial
        )
        return rc == 0

    async def clear_proxy(self, serial: Optional[str] = None) -> bool:
        """Clear HTTP proxy settings."""
        rc, _ = await self.shell("settings put global http_proxy :0", serial=serial)
        return rc == 0

    async def install_ca_cert(
        self,
        cert_path: str,
        serial: Optional[str] = None,
    ) -> bool:
        """Install CA certificate on device (requires root for system store)."""
        # Push cert to device
        remote = "/sdcard/siren_ca.crt"
        if not await self.push_file(cert_path, remote, serial=serial):
            return False

        # Try system store (root)
        cert_hash = hashlib.md5(Path(cert_path).read_bytes()).hexdigest()[:8]
        system_cert = f"/system/etc/security/cacerts/{cert_hash}.0"

        rc, _ = await self.shell(
            f"mount -o remount,rw /system && cp {remote} {system_cert} && chmod 644 {system_cert}",
            serial=serial,
            as_root=True,
        )
        if rc == 0:
            return True

        # Fallback: user store
        rc, _ = await self.shell(
            f"am start -a android.credentials.INSTALL -t application/x-x509-ca-cert -d file://{remote}",
            serial=serial,
        )
        return rc == 0

    async def backup_app(
        self,
        package: str,
        output_path: str,
        serial: Optional[str] = None,
    ) -> bool:
        """Backup app data via adb backup."""
        rc, _, _ = await self.execute(
            "backup",
            "-f",
            output_path,
            "-noapk",
            package,
            serial=serial,
            timeout=60,
        )
        return rc == 0 and os.path.isfile(output_path)


# ════════════════════════════════════════════════════════════════════════════
# APK HANDLER — Extract, Analyze, Repack, Sign
# ════════════════════════════════════════════════════════════════════════════


class APKHandler:
    """APK static extraction and manipulation (no external tools needed for basic ops)."""

    MANIFEST_MAGIC = b"\x00\x00\x08\x00"

    def __init__(self, apk_path: str) -> None:
        self.apk_path = apk_path
        self.info = APKInfo(path=apk_path)
        self._temp_dir: Optional[str] = None

    async def analyze(self) -> APKInfo:
        """Full APK analysis using zipfile + XML parsing."""
        if not os.path.isfile(self.apk_path):
            raise FileNotFoundError(f"APK not found: {self.apk_path}")

        self.info.total_size_bytes = os.path.getsize(self.apk_path)
        self.info.sha256 = hashlib.sha256(Path(self.apk_path).read_bytes()).hexdigest()

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                self._analyze_zip_contents(zf)
                self._parse_manifest_from_zip(zf)
                self._extract_signing_info(zf)
                self._find_native_libs(zf)
                self._count_dex(zf)
        except zipfile.BadZipFile:
            logger.error("Invalid ZIP/APK file: %s", self.apk_path)

        self.info.dangerous_permissions = [
            p for p in self.info.permissions if p in DANGEROUS_PERMISSIONS
        ]

        return self.info

    def _analyze_zip_contents(self, zf: zipfile.ZipFile) -> None:
        """Analyze ZIP structure for interesting files."""
        for name in zf.namelist():
            lower = name.lower()
            if lower.endswith(".so"):
                self.info.native_libs.append(name)

    def _parse_manifest_from_zip(self, zf: zipfile.ZipFile) -> None:
        """Try to parse AndroidManifest.xml (binary XML)."""
        try:
            manifest_data = zf.read("AndroidManifest.xml")
        except KeyError:
            return

        # Try aapt/aapt2 first (most reliable)
        aapt = shutil.which("aapt2") or shutil.which("aapt")
        if aapt:
            self._parse_via_aapt(aapt)
            return

        # Binary XML parsing fallback
        self._parse_binary_manifest(manifest_data)

    def _parse_via_aapt(self, aapt_path: str) -> None:
        """Parse manifest via aapt dump."""
        try:
            result = subprocess.run(
                [aapt_path, "dump", "badging", self.apk_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout

            # Package name, version
            m = re.search(
                r"package:\s*name='([^']+)'\s+versionCode='(\d+)'\s+versionName='([^']*)'",
                output,
            )
            if m:
                self.info.package_name = m.group(1)
                self.info.version_code = int(m.group(2))
                self.info.version_name = m.group(3)

            # SDK versions
            m = re.search(r"sdkVersion:'(\d+)'", output)
            if m:
                self.info.min_sdk = int(m.group(1))
            m = re.search(r"targetSdkVersion:'(\d+)'", output)
            if m:
                self.info.target_sdk = int(m.group(1))

            # Permissions
            for m in re.finditer(r"uses-permission:\s*name='([^']+)'", output):
                self.info.permissions.append(m.group(1))

            # Launchable activity
            m = re.search(r"launchable-activity:\s*name='([^']+)'", output)
            if m:
                self.info.activities.append(m.group(1))

            # Get full XML dump for components
            result2 = subprocess.run(
                [aapt_path, "dump", "xmltree", self.apk_path, "AndroidManifest.xml"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self._parse_xmltree(result2.stdout)

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug("aapt parse error: %s", e)

    def _parse_xmltree(self, xmltree: str) -> None:
        """Parse aapt xmltree output for components and attributes."""
        current_element = ""
        current_exported = False
        current_name = ""

        for line in xmltree.splitlines():
            stripped = line.strip()

            # Element start
            m = re.match(r"E:\s+(\S+)", stripped)
            if m:
                # Save previous component
                if current_name and current_exported:
                    self.info.exported_components.append(current_name)
                current_element = m.group(1)
                current_exported = False
                current_name = ""

            # Attributes
            if "android:name" in stripped:
                m = re.search(r'android:name\([^)]*\)="([^"]+)"', stripped)
                if m:
                    current_name = m.group(1)
                    if current_element == "activity":
                        if current_name not in self.info.activities:
                            self.info.activities.append(current_name)
                    elif current_element == "service":
                        self.info.services.append(current_name)
                    elif current_element == "receiver":
                        self.info.receivers.append(current_name)
                    elif current_element == "provider":
                        self.info.providers.append(current_name)

            if "android:exported" in stripped:
                if "0xffffffff" in stripped or "true" in stripped.lower():
                    current_exported = True

            if "android:debuggable" in stripped:
                if "0xffffffff" in stripped or "true" in stripped.lower():
                    self.info.debuggable = True

            if "android:allowBackup" in stripped:
                if "0xffffffff" in stripped or "true" in stripped.lower():
                    self.info.allow_backup = True
                else:
                    self.info.allow_backup = False

            if "android:usesCleartextTraffic" in stripped:
                if "0xffffffff" in stripped or "true" in stripped.lower():
                    self.info.uses_cleartext = True

            # Deep links / schemes
            if "android:scheme" in stripped:
                m = re.search(r'android:scheme\([^)]*\)="([^"]+)"', stripped)
                if m:
                    scheme = m.group(1)
                    if scheme not in ("http", "https"):
                        self.info.custom_schemes.append(scheme)

            if "android:host" in stripped:
                m = re.search(r'android:host\([^)]*\)="([^"]+)"', stripped)
                if m:
                    self.info.deeplinks.append(m.group(1))

        # Final component
        if current_name and current_exported:
            self.info.exported_components.append(current_name)

    def _parse_binary_manifest(self, data: bytes) -> None:
        """Fallback: extract strings from binary XML manifest."""
        # Extract readable strings as fallback
        strings = set()
        i = 0
        while i < len(data) - 1:
            if data[i] > 0x20 and data[i] < 0x7F:
                end = i
                while end < len(data) and data[end] > 0x1F and data[end] < 0x7F:
                    end += 1
                s = data[i:end].decode("ascii", errors="ignore")
                if len(s) > 3:
                    strings.add(s)
                i = end
            else:
                i += 1

        # Heuristic extraction from strings
        for s in strings:
            if s.startswith("android.permission."):
                self.info.permissions.append(s)
            elif "." in s and s[0].islower() and len(s) > 10:
                # Could be package name
                if not self.info.package_name and s.count(".") >= 2:
                    self.info.package_name = s

    def _extract_signing_info(self, zf: zipfile.ZipFile) -> None:
        """Extract APK signing certificate info."""
        cert_files = [
            n
            for n in zf.namelist()
            if n.startswith("META-INF/")
            and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))
        ]
        if cert_files:
            cert_data = zf.read(cert_files[0])
            self.info.signing_info = {
                "cert_file": cert_files[0],
                "cert_size": len(cert_data),
                "cert_sha256": hashlib.sha256(cert_data).hexdigest(),
            }

        # Check for v2/v3 signing block
        sf_files = [
            n for n in zf.namelist() if n.startswith("META-INF/") and n.endswith(".SF")
        ]
        if sf_files:
            sf_data = zf.read(sf_files[0]).decode("utf-8", errors="ignore")
            if "SHA-256-Digest" in sf_data:
                self.info.signing_info["digest_algorithm"] = "SHA-256"
            elif "SHA1-Digest" in sf_data:
                self.info.signing_info["digest_algorithm"] = "SHA-1"

    def _find_native_libs(self, zf: zipfile.ZipFile) -> None:
        """Find native libraries by ABI."""
        libs: Dict[str, List[str]] = defaultdict(list)
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                parts = name.split("/")
                if len(parts) >= 3:
                    abi = parts[1]
                    lib_name = parts[-1]
                    libs[abi].append(lib_name)
        if libs:
            self.info.signing_info["native_abis"] = list(libs.keys())

    def _count_dex(self, zf: zipfile.ZipFile) -> None:
        """Count DEX files (multidex indicator)."""
        self.info.dex_count = sum(1 for n in zf.namelist() if n.endswith(".dex"))

    async def extract_to(self, output_dir: str) -> str:
        """Extract APK contents to directory."""
        os.makedirs(output_dir, exist_ok=True)
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            zf.extractall(output_dir)
        return output_dir

    async def decompile(self, output_dir: str) -> Tuple[bool, str]:
        """Decompile APK using apktool or jadx."""
        # Try jadx first
        jadx = shutil.which("jadx")
        if jadx:
            try:
                proc = await asyncio.create_subprocess_exec(
                    jadx,
                    "-d",
                    output_dir,
                    "--no-res",
                    self.apk_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, err = await asyncio.wait_for(proc.communicate(), timeout=300)
                if proc.returncode == 0:
                    return True, output_dir
            except (asyncio.TimeoutError, FileNotFoundError) as e:
                logger.debug("jadx decompile error: %s", e)

        # Try apktool
        apktool = shutil.which("apktool")
        if apktool:
            try:
                proc = await asyncio.create_subprocess_exec(
                    apktool,
                    "d",
                    "-f",
                    "-o",
                    output_dir,
                    self.apk_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, err = await asyncio.wait_for(proc.communicate(), timeout=300)
                if proc.returncode == 0:
                    return True, output_dir
            except (asyncio.TimeoutError, FileNotFoundError) as e:
                logger.debug("apktool decompile error: %s", e)

        return False, "No decompiler available (install jadx or apktool)"


# ════════════════════════════════════════════════════════════════════════════
# IPA HANDLER — iOS App Package Analysis
# ════════════════════════════════════════════════════════════════════════════


class IPAHandler:
    """IPA analysis — extract, parse Info.plist, entitlements."""

    def __init__(self, ipa_path: str) -> None:
        self.ipa_path = ipa_path
        self.info = IPAInfo(path=ipa_path)

    async def analyze(self) -> IPAInfo:
        """Analyze IPA package."""
        if not os.path.isfile(self.ipa_path):
            raise FileNotFoundError(f"IPA not found: {self.ipa_path}")

        self.info.total_size_bytes = os.path.getsize(self.ipa_path)
        self.info.sha256 = hashlib.sha256(Path(self.ipa_path).read_bytes()).hexdigest()

        try:
            with zipfile.ZipFile(self.ipa_path, "r") as zf:
                self._parse_info_plist(zf)
                self._parse_entitlements(zf)
                self._find_frameworks(zf)
        except zipfile.BadZipFile:
            logger.error("Invalid ZIP/IPA file: %s", self.ipa_path)

        return self.info

    def _parse_info_plist(self, zf: zipfile.ZipFile) -> None:
        """Parse Info.plist from IPA."""
        plist_files = [
            n for n in zf.namelist() if n.endswith("Info.plist") and "Payload/" in n
        ]
        if not plist_files:
            return

        plist_data = zf.read(plist_files[0])

        # Try XML plist parsing
        try:
            text = plist_data.decode("utf-8", errors="ignore")

            def _extract_plist_value(key: str) -> str:
                pattern = rf"<key>{re.escape(key)}</key>\s*" r"<string>(.*?)</string>"
                m = re.search(pattern, text, re.S)
                return m.group(1).strip() if m else ""

            self.info.bundle_id = _extract_plist_value("CFBundleIdentifier")
            self.info.bundle_name = _extract_plist_value("CFBundleName")
            self.info.version = _extract_plist_value("CFBundleShortVersionString")
            self.info.build = _extract_plist_value("CFBundleVersion")
            self.info.min_ios = _extract_plist_value("MinimumOSVersion")

            # URL Schemes
            scheme_pattern = re.compile(
                r"<key>CFBundleURLSchemes</key>\s*<array>(.*?)</array>",
                re.S,
            )
            m = scheme_pattern.search(text)
            if m:
                for sm in re.finditer(r"<string>(.*?)</string>", m.group(1)):
                    self.info.url_schemes.append(sm.group(1))

            # ATS (App Transport Security)
            if "NSAppTransportSecurity" in text:
                self.info.has_app_transport_security = True
                if "NSAllowsArbitraryLoads" in text:
                    ats_pattern = (
                        r"<key>NSAllowsArbitraryLoads</key>\s*" r"<(true|false)\s*/>"
                    )
                    m = re.search(ats_pattern, text)
                    if m and m.group(1) == "true":
                        self.info.allows_arbitrary_loads = True

            # Universal Links
            domains_pattern = re.compile(
                r"<key>com\.apple\.developer\.associated-domains</key>"
                r"\s*<array>(.*?)</array>",
                re.S,
            )
            m = domains_pattern.search(text)
            if m:
                for dm in re.finditer(r"<string>(.*?)</string>", m.group(1)):
                    self.info.universal_links.append(dm.group(1))

        except Exception as e:
            logger.debug("Info.plist parse error: %s", e)

    def _parse_entitlements(self, zf: zipfile.ZipFile) -> None:
        """Extract embedded entitlements."""
        for name in zf.namelist():
            if name.endswith(".entitlements") or "embedded.mobileprovision" in name:
                try:
                    data = zf.read(name).decode("utf-8", errors="ignore")
                    # Extract key-value pairs from plist XML
                    for m in re.finditer(
                        r"<key>(.*?)</key>\s*<(true|false|string)/?>(.*?)<",
                        data,
                        re.S,
                    ):
                        key = m.group(1)
                        val_type = m.group(2)
                        if val_type == "true":
                            self.info.entitlements[key] = True
                        elif val_type == "false":
                            self.info.entitlements[key] = False
                        elif val_type == "string":
                            self.info.entitlements[key] = m.group(3).strip()
                except Exception as e:
                    logger.debug("Entitlements parse error in %s: %s", name, e)

    def _find_frameworks(self, zf: zipfile.ZipFile) -> None:
        """Find embedded frameworks."""
        frameworks: Set[str] = set()
        for name in zf.namelist():
            if "/Frameworks/" in name and name.endswith(".framework/"):
                fw_name = name.split("/Frameworks/")[-1].rstrip("/")
                frameworks.add(fw_name)
            elif "/Frameworks/" in name and ".framework/" in name:
                parts = name.split("/Frameworks/")
                if len(parts) > 1:
                    fw = parts[1].split("/")[0]
                    frameworks.add(fw)
        self.info.frameworks = sorted(frameworks)


# ════════════════════════════════════════════════════════════════════════════
# FRIDA ENGINE — Process Injection & Hooking
# ════════════════════════════════════════════════════════════════════════════


class FridaEngine:
    """Frida integration for dynamic instrumentation.

    NOTE: Requires frida/frida-tools installed: pip install frida frida-tools
    Falls back to ADB-based instrumentation if Frida is unavailable.
    """

    def __init__(self, adb: ADBBridge) -> None:
        self.adb = adb
        self._frida_available = False
        self._frida = None
        self._device = None
        self._active_sessions: Dict[str, Any] = {}
        self._script_results: Dict[str, List[Any]] = defaultdict(list)
        self._check_frida()

    def _check_frida(self) -> None:
        """Check if Frida Python bindings are available."""
        try:
            import frida  # type: ignore

            self._frida = frida
            self._frida_available = True
            logger.info("Frida %s available", frida.__version__)
        except ImportError:
            logger.info("Frida not available — dynamic hooks will use ADB fallback")

    async def ensure_frida_server(self, serial: Optional[str] = None) -> bool:
        """Ensure frida-server is running on device."""
        if not self._frida_available:
            return False

        # Check if already running
        _, out = await self.adb.shell("ps -A | grep frida-server", serial=serial)
        if "frida-server" in out:
            return True

        # Try to start it
        rc, _ = await self.adb.shell(
            "nohup /data/local/tmp/frida-server &",
            serial=serial,
            as_root=True,
        )
        await asyncio.sleep(1)

        _, out = await self.adb.shell("ps -A | grep frida-server", serial=serial)
        return "frida-server" in out

    async def attach(
        self, package_or_pid: str | int, serial: Optional[str] = None
    ) -> Optional[str]:
        """Attach to a running process. Returns session ID."""
        if not self._frida_available:
            return None

        try:
            import frida  # type: ignore

            if serial:
                device = frida.get_device(serial)
            else:
                device = frida.get_usb_device()
            self._device = device

            if isinstance(package_or_pid, int):
                session = device.attach(package_or_pid)
            else:
                session = device.attach(package_or_pid)

            session_id = hashlib.md5(
                f"{package_or_pid}_{time.time()}".encode()
            ).hexdigest()[:16]
            self._active_sessions[session_id] = session

            return session_id

        except Exception as e:
            logger.debug("Frida attach error: %s", e)
            return None

    async def spawn_and_attach(
        self, package: str, serial: Optional[str] = None
    ) -> Optional[str]:
        """Spawn app and attach before main activity runs."""
        if not self._frida_available:
            return None

        try:
            import frida  # type: ignore

            if serial:
                device = frida.get_device(serial)
            else:
                device = frida.get_usb_device()
            self._device = device

            pid = device.spawn([package])
            session = device.attach(pid)

            session_id = hashlib.md5(
                f"{package}_spawn_{time.time()}".encode()
            ).hexdigest()[:16]
            self._active_sessions[session_id] = session

            device.resume(pid)
            return session_id

        except Exception as e:
            logger.debug("Frida spawn error: %s", e)
            return None

    async def inject_script(
        self, session_id: str, js_code: str
    ) -> Optional[Dict[str, Any]]:
        """Inject JavaScript code into attached process."""
        session = self._active_sessions.get(session_id)
        if not session:
            return None

        results: List[Any] = []

        def on_message(message: Any, data: Any) -> None:
            if message.get("type") == "send":
                results.append(message.get("payload"))
            elif message.get("type") == "error":
                results.append({"error": message.get("description", "")})

        try:
            script = session.create_script(js_code)
            script.on("message", on_message)
            script.load()

            # Wait for results
            await asyncio.sleep(2)

            self._script_results[session_id].extend(results)
            return {"session": session_id, "results": results, "loaded": True}
        except Exception as e:
            logger.debug("Script injection error: %s", e)
            return {"session": session_id, "error": str(e), "loaded": False}

    async def detach(self, session_id: str) -> bool:
        """Detach from process."""
        session = self._active_sessions.pop(session_id, None)
        if session:
            try:
                session.detach()
                return True
            except Exception as e:
                logger.debug("Frida detach error: %s", e)
        return False

    async def detach_all(self) -> int:
        """Detach from all sessions."""
        count = 0
        for sid in list(self._active_sessions.keys()):
            if await self.detach(sid):
                count += 1
        return count

    async def list_processes(
        self, serial: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List running processes via Frida."""
        if not self._frida_available:
            return []

        try:
            import frida  # type: ignore

            if serial:
                device = frida.get_device(serial)
            else:
                device = frida.get_usb_device()

            procs = device.enumerate_processes()
            return [{"pid": p.pid, "name": p.name} for p in procs]
        except Exception as e:
            logger.debug("Frida process list error: %s", e)
            return []

    async def list_apps(self, serial: Optional[str] = None) -> List[Dict[str, Any]]:
        """List installed applications via Frida."""
        if not self._frida_available:
            return []

        try:
            import frida  # type: ignore

            if serial:
                device = frida.get_device(serial)
            else:
                device = frida.get_usb_device()

            apps = device.enumerate_applications()
            return [
                {
                    "identifier": a.identifier,
                    "name": a.name,
                    "pid": a.pid,
                }
                for a in apps
            ]
        except Exception as e:
            logger.debug("Frida app list error: %s", e)
            return []


# ════════════════════════════════════════════════════════════════════════════
# LOGCAT ANALYZER — Real-time Log Analysis & Pattern Detection
# ════════════════════════════════════════════════════════════════════════════


class LogcatAnalyzer:
    """Analyze logcat output for security-relevant patterns."""

    SENSITIVE_PATTERNS = {
        "api_key": re.compile(
            r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})",
            re.I,
        ),
        "token": re.compile(
            r"(?:token|bearer|auth)\s*[:=]\s*['\"]?([A-Za-z0-9._\-]{20,})",
            re.I,
        ),
        "password": re.compile(
            r"(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]?(\S{4,})",
            re.I,
        ),
        "url_with_creds": re.compile(r"https?://[^:]+:[^@]+@[^\s]+", re.I),
        "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", re.I),
        "sql_query": re.compile(
            r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?(?:FROM|INTO|SET)\s+",
            re.I,
        ),
        "firebase_url": re.compile(r"https://[\w-]+\.firebaseio\.com", re.I),
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}", re.I),
        "google_api": re.compile(r"AIza[0-9A-Za-z_\-]{35}", re.I),
        "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.", re.I),
        "internal_ip": re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "base64_blob": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
        "stack_trace": re.compile(
            r"(?:at\s+[\w.$]+\([\w.]+:\d+\)|Traceback|Exception:|FATAL EXCEPTION)",
            re.I,
        ),
        "crypto_weak": re.compile(
            r"(?:DES|RC4|MD5|SHA1)\s*(?:cipher|hash|digest|encrypt)",
            re.I,
        ),
    }

    CRASH_INDICATORS = [
        "FATAL EXCEPTION",
        "java.lang.NullPointerException",
        "java.lang.SecurityException",
        "android.os.StrictMode",
        "SIGABRT",
        "SIGSEGV",
        "signal 11",
        "Native crash",
    ]

    def __init__(self) -> None:
        self.findings: List[MobileFinding] = []
        self.crashes: List[Dict[str, Any]] = []
        self._seen_hashes: Set[str] = set()

    def analyze_entries(
        self, entries: List[LogcatEntry], package: str = ""
    ) -> List[MobileFinding]:
        """Analyze logcat entries for security issues."""
        findings = []

        for entry in entries:
            # Filter by package if specified (by tag heuristic)
            msg = entry.message
            tag = entry.tag

            # Check sensitive data leaks
            for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
                matches = pattern.findall(msg)
                if matches:
                    # Deduplicate
                    sig = hashlib.md5(
                        f"{pattern_name}:{matches[0][:20]}".encode()
                    ).hexdigest()
                    if sig in self._seen_hashes:
                        continue
                    self._seen_hashes.add(sig)

                    finding = MobileFinding(
                        title=f"Sensitive data in logs: {pattern_name}",
                        severity=SecurityLevel.HIGH,
                        owasp_category="M9",
                        description=(
                            f"Found {pattern_name} pattern in logcat output "
                            f"(tag: {tag}, level: {entry.level})"
                        ),
                        evidence=msg[:500],
                        remediation=(
                            "Remove sensitive data from log statements. "
                            "Use ProGuard/R8 to strip Log.d/Log.v in release builds."
                        ),
                        component=tag,
                        cwe="CWE-532",
                        tags=["logcat", "data-leak", pattern_name],
                    )
                    findings.append(finding)

            # Check for crashes
            for indicator in self.CRASH_INDICATORS:
                if indicator in msg:
                    self.crashes.append(
                        {
                            "indicator": indicator,
                            "tag": tag,
                            "message": msg[:1000],
                            "timestamp": entry.timestamp,
                        }
                    )
                    break

        self.findings.extend(findings)
        return findings

    def analyze_text(self, logcat_text: str, package: str = "") -> List[MobileFinding]:
        """Analyze raw logcat text."""
        entries = []
        pattern = re.compile(
            r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
            r"(\d+)\s+(\d+)\s+([VDIWEF])\s+"
            r"(\S+)\s*:\s*(.*)"
        )
        for line in logcat_text.splitlines():
            m = pattern.match(line)
            if m:
                entries.append(
                    LogcatEntry(
                        timestamp=m.group(1),
                        pid=int(m.group(2)),
                        tid=int(m.group(3)),
                        level=m.group(4),
                        tag=m.group(5),
                        message=m.group(6),
                    )
                )
        return self.analyze_entries(entries, package)


# ════════════════════════════════════════════════════════════════════════════
# DEVICE MANAGER — Multi-Device Orchestration
# ════════════════════════════════════════════════════════════════════════════


class DeviceManager:
    """Manage multiple devices for parallel testing."""

    def __init__(self, adb: Optional[ADBBridge] = None) -> None:
        self.adb = adb or ADBBridge()
        self.devices: Dict[str, DeviceInfo] = {}
        self._primary_serial: Optional[str] = None

    async def refresh(self) -> List[DeviceInfo]:
        """Refresh device list."""
        found = await self.adb.list_devices()
        self.devices = {d.serial: d for d in found}
        if found and not self._primary_serial:
            connected = [d for d in found if d.state == DeviceState.CONNECTED]
            if connected:
                self._primary_serial = connected[0].serial
        return found

    @property
    def primary(self) -> Optional[DeviceInfo]:
        return self.devices.get(self._primary_serial or "")

    def set_primary(self, serial: str) -> bool:
        if serial in self.devices:
            self._primary_serial = serial
            return True
        return False

    async def health_check(self, serial: Optional[str] = None) -> Dict[str, Any]:
        """Run health check on device."""
        target = serial or self._primary_serial
        if not target:
            return {"error": "No device connected"}

        info = self.devices.get(target)
        if not info:
            return {"error": f"Device {target} not found"}

        result: Dict[str, Any] = {
            "serial": target,
            "state": info.state.value,
            "model": info.model,
            "android_version": info.android_version,
            "api_level": info.api_level,
            "root_status": info.root_status.value,
            "battery": info.battery_level,
            "is_emulator": info.is_emulator,
        }

        # Check ADB responsiveness
        start = time.time()
        rc, _ = await self.adb.shell("echo ok", serial=target)
        result["adb_latency_ms"] = round((time.time() - start) * 1000)
        result["adb_responsive"] = rc == 0

        # SELinux
        result["selinux"] = await self.adb.check_selinux(serial=target)

        # Frida
        result["frida_running"] = info.frida_server_running

        return result


# ════════════════════════════════════════════════════════════════════════════
# TRAFFIC INTERCEPTOR — Network Traffic Analysis
# ════════════════════════════════════════════════════════════════════════════


class TrafficInterceptor:
    """Capture and analyze mobile app network traffic."""

    def __init__(self, adb: ADBBridge) -> None:
        self.adb = adb
        self.captures: List[TrafficCapture] = []
        self._proxy_running = False

    async def start_tcpdump(
        self,
        output_pcap: str,
        serial: Optional[str] = None,
        interface: str = "any",
        filter_expr: str = "",
    ) -> bool:
        """Start tcpdump on device (requires root)."""
        remote_pcap = "/sdcard/siren_capture.pcap"
        cmd = f"tcpdump -i {interface} -w {remote_pcap}"
        if filter_expr:
            cmd += f" {filter_expr}"
        cmd += " &"

        rc, _ = await self.adb.shell(cmd, serial=serial, as_root=True)
        return rc == 0

    async def stop_tcpdump(
        self,
        local_output: str,
        serial: Optional[str] = None,
    ) -> bool:
        """Stop tcpdump and pull pcap file."""
        await self.adb.shell("killall tcpdump", serial=serial, as_root=True)
        await asyncio.sleep(1)
        remote_pcap = "/sdcard/siren_capture.pcap"
        success = await self.adb.pull_file(remote_pcap, local_output, serial=serial)
        await self.adb.shell(f"rm {remote_pcap}", serial=serial)
        return success

    def analyze_urls(self, captures: List[TrafficCapture]) -> List[MobileFinding]:
        """Analyze captured URLs for security issues."""
        findings = []

        for cap in captures:
            url = cap.request_url
            headers = cap.headers

            # HTTP (non-HTTPS)
            if url.startswith("http://"):
                findings.append(
                    MobileFinding(
                        title="Cleartext HTTP traffic detected",
                        severity=SecurityLevel.HIGH,
                        owasp_category="M5",
                        description=f"App sends traffic over unencrypted HTTP: {url[:200]}",
                        evidence=f"URL: {url}\nMethod: {cap.method}",
                        remediation="Use HTTPS for all network communication",
                        cwe="CWE-319",
                        tags=["network", "cleartext", "http"],
                    )
                )

            # Sensitive data in URL query params
            sensitive_params = {
                "password",
                "passwd",
                "pwd",
                "token",
                "api_key",
                "apikey",
                "secret",
                "session",
                "auth",
                "credit_card",
                "ssn",
                "pin",
            }
            parsed = __import__("urllib.parse", fromlist=["parse"]).urlparse(url)
            if parsed.query:
                params = __import__("urllib.parse", fromlist=["parse"]).parse_qs(
                    parsed.query
                )
                for param_name in params:
                    if param_name.lower() in sensitive_params:
                        findings.append(
                            MobileFinding(
                                title=f"Sensitive parameter in URL: {param_name}",
                                severity=SecurityLevel.HIGH,
                                owasp_category="M5",
                                description=f"Sensitive data '{param_name}' passed via URL query parameter",
                                evidence=f"URL: {url[:300]}",
                                remediation="Send sensitive data in request body, not URL params",
                                cwe="CWE-598",
                                tags=["network", "sensitive-data", "url-param"],
                            )
                        )

            # Weak TLS
            if cap.tls_version and cap.tls_version in (
                "TLSv1",
                "TLSv1.0",
                "TLSv1.1",
                "SSLv3",
            ):
                findings.append(
                    MobileFinding(
                        title=f"Weak TLS version: {cap.tls_version}",
                        severity=SecurityLevel.HIGH,
                        owasp_category="M5",
                        description=f"Connection using deprecated TLS version: {cap.tls_version}",
                        evidence=f"URL: {url}\nTLS: {cap.tls_version}",
                        remediation="Enforce TLS 1.2+ minimum",
                        cwe="CWE-326",
                        tags=["network", "tls", "weak-crypto"],
                    )
                )

            # Missing security headers in response
            resp_headers_lower = {k.lower(): v for k, v in cap.response_headers.items()}
            missing_headers = []
            for h in [
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
            ]:
                if h not in resp_headers_lower:
                    missing_headers.append(h)
            if missing_headers and url.startswith("https://"):
                findings.append(
                    MobileFinding(
                        title="Missing security headers in API response",
                        severity=SecurityLevel.LOW,
                        owasp_category="M8",
                        description=f"Missing headers: {', '.join(missing_headers)}",
                        evidence=f"URL: {url[:200]}",
                        remediation="Add security headers to all API responses",
                        cwe="CWE-693",
                        tags=["network", "headers", "misconfiguration"],
                    )
                )

        return findings


# ════════════════════════════════════════════════════════════════════════════
# EMULATOR MANAGER — AVD Creation & Management
# ════════════════════════════════════════════════════════════════════════════


class EmulatorManager:
    """Android emulator management for testing."""

    def __init__(self) -> None:
        self._sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get(
            "ANDROID_SDK_ROOT", ""
        )
        self._avdmanager = self._find_tool("avdmanager")
        self._emulator = self._find_tool("emulator")
        self._sdkmanager = self._find_tool("sdkmanager")

    def _find_tool(self, name: str) -> str:
        """Find Android SDK tool."""
        found = shutil.which(name)
        if found:
            return found
        if self._sdk_root:
            candidates = [
                os.path.join(self._sdk_root, "cmdline-tools", "latest", "bin", name),
                os.path.join(self._sdk_root, "tools", "bin", name),
                os.path.join(self._sdk_root, "emulator", name),
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return c
                if os.path.isfile(c + ".bat"):
                    return c + ".bat"
        return name

    async def list_avds(self) -> List[str]:
        """List available AVDs."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self._emulator,
                "-list-avds",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            return [l.strip() for l in out.decode().splitlines() if l.strip()]
        except Exception as e:
            logger.debug("List AVDs error: %s", e)
            return []

    async def start_emulator(
        self,
        avd_name: str,
        no_window: bool = False,
        wipe_data: bool = False,
        port: int = 5554,
    ) -> Optional[int]:
        """Start emulator and return PID."""
        cmd = [self._emulator, "-avd", avd_name, "-port", str(port)]
        if no_window:
            cmd.append("-no-window")
        if wipe_data:
            cmd.append("-wipe-data")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            # Wait for boot
            serial = f"emulator-{port}"
            for _ in range(60):
                await asyncio.sleep(2)
                adb = ADBBridge()
                devices = await adb.list_devices()
                for d in devices:
                    if d.serial == serial and d.state == DeviceState.CONNECTED:
                        return proc.pid
            return proc.pid
        except Exception as e:
            logger.debug("Emulator start error: %s", e)
            return None


# ════════════════════════════════════════════════════════════════════════════
# SIREN MOBILE CONTROLLER — Orchestrates All Mobile Operations
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class MobileTestConfig:
    """Configuration for mobile security testing."""

    # Target
    apk_path: str = ""
    ipa_path: str = ""
    package_name: str = ""
    target_serial: Optional[str] = None

    # Testing options
    enable_frida: bool = True
    enable_traffic_capture: bool = True
    enable_logcat_analysis: bool = True
    enable_static_analysis: bool = True
    enable_dynamic_analysis: bool = True

    # Paths
    output_dir: str = ""
    frida_scripts_dir: str = ""
    wordlist_dir: str = ""

    # Limits
    max_test_duration_seconds: int = 3600
    max_concurrent_tests: int = 5

    # Network
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080

    # OWASP categories to test (empty = all)
    owasp_categories: List[str] = field(default_factory=list)


@dataclass
class MobileTestResult:
    """Complete mobile security test results."""

    package_name: str = ""
    platform: Platform = Platform.UNKNOWN
    apk_info: Optional[APKInfo] = None
    ipa_info: Optional[IPAInfo] = None
    findings: List[MobileFinding] = field(default_factory=list)
    device_info: Optional[DeviceInfo] = None
    test_duration_seconds: float = 0.0
    tests_run: int = 0
    tests_passed: int = 0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SecurityLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SecurityLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SecurityLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SecurityLevel.LOW)


class SirenMobileController:
    """Master controller for all mobile security testing operations.

    Orchestrates ADB, Frida, static analysis, dynamic analysis,
    traffic capture, and logcat analysis into one unified workflow.
    """

    VERSION = "1.0.0"

    def __init__(self, config: Optional[MobileTestConfig] = None) -> None:
        self.config = config or MobileTestConfig()
        self.adb = ADBBridge()
        self.device_manager = DeviceManager(self.adb)
        self.frida = FridaEngine(self.adb)
        self.logcat_analyzer = LogcatAnalyzer()
        self.traffic_interceptor = TrafficInterceptor(self.adb)
        self.emulator_manager = EmulatorManager()
        self.result = MobileTestResult()
        self._start_time = 0.0

        if self.config.output_dir:
            os.makedirs(self.config.output_dir, exist_ok=True)

    async def run_full_assessment(self) -> MobileTestResult:
        """Execute comprehensive mobile security assessment."""
        self._start_time = time.time()
        logger.info("[SIREN MOBILE] Starting full assessment v%s", self.VERSION)

        # Phase 1: Device setup
        await self._phase_device_setup()

        # Phase 2: Static analysis
        if self.config.enable_static_analysis:
            await self._phase_static_analysis()

        # Phase 3: Install & launch
        await self._phase_install_and_launch()

        # Phase 4: Dynamic analysis
        if self.config.enable_dynamic_analysis:
            await self._phase_dynamic_analysis()

        # Phase 5: Traffic analysis
        if self.config.enable_traffic_capture:
            await self._phase_traffic_analysis()

        # Phase 6: Logcat analysis
        if self.config.enable_logcat_analysis:
            await self._phase_logcat_analysis()

        self.result.test_duration_seconds = time.time() - self._start_time
        logger.info(
            "[SIREN MOBILE] Assessment complete: %d findings "
            "(%d critical, %d high, %d medium, %d low) in %.1fs",
            len(self.result.findings),
            self.result.critical_count,
            self.result.high_count,
            self.result.medium_count,
            self.result.low_count,
            self.result.test_duration_seconds,
        )
        return self.result

    async def _phase_device_setup(self) -> None:
        """Phase 1: Connect and verify device."""
        logger.info("[SIREN MOBILE] Phase 1: Device setup")
        devices = await self.device_manager.refresh()

        if not devices:
            logger.warning("No devices connected")
            return

        if self.config.target_serial:
            self.device_manager.set_primary(self.config.target_serial)

        device = self.device_manager.primary
        if device:
            self.result.device_info = device
            self.result.platform = device.platform
            logger.info(
                "[SIREN MOBILE] Device: %s %s (Android %s, API %d)",
                device.manufacturer,
                device.model,
                device.android_version,
                device.api_level,
            )

            # Setup Frida if enabled
            if self.config.enable_frida:
                await self.frida.ensure_frida_server(serial=device.serial)

    async def _phase_static_analysis(self) -> None:
        """Phase 2: Static analysis of APK/IPA."""
        logger.info("[SIREN MOBILE] Phase 2: Static analysis")

        if self.config.apk_path:
            handler = APKHandler(self.config.apk_path)
            apk_info = await handler.analyze()
            self.result.apk_info = apk_info
            self.result.package_name = apk_info.package_name
            self.result.platform = Platform.ANDROID

            # Generate findings from static analysis
            self._audit_apk_static(apk_info)

        elif self.config.ipa_path:
            handler = IPAHandler(self.config.ipa_path)
            ipa_info = await handler.analyze()
            self.result.ipa_info = ipa_info
            self.result.package_name = ipa_info.bundle_id
            self.result.platform = Platform.IOS

            self._audit_ipa_static(ipa_info)

    def _audit_apk_static(self, info: APKInfo) -> None:
        """Generate findings from APK static analysis."""
        # Debuggable
        if info.debuggable:
            self.result.findings.append(
                MobileFinding(
                    title="Application is debuggable",
                    severity=SecurityLevel.CRITICAL,
                    owasp_category="M7",
                    description="android:debuggable=true in manifest. Allows debugger attachment and data extraction.",
                    evidence='AndroidManifest.xml: android:debuggable="true"',
                    remediation='Set android:debuggable="false" in release builds',
                    cwe="CWE-489",
                    cvss=7.5,
                    tags=["static", "manifest", "debuggable"],
                )
            )

        # Backup enabled
        if info.allow_backup:
            self.result.findings.append(
                MobileFinding(
                    title="Application allows backup",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M9",
                    description="android:allowBackup=true. App data can be extracted via adb backup.",
                    evidence='AndroidManifest.xml: android:allowBackup="true"',
                    remediation='Set android:allowBackup="false" or use android:fullBackupContent with rules',
                    cwe="CWE-530",
                    cvss=5.0,
                    tags=["static", "manifest", "backup"],
                )
            )

        # Cleartext traffic
        if info.uses_cleartext:
            self.result.findings.append(
                MobileFinding(
                    title="Cleartext traffic allowed",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M5",
                    description="android:usesCleartextTraffic=true. HTTP traffic is permitted.",
                    evidence='AndroidManifest.xml: android:usesCleartextTraffic="true"',
                    remediation='Set usesCleartextTraffic="false" and configure network_security_config.xml',
                    cwe="CWE-319",
                    cvss=6.5,
                    tags=["static", "manifest", "cleartext"],
                )
            )

        # Low target SDK
        if info.target_sdk > 0 and info.target_sdk < 31:
            self.result.findings.append(
                MobileFinding(
                    title=f"Low target SDK version: {info.target_sdk}",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M8",
                    description=f"targetSdkVersion={info.target_sdk}. Missing security features from newer Android versions.",
                    evidence=f"targetSdkVersion: {info.target_sdk}",
                    remediation="Update targetSdkVersion to at least 33 (Android 13)",
                    cwe="CWE-693",
                    tags=["static", "manifest", "sdk-version"],
                )
            )

        # Dangerous permissions
        if info.dangerous_permissions:
            for perm in info.dangerous_permissions:
                severity = SecurityLevel.MEDIUM
                short = perm.split(".")[-1]
                if short in (
                    "CAMERA",
                    "RECORD_AUDIO",
                    "ACCESS_FINE_LOCATION",
                    "ACCESS_BACKGROUND_LOCATION",
                    "READ_SMS",
                    "SEND_SMS",
                    "READ_CALL_LOG",
                    "READ_CONTACTS",
                ):
                    severity = SecurityLevel.HIGH

                self.result.findings.append(
                    MobileFinding(
                        title=f"Dangerous permission: {short}",
                        severity=severity,
                        owasp_category="M6",
                        description=f"App requests dangerous permission: {perm}",
                        evidence=f"uses-permission: {perm}",
                        remediation="Verify this permission is necessary and request at runtime",
                        cwe="CWE-250",
                        tags=["static", "permissions", short.lower()],
                    )
                )

        # Exported components
        if info.exported_components:
            for comp in info.exported_components:
                self.result.findings.append(
                    MobileFinding(
                        title=f"Exported component: {comp.split('.')[-1]}",
                        severity=SecurityLevel.MEDIUM,
                        owasp_category="M3",
                        description=f"Component is exported and accessible to other apps: {comp}",
                        evidence=f'android:exported="true": {comp}',
                        remediation='Set android:exported="false" unless external access is required. Add permission checks.',
                        cwe="CWE-926",
                        tags=["static", "components", "exported"],
                    )
                )

        # Custom URL schemes
        if info.custom_schemes:
            for scheme in info.custom_schemes:
                self.result.findings.append(
                    MobileFinding(
                        title=f"Custom URL scheme: {scheme}://",
                        severity=SecurityLevel.LOW,
                        owasp_category="M3",
                        description=f"App registers custom URL scheme '{scheme}://' which may be hijackable.",
                        evidence=f"intent-filter scheme: {scheme}",
                        remediation="Validate all data received via deep links. Consider using App Links (verified domains).",
                        cwe="CWE-939",
                        tags=["static", "deeplink", "scheme"],
                    )
                )

        # Weak signing
        if info.signing_info.get("digest_algorithm") == "SHA-1":
            self.result.findings.append(
                MobileFinding(
                    title="APK signed with SHA-1",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M10",
                    description="APK uses SHA-1 digest which is cryptographically weak.",
                    evidence=f"Signing: {info.signing_info}",
                    remediation="Use APK Signature Scheme v2/v3 with SHA-256",
                    cwe="CWE-328",
                    tags=["static", "signing", "weak-crypto"],
                )
            )

        # Multidex (complexity indicator)
        if info.dex_count > 1:
            self.result.findings.append(
                MobileFinding(
                    title=f"Multidex application ({info.dex_count} DEX files)",
                    severity=SecurityLevel.INFO,
                    owasp_category="M7",
                    description=f"App uses {info.dex_count} DEX files, indicating large codebase.",
                    evidence=f"DEX count: {info.dex_count}",
                    remediation="Consider code shrinking with R8/ProGuard",
                    tags=["static", "dex", "complexity"],
                )
            )

        self.result.tests_run += 1
        self.result.tests_passed += 1

    def _audit_ipa_static(self, info: IPAInfo) -> None:
        """Generate findings from IPA static analysis."""
        # ATS disabled
        if info.allows_arbitrary_loads:
            self.result.findings.append(
                MobileFinding(
                    title="App Transport Security disabled",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M5",
                    description="NSAllowsArbitraryLoads=true disables ATS, allowing insecure connections.",
                    evidence="Info.plist: NSAllowsArbitraryLoads = true",
                    remediation="Remove NSAllowsArbitraryLoads or set to false. Add per-domain exceptions only if needed.",
                    cwe="CWE-319",
                    cvss=6.5,
                    tags=["static", "ats", "ios", "cleartext"],
                )
            )

        # Custom URL schemes
        for scheme in info.url_schemes:
            self.result.findings.append(
                MobileFinding(
                    title=f"iOS URL scheme: {scheme}://",
                    severity=SecurityLevel.LOW,
                    owasp_category="M3",
                    description=f"App registers URL scheme '{scheme}://' which may be hijackable.",
                    evidence=f"CFBundleURLSchemes: {scheme}",
                    remediation="Validate all data from URL schemes. Use Universal Links for secure deep linking.",
                    cwe="CWE-939",
                    tags=["static", "ios", "url-scheme"],
                )
            )

        # Dangerous entitlements
        dangerous_entitlements = {
            "com.apple.developer.associated-domains": ("M3", "LOW"),
            "com.apple.developer.networking.vpn.api": ("M5", "MEDIUM"),
            "keychain-access-groups": ("M9", "INFO"),
        }
        for ent in info.entitlements:
            if ent in dangerous_entitlements:
                cat, sev = dangerous_entitlements[ent]
                self.result.findings.append(
                    MobileFinding(
                        title=f"Entitlement: {ent}",
                        severity=SecurityLevel[sev],
                        owasp_category=cat,
                        description=f"App has entitlement: {ent}",
                        evidence=f"Entitlements: {ent} = {info.entitlements[ent]}",
                        remediation="Review if this entitlement is necessary",
                        tags=["static", "ios", "entitlement"],
                    )
                )

        self.result.tests_run += 1
        self.result.tests_passed += 1

    async def _phase_install_and_launch(self) -> None:
        """Phase 3: Install app on device and launch."""
        logger.info("[SIREN MOBILE] Phase 3: Install & launch")
        device = self.device_manager.primary
        if not device:
            return

        pkg = self.config.package_name or (
            self.result.apk_info.package_name if self.result.apk_info else ""
        )

        if self.config.apk_path and pkg:
            # Install
            success, msg = await self.adb.install_apk(
                self.config.apk_path, serial=device.serial
            )
            if success:
                logger.info("[SIREN MOBILE] Installed %s", pkg)
            else:
                logger.warning("[SIREN MOBILE] Install failed: %s", msg)

            # Clear data for clean test
            await self.adb.clear_app_data(pkg, serial=device.serial)

            # Launch
            success, _ = await self.adb.start_activity(pkg, serial=device.serial)
            if success:
                logger.info("[SIREN MOBILE] Launched %s", pkg)
                await asyncio.sleep(3)  # Wait for app to initialize

        self.result.tests_run += 1

    async def _phase_dynamic_analysis(self) -> None:
        """Phase 4: Dynamic runtime analysis."""
        logger.info("[SIREN MOBILE] Phase 4: Dynamic analysis")
        device = self.device_manager.primary
        if not device:
            return

        pkg = self.config.package_name or (
            self.result.apk_info.package_name if self.result.apk_info else ""
        )
        if not pkg:
            return

        # Frida-based analysis
        if self.config.enable_frida:
            session_id = await self.frida.attach(pkg, serial=device.serial)
            if session_id:
                await self._run_frida_checks(session_id, pkg)
                await self.frida.detach(session_id)

        # App data analysis
        if self.config.output_dir:
            data_dir = os.path.join(self.config.output_dir, "app_data")
            data = await self.adb.dump_app_data(pkg, data_dir, serial=device.serial)
            self._analyze_app_data(data, data_dir)

        self.result.tests_run += 1

    async def _run_frida_checks(self, session_id: str, package: str) -> None:
        """Run Frida-based security checks."""
        # Check for root detection
        root_bypass_script = """
        Java.perform(function() {
            var results = [];

            // Check for common root detection classes
            try {
                var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
                results.push({type: 'root_detection', lib: 'RootBeer', found: true});
            } catch(e) {}

            try {
                var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNetApi');
                results.push({type: 'integrity_check', lib: 'SafetyNet', found: true});
            } catch(e) {}

            try {
                var PlayIntegrity = Java.use('com.google.android.play.core.integrity.IntegrityManager');
                results.push({type: 'integrity_check', lib: 'PlayIntegrity', found: true});
            } catch(e) {}

            // Check for SSL pinning
            try {
                var CertPinner = Java.use('okhttp3.CertificatePinner');
                results.push({type: 'ssl_pinning', lib: 'OkHttp', found: true});
            } catch(e) {}

            try {
                var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                results.push({type: 'ssl_pinning', lib: 'X509TrustManager', found: true});
            } catch(e) {}

            // Check for obfuscation
            try {
                var classes = Java.enumerateLoadedClassesSync();
                var obfuscated = classes.filter(function(c) {
                    return c.match(/^[a-z]\\.[a-z]\\.[a-z]$/);
                });
                results.push({type: 'obfuscation', obfuscated_classes: obfuscated.length, total_classes: classes.length});
            } catch(e) {}

            send(results);
        });
        """
        result = await self.frida.inject_script(session_id, root_bypass_script)
        if result and result.get("results"):
            for item in result["results"]:
                if isinstance(item, list):
                    for r in item:
                        if r.get("type") == "root_detection":
                            self.result.findings.append(
                                MobileFinding(
                                    title=f"Root detection library: {r.get('lib', 'unknown')}",
                                    severity=SecurityLevel.INFO,
                                    owasp_category="M7",
                                    description=f"App uses {r.get('lib')} for root detection",
                                    evidence=str(r),
                                    tags=["dynamic", "frida", "root-detection"],
                                )
                            )
                        elif r.get("type") == "ssl_pinning":
                            self.result.findings.append(
                                MobileFinding(
                                    title=f"SSL pinning detected: {r.get('lib', 'unknown')}",
                                    severity=SecurityLevel.INFO,
                                    owasp_category="M5",
                                    description=f"App implements SSL pinning via {r.get('lib')}",
                                    evidence=str(r),
                                    tags=["dynamic", "frida", "ssl-pinning"],
                                )
                            )
                        elif r.get("type") == "obfuscation":
                            total = r.get("total_classes", 0)
                            obf = r.get("obfuscated_classes", 0)
                            if total > 0:
                                ratio = obf / total
                                sev = (
                                    SecurityLevel.INFO
                                    if ratio > 0.3
                                    else SecurityLevel.MEDIUM
                                )
                                self.result.findings.append(
                                    MobileFinding(
                                        title=f"Code obfuscation: {ratio:.0%}",
                                        severity=sev,
                                        owasp_category="M7",
                                        description=(
                                            f"{obf}/{total} classes appear obfuscated "
                                            f"({ratio:.0%})"
                                        ),
                                        evidence=str(r),
                                        remediation=(
                                            "Use ProGuard/R8 for stronger obfuscation"
                                            if ratio < 0.3
                                            else ""
                                        ),
                                        tags=["dynamic", "frida", "obfuscation"],
                                    )
                                )

    def _analyze_app_data(self, data: Dict[str, Any], data_dir: str) -> None:
        """Analyze dumped app data for sensitive information."""
        # Check SharedPreferences for sensitive data
        for sp_file in data.get("shared_prefs", []):
            local_path = sp_file.get("local", "")
            if not local_path or not os.path.isfile(local_path):
                continue

            try:
                content = Path(local_path).read_text(encoding="utf-8", errors="ignore")

                # Check for sensitive patterns
                sensitive_patterns = {
                    "password": r"(?:password|passwd|pwd)\s*[=:>]\s*\S+",
                    "token": r"(?:token|auth_token|access_token|refresh_token)\s*[=:>]\s*\S+",
                    "api_key": r"(?:api[_-]?key|apikey)\s*[=:>]\s*\S+",
                    "private_key": r"-----BEGIN.*?PRIVATE KEY-----",
                    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
                    "email_password": r"(?:email|mail).*?(?:pass|pwd|password)",
                }

                for pattern_name, pattern in sensitive_patterns.items():
                    if re.search(pattern, content, re.I):
                        self.result.findings.append(
                            MobileFinding(
                                title=f"Sensitive data in SharedPreferences: {pattern_name}",
                                severity=SecurityLevel.HIGH,
                                owasp_category="M9",
                                description=(
                                    f"Found {pattern_name} pattern in "
                                    f"SharedPreferences file: {sp_file['file']}"
                                ),
                                evidence=f"File: {sp_file['file']}",
                                remediation=(
                                    "Use EncryptedSharedPreferences from AndroidX Security library. "
                                    "Never store sensitive data in plain SharedPreferences."
                                ),
                                cwe="CWE-312",
                                tags=["data-storage", "shared-prefs", pattern_name],
                            )
                        )

            except Exception as e:
                logger.debug(
                    "SharedPreferences analysis error for %s: %s",
                    sp_file.get("file", "?"),
                    e,
                )

        # Check databases for unencrypted sensitive data
        for db_file in data.get("databases", []):
            local_path = db_file.get("local", "")
            if not local_path or not os.path.isfile(local_path):
                continue

            try:
                # Read first bytes to check if encrypted
                first_bytes = Path(local_path).read_bytes()[:16]
                if first_bytes.startswith(b"SQLite format 3"):
                    # Unencrypted SQLite
                    self.result.findings.append(
                        MobileFinding(
                            title=f"Unencrypted database: {db_file['file']}",
                            severity=SecurityLevel.MEDIUM,
                            owasp_category="M9",
                            description=f"Database {db_file['file']} is not encrypted.",
                            evidence=f"File: {db_file['file']} (SQLite format 3, unencrypted)",
                            remediation="Use SQLCipher or Room with encryption for sensitive databases",
                            cwe="CWE-311",
                            tags=["data-storage", "database", "unencrypted"],
                        )
                    )
            except Exception as e:
                logger.debug("Database analysis error: %s", e)

    async def _phase_traffic_analysis(self) -> None:
        """Phase 5: Network traffic analysis."""
        logger.info("[SIREN MOBILE] Phase 5: Traffic analysis")
        device = self.device_manager.primary
        if not device:
            return

        # Setup proxy
        await self.adb.set_proxy(
            self.config.proxy_host,
            self.config.proxy_port,
            serial=device.serial,
        )

        # Start traffic capture via tcpdump
        if self.config.output_dir:
            pcap_path = os.path.join(self.config.output_dir, "capture.pcap")
            await self.traffic_interceptor.start_tcpdump(
                pcap_path, serial=device.serial
            )

            # Wait for some traffic
            await asyncio.sleep(10)

            await self.traffic_interceptor.stop_tcpdump(pcap_path, serial=device.serial)

        # Clean up proxy
        await self.adb.clear_proxy(serial=device.serial)
        self.result.tests_run += 1

    async def _phase_logcat_analysis(self) -> None:
        """Phase 6: Logcat analysis."""
        logger.info("[SIREN MOBILE] Phase 6: Logcat analysis")
        device = self.device_manager.primary
        if not device:
            return

        pkg = self.config.package_name or (
            self.result.apk_info.package_name if self.result.apk_info else ""
        )

        entries = await self.adb.get_logcat(
            package=pkg, lines=2000, serial=device.serial
        )
        findings = self.logcat_analyzer.analyze_entries(entries, package=pkg)
        self.result.findings.extend(findings)

        self.result.tests_run += 1
        self.result.tests_passed += 1

    def get_summary(self) -> Dict[str, Any]:
        """Get test result summary."""
        return {
            "package": self.result.package_name,
            "platform": self.result.platform.value,
            "duration": self.result.test_duration_seconds,
            "findings": len(self.result.findings),
            "critical": self.result.critical_count,
            "high": self.result.high_count,
            "medium": self.result.medium_count,
            "low": self.result.low_count,
            "tests_run": self.result.tests_run,
            "device": (
                f"{self.result.device_info.manufacturer} "
                f"{self.result.device_info.model}"
                if self.result.device_info
                else "None"
            ),
        }
