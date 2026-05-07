import os
import re
import json
import glob
import hashlib
import psutil
import datetime
import subprocess
import winreg
from pathlib import Path
from typing import Optional, Annotated, List, Dict, Any
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from collections import defaultdict

# 尝试导入 Windows 特有模块
try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

# 初始化 MCP 服务
mcp = FastMCP("SilverFox-IR-and-Lateral-Movement-Detector")

# 加载配置和 IOC 数据
SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR / "config.json"
IOC_FILE = SCRIPT_DIR / "silverfox_ioc.json"

def load_config() -> Dict[str, Any]:
    """加载配置文件"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def load_ioc() -> Dict[str, Any]:
    """加载 IOC 数据库"""
    if IOC_FILE.exists():
        with open(IOC_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

CONFIG = load_config()
IOC_DB = load_ioc()

# ==================== 辅助函数 ====================

def calculate_file_hash(file_path: str) -> str:
    """计算文件 SHA256 哈希"""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return "ERROR"

def is_suspicious_path(file_path: str) -> bool:
    """判断文件路径是否可疑"""
    suspicious_dirs = ['\\Temp\\', '\\AppData\\', '\\Public\\', '\\Downloads\\', '\\ProgramData\\']
    return any(d in file_path for d in suspicious_dirs)

def format_timestamp(timestamp: float) -> str:
    """格式化时间戳"""
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

# ==================== 1. 银狐木马特征检测 ====================

@mcp.tool()
def detect_silverfox_indicators(
    scan_processes: Annotated[bool, Field(description="是否扫描可疑进程")] = True,
    scan_files: Annotated[bool, Field(description="是否扫描可疑文件")] = True,
    scan_registry: Annotated[bool, Field(description="是否扫描注册表")] = True,
    scan_network: Annotated[bool, Field(description="是否扫描网络连接")] = True,
    max_results: Annotated[int, Field(description="最多返回结果数", ge=1, le=1000)] = 100
) -> str:
    """
    检测银狐木马的已知 IOC 指标：
    - 可疑文件路径（临时目录、AppData、Public 目录中的可执行文件）
    - 可疑进程名称（伪装的系统进程）
    - 可疑注册表键值（持久化机制）
    - 可疑网络连接（C2 通信）
    """
    if os.name != 'nt':
        return "该工具仅支持 Windows 系统。"

    findings = []
    silverfox_ioc = IOC_DB.get('silverfox_ioc', {})

    # === 1. 进程检测 ===
    if scan_processes:
        suspicious_procs = silverfox_ioc.get('process_names', [])
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
            try:
                name = proc.info['name']
                if name in suspicious_procs:
                    findings.append({
                        'type': 'process',
                        'severity': 'critical',
                        'description': f"检测到伪装系统进程: {name} (PID {proc.info['pid']})",
                        'details': f"路径: {proc.info['exe']}, 启动时间: {format_timestamp(proc.info['create_time'])}"
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # === 2. 文件检测 ===
    if scan_files:
        scan_paths = CONFIG.get('detection_config', {}).get('scan_paths', ['C:\\Users', 'C:\\ProgramData'])
        file_extensions = CONFIG.get('detection_config', {}).get('suspicious_file_extensions', ['.exe', '.dll'])

        for scan_path in scan_paths:
            if not os.path.exists(scan_path):
                continue
            for ext in file_extensions:
                pattern = f"{scan_path}\\**\\*{ext}"
                for file_path in glob.glob(pattern, recursive=True):
                    if len(findings) >= max_results:
                        break
                    if is_suspicious_path(file_path):
                        file_hash = calculate_file_hash(file_path)
                        findings.append({
                            'type': 'file',
                            'severity': 'high',
                            'description': f"检测到可疑文件: {file_path}",
                            'details': f"SHA256: {file_hash}, 大小: {os.path.getsize(file_path)} bytes"
                        })

    # === 3. 注册表检测 ===
    if scan_registry:
        reg_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive, key_path in reg_keys:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if is_suspicious_path(str(value)):
                                findings.append({
                                    'type': 'registry',
                                    'severity': 'high',
                                    'description': f"检测到可疑注册表启动项: {name}",
                                    'details': f"路径: {key_path}, 值: {value}"
                                })
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                continue
            except Exception:
                continue

    # === 4. 网络连接检测 ===
    if scan_network:
        suspicious_ports = silverfox_ioc.get('network_indicators', {}).get('suspicious_ports', [])
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.raddr.port in suspicious_ports:
                try:
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                    findings.append({
                        'type': 'network',
                        'severity': 'medium',
                        'description': f"检测到可疑网络连接: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}",
                        'details': f"进程: {proc_name} (PID {conn.pid}), 状态: {conn.status}"
                    })
                except:
                    continue

    # === 生成报告 ===
    if not findings:
        return "✅ 未检测到银狐木马相关 IOC 指标。"

    report = [f"🚨 检测到 {len(findings)} 个银狐木马相关威胁指标:\n"]
    for idx, finding in enumerate(findings, 1):
        severity_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(finding['severity'], '⚪')
        report.append(f"{idx}. {severity_icon} [{finding['type'].upper()}] {finding['description']}")
        report.append(f"   {finding['details']}\n")

    return "\n".join(report)

# ==================== 2. 内网横向移动检测 ====================

@mcp.tool()
def detect_lateral_movement(
    check_wmi: Annotated[bool, Field(description="检测 WMI 远程执行")] = True,
    check_psexec: Annotated[bool, Field(description="检测 PSExec 执行")] = True,
    check_rdp: Annotated[bool, Field(description="检测 RDP 登录")] = True,
    check_smb: Annotated[bool, Field(description="检测 SMB 共享访问")] = True,
    time_range_hours: Annotated[int, Field(description="检测时间范围（小时）", ge=1, le=168)] = 24
) -> str:
    """
    检测内网横向移动痕迹：
    - WMI 远程执行（Event ID 5857, 5858）
    - PSExec 执行（PSEXESVC 服务）
    - RDP 登录（Event ID 4624 Type 10）
    - SMB 共享访问（Event ID 5140）
    """
    if os.name != 'nt':
        return "该工具仅支持 Windows 系统。"

    if not WIN32_AVAILABLE:
        return "需要安装 pywin32 模块才能检测横向移动。"

    findings = []
    lateral_ioc = IOC_DB.get('lateral_movement_indicators', {})
    after_time = datetime.datetime.now() - datetime.timedelta(hours=time_range_hours)

    # === 1. PSExec 检测 ===
    if check_psexec:
        suspicious_services = lateral_ioc.get('suspicious_services', [])
        try:
            for svc in psutil.win_service_iter():
                try:
                    svc_name = svc.name()
                    if any(s.lower() in svc_name.lower() for s in suspicious_services):
                        config = svc.as_dict()
                        findings.append({
                            'type': 'psexec',
                            'severity': 'critical',
                            'description': f"检测到 PSExec 服务: {svc_name}",
                            'details': f"显示名: {config.get('display_name')}, 路径: {config.get('binpath')}"
                        })
                except:
                    continue
        except Exception:
            pass

    # === 2. RDP 登录检测 ===
    if check_rdp:
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            if hand:
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events_checked = 0
                max_events = 500

                while events_checked < max_events:
                    chunk = win32evtlog.ReadEventLog(hand, flags, 0, 100)
                    if not chunk:
                        break
                    for event in chunk:
                        events_checked += 1
                        if event.EventID == 4624:  # 登录成功
                            event_time = datetime.datetime.fromtimestamp(event.TimeGenerated.timestamp())
                            if event_time < after_time:
                                continue
                            msg = win32evtlogutil.SafeFormatMessage(event, "Security")
                            if "Logon Type:\t\t\t10" in msg or "登录类型:\t\t\t10" in msg:
                                findings.append({
                                    'type': 'rdp',
                                    'severity': 'high',
                                    'description': f"检测到 RDP 登录: {event_time.strftime('%Y-%m-%d %H:%M:%S')}",
                                    'details': msg[:200]
                                })
                win32evtlog.CloseEventLog(hand)
        except Exception as e:
            findings.append({
                'type': 'error',
                'severity': 'low',
                'description': f"RDP 日志检测失败: {str(e)}",
                'details': "可能需要管理员权限"
            })

    # === 3. WMI 检测 ===
    if check_wmi:
        try:
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-WMI-Activity/Operational")
            if hand:
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events_checked = 0
                max_events = 200

                while events_checked < max_events:
                    chunk = win32evtlog.ReadEventLog(hand, flags, 0, 50)
                    if not chunk:
                        break
                    for event in chunk:
                        events_checked += 1
                        if event.EventID in [5857, 5858, 5859, 5860, 5861]:
                            event_time = datetime.datetime.fromtimestamp(event.TimeGenerated.timestamp())
                            if event_time < after_time:
                                continue
                            msg = win32evtlogutil.SafeFormatMessage(event, "Microsoft-Windows-WMI-Activity/Operational")
                            findings.append({
                                'type': 'wmi',
                                'severity': 'high',
                                'description': f"检测到 WMI 活动 (Event ID {event.EventID}): {event_time.strftime('%Y-%m-%d %H:%M:%S')}",
                                'details': msg[:200] if msg else "无详细信息"
                            })
                win32evtlog.CloseEventLog(hand)
        except Exception:
            pass

    # === 4. SMB 共享访问检测 ===
    if check_smb:
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            if hand:
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events_checked = 0
                max_events = 300

                while events_checked < max_events:
                    chunk = win32evtlog.ReadEventLog(hand, flags, 0, 100)
                    if not chunk:
                        break
                    for event in chunk:
                        events_checked += 1
                        if event.EventID == 5140:  # 网络共享访问
                            event_time = datetime.datetime.fromtimestamp(event.TimeGenerated.timestamp())
                            if event_time < after_time:
                                continue
                            msg = win32evtlogutil.SafeFormatMessage(event, "Security")
                            if any(share in msg for share in ['\\C$', '\\ADMIN$', '\\IPC$']):
                                findings.append({
                                    'type': 'smb',
                                    'severity': 'medium',
                                    'description': f"检测到管理共享访问: {event_time.strftime('%Y-%m-%d %H:%M:%S')}",
                                    'details': msg[:200]
                                })
                win32evtlog.CloseEventLog(hand)
        except Exception:
            pass

    # === 生成报告 ===
    if not findings:
        return f"✅ 未检测到最近 {time_range_hours} 小时内的内网横向移动痕迹。"

    report = [f"🚨 检测到 {len(findings)} 个内网横向移动相关威胁指标（最近 {time_range_hours} 小时）:\n"]
    for idx, finding in enumerate(findings, 1):
        severity_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(finding['severity'], '⚪')
        report.append(f"{idx}. {severity_icon} [{finding['type'].upper()}] {finding['description']}")
        report.append(f"   {finding['details']}\n")

    return "\n".join(report)

# ==================== 3. 文件时间线分析 ====================

@mcp.tool()
def analyze_file_timeline(
    root_paths: Annotated[List[str], Field(description="扫描根目录列表")] = [r"C:\Users", r"C:\ProgramData"],
    time_range_hours: Annotated[int, Field(description="时间范围（小时）", ge=1, le=168)] = 24,
    file_types: Annotated[List[str], Field(description="文件扩展名列表")] = ['.exe', '.dll', '.ps1', '.bat', '.vbs'],
    min_size_bytes: Annotated[int, Field(description="最小文件大小（字节）", ge=0)] = 1024,
    max_results: Annotated[int, Field(description="最多返回结果数", ge=1, le=1000)] = 100
) -> str:
    """
    分析指定时间范围内的文件变更时间线：
    - 按修改时间排序
    - 过滤可疑文件类型
    - 标记异常路径
    - 计算文件哈希
    """
    if os.name != 'nt':
        return "该工具仅支持 Windows 系统。"

    cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=time_range_hours)
    cutoff_timestamp = cutoff_time.timestamp()
    results = []

    for root_path in root_paths:
        if not os.path.exists(root_path):
            continue

        for file_type in file_types:
            pattern = f"{root_path}\\**\\*{file_type}"
            for file_path in glob.glob(pattern, recursive=True):
                if len(results) >= max_results:
                    break

                try:
                    stat_info = os.stat(file_path)
                    if stat_info.st_mtime < cutoff_timestamp:
                        continue
                    if stat_info.st_size < min_size_bytes:
                        continue

                    file_hash = calculate_file_hash(file_path)
                    is_susp = is_suspicious_path(file_path)

                    results.append({
                        'path': file_path,
                        'modified': format_timestamp(stat_info.st_mtime),
                        'size': stat_info.st_size,
                        'hash': file_hash,
                        'suspicious': is_susp
                    })
                except (OSError, PermissionError):
                    continue

    # 按修改时间排序
    results.sort(key=lambda x: x['modified'], reverse=True)

    if not results:
        return f"✅ 未发现最近 {time_range_hours} 小时内修改的可疑文件。"

    report = [f"📁 文件时间线分析（最近 {time_range_hours} 小时，共 {len(results)} 个文件）:\n"]
    for idx, item in enumerate(results, 1):
        susp_flag = "🚨" if item['suspicious'] else "📄"
        report.append(f"{idx}. {susp_flag} {item['path']}")
        report.append(f"   修改时间: {item['modified']}, 大小: {item['size']} bytes")
        report.append(f"   SHA256: {item['hash']}\n")

    return "\n".join(report)

# ==================== 4. PowerShell 日志深度分析 ====================

@mcp.tool()
def analyze_powershell_logs_advanced(
    time_range_hours: Annotated[int, Field(description="时间范围（小时）", ge=1, le=168)] = 24,
    detect_obfuscation: Annotated[bool, Field(description="检测混淆技术")] = True,
    detect_download: Annotated[bool, Field(description="检测远程下载")] = True,
    detect_execution: Annotated[bool, Field(description="检测远程执行")] = True,
    max_events: Annotated[int, Field(description="最多返回事件数", ge=1, le=500)] = 100
) -> str:
    """
    深度分析 PowerShell 日志，检测：
    - Base64 编码命令
    - 远程下载（Invoke-WebRequest, downloadstring, iex）
    - 反射加载
    - 混淆技术
    - 远程执行
    """
    if os.name != 'nt':
        return "该工具仅支持 Windows 系统。"

    if not WIN32_AVAILABLE:
        return "需要安装 pywin32 模块才能分析 PowerShell 日志。"

    findings = []
    after_time = datetime.datetime.now() - datetime.timedelta(hours=time_range_hours)

    # 可疑模式
    obfuscation_patterns = [r'-enc\s', r'-e\s', r'-encodedcommand', r'\[char\]', r'"\+"']
    download_patterns = [r'downloadstring', r'downloadfile', r'invoke-webrequest', r'invoke-restmethod', r'iex\s*\(', r'invoke-expression']
    execution_patterns = [r'invoke-command', r'enter-pssession', r'invoke-mimikatz', r'invoke-shellcode']

    try:
        hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-PowerShell/Operational")
        if not hand:
            return "无法打开 PowerShell 日志（可能未启用或权限不足）。"

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events_checked = 0
        max_check = 1000

        while events_checked < max_check and len(findings) < max_events:
            chunk = win32evtlog.ReadEventLog(hand, flags, 0, 100)
            if not chunk:
                break

            for event in chunk:
                events_checked += 1
                if event.EventID != 4104:  # 脚本块日志
                    continue

                event_time = datetime.datetime.fromtimestamp(event.TimeGenerated.timestamp())
                if event_time < after_time:
                    continue

                msg = win32evtlogutil.SafeFormatMessage(event, "Microsoft-Windows-PowerShell/Operational")
                if not msg:
                    continue

                msg_lower = msg.lower()
                detected_patterns = []

                # 检测混淆
                if detect_obfuscation:
                    for pattern in obfuscation_patterns:
                        if re.search(pattern, msg_lower):
                            detected_patterns.append(f"混淆: {pattern}")

                # 检测下载
                if detect_download:
                    for pattern in download_patterns:
                        if re.search(pattern, msg_lower):
                            detected_patterns.append(f"下载: {pattern}")

                # 检测执行
                if detect_execution:
                    for pattern in execution_patterns:
                        if re.search(pattern, msg_lower):
                            detected_patterns.append(f"执行: {pattern}")

                if detected_patterns:
                    findings.append({
                        'time': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'patterns': detected_patterns,
                        'snippet': msg[:300]
                    })

        win32evtlog.CloseEventLog(hand)

    except Exception as e:
        return f"PowerShell 日志分析失败: {str(e)}"

    if not findings:
        return f"✅ 未检测到最近 {time_range_hours} 小时内的可疑 PowerShell 活动。"

    report = [f"🔍 检测到 {len(findings)} 个可疑 PowerShell 活动（最近 {time_range_hours} 小时）:\n"]
    for idx, finding in enumerate(findings, 1):
        report.append(f"{idx}. 时间: {finding['time']}")
        report.append(f"   检测到: {', '.join(finding['patterns'])}")
        report.append(f"   脚本片段: {finding['snippet']}...\n")

    return "\n".join(report)

# ==================== 5. 网络扫描痕迹检测 ====================

@mcp.tool()
def detect_network_scanning(
    check_arp_cache: Annotated[bool, Field(description="检测 ARP 缓存异常")] = True,
    check_dns_cache: Annotated[bool, Field(description="检测 DNS 缓存异常")] = True,
    check_netstat: Annotated[bool, Field(description="检测网络连接异常")] = True,
    detect_port_scan: Annotated[bool, Field(description="检测端口扫描特征")] = True
) -> str:
    """
    检测内网扫描痕迹：
    - ARP 缓存异常（大量 ARP 条目）
    - DNS 缓存异常（内网 IP 反查）
    - 网络连接异常（大量 SYN_SENT 状态）
    - 端口扫描特征（短时间内连接多个端口）
    """
    if os.name != 'nt':
        return "该工具仅支持 Windows 系统。"

    findings = []

    # === 1. ARP 缓存检测 ===
    if check_arp_cache:
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                arp_lines = [line for line in result.stdout.splitlines() if 'dynamic' in line.lower() or '动态' in line.lower()]
                if len(arp_lines) > 100:
                    findings.append({
                        'type': 'arp',
                        'severity': 'medium',
                        'description': f"检测到大量 ARP 缓存条目: {len(arp_lines)} 个",
                        'details': "可能存在内网扫描行为"
                    })
        except Exception:
            pass

    # === 2. DNS 缓存检测 ===
    if check_dns_cache:
        try:
            result = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True, timeout=10, encoding='gbk', errors='ignore')
            if result.returncode == 0:
                dns_entries = result.stdout.count('Record Name')
                if dns_entries > 200:
                    findings.append({
                        'type': 'dns',
                        'severity': 'low',
                        'description': f"检测到大量 DNS 缓存条目: {dns_entries} 个",
                        'details': "可能存在域名扫描或侦察行为"
                    })
        except Exception:
            pass

    # === 3. 网络连接状态检测 ===
    if check_netstat:
        try:
            syn_sent_count = 0
            established_count = 0
            unique_remote_ips = set()

            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'SYN_SENT':
                    syn_sent_count += 1
                elif conn.status == 'ESTABLISHED':
                    established_count += 1
                if conn.raddr:
                    unique_remote_ips.add(conn.raddr.ip)

            if syn_sent_count > 50:
                findings.append({
                    'type': 'netstat',
                    'severity': 'high',
                    'description': f"检测到大量 SYN_SENT 状态连接: {syn_sent_count} 个",
                    'details': "可能正在进行端口扫描"
                })

            if len(unique_remote_ips) > 100:
                findings.append({
                    'type': 'netstat',
                    'severity': 'medium',
                    'description': f"检测到连接到大量不同 IP: {len(unique_remote_ips)} 个",
                    'details': "可能存在网络扫描或横向移动"
                })
        except Exception:
            pass

    # === 4. 端口扫描特征检测 ===
    if detect_port_scan:
        try:
            port_connections = defaultdict(list)
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    port_connections[conn.raddr.ip].append(conn.raddr.port)

            for ip, ports in port_connections.items():
                if len(set(ports)) > 20:  # 连接到同一 IP 的 20 个以上不同端口
                    findings.append({
                        'type': 'portscan',
                        'severity': 'high',
                        'description': f"检测到对 {ip} 的端口扫描行为",
                        'details': f"连接到 {len(set(ports))} 个不同端口"
                    })
        except Exception:
            pass

    # === 生成报告 ===
    if not findings:
        return "✅ 未检测到网络扫描痕迹。"

    report = [f"🌐 检测到 {len(findings)} 个网络扫描相关威胁指标:\n"]
    for idx, finding in enumerate(findings, 1):
        severity_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(finding['severity'], '⚪')
        report.append(f"{idx}. {severity_icon} [{finding['type'].upper()}] {finding['description']}")
        report.append(f"   {finding['details']}\n")

    return "\n".join(report)

# ==================== 6. 综合应急响应报告生成 ====================

@mcp.tool()
def generate_incident_response_report(
    incident_type: Annotated[str, Field(description="事件类型: silverfox 或 lateral_movement")] = "silverfox",
    output_format: Annotated[str, Field(description="输出格式: markdown 或 json")] = "markdown",
    include_remediation: Annotated[bool, Field(description="是否包含修复建议")] = True,
    save_to_file: Annotated[bool, Field(description="是否保存到文件")] = False
) -> str:
    """
    生成综合应急响应报告：
    - 执行所有检测模块
    - 汇总发现的威胁指标
    - 按严重程度排序
    - 提供修复建议
    - 生成时间线视图
    """
    if os.name != 'nt':
        return "该工具仅支持 Windows 系统。"

    report_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    all_findings = []

    # === 执行检测模块 ===
    if incident_type == "silverfox":
        # 银狐木马检测
        silverfox_result = detect_silverfox_indicators()
        all_findings.append(("银狐木马检测", silverfox_result))

        # 文件时间线分析
        timeline_result = analyze_file_timeline()
        all_findings.append(("文件时间线分析", timeline_result))

        # PowerShell 日志分析
        ps_result = analyze_powershell_logs_advanced()
        all_findings.append(("PowerShell 日志分析", ps_result))

    elif incident_type == "lateral_movement":
        # 内网横向移动检测
        lateral_result = detect_lateral_movement()
        all_findings.append(("内网横向移动检测", lateral_result))

        # 网络扫描检测
        scan_result = detect_network_scanning()
        all_findings.append(("网络扫描检测", scan_result))

        # PowerShell 日志分析
        ps_result = analyze_powershell_logs_advanced()
        all_findings.append(("PowerShell 日志分析", ps_result))

    # === 生成 Markdown 报告 ===
    if output_format == "markdown":
        report_lines = [
            f"# 应急响应报告 - {incident_type.upper()}",
            f"\n## 执行摘要",
            f"- 检测时间: {report_time}",
            f"- 事件类型: {incident_type}",
            f"- 检测模块数: {len(all_findings)}",
            f"\n## 检测结果\n"
        ]

        for module_name, result in all_findings:
            report_lines.append(f"### {module_name}\n")
            report_lines.append(result)
            report_lines.append("\n---\n")

        if include_remediation:
            report_lines.append("\n## 修复建议\n")
            if incident_type == "silverfox":
                report_lines.append("1. 立即隔离受感染主机，断开网络连接")
                report_lines.append("2. 终止所有可疑进程（参考上述检测结果）")
                report_lines.append("3. 删除恶意文件并清理持久化机制（注册表、计划任务、服务）")
                report_lines.append("4. 使用杀毒软件进行全盘扫描")
                report_lines.append("5. 重置所有受影响账户的密码")
                report_lines.append("6. 检查其他主机是否被横向移动")
                report_lines.append("7. 加固系统安全配置，启用 PowerShell 日志记录")
                report_lines.append("8. 部署 EDR/XDR 解决方案进行持续监控")
            elif incident_type == "lateral_movement":
                report_lines.append("1. 立即隔离受影响主机，阻断横向移动路径")
                report_lines.append("2. 禁用或限制 WMI、PSExec、RDP 等远程管理工具")
                report_lines.append("3. 审计所有管理员账户，重置密码并启用 MFA")
                report_lines.append("4. 检查并清理所有可疑服务和计划任务")
                report_lines.append("5. 启用 Windows 防火墙，限制 SMB 和 RDP 访问")
                report_lines.append("6. 部署网络分段，限制横向移动范围")
                report_lines.append("7. 启用高级审计策略，记录所有登录和特权使用事件")
                report_lines.append("8. 定期审计域控制器和关键服务器的安全日志")

        report_content = "\n".join(report_lines)

        if save_to_file:
            output_dir = CONFIG.get('report_config', {}).get('output_dir', r'C:\incident_reports')
            os.makedirs(output_dir, exist_ok=True)
            filename = f"{incident_type}_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return f"✅ 报告已保存到: {filepath}\n\n{report_content}"

        return report_content

    # === 生成 JSON 报告 ===
    elif output_format == "json":
        report_data = {
            'report_time': report_time,
            'incident_type': incident_type,
            'findings': [{'module': name, 'result': result} for name, result in all_findings]
        }
        return json.dumps(report_data, ensure_ascii=False, indent=2)

    return "不支持的输出格式。"

# ==================== 启动服务 ====================
if __name__ == "__main__":
    mcp.run()
