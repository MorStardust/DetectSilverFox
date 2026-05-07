import os
import psutil
import hashlib
import json
import datetime
import subprocess
import winreg
import glob
import ctypes
from typing import Optional, Annotated, List
from pydantic import Field
from mcp.server.fastmcp import FastMCP
import requests
import base64
from win32evtlog import *
from win32evtlogutil import SafeFormatMessage
import win32con
import win32api
import win32security
import hashlib
import pefile
import requests
from pathlib import Path

# 初始化增强版 MCP 服务
mcp = FastMCP("Forensic-Master-Suite-Pro")


# --- 1. 深度进程与反隐藏模块 ---
@mcp.tool()
def analyze_processes(
        pid: Annotated[Optional[int], Field(description="指定PID进行深入分析")] = None,
        name_filter: Annotated[Optional[str], Field(description="过滤进程名关键词")] = None,
        check_dlls: bool = False,
        show_network: bool = True
) -> str:
    results = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'create_time']):
        try:
            pinfo = proc.info
            if pid and pinfo['pid'] != pid: continue
            if name_filter and name_filter.lower() not in pinfo['name'].lower(): continue

            ctime = datetime.datetime.fromtimestamp(pinfo['create_time']).isoformat()
            detail = f"\n[Process: {pinfo['name']} (PID: {pinfo['pid']})]\nPath: {pinfo['exe']}\nUser: {pinfo['username']}\nStarted: {ctime}"

            if check_dlls:
                modules = [m.path for m in proc.memory_maps() if m.path and m.path.endswith('.dll')]
                detail += f"\nModules: {', '.join(modules[:5])} (Total: {len(modules)})"

            if show_network:
                conns = [f"{c.raddr.ip}:{c.raddr.port}({c.status})" for c in proc.connections() if c.raddr]
                detail += f"\nNetwork: {', '.join(conns) if conns else 'No active remote connections'}"

            results.append(detail)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return "\n---\n".join(results) if results else "未找到匹配进程。"


@mcp.tool()
def hunt_hidden_processes_pure_python() -> str:
    """
    纯 Python 检测 Windows 隐藏进程（无需 handle.exe / pslist.exe）
    - 使用 ctypes 直接调用 Windows API
    - 比对 psutil 与底层 API 结果
    - 检测进程树断裂和异常特征
    """
    # === Windows API 常量 ===
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    MAX_PATH = 260

    # 加载 kernel32.dll
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    # === 1. 获取 psutil 可见的 PID ===
    try:
        psutil_pids = set(psutil.pids())
    except Exception as e:
        return f"❌ psutil 初始化失败: {e}"

    # === 2. 尝试枚举所有可能 PID（1～65535）===
    # 注意：Windows PID 默认是 4 的倍数，但也可配置为随机
    candidate_pids = set()
    hidden_candidates = []

    # 先快速扫描活跃 PID 范围（避免全扫 65535）
    max_pid = 65536
    if hasattr(psutil, 'boot_time'):
        # 启发式：最大 PID 不太可能超过当前最大值太多
        max_observed = max(psutil_pids) if psutil_pids else 4096
        max_pid = min(max_pid, max_observed + 2048)

    for pid in range(4, max_pid, 4):  # Windows PID 通常是 4 的倍数
        if pid < 4 or pid == 0:
            continue

        h_process = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            pid
        )
        if h_process:
            try:
                # 尝试获取进程路径（验证是否真实存在）
                image_name = ctypes.create_unicode_buffer(MAX_PATH)
                size = wintypes.DWORD(MAX_PATH)
                success = ctypes.windll.kernel32.QueryFullProcessImageNameW(
                    h_process, 0, image_name, ctypes.byref(size)
                )
                if success and image_name.value:
                    candidate_pids.add(pid)
                    # 如果 psutil 看不到，但 API 能打开 → 可疑！
                    if pid not in psutil_pids:
                        hidden_candidates.append(pid)
            finally:
                kernel32.CloseHandle(h_process)

    # === 3. 检查进程树断裂（PPID 不存在）===
    orphaned_procs = []
    for proc in psutil.process_iter(['pid', 'ppid']):
        try:
            ppid = proc.info['ppid']
            if ppid and ppid not in psutil_pids and ppid != 0:
                orphaned_procs.append(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # === 4. 构建结果 ===
    results = []

    if hidden_candidates:
        results.append(
            "🚨 发现疑似隐藏进程（Windows API 可访问，但 psutil 不可见）:\n"
            f"PID: {', '.join(map(str, sorted(hidden_candidates)[:10]))}\n"
            "⚠️ 注意：此方法无法检测内核级 DKOM 隐藏，但可发现用户态 Hook 绕过。"
        )
    else:
        results.append("✅ 未发现 API 层面的隐藏进程迹象。")

    if orphaned_procs:
        results.append(
            f"🔍 发现 {len(orphaned_procs)} 个孤儿进程（父进程已退出）:\n"
            f"PID: {', '.join(map(str, orphaned_procs[:10]))}"
        )

    # === 5. 补充：可疑进程行为扫描 ===
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'] or ''
            exe = proc.info['exe'] or ''
            cmdline = ' '.join(proc.info['cmdline'] or [])

            # 特征1: 无有效 exe 路径（反射加载）
            if not exe or not os.path.exists(exe):
                suspicious.append(f"{pid} ({name}) - 无有效可执行文件")
            # 特征2: 伪装系统进程
            elif 'svchost' in name.lower() and '0' in name:
                suspicious.append(f"{pid} ({name}) - 可疑名称仿冒")
            # 特征3: PowerShell 混淆
            elif 'powershell' in name.lower() and any(kw in cmdline for kw in ['-enc', 'iex', 'downloadstring']):
                suspicious.append(f"{pid} - 可疑 PowerShell 行为")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if suspicious:
        results.append("⚠️ 发现可疑进程行为:\n" + "\n".join(suspicious[:5]))

    return "\n\n".join(results)


# --- 2. 网络通信管理与深度分析 ---
@mcp.tool()
def get_full_network_status() -> str:
    try:
        connections = psutil.net_connections(kind='inet')
        res = ["PID | 进程名 | 本地地址 | 远程地址 | 状态"]
        for conn in connections:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "LISTENING"
            try:
                p_name = psutil.Process(conn.pid).name() if conn.pid else "N/A"
            except:
                p_name = "Unknown"
            res.append(f"{conn.pid} | {p_name} | {laddr} | {raddr} | {conn.status}")
        return "\n".join(res)
    except Exception as e:
        return f"获取失败: {str(e)}"


@mcp.tool()
def audit_dns_cache() -> str:
    if os.name == 'nt':
        try:
            return subprocess.check_output("ipconfig /displaydns", shell=True).decode('gbk', errors='ignore')[:2000]
        except:
            return "无法读取DNS缓存。"
    return "该功能目前仅支持Windows。"


@mcp.tool()
def manage_firewall_block(ip: str, action: str = "add") -> str:
    if os.name != 'nt': return "仅支持Windows防火墙管理。"
    rule_name = f"MCP_BLOCK_{ip}"
    try:
        if action == "add":
            cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=out action=block remoteip={ip}"
        else:
            cmd = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
        subprocess.check_call(cmd, shell=True)
        return f"成功：已对 IP {ip} 执行 {action} 规则。"
    except Exception as e:
        return f"操作失败（请检查管理员权限）: {str(e)}"


# --- 3. 内存与持久化排查 ---
@mcp.tool()
def scan_memory_injection(pid: int) -> str:
    try:
        proc = psutil.Process(pid)
        suspicious = [f"地址: {m.addr} | 权限: {m.perms} | 路径: {m.path or 'In-Memory'}"
                      for m in proc.memory_maps() if not m.path or m.path.startswith("[")]
        return f"PID {pid} 发现可疑区域：\n" + "\n".join(suspicious) if suspicious else "未发现异常。"
    except Exception as e:
        return f"分析失败: {str(e)}"


# ==================== 辅助函数 ====================
def _scan_registry_key(hive, key_path):
    items = []
    try:
        with winreg.OpenKey(hive, key_path) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    items.append(f"{key_path} -> {name} = {value}")
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return items


# ==================== 持久化检测模块 ====================

@mcp.tool()
def check_persistence_registry() -> str:
    findings = []
    reg_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
    ]
    for path in reg_paths:
        findings.extend(_scan_registry_key(winreg.HKEY_CURRENT_USER, path))
        findings.extend(_scan_registry_key(winreg.HKEY_LOCAL_MACHINE, path))

    # ScreenSaver
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop") as k:
            screensaver = winreg.QueryValueEx(k, "SCRNSAVE.EXE")[0]
            if screensaver and os.path.exists(screensaver):
                findings.append(r"Control Panel\Desktop -> SCRNSAVE.EXE = " + screensaver)
    except:
        pass

    return "\n".join(findings) if findings else "未在注册表中发现可疑持久化项。"


@mcp.tool()
def check_persistence_scheduled_tasks() -> str:
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return "无法查询计划任务（可能需要管理员权限）。"

        lines = result.stdout.strip().splitlines()
        if len(lines) < 2:
            return "无计划任务。"

        suspicious = []
        for line in lines[1:]:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 8:
                continue
            task_name = parts[0]
            author = parts[6]
            path = parts[7] if len(parts) > 7 else ""
            if "Microsoft" not in author and "Windows" not in author and path:
                suspicious.append(f"{task_name} | 作者: {author} | 路径: {path}")

        return "\n".join(suspicious) if suspicious else "未发现可疑计划任务。"
    except Exception as e:
        return f"计划任务扫描失败: {e}"


@mcp.tool()
def check_persistence_services() -> str:
    suspicious = []
    try:
        services = [s for s in psutil.win_service_iter()]
        for svc in services:
            try:
                config = svc.as_dict()
                bin_path = config.get('binpath', '')
                display_name = config.get('display_name', '')
                if bin_path and 'system32' not in bin_path.lower():
                    suspicious.append(f"{svc.name()} | {display_name} | {bin_path}")
            except:
                continue
    except Exception as e:
        return f"服务扫描失败（需 Windows）: {e}"

    return "\n".join(suspicious) if suspicious else "未发现可疑服务。"


@mcp.tool()
def check_persistence_startup_folders() -> str:
    startup_paths = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    ]
    suspicious = []
    for folder in startup_paths:
        if os.path.exists(folder):
            for item in glob.glob(os.path.join(folder, "*")):
                if item.endswith(('.exe', '.bat', '.cmd', '.lnk', '.ps1', '.vbs')):
                    suspicious.append(item)
    return "\n".join(suspicious) if suspicious else "启动文件夹中未发现可疑文件。"


@mcp.tool()
def check_persistence_wmi() -> str:
    if os.name != 'nt':
        return "仅支持 Windows。"
    try:
        filters = subprocess.check_output(
            ["powershell", "-Command", "Get-WmiObject -Namespace root\\Subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select Name, Query | ConvertTo-Json -Compress"],
            shell=True, text=True, timeout=10
        ).strip()
        if not filters or "[]" in filters:
            return "未发现 WMI 事件过滤器。"
        else:
            return "发现 WMI 事件订阅（可能用于持久化）:\n" + filters
    except:
        return "WMI 检测失败（可能无 PowerShell 或权限不足）。"


# =============== 新增：高阶持久化检测 ===============

@mcp.tool()
def check_persistence_ifeo_debugger() -> str:
    """检测 IFEO 调试器劫持（Image File Execution Options Debugger）"""
    suspicious = []
    try:
        base_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as root:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(root, i)
                    subkey_path = f"{base_key}\\{subkey_name}"
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path) as sk:
                            debugger, _ = winreg.QueryValueEx(sk, "Debugger")
                            if debugger:
                                suspicious.append(f"{subkey_name} -> Debugger = {debugger}")
                    except FileNotFoundError:
                        pass
                    i += 1
                except OSError:
                    break
    except Exception as e:
        return f"IFEO 扫描失败: {e}"
    return "\n".join(suspicious) if suspicious else "未发现 IFEO 调试器劫持。"


@mcp.tool()
def check_persistence_bits_jobs() -> str:
    """检测 BITS 后台传输任务（常用于隐蔽下载/回连）"""
    if os.name != 'nt':
        return "仅支持 Windows。"
    try:
        output = subprocess.check_output(
            ["bitsadmin", "/list", "/allusers", "/verbose"],
            shell=True, text=True, stderr=subprocess.STDOUT
        )
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        # 排除空或仅标题行
        if len(lines) <= 2:
            return "无 BITS 任务。"
        # 返回非空任务列表（跳过 header）
        tasks = [line for line in lines if "JOB ID" not in line and "--" not in line and line]
        return "\n".join(tasks) if tasks else "无活跃 BITS 任务。"
    except subprocess.CalledProcessError as e:
        if "no jobs" in e.output.lower():
            return "无 BITS 任务。"
        return "BITS 检测失败（可能需要管理员权限）。"
    except Exception as e:
        return f"无法执行 bitsadmin: {e}"


@mcp.tool()
def check_persistence_com_hijack() -> str:
    """检测 HKCU 下的 COM 劫持（常用于 Office 持久化）"""
    suspicious = []
    try:
        base_key = r"Software\Classes\CLSID"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_key) as root:
            i = 0
            while True:
                try:
                    clsid = winreg.EnumKey(root, i)
                    inproc_path = f"{base_key}\\{clsid}\\InprocServer32"
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, inproc_path) as k:
                            dll_path, _ = winreg.QueryValueEx(k, "")
                            if dll_path and os.path.exists(dll_path):
                                suspicious.append(f"COM 劫持: {clsid} -> {dll_path}")
                    except FileNotFoundError:
                        pass
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        return "HKCU\\Software\\Classes 不存在（无 COM 劫持）。"
    except Exception as e:
        return f"COM 劫持扫描失败: {e}"
    return "\n".join(suspicious) if suspicious else "未发现 COM 劫持。"


@mcp.tool()
def check_persistence_appinit_dlls() -> str:
    """检测 AppInit_DLLs 和 AppCertDlls（全局 DLL 注入）"""
    findings = []
    try:
        # AppInit_DLLs
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows") as k:
            appinit, _ = winreg.QueryValueEx(k, "AppInit_DLLs")
            load_order, _ = winreg.QueryValueEx(k, "LoadAppInit_DLLs")
            if appinit.strip() and str(load_order) == "1":
                findings.append(f"AppInit_DLLs 已启用: {appinit}")
    except:
        pass

    try:
        # AppCertDlls
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager") as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                    if name.lower().startswith("appcertdlls"):
                        findings.append(f"AppCertDlls 条目: {name} = {value}")
                    i += 1
                except OSError:
                    break
    except:
        pass

    return "\n".join(findings) if findings else "未发现 AppInit/AppCert DLL 劫持。"


@mcp.tool()
def check_persistence_office_addins() -> str:
    """检测 Office 加载项（VSTO、COM Add-ins）"""
    addin_paths = [
        os.path.expandvars(r"%APPDATA%\Microsoft\AddIns"),
        os.path.expandvars(r"%APPDATA%\Microsoft\Excel\XLSTART"),
        os.path.expandvars(r"%APPDATA%\Microsoft\Word\STARTUP"),
    ]
    suspicious = []
    for path in addin_paths:
        if os.path.exists(path):
            for ext in ('*.xlam', '*.xla', '*.ppam', '*.ppa', '*.dotm', '*.dot', '*.dll', '*.exe'):
                for f in glob.glob(os.path.join(path, ext)):
                    suspicious.append(f)
    return "\n".join(suspicious) if suspicious else "未发现可疑 Office 加载项。"


# =============== 综合调用 ===============
@mcp.tool()
def check_persistence_all() -> str:
    report = []
    report.append("🔍 注册表持久化:")
    report.append(check_persistence_registry())
    report.append("\n📅 计划任务:")
    report.append(check_persistence_scheduled_tasks())
    report.append("\n⚙️ 服务:")
    report.append(check_persistence_services())
    report.append("\n📂 启动文件夹:")
    report.append(check_persistence_startup_folders())
    report.append("\n📡 WMI 事件订阅:")
    report.append(check_persistence_wmi())
    report.append("\n🧪 IFEO 调试器劫持:")
    report.append(check_persistence_ifeo_debugger())
    report.append("\n📤 BITS Jobs:")
    report.append(check_persistence_bits_jobs())
    report.append("\n🧩 COM 劫持:")
    report.append(check_persistence_com_hijack())
    report.append("\n💉 AppInit/AppCert DLLs:")
    report.append(check_persistence_appinit_dlls())
    report.append("\n📊 Office 加载项:")
    report.append(check_persistence_office_addins())
    return "\n" + "\n".join(report)


# --- 4. 文件取证与实时处置 ---
@mcp.tool()
def get_file_metadata(file_path: str) -> str:
    if not os.path.exists(file_path): return "文件不存在。"
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""): sha256.update(chunk)
    stat = os.stat(file_path)
    return json.dumps({"path": file_path, "sha256": sha256.hexdigest(), "size": stat.st_size,
                       "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat()}, indent=2)


@mcp.tool()
def kill_and_quarantine(pid: int) -> str:
    try:
        p = psutil.Process(pid)
        path = p.exe()
        p.kill()
        if path and os.path.exists(path):
            quarantine_path = path + ".quarantine"
            os.rename(path, quarantine_path)
            return f"成功：PID {pid} 已结束，文件已隔离至 {quarantine_path}"
        return f"PID {pid} 已结束，但未找到磁盘文件。"
    except Exception as e:
        return f"处置失败: {str(e)}"

@mcp.tool()
def audit_powershell_activity(
    check_logging_status: Annotated[bool, Field(description="是否检查 PowerShell 日志功能是否被禁用")] = True,
    max_events: Annotated[int, Field(description="最多返回的日志条数", ge=1, le=1000)] = 50
) -> str:
    """
    审计 PowerShell 执行活动，包括脚本块日志、模块日志等。
    需要 Windows 且启用 PowerShell 日志（默认 Win10/Server 2016+ 开启 Script Block Logging）。
    """
    if os.name != 'nt':
        return "仅支持 Windows 系统。"

    findings = []

    # --- 检查日志配置是否被篡改 ---
    if check_logging_status:
        try:
            reg_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                enabled, _ = winreg.QueryValueEx(key, "EnableScriptBlockLogging")
                if not enabled:
                    findings.append("[!] 警告：PowerShell ScriptBlockLogging 已被禁用！")
        except FileNotFoundError:
            findings.append("[?] 未配置组策略，使用默认日志状态。")
        except Exception as e:
            findings.append(f"[!] 无法检查日志策略: {e}")

    # --- 读取 PowerShell Operational 日志 ---
    try:
        hand = OpenEventLog(None, "Microsoft-Windows-PowerShell/Operational")
        if not hand:
            return "未找到 PowerShell 日志（可能未启用或权限不足）。"

        events = []
        flags = EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ
        while len(events) < max_events:
            chunk = ReadEventLog(hand, flags, 0, 8192)
            if not chunk:
                break
            for event in chunk:
                if event.EventID in (4104, 4103):  # Script block / Module logging
                    msg = SafeFormatMessage(event, "Microsoft-Windows-PowerShell/Operational")
                    if msg:
                        # 提取关键信息：时间、用户、脚本内容片段
                        time_str = event.TimeGenerated.Format()
                        user = event.UserSid
                        if user:
                            try:
                                user_name = win32security.LookupAccountSid(None, user)[0]
                            except:
                                user_name = str(user)
                        else:
                            user_name = "SYSTEM"
                        snippet = msg[:200].replace('\n', ' ').replace('\r', '')
                        events.append(f"[{time_str}] User: {user_name} | {snippet}...")
            if len(events) >= max_events:
                break

        CloseEventLog(hand)
        findings.append(f"\n🔍 发现 {len(events)} 条 PowerShell 执行记录（最近 {max_events} 条内）:")
        findings.extend(events[:max_events])
    except Exception as e:
        findings.append(f"[!] 读取 PowerShell 日志失败: {e}")

    return "\n".join(findings) if findings else "未发现 PowerShell 执行活动。"


@mcp.tool()
def check_lsass_access(
    suspicious_permissions: Annotated[List[str], Field(description="可疑的访问权限掩码", example=["PROCESS_VM_READ", "PROCESS_DUP_HANDLE"])] = ["PROCESS_VM_READ"]
) -> str:
    """
    检测是否有非系统进程以可疑权限（如 PROCESS_VM_READ）打开 lsass.exe。
    这是 Mimikatz、Procdump 等凭证窃取工具的典型行为。
    """
    if os.name != 'nt':
        return "仅支持 Windows 系统。"

    try:
        # 获取 lsass PID
        lsass_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == 'lsass.exe':
                lsass_pid = proc.info['pid']
                break
        if not lsass_pid:
            return "未找到 lsass.exe 进程。"

        # 获取所有句柄（需要 SeDebugPrivilege，通常需管理员）
        import ctypes
        from ctypes import wintypes

        # 启用调试权限（关键！）
        def enable_debug_privilege():
            """提升至 SeDebugPrivilege，否则无法查询其他进程句柄"""
            try:
                token = ctypes.c_void_p()
                if ctypes.windll.advapi32.OpenProcessToken(
                    ctypes.windll.kernel32.GetCurrentProcess(),
                    win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
                    ctypes.byref(token)
                ):
                    luid = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
                    new_state = (luid, win32con.SE_PRIVILEGE_ENABLED)
                    ctypes.windll.advapi32.AdjustTokenPrivileges(token, False, new_state, 0, None, None)
                    ctypes.windll.kernel32.CloseHandle(token)
                return True
            except:
                return False

        if not enable_debug_privilege():
            return "警告：无法启用调试权限，LSASS 检查可能不完整（建议以管理员运行）。"

        # 枚举所有进程的句柄
        suspicious_procs = []
        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.info['pid']
            if pid == lsass_pid or pid == os.getpid():
                continue
            try:
                h_process = ctypes.windll.kernel32.OpenProcess(
                    win32con.PROCESS_DUP_HANDLE, False, pid
                )
                if not h_process:
                    continue

                # 尝试复制 lsass 句柄（模拟攻击行为检测）
                h_lsass_dup = ctypes.c_void_p()
                if ctypes.windll.kernel32.DuplicateHandle(
                    h_process, ctypes.c_void_p(lsass_pid),
                    ctypes.windll.kernel32.GetCurrentProcess(),
                    ctypes.byref(h_lsass_dup),
                    0, False, 2  # DUPLICATE_SAME_ACCESS
                ):
                    if h_lsass_dup.value:
                        # 成功复制 → 极可疑！
                        suspicious_procs.append(f"PID {pid} ({proc.info['name']}) 复制了 LSASS 句柄！")
                    ctypes.windll.kernel32.CloseHandle(h_lsass_dup)
                ctypes.windll.kernel32.CloseHandle(h_process)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        if suspicious_procs:
            return "[!] 发现可疑 LSASS 访问行为（可能正在窃取凭证）:\n" + "\n".join(suspicious_procs)
        else:
            return "未发现可疑进程访问 LSASS。"
    except Exception as e:
        return f"LSASS 检查失败: {e}"

@mcp.tool()
def upload_file_to_remote(
    file_path: Annotated[str, Field(description="本地文件绝对路径")],
    remote_url: Annotated[str, Field(description="远程接收 URL（如 http://your-sandbox/upload）")],
    auth_token: Annotated[Optional[str], Field(description="Bearer Token 用于认证", example="secret123")] = None,
    timeout: Annotated[int, Field(description="上传超时（秒）", ge=5, le=300)] = 60
) -> str:
    """
    将本地文件以 multipart/form-data 形式上传到远程分析平台。
    支持认证，适用于上传恶意样本到沙箱/VirusTotal/内部系统。
    """
    if not os.path.exists(file_path):
        return "错误：本地文件不存在。"

    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            headers = {}
            if auth_token:
                headers["Authorization"] = f"Bearer {auth_token}"

            resp = requests.post(
                remote_url,
                files=files,
                headers=headers,
                timeout=timeout,
                verify=False  # 生产环境应设为 True 并配证书
            )
            if resp.status_code in (200, 201, 202):
                return f"✅ 上传成功！响应: {resp.text[:200]}"
            else:
                return f"❌ 上传失败（HTTP {resp.status_code}）: {resp.text[:200]}"
    except Exception as e:

        @mcp.tool()
        def analyze_process_modules(
                pid: Annotated[int, Field(description="目标进程 PID")],
                check_disk_mismatch: Annotated[bool, Field(description="是否比对磁盘文件哈希")] = True,
                detect_reflective_loading: Annotated[bool, Field(description="是否尝试检测反射式加载（启发式）")] = True
        ) -> str:
            """
            深度分析进程加载的模块（DLL/EXE），识别可疑行为：
            - 内存中存在但磁盘无对应文件（反射加载）
            - 磁盘文件哈希与内存不一致（DLL 劫持/补丁）
            - 非标准路径加载（如 AppData、Temp）
            """
            if os.name != 'nt':
                return "仅支持 Windows 系统。"

            try:
                import ctypes
                from ctypes import wintypes

                # 获取进程句柄（需 SeDebugPrivilege）
                def enable_debug_privilege():
                    try:
                        token = ctypes.c_void_p()
                        if ctypes.windll.advapi32.OpenProcessToken(
                                ctypes.windll.kernel32.GetCurrentProcess(),
                                0x0020 | 0x0008,  # TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
                                ctypes.byref(token)
                        ):
                            luid = ctypes.c_longlong()
                            ctypes.windll.advapi32.LookupPrivilegeValueA(None, b"SeDebugPrivilege", ctypes.byref(luid))
                            new_state = (luid.value, 0x00000002)  # SE_PRIVILEGE_ENABLED

                            class TokPriv1Luid(ctypes.Structure):
                                _fields_ = [("Luid", ctypes.c_longlong), ("Attributes", ctypes.c_ulong)]

                            tp = TokPriv1Luid()
                            tp.Luid = luid.value
                            tp.Attributes = 0x00000002
                            ctypes.windll.advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
                            ctypes.windll.kernel32.CloseHandle(token)
                        return True
                    except:
                        return False

                if not enable_debug_privilege():
                    return "警告：无法启用调试权限，部分分析可能受限（建议以管理员运行）。"

                # 获取进程完整模块列表（使用 PSAPI）
                h_process = ctypes.windll.kernel32.OpenProcess(0x0400 | 0x0010, False,
                                                               pid)  # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
                if not h_process:
                    return f"无法打开进程 {pid}（可能已退出或权限不足）。"

                modules = []
                module_handles = (ctypes.c_void_p * 1024)()
                cb_needed = ctypes.c_ulong()
                if ctypes.windll.psapi.EnumProcessModules(
                        h_process, ctypes.byref(module_handles), ctypes.sizeof(module_handles), ctypes.byref(cb_needed)
                ):
                    num_modules = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
                    for i in range(min(num_modules, 512)):
                        h_mod = module_handles[i]
                        mod_name = ctypes.create_unicode_buffer(1024)
                        ctypes.windll.psapi.GetModuleFileNameExW(h_process, h_mod, mod_name, 1024)
                        full_path = mod_name.value

                        # 获取模块基址和大小
                        mod_info = ctypes.c_ulonglong()
                        ctypes.windll.psapi.GetModuleInformation(h_process, h_mod, ctypes.byref(mod_info),
                                                                 ctypes.sizeof(mod_info))
                        base_addr = mod_info.value & 0xFFFFFFFFFFFF
                        size = (mod_info.value >> 48) & 0xFFFF

                        modules.append({
                            'path': full_path,
                            'base': hex(base_addr),
                            'size': size
                        })

                ctypes.windll.kernel32.CloseHandle(h_process)

                findings = [f"🔍 分析进程 PID {pid}，共加载 {len(modules)} 个模块:"]
                suspicious = []

                for mod in modules:
                    path = mod['path']
                    is_suspicious = False
                    reasons = []

                    # --- 检查路径是否可疑 ---
                    low_path = path.lower()
                    if any(kw in low_path for kw in
                           ['\\appdata\\', '\\temp\\', '\\users\\public\\', '\\windows\\temp\\']):
                        reasons.append("位于临时/用户目录")
                        is_suspicious = True

                    # --- 检查是否在磁盘存在 ---
                    if not path or not Path(path).exists():
                        reasons.append("磁盘文件不存在（可能为反射加载）")
                        is_suspicious = True
                        if not path:
                            path = "[unnamed memory module]"
                    else:
                        # --- 比对哈希（可选）---
                        if check_disk_mismatch:
                            try:
                                with open(path, 'rb') as f:
                                    disk_hash = hashlib.sha256(f.read()).hexdigest()[:8]
                                # 注意：无法直接读取内存模块内容（需 ReadProcessMemory），此处跳过内存哈希比对
                                # 但可检查文件是否被篡改（如非微软签名）
                                try:
                                    pe = pefile.PE(path)
                                    if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                                        reasons.append("无数字签名")
                                        is_suspicious = True
                                except:
                                    pass
                            except Exception as e:
                                reasons.append(f"读取失败: {e}")

                    # --- 启发式反射加载检测 ---
                    if detect_reflective_loading and path == "":
                        reasons.append("无文件路径（典型反射加载特征）")
                        is_suspicious = True

                    if is_suspicious:
                        desc = f"  {path} @ {mod['base']} ({mod['size']}B)"
                        if reasons:
                            desc += " | " + "; ".join(reasons)
                        suspicious.append(desc)

                if suspicious:
                    findings.append("\n🚨 发现可疑模块:")
                    findings.extend(suspicious)
                else:
                    findings.append("未发现明显异常模块。")

                return "\n".join(findings)

            except Exception as e:
                return f"进程模块分析失败: {e}"

if __name__ == "__main__":
    mcp.run()