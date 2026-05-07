import os
import re
import glob
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Annotated, List
from pydantic import Field
from mcp.server.fastmcp import FastMCP

# 尝试导入 Windows 特有模块
try:
    import win32evtlog
    import win32evtlogutil
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

mcp = FastMCP("Log-Audit-and-File-Hunter")


# ==================== 辅助函数 ====================

def _is_hidden(filepath: Path) -> bool:
    """判断文件是否为隐藏（跨平台）"""
    if os.name == 'nt':
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
        return bool(attrs & 2)  # FILE_ATTRIBUTE_HIDDEN
    else:
        return filepath.name.startswith('.')

def _parse_log_time(line: str, time_format: str = "%d/%b/%Y:%H:%M:%S") -> Optional[datetime]:
    """尝试从日志行中提取时间（支持常见 Web 日志格式）"""
    match = re.search(r"  $ (\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})", line)
    if match:
        try:
            return datetime.strptime(match.group(1), time_format)
        except:
            pass
    return None


# ==================== 1. Web 日志分析 ====================

@mcp.tool()
def search_web_logs(
    log_path: Annotated[str, Field(description="Web 日志文件路径（支持通配符 *）", example="/var/log/nginx/access.log*")],
    ip_filter: Annotated[Optional[str], Field(description="筛选特定 IP")] = None,
    status_code: Annotated[Optional[str], Field(description="HTTP 状态码，如 '404', '500'")] = None,
    user_agent_contains: Annotated[Optional[str], Field(description="User-Agent 包含关键词")] = None,
    after_time: Annotated[Optional[str], Field(description="仅返回此时间之后的日志（ISO8601 格式）")] = None,
    max_lines: Annotated[int, Field(description="最多返回行数", ge=1, le=10000)] = 100
) -> str:
    """检索 Web 访问日志（Nginx/Apache/IIS 格式）"""
    results = []
    count = 0

    # 解析时间过滤
    after_dt = None
    if after_time:
        try:
            after_dt = datetime.fromisoformat(after_time.replace("Z", "+00:00"))
        except:
            return "时间格式错误，请使用 ISO8601（如 2025-01-01T12:00:00）"

    # 展开通配符
    paths = glob.glob(log_path)
    if not paths:
        return f"未找到匹配的日志文件: {log_path}"

    for path in paths:
        if count >= max_lines:
            break
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if count >= max_lines:
                        break
                    line = line.strip()
                    if not line:
                        continue

                    # 时间过滤
                    if after_dt:
                        log_time = _parse_log_time(line)
                        if not log_time or log_time < after_dt:
                            continue

                    # IP 过滤
                    if ip_filter and ip_filter not in line:
                        continue

                    # 状态码过滤（假设在第9个字段）
                    if status_code:
                        parts = line.split()
                        if len(parts) > 8 and status_code != parts[8]:
                            continue

                    # User-Agent 过滤
                    if user_agent_contains and user_agent_contains.lower() not in line.lower():
                        continue

                    results.append(f"[{path}] {line}")
                    count += 1
        except Exception as e:
            results.append(f"读取 {path} 失败: {e}")

    if results:
        summary = f"\n🔍 共找到 {len(results)} 条匹配日志（限制 {max_lines} 条）:\n"
        return summary + "\n".join(results[:max_lines])
    else:
        return "未找到匹配的日志条目。"


# ==================== 2. Windows 系统日志审计 ====================

@mcp.tool()
def search_windows_event_logs(
    log_type: Annotated[str, Field(description="日志类型", example="System,Security,Application")],
    event_id: Annotated[Optional[int], Field(description="事件 ID，如 4624（登录）")] = None,
    source: Annotated[Optional[str], Field(description="事件来源（如 Microsoft-Windows-Security-Auditing）")] = None,
    message_contains: Annotated[Optional[str], Field(description="消息包含关键词")] = None,
    after_time: Annotated[Optional[str], Field(description="ISO8601 时间之后")] = None,
    max_events: Annotated[int, Field(description="最多返回事件数", ge=1, le=500)] = 50
) -> str:
    """检索 Windows Event Log（需 Windows + pywin32）"""
    if not WIN32_AVAILABLE:
        return "该功能仅支持 Windows（需安装 pywin32）。"

    try:
        hand = win32evtlog.OpenEventLog(None, log_type)
        if not hand:
            return f"无法打开日志: {log_type}（可能不存在或权限不足）"

        events = []
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        after_dt = None
        if after_time:
            after_dt = datetime.fromisoformat(after_time.replace("Z", "+00:00"))

        while len(events) < max_events:
            chunk = win32evtlog.ReadEventLog(hand, flags, 0, 8192)
            if not chunk:
                break
            for event in chunk:
                # 时间过滤
                if after_dt and event.TimeGenerated.Format() < after_dt.strftime("%c"):
                    continue
                # EventID 过滤
                if event_id is not None and event.EventID != event_id:
                    continue
                # Source 过滤
                if source and source not in event.SourceName:
                    continue
                # 消息内容过滤
                msg = win32evtlogutil.SafeFormatMessage(event, log_type)
                if message_contains and message_contains.lower() not in msg.lower():
                    continue

                time_str = event.TimeGenerated.Format()
                events.append(f"[{time_str}] ID:{event.EventID} Source:{event.SourceName}\n{msg[:300]}...")
                if len(events) >= max_events:
                    break

        win32evtlog.CloseEventLog(hand)
        if events:
            return f"✅ 在 '{log_type}' 中找到 {len(events)} 条匹配事件:\n" + "\n---\n".join(events)
        else:
            return "未找到匹配的 Windows 事件。"
    except Exception as e:
        return f"Windows 日志检索失败: {e}"


# ==================== 3. 应用日志通用检索 ====================

@mcp.tool()
def search_application_logs(
    log_dir: Annotated[str, Field(description="应用日志目录路径")],
    file_pattern: Annotated[str, Field(description="文件名模式（如 *.log, error*.txt）")] = "*.log",
    keyword: Annotated[str, Field(description="日志内容关键词（支持正则）")] = "",
    case_sensitive: Annotated[bool, Field(description="是否区分大小写")] = False,
    max_files: Annotated[int, Field(description="最多扫描文件数", ge=1, le=100)] = 20,
    max_lines_per_file: Annotated[int, Field(description="每个文件最多扫描行数")] = 1000
) -> str:
    """在指定目录下按关键词搜索应用日志"""
    log_dir_path = Path(log_dir)
    if not log_dir_path.exists():
        return f"目录不存在: {log_dir}"

    results = []
    scanned = 0

    for log_file in log_dir_path.rglob(file_pattern):
        if scanned >= max_files:
            break
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= max_lines_per_file:
                        break
                    search_line = line if case_sensitive else line.lower()
                    search_keyword = keyword if case_sensitive else keyword.lower()
                    if search_keyword in search_line:
                        results.append(f"[{log_file}] {line.strip()}")
            scanned += 1
        except Exception as e:
            results.append(f"跳过 {log_file}: {e}")

    if results:
        return f"🔍 在 {scanned} 个文件中找到 {len(results)} 条匹配:\n" + "\n".join(results[:100])
    else:
        return "未找到匹配的应用日志。"


# ==================== 4. 高级文件检索（含隐藏） ====================

@mcp.tool()
def hunt_suspicious_files(
    root_path: Annotated[str, Field(description="扫描根目录（如 C:\\ 或 /home")],
    extensions: Annotated[Optional[List[str]], Field(description="可疑扩展名列表", example=[".exe", ".dll", ".ps1"])] = None,
    filename_contains: Annotated[Optional[str], Field(
        description="文件名中包含的关键词，多个关键词用 | 分隔（不区分大小写，满足任一即匹配）",
        example="webshell|backdoor|eval"
    )] = None,
    min_size_mb: Annotated[Optional[float], Field(description="最小文件大小（MB）")] = None,
    include_hidden: Annotated[bool, Field(description="是否包含隐藏文件")] = True,
    max_results: Annotated[int, Field(description="最多返回结果数", ge=1, le=500)] = 100
) -> str:
    """
    深度扫描可疑文件：
    - ✅ 支持多关键词文件名筛选：用 | 分隔（如 'shell|eval|cmd'）
    - ✅ 支持扩展名列表过滤（如 ['.php', '.jsp']）
    - ✅ 支持最小文件大小（MB）
    - ✅ 可选是否包含隐藏文件
    - ❌ 不支持按修改时间筛选（已禁用）

    📌 使用示例：
      - filename_contains="shell" → 匹配含 'shell' 的文件
      - filename_contains="a|b|c" → 匹配含 a 或 b 或 c 的文件
      - 留空则不过滤文件名
    """
    root = Path(root_path)
    if not root.exists():
        return f"根目录不存在: {root_path}"

    results = []

    # 默认可疑扩展名（仅当 extensions 未提供时启用）
    default_extensions = ['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.zip', '.rar']
    use_extension_filter = extensions is not None

    # === 解析 filename_contains 为关键词列表 ===
    keywords = []
    if filename_contains:
        # 按 | 分割，去除空白，转小写，过滤空字符串
        keywords = [kw.strip().lower() for kw in filename_contains.split('|') if kw.strip()]

    for file_path in root.rglob('*'):
        if len(results) >= max_results:
            break
        try:
            if not file_path.is_file():
                continue

            # === 文件名关键词过滤（支持多个，OR 逻辑）===
            if keywords:
                name_lower = file_path.name.lower()
                if not any(kw in name_lower for kw in keywords):
                    continue

            # === 扩展名过滤 ===
            if use_extension_filter:
                if file_path.suffix.lower() not in (ext.lower() for ext in extensions):
                    continue

            # === 大小过滤 ===
            if min_size_mb is not None:
                size_mb = file_path.stat().st_size / (1024 * 1024)
                if size_mb < min_size_mb:
                    continue

            # === 隐藏文件处理 ===
            is_hidden_file = _is_hidden(file_path)
            if not include_hidden and is_hidden_file:
                continue

            # === 构建结果 ===
            desc = f"{file_path} ({file_path.stat().st_size} bytes)"
            if is_hidden_file:
                desc += " [HIDDEN]"
            results.append(desc)

        except (OSError, PermissionError):
            continue  # 跳过无权限或不可访问的文件

    if results:
        summary = f"🕵️‍♂️ 发现 {len(results)} 个可疑文件（限制 {max_results} 个）:\n"
        return summary + "\n".join(results)
    else:
        return "未发现可疑文件。"


# ==================== 5. 日志摘要统计 ====================

@mcp.tool()
def summarize_web_logs(
    log_path: Annotated[str, Field(description="Web 日志路径（支持通配符）")]
) -> str:
    """生成 Web 日志摘要：高频 IP、异常状态码、可疑 UA"""
    top_ips = {}
    status_codes = {}
    suspicious_ua = []
    total = 0

    for path in glob.glob(log_path):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total += 1
                    # 提取 IP（第一个字段）
                    parts = line.split()
                    if parts:
                        ip = parts[0]
                        top_ips[ip] = top_ips.get(ip, 0) + 1
                    # 提取状态码（第9个字段）
                    if len(parts) > 8:
                        code = parts[8]
                        status_codes[code] = status_codes.get(code, 0) + 1
                    # 检查可疑 UA
                    if "sqlmap" in line.lower() or "nmap" in line.lower() or "nikto" in line.lower():
                        if len(suspicious_ua) < 10:
                            suspicious_ua.append(line.strip())
        except:
            continue

    # 排序
    top_ips_sorted = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    bad_status = {k: v for k, v in status_codes.items() if k.startswith(('4', '5'))}

    report = [
        f"📊 总日志行数: {total}",
        f"🔝 Top 10 IPs: {dict(top_ips_sorted)}",
        f"⚠️ 异常状态码: {bad_status}",
    ]
    if suspicious_ua:
        report.append("🚨 可疑 User-Agent/工具检测到:")
        report.extend(suspicious_ua)

    return "\n".join(report)


@mcp.tool()
def find_files_by_criteria(
        directory: Annotated[str, Field(description="要搜索的目录路径（支持绝对路径）")],
        min_size_bytes: Annotated[Optional[int], Field(description="最小文件大小（字节）", ge=0)] = None,
        max_size_bytes: Annotated[Optional[int], Field(description="最大文件大小（字节）", ge=0)] = None,
        created_after: Annotated[
            Optional[str], Field(description="创建时间在此之后（ISO8601 格式，如 2025-01-01T00:00:00）")] = None,
        created_before: Annotated[Optional[str], Field(description="创建时间在此之前（ISO8601）")] = None,
        modified_after: Annotated[Optional[str], Field(description="修改时间在此之后（ISO8601）")] = None,
        modified_before: Annotated[Optional[str], Field(description="修改时间在此之前（ISO8601）")] = None,
        file_attributes: Annotated[Optional[List[str]], Field(
            description="文件属性过滤（Windows），可选: hidden, system, readonly, archive",
            example=["hidden", "system"]
        )] = None,
        recursive: Annotated[bool, Field(description="是否递归子目录")] = True,
        max_results: Annotated[int, Field(description="最多返回结果数", ge=1, le=500)] = 100
) -> str:
    """
    在指定目录中按大小、创建/修改时间、文件属性精确查找文件。

    注意：
    - Windows 使用 'st_ctime' 作为创建时间；Linux/macOS 的 'st_ctime' 是 inode 变更时间，非创建时间。
    - 文件属性仅在 Windows 上有效。
    """
    root = Path(directory)
    if not root.exists():
        return f"错误：目录不存在 - {directory}"
    if not root.is_dir():
        return f"错误：{directory} 不是一个目录"

    # 解析时间
    def parse_time(t_str):
        if t_str:
            try:
                return datetime.fromisoformat(t_str.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError(f"时间格式无效: {t_str}")
        return None

    try:
        created_after_dt = parse_time(created_after)
        created_before_dt = parse_time(created_before)
        modified_after_dt = parse_time(modified_after)
        modified_before_dt = parse_time(modified_before)
    except ValueError as e:
        return str(e)

    results = []
    search_pattern = "**/*" if recursive else "*"

    for path in root.glob(search_pattern):
        if len(results) >= max_results:
            break
        if not path.is_file():
            continue

        stat_info = path.stat()

        # --- 大小过滤 ---
        size = stat_info.st_size
        if min_size_bytes is not None and size < min_size_bytes:
            continue
        if max_size_bytes is not None and size > max_size_bytes:
            continue

        # --- 时间过滤（创建时间）---
        # 注意：Linux/macOS 的 st_ctime 不是创建时间！
        if os.name == 'nt':
            # Windows: st_ctime 是创建时间
            create_time = datetime.fromtimestamp(stat_info.st_ctime)
        else:
            # Linux/macOS: 无法可靠获取创建时间，跳过 created_* 过滤
            create_time = None

        if created_after_dt and (create_time is None or create_time < created_after_dt):
            continue
        if created_before_dt and (create_time is None or create_time > created_before_dt):
            continue

        # --- 修改时间过滤 ---
        modify_time = datetime.fromtimestamp(stat_info.st_mtime)
        if modified_after_dt and modify_time < modified_after_dt:
            continue
        if modified_before_dt and modify_time > modified_before_dt:
            continue

        # --- 文件属性过滤（仅 Windows）---
        if file_attributes and os.name == 'nt':
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            attr_map = {
                'hidden': 0x2,
                'system': 0x4,
                'readonly': 0x1,
                'archive': 0x20
            }
            has_all = True
            for attr in file_attributes:
                flag = attr_map.get(attr.lower())
                if flag is None:
                    continue
                if not (attrs & flag):
                    has_all = False
                    break
            if not has_all:
                continue

        # 构建结果行
        info_parts = [str(path)]
        info_parts.append(f"size={size}B")
        if os.name == 'nt':
            info_parts.append(f"created={create_time.strftime('%Y-%m-%d %H:%M:%S')}")
        info_parts.append(f"modified={modify_time.strftime('%Y-%m-%d %H:%M:%S')}")

        if os.name == 'nt' and file_attributes:
            attr_names = []
            attrs_val = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs_val & 0x2: attr_names.append("HIDDEN")
            if attrs_val & 0x4: attr_names.append("SYSTEM")
            if attrs_val & 0x1: attr_names.append("READONLY")
            if attr_names:
                info_parts.append(f"attrs=[{','.join(attr_names)}]")

        results.append(" | ".join(info_parts))

    if results:
        summary = f"✅ 在 '{directory}' 中找到 {len(results)} 个匹配文件（限制 {max_results} 个）:\n"
        return summary + "\n".join(results)
    else:
        return "未找到匹配的文件。"


# ==================== 启动服务 ====================
if __name__ == "__main__":
    mcp.run()