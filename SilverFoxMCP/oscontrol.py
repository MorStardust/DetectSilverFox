import os
import subprocess
import sys
import json
import stat
import psutil
import datetime
from pathlib import Path
from typing import Optional, Annotated, List
from pydantic import Field
from mcp.server.fastmcp import FastMCP  # 替换为你的实际 MCP 框架路径

# 初始化运维型 MCP 服务
mcp = FastMCP("OS-Operations-Master")


def _is_hidden(filepath: Path) -> bool:
    """判断文件或目录是否为隐藏（跨平台）"""
    if os.name == 'nt':
        import ctypes
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
            return bool(attrs & 2)  # FILE_ATTRIBUTE_HIDDEN
        except (OSError, ValueError):
            return False
    else:
        return filepath.name.startswith('.')


# ==================== 1. 文件系统操作 ====================

@mcp.tool()
def file_read(path: Annotated[str, Field(description="要读取的文件绝对路径")]) -> str:
    """读取文本文件内容（UTF-8 编码）"""
    p = Path(path).resolve()
    if not p.exists():
        return f"错误：文件不存在 - {p}"
    try:
        return p.read_text(encoding='utf-8')
    except Exception as e:
        return f"读取失败: {e}"


@mcp.tool()
def file_write(
        path: Annotated[str, Field(description="目标文件绝对路径")],
        content: Annotated[str, Field(description="要写入的内容")],
        mode: Annotated[str, Field(description="写入模式: 'w' 覆盖, 'a' 追加", pattern=r"^[wa] $ ")] = "w"
) -> str:
    """写入或追加文本到文件（自动创建父目录）"""
    p = Path(path).resolve()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding='utf-8', newline='')
        return f"成功写入 {len(content)} 字节到 {p}"
    except Exception as e:
        return f"写入失败: {e}"


@mcp.tool()
def file_copy(
        src: Annotated[str, Field(description="源文件路径")],
        dst: Annotated[str, Field(description="目标文件路径")]
) -> str:
    """复制文件（支持跨目录）"""
    src_p, dst_p = Path(src).resolve(), Path(dst).resolve()
    if not src_p.exists():
        return f"源文件不存在: {src_p}"
    try:
        dst_p.parent.mkdir(parents=True, exist_ok=True)
        import shutil
        shutil.copy2(src_p, dst_p)
        return f"已复制 {src_p} → {dst_p}"
    except Exception as e:
        return f"复制失败: {e}"


@mcp.tool()
def file_move(
        src: Annotated[str, Field(description="源路径")],
        dst: Annotated[str, Field(description="目标路径")]
) -> str:
    """移动或重命名文件/目录"""
    src_p, dst_p = Path(src).resolve(), Path(dst).resolve()
    if not src_p.exists():
        return f"源路径不存在: {src_p}"
    try:
        dst_p.parent.mkdir(parents=True, exist_ok=True)
        src_p.rename(dst_p)
        return f"已移动 {src_p} → {dst_p}"
    except Exception as e:
        return f"移动失败: {e}"


@mcp.tool()
def file_delete(path: Annotated[str, Field(description="要删除的文件或目录路径")]) -> str:
    """删除文件或空目录（非递归）"""
    p = Path(path).resolve()
    if not p.exists():
        return f"路径不存在: {p}"
    try:
        if p.is_file():
            p.unlink()
        elif p.is_dir():
            p.rmdir()  # 仅删除空目录
        return f"已删除 {p}"
    except OSError as e:
        if "Directory not empty" in str(e):
            return f"错误：目录非空，无法删除（请先清空）: {p}"
        return f"删除失败: {e}"
    except Exception as e:
        return f"删除异常: {e}"


@mcp.tool()
def file_chmod(
        path: Annotated[str, Field(description="文件路径")],
        mode_octal: Annotated[str, Field(description="八进制权限字符串，如 '755'", pattern=r"^[0-7]{3,4} $ ")]
) -> str:
    """修改文件权限（仅 Unix-like 系统有效）"""
    if os.name == 'nt':
        return "chmod 在 Windows 上无效。"
    p = Path(path).resolve()
    if not p.exists():
        return f"文件不存在: {p}"
    try:
        p.chmod(int(mode_octal, 8))
        return f"权限已设为 {mode_octal} ({stat.filemode(p.stat().st_mode)})"
    except Exception as e:
        return f"chmod 失败: {e}"


@mcp.tool()
def dir_tree(
    path: Annotated[str, Field(description="要列出的目录路径")],
    include_files: Annotated[bool, Field(description="是否在树中包含文件（否则只列目录）")] = True,
    show_hidden: Annotated[bool, Field(description="是否显示隐藏文件/目录")] = False
) -> str:
    """
    【核心用途：列出目录结构】以树状格式显示目录和子文件，固定递归深度为8层。
    适用于：查看文件夹层级、审计目录布局、排查文件位置。
    替代命令：tree, ls -R, dir /s
    """
    from pathlib import Path

    def _is_hidden(p):
        return p.name.startswith('.')

    root = Path(path).resolve()
    if not root.exists():
        return f"错误：路径不存在 - {root}"
    if not root.is_dir():
        return f"错误：{root} 不是一个目录"

    MAX_DEPTH = 8  # 固定最大深度为8层

    def _build_tree(current, prefix="", depth=0):
        if depth > MAX_DEPTH:
            return []
        try:
            items = sorted(current.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
        except PermissionError:
            return [f"{prefix}⚠️ 权限不足"]

        lines = []
        visible_items = [
            item for item in items
            if show_hidden or not _is_hidden(item)
        ]

        total = len(visible_items)
        for i, item in enumerate(visible_items):
            is_last = (i == total - 1)
            connector = "└── " if is_last else "├── "
            name = item.name
            if item.is_dir():
                lines.append(f"{prefix}{connector}{name}/")
                if depth < MAX_DEPTH:
                    extension = "    " if is_last else "│   "
                    lines.extend(_build_tree(item, prefix + extension, depth + 1))
            elif include_files:
                lines.append(f"{prefix}{connector}{name}")
        return lines

    try:
        tree_lines = _build_tree(root, depth=0)
        header = f"📁 目录树: {root} (深度≤8, {'含文件' if include_files else '仅目录'})\n"
        if not tree_lines:
            header += "(空目录)"
        return header + "\n".join(tree_lines)
    except Exception as e:
        return f"生成目录树失败: {e}"


@mcp.tool()
def file_info(path: Annotated[str, Field(description="文件或目录的绝对路径")]) -> str:
    """
    【核心用途：查看文件或目录的详细信息】获取类型、大小、权限、时间戳、所有者等元数据。
    适用于：检查文件属性、验证文件状态、排查权限或时间问题。
    替代命令：ls -l, stat, dir, Get-ItemProperty
    """
    p = Path(path).resolve()
    if not p.exists():
        return f"错误：路径不存在 - {p}"

    try:
        stat_info = p.stat()
        info = [f"📄 路径: {p}"]

        # 类型与基本统计
        if p.is_symlink():
            info.append("类型: 符号链接")
            try:
                target = os.readlink(p)
                info.append(f"→ 指向: {target}")
            except Exception:
                pass
        elif p.is_dir():
            info.append("类型: 目录")
            try:
                child_count = len(list(p.iterdir()))
                info.append(f"子项数量: {child_count}")
            except PermissionError:
                info.append("子项数量: [权限不足]")
        else:
            info.append("类型: 普通文件")
            size_bytes = stat_info.st_size
            info.append(f"大小: {size_bytes} 字节 ({size_bytes / (1024 ** 2):.2f} MB)")

        # 时间信息
        info.append(f"修改时间 (mtime): {datetime.datetime.fromtimestamp(stat_info.st_mtime)}")
        info.append(f"访问时间 (atime): {datetime.datetime.fromtimestamp(stat_info.st_atime)}")

        if os.name == 'nt':
            info.append(f"创建时间 (ctime): {datetime.datetime.fromtimestamp(stat_info.st_ctime)}")
        else:
            info.append(f"Inode变更时间 (ctime): {datetime.datetime.fromtimestamp(stat_info.st_ctime)}")

        # 权限与属性
        if os.name == 'nt':
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(p))
            attr_list = []
            if attrs & 0x2: attr_list.append("HIDDEN")
            if attrs & 0x4: attr_list.append("SYSTEM")
            if attrs & 0x1: attr_list.append("READONLY")
            info.append(f"Windows属性: {', '.join(attr_list) if attr_list else 'None'}")
        else:
            mode = stat_info.st_mode
            from stat import filemode
            info.append(f"Unix权限: {oct(mode)[-3:]} ({filemode(mode)})")
            try:
                import pwd, grp
                user = pwd.getpwuid(stat_info.st_uid).pw_name
                group = grp.getgrgid(stat_info.st_gid).gr_name
                info.append(f"所有者: {user}:{group}")
            except (ImportError, KeyError, OSError):
                info.append(f"所有者 UID/GID: {stat_info.st_uid}/{stat_info.st_gid}")

        return "\n".join(info)

    except Exception as e:
        return f"获取文件信息失败: {e}"


# ==================== 2. 服务管理 ====================

@mcp.tool()
def service_control(
        name: Annotated[str, Field(description="服务名称（如 nginx, sshd, Spooler）")],
        action: Annotated[
            str, Field(description="操作: start, stop, restart, status", pattern=r"^(start|stop|restart|status) $ ")]
) -> str:
    """控制系统服务（跨平台）"""
    try:
        if sys.platform.startswith('win'):
            cmd = ["sc", action, name] if action != "status" else ["sc", "query", name]
        else:  # Linux/macOS
            if action == "status":
                cmd = ["systemctl", "is-active", name]
            else:
                cmd = ["systemctl", action, name]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return f"服务 '{name}' {action} 成功。\n输出: {result.stdout.strip()}"
        else:
            return f"服务操作失败（{action} {name}）:\n{result.stderr.strip()}"
    except FileNotFoundError:
        return "未找到服务管理工具（Windows 需 sc，Linux 需 systemctl）。"
    except subprocess.TimeoutExpired:
        return "服务操作超时（可能卡住）。"
    except Exception as e:
        return f"服务控制异常: {e}"


# ==================== 3. 启动项管理 ====================

@mcp.tool()
def startup_add(
        name: Annotated[str, Field(description="启动项名称")],
        command: Annotated[str, Field(description="要执行的完整命令或脚本路径")]
) -> str:
    """添加开机自启项（跨平台）"""
    try:
        if sys.platform == "win32":
            import winreg
            key = winreg.HKEY_CURRENT_USER
            subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as regkey:
                winreg.SetValueEx(regkey, name, 0, winreg.REG_SZ, command)
            return f"已添加 Windows 启动项: {name} = {command}"
        elif sys.platform == "darwin":  # macOS
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>local.{name}</string>
    <key>ProgramArguments</key>
    <array><string>{command}</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>"""
            plist_path = Path.home() / "Library" / "LaunchAgents" / f"local.{name}.plist"
            plist_path.write_text(plist_content)
            subprocess.run(["launchctl", "load", str(plist_path)], check=False)
            return f"已添加 macOS LaunchAgent: {plist_path}"
        else:  # Linux
            desktop_entry = f"""[Desktop Entry]
Type=Application
Name={name}
Exec={command}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
            autostart_dir = Path.home() / ".config" / "autostart"
            autostart_dir.mkdir(parents=True, exist_ok=True)
            entry_path = autostart_dir / f"{name}.desktop"
            entry_path.write_text(desktop_entry)
            entry_path.chmod(0o755)
            return f"已添加 Linux 自启动项: {entry_path}"
    except Exception as e:
        return f"添加启动项失败: {e}"


@mcp.tool()
def startup_remove(name: Annotated[str, Field(description="启动项名称")]) -> str:
    """移除开机自启项（跨平台）"""
    try:
        if sys.platform == "win32":
            import winreg
            key = winreg.HKEY_CURRENT_USER
            subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as regkey:
                winreg.DeleteValue(regkey, name)
            return f"已移除 Windows 启动项: {name}"
        elif sys.platform == "darwin":
            plist_path = Path.home() / "Library" / "LaunchAgents" / f"local.{name}.plist"
            if plist_path.exists():
                subprocess.run(["launchctl", "unload", str(plist_path)], check=False)
                plist_path.unlink()
                return f"已移除 macOS LaunchAgent: {plist_path}"
            else:
                return "macOS 启动项不存在。"
        else:
            entry_path = Path.home() / ".config" / "autostart" / f"{name}.desktop"
            if entry_path.exists():
                entry_path.unlink()
                return f"已移除 Linux 自启动项: {entry_path}"
            else:
                return "Linux 自启动项不存在。"
    except FileNotFoundError:
        return "启动项不存在。"
    except Exception as e:
        return f"移除启动项失败: {e}"


# ==================== 4. 程序与脚本执行 ====================

@mcp.tool()
def exec_run(
        command: Annotated[List[str], Field(description="命令及参数列表，如 ['ls', '-l']")],
        shell: Annotated[bool, Field(description="是否通过 shell 执行（慎用）")] = False,
        timeout: Annotated[int, Field(description="超时秒数", ge=1, le=3600)] = 60,
        background: Annotated[bool, Field(description="是否后台运行（不等待结果）")] = False
) -> str:
    """运行外部命令或脚本"""
    try:
        if background:
            subprocess.Popen(command, shell=shell, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return f"已在后台启动: {' '.join(command)}"
        else:
            result = subprocess.run(
                command, shell=shell, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout.strip()
            error = result.stderr.strip()
            status = "成功" if result.returncode == 0 else f"失败 (exit {result.returncode})"
            return f"[{status}]\nSTDOUT:\n{output}\nSTDERR:\n{error}"
    except subprocess.TimeoutExpired:
        return f"命令执行超时（>{timeout}秒）"
    except FileNotFoundError:
        return "命令未找到，请检查路径或是否安装"
    except Exception as e:
        return f"执行异常: {e}"


@mcp.tool()
def process_kill(
        pid: Annotated[Optional[int], Field(description="进程 PID")] = None,
        name: Annotated[Optional[str], Field(description="进程名称（模糊匹配）")] = None
) -> str:
    """终止进程（按 PID 或名称）"""
    if pid is None and name is None:
        return "错误：必须指定 pid 或 name"
    killed = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if (pid and proc.info['pid'] == pid) or (name and name.lower() in proc.info['name'].lower()):
                proc.terminate()
                killed.append(f"PID {proc.info['pid']} ({proc.info['name']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if killed:
        return f"已终止进程: {', '.join(killed)}"
    else:
        return "未找到匹配的进程。"


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
                return datetime.datetime.fromisoformat(t_str.replace("Z", "+00:00"))
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
            create_time = datetime.datetime.fromtimestamp(stat_info.st_ctime)
        else:
            # Linux/macOS: 无法可靠获取创建时间，跳过 created_* 过滤
            create_time = None

        if created_after_dt and (create_time is None or create_time < created_after_dt):
            continue
        if created_before_dt and (create_time is None or create_time > created_before_dt):
            continue

        # --- 修改时间过滤 ---
        modify_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
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