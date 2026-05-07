# 银狐木马应急响应与内网横向检测 MCP 服务器

## 概述

这是一个专门用于应急响应银狐木马（Silver Fox trojan）和检测 Windows 主机内网横向移动的 MCP（Model Context Protocol）服务器。该工具整合了威胁情报、行为分析和日志审计能力，帮助安全团队快速识别和响应安全事件。

## 功能特性

### 1. 银狐木马检测
- ✅ 检测伪装的系统进程（svchost0.exe, csrss0.exe 等）
- ✅ 扫描可疑文件路径（临时目录、AppData、Public 目录）
- ✅ 检测注册表持久化机制
- ✅ 识别可疑网络连接（C2 通信）
- ✅ 计算文件 SHA256 哈希用于威胁情报匹配

### 2. 内网横向移动检测
- ✅ WMI 远程执行检测（Event ID 5857, 5858, 5859, 5860, 5861）
- ✅ PSExec 执行检测（PSEXESVC 服务、命名管道）
- ✅ RDP 登录检测（Event ID 4624 Type 10, 4778, 4779）
- ✅ SMB 共享访问检测（Event ID 5140, 5145）
- ✅ 时间范围过滤（支持 1-168 小时）

### 3. 文件时间线分析
- ✅ 按修改时间排序文件
- ✅ 过滤可疑文件类型（.exe, .dll, .ps1, .bat, .vbs 等）
- ✅ 标记异常路径（临时目录、用户目录）
- ✅ 计算文件哈希（SHA256）
- ✅ 支持自定义时间范围和文件大小过滤

### 4. PowerShell 日志深度分析
- ✅ 检测 Base64 编码命令（-enc, -encodedcommand）
- ✅ 检测远程下载（Invoke-WebRequest, downloadstring, iex）
- ✅ 检测反射加载（Invoke-ReflectivePEInjection）
- ✅ 检测混淆技术（字符串拼接、变量替换）
- ✅ 检测远程执行（Invoke-Command, Enter-PSSession）

### 5. 网络扫描痕迹检测
- ✅ ARP 缓存异常检测（大量 ARP 条目）
- ✅ DNS 缓存异常检测（内网 IP 反查）
- ✅ 网络连接异常检测（大量 SYN_SENT 状态）
- ✅ 端口扫描特征检测（短时间内连接多个端口）

### 6. 综合应急响应报告
- ✅ 自动执行所有检测模块
- ✅ 按严重程度分类威胁指标
- ✅ 生成 Markdown 或 JSON 格式报告
- ✅ 提供详细的修复建议
- ✅ 支持保存到文件

## 系统要求

- **操作系统**: Windows 10/11 或 Windows Server 2016+
- **权限**: 管理员权限（用于访问事件日志和系统进程）
- **Python**: Python 3.8+
- **PowerShell**: PowerShell 5.1+（用于日志审计）

## 依赖项

```bash
pip install fastmcp psutil pefile requests pywin32
```

### Python 包说明
- `fastmcp>=0.1.0` - MCP 服务器框架
- `psutil>=5.9.0` - 进程和系统信息
- `pefile>=2023.2.7` - PE 文件分析
- `requests>=2.31.0` - HTTP 请求
- `pywin32>=306` - Windows API 和事件日志访问

## 安装与配置

### 1. 克隆或下载代码

```bash
git clone https://github.com/MorStardust/DetectSilverFox.git
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置文件

编辑 `config.json` 自定义检测参数：

```json
{
  "detection_config": {
    "time_range_hours": 24,
    "max_results": 500,
    "scan_paths": [
      "C:\\Windows\\Temp",
      "C:\\Users",
      "C:\\ProgramData"
    ]
  }
}
```

### 4. IOC 数据库

编辑 `silverfox_ioc.json` 添加自定义 IOC 指标：

```json
{
  "silverfox_ioc": {
    "process_names": [
      "svchost0.exe",
      "csrss0.exe"
    ],
    "file_hashes": {
      "sha256": [
        "abc123..."
      ]
    }
  }
}
```

## 使用方法

### 启动 MCP 服务器

```bash
python silverfox_ir.py
```

### 通过 MCP 客户端调用工具

#### 1. 检测银狐木马

```python
# 完整检测
detect_silverfox_indicators(
    scan_processes=True,
    scan_files=True,
    scan_registry=True,
    scan_network=True,
    max_results=100
)

# 仅检测进程和文件
detect_silverfox_indicators(
    scan_processes=True,
    scan_files=True,
    scan_registry=False,
    scan_network=False
)
```

#### 2. 检测内网横向移动

```python
# 完整检测（最近 24 小时）
detect_lateral_movement(
    check_wmi=True,
    check_psexec=True,
    check_rdp=True,
    check_smb=True,
    time_range_hours=24
)

# 仅检测 RDP 和 SMB（最近 48 小时）
detect_lateral_movement(
    check_wmi=False,
    check_psexec=False,
    check_rdp=True,
    check_smb=True,
    time_range_hours=48
)
```

#### 3. 分析文件时间线

```python
# 扫描 C:\Users 和 C:\ProgramData（最近 24 小时）
analyze_file_timeline(
    root_paths=["C:\\Users", "C:\\ProgramData"],
    time_range_hours=24,
    file_types=['.exe', '.dll', '.ps1', '.bat', '.vbs'],
    min_size_bytes=1024,
    max_results=100
)
```

#### 4. 分析 PowerShell 日志

```python
# 完整分析（最近 24 小时）
analyze_powershell_logs_advanced(
    time_range_hours=24,
    detect_obfuscation=True,
    detect_download=True,
    detect_execution=True,
    max_events=100
)
```

#### 5. 检测网络扫描

```python
# 完整检测
detect_network_scanning(
    check_arp_cache=True,
    check_dns_cache=True,
    check_netstat=True,
    detect_port_scan=True
)
```

#### 6. 生成综合报告

```python
# 生成银狐木马应急响应报告（Markdown 格式）
generate_incident_response_report(
    incident_type="silverfox",
    output_format="markdown",
    include_remediation=True,
    save_to_file=True
)

# 生成内网横向移动报告（JSON 格式）
generate_incident_response_report(
    incident_type="lateral_movement",
    output_format="json",
    include_remediation=True,
    save_to_file=False
)
```

## 输出示例

### 银狐木马检测输出

```
🚨 检测到 3 个银狐木马相关威胁指标:

1. 🔴 [PROCESS] 检测到伪装系统进程: svchost0.exe (PID 1234)
   路径: C:\Users\Public\svchost0.exe, 启动时间: 2026-05-06 14:23:15

2. 🟠 [FILE] 检测到可疑文件: C:\Users\Public\update.exe
   SHA256: abc123def456..., 大小: 524288 bytes

3. 🟡 [NETWORK] 检测到可疑网络连接: 192.168.1.100:49152 -> 45.xxx.xxx.xxx:443
   进程: svchost0.exe (PID 1234), 状态: ESTABLISHED
```

### 内网横向移动检测输出

```
🚨 检测到 2 个内网横向移动相关威胁指标（最近 24 小时）:

1. 🔴 [PSEXEC] 检测到 PSExec 服务: PSEXESVC
   显示名: PsExec Service, 路径: C:\Windows\PSEXESVC.exe

2. 🟠 [RDP] 检测到 RDP 登录: 2026-05-06 15:30:45
   登录类型: 10 (RemoteInteractive), 源 IP: 192.168.1.50
```

## 威胁情报来源

本工具基于以下威胁情报和技术分析：

- [Qianxin Threat Intelligence - Silver Fox APT](https://ti.qianxin.com/blog/articles/apt-q-27-gang-recent-use-of-silver-fox-trojan-stealing-activities-en/)
- [Antiy Labs - Silver Fox Multi-layer Payload Analysis](https://www.antiy.net/p/analysis-of-multi-layer-concealed-payload-decryption-and-driver-level-blinding-countermeasures-technical-and-tactical-tracking-of-swimming-snake-silver-fox/)
- [The Hacker News - Silver Fox Expands Asia Campaign](https://thehackernews.com/2026/03/silver-fox-expands-asia-cyber-campaign.html)
- [Picus Security - Silver Fox APT Targets Public Sector](https://www.picussecurity.com/resource/blog/silver-fox-apt-targets-public-sector-via-trojanized-medical-software)
- [Microsoft - Containing Domain Compromise](https://www.microsoft.com/en-us/security/blog/2026/04/17/domain-compromise-predictive-shielding-shut-down-lateral-movement/)
- [Palo Alto Networks - What Is Lateral Movement](https://www.paloaltonetworks.com/cyberpedia/what-is-lateral-movement)

## 注意事项

1. **权限要求**: 所有检测工具需要管理员权限运行，否则无法访问系统日志和进程信息
2. **性能影响**: 文件扫描可能需要较长时间，建议在非业务高峰期运行
3. **误报处理**: 工具提供白名单机制，可在 `config.json` 中配置排除路径和进程
4. **日志记录**: 所有检测操作记录到 `incident_log.txt`，便于审计
5. **隔离操作**: 工具不会自动删除文件或终止进程，需用户手动确认后操作

## 故障排除

### 问题 1: 无法访问事件日志

**错误**: `需要安装 pywin32 模块才能检测横向移动。`

**解决方案**:
```bash
pip install pywin32
```

### 问题 2: 权限不足

**错误**: `可能需要管理员权限`

**解决方案**: 以管理员身份运行 PowerShell 或命令提示符，然后启动 MCP 服务器。

### 问题 3: 文件扫描速度慢

**解决方案**: 在 `config.json` 中减少 `scan_paths` 或增加 `exclude_paths`。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进本工具。

## 许可证

本项目仅供安全研究和应急响应使用，请勿用于非法用途。

## 联系方式

如有问题或建议，请通过 GitHub Issues 联系。

---

**最后更新**: 2026-05-07
**版本**: 1.0.0
