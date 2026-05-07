# 银狐木马应急响应 MCP 服务器 - 快速开始指南

## 快速安装

```bash
cd C:\Users\wubo1\Downloads\wuwenMCP
pip install -r requirements.txt
```

## 快速测试

### 1. 启动 MCP 服务器

```bash
python silverfox_ir.py
```

### 2. 基础检测命令

#### 检测银狐木马（快速扫描）
```python
detect_silverfox_indicators(
    scan_processes=True,
    scan_files=False,  # 跳过文件扫描以加快速度
    scan_registry=True,
    scan_network=True,
    max_results=50
)
```

#### 检测内网横向移动（最近 24 小时）
```python
detect_lateral_movement(
    check_wmi=True,
    check_psexec=True,
    check_rdp=True,
    check_smb=True,
    time_range_hours=24
)
```

#### 生成完整应急响应报告
```python
generate_incident_response_report(
    incident_type="silverfox",
    output_format="markdown",
    include_remediation=True,
    save_to_file=True
)
```

## 文件结构

```
wuwenMCP/
├── silverfox_ir.py          # 主 MCP 服务器文件（748 行）
├── silverfox_ioc.json       # IOC 数据库（2.3 KB）
├── config.json              # 配置文件（1.6 KB）
├── requirements.txt         # Python 依赖
├── README_SILVERFOX.md      # 完整文档（8.5 KB）
├── QUICKSTART.md            # 本文件
├── yingji.py                # 原有应急响应工具
├── log.py                   # 原有日志分析工具
└── oscontrol.py             # 原有系统控制工具

```

## 核心功能

### 1. 银狐木马检测
- ✅ 检测伪装系统进程（svchost0.exe 等）
- ✅ 扫描可疑文件路径
- ✅ 检测注册表持久化
- ✅ 识别 C2 通信

### 2. 内网横向移动检测
- ✅ WMI 远程执行
- ✅ PSExec 执行
- ✅ RDP 登录
- ✅ SMB 共享访问

### 3. 文件时间线分析
- ✅ 按修改时间排序
- ✅ 计算文件哈希
- ✅ 标记异常路径

### 4. PowerShell 日志分析
- ✅ 检测混淆命令
- ✅ 检测远程下载
- ✅ 检测反射加载

### 5. 网络扫描检测
- ✅ ARP 缓存异常
- ✅ DNS 缓存异常
- ✅ 端口扫描特征

### 6. 综合报告生成
- ✅ Markdown/JSON 格式
- ✅ 修复建议
- ✅ 保存到文件

## 常见问题

### Q1: 如何以管理员权限运行？
A: 右键点击 PowerShell 或命令提示符，选择"以管理员身份运行"，然后执行 `python silverfox_ir.py`。

### Q2: 如何减少误报？
A: 编辑 `config.json` 中的 `whitelist` 部分，添加已知的合法进程和路径。

### Q3: 如何自定义 IOC 指标？
A: 编辑 `silverfox_ioc.json`，添加自定义的进程名称、文件哈希、C2 域名/IP 等。

### Q4: 如何加快扫描速度？
A: 在 `config.json` 中减少 `scan_paths` 或增加 `exclude_paths`，或在调用工具时设置 `scan_files=False`。

## 下一步

1. 阅读完整文档：`README_SILVERFOX.md`
2. 自定义配置：编辑 `config.json` 和 `silverfox_ioc.json`
3. 集成到现有工作流：参考 MCP 客户端文档
4. 定期更新 IOC 数据库：从威胁情报源获取最新指标

## 技术支持

- 完整文档：`README_SILVERFOX.md`
- 威胁情报来源：参考 README 中的"威胁情报来源"章节
- 问题反馈：通过 GitHub Issues 提交

---

**版本**: 1.0.0  
**最后更新**: 2026-05-07
