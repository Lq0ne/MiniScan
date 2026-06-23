## MiniScan

MiniScan 是一款 Windows 工具，功能包括：

- **反编译微信小程序**：使用外部解包工具 (`KillWxapkg.exe`)
- **扫描反编译源码**：提取 URL 和潜在敏感信息，生成 Excel 报告
- **可选运行 Fortify SCA**：对反编译源码执行静态安全分析，生成 FPR/PDF 报告

MiniScan 设计为通过 PyInstaller 打包成单个 `Mini-Scan.exe`，同时保持 `config` 和 `tools` 文件夹为外部可编辑状态。

![image-20260320163433254](assets/image-20260320163433254.png)

---

## 目录结构

运行时（无论从源码运行还是使用打包后的 exe），工作目录应如下所示：

- `Mini-Scan.exe`（或源码运行时的 `Mini-Scan.py`）
- `config/`
  - `config.yaml` – 主配置文件（微信缓存路径、Fortify 路径等）
  - `rule.yaml` – 敏感信息/令牌/ID 的正则规则
- `tools/`
  - `KillWxapkg.exe` – 微信小程序解包工具
  - `WeChatAppEx.exe.js` – Frida Hook 脚本
- `Output/`
  - `Source/` – Fortify 扫描的微信小程序源码
  - `Audit/` – Fortify FPR 和 PDF 报告
  - `Log/` – Fortify 日志和摘要文件

![image-20260320163645163](assets/image-20260320163645163.png)

---

## 安装与构建

### **安装**

### 1. 在 [发布页面](https://github.com/Lq0ne/MiniScan/releases) 下载打包好的 MiniScan。

### 2. 配置 Fortify（可选但推荐）

编辑 `config/config.yaml`：

- 设置 `fortify_path` 为您的 Fortify SCA 安装路径

```yaml
fortify_path: "C:\\Program Files\\Fortify\\OpenText_SAST_Fortify_25.3.0"
```

- 设置 `report_generator_path` 为 `ReportGenerator.bat`

```yaml
report_generator_path: "C:\\Program Files\\Fortify\\OpenText_Application_Security_Tools_25.2.0\\bin\\ReportGenerator.bat"
```

- 可选调整：
  - `max_worker`（默认 `1`）
  - `output_dir`（默认 `./Output/Audit`）

### 3. 配置微信小程序缓存路径

在 `config/config.yaml` 中：

- 设置 `mini_scan.wx_dir` 为微信小程序缓存目录，例如：

```yaml
mini_scan:
  wx_dir: "C:\\Users\\<用户名>\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages"
```

MiniScan 将监控此目录以检测新生成的小程序包。



### **构建：**

### 1. Python 环境

- Windows 10 或更高版本（需要微信桌面客户端）
- 推荐 Python 3.9+
- 安装依赖：

```bash
pip install -r requirements.txt
```

### 2. 配置 Fortify（可选但推荐）

编辑 `config/config.yaml`：

- 设置 `fortify_path` 为您的 Fortify SCA 安装路径

```yaml
fortify_path: "C:\\Program Files\\Fortify\\OpenText_SAST_Fortify_25.3.0"
```

- 设置 `report_generator_path` 为 `ReportGenerator.bat`

```yaml
report_generator_path: "C:\\Program Files\\Fortify\\OpenText_Application_Security_Tools_25.2.0\\bin\\ReportGenerator.bat"
```

- 可选调整：
  - `max_worker`（默认 `1`）
  - `output_dir`（默认 `./Output/Audit`）

### 3. 配置微信小程序缓存路径

在 `config/config.yaml` 中：

- 设置 `mini_scan.wx_dir` 为微信小程序缓存目录，例如：

```yaml
mini_scan:
  wx_dir: "C:\\Users\\<用户名>\\AppData\\Roaming\\Tencent\\xwechat\\radium\\Applet\\packages"
```

MiniScan 将监控此目录以检测新生成的小程序包。

### 4. 构建为单个 EXE（可选）

PyInstaller 配置文件 (`Mini-Scan.spec`) 已提供，并保持 `config` 和 `tools` 为外部文件夹：

```bash
pyinstaller Mini-Scan.spec
```

构建完成后，复制或确保：

- `config/` 位于 `Mini-Scan.exe` 旁边
- `tools/` 位于 `Mini-Scan.exe` 旁边

然后您可以编辑 `config.yaml` 或替换 `tools/` 中的工具，而无需重新构建 exe。

---

## 运行模式

MiniScan 现在支持**三种互斥模式**：

- `--scan-all` – 仅 Fortify 批量扫描模式
- `--monitor` – 监控 + 反编译 + 本地分析 + Fortify 模式
- `--testing` – 监控 + 反编译 + 本地分析，**不包含** Fortify

启动 MiniScan 时**必须**指定且仅指定其中一种模式。

所有模式默认启用代码美化格式化（相当于 `--pretty`）。

---

## 使用方法

从源码运行的基本用法：

```bash
python Mini-Scan.py --scan-all
python Mini-Scan.py --monitor
python Mini-Scan.py --testing
```

您还可以结合可选标志使用：

```bash
python Mini-Scan.py --monitor --hook
python Mini-Scan.py --testing --hook
```

### 全局选项

- `--hook` / `-hook`  
  启用 Frida Hook，附加 `WeChatAppEx.exe.js` 并为小程序进程打开 DevTools。

- `--pretty` / `-pretty`  
  启用反编译代码的美化格式化。  
  当前此功能**默认启用**；保留此标志是为了兼容性。

### 必需模式（选择且仅选择一种）

- `--scan-all`  
  对 `Output/Source` 下的所有现有小程序项目运行 **Fortify SCA**。  
  此模式下不进行微信监控或反编译。

- `--monitor`  
  监控微信小程序窗口，实时反编译每个小程序，运行 MiniScan 本地分析（URL/敏感信息），然后触发 Fortify 批量扫描。

- `--testing`  
  与 `--monitor` 相同，但**不运行 Fortify**。  
  当您只关心反编译和本地 URL/敏感信息报告时很有用。

---

## 模式详情与工作流

**首次使用，强烈建议尝试 `--monitor` 选项！**

### 1. `--scan-all` 模式（仅 Fortify 批量扫描）

行为：

- **不**监控微信或反编译新的小程序
- 读取 `Output/Source` 下的所有项目文件夹
- 对每个项目：
  - 将源码转换为 Fortify 会话
  - 使用 JavaScript / 前端规则运行 SCA
  - 生成：
    - `Output/Audit` 中的 `<项目名>.fpr` 和 `<项目名>.pdf`
  - 将进度和错误记录到 `Output/Log/fortify_fortify.log`
- 生成摘要文本报告：  
  `Output/Log/min_code_scan_summary.txt`

典型工作流：

1. 使用 `--monitor` 或 `--testing` 将反编译项目生成到 `Output/Source`
2. 然后运行：

```bash
.\Mini-Scan.exe --scan-all
```

![image-20260320170002334](assets/image-20260320170002334.png)

---

### 2. `--monitor` 模式（监控 + 反编译 + 扫描）

行为：

- 启动时显示**警告**，询问是否要清理 `mini_scan.wx_dir` 下现有的微信小程序缓存文件夹
  - 如果输入 `yes`，MiniScan 将：
    - 递归删除小程序缓存目录（以 `wx` 开头且长度为 18 的目录）
    - 记录清理结果
  - 如果跳过，保留现有缓存
  
  ![image-20260320170208429](assets/image-20260320170208429.png)
- 然后持续：
  - 监控 `wx_dir` 中的新小程序文件夹，直到您输入 `start` 并按回车。
  - 对每个新打开的小程序：
    - 通过 `WeChatAppEx.exe` 识别窗口标题
    - 使用 `KillWxapkg.exe` 反编译到：
      - `result/<窗口标题或随机后缀>/`
    - 运行**本地分析** (`FileProcessor`)：
      - 提取 URL 和 URL 路径
      - 应用 `config/rule.yaml` 中的正则规则查找敏感信息/令牌
      - 写入 Excel 报告 `Key.xlsx`（或配置的名称），包含：
        - URL 列表
        - 基于正则的密钥发现
        - 可选的异步 HTTP 模糊测试结果（如果启用）
    - 如果在 `--monitor` 模式下运行：
      - 触发 `fortify_scan.main()` 扫描 `Output/Source` 下的所有项目

![image-20260320170147734](assets/image-20260320170147734.png)

提示：

- 确保微信正在运行且小程序正常打开
- 在关闭小程序前等待 UI 完全加载，以确保缓存完整

---

### 3. `--testing` 模式（监控 + 反编译，无 Fortify）

行为：

- 与 `--monitor` 相同的功能：
  - 监控新的小程序窗口
  - 美化格式化反编译
  - 运行本地 URL/敏感信息提取和 Excel 输出
- **不**运行 Fortify 扫描

在以下情况使用 `--testing`：

- 您只验证反编译行为
- 您只需要 Excel 结果 (`Key.xlsx`) 和 `result/` 下的原始源码
- Fortify 尚未安装或配置

![image-20260320170532939](assets/image-20260320170532939.png)

---

## 结果文件

- 反编译输出：
  - `result/<小程序标题>/` – 反编译源码树
  - `result/<小程序标题>/Key.xlsx` – URL/敏感信息扫描结果

- Fortify 输出（用于 `--scan-all` 或 `--monitor`）：
  - `Output/Source/<小程序标题>/` – 待扫描源码
  - `Output/Audit/<小程序标题>.fpr` – Fortify 项目结果
  - `Output/Audit/<小程序标题>.pdf` – Fortify PDF 报告
  - `Output/Log/fortify_fortify.log` – Fortify 详细日志
  - `Output/Log/min_code_scan_summary.txt` – 批量摘要

- 日志：
  - `scan_results/miniscan.log` – MiniScan 运行日志

---

## 配置文件

### `config/config.yaml`

包含：

- `mini_scan` 部分 – 微信、异步 HTTP、线程和反编译设置
- `fortify_scan` 部分 – Fortify 安装路径和性能参数

文件中的注释解释了每个键的含义，全部为英文。

### `config/rule.yaml`

定义以下内容的正则规则：

- 邮箱、手机号、身份证号
- JWT 令牌、多个云服务商的 API 密钥
- Webhook URL、私钥、密码、授权头等

每条规则包含：

- `id` – 规则标识符（用于 Excel 输出）
- `enabled` – 规则是否激活
- `pattern` – 正则表达式字符串

您可以根据需要启用/禁用或自定义规则。

---

## 注意事项与最佳实践

- **以运行微信的同一用户身份运行**，以便 MiniScan 可以访问正确的缓存路径
- **在 `--monitor` 模式下使用此工具前，确保所有小程序已关闭！！！**
- **打包后始终将 `config/` 和 `tools/` 放在 exe 旁边**
- 升级工具时：
  - 替换 `tools/` 下的二进制文件/脚本
  - 如有必要，调整 `mini_scan.unpack_tool` 和其他路径
- 调试时：
  - 查看 `scan_results/miniscan.log` 了解 MiniScan 问题
  - 查看 `Output/Log/fortify_fortify.log` 了解 Fortify 问题
