# Windows ETW 专家动态观测

## 目标

`observe windows-etw` 是 Windows 样本的显式专家模式，用于静态分析不足的场景，例如强壳、混淆或导入表被隐藏的 PE 文件。它会在 Windows 本机真实运行目标文件，并记录有限的运行时证据，再通过 `scan --dynamic-report` 合并进 BinSight 风险报告。

这个模式不是沙箱。它不会隔离、拦截或阻止恶意行为。

## 命令

```powershell
.\bin\binsight.exe observe windows-etw .\sample.exe `
  --out dynamic.json `
  --i-understand-risk `
  --timeout 90 `
  --max-events 5000 `
  --max-json-bytes 10485760 `
  --network observe

.\bin\binsight.exe scan .\sample.exe --dynamic-report dynamic.json
```

## 采集证据

第一版只记录受限摘要：

- 目标进程启动和退出
- 子进程发现
- 目标进程树拥有的 TCP 连接快照
- 目标文件所在目录附近的文件创建、修改、删除摘要
- 退出码和超时状态
- 关于限制和风险边界的 warning

报告中会标记为 `platform=windows` 和 `mode=windows_etw`。

动态报告也会记录目标进程是否真的启动：

- `started=true`：目标已经启动，报告中可能包含运行时证据。
- `started=false` 且 `failure_reason=requires_elevation`：样本需要管理员权限。请用管理员 PowerShell 运行 `observe windows-etw`，或允许 GUI 弹出的提权提示。
- `started=false` 且存在其他 `failure_reason`：这表示只完成了尝试观测，不代表成功运行样本。

Windows 会阻止普通资源管理器向管理员权限的 GUI 窗口拖拽文件。为了保持拖拽体验，建议 GUI 普通权限运行，只在动态观测子进程需要时单独提权。

## 存储策略

BinSight 默认不保存原始 `.etl` trace，只写出 `dynamic.json`。

默认限制：

- `--max-events 5000`
- `--max-json-bytes 10485760`
- `--timeout 90`

达到限制后，BinSight 会停止追加详细事件并写入 warning。这样可以避免发行包和单次运行日志失控。预计发行包增量约为压缩后 1-5 MB、解压后 3-15 MB。

## 工业组件决策

Windows ETW 是 Windows 操作系统标准 tracing 接口。第一版优先使用 Windows SDK 和系统观测 API，因为它属于工业标准库，且不会引入额外运行时体积。如果后续扩大 ETW provider 覆盖范围，可以再引入 Microsoft `krabsetw` 这类成熟 C++ 封装。

该功能不是自研二进制 parser，也不引入必需 CLI 工具依赖。发行包不会捆绑 Sysmon、Procmon、VM 镜像或 Windows SDK 工具。

## 安全边界

只有在满足以下条件时才使用该模式：

- 你理解目标文件会在本机真实执行。
- 当前主机是实验机，或你能接受其被污染。
- 你接受 BinSight 不能阻止持久化、文件修改、联网或其他副作用。

高风险恶意样本仍建议使用专用 VM 或专业沙箱。
