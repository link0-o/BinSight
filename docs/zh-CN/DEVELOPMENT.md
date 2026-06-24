# 开发说明

## 目录结构

- `include/binsight/`：项目头文件。
- `src/`：核心实现。
- `tests/`：单元测试和轻量集成测试。
- `rules/`：YAML 风格风险规则。
- `knowledge/`：本地 RAG 知识库。
- `docs/`：英文文档。
- `docs/zh-CN/`：中文文档。

## Linux 构建

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Windows 构建

安装 Visual Studio 2022，并勾选 C++ 桌面开发工具：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

## 解析依赖

BinSight 遵守[工业组件优先法则](DESIGN_PRINCIPLES.md)。生产级解析应优先选择成熟的可嵌入组件，而不是自研解析代码或必需 CLI 工具依赖。

后续 coding agent 在修改本项目之前必须遵守仓库根目录的 [AGENTS.md](../../AGENTS.md)。该文件是 AI 自动读取的生产红线入口，不是可选贡献文档。

LIEF 是 PE/ELF 解析的优先方向：

```bash
cmake -S . -B build -DBINSIGHT_USE_LIEF=ON
```

当前内置 parser 覆盖第一版需要的最低限度证据：

- ELF/PE 魔数和架构识别。
- PE import directory 解析。
- PE section table 解析。
- ASCII 和 UTF-16LE 字符串提取。

该内置 parser 被归类为 **Temporary / Prototype / Educational Implementation**。它只作为离线或依赖受限环境下的 fallback；只要 LIEF 能满足同类需求，就应迁移到 LIEF-backed parsing。

## 外部工具

运行时会把以下工具当作可选增强：

- `objdump` 或 `llvm-objdump`：提取有限反汇编片段。
- `readelf`：Linux 上补充 ELF 动态元数据。
- `curl`：仅 `openai` 或 `ollama` 模式需要。

工具缺失或解析失败应记录到 `warnings`，不应直接导致程序崩溃。

## 打包

本地生成发行包：

```bash
cmake --build build --target package
```

发行包会包含可执行文件、`rules/`、`knowledge/`、`docs/`、中英文 README 和 `LICENSE`。

## CI

GitHub Actions 会运行：

- Ubuntu 构建和测试。
- Windows 构建和测试。
- CLI help 冒烟测试。

推送 `v*` tag 会触发 release workflow，并发布 Linux/Windows 压缩包。
