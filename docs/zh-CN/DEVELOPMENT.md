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

## GUI 构建

GUI 是可选的 Qt 6 Widgets 可执行程序。Qt 是桌面界面的工业组件选择：成熟、跨平台、能直接集成 CMake/C++，避免自研窗口系统。GUI 支持中文和英文界面，并且界面语言与报告语言分开选择。

```bash
cmake -S . -B build -DBINSIGHT_BUILD_GUI=AUTO
cmake --build build
```

`BINSIGHT_BUILD_GUI` 支持：

- `AUTO`：找到 Qt 6 Widgets 就构建 `binsight-gui`；找不到就只构建 CLI。
- `ON`：强制要求 Qt 6 Widgets，缺失时配置失败。
- `OFF`：只构建 CLI。

Linux 依赖示例：

```bash
sudo apt-get install qt6-base-dev
```

Windows 开发者可以安装 MSVC 2022 对应的 Qt 6。如果 CMake 不能自动找到 Qt，可以设置 `CMAKE_PREFIX_PATH`。

GUI 必须复用 `binsight_core` 和 `scan_pipeline`，不能重复实现 parser、规则、RAG、LLM 或报告生成逻辑。

## 解析依赖

BinSight 遵守[工业组件优先法则](DESIGN_PRINCIPLES.md)。生产级解析应优先选择成熟的可嵌入组件，而不是自研解析代码或必需 CLI 工具依赖。

LIEF 是 PE/ELF 的生产级主解析路径，并且默认开启：

```bash
cmake -S . -B build -DBINSIGHT_USE_LIEF=ON
```

只有在依赖受限或离线开发构建时，才使用：

```bash
cmake -S . -B build -DBINSIGHT_USE_LIEF=OFF
```

fallback parser 在 LIEF 不可用时覆盖最低限度证据：

- ELF/PE 魔数和架构识别。
- PE import directory 解析。
- PE section table 解析。
- ASCII 和 UTF-16LE 字符串提取。

该内置 parser 被归类为 **Temporary / Prototype / Educational Implementation**。它只作为离线或依赖受限环境下的 fallback；只要 LIEF 能满足同类需求，就不能把它当作生产级 parser。

## 外部工具

运行时会把以下工具当作可选增强：

- `objdump` 或 `llvm-objdump`：提取有限反汇编片段。
- `curl`：仅 `openai` 或 `ollama` 模式需要。
- `docker`：仅显式执行 `observe linux-docker` 时需要。

工具缺失或解析失败应记录到 `warnings`，不应直接导致程序崩溃。

## Linux Docker 动态观测

构建轻量 observer 镜像：

```bash
docker build -t binsight-observer:latest docker/linux-observer
```

只有显式接受风险时才运行：

```bash
./build/binsight observe linux-docker ./sample --out dynamic.json --i-understand-risk
./build/binsight scan ./sample --dynamic-report dynamic.json
```

该模式**不是**恶意软件级别沙箱。它使用 Docker、`strace`、默认禁网和资源限制来采集轻量运行时证据。

## 打包

本地生成发行包：

```bash
cmake --build build --target package
```

发行包会包含可执行文件、`rules/`、`knowledge/`、`docs/`、`docker/`、中英文 README 和 `LICENSE`。
如果打包时 Qt 可用，发行包还会包含 `binsight-gui` / `binsight-gui.exe`。

## CI

GitHub Actions 会运行：

- Ubuntu 构建和测试。
- Windows 构建和测试。
- CLI help 冒烟测试。
- Qt 可用时构建 GUI，并运行 `binsight-gui --help` 冒烟测试。

推送 `v*` tag 会触发 release workflow，并发布 Linux/Windows 压缩包。
