# 开发说明

## 目录结构

- `include/binsight/`：项目头文件。
- `src/`：核心实现。
- `tests/`：测试。
- `rules/`：YAML 风格风险规则。
- `knowledge/`：本地 RAG 知识库。
- `docs/`：英文文档。
- `docs/zh-CN/`：中文文档。

## 构建与测试

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

当前原型不依赖第三方 C++ 库，因此能在受限网络环境中构建。后续如果追求更强可维护性，可以逐步替换为：

- CLI11：参数解析。
- yaml-cpp：完整 YAML 支持。
- nlohmann/json：JSON 读写。
- Catch2：测试框架。

## 运行依赖

扫描时会尽量调用以下系统工具：

- `file`
- `readelf`
- `objdump`
- `strings`
- `curl`，仅在 `openai` 或 `ollama` 模式下需要。

工具缺失或解析失败应记录到 `warnings`，不应直接导致程序崩溃。

## Windows 说明

当前原型优先支持 Linux/WSL 环境运行。Windows 用户建议先通过 WSL2 使用 BinSight，详见 [Windows 使用指南](WINDOWS.md)。

原生 Windows 可执行文件不是当前第一版的推荐部署方式，因为 `ProcessRunner` 仍使用 POSIX 的 `popen`、`timeout` 和 `sys/wait.h`，并且扫描链路依赖 `file/readelf/objdump/strings` 这类 Unix/binutils 工具。
