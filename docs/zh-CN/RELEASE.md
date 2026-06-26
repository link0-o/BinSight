# 发行版说明

## 版本号

使用这种 tag 格式：

```text
v0.2.0
```

创建新发行版前，应先更新 CMake 项目版本号。

## 本地打包

配置、构建和测试：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

生成压缩包：

```bash
cmake --build build --target package
```

压缩包内容包括：

- `bin/binsight` 或 `bin/binsight.exe`
- 打包时 Qt 可用则包含 `bin/binsight-gui` 或 `bin/binsight-gui.exe`
- Windows GUI 发行包会使用 Qt 官方 `windeployqt` 部署所需 Qt 运行时 DLL
- `rules/`
- `knowledge/`
- `docs/`
- `docker/`
- `README.md`
- `README.zh-CN.md`
- `LICENSE`

## GitHub 自动发布

创建并推送 tag：

```bash
git tag v0.2.0
git push origin v0.2.0
```

GitHub Actions 会自动构建并上传：

- `BinSight-v0.2.0-linux-x86_64.tar.gz`
- `BinSight-v0.2.0-windows-x86_64.zip`

Windows Release job 会检查 GUI 包里是否包含 `Qt6Core.dll`、`Qt6Widgets.dll` 和 `platforms/qwindows.dll`。

## 验收测试

下载发行包后：

Windows：

```powershell
.\bin\binsight.exe --help
.\bin\binsight.exe gui
.\bin\binsight.exe scan .\sample.exe --provider none --out report.md --json report.json
```

Linux：

```bash
./bin/binsight --help
./bin/binsight gui
./bin/binsight scan ./sample --provider none --out report.md --json report.json
docker build -t binsight-observer:latest docker/linux-observer
```

无 API key 时也应该能生成离线规则报告。缺少可选反汇编工具时，只应在报告中出现 warning，不应崩溃。
Linux 服务器没有图形会话时，`binsight gui` 应输出 CLI 降级提示。如果打包时没有 Qt，`binsight gui` 应提示 GUI 组件未安装。
