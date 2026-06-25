# 发行版说明

## 版本号

使用这种 tag 格式：

```text
v0.1.0
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
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions 会自动构建并上传：

- `BinSight-v0.1.0-linux-x86_64.tar.gz`
- `BinSight-v0.1.0-windows-x86_64.zip`

## 验收测试

下载发行包后：

Windows：

```powershell
.\bin\binsight.exe --help
.\bin\binsight.exe scan .\sample.exe --provider none --out report.md --json report.json
```

Linux：

```bash
./bin/binsight --help
./bin/binsight scan ./sample --provider none --out report.md --json report.json
docker build -t binsight-observer:latest docker/linux-observer
```

无 API key 时也应该能生成离线规则报告。缺少可选反汇编工具时，只应在报告中出现 warning，不应崩溃。
