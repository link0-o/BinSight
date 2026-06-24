# Windows 使用指南

## 一句话版本

你现在要做的不是把 BinSight 编译成 Windows 原生程序，而是：

```text
在 Windows 安装 WSL2
在 WSL 里编译 BinSight
用 WSL 路径 /mnt/c/... 去扫描 Windows 里的 exe/dll
```

例如 Windows 文件：

```text
C:\Users\link\Downloads\sample.exe
```

在 WSL 里对应：

```text
/mnt/c/Users/link/Downloads/sample.exe
```

当前 BinSight 最推荐的 Windows 使用方式是：

```text
Windows 机器
  -> 安装 WSL2 Ubuntu/Debian
  -> 在 WSL 里构建和运行 BinSight
  -> 通过 /mnt/c/... 扫描 Windows 上的 .exe/.dll 文件
```

也就是说，第一版不是直接生成原生 `binsight.exe`，而是在 Windows 上用 WSL 跑 Linux 版 BinSight 来分析 PE 文件。

## 为什么推荐 WSL

BinSight 当前扫描链路依赖这些工具：

- `file`
- `readelf`
- `objdump`
- `strings`
- `curl`，仅模型接口模式需要

代码里的 `ProcessRunner` 当前也使用 POSIX 能力，例如 `popen`、`timeout` 和 `sys/wait.h`。这些在 WSL/Linux 下直接可用，但在原生 Windows 下需要额外适配。

## 1. 安装 WSL

在 Windows PowerShell 里执行：

```powershell
wsl --install
```

安装完成后重启电脑，并打开 Ubuntu 或 Debian 终端。

如果你已经装过 WSL，可以查看：

```powershell
wsl -l -v
```

## 2. 在 WSL 里安装依赖

Ubuntu/Debian WSL 里执行：

```bash
sudo apt update
sudo apt install -y git cmake ninja-build g++ binutils file curl
```

如果你的发行版没有 `ninja-build`，可以先只用 Makefile：

```bash
sudo apt install -y git cmake g++ binutils file curl
```

然后构建时去掉 `-G Ninja`。

## 3. 拉取项目

```bash
git clone https://github.com/link0-o/BinSight.git
cd BinSight
```

如果你已经在 Windows 里 clone 了仓库，也可以在 WSL 里进入 Windows 目录，例如：

```bash
cd /mnt/c/Users/<你的用户名>/code/BinSight
```

但更推荐把代码放在 WSL 自己的 Linux 文件系统里，构建会更快。

## 4. 构建 BinSight

使用 Ninja：

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

如果没有 Ninja：

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## 5. 找到要扫描的 Windows 文件

Windows 的 `C:\` 盘在 WSL 中通常是：

```text
/mnt/c/
```

常见路径转换：

```text
C:\Users\你的用户名\Downloads\sample.exe
```

变成：

```text
/mnt/c/Users/你的用户名/Downloads/sample.exe
```

如果路径里有空格，命令里要加引号。

## 6. 离线扫描 Windows exe/dll

例如扫描下载目录里的程序：

```bash
./build/binsight scan "/mnt/c/Users/<你的用户名>/Downloads/sample.exe" \
  --provider none \
  --rules-dir ./rules \
  --knowledge-dir ./knowledge \
  --out report.md \
  --json report.json
```

扫描 DLL：

```bash
./build/binsight scan "/mnt/c/Users/<你的用户名>/Downloads/sample.dll" \
  --provider none \
  --rules-dir ./rules \
  --knowledge-dir ./knowledge \
  --out report.md \
  --json report.json
```

生成的 `report.md` 和 `report.json` 会出现在你运行命令的当前目录。

如果你只是想先确认工具能跑，就用这个模式。`--provider none` 不需要 API key，也不会联网。

## 7. 使用 DeepSeek 分析

DeepSeek 使用 OpenAI 兼容接口，所以仍然使用 `--provider openai`：

```bash
export DEEPSEEK_API_KEY=你的_key

./build/binsight scan "/mnt/c/Users/<你的用户名>/Downloads/sample.exe" \
  --provider openai \
  --base-url https://api.deepseek.com \
  --model deepseek-v4-flash \
  --api-key-env DEEPSEEK_API_KEY \
  --rules-dir ./rules \
  --knowledge-dir ./knowledge \
  --out report.md \
  --json report.json
```

如果只是先验证扫描链路，优先用 `--provider none`，不用 API key，也不会产生模型费用。

## 8. 推荐部署方式

第一版最小部署包：

```text
binsight
rules/default-rules.yaml
knowledge/*.md
```

可以在 WSL 里打包：

```bash
mkdir -p dist/rules dist/knowledge
cp build/binsight dist/
cp rules/default-rules.yaml dist/rules/
cp knowledge/*.md dist/knowledge/
```

运行：

```bash
cd dist

./binsight scan "/mnt/c/Users/<你的用户名>/Downloads/sample.exe" \
  --provider none \
  --rules-dir ./rules \
  --knowledge-dir ./knowledge \
  --out report.md \
  --json report.json
```

## 原生 Windows 支持计划

如果后续要做真正的 `binsight.exe`，需要补这些工作：

- 把 `ProcessRunner` 改成跨平台实现：Windows 下使用 `_popen` 或 Win32 Process API。
- 移除 Linux `timeout` 命令依赖，改成 C++/Win32 超时控制。
- 替换 `sys/wait.h`。
- 明确 Windows 下使用 MSYS2/MinGW binutils、LLVM 工具链，或内置 PE 解析器。
- 为 `file/readelf/objdump/strings` 做工具发现和错误提示。

因此当前建议是：先用 WSL 跑通扫描和报告，再把原生 Windows 支持作为后续里程碑。

## 常见问题

### 我是不是需要一个 Windows 版 binsight.exe？

当前不需要。第一版推荐在 WSL 里运行 `./build/binsight`，它可以扫描 Windows 磁盘里的 `.exe/.dll`。

### 我扫描的是 Windows exe，为什么还要在 Linux/WSL 里跑？

因为 PE 文件格式可以在 Linux 工具链下解析。BinSight 当前依赖 `objdump`、`strings`、`file` 等工具，WSL 里这些工具最容易安装和运行。

### report.md 在哪里？

在你运行命令的当前目录。比如你在 `~/BinSight` 里运行命令，报告就在：

```text
~/BinSight/report.md
~/BinSight/report.json
```

### 路径提示找不到文件怎么办？

先在 WSL 里检查文件是否存在：

```bash
ls "/mnt/c/Users/<你的用户名>/Downloads/sample.exe"
```

如果 `ls` 都找不到，说明路径写错了。
