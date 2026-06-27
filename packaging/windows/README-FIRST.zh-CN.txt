BinSight 新手使用说明
======================

1. 请先完整解压 zip，不要直接在压缩包预览窗口里运行。

2. 打开图形界面：
   双击 "打开 BinSight 图形界面.cmd"。
   发行包也包含英文快捷方式 "Open BinSight GUI.lnk"。

3. 扫描文件：
   打开图形界面后，把 .exe 或其他二进制文件拖拽到窗口上方的拖拽区域。
   也可以点击按钮选择文件。

4. 报告输出：
   默认会生成 report.zh-CN.md、report.en.md 和 report.json。
   如果你在 GUI 里设置了输出目录，报告会写到对应目录。

5. 安全提示：
   默认静态扫描不会运行目标文件。
   Windows ETW 专家动态观测会在本机真实运行目标文件，不是沙箱。

高级命令：
   bin\binsight.exe scan path\to\sample.exe
   bin\binsight.exe gui
