BinSight Quick Start
====================

1. Extract the full zip first. Do not run BinSight from inside the zip preview window.

2. Open the graphical interface:
   Double-click "Open BinSight GUI.lnk".
   If the shortcut is unavailable, double-click "Open BinSight GUI.cmd".

3. Scan a file:
   Open the GUI, then drag an .exe or another binary file onto the drop area at the top.
   You can also choose a file with the file picker.

4. Report output:
   BinSight writes report.zh-CN.md, report.en.md, and report.json by default.
   If you configured an output directory in the GUI, reports are written there.

5. Safety:
   Static scans do not execute the target file.
   Windows ETW expert observation runs the target on the local host and is not a sandbox.

Advanced commands:
   bin\binsight.exe scan path\to\sample.exe
   bin\binsight.exe gui
