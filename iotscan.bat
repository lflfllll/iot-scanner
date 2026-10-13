@echo off
rem IoT Security Scanner 启动脚本 (Windows)
cd /d %~dp0
python iotscan.py %*
pause
