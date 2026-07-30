@echo off
cd /d "%~dp0"
set "PY=python"
where python >/dev/null 2>/dev/null || set "PY=py -3"
echo ==========================================
echo   第2步：扫描已删除记录并搜索关键词
echo ==========================================
%PY% "tools\scan_all.py" %*
if errorlevel 1 (
  echo.
  echo [未完成] 请根据上方提示处理后重试。
  pause
  exit /b 1
)
echo.
echo 完成，打开 04_恢复输出\搜索结果.txt 查看。
pause
