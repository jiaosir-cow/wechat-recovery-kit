@echo off
cd /d "%~dp0"
set "PY=python"
where python >/dev/null 2>/dev/null || set "PY=py -3"
echo ==========================================
echo   第1步：解密数据库（自动识别微信 3.x / 4.x）
echo   需要: Python 3.10+ 且 pip install pycryptodome
echo ==========================================
%PY% "tools\decrypt_all.py" %*
if errorlevel 1 (
  echo.
  echo [未完成] 请根据上方提示处理后重试。
  pause
  exit /b 1
)
echo.
echo 全部完成，请继续运行 第2步_扫描已删除记录.bat
pause
