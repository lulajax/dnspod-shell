@echo off

rem 切换到 UTF-8 代码页以正确显示中文字符
chcp 65001 > nul

rem #
rem # DNSPod DDNS - Windows 启动脚本
rem #

rem 切换到脚本所在目录
cd /d "%~dp0"

rem 检查 python 是否存在于系统 PATH 中
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo 错误: 未在 PATH 环境变量中找到 python.exe。
    echo 请确保已安装 Python 并将其添加到了系统 PATH。
    pause
    exit /b 1
)

echo 正在使用 python 执行 DDNS 任务...
echo ----------------------------------------

rem --- 配置和执行区 ---
rem
rem 在下方添加或修改行来配置您的域名
rem
rem 用法:
rem python dnspod_ddns.py "主域名" "子域名" [IP版本] [网卡]
rem
rem IP版本:
rem   留空或 "4"  ->  IPv4
rem   "6"        ->  IPv6
rem
rem 示例:
rem python dnspod_ddns.py "example.com" "www"
rem python dnspod_ddns.py "example.com" "ipv6" 6
rem python dnspod_ddns.py "example.com" "nas" 4 "eth0"

python dnspod_ddns.py "77happy.cn" "homepc" 6 "以太网"

rem --- 配置结束 ---

echo ----------------------------------------
echo 所有任务已执行完毕。
rem pause
