#!/bin/sh
#
# DNSPod DDNS - 启动脚本
#
# 确保此脚本有执行权限: chmod +x run.sh
#

cd "$(dirname "$0")" || exit 1

# 寻找可用的 python 命令
PYTHON_CMD="python3"
if ! command -v $PYTHON_CMD >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

if ! command -v $PYTHON_CMD >/dev/null 2>&1; then
    echo "错误: 未找到 python 或 python3 命令。"
    exit 1
fi

echo "使用 $PYTHON_CMD 执行 DDNS 任务..."
echo "----------------------------------------"

# --- 配置和执行区 ---
#
# 在下方添加或修改行来配置您的域名
#
# 用法:
# $PYTHON_CMD dnspod_ddns.py "主域名" "子域名" [IP版本] [网卡]
#
# IP版本:
#   留空或 "4"  ->  IPv4
#   "6"        ->  IPv6
#
# 示例:
# $PYTHON_CMD dnspod_ddns.py "example.com" "www"
# $PYTHON_CMD dnspod_ddns.py "example.com" "ipv6" 6
# $PYTHON_CMD dnspod_ddns.py "example.com" "nas" 4 "eth0"

$PYTHON_CMD dnspod_ddns.py "77happy.cn" "homepc" 6

# --- 配置结束 ---

echo "----------------------------------------"
echo "所有任务已执行完毕。"
