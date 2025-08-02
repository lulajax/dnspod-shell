#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
DNSPod DDNS Script in Python.

This script replaces the original ardnspod shell script with a Python-based solution.
It automatically updates your DNSPod domain records with your current public IP address.
"""

import sys
import os
import re
import json
import logging
import platform
import ipaddress
import hashlib
from pathlib import Path

try:
    import requests
except ImportError:
    print("错误: 'requests' 库未安装。请使用 'pip install requests' 安装。", file=sys.stderr)
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    print("错误: 'python-dotenv' 库未安装。请使用 'pip install python-dotenv' 安装。", file=sys.stderr)
    sys.exit(1)

# --- 配置区 ---

# 从 .env 文件加载 DNSPod Token。脚本将不再直接从此处读取 TOKEN。
# TOKEN = "12345,7676f344eaeaea9074c1234512d"

# 用于查询公网 IP 地址的 API 地址。通常不需要修改。
IP4_QUERY_URL = "http://ipv4.rehi.org/ip"
IP6_QUERY_URL = "http://ipv6.rehi.org/ip"

# 用于存储上一次记录的 IP 的临时文件名前缀。
LAST_RECORD_FILE_PREFIX = "ardnspod_last_record"

# 当 DDNS 记录未发生变化时的退出代码。
# 设置为非 0 值可以与更新成功的情况区分开。
UNCHANGED_EXIT_CODE = 0

try:
    import psutil
except ImportError:
    print("错误: 'psutil' 库未安装。请使用 'pip install psutil' 安装。", file=sys.stderr)
    sys.exit(1)


import argparse

# --- 配置区结束 ---

# 日志设置
logging.basicConfig(level=logging.INFO, format='%(message)s', stream=sys.stderr)
logger = logging.getLogger(__name__)


import tempfile

import socket

import subprocess

class Ddns:
    """
    DNSPod DDNS 更新器
    """
    API_BASE_URL = "https://dnsapi.cn/"
    USER_AGENT = "AnripDdns/6.4.0 Python rewrite"

    def __init__(self, token, ip4_query_url, ip6_query_url, last_record_prefix, unchanged_exit_code):
        self.token = token
        self.ip4_query_url = ip4_query_url
        self.ip6_query_url = ip6_query_url
        self.last_record_prefix = last_record_prefix
        self.unchanged_exit_code = unchanged_exit_code
        # 使用 tempfile 模块获取跨平台兼容的临时目录
        self.temp_dir = Path(tempfile.gettempdir())

    def _api_call(self, endpoint, **data):
        """向 DNSPod API 发送请求"""
        url = self.API_BASE_URL + endpoint
        params = {
            "login_token": self.token,
            "format": "json",
            "lang": "en",
            **data,
        }
        headers = {"User-Agent": self.USER_AGENT}
        try:
            response = requests.post(url, data=params, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"> API 请求失败: {e}")
            return None

    @staticmethod
    def _get_ip_from_url(url):
        """通过 URL 获取公网 IP"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            ip = response.text.strip()
            # 验证IP地址格式是否正确
            ipaddress.ip_address(ip)
            return ip
        except (requests.exceptions.RequestException, ValueError):
            return None

    @staticmethod
    def _is_lan_ip(ip_str):
        """检查是否是局域网/私有IP"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            return False

    def _get_ip_from_psutil(self, interface_name, ip_version):
        """通过 psutil 库获取指定网卡的 IP 地址"""
        try:
            all_addrs = psutil.net_if_addrs()
        except Exception as e:
            return None, f"无法获取网络接口信息: {e}"

        if interface_name not in all_addrs:
            return None, f"找不到网络接口 '{interface_name}'。可用接口: {', '.join(all_addrs.keys())}"

        ip_candidates = []
        target_family = socket.AF_INET6 if ip_version == '6' else socket.AF_INET

        for addr in all_addrs[interface_name]:
            if addr.family == target_family:
                try:
                    ip_str = addr.address.split('%')[0] # 去除 IPv6 的 scope id
                    ip = ipaddress.ip_address(ip_str)
                    # 对于IPv6，我们需要一个非临时的、非本地链接的全局地址
                    # psutil 没有直接提供临时地址的判断，但我们可以筛选出全局地址
                    if ip.is_global:
                         ip_candidates.append(str(ip))
                except ValueError:
                    continue
        
        if ip_candidates:
            # 通常，非临时的全局地址会排在前面
            return ip_candidates[0], f"从 {interface_name} (psutil) 获取"
        
        return None, f"未能在接口 '{interface_name}' 上找到合适的全局 IPv{ip_version} 地址"


    def get_host_ip(self, ip_version="4", interface=None):
        """获取主机 IP 地址"""
        if interface:
            ip, source = self._get_ip_from_psutil(interface, ip_version)
            if ip:
                return ip, source
            # 如果本地查找失败，可以选择继续使用公网查询作为后备
            logger.warning(f"> {source}。将尝试使用公网地址查询。")

        # 未指定网卡或本地查找失败时，使用公网查询
        url = self.ip4_query_url if ip_version == "4" else self.ip6_query_url
        ip = self._get_ip_from_url(url)
        if ip:
            return ip, f"从 {url} 获取"
        
        return None, "无法获取主机IP"


    def get_record(self, domain, sub_domain, record_type):
        """获取记录信息 (ID 和 当前 IP)"""
        params = {"domain": domain, "record_type": record_type}
        if sub_domain != "@":
            params["sub_domain"] = sub_domain
        
        result = self._api_call("Record.List", **params)
        
        if not result or result.get("status", {}).get("code") != "1":
            message = result.get("status", {}).get("message", "未知错误") if result else "请求失败"
            logger.error(f"> 获取记录ID失败: {message}")
            return None, None

        records = [r for r in result.get("records", []) if r.get("name") == sub_domain]
        if not records:
            logger.error(f"> 找不到子域名 '{sub_domain}' 的记录")
            return None, None

        record = records[0]
        return record.get("id"), record.get("value")

    def update_record(self, domain, record_id, sub_domain, record_type, new_ip):
        """更新记录值"""
        params = {
            "domain": domain,
            "record_id": record_id,
            "sub_domain": sub_domain,
            "value": new_ip,
            "record_type": record_type,
            "record_line": "默认",
        }
        
        result = self._api_call("Record.Modify", **params)

        if not result or result.get("status", {}).get("code") != "1":
            message = result.get("status", {}).get("message", "未知错误") if result else "请求失败"
            logger.error(f"> arDdnsUpdate - error: {message}")
            return False, None
        
        updated_ip = result.get("record", {}).get("value")
        return True, updated_ip

    def _get_last_ip_file(self, record_id):
        """获取缓存IP的文件路径"""
        # 使用 record_id 的哈希值以避免文件名过长或包含非法字符
        record_hash = hashlib.md5(str(record_id).encode()).hexdigest()
        return self.temp_dir / f"{self.last_record_prefix}.{record_hash}"

    def get_last_ip(self, record_id):
        """读取缓存的 IP"""
        last_ip_file = self._get_last_ip_file(record_id)
        if last_ip_file.exists():
            return last_ip_file.read_text().strip()
        return None

    def save_last_ip(self, record_id, ip):
        """保存 IP 到缓存文件"""
        last_ip_file = self._get_last_ip_file(record_id)
        try:
            last_ip_file.write_text(ip)
        except IOError as e:
            logger.error(f"> 无法写入缓存文件 {last_ip_file}: {e}")

    def check(self, domain, sub_domain, ip_version="4", interface=None):
        """执行 DDNS 检查和更新"""
        logger.info(f"=== Check {sub_domain}.{domain} ===")
        record_type = "A" if ip_version == "4" else "AAAA"

        logger.info("获取主机 IP")
        host_ip, ip_source = self.get_host_ip(ip_version, interface)
        if not host_ip:
            logger.error(f"> {ip_source}")
            return 1
        logger.info(f"> 主机 IP: {host_ip} ({ip_source})")
        logger.info(f"> 记录类型: {record_type}")

        logger.info("获取域名记录")
        record_id, record_ip = self.get_record(domain, sub_domain, record_type)
        if not record_id:
            return 1
        logger.info(f"> 记录 ID: {record_id}")
        logger.info(f"> 当前记录 IP: {record_ip}")

        last_ip = self.get_last_ip(record_id) or record_ip

        if host_ip == last_ip:
            logger.info(f"> arDdnsUpdate - unchanged: {host_ip}")
            return self.unchanged_exit_code
        
        logger.info("更新记录值")
        success, updated_ip = self.update_record(domain, record_id, sub_domain, record_type, host_ip)
        
        if success:
            logger.info(f"> arDdnsUpdate - updated: {updated_ip}")
            self.save_last_ip(record_id, updated_ip)
            return 0
        
        return 1

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="使用 DNSPod API 更新 DDNS 记录。")
    parser.add_argument("domain", help="主域名，例如 'example.com'")
    parser.add_argument("sub_domain", help="子域名，例如 'www'")
    parser.add_argument("ip_version", nargs='?', default="4", choices=['4', '6'], help="IP 版本 (4 或 6)，默认为 4")
    parser.add_argument("interface", nargs='?', default=None, help="(可选) 用于获取 IP 的网络接口名称")

    args = parser.parse_args()

    load_dotenv()
    token = os.getenv("DNSPOD_TOKEN")

    if not token:
        logger.error("错误: 未找到 DNSPOD_TOKEN。请确保创建了 .env 文件并将您的 Token 放入其中。")
        sys.exit(1)

    ddns = Ddns(
        token=token,
        ip4_query_url=IP4_QUERY_URL,
        ip6_query_url=IP6_QUERY_URL,
        last_record_prefix=LAST_RECORD_FILE_PREFIX,
        unchanged_exit_code=UNCHANGED_EXIT_CODE
    )

    try:
        ret = ddns.check(args.domain, args.sub_domain, args.ip_version, args.interface)
        sys.exit(ret)
    except Exception as e:
        logger.error(f"处理 {args.sub_domain}.{args.domain} 时发生意外错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
