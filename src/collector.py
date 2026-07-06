"""
免费节点抓取器 - 主程序
从多个公开免费节点源抓取 V2Ray/Trojan/SS 节点和 Clash 订阅链接
"""

import os
import re
import sys
import time
import json
import base64
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import requests

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# 输出目录
OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "2026免费节点"
)

# 中国时区
CST = timezone(timedelta(hours=8))


# ============================================================
# 节点源配置
# ============================================================
# 每个源包含：名称、URL、类型（base64/raw/clash）
SOURCES = [
    # --- V2Ray/Trojan/SS 订阅源（base64编码） ---
    {
        "name": "freefq/free",
        "url": "https://raw.githubusercontent.com/freefq/free/master/v2",
        "type": "base64",
    },
    {
        "name": "Pawdroid/Free-servers",
        "url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
        "type": "base64",
    },
    {
        "name": "aiboboxx/kremlin",
        "url": "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
        "type": "base64",
    },
    {
        "name": "mahdibland/V2RayAggregator",
        "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
        "type": "base64",
    },
    {
        "name": "yebekhe/TVC",
        "url": "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64/mix",
        "type": "base64",
    },
    {
        "name": "barry-far/V2ray-Configs",
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
        "type": "base64",
    },
    {
        "name": "mfuu/v2ray",
        "url": "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
        "type": "base64",
    },
    {
        "name": "peasoft/NoMoreWalls",
        "url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
        "type": "raw",
    },
    # --- Clash 订阅源 ---
    {
        "name": "freefq/clash",
        "url": "https://raw.githubusercontent.com/freefq/free/master/clash",
        "type": "clash",
    },
    {
        "name": "Pawdroid/clash",
        "url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/clash",
        "type": "clash",
    },
    {
        "name": "aiboboxx/clash",
        "url": "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/clash",
        "type": "clash",
    },
    {
        "name": "yebekhe/clash",
        "url": "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/clash/mix",
        "type": "clash",
    },
    {
        "name": "mfuu/clash",
        "url": "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
        "type": "clash",
    },
]

# 请求配置
REQUEST_TIMEOUT = 30
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


# ============================================================
# 节点解析工具
# ============================================================


def decode_base64(text: str) -> str:
    """解码base64文本，自动补齐padding"""
    try:
        padding = 4 - len(text) % 4
        if padding != 4:
            text += "=" * padding
        return base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def parse_vmess_link(link: str) -> Optional[Dict]:
    """解析 vmess:// 链接"""
    try:
        data = link.replace("vmess://", "")
        decoded = decode_base64(data)
        if not decoded:
            return None
        info = json.loads(decoded)
        return {
            "type": "vmess",
            "ps": info.get("ps", ""),
            "add": info.get("add", ""),
            "port": info.get("port", ""),
            "id": info.get("id", ""),
            "aid": info.get("aid", ""),
            "net": info.get("net", ""),
            "type": info.get("type", ""),
            "host": info.get("host", ""),
            "path": info.get("path", ""),
            "tls": info.get("tls", ""),
            "raw": link.strip(),
        }
    except Exception:
        return None


def parse_vless_link(link: str) -> Optional[Dict]:
    """解析 vless:// 链接"""
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        return {
            "type": "vless",
            "ps": params.get("name", [""])[0],
            "add": parsed.hostname or "",
            "port": parsed.port or "",
            "id": parsed.username or "",
            "net": params.get("type", [""])[0],
            "host": params.get("sni", [""])[0],
            "path": params.get("path", [""])[0],
            "tls": params.get("security", [""])[0],
            "raw": link.strip(),
        }
    except Exception:
        return None


def parse_trojan_link(link: str) -> Optional[Dict]:
    """解析 trojan:// 链接"""
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        return {
            "type": "trojan",
            "ps": params.get("name", [""])[0] or parsed.fragment,
            "add": parsed.hostname or "",
            "port": parsed.port or "",
            "id": parsed.username or "",
            "net": params.get("type", [""])[0],
            "host": params.get("sni", [""])[0],
            "path": params.get("path", [""])[0],
            "tls": "tls"
            if params.get("security", [""])[0] in ("tls", "")
            else params.get("security", [""])[0],
            "raw": link.strip(),
        }
    except Exception:
        return None


def parse_ss_link(link: str) -> Optional[Dict]:
    """解析 ss:// 链接"""
    try:
        data = link.replace("ss://", "")
        # ss://method:password@host:port#name 格式
        if "@" in data:
            main_part, name = (data.split("#", 1) + [""])[:2]
            if ":" in main_part.split("@")[0]:
                # method:password@host:port
                userinfo, server = main_part.rsplit("@", 1)
                method, password = userinfo.split(":", 1)
            else:
                # base64@host:port
                encoded, server = main_part.rsplit("@", 1)
                decoded = decode_base64(encoded)
                if not decoded or ":" not in decoded:
                    return None
                method, password = decoded.split(":", 1)
            return {
                "type": "ss",
                "ps": name,
                "add": server.split(":")[0] if ":" in server else server,
                "port": server.split(":")[1] if ":" in server else "",
                "id": password,
                "method": method,
                "raw": link.strip(),
            }
        else:
            # ss://base64#name 格式
            encoded, name = (data.split("#", 1) + [""])[:2]
            decoded = decode_base64(encoded)
            if not decoded or "@" not in decoded:
                return None
            userinfo, server = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            return {
                "type": "ss",
                "ps": name,
                "add": server.split(":")[0],
                "port": server.split(":")[1] if ":" in server else "",
                "id": password,
                "method": method,
                "raw": link.strip(),
            }
    except Exception:
        return None


def parse_ssr_link(link: str) -> Optional[Dict]:
    """解析 ssr:// 链接"""
    try:
        data = link.replace("ssr://", "")
        decoded = decode_base64(data)
        if not decoded:
            return None
        # server:port:protocol:method:obfs:base64pass/?...
        parts = decoded.split("/?", 1)
        main = parts[0]
        server_info = main.split(":")
        if len(server_info) < 6:
            return None
        return {
            "type": "ssr",
            "ps": "",
            "add": server_info[0],
            "port": server_info[1],
            "method": server_info[3],
            "raw": link.strip(),
        }
    except Exception:
        return None


def parse_hysteria2_link(link: str) -> Optional[Dict]:
    """解析 hysteria2:// 链接"""
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        return {
            "type": "hysteria2",
            "ps": params.get("name", [""])[0] or parsed.fragment,
            "add": parsed.hostname or "",
            "port": parsed.port or "",
            "id": parsed.username or "",
            "host": params.get("sni", [""])[0],
            "raw": link.strip(),
        }
    except Exception:
        return None


# 节点解析映射
PARSERS = {
    "vmess": parse_vmess_link,
    "vless": parse_vless_link,
    "trojan": parse_trojan_link,
    "ss": parse_ss_link,
    "ssr": parse_ssr_link,
    "hysteria2": parse_hysteria2_link,
}


def parse_single_link(link: str) -> Optional[Dict]:
    """解析单个节点链接"""
    link = link.strip()
    if not link:
        return None
    for proto, parser in PARSERS.items():
        if link.startswith(f"{proto}://"):
            return parser(link)
    return None


def parse_links(text: str) -> List[Dict]:
    """从文本中提取并解析所有节点链接"""
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        node = parse_single_link(line)
        if node:
            nodes.append(node)
    return nodes


def deduplicate_nodes(nodes: List[Dict]) -> List[Dict]:
    """去重：基于类型+地址+端口"""
    seen = set()
    result = []
    for node in nodes:
        key = f"{node.get('type', '')}:{node.get('add', '')}:{node.get('port', '')}"
        if key not in seen and node.get("add") and node.get("port"):
            seen.add(key)
            result.append(node)
    return result


def filter_nodes(nodes: List[Dict]) -> List[Dict]:
    """过滤无效节点"""
    result = []
    for node in nodes:
        add = node.get("add", "")
        port = node.get("port", "")
        # 过滤空地址/端口、局域网地址
        if not add or not port:
            continue
        if add in ("127.0.0.1", "0.0.0.0", "localhost"):
            continue
        if add.startswith(
            (
                "10.",
                "192.168.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.2",
                "172.3",
            )
        ):
            continue
        try:
            port_int = int(port)
            if port_int < 1 or port_int > 65535:
                continue
        except (ValueError, TypeError):
            continue
        result.append(node)
    return result


# ============================================================
# 数据抓取
# ============================================================


def fetch_url(url: str, timeout: int = REQUEST_TIMEOUT) -> Optional[str]:
    """请求URL并返回文本内容"""
    try:
        resp = requests.get(url, headers=REQUEST_HEADERS, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        logger.warning(f"请求失败: {url} - {e}")
        return None


def fetch_source(source: Dict) -> Tuple[List[Dict], List[str]]:
    """抓取单个数据源，返回 (节点列表, clash原始内容列表)"""
    name = source["name"]
    url = source["url"]
    source_type = source["type"]

    logger.info(f"正在抓取: {name} ({url})")
    content = fetch_url(url)
    if not content:
        logger.warning(f"跳过空源: {name}")
        return [], []

    nodes = []
    clash_raw = []

    if source_type == "base64":
        decoded = decode_base64(content.strip())
        if decoded:
            nodes = parse_links(decoded)
        else:
            # 解码失败，尝试当raw处理
            nodes = parse_links(content)
    elif source_type == "raw":
        nodes = parse_links(content)
    elif source_type == "clash":
        clash_raw.append(content)
        # 也尝试从clash配置中提取节点链接
        nodes = extract_from_clash(content)

    logger.info(f"  {name}: 获取 {len(nodes)} 个节点, {len(clash_raw)} 个Clash配置")
    return nodes, clash_raw


def extract_from_clash(clash_text: str) -> List[Dict]:
    """从Clash YAML中提取代理信息（简易解析）"""
    nodes = []
    try:
        import yaml

        config = yaml.safe_load(clash_text)
        proxies = config.get("proxies", [])
        for p in proxies:
            ptype = p.get("type", "")
            name = p.get("name", "")
            server = p.get("server", "")
            port = p.get("port", "")
            if server and port:
                # 构建通用节点字典
                node = {
                    "type": ptype,
                    "ps": name,
                    "add": server,
                    "port": str(port),
                    "raw": f"{ptype}://{server}:{port}",
                    "from_clash": True,
                    # 保留原始Clash代理数据
                    "clash_proxy": p,
                }
                nodes.append(node)
    except ImportError:
        logger.warning("未安装PyYAML，跳过Clash YAML解析")
    except Exception as e:
        logger.warning(f"Clash YAML解析失败: {e}")
    return nodes


# ============================================================
# 输出文件生成
# ============================================================


def generate_v2ray_sub(nodes: List[Dict]) -> str:
    """生成V2Ray订阅内容（base64编码）"""
    lines = [node["raw"] for node in nodes if node.get("raw")]
    content = "\n".join(lines)
    return base64.b64encode(content.encode("utf-8")).decode("utf-8")


def generate_clash_config(nodes: List[Dict], clash_raws: List[str]) -> str:
    """生成Clash配置文件"""
    try:
        import yaml
    except ImportError:
        return ""

    proxies = []
    proxy_names = []

    # 从Clash原始配置中提取代理
    for raw in clash_raws:
        try:
            config = yaml.safe_load(raw)
            if config and "proxies" in config:
                for p in config["proxies"]:
                    name = p.get("name", "")
                    if name and name not in proxy_names:
                        proxies.append(p)
                        proxy_names.append(name)
        except Exception:
            continue

    # 从节点列表构建Clash代理
    for node in nodes:
        if node.get("from_clash") and node.get("clash_proxy"):
            # 已有Clash格式数据
            p = node["clash_proxy"]
            name = p.get("name", "")
            if name and name not in proxy_names:
                proxies.append(p)
                proxy_names.append(name)
            continue

        ptype = node.get("type", "")
        name = (
            node.get("ps", "")
            or f"{ptype}-{node.get('add', '')}-{node.get('port', '')}"
        )
        if name in proxy_names:
            continue

        server = node.get("add", "")
        port = node.get("port", "")

        if ptype == "vmess":
            p = {
                "name": name,
                "type": "vmess",
                "server": server,
                "port": int(port),
                "uuid": node.get("id", ""),
                "alterId": int(node.get("aid", 0)),
                "cipher": "auto",
                "udp": True,
                "network": node.get("net", "tcp"),
            }
            if node.get("tls") == "tls":
                p["tls"] = True
                if node.get("host"):
                    p["servername"] = node["host"]
            if node.get("net") == "ws":
                p["ws-opts"] = {}
                if node.get("path"):
                    p["ws-opts"]["path"] = node["path"]
                if node.get("host"):
                    p["ws-opts"]["headers"] = {"Host": node["host"]}
            elif node.get("net") == "grpc":
                p["grpc-opts"] = {}
                if node.get("path"):
                    p["grpc-opts"]["grpc-service-name"] = node["path"]
            proxies.append(p)
            proxy_names.append(name)

        elif ptype == "vless":
            p = {
                "name": name,
                "type": "vless",
                "server": server,
                "port": int(port),
                "uuid": node.get("id", ""),
                "udp": True,
                "network": node.get("net", "tcp"),
                "tls": node.get("tls") in ("tls", "reality"),
            }
            if node.get("host"):
                p["servername"] = node["host"]
            if node.get("net") == "ws":
                p["ws-opts"] = {}
                if node.get("path"):
                    p["ws-opts"]["path"] = node["path"]
                if node.get("host"):
                    p["ws-opts"]["headers"] = {"Host": node["host"]}
            elif node.get("net") == "grpc":
                p["grpc-opts"] = {}
                if node.get("path"):
                    p["grpc-opts"]["grpc-service-name"] = node["path"]
            proxies.append(p)
            proxy_names.append(name)

        elif ptype == "trojan":
            p = {
                "name": name,
                "type": "trojan",
                "server": server,
                "port": int(port),
                "password": node.get("id", ""),
                "udp": True,
            }
            if node.get("host"):
                p["sni"] = node["host"]
            proxies.append(p)
            proxy_names.append(name)

        elif ptype == "ss":
            p = {
                "name": name,
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": node.get("method", "aes-256-gcm"),
                "password": node.get("id", ""),
                "udp": True,
            }
            proxies.append(p)
            proxy_names.append(name)

        elif ptype == "ssr":
            p = {
                "name": name,
                "type": "ssr",
                "server": server,
                "port": int(port),
                "cipher": node.get("method", "aes-256-cfb"),
                "password": node.get("id", ""),
                "udp": True,
            }
            proxies.append(p)
            proxy_names.append(name)

        elif ptype == "hysteria2":
            p = {
                "name": name,
                "type": "hysteria2",
                "server": server,
                "port": int(port),
                "password": node.get("id", ""),
                "udp": True,
            }
            if node.get("host"):
                p["sni"] = node["host"]
            proxies.append(p)
            proxy_names.append(name)

    if not proxies:
        return ""

    # 构建完整Clash配置
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "nameserver": [
                "223.5.5.5",
                "119.29.29.29",
            ],
            "fallback": [
                "8.8.8.8",
                "1.1.1.1",
            ],
        },
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "DIRECT"] + proxy_names,
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "proxies": proxy_names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
            },
            {
                "name": "🎯 全球直连",
                "type": "select",
                "proxies": ["DIRECT", "🚀 节点选择"],
            },
            {
                "name": "🛑 全球拦截",
                "type": "select",
                "proxies": ["REJECT", "DIRECT"],
            },
        ],
        "rules": [
            "DOMAIN-SUFFIX,local,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT",
            "IP-CIDR,172.16.0.0/12,DIRECT",
            "IP-CIDR,192.168.0.0/16,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "GEOIP,CN,🎯 全球直连",
            "MATCH,🚀 节点选择",
        ],
    }

    return yaml.dump(
        config, allow_unicode=True, default_flow_style=False, sort_keys=False
    )


def save_output(nodes: List[Dict], clash_raws: List[str], output_dir: str):
    """保存输出文件"""
    os.makedirs(output_dir, exist_ok=True)

    now = datetime.now(CST)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    # 统计
    type_counts = {}
    for node in nodes:
        t = node.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    logger.info(f"去重后节点总数: {len(nodes)}")
    for t, c in sorted(type_counts.items()):
        logger.info(f"  {t}: {c}")

    # 1. V2Ray订阅文件 (base64)
    v2ray_content = generate_v2ray_sub(nodes)
    v2ray_path = os.path.join(output_dir, "v2ray")
    with open(v2ray_path, "w", encoding="utf-8") as f:
        f.write(v2ray_content)
    logger.info(f"已保存 V2Ray 订阅: {v2ray_path} ({len(nodes)} 个节点)")

    # 2. Clash配置文件
    clash_content = generate_clash_config(nodes, clash_raws)
    if clash_content:
        clash_path = os.path.join(output_dir, "clash.yaml")
        with open(clash_path, "w", encoding="utf-8") as f:
            f.write(clash_content)
        logger.info(f"已保存 Clash 配置: {clash_path}")

    # 3. 节点明细 (可读)
    detail_path = os.path.join(output_dir, "nodes.txt")
    with open(detail_path, "w", encoding="utf-8") as f:
        f.write(f"# 免费节点列表 - 更新时间: {timestamp}\n")
        f.write(f"# 总计: {len(nodes)} 个节点\n")
        f.write(
            f"# 类型: {', '.join(f'{t}({c})' for t, c in sorted(type_counts.items()))}\n"
        )
        f.write("#" + "=" * 60 + "\n\n")
        for i, node in enumerate(nodes, 1):
            f.write(
                f"[{i}] {node.get('type', '?').upper()} - {node.get('ps', 'N/A')}\n"
            )
            f.write(f"    地址: {node.get('add', '?')}:{node.get('port', '?')}\n")
            if node.get("net"):
                f.write(f"    传输: {node.get('net', '')}\n")
            if node.get("tls"):
                f.write(f"    TLS: {node.get('tls', '')}\n")
            f.write(f"    原始: {node.get('raw', '')[:100]}...\n\n")
    logger.info(f"已保存节点明细: {detail_path}")

    # 4. 更新信息
    info_path = os.path.join(output_dir, "update_info.json")
    info = {
        "update_time": timestamp,
        "total_nodes": len(nodes),
        "type_counts": type_counts,
        "sources_count": len(SOURCES),
    }
    with open(info_path, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)

    return len(nodes)


# ============================================================
# 主流程
# ============================================================


def main():
    logger.info("=" * 60)
    logger.info("免费节点抓取器 启动")
    logger.info(f"数据源: {len(SOURCES)} 个")
    logger.info("=" * 60)

    all_nodes = []
    all_clash_raws = []
    success_count = 0
    fail_count = 0

    for source in SOURCES:
        try:
            nodes, clash_raws = fetch_source(source)
            all_nodes.extend(nodes)
            all_clash_raws.extend(clash_raws)
            success_count += 1
        except Exception as e:
            logger.error(f"抓取异常: {source['name']} - {e}")
            fail_count += 1
        # 礼貌延迟
        time.sleep(1)

    logger.info(f"抓取完成: 成功 {success_count}, 失败 {fail_count}")
    logger.info(f"原始节点总数: {len(all_nodes)}")

    # 过滤 + 去重
    all_nodes = filter_nodes(all_nodes)
    all_nodes = deduplicate_nodes(all_nodes)
    logger.info(f"过滤+去重后: {len(all_nodes)} 个节点")

    # 保存输出
    count = save_output(all_nodes, all_clash_raws, OUTPUT_DIR)

    logger.info("=" * 60)
    logger.info(f"完成! 共输出 {count} 个有效节点")
    logger.info("=" * 60)

    return 0 if count > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
