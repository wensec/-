#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import aiodns
import random
import string
import argparse
import time
from colorama import init, Fore, Style


class WildcardDNSTester:
    """对抗泛解析检测工具"""

    def __init__(self, domain, threads=10, timeout=5,
                 random_count=20, use_custom_resolvers=True):
        # 初始化参数
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.random_count = random_count
        self.results = []
        self.ip_groups = {}
        self.is_wildcard = False
        self.confidence = 0.0
        self.custom_resolvers = [
            "8.8.8.8",  # Google DNS
            "1.1.1.1",  # Cloudflare DNS
            "9.9.9.9",  # Quad9 DNS
            "208.67.222.222",  # OpenDNS
        ] if use_custom_resolvers else []

        # 初始化彩色输出
        init(autoreset=True)

        # 不在这里创建解析器，而是在运行时创建，确保使用正确的事件循环
        self.resolver = None

    async def init_resolver(self):
        """在事件循环中初始化解析器"""
        self.resolver = aiodns.DNSResolver(timeout=self.timeout)
        if self.custom_resolvers:
            self.resolver.nameservers = self.custom_resolvers

    async def query(self, subdomain, record_type="A"):
        """执行异步DNS查询"""
        try:
            # 构造完整域名
            full_domain = f"{subdomain}.{self.domain}" if subdomain else self.domain
            # 执行查询
            answers = await self.resolver.query(full_domain, record_type)
            # 提取IP地址或CNAME
            if record_type == "A":
                return [answer.host for answer in answers]
            elif record_type == "CNAME":
                return [answer.cname for answer in answers]
            else:
                return [str(answer) for answer in answers]
        except aiodns.error.DNSError as e:
            # 处理常见错误类型
            if e.args[0] == aiodns.error.ARES_ENOTFOUND:  # NXDOMAIN
                return None
            elif e.args[0] == aiodns.error.ARES_ETIMEOUT:  # 超时
                return "TIMEOUT"
            else:
                return f"ERROR: {e}"
        except Exception as e:
            return f"UNEXPECTED_ERROR: {str(e)}"

    def generate_random_subdomain(self, length=None):
        """生成随机子域名"""
        if length is None:
            length = random.randint(12, 24)  # 随机长度12-24个字符
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    async def check_wildcard(self):
        """检测泛解析配置"""
        # 先初始化解析器，确保在正确的事件循环中
        await self.init_resolver()

        print(f"{Fore.CYAN}[+] 正在检测域名 {self.domain} 是否配置泛解析...")

        # 1. 查询主域名的A记录
        print(f"{Fore.YELLOW}[*] 查询主域名 A 记录...")
        main_domain_ips = await self.query("", "A")
        if main_domain_ips is None:
            print(f"{Fore.RED}[-] 主域名 {self.domain} 不存在或无法解析")
            return False
        elif isinstance(main_domain_ips, str):
            print(f"{Fore.RED}[-] 查询主域名时出错: {main_domain_ips}")
            return False
        else:
            print(f"{Fore.GREEN}[+] 主域名 A 记录: {', '.join(main_domain_ips)}")

        # 2. 生成随机子域名并查询
        print(f"{Fore.YELLOW}[*] 生成 {self.random_count} 个随机子域名进行测试...")
        random_subdomains = [self.generate_random_subdomain() for _ in range(self.random_count)]

        # 3. 并发查询所有随机子域名
        tasks = []
        for subdomain in random_subdomains:
            tasks.append(self.query(subdomain, "A"))

        # 执行查询并收集结果
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        elapsed_time = time.time() - start_time

        # 4. 分析结果
        resolved_count = 0
        unique_ips = set()

        for i, (subdomain, ips) in enumerate(zip(random_subdomains, results)):
            if ips is None:
                status = f"{Fore.GREEN}NXDOMAIN"
            elif ips == "TIMEOUT":
                status = f"{Fore.RED}TIMEOUT"
            elif isinstance(ips, str):
                status = f"{Fore.RED}{ips}"
            else:
                resolved_count += 1
                status = f"{Fore.YELLOW}{', '.join(ips)}"
                for ip in ips:
                    unique_ips.add(ip)

            # 分组统计IP出现次数
            if isinstance(ips, list):
                for ip in ips:
                    if ip in self.ip_groups:
                        self.ip_groups[ip].append(subdomain)
                    else:
                        self.ip_groups[ip] = [subdomain]

            # 显示前10个结果，其余省略
            if i < 10 or i >= self.random_count - 10:
                print(f"{Fore.CYAN}[{i + 1}/{self.random_count}] {subdomain}.{self.domain} -> {status}")
            elif i == 10:
                print(f"{Fore.CYAN}... 中间省略 {self.random_count - 20} 个结果 ...")

        # 5. 判断是否存在泛解析
        resolution_rate = resolved_count / self.random_count
        self.confidence = resolution_rate

        if resolution_rate >= 0.9:
            self.is_wildcard = True
            verdict = f"{Fore.RED}[!] 高度确认存在泛解析 ({resolution_rate:.0%} 的随机子域名可解析)"
        elif resolution_rate >= 0.5:
            self.is_wildcard = True
            verdict = f"{Fore.YELLOW}[!] 可能存在泛解析 ({resolution_rate:.0%} 的随机子域名可解析)"
        else:
            self.is_wildcard = False
            verdict = f"{Fore.GREEN}[+] 未检测到泛解析 ({resolution_rate:.0%} 的随机子域名可解析)"

        # 6. 分析IP分组情况
        if self.ip_groups:
            print(f"\n{Fore.CYAN}[+] IP分组统计:")
            sorted_ips = sorted(self.ip_groups.items(),
                                key=lambda x: len(x[1]), reverse=True)
            for ip, subdomains in sorted_ips[:5]:  # 显示前5个最常见的IP
                count = len(subdomains)
                percentage = count / resolved_count * 100
                print(f"  {Fore.YELLOW}{ip} 出现 {count} 次 ({percentage:.1f}%)")

        # 7. 对比主域名IP和随机子域名IP
        if self.is_wildcard and main_domain_ips:
            overlap = set(main_domain_ips).intersection(unique_ips)
            if overlap:
                print(f"{Fore.YELLOW}[!] 主域名IP与随机子域名IP存在重叠: {', '.join(overlap)}")
                print(f"{Fore.YELLOW}[!] 这表明泛解析配置可能指向与主域名相同的服务器")

        print(f"\n{Fore.CYAN}[+] 检测完成，耗时 {elapsed_time:.2f} 秒")
        print(verdict)
        print(f"{Fore.CYAN}[+] 使用的DNS服务器: {', '.join(map(str, self.resolver.nameservers))}")

        return self.is_wildcard


def main():
    parser = argparse.ArgumentParser(description='检测域名是否配置泛解析')
    parser.add_argument('domain', help='要检测的域名')
    parser.add_argument('-t', '--threads', type=int, default=10, help='并发线程数 (默认: 10)')
    parser.add_argument('-T', '--timeout', type=int, default=5, help='DNS查询超时时间 (秒, 默认: 5)')
    parser.add_argument('-c', '--count', type=int, default=20, help='随机子域名测试数量 (默认: 20)')
    parser.add_argument('--system-dns', action='store_true', help='使用系统DNS服务器而非默认的公共DNS')

    args = parser.parse_args()

    # 创建并运行检测工具
    tester = WildcardDNSTester(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout,
        random_count=args.count,
        use_custom_resolvers=not args.system_dns
    )

    # 运行异步检测
    asyncio.run(tester.check_wildcard())


if __name__ == "__main__":
    main()