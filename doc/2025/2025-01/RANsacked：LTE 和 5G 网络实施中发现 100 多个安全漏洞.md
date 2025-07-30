#  RANsacked：LTE 和 5G 网络实施中发现 100 多个安全漏洞   
会杀毒的单反狗  军哥网络安全读报   2025-01-25 01:01  
  
**导****读**  
  
  
  
研究人员披露了影响 LTE 和 5G 实施的 100 多个安全漏洞的详细信息，这些漏洞可能被攻击者利用来破坏服务访问，甚至进入蜂窝核心网络。  
  
  
据佛罗里达大学和北卡罗来纳州立大学的研究人员称，这119 个漏洞被分配了 97 个唯一的 CVE 标识符，涵盖七种 LTE 实现（Open5GS、Magma、OpenAirInterface、Athonet、SD-Core、NextEPC、srsRAN）和三种 5G 实现（Open5GS、Magma、OpenAirInterface）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaEMjWCEjRPCgytOhoiaeWQ8mzVdHwvFtGcknvicjxQ9cWmClhBic1PI2nia5uGER9D4KDrQwKujPUwFqA/640?wx_fmt=png&from=appmsg "")  
  
威胁模型  
  
  
该研究结果已在题为“RANsacked：一种用于模糊 LTE 和 5G RAN-Core 接口的领域知情方法”的研究中详细说明。  
  
  
研究人员表示：“下面讨论的 100 多个漏洞中的每一个都可以用来持续破坏城市范围内的所有蜂窝通信（电话通话、消息和数据）。”  
  
  
“攻击者只需以未经身份验证的用户身份通过  
  
网络发送单个小数据包（无需 SIM 卡），即可持续破坏 LTE/5G 网络中的移动管理实体 (MME) 或接入和移动管理功能 (AMF)。 ”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaEMjWCEjRPCgytOhoiaeWQ8mmE5cKdhXMQmgbcZWib8hq9iblpo70w2NKXt7tibBiaR1lgibBj9UZgSUOiaQ/640?wx_fmt=png&from=appmsg "")  
  
  
这一发现是研究人员针对无线接入网络（RAN ）核心接口进行的一项名为 RANsacked 的模糊测试的结果，该接口能够直接从移动手机和基站接收输入。  
  
  
研究人员表示，发现的几个漏洞与缓冲区溢出和内存损坏错误有关，这些漏洞可被利用来破坏蜂窝核心网络，并利用该访问权限在城市范围内监控所有用户的手机位置和连接信息，对特定用户进行有针对性的攻击，并对网络本身执行进一步的恶意操作。  
  
  
此外，已发现的漏洞可分为两大类：可被任何未经身份验证的移动设备利用的漏洞和可被破坏基站或微蜂窝的对手利用的漏洞。  
  
  
在发现的 119 个漏洞中，79 个出现在 MME 实现中，36 个出现在 AMF 实现中，4 个出现在 SGW 实现中。25 个缺陷导致非接入层 ( NAS ) 预认证攻击，这种攻击可由任意手机执行。  
  
  
研究指出：“家用微蜂窝的引入，以及随后在 5G 部署中更易于访问的 gNodeB 基站，代表着安全动态的进一步转变：RAN 设备曾经被物理锁定，但现在却公开暴露在物理对抗威胁之下。”  
  
  
“我们的工作通过启用高性能模糊测试接口来探索这一最终领域的含义，这些接口在历史上被认为是隐含安全的，但现在面临着迫在眉睫的威胁。”  
  
  
详细漏洞公告：  
  
https://cellularsecurity.org/ransacked  
  
  
论文《RANsacked: A Domain-Informed Approach for Fuzzing LTE and 5G RAN-Core Interfaces》下载：  
  
https://dl.acm.org/doi/abs/10.1145/3658644.3670320?download=true  
  
  
新闻链接：  
  
https://thehackernews.com/2025/01/ransacked-over-100-security-flaws-found.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
