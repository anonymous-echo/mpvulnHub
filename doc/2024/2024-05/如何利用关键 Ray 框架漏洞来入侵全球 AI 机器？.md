#  如何利用关键 Ray 框架漏洞来入侵全球 AI 机器？   
cybernews  OSINT研习社   2024-05-01 09:00  
  
自 2023 年 9 月 5 日以来，一种名为“ShadowRay”活动的复杂网络威胁针对 Ray 框架中的漏洞。  
  
该活动凸显了 Ray 框架中的一个严重漏洞，该框架由 Anyscale 开发，并被 Amazon 和OpenAI  
等巨头使用 ，用于协调教育、加密货币和生物制药等领域的大量 AI 和 Python 应用程序。  
  
Ray 的 GitHub 存储库已获得超过   
30,500  
 颗星，其泄露标志着网络间谍活动中的重大事件，影响了数百台服务器并泄露了敏感数据。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0PXJViaVOv7AwxjJFHaYp3Qd402RQub4jLnGCJNp0A608ZsDJoHpOwJQ/640?wx_fmt=other&from=appmsg "")  
  
  
Ray 的众多用户中的一些（来源：ray.io）  
## 攻击者如何利用 Ray 的 Jobs API？  
  
由于CVE-2023-48022  
漏洞，Ray 的 Jobs API 中缺乏授权会带来重大的安全风险，为未经授权的用户的潜在滥用打开了大门  。  
  
鉴于任何有权访问仪表板网络（HTTP 端口 8265）的人都可能在没有任何形式的身份验证的情况下在远程主机上执行任意作业，因此该漏洞变得尤其令人担忧。  
  
Ray 的官方文档强调了安全最佳实践的重要性，强调安全和隔离措施必须在 Ray Cluster 之外强制执行。然而，很明显，如果没有适当的授权机制，未经授权的访问风险仍然不会减轻。  
  
Ray 背后的公司 Anyscale 声称，用户有责任确保 Ray 执行能力的本地性和安全性。他们建议仪表板应该无法从互联网访问或仅限于受信任的各方。  
  
然而，这种方法在安全性方面留下了一个关键漏洞，因为它依赖于具有足够路由逻辑（例如网络隔离、Kubernetes 命名空间、防火墙规则或安全组）的安全环境的假设。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0OW9aQd4GibGmqXFbpDicSUIacTUrTtoqmQ9gTtLvjTGyO4Nibb9MJb6Yg/640?wx_fmt=other&from=appmsg "")  
  
  
CVE-2023-48022漏洞卡（SOCRadar漏洞情报）  
  
许多业内人士并不知道 Ray 仪表板中存在的漏洞，尤其是与其 Jobs API 相关的漏洞。此外，这些漏洞（包括提到的 CVE）的披露并没有很快引起广泛关注。  
  
例如，Ray 的官方 Kubernetes 部署指南和 Kuberay 的 Kubernetes 运营商鼓励在 0.0.0.0 上公开仪表板，这可能会通过使其可供更广泛的网络实体访问而加剧风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0HribmwMBErLYkYVRagl26wXhmZEaGT7sI6QcIN8PO11GsmsCk1wxXwQ/640?wx_fmt=other&from=appmsg "")  
  
  
Kuberay 的 Kubernetes 操作员指南  
  
MITRE 为与 Ray 的 Jobs API 相关的安全漏洞评分为 9.8 分。但值得注意的是，该漏洞目前在   
MITRE 框架  
内被标记为“有争议” 。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx06NDBvy6WRPwRq8DLNCj2LdRicw7kicvzcPVmicmgUsF7T5iaeNJNlhtFCw/640?wx_fmt=other&from=appmsg "")  
  
  
CVE 有争议的说明  
### 野外利用射线簇：哪些敏感数据受到损害？  
  
当黑客破坏 Ray 生产集群时，他们可以访问宝贵的公司数据，并可以在不被发现的情况下运行自己的代码，从而利用传统安全工具的局限性。这导致大量敏感信息从受感染的服务器泄漏。  
  
攻击者能够操纵   
人工智能  
 生产工作负载，可能影响人工智能模型的准确性和可靠性，并影响包括医疗保健、视频分析和顶级学校在内的各个行业。  
  
Ray 生产集群的泄露使攻击者能够访问   
生产数据库凭据  
，使他们能够悄悄下载整个数据库并在某些计算机上使用勒索软件篡改或加密它们。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx08ib6A7HEsbSAeQmv2SUX0fUDDfAnCTMwT6BTibKVbwB2Dh8VVjwbNM0A/640?wx_fmt=other&from=appmsg "")  
  
  
生产数据库凭证  
  
此外，有证据表明，攻击者通过一个简单的命令“cat /etc/shadow”从计算机获取了密码哈希值，该命令在作业历史记录中执行了多次，表明渗透成功。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0n83ZCO8gFejph1ibPJEuk00WX9RbsIqffh2kbtqCFURsGibgtc0jTXFw/640?wx_fmt=other&from=appmsg "")  
  
  
Ray 的工作历史显示，攻击者窃取了密码并启动了反向 shell。  
  
Oligo 研究人员还  
发现了  
 许多 SSH 私钥，这些密钥可用于使用相同的 VM 映像模板来访问其他机器，以扩展   
加密货币挖掘活动  
的计算能力 或建立持久性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0es6ZibHcOdibOwkKnQ89hibibssTCCceY6v1RcprACB0nM4UhzVab4H6QQ/640?wx_fmt=other&from=appmsg "")  
  
  
AWS 集群计算机凭证，允许使用 SSH 连接到集群的所有计算机。  
  
还发现了 OpenAI、HuggingFace 和 Stripe 代币，这些代币可被用来耗尽受影响公司的信用、渗透账户并覆盖模型、执行未经授权的交易，甚至导致   
供应链攻击  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0X6rr8WfBAuIvibUKcOiaVOMM6tw3XYI9lmPXuDGp1bdK47YicDranjYUg/640?wx_fmt=other&from=appmsg "")  
  
  
人工智能模型实时处理用户提交的查询。该模型可能会被攻击者滥用，从而改变客户的请求或响应。  
  
此外，攻击者可以从受感染的 Ray 集群获取对云环境（AWS、GCP、Azure、Lambda Labs）的访问权限，其中许多集群以提升的权限运行。这些受损的集群为攻击者提供了对敏感云服务的访问权限，可能会暴露完整的数据库、客户数据、代码库、工件和秘密。  
  
此外，KubernetesAPI 访问使攻击者能够感染云工作负载并窃取 Kubernetes 机密。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0K33dMWnHvEEBqy6azuVQhvv7dVglVyuCKZYCxIfR7GfemzuwmZjDjg/640?wx_fmt=other&from=appmsg "")  
  
  
Kuberay Operator 在 Kubernetes API 上以管理员权限运行。  
  
调查还发现了 Slack 代币；利用这些令牌可能会授予对组织的 Slack 消息的未经授权的访问权限，并使攻击者能够发送任意消息，从而损害机密性和完整性。  
### ShadowRay 活动的财务影响  
  
受感染的机器具有巨大的经济价值，特别是考虑到受影响的 GPU 型号的稀缺性。其中许多 GPU 模型目前无法通过常规渠道获取且具有挑战性。  
  
例如， 从机器中观察到的  
A6000 GPU  
在NVIDIA官网上已经缺货。这种稀缺性放大了它们的市场价值，并凸显了由于它们的妥协而造成的巨大财务损失。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0lsdDqicevlibwfgJPX0c5ZH9JCrNUdVeAsAQ8BrvcicD2ibzCk8zoeTBtQ/640?wx_fmt=other&from=appmsg "")  
  
  
来自受感染机器的 nvidia-smi 输出  
## 加密货币挖矿活动的时间表和范围  
  
研究人员透露，第一个加密货币挖矿程序于 2024 年 2 月 21 日启动。然而，公共网络情报工具表明，相关 IP 自 2023 年 9 月 5 日以来一直在接受与目标端口的连接，这表明存在潜在的预披露漏洞。  
  
据报道，这些攻击的规模和时间都表明有一个复杂的黑客组织参与其中。  
  
在发现的加密货币挖矿活动中，有 XMRig 矿工的实例，其中一些在内存中运行，无需磁盘下载，这使得检测和根除工作变得复杂。值得注意的是，还发现了 NBMiner 和基于 Java 的 Zephyr 矿工的存在。  
### 攻击者的身份  
  
这些攻击中使用的命令行包含攻击者的独特用户名和密码，以及与之通信的服务器。通过检查矿池，研究人员成功地确定了攻击者在排行榜上的位置，揭示了这些加密货币挖矿操作背后的犯罪者的身份和活动。  
  
攻击者在矿池内3216 名矿工  
中排名第 148 位  ，在参与矿池的矿工中排名前 5%。这凸显了他们的剥削努力的程度以及他们的活动在   
加密货币  
 挖矿社区中的重大影响。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0UA7FHMh4gic4YKdF3TMWXrgY5OvGvYl50ia4QxRAQhfJ9l00LDC7I8DA/640?wx_fmt=other&from=appmsg "")  
  
  
攻击者在 3216 名中排名第 148 位。  
### 使用反向 shell 建立持久访问  
  
我们发现了多个反向 shell 实例，使攻击者能够在生产环境中执行任意代码，从而对受影响基础设施的安全性和完整性构成重大威胁。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0ECUwiaVz6u6VAS64QaYKXvAWxa4qN5pou8PFduIlaibQVR1iciays2tcyA/640?wx_fmt=other&from=appmsg "")  
  
  
Ray星团上最古老的反向壳记录是2023年9月5日  
  
此外，通过对oast.fun  
域的进一步调查 ，发现攻击者正在利用开源服务   
Interactsh  
 来逃避检测。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0ibbLJVicibz494iaSF8NXqlRXQ5t1TU4qvnT4gLtj0TReia0BQayGx4huCg/640?wx_fmt=other&from=appmsg "")  
  
  
使用interactsh，攻击者从客户端接收有关DNS查询的带外通知  
  
域 oast.fun 是该项目维护的公共服务器之一。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0zic1ztx2Vuu7vHuXmiaI6OTibx6fc8I3TQ3OzWe26kqmL05upAH9QGChA/640?wx_fmt=other&from=appmsg "")  
  
  
公共服务器上的默认页面  
  
攻击者利用免费的公共服务器作为逃避检测的手段。通过 Jobs API 成功执行 Base64 有效负载后，会触发从受感染计算机到攻击者控制的免费子域的 DNS 查询。这使得攻击者能够及时收到包含受感染计算机 IP 地址的通知。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0YHAVX8evxN2RoVrvN6gWAu6gPeqGB8MMEjygAAlrACZczB9TQsNSaw/640?wx_fmt=other&from=appmsg "")  
  
  
为有效负载提供服务的攻击者控制的 IP 地址  
  
总之，调查揭露了复杂且持续的加密货币挖矿操作，凸显了实施强有力的安全措施以有效应对此类入侵的至关重要性。  
### 权限提升策略和开源脚本的使用  
  
调查发现，攻击者试图使用 sudo 来升级权限，而受攻击的计算机上无法使用 sudo。研究人员强调，攻击者使用开源存储库利用了 www[.]akuh[.]net 服务。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0AvCZm0RQju2FdO47kaBJhZ3wmRPFobjNjKiaEoicQpukDwAlSv68xoQA/640?wx_fmt=other&from=appmsg "")  
  
  
攻击者使用的开源脚本。  
  
VirusTotal 没有显示有效负载的危险信号，检测率为 0/59。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rWVoKKJPdj5D5pBOnibJNJqAwX1IDFJx0Pp1KJSicYvnlLJ6IzPrS69cmGmJKapjLUmibhEx1NWV4dChYFHOp35Gg/640?wx_fmt=other&from=appmsg "")  
  
  
有效负载的 VirusTotal 结果。  
## 提高 Ray 部署安全性的缓解策略  
  
以下是保护 Ray 部署免遭攻击的一些最佳实践：  
- 在安全环境中启动部署：  
 在安全可靠的环境中启动 Ray 部署，建立强大的安全基础。应用防火墙规则或安全组来有效防止未经授权的访问尝试。  
  
- 添加对安全 Ray 仪表板端口的授权 (8265)：  
 重点关注 Ray 仪表板端口的授权机制。部署具有授权层的代理来控制对 Ray API 的访问并仅允许授权人员进行访问。  
  
- 实施持续监控策略：  
 通过持续监控对生产环境和 AI 集群保持警惕。传统的代码扫描和错误配置工具可能不够，需要特殊的监控和保护机制来有效检测和防止潜在的攻击。  
  
为了进一步增强 Ray 部署的安全性，建议避免连接到 0.0.0.0 IP 地址，以最大限度地减少攻击面。相反，请选择与特定网络接口或受信任的私有 VPC/VPN 关联的 IP。  
##   
## 针对 ShadowRay 的补救措施  
  
为了有效保护 Rail 部署的安全，请通过实施防火墙规则并向 Ray Dashboard 端口添加授权来优先考虑在安全环境中进行操作。持续监控异常情况并避免绑定到 0.0.0.0 等默认设置，并利用可改善集群安全状况的工具。  
  
  
  
