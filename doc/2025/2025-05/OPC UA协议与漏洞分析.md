#  OPC UA协议与漏洞分析   
原创 自主研发技术驱动  珞安科技   2025-05-21 10:02  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/eXicedYoc2qUBq2XkibuVB46Wic8VXSpNXhplqfNmFooI0CWrFiagkCiarAuyia5s4gO5t1IgibprGPGb0Mskt144vpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**01**  
  
**概 述**  
  
  
OPC（OLE for Process Control）是一种专为工业自动化系统设计的数据通信标准，旨在解决不同厂商设备间接口不统一、通信协议不兼容、驱动开发重复等问题。早期 OPC 标准基于微软 COM/DCOM 技术，主要运行于 Windows 平台。这一阶段的 OPC 规范统称为 OPC Classic，包括OPC DA、OPC AE、OPC HDA，这些规范广泛应用于工业控制系统，但也存在一些明显的缺陷，例如依赖COM/DCOM、配置难度高、缺乏现代化的身份认证以及难以适应物联网、云计算等新兴技术场景。  
  
  
为应对这些挑战，OPC基金会推出了全新一代标准——OPC UA（Unified Architecture）。OPC UA 完全摆脱了对 COM/DCOM 的依赖，采用跨平台架构，支持在 Windows、Linux、嵌入式设备等多种环境下部署。OPC UA 在架构上融合了服务导向架构（SOA）理念，不仅支持实时数据访问，还支持事件处理、方法调用、历史数据读取等高级功能，并引入了统一的语义信息模型和强安全机制，如加密传输、证书认证和访问控制等。  
  
  
随着工业 4.0 和工业互联网（IIoT）理念的普及，OPC UA 由于与其平台无关、安全可靠、结构灵活的特点，在制造业、能源、交通、化工等多个行业得到了广泛应用。  
  
![1.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyPJuS8Yt7l1EjkyjTIc4loQfkafleMg4jaXZNqOPyicsUsCe8gjSY1Aw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**02**  
  
**OPC UA协议分析**  
  
  
**2.1 通信架构与工作流程**  
  
OPC UA 协议可在多种底层传输协议之上运行，包括 TCP/IP、HTTP、WebSocket 和 MQTT，其中最常见的是基于 TCP 的 UA Binary 通信方式。OPC UA 一些常见端口如下：  
  
![2.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHynfpjnESmBNWyyIylJgib10tjfFIwib2zHrqJ3CcK31oCxqmib5EMT4nrw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**2.1.1 OPC UA安全架构**  
  
OPC UA的安全架构从底层到上层分为三个主要层级：传输层、通信层和应用层，每一层都承载着不同的安全目标与功能。  
  
![3.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHy83KpWFXO8fiapR1H1dOia6yUdMDBuicIhNykjaz2Dh9VlmxdVZuuupxIQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
传输层负责网络连接的可用性，确保设备间能建立稳定通信；通信层保障数据传输过程的安全性，通过加密、签名和校验机制防止信息被窃取或篡改，同时进行程序实体认证；应用层则实现用户与客户端应用的访问控制与权限管理，通过用户名密码、证书等方式验证身份，并在会话建立阶段对客户端程序和设备合法性进行认证，确保只有受信任的实体才能访问关键数据与功能。  
  
  
**2.1.2 OPC UA通信流程**  
  
OPC通信流程大概分为如下几个阶段：  
  
- **发送Hello报文**  
（客户端首先向服务端发送一个 Hello报文，表示即将建立连接并提供自身的一些连接参数，如协议版本、接收缓冲区大小、最大消息长度等）  
  
- **返回Ack确认报文**  
（服务端接收到 HEL 报文后，会返回一个 Acknowledge（简称 ACK）报文，确认可以进行连接，并提供服务端自身的连接参数）  
  
- **OPN安全通道建立**  
（建立一个安全通道，通常服务端会返回一个 SecureChannelID（安全通道 ID），用于后续安全通信的标识。该安全通道用于加密和签名 OPC UA 报文，以保证通信的机密性与完整性）  
  
- **MSG类型信息通信**  
（户端和服务端将通过 Message类型的报文进行业务数据的传输。这些消息封装了实际的服务请求与响应（如读取、写入、订阅等），并在安全通道内进行加密和完整性保护）  
  
- **CLO报文断开连接**  
（客户端会发送一个 CloseSecureChannelRequest 报文，请求关闭安全通道并断开连接。服务端响应 CloseSecureChannelResponse 报文后，双方连接正式断开）  
  
  
**通信流程图如下所示：**  
  
![4.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHylAic2xXpw1SA6GALrsyR79eXIus7k2Fic4yTIa0hBMFYCj6dicsa3icgVQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
通过Wireshark抓取流量包，如下所示：  
  
![5.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyzibfzXYphWBIqREAJQPAznb1pfibgprYLcKTCzF8olv5lAkn9kgaRIEQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**2.2 OPC UA协议格式**  
  
  
**2.2.1 UA TCP**  
  
通用OPC UA TCP的消息包含一个消息头和消息体，如图所示：  
  
![6.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyWW4QHhCU43XBCsCeZqvfwsVJCkhbTNGlmRjRk8KWN9icw6zOibFXQ8fQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
消息头通常包含消息类型、编码方式、消息长度等关键信息，用于标识通信目的和数据结构；消息体则承载实际的数据内容，如会话建立、服务请求或数据传输等操作所需的参数和响应内容。这种结构便于消息的快速解析与处理，适用于工业通信对低延迟与高可靠性的要求。  
  
  
每个OPC UA连接协议消息均包含消息头，其字段定义如下：  
  
![7.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyCbosfJz5a8jjricQGicOmVficsrGqibiaqOnWv2zQIw9icg4GDrJUriaicwLQQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
流量包如下：  
  
![8.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHypwCw8w2o32hqIaH6HoAt29Df0ee7xEUhBVVHCtA4F5tnYkYNlNvnMQ/640?wx_fmt=png&from=appmsg "")  
  
  
**2.2.2 UA Secure Conversation**  
  
OPC安全会话消息由多个部分组成，用于保障通信的安全性与完整性，结构如下：  
  
![9.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyUjNnBoTBgia8SVNym3phqul0CRhKPBp6aLmRpIicnkkaRCK9QHJscMibQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
整个消息由“加密数据”和“签名数据”构成，其中包括消息头、对称/非对称安全头、序列头、消息体、填充和签名等字段。消息头用于标识消息类型和长度，安全头携带安全策略和证书信息，序列头用于防止重放攻击，消息体承载实际业务数据，填充和签名则确保消息的完整性与机密性。通过该结构，OPC UA 实现了分块加密、安全认证和完整性校验，是其安全通信机制的核心基础。  
  
  
每个消息分块（MessageChunk）均包含以下头部字段：  
  
![10.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyQ7hIJWGOPd1jE0ToDw7MxqQo3QSpGzBXymticrGrQgX56QCIvUnoawA/640?wx_fmt=png&from=appmsg "")  
  
  
流量包如下：  
  
![11.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyhBNJmGCVLyico6ibkfhGQBKrGkiawg8hoiaaFwTibKGyqBIt7Xrow8FzT6Q/640?wx_fmt=png&from=appmsg "")  
  
  
**03**  
  
**攻击面与漏洞分析**  
  
  
OPC UA 协议作为工业自动化系统中的核心通信标准，凭借其平台无关性与跨协议特性，在能源、电力、制造等关键基础设施中被广泛部署。然而，其复杂的协议结构和庞大的生态也带来了多维度的安全风险，成为高级持续性威胁（APT）攻击的重要目标。典型案例如臭名昭著的 Industroyer（CrashOverride）恶意软件，其中攻击模块就包含针对 OPC 协议的攻击。  
  
  
**3.1 攻击面梳理**  
  
OPC UA 的攻击面主要集中在协议栈实现、通信机制、身份认证、系统集成以及供应链等方面，总结如下：  
  
- **协议栈漏洞：**  
OPC UA底层协议栈常由C/C++编写（如open62541、UA Automation），容易受到缓冲区溢出、内存泄漏、UAF 等内存安全问题影响。而基于 Java/.NET 的实现也曾在 Prosys SDK、Pwn2Own 赛事中曝出反序列化和认证绕过漏洞。  
  
- **证书验证缺陷：**  
在通信层面，OPC UA 依赖 TCP 和 HTTPS 传输，若未强制启用加密或忽略证书校验，将暴露于中间人攻击（MITM）之下；异常分块、超长字段等构造亦可用于模糊测试，诱发服务端崩溃或资源耗尽。  
  
- **配置不当：**  
客户端与服务器集成时常因配置不当引入风险，如启用弱加密算法、证书管理疏漏等问题频繁出现，尤其是在嵌入式设备或工程工具（如西门子 TIA Portal、施耐德 Control Expert）中，资源限制与默认配置易被攻击者利用。  
  
- **身份认证问题：**  
在身份认证和权限控制方面，不少实现允许匿名访问敏感变量，或存在会话令牌管理不当、权限划分不清等问题，攻击者可借此实现会话劫持、权限绕过等操作。  
  
- **供应链安全****：**  
OPC UA 的核心 SDK 被众多厂商复用，一旦出现漏洞，将对整个供应链产生级联影响。典型如 Kepware 协议栈漏洞，影响范围波及 Rockwell、GE 等多个工业厂商；而协议转换组件（如 OPC UA Tunneller）亦因加解密不当、边界检查缺失等问题，成为新增的攻击通道。  
  
  
**3.2 KEPServerEX漏洞分析**  
  
  
**3.2.1 漏洞介绍**  
  
KEPServerEX是一款在工业控制中比较常见的数据采集服务软件之一，提供了多种类型的驱动，作为OPC Server，具有比较广泛的适用性。  
  
  
CVE-2023-3825是一个影响KEPServerEX 的高危漏洞，该漏洞属于资源消耗不受控制（CWE-400），CVSS v3.1 基础评分为 7.5，影响 KEPServerEX 版本 6.0 至 6.14.263。  
  
  
攻击者可通过网络远程发起低复杂度攻击，无需认证或用户交互，可能导致服务崩溃。漏洞产生的原因在于 KEPServerEX 在解析 OPC UA 协议中嵌套对象时缺乏对递归结构的有效检查，攻击者可构造恶意递归对象诱使服务器陷入无限解析，导致堆栈溢出。  
  
  
**3.2.2 漏洞验证**  
  
OPCUA-Exploit-Framework是由国外Team82团队开源的工业协议安全测试工具，用于挖掘和验证 OPC UA 协议的安全缺陷，我们也对该攻击框架进行了一些改进。  
  
  
在本地部署KEPServerEX OPC UA 服务器后，并开启远程访问，接着执行漏洞利用代码，如图所示：  
  
![12.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHypObqiaeYXaSC8Pdh3xczuOEnY7mxoX8EzECVtKFjhWh3TgX1duxsvVg/640?wx_fmt=png&from=appmsg "")  
  
  
  
服务器在收到Payload后立即断开连接，攻击导致OPC UA 服务中断，如图所示：  
  
![13.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyuaOOuUpxiafKKpbriadMV2j0ypWT7lLo6KQ4ksnebM8soU0A41ZPegWg/640?wx_fmt=png&from=appmsg "")  
  
  
**3.2.3 分析漏洞形成原理**  
  
通过Wireshark抓取攻击流量，解析可发现大量嵌套的Variant数组，如图所示：  
  
![14.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHypk7ewDch3Mt3kZpZzal3pj0PS7Y5Y9egKWhbibAq2iav6MRcXP1UfvicA/640?wx_fmt=png&from=appmsg "")  
  
  
  
结合payload代码也能清晰知道  
  
![15.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyfCk8zlKGHZBE3lUFI1Eib6dqDlszGYIJVJibibyeaAvRLbiaxR7iagK2R2w/640?wx_fmt=png&from=appmsg "")  
  
  
接下来对KEPServerEx进行分析，软件创建服务较多，本次关注的服务是KEPServerEXV6，即server_runtime.exe，其加载了OPC通信、协议解析等核心模块。  
  
![16.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyDWgX8kV7NqqGPUr99aibbDr7Wibkfx0cDgXDv3tMXWwbnjPrAC2hcLGw/640?wx_fmt=png&from=appmsg "")  
  
  
注：由于server_runtime.exe中包含某商业License保护的模块，存在反调试，干扰了漏洞分析，因此分析前需要绕过反调试，这部分内容不在此展开。  
  
  
准备工作完成后，使用Windbg附加server_runtime.exe进程，发送payload后，我们定位到了异常线程，调用栈如图所示：  
  
![17.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyRbAqbqASdLxh7YrNpHf1sg8kn9L9ehhBmU28iaWWYpZzSYMqNwKrvQw/640?wx_fmt=png&from=appmsg "")  
  
  
由于windbg栈回溯分析的BUG，显示不全，但并不影响分析。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyhONibc1ERRdm4wvGRHFBic7KIfUw9c9icT5MhkJOkkTdVAg17JAPWNhFw/640?wx_fmt=png&from=appmsg "")  
  
  
在push esi触发了异常，很明显的栈溢出，通过查看TEB也可以论证，在线程继续压栈时已没内存可扩，因此触发了页保护异常。  
  
![20.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHySoRHNIstzMiby69aKZ0CLhUlU003n9Muz8BHdrkfb2Aj0Wb2ibdNhh9g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHy7x56qS6UtzFPNsAsroDSkkRaLCOfUnkxlI9bMiaV6S1OHlia6OpwcOww/640?wx_fmt=png&from=appmsg "")  
  
  
根据调用可知漏洞位于libua.dll中，利用IDA分析得知sub_283F0负责类型分发，在0x24分支中调用sub_33510对Variant数组进行解析：  
  
![22.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyJ7xq22WFMKYhKdMeW6QqeibTC1L8SOSSvmQ9qWRcwOPK9iaWhs5sEH8g/640?wx_fmt=png&from=appmsg "")  
  
  
  
其中sub_33510函数又递归调用了sub_283F0。  
  
![23.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyDzUKez74tZ2TaEhokicUJgnWIAx4UySSHBtQ0952GCKQA5TH1ELjAuA/640?wx_fmt=png&from=appmsg "")  
  
  
最后在构造大量嵌套次数后，由于未做任何限制，导致栈被耗尽而触发Crash，server_runtime.exe崩溃，最终OPC连接异常断开。  
  
  
值得一提的是OPC基金会在文档也预警了此类风险，但是安全问题往往会被开发者忽视，因此企业加强安全建设尤为重要，供应链厂商更应如此。  
  
![24.png](https://mmbiz.qpic.cn/mmbiz_png/eXicedYoc2qXVkvNcUSJVwACNNqPKulHyCzEklsEjmdUEgYkLINpx7ImlY6LTfTVDEwJriao0Jy9TKpJf2rrvpIg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**安全防护建议**  
  
  
为了降低 OPC UA 协议在工业控制系统中的安全风险，企业应从系统配置、网络部署、访问控制、身份验证、加密策略及运维机制等多个维度入手，构建一套切实可行的防护体系，例如：  
  
- 定期更新 OPC UA 服务端、操作系统及依赖库，修复已知漏洞，避免系统长期暴露于风险中。  
  
- 实施最小权限访问控制，基于角色定义访问权限，确保用户仅能访问其职责范围内的资源，防止权限滥用。  
  
- 强化身份认证机制，禁用匿名访问，为每个用户分配唯一账号，配合强密码策略和多因素认证。  
  
- 启用加密通信与安全策略，使用强加密模式和安全策略，防止通信被劫持或篡改。  
  
- 使用可信证书体系避免使用自签名证书，建议建立内部 CA，实现证书统一管理与吊销机制。  
  
- 接入安全防护产品，开启日志审计、防火墙等功能，记录关键操作与访问行为，便于异常分析与溯源。  
  
  
  
  
**参考链接：**  
  
https://reference.opcfoundation.org/  
  
https://claroty.com/team82/research/opc-ua-deep-dive-history-of-the-opc-ua-protocol  
  
https://github.com/claroty/opcua-exploit-framework/tree/main  
  
  
**珞安科技**  
  
  
  
**北京珞安科技有限责任公司（简称：珞安科技）成立于2016年，是专注工业网络空间安全的创新型高科技企业和国家专精特新“小巨人”企业，并于2022年行业内率先通过CMMI5级认证。**  
  
  
珞安科技拥有业内顶尖工控安全专家团队、工业网络空间安全研究实验室和四大研发中心，坚持自主研发和技术创新，以零信任理念和体系化思想为指导，打造“实战化、易部署、易维护”工控网络安全产品体系，覆盖工控安全、业务安全和工业互联网安全，构建了全方位的工业网络空间安全防护体系。  
  
  
依托强大的技术原厂商实力，积极开展安全服务和安全运营，业务遍布20多个行业的2000余家工业企业。在全国设有20+分子公司及办事处，提供7*24h安全应急服务响应，保障国家关键信息基础设施安全稳定运行。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn5JEGIJwk3K7YskNAsooBaDicu1JBb0qCgYF4MlIgbasEibZPiaxIO5vvIicSkppgrgic3iaYqUJuR0O43w/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6YThhy11Smc2QOP8zOBxpqd8SpV8ic7Fc3BjiaKwDfBzpy76Lf5ianBDGL2BoXWicJm8U4ZnYI3CSQ3g/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MzU2NjI5NzY1OA==&mid=2247512889&idx=1&sn=de59b71777a0faa36c87366cbb99ec42&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzU2NjI5NzY1OA==&mid=2247512799&idx=1&sn=942b026bc2529aae9a6274b8c3589258&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzU2NjI5NzY1OA==&mid=2247511693&idx=1&sn=db8fa52576bd6de6b9ad91684a970f63&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzU2NjI5NzY1OA==&mid=2247511609&idx=1&sn=8aa963343713cabef813aa053e64d821&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/eXicedYoc2qU6L7OdM6LWJZ3NrSxRiasZrBX7nKAn9QxSI5xT77YSJXFoohNZeuyb1moicaxZe3vEw9jNGkogEJ6w/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
