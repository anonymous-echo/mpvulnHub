#  对MOVEit Transfer SQL注入漏洞的最新分析（10月4日更新）   
lucywang  嘶吼专业版   2023-10-12 15:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29wU9fqVsIMW1WxNUX1jr4bg5BhFWmrThCDu7Cs1LFJ9nWY0BfibUUmMhkBtD9HSHFLcpRKwJuddTw/640?wx_fmt=png "")  
  
今年5月31日，Progress Software发布了一则通知，提醒客户其MOVEit Transfer产品存在严重的结构化查询语言注入（SQLi）漏洞（CVE-2023-34362）。MOVEit Transfer是一个托管文件传输（MFT）应用程序，旨在提供安全协作和敏感数据的自动文件传输。  
  
6月9日，有研究人员在MOVEit Transfer web应用程序中发现了SQL注入漏洞，这些漏洞可能允许未经身份验证的攻击者获得对MOVEit Transfer数据库的未经授权访问。攻击者可以向MOVEit Transfer应用程序终端提交精心制作的有效负载，可能导致MOVEit数据库内容的修改和泄露。6月15日，Progress Software提醒客户注意其他SQL注入漏洞，这些漏洞也被Progress评为严重漏洞，并分别命名为CVE-2023-35036和CVE-2023-35708。  
  
7月7日，Progress Software发布了一个服务包，解决了另外三个漏洞，一个被评为关键漏洞，两个被评为高漏洞，分别是CVE-2023-36934（关键），CVE-2023-36932（高），CVE-2023-36933（高）。  
  
CVE-2023-36934是一个SQLi漏洞，可能允许未经身份验证的攻击者获得对MOVEit Transfer数据库的未经授权访问。CVE-2023-36932涉及多个SQLi漏洞，这些漏洞可能允许经过身份验证的攻击者获得对MOVEit Transfer数据库的未经授权访问。最后，CVE-2023-36933指的是一个漏洞，该漏洞可能允许攻击者调用导致未处理异常的方法，该异常可能导致MOVEit Transfer应用程序意外终止。  
  
这三个漏洞都是由安全研究人员发现的，目前没有证据表明任何一个漏洞已在野外被利用。  
  
Progress建议所有客户应用2023年7月的service pack，因为它包含对所有三个漏洞的修复。  
  
在目前已发现的所有样本中，攻击者都会利用原始漏洞将web shell上传到MOVEit Transfer服务器。web shell还允许攻击者枚举MOVEit Transfer服务器上的文件和文件夹，读取配置信息，下载文件，以及创建或删除MOVEit服务器用户帐户。  
  
调查过程中，最早的攻击证据出现在5月27日。  
  
Palo Alto Networks Xpanse指出，至少有2674台MOVEit服务器暴露HTTP/HTTPs流量。这不包括MOVEit Cloud服务器。调查表明，所有MOVEit Cloud服务器都已“修补并完全恢复”。  
  
Progress Software提供了缓解指南，所有MOVEit Transfer客户都应该认真考虑遵循这些指南。  
  
Palo Alto Networks客户通过以下方式获得CVE-2023-34362的保护和缓解：  
  
1.具有高级威胁防护安全订阅功能的下一代防火墙可以帮助阻止关联的web shell。  
  
2.具有威胁防护安全订阅功能的下一代防火墙，可以通过威胁防护签名阻止具有最佳实践的攻击。  
  
3.高级URL筛选可以阻止已知的IoC。  
  
4.Cortex XSOAR响应包和行动手册可以自动化缓解过程。  
  
5.Cortex XDR和XSIAM代理使用行为威胁保护、反webshell保护和多个附加的安全模块，以帮助防止本文中描述的利用后活动。  
  
6.Cortex Analytics有多个检测模型，有助于检测利用后的活动，身份分析和ITDR模块还涵盖了其他相关内容。  
  
7.Cortex Xpanse客户可以通过“MOVEit Transfer”攻击面规则识别应用程序的面向外部的实例。  
  
8.下面提供的XQL查询可以与Cortex XDR一起使用，以帮助跟踪利用此CVE的尝试。  
  
9.各类组织可以与Unit 42事件响应组织联系，以获得针对此威胁和其他威胁的具体援助。  
  
10.Prisma Cloud WAAS客户通过应用防火墙SQL注入保护免受此威胁。  
  
11.具有高级威胁防护安全订阅功能的下一代防火墙可以帮助阻止关联的web shell。  
  
12.具有高级威胁防护安全订阅的下一代防火墙可以帮助检测和阻止漏洞利用流量。  
  
接下来，将详细讨论CVE-2023-34362、CVE-2023-3 5036、CVE--2023-35708、CVE-202 3-36934。  
# 漏洞详情  
  
5月31日，Progress Software发布了一则通知，提醒客户他们的MOVEit Transfer产品存在一个严重漏洞（CVE-2023-34362）。CVE-2023-34362是一个SQLi漏洞，该漏洞使攻击者能够悄无声息地提升权限，查看和下载数据库服务器上的数据，并可能窃取Azure系统设置以及相关密钥和容器。  
  
Huntress和Mandiant在CVE任务前几天都发表了各自的博客，详细介绍了他们对正在进行的利用该漏洞的活动的观察。Mandiant已经确定了“多起受害者的MOVEit Transfer系统中大量文件被盗的案件”。调查结果与上述博文分析一致。  
  
Unit 42的研究人员已经在D:\MOVEitDMZ\wwwroot\human2.aspx 目录中看到了web shell，这与Huntress报告的目录略有不同。研究人员还在C:\Windows\Temp目录中看到了预编译的.NET DLL。  
  
例如，研究人员观察到文件路径C：\Windows\Temp\erymbsqv\erymbsqv.dll，其中文件夹和文件名的随机字符是动态生成的，并且在受攻击的主机之间有所不同。以下是Progress, Huntress或Mandiant文中未提及的其他攻击指标。  
  
注意：下面的IoC确实包含Progress, Huntress和Mandiant文中提到的IP地址，因为我们认为在受害者组织中强调基础设施的重用很重要。  
# 当前攻击范围  
  
CVE-2023-34362最早是在5月27日发现的，攻击者利用该漏洞造成了最初的攻击和web shell的部署。研究人员一致认为这些攻击很可能是Cl0p勒索软件组织所为，受到威胁的组织可能会在不久的将来收到勒索通信。今年，一个名为CL0P的新兴组织快速发展壮大，在几个月内超越了LockBit等大型组织，RaaS 的传播方式多种多样，但据说最常见的是通过电子邮件发送。3 月，该组织利用 GoAnywhere MFT 安全文件传输工具中的零日漏洞发起攻击，累计发动的次数几乎是 LockBit 总攻击次数的两倍。5月下旬，在沉寂了两个月之后，CL0P卷土重来，利用Progress Software公司文件传输工具MOVEit Transfer中的零日漏洞攻击了更多的受害者。  
  
Palo Alto Networks Xpanse表示，至少有2674台MOVEit服务器暴露了HTTP/HTTPs流量。这不包括MOVEit Cloud服务器。目前，所有MOVEit云服务器都已“修补并完全恢复”  
# 野外利用  
  
MOVEit是一款管理文件传输软件，可对文件进行加密，并使用FTP或SFTP等文件传输协议传输数据，它还提供自动化服务、分析和故障转移选项。  
  
在MOVEit中，包用于确保敏感信息的安全和受控交换。“包”指的是一个容器或信封，里面装着要在各方之间安全地传输的文件和数据。  
  
对于访客用户，MOVEit提供一次性使用场景。访客用户可以发送、查看、下载、重播和接收包。  
  
访客用户必须通过向 /human.aspx组件发出请求来注册为访客，并提供其电子邮件地址以及数据包接收器的电子邮件地址。此请求最终将重定向到/guestaccess.aspx 组件，自动创建一个包含发件人和收件人电子邮件地址的电子邮件模板，然后访客用户可以使用此电子邮件模板发送数据包。  
  
SQL注入是由于无法对组件/moveitsapi/moveitisapi.dll中的输入数据进行净化而发生的，该组件提供与MOVEit API相关的文件传输函数。  
  
下图描述了访客用户如何通过使用以下条件向/moveitisapi/moveitisapi.dll终端发送请求来更新会话变量的值：  
  
HTTP参数action=m2；  
  
HTTP请求标头x-silock-transaction:folder_add_by_path和x-silock-transaction:session_setrvars。  
  
更新的会话变量将允许攻击者使用SQL注入字符更新收件人的电子邮件地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29wU9fqVsIMW1WxNUX1jr4bOp2XvgIVic8EyjgNVjrUra7B6dibxEVWZx5HpeicTphMJfW9icickowHIlA/640?wx_fmt=png "")  
  
MOVEit SQL注入漏洞  
# 攻击流量趋势（2023年6月至9月）  
  
Progress Community于2023年6月16日发布了CVE-2023-34362的补丁，并于2021年7月6日发布了针对CVE-2023-3 6934的补丁。  
  
patch diff的技术分析在2023年7月11日左右公开，patch diff是一个记录文件两个版本之间变化的文件。此后，攻击次数开始增加，7月29日达到峰值1639次。下图显示了从6月到9月的攻击流量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29wU9fqVsIMW1WxNUX1jr4buwnccV0wReQY7wZdUI5xMdUaFDbTwnPKxUYIDhZDShjHtQ8lzblbeQ/640?wx_fmt=png "")  
  
MOVEit漏洞利用的趋势  
# 预防措施  
  
以下是Progress Software建议的缓解措施，有关缓解过程的详细列表和解释，  
  
1.禁用所有到MOVEit Transfer主机的HTTP和HTTPs流量。  
  
2.查看、删除和重置任何未经授权的文件和用户帐户。  
  
3.应用相应的补丁。  
  
4.检查所有恶意文件和用户帐号是否已被删除/重置。再次重置服务帐户凭据。  
  
5.重新启用所有到MOVEit Transfer环境的HTTP和HTTPs流量。  
  
6.持续监控网络、终端和日志，以报告与当前活动相关的IoC。  
  
Unit 42团队还建议，任何暴露了MOVEit Transfer web界面的组织都应该假设它已经被攻击了。他们强烈建议受影响的组织对服务器进行取证分析，以确保它没有受到损害。  
  
6月15日，针对最新报告的SQLi漏洞，Progress Software更新了他们的缓解措施，称：“鉴于新发布的漏洞，我们关闭了MOVEit Cloud的HTTPs流量，并要求所有MOVEit Transfer客户关闭HTTP和HTTPs流量，以保护他们的环境，同时创建和测试补丁。”  
  
参考及来源：https://unit42.paloaltonetworks.com/threat-brief-moveit-cve-2023-34362/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29wU9fqVsIMW1WxNUX1jr4b32U2cItfyuhrgaDaBIia8FWiarKo6bz2dDX6xjOUg2UKYWRmgnWUVPlw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29wU9fqVsIMW1WxNUX1jr4bWuvlGiaKFpsaQ0K0ibGSrSTt8mXf0zPrOljicXrqicE4NFCFPgrZlfm4ww/640?wx_fmt=png "")  
  
  
  
