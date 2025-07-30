#  工信部CSTIS提醒：防范Murdoc_Botnet僵尸网络的风险；谷歌修复两个已被利用的Android零日漏洞 | 牛览   
 安全牛   2025-03-05 17:22  
  
点击蓝字·关注我们   
/   
aqniu  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBjwIRcuxcIx3fvDBydiaqkxw4o55dLPMJBKVsRbYl7ULkJDmFtatY9fWSIcZttiaeQm76cm0TXSBCA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**新闻速览**  
  
  
  
•工信部CSTIS提醒：防范Murdoc_Botnet僵尸网络的风险  
  
•波兰航天局遭遇网络攻击后，系统仍处于离线状态  
  
•编码问题引发微软365服务大面积中断，身份验证等功能一度中断  
  
•新型僵尸网络Eleven11bot蔓延，感染逾8.6万物联网设备发动DDos攻击  
  
•猎人团伙声称对Tata Technologies网络攻击负责，窃取1.4TB数据  
  
•AWS环境遭黑客组织JavaGhost利用，发动持续钓鱼活动  
  
•新型多语种恶意软件Sosano对阿联酋关键行业发动攻击  
  
•谷歌修复两个已被利用的Android零日漏洞  
  
•HPE远程管理工具存在RCE漏洞, PoC代码已公开  
  
  
  
**特别关注**  
  
  
  
**工信部CSTIS提醒：防范Murdoc_Botnet僵尸网络的风险**  
  
  
2月28日，工业和信息化部网络安全威胁和漏洞信息共享平台（CSTIS）发布《关于防范Murdoc_Botnet僵尸网络的风险提示》。根据风险提示，CSTIS监测发现Murdoc_Botnet僵尸网络持续活跃，其主要攻击目标为类Unix系统，尤其是物联网相关设备，可能导致敏感信息泄露、勒索攻击、业务中断等风险。  
  
  
Murdoc_Botnet是一种基于Mirai新变种的僵尸网络恶意软件，最早发现于2024年7月。该恶意软件利用网络摄像机、路由器等物联网（IoT）设备的已知漏洞，通过ELF和shell脚本向目标设备植入恶意代码，进而下载Mirai新变种（Murdoc_Botnet）。一旦成功入侵，该恶意软件会将设备纳入其控制的僵尸网络之中，参与DDoS攻击、窃取敏感数据、传播其他恶意软件等恶意活动。在攻击过程中，Murdoc_Botnet可利用GTFOBins工具获取系统权限，通过chmod命令赋予恶意脚本执行权限，并通过删除其自身脚本以逃避检测，同时具备高度的模块化和可扩展性。此外，该恶意软件还能够与多个控制服务器通信，进一步扩大攻击范围和提升攻击效率。  
  
  
CSTIS建议相关单位和用户立即组织排查，及时更新防病毒软件，实施全盘病毒查杀，使用最新补丁更新系统和固件，监控可疑进程，避免执行不可信来源的脚本，并可通过及时修复安全漏洞，定期备份数据等措施，防范网络攻击风险。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/fYHTgtA2mPZH60bRZRcXPg  
  
  
  
**热点观察**  
  
  
  
**波兰航天局遭遇网络攻击后，系统仍处于离线状态**  
  
  
波兰航天局(POLSA)在上周末遭遇网络安全事件，切断其系统与互联网的连接以遏制其IT基础设施遭到入侵后，目前仍处于离线状态。  
  
  
在发现攻击后，航天局向相关部门报告了此次事件，并启动调查以评估其影响。为确保数据安全，POLSA网络立即与互联网断开连接。航天局将持续更新事态进展。POLSA尚未披露此次安全事件的性质，也未将攻击归咎于任何特定的威胁来源。但是根据内部人员消息，在攻击者入侵了 POLSA 的电子邮件系统后，工作人员被要求使用电话。  
  
  
目前，航天局正在与波兰计算机安全事件应急响应中心(CSIRT NASK)和波兰军队计算机安全事件应急响应中心(CSIRT MON)合作，以恢复受影响的服务。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/polish-space-agency-offline-as-it-recovers-from-cyberattack/  
  
  
**编码问题引发微软365服务大面积中断，身份验证等功能一度中断**  
  
  
微软近日承认，上周末发生的微软365服务中断事件是由一个编码问题导致的。该事件影响了Outlook和Exchange Online的身份验证功能。  
  
  
根据微软在周六晚上9:29发布于微软365管理中心的事件报告，此次中断还导致Teams和Power Platform功能受损，并引发了Purview访问问题和错误。微软透露，微软365身份验证系统的一次更新中存在编码问题，导致部分微软365应用程序和服务受到影响。这些问题通过回滚被确认为广泛中断根源的有缺陷代码更改得到解决。  
  
  
尽管微软已解决了此次微软365身份验证问题，但另一则发布于管理中心的公告称，Exchange Online用户在iOS原生邮件应用中仍然无法访问日历条目和电子邮件。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/microsoft/microsoft-links-recent-microsoft-365-outage-to-buggy-update/  
  
  
  
**网络攻击**  
  
  
  
**新型僵尸网络Eleven11bot蔓延，感染逾8.6万物联网设备发动DDos攻击**  
  
  
近日，新型僵尸网络恶意软件Eleven11bot已感染逾8.6万台物联网设备，主要针对安全摄像头和网络视频录像机(NVR)，用于发动分布式拒绝服务(DDoS)攻击。  
  
  
诺基亚研究人员发现了Eleven11bot，并与威胁监控平台 GreyNoise 分享了相关细节。诺基亚安全研究员表示， Eleven11bot是他们近年来观察到的最大DDoS僵尸网络之一，并已对电信服务提供商和在线游戏服务器发动了 DDoS 攻击。该僵尸网络的攻击流量已达到每秒数亿个数据包，持续时间常常跨越数天。GreyNoise在Censys的帮助下，在过去一个月内记录了1400个与该僵尸网络活动相关的IP地址，其中96%来自真实设备(非伪造)，有300多个被GreyNoise列为恶意。GreyNoise报告称，该恶意软件通过暴力破解弱口令或常用管理员凭据、利用特定物联网型号的已知默认凭据，以及主动扫描网络寻找暴露的Telnet和SSH端口等方式传播。  
  
  
GreyNoise已公布一份与Eleven11bot相关并确认执行恶意行为的IP地址列表，建议防御人员将此列表添加到阻止列表中，并监控可疑的登录尝试。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/new-eleven11bot-botnet-infects-86-000-devices-for-ddos-attacks/  
  
  
**猎人团伙声称对Tata Technologies网络攻击负责，窃取1.4TB数据**  
  
  
猎人国际勒索软件团伙声称在1月份对印度科技巨头Tata Technologies发动了的网络攻击，并窃取了1.4TB的公司数据。  
  
  
Tata Technologies为全球制造业提供工程和数字解决方案。该公司在今年1月曾报告遭受勒索软件行为者的入侵，部分IT系统受到干扰。但该公司表示，此次事件对运营的影响有限，客户交付服务完全未受影响。Tata表示，正在借助专家的协助恢复受影响的IT系统，并承诺将在内部调查有结果后分享更多更新。  
  
  
然而，在一个多月未有任何进一步消息公布之际，猎人国际勒索软件团伙在其黑网勒索页面上添加了Tata Technologies的条目，宣称对该公司的攻击。该团伙声称从Tata Technologies窃取了1.4TB数据，包含73万个文件。如果勒索要求未被满足，他们将在一周内公开这些被盗文件。不过，猎人国际并未公布任何被盗文件样本或详述所持有文件的类型。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/hunters-international-ransomware-claims-attack-on-tata-technologies/  
  
  
**AWS环境遭黑客组织JavaGhost利用，发动持续钓鱼活动**  
  
  
Unit 42威胁情报团队发现，威胁组织JavaGhost的攻击手法已从网站篡改演变为利用被入侵的AWS环境执行持续的网络钓鱼活动。他们利用过于宽松的Amazon身份和访问管理(IAM)权限，滥用受害者的简单邮件服务(SES)和WorkMail服务发送钓鱼邮件。  
  
  
JavaGhost最初的入侵通常始于获取与IAM用户关联的暴露的长期访问密钥。与其他攻击者不同，JavaGhost有意避免在进入时使用GetCallerIdentity API调用，而是执行GetServiceQuota、GetSendQuota和GetAccount等替代初始API调用，以确认访问权限同时保持低调。为进一步隐藏活动，JavaGhost通过涉及GetFederationToken和GetSigninToken API的多步骤过程生成临时凭证和登录URL。在获得控制台访问权后，JavaGhost开始建立其钓鱼基础设施，创建各种SES电子邮件身份并配置DomainKeys Identified Mail(DKIM)设置。他们修改SES虚拟交付管理器属性和Mail-from设置，然后配置WorkMail组织和用户。创建WorkMail组织会在CloudTrail日志中触发诸如CreateReceiptRule、CreateReceiptRuleSet和PutIdentityPolicy等多个SES和AWS Directory Service事件。  
  
  
在发起钓鱼活动之前，JavaGhost会创建新的SMTP凭证，从而产生具有特定权限的IAM用户。在整个攻击生命周期中，他们还会创建附加了AWS托管AdministratorAccess策略的额外IAM用户，以获得目标环境的全部权限。该组织一贯会留下"Java_Ghost"的EC2安全组作为其标志，描述为"We Are There But Not Visible"。  
  
  
原文链接：  
  
https://cybersecuritynews.com/javaghost-leveraging-amazon-iam-permissions/  
  
  
**新型多语种恶意软件Sosano对阿联酋关键行业发动攻击**  
  
  
Proofpoint近日揭示，一种前所未见的多语种恶意软件正在针对阿联酋的航空、卫星通信和关键运输组织发动攻击。该恶意软件传递了Sosano后门程序，能在感染的设备上实现持久存在，并允许攻击者远程执行命令。  
  
  
Proofpoint揭示，攻击始于从被入侵公司INDIC Electronics发出的高度针对性的鱼叉式网络钓鱼邮件。这些邮件包含恶意URL，将受害者引导至一个伪造的域名(indicelectronics[.]net)，并提示下载一个ZIP压缩包("OrderList.zip")。  
  
  
该压缩包包含一个伪装成XLS文件的LNK文件，以及两个多语种PDF文件("about-indic.pdf"和"electronica-2024.pdf")。第一个PDF文件包含HTA代码，而另一个则隐藏了一个ZIP压缩包。使用多语种文件是为了规避检测，因为大多数安全工具只会检查第一种文件格式(PDF)，即一个良性文档，而完全忽略隐藏的恶意部分(HTA/ZIP负载)。  
  
  
执行LNK文件时，cmd.exe会启动mshta.exe，后者执行隐藏在第一个PDF中的HTA脚本，从而触发第二个PDF文件的启动。第二个PDF内的隐藏压缩包会将一个URL文件写入Windows注册表以实现持久化，然后执行一个XOR编码的JPEG文件，解码出一个DLL负载，即Sosano后门程序。一旦激活，Sosano就会与其位于"bokhoreshonline[.]com"的命令和控制(C2)服务器建立连接，等待执行文件操作、Shell命令和获取额外负载等命令。  
  
  
原文链接：  
  
https://www.infosecurity-magazine.com/news/espionage-campaign-targets-uae/  
  
  
  
**安全漏洞**  
  
  
  
**谷歌修复两个已被利用的Android零日漏洞**  
  
  
谷歌在2025年3月的Android安全更新中修复了43个漏洞，其中包括两个被利用于针对性攻击的零日漏洞。  
  
  
塞尔维亚当局利用了其中一个高危信息泄露漏洞(CVE-2024-50302)，该漏洞存在于Linux内核的人机接口设备驱动程序中，用于解锁被没收的设备。据报道，这个漏洞被以色列数字取证公司Cellebrite开发的Android零日漏洞利用链所利用。该利用链还包括上月修复的USB视频类零日漏洞(CVE-2024-53104)和ALSA USB声卡驱动程序零日漏洞。  
  
  
本月修复的第二个零日漏洞(CVE-2024-43093)是一个Android框架权限升级漏洞，由于Unicode规范化不正确，允许本地攻击者在不需要额外执行权限或用户交互的情况下，通过利用文件路径过滤器绕过访问敏感目录。  
  
  
此次Android安全更新还解决了11个可让攻击者在易受攻击设备上远程执行代码的漏洞。谷歌发布了两组安全补丁，2025-03-01和2025-03-05安全补丁级别。后者包含了前一批次的所有修复以及针对闭源第三方和内核子组件的补丁，可能不适用于所有Android设备。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/google-fixes-android-zero-days-exploited-in-targeted-attacks/  
  
  
**HPE远程管理工具存在RCE漏洞, PoC代码已公开**  
  
  
一项新披露的严重漏洞（CVE-2024-53676）影响了惠普企业(HPE)的Insight Remote Support工具,该漏洞可让未经身份验证的攻击者在易受攻击系统上远程执行任意代码。研究人员已公开发布了概念验证(PoC)漏洞利用代码。  
  
  
该漏洞源于该工具的文件上传功能对用户提供的文件路径验证不当。攻击者可注入目录遍历序列，覆盖系统文件并以系统级权限部署恶意负载。在处理通过SOAP请求提交的文件附件时，应用程序使用来自传入请求的未经验证的attachmentName参数构建文件路径，缺少对该参数的清理导致了路径遍历攻击。攻击者可提交精心编制的SOAP请求，将恶意的JavaServer Pages(JSP)文件上传到Web服务器部署目录，从而实现远程代码执行。不过，成功利用此漏洞需满足两个条件:拥有有效的设备注册凭证，以及Web服务器文件权限允许写入目标目录。  
  
  
研究人员发布了一个Python编写的PoC，演示了如何构建恶意SOAP请求。HPE尚未发布官方补丁，建议使用该工具的用户隔离管理接口、监控文件写入活动并分析SOAP流量，以缓解此漏洞的风险。  
  
  
原文链接： https://cybersecuritynews.com/hpe-remote-support-tool-vulnerability/  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kuIKKC9tNkAibeib6HUSIXJ4IhpazTYic3uwicySgIEk8ZeMC7X5evYXoNPHxoUlibqgo6Ilq0dRkGrMKibWtfcibYwsg/640?wx_fmt=jpeg "")  
  
合作电话：18311333376  
  
合作微信：aqniu001  
  
投稿邮箱：editor@aqniu.com  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/kuIKKC9tNkAfZibz9TQ8KWj4voxxxNSGMAGiauAWicdDiaVl8fUJYtSgichibSzDUJvsic9HUfC38aPH9ia3sopypYW8ew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
