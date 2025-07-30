> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1OTA1MzQzNA==&mid=2651248151&idx=1&sn=757d9ada4ed57f09ef720dcca0cef6a5

#  实战：滥用MCP服务攻击企业AI，窃取企业内部数据 | WinRAR目录遍历漏洞允许通过恶意文件执行任意代码  
e安在线  e安在线   2025-06-26 04:04  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1Y08O57sHWiahTldalExhOyzXNMO6kcO7ULmiclhSZfg8zVMLHEMUGBu3lBjFbjib8vsYDZzplofMSC7epkHHWpibw/640?wx_fmt=png&from=appmsg "")  
# 实战：滥用MCP服务攻击企业AI，窃取企业内部数据  
  
6月25日消息，AI代理为IT工单服务带来了巨大潜力，同时也引入了新的风险。  
  
美国云安全公司Cato Networks的研究人员披露，知名研发软件厂商Atlassian推出的新型AI代理协议，可能被攻击者通过提示注入在Jira Service Management（JSM）中提交恶意支持工单。  
  
研究人员将这一概念验证（PoC）攻击命名为“以AI为生”（Living off AI）攻击，并在最新发布的报告中详细阐述了该PoC攻击的技术概览。  
  
  
**MCP：日益流行的AI代理协议标准**  
  
  
2025年5月，Atlassian推出MCP服务器，将AI深度整合进企业工作流。  
  
MCP（模型上下文协议）是一项开放标准，由美国知名大模型公司Anthropic（Claude出品方）于2024年11月首次发布。MCP服务器用于管理并利用大模型运行过程中的上下文信息。  
  
MCP的架构由本地运行的MCP主机和多个MCP服务器组成。充当代理的主机可以是AI驱动的应用程序（如Claude桌面版）、设备上的大模型（如Claude Sonnet），或集成开发环境（如Visual Studio）。  
  
Atlassian MCP服务支持多项AI驱动的功能，包括在JSM与Confluence中生成工单摘要、自动回复、分类及智能推荐等。  
  
它还允许支持工程师和内部用户通过原生界面直接与AI交互。  
  
  
**“以AI为生”攻击解析**  
  
  
研究人员利用Atlassian的MCP资产对Atlassian JSM发起PoC攻击，演示匿名外部用户如何通过JSM执行一系列恶意操作，包括：  
- 通过提交工单触发Atlassian MCP交互，随后由使用Claude Sonnet等MCP工具的支持工程师处理，从而自动激活恶意流程；  
  
- 引导支持工程师在毫不知情的情况下，借助Atlassian MCP执行注入指令；  
  
- 访问JSM中原本对外部威胁者隐藏的内部租户数据；  
  
- 通过将提取的数据写回工单本身，实现对与支持工程师关联租户的数据窃取。  
  
典型攻击链如下：  
1. 外部用户提交经过精心构造的支持工单；  
  
1. 与租户关联的内部代理或自动化工具调用连接至MCP的AI操作；  
  
1. 工单中的提示注入有效载荷在内部权限下被执行；  
  
1. 数据被提取至威胁者的工单，或在内部系统中遭到篡改；  
  
1. 若缺乏沙箱或验证机制，威胁者即可借内部用户之手获得全面访问权限。  
  
研究人员指出：“值得注意的是，在本次PoC演示中，威胁者从未直接访问Atlassian MCP。真正执行恶意指令的是毫不知情的支持工程师，他们被充当成了代理。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWjiaPEzRWDJApKXhm03sRjIUicoDAfgEvMMt0bceiakOPNcibjIoHQWcM6cIYOzDe6eShFofllv5WI1lA/640?wx_fmt=jpeg "")  
  
图：通过Jira Service Management进行的提示注入  
  
尽管本次攻击演示以Atlassian为例，Cato研究人员认为，任何在处理不受信输入时缺乏提示隔离或上下文控制的AI环境均面临同样风险。  
  
他们补充道：“我们展示的风险并非某一家厂商独有，而是一种通用模式。一旦外部输入流在MCP中得不到控制，威胁者就能滥用此路径，在无需身份验证的情况下获得特权访问。”  
  
“许多企业或已采用类似架构，将MCP服务器联通外部系统与内部AI逻辑，以提升工作流效率和自动化水平。此类设计模式带来全新的风险，必须严肃对待。”  
  
  
**缓解措施建议**  
  
  
研究人员建议，如要预防或缓解此类攻击，应制定规则，阻止或告警所有远程MCP工具调用（如创建、新增或编辑操作）。  
  
此举可帮助用户：  
- 在AI驱动操作中贯彻最小权限原则；  
  
- 实时监测可疑提示的使用；  
  
- 保持全网MCP活动的审计日志。  
  
在该报告发布前几天，协同办公平台Asana宣布其MCP服务器[存在漏洞](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247514546&idx=1&sn=9e475c8d0292ac7001b0d6491e030db9&scene=21#wechat_redirect)  
  
，致使客户数据被暴露给其他组织。  
  
  
# WinRAR目录遍历漏洞允许通过恶意文件执行任意代码  
  
  
  
![WinRAR漏洞允许通过恶意文件执行任意代码](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibeEzGHicGrfDkL0C5buG56XdDHdQUkavhK1ZCV45r4J7un8ic3nEhGxcG0gRdquiciakz1FE74iaTpdxg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part01**  
### 漏洞概述  
  
  
1. WinRAR软件中存在一个高危漏洞（CVE-2025-6218），攻击者可利用该软件处理压缩包内文件路径的方式执行任意代码  
  
  
2. 该漏洞允许攻击者使用特制的包含目录遍历序列的压缩文件，最终实现远程代码执行  
  
  
3. 漏洞利用需要用户交互，如下载或打开恶意压缩包，或访问被攻陷的网页  
  
  
4. RARLAB已发布安全更新，用户应立即升级至最新版本以保护系统安全  
  
  
**Part02**  
### 漏洞详情  
###   
  
RARLAB公司的WinRAR压缩软件中发现了一个严重安全漏洞，远程攻击者可通过恶意压缩文件执行任意代码。该漏洞编号为CVE-2025-6218，CVSS评分为7.8分，影响这款广泛使用的文件压缩工具处理压缩包内目录路径的方式。  
  
  
远程代码执行漏洞  
  
  
该目录遍历漏洞被正式记录为ZDI-25-409，对全球WinRAR用户构成重大安全风险。这个远程代码执行（RCE）漏洞允许攻击者在当前用户权限下执行恶意代码，但需要用户交互才能成功利用。  
  
  
漏洞的CVSS向量字符串AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H表明，在机密性、完整性和可用性方面都具有高度影响。漏洞利用机制主要基于压缩包内特制的文件路径，这些路径可能导致WinRAR进程遍历到非预期的目录。  
  
  
这种路径遍历攻击绕过了正常的安全边界，使攻击者能够将文件写入预期解压目录之外的位置。此类漏洞尤其危险，因为与其他攻击技术结合使用时，可能导致系统完全被攻陷。  
  
**Part03**  
### 技术分析  
  
  
技术分析显示，该漏洞存在于WinRAR处理压缩包文件的路径处理例程中。发现并报告该漏洞的安全研究员whs3-detonator确认，包含恶意目录路径的特制压缩文件可以操控解压过程。攻击需要目标用户访问恶意网页或打开恶意压缩文件，因此容易受到社会工程攻击。  
  
  
技术利用手段基于嵌入在压缩文件结构中的目录遍历序列。这些序列可能包含"../"等相对路径指示符，使攻击者能够导航到预期解压目录之外的位置。一旦成功，该漏洞便能在运行WinRAR的用户权限下执行任意代码。  
  
**Part04**  
### 风险因素  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibeEzGHicGrfDkL0C5buG56XfBexmKuB3sdLCjA4CfPG1jZiaB2m6xcCIeZpD2xBD8kmLTvulIXTibmw/640?wx_fmt=png&from=appmsg "")  
  
**Part05**  
### 缓解措施  
###   
  
RARLAB已迅速响应这一关键安全问题，发布了WinRAR更新版本。建议用户升级至WinRAR 7.11版本，该版本具有更快的速度、改进的可用性和新的自定义选项。  
  
  
厂商已发布有关安全更新的详细信息，强调应用此补丁以防止潜在利用的重要性。由于该漏洞的高严重性评级以及针对系统的远程代码执行攻击可能性，各组织应优先考虑此更新。  
  
  
  
  
声明：除发布的文章无法追溯到作者并获得授权外，我们均会注明作者和文章来源。如涉及版权问题请及时联系我们，我们会在第一时间删改，谢谢！文章来源： 来源：安全内参、FreeBuf、  
  
参考资料：infosecurity-magazine.com  
  
参考来源：  
  
WinRAR Directory Vulnerability Allows Arbitrary Code Execution Using a Malicious Filehttps://cybersecuritynews.com/winrar-vulnerability/  
  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaM9uv5Q89hYMT8zuKQtQYuvSPy0HyyLwRShZOMcoGgoBy6qiatgDhW3UhCXGVXiaEbS8ANmZwViaMAw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
