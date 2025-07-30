> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1OTA1MzQzNA==&mid=2651248204&idx=1&sn=178c491f38246ca9d1e8161b2c9cc9db

#  微软紧急修复高危蠕虫级RCE漏洞，威胁全网Windows系统 | 用“算力门槛”阻击AI爬虫  
e安在线  e安在线   2025-07-11 02:04  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1Y08O57sHWiahTldalExhOyzXNMO6kcO7ULmiclhSZfg8zVMLHEMUGBu3lBjFbjib8vsYDZzplofMSC7epkHHWpibw/640?wx_fmt=png&from=appmsg "")  
# 微软紧急修复高危蠕虫级RCE漏洞，威胁全网Windows系统  
  
微软已发布关键安全更新，修复编号为CVE-2025-47981的高危漏洞。该漏洞存在于SPNEGO扩展协商(NEGOEX)安全机制中，属于基于堆的缓冲区溢出漏洞，影响多个Windows和Windows Server版本。  
  
  
该漏洞CVSS评分为9.8分(满分10分)，属于最高危级别，可在无需用户交互的情况下实现远程代码执行。  
  
  
**Part01**  
## 核心要点  
  
  
1. Windows SPNEGO中存在基于堆的缓冲区溢出漏洞，CVSS评分9.8/10，可实现远程代码执行  
  
  
2. 攻击者无需用户交互或特权，仅需向服务器发送恶意消息即可执行代码  
  
  
3. 影响Windows 10(1607及以上)、Windows 11及Windows Server等33种系统配置  
  
  
4. 微软于2025年7月8日发布更新，建议优先部署在面向互联网的系统及域控制器上  
  
  
该漏洞允许未经授权的攻击者通过网络连接执行任意代码，对企业环境构成严重威胁。  
  
  
**Part02**  
## 可蠕虫传播的RCE漏洞  
  
  
该漏洞存在于Windows SPNEGO扩展协商机制中，该机制是对简单且受保护的GSS-API协商机制的扩展。  
  
  
CVE-2025-47981被归类为CWE-122，属于可远程利用的基于堆的缓冲区溢出漏洞。其CVSS向量字符串CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C表明，该漏洞可通过网络发起攻击，复杂度低，无需特权或用户交互，但对机密性、完整性和可用性影响极大。  
  
  
安全研究人员评估该漏洞"极有可能被利用"，不过截至披露时尚未发现公开利用代码或实际攻击案例。该漏洞尤其影响运行Windows 10版本1607及更高版本的客户端计算机，这些系统默认启用了组策略对象"网络安全：允许PKU2U身份验证请求使用在线身份"。  
  
  
攻击者可通过向受影响服务器发送恶意消息来利用CVE-2025-47981，可能获得远程代码执行能力。基于堆的缓冲区溢出发生在NEGOEX处理机制中，允许攻击者覆盖内存结构并控制程序执行流程。这种可蠕虫传播的特性意味着漏洞可能通过网络连接的系统自动传播，无需用户干预。  
  
  
该漏洞由安全研究人员通过协调披露机制发现，包括匿名贡献者和Yuki Chen。微软对这些研究人员的致谢体现了负责任漏洞披露对维护企业安全态势的重要性。  
  
  
**Part03**  
## 风险因素  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibzavJNKq3vfiaQIbcHJwllknS7gPBxytEzyvddKEzOdLeCvO0cogDZ2PzTs5g5dTOlkibx6VHsbvyg/640?wx_fmt=png&from=appmsg "")  
  
  
**Part04**  
## 补丁部署  
  
  
微软于2025年7月8日发布了全面的安全更新，针对不同Windows配置修复了该漏洞。关键更新包括Windows Server 2025(版本10.0.26100.4652)、Windows 11 24H2版(版本10.0.26100.4652)、Windows Server 2022 23H2版(版本10.0.25398.1732)以及Windows Server 2008 R2(版本6.1.7601.27820)等旧系统的补丁。  
  
  
企业应优先为面向互联网的系统和域控制器部署这些安全更新。补丁可通过Windows Update、Microsoft更新目录和Windows Server更新服务(WSUS)获取。系统管理员应通过核对微软安全公告中的版本号来验证补丁是否成功安装，并考虑在部署补丁期间实施网络分段作为额外防御措施。  
  
# 用“算力门槛”阻击AI爬虫  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWjEdLYicibqqI9ubmGmc9UsqsKA6wdmpMPJZcxd1dpj55pxXbhrRMAHPC4sPhsK07wd3sNNLdKYLzNQ/640?wx_fmt=jpeg "")  
  
  
在大语言模型（LLM）成为数据黑洞的时代，越来越多的网站开始寻找新方式抵御AI公司如潮水般的抓取请求。一款名为Anubis的开源软件，正在以一种巧妙又高效的方式应对这一挑战：通过“工作量证明”（Proof of Work, PoW）机制，把AI爬虫挡在门外。  
  
  
  
**传统“反扒”手段失效，AI爬虫变本加厉**  
  
  
  
传统网站阻止爬虫的方式是通过robots.txt文件声明抓取规则，但这本质上依赖抓取方“自觉遵守”，缺乏强制力。很多AI公司对此置若罔闻。  
  
  
例如，《The Register》曾披露ClaudeBot一天内抓取网站百万次；Reddit也因Anthropic未经授权抓取论坛内容而提起诉讼。开源技术文档平台ReadTheDocs甚至报告称，仅一个AI爬虫一个月内就下载了73TB数据。  
  
  
  
**人类“快速通行”，爬虫“算力爆炸”**  
  
  
  
Anubis的思路源自反垃圾邮件领域上世纪90年代的技术Hashcash。与传统的验证码不同，Anubis不是验证你是不是人类，而是要求访客的浏览器在后台完成一个加密计算任务。  
  
  
对普通人类用户来说，这一过程几乎无感：浏览器在你几乎未察觉的几百毫秒内完成计算，并顺利放行。而对规模化运营AI爬虫的公司而言，则意味着需要调用整排服务器完成这些计算任务，带来极大的算力开销和电力成本。  
  
  
开发者Xe Iaso表示：“我只是想让AI公司‘付出代价’，让他们知道抓取别人的内容不是免费的。”Anubis也因此得名——源自埃及神话中为死者称量心脏的豺头神阿努比斯，隐喻这种“算力天平”。  
  
  
  
**技术原理简单，生态支持强大**  
  
  
  
Anubis主要依赖现代浏览器的webcrypto API和JIT引擎，因此即使是老旧设备也能流畅运行。其PoW算法虽然并不复杂，但在大规模并发下会形成有效阻力。  
  
  
目前，包括UNESCO、GNOME项目、WINE、Enlightenment在内的多个知名组织已部署Anubis。对开源社区来说，这是一种不涉足加密货币的“纯净”算力对策。开发者也明确拒绝类似Coinhive挖矿脚本的做法，避免被浏览器标记为恶意行为。  
  
  
除了Anubis，还有一些创意十足的反AI爬虫工具。例如：  
  
- Nepenthes：生成大量毫无意义的链接页面，将AI爬虫困在无用循环中；   
  
- Quixotic、Linkmaze：制造链接迷宫，扰乱抓取路径；  
  
- TollBit：提供付费级别反AI抓取解决方案。  
  
  
  
  
**争议焦点：“以暴制暴”是否行得通？**  
  
  
  
尽管PoW方式确实“浪费能源”，但支持者认为这是对抗更大浪费（AI抓取、模型训练耗电）的必要成本。反对者如FOSS倡导者Jamie Zawinski则表示：“这类机制本质上是通胀性、无效率的废物，只会引发新的军备竞赛。”  
  
  
但即使在批评声中，Anubis等项目仍获得越来越多独立开发者和中小型网站的支持。面对由OpenAI、Anthropic、Google等巨头驱动的AI爬虫浪潮，普通网站终于有了“以暴制暴”的工具。  
  
  
正如开发者所言：“我宁愿牺牲一点CPU，也不想再被这些公司无休止地榨取内容。”  
  
  
  
  
声明：除发布的文章无法追溯到作者并获得授权外，我们均会注明作者和文章来源。如涉及版权问题请及时联系我们，我们会在第一时间删改，谢谢！文章来源：   
  
FreeBuf、GoUpSec  
  
   
  
参考来源：  
  
Microsoft Patches Wormable RCE Vulnerability in Windows and Windows Server  
  
https://cybersecuritynews.com/microsoft-patches-wormable-rce-vulnerability/  
  
  
参考链接：  
https://www.theregister.com/2025/07/09/anubis_fighting_the_llm_hordes/  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaM9uv5Q89hYMT8zuKQtQYuvSPy0HyyLwRShZOMcoGgoBy6qiatgDhW3UhCXGVXiaEbS8ANmZwViaMAw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
