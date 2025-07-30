> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1OTA1MzQzNA==&mid=2651248146&idx=1&sn=5ef4c9942a320bc7e46b5d456b4ec346

#  Notepad++ 存在严重权限提升漏洞，PoC已发布 | 史上最大规模DDoS攻击在短短45秒内传输了37.4TB的恶意流量  
e安在线  e安在线   2025-06-25 01:56  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1Y08O57sHWiahTldalExhOyzXNMO6kcO7ULmiclhSZfg8zVMLHEMUGBu3lBjFbjib8vsYDZzplofMSC7epkHHWpibw/640?wx_fmt=png&from=appmsg "")  
# Notepad++ 存在严重权限提升漏洞，PoC已发布  
  
Notepad++ 8.8.1版本中发现一个严重的权限提升漏洞，可能导致全球数百万用户面临系统完全被控制的风险。该漏洞编号为CVE-2025-49144，攻击者可通过二进制植入技术获取SYSTEM级权限，目前已有公开的概念验证演示。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38LEqIgxpLGJtu8bNZDFVwZicoV0ibgHPxWTOibyRus4K8Qvhde1j3D9mzJiceRtKP01UibYdJibE8QkQzA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part01**  
### 漏洞详情  
  
  
该漏洞影响2025年5月5日发布的Notepad++ v8.8.1安装程序，利用未受控的可执行文件搜索路径实现本地权限提升攻击。安全研究人员发现，安装程序会在当前工作目录中搜索可执行依赖项而未经适当验证，这为恶意代码注入创造了可乘之机。  
  
  
由于利用该漏洞所需的用户交互极少，安全风险尤为突出。攻击向量利用了Windows标准DLL搜索顺序机制，使攻击者能够在安装过程中自动加载具有提升权限的恶意可执行文件。  
  
  
**Part02**  
### 攻击方法与概念验证  
###   
  
攻击过程非常简单，充分展示了二进制植入攻击的危险性。攻击者可在Notepad++安装程序所在目录放置恶意可执行文件（如被篡改的regsvr32.exe）。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38LEqIgxpLGJtu8bNZDFVwZibjf8ZiccZZE9nPwia5FmJiaI2FF23EnYnkE24icj3D2Q1Bbf3VrEDaTtrw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
当用户运行安装程序时，系统会自动以SYSTEM权限加载恶意文件，使攻击者获得目标机器的完全控制权。概念验证材料中的Process Monitor日志清晰展示了安装程序在当前目录搜索可执行文件的漏洞行为。  
  
  
**Part03**  
### 影响范围与风险  
  
  
Notepad++在全球拥有大量用户，截至2025年6月，其官网月访问量超过160万次。在IDE和文本编辑器类别中，Notepad++约占1.33%的市场份额，意味着全球可能有数十万安装存在漏洞。  
  
  
考虑到Notepad++在开发者、IT专业人员和各行业普通用户中的普及程度，该漏洞带来的风险尤为严重。企业环境中广泛使用该软件进一步放大了潜在攻击影响，可能导致数据泄露、网络横向移动和系统完全被控制。  
  
  
**Part04**  
### 缓解措施与响应  
###   
  
Notepad++开发团队迅速做出响应，发布8.8.2版本修复该关键漏洞。补丁遵循微软安全加载指南，实现了安全的库加载实践和对可执行依赖项的绝对路径验证。强烈建议用户立即更新至修复版本以消除安全风险。  
  
  
安全专家建议采取额外防护措施，包括从安全隔离目录运行安装程序，以及部署能够检测二进制植入攻击的终端安全解决方案。企业还应考虑实施应用程序白名单和加强对安装过程的监控。  
  
  
该事件凸显了安全软件开发实践的重要性，特别是在可信应用程序的安装程序设计和依赖项加载机制方面。随着网络威胁不断演变，安全社区强调需要对影响广泛使用软件平台的新威胁采取主动漏洞管理和快速响应措施。  
  
# 史上最大规模DDoS攻击在短短45秒内传输了37.4TB的恶意流量  
  
有记录以来，最大的分布式拒绝服务（DDoS）攻击于2025年5月中旬被Cloudflare成功阻止。攻击者发动了破坏性极强的每秒7.3太比特（Tbps）攻击。短短45秒内，恶意流量高达37.4TB。  
  
  
这前所未有的网络攻击目标直指Cloudflare Magic Transit服务的托管服务商客户，攻击规模比前纪录高出12%。这彰显了现代DDoS攻击规模与技术的升级。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/5eH7xATwT39KsUtic3YDvP3Sdq7OiaEqsVPPtlUYvhRoqWhTSpE7Z7L7EbDQE4okZR4icybKcNfCacJtOa6VxrfuA/640?wx_fmt=gif&from=appmsg&wxfrom=13&tp=wxpic "")  
  
  
![图片1.png](https://mmbiz.qpic.cn/mmbiz_png/5eH7xATwT39KsUtic3YDvP3Sdq7OiaEqsV0Lia5MHHTPU3sgQ6ibVtMToFxeRIhy5R7gCOjVicpNFRYZ6OChgM3XPlQ/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
  
**多向量DDoS攻击**  
  
  
  
  
本次大规模攻击采用多向量方式。99.996%的攻击流量是UDP洪流，流量平均针对单个IP上的21,925个目标端口，峰值达每秒34,517个。  
  
  
**其他攻击向量**  
  
  
  
  
剩余的0.004%使用了精密的反射放大技术。包括：利用UDP端口17的Quote of the Day (QOTD)协议；利用UDP/TCP端口7的Echo协议攻击；利用monlist命令的网络时间协议（NTP）放大攻击。  
  
  
其他攻击向量包括：Mirai僵尸网络的UDP洪流；利用UDP端口111的Portmap服务；利用UDP端口520的路由信息协议版本1（RIPv1）攻击。  
  
  
**攻击来源**  
  
  
  
  
攻击流量来源的地理分布极为广泛。源自161个国家5,433个自治系统（AS）中的122,145个唯一源IP地址。  
  
  
巴西和越南是主要攻击来源地，各自贡献约25%的总流量。印度尼西亚、乌克兰、厄瓜多尔、泰国、美国和沙特阿拉伯合计贡献了另外三分之一的恶意流量。  
  
  
Telefonica Brazil（AS27699）是参与攻击的最大网络。贡献了10.5%的攻击流量。紧随其后的是Viettel Group（AS7552），贡献了9.8%。  
  
  
**自主检测与缓解技术**  
  
  
  
  
报告指出，Cloudflare防御系统利用先进数据包采样技术。该技术在Linux内核中使用eXpress数据路径（XDP）和扩展伯克利数据包过滤器（eBPF）程序，这能实时分析流量模式。  
  
  
公司专有的启发式引擎“dosd”（拒绝服务守护程序）自动生成多重指纹排列，以此识别攻击模式，同时能最大限度减少对合法流量的影响。  
  
  
攻击通过任播路由被检测并缓解，流量被分散到全球293个地点的477个数据中心，这是利用了Cloudflare的网络基础设施。每个数据中心都能维护本地威胁情报缓存，缓存通过流言协议更新，确保新出现的攻击特征能在亚秒级内传播至整个网络。  
  
  
这一集成的自主框架实现了7.3 Tbps攻击的零接触缓解。而攻击在其45秒内被完全遏制，没有触发事件响应协议。  
  
  
整个缓解过程完全自动化，无需人工干预，未发生告警或服务事故。这展示了现代云端DDoS防护系统应对日益复杂网络威胁的有效性。  
###   
  
  
  
声明：除发布的文章无法追溯到作者并获得授权外，我们均会注明作者和文章来源。如涉及版权问题请及时联系我们，我们会在第一时间删改，谢谢！文章来源： 来源：安在、FreeBuf、  
  
参考来源：  
  
Notepad++ Vulnerability Let Attacker Gain Complete System Control – PoC Releasedhttps://cybersecuritynews.com/notepad-vulnerability/  
  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaM9uv5Q89hYMT8zuKQtQYuvSPy0HyyLwRShZOMcoGgoBy6qiatgDhW3UhCXGVXiaEbS8ANmZwViaMAw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
