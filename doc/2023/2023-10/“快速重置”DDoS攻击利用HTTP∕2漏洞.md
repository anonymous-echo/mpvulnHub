#  “快速重置”DDoS攻击利用HTTP/2漏洞   
布加迪  嘶吼专业版   2023-10-13 14:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
谷歌、AWS和Cloudflare三家公司周二发布公告称，它们阻止了据称有史以来最大的DDoS攻击。  
  
这次攻击是由一个新的DDoS漏洞（编号为CVE-2023-44487）引起的，涉及HTTP/2协议，用于互联网上传输文件的一套标准化规则。美国国家标准与技术研究所（NIST）官网上的漏洞页面介绍说到：“HTTP/2协议之所以允许拒绝服务（服务器资源消耗），是由于请求取消可以快速重置许多请求流。”  
  
作为多方协调披露的一部分，谷歌云、亚马逊网络服务（AWS）和Cloudflare都发布了博文和公告，提供了有关这条DDoS攻击途径的更多技术信息。在谷歌发布的博文中称：这家科技巨头称之为“迄今为止最大的DDoS攻击，峰值时期每秒超过3.98亿个请求。”  
  
在Cloudflare的技术分析博文中写道，它追踪到峰值时期每秒超过2.01亿个请求，几乎是之前观察到的创纪录攻击的三倍。  
  
Cloudflare的两名工程师Lucas Pardue和Julien Desgats说：“令人担忧的是，攻击者仅用2万台机器组成的僵尸网络就能发动这等规模的攻击。现在的僵尸网络由数十万乃至数百万台机器组成。考虑到整个互联网通常每秒只出现10亿到30亿个请求，可想而知，使用这种方法可以将整个互联网的请求都集中在少数目标上。”  
  
在另一篇博文中，谷歌的两名工程师Juho Snellman和Daniele Iamartino专门介绍了这起攻击和攻击途径的工作原理。他们写道，这次名为Rapid Reset（“快速重置”）的攻击持续了几个月，在8月份达到了高峰。  
  
博文作者说道，自2021年底以来，谷歌服务遭到的大多数应用层或第7层DDoS攻击基于HTTP/2，“无论从攻击数量来看还是从峰值请求速率来看”。  
  
谷歌表示，HTTP/2攻击之所以占主导地位，是由于这种协议能够以多路并发“流”的方式处理请求，而不是像HTTP/1.1那样需要按顺序处理请求。正因为如此，HTTP/2攻击能够执行的并发请求数量比利用旧协议的攻击多得多。  
  
就快速重置DDoS而言，攻击客户端“像在标准的HTTP/2攻击中一样，一次性打开大量的请求流，但客户端不是等待服务器或代理对每个请求流作出响应，而是立即取消每个请求。”  
  
更多的技术细节可以在谷歌、Cloudflare和亚马逊的博文中找到。  
  
谷歌认为，其负载均衡基础设施“基本上”在其网络的边缘设法阻止了快速重置攻击，防止任何中断。亚马逊表示，AWS在“短短几分钟内”确定了攻击的性质，其CloudFront内容分发网络自动化解了攻击。  
  
与此同时，Cloudflare表示，它看到了502错误和请求数量激增，但通过改变其技术堆栈和技术故障中详细说明的缓解措施，迅速做出了反应。  
  
关于缓解措施，谷歌，阻止单个请求还不够，一旦发现滥用情况，就需要关闭整条TCP连接，更广泛的缓解包括跟踪分析连接统计数据以及基于各种信号为GOAWAY帧类型的内置HTTP/2缓解优先考虑连接。这三家供应商还都实施了另外的内部检测和缓解措施。  
  
Pardue和Desgats在Cloudflare的博文中警告，CVE-2023-44487和快速重置攻击的风险普遍存在。他们写道：“由于攻击滥用了HTTP/2协议的底层弱点，我们相信任何实施了HTTP/2的供应商都将受到攻击。这包括每一台现代Web服务器。”  
  
Forster说：“组织必须将事件管理、打补丁和完善安全保护措施变成一种持续的过程。针对每个漏洞变体的补丁降低了风险，但并不总是完全消除风险。在这种情况下，Cloudflare开发了专门的技术以缓解零日漏洞的影响。”  
  
参考及来源:https://www.techtarget.com/searchsecurity/news/366554941/Rapid-Reset-DDoS-attacks-exploiting-HTTP-2-vulnerability  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibiaP5BNKpEXq4IaZyxNRicnicibq9fu9dF3SJIOCnAnkzdOOfPtR55LLulc3GGXuzxnicKNxdfzJRH7lQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibiaP5BNKpEXq4IaZyxNRicnicg04URAz3Kd7icLibtI8yazrhryLicL2CIxHfviceSR31W5cibQwNOV59qlA/640?wx_fmt=png "")  
  
  
  
