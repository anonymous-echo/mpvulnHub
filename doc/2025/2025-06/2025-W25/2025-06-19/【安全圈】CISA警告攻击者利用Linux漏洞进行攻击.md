> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070247&idx=4&sn=a9da49b7c850012e89fbee85c39fe677

#  【安全圈】CISA警告攻击者利用Linux漏洞进行攻击  
 安全圈   2025-06-19 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhBiaVUOiabbsTez6CCTurmkCMOoSup4xUYztkFicNib55Uc9vMhX0ZI0ed4CNPvicia4ZIhPttm2Y4RhiaA/640?wx_fmt=png&from=appmsg "")  
  
CISA 已警告美国联邦机构，攻击者以 Linux 内核的 OverlayFS 子系统中的一个高严重性漏洞为目标，该漏洞允许他们获得 root 权限。  
  
此本地权限提升安全漏洞 （CVE-2023-0386） 是由 Linux 内核不当的所有权管理漏洞引起的，于 2023 年 1 月修补，并在两个月后公开披露。  
  
从 2023 年 5 月开始，GitHub 上还分享了多个概念验证 （PoC） 漏洞利用，使漏洞利用尝试更容易实现，并将漏洞推向 Linux 管理员修补优先级列表的顶部。  
  
根据 Datadog Security Labs 的分析，CVE-2023-0386 很容易被利用，并且会影响广泛的 Linux 发行版，包括 Debian、Red Hat、Ubuntu 和 Amazon Linux 等流行的发行版，如果它们使用的内核版本低于 6.2。  
  
“Linux 内核包含一个不正确的所有权管理漏洞，在用户如何将支持的文件从 nosuid 挂载复制到另一个挂载中，在 Linux 内核的 OverlayFS 子系统中发现了对具有功能的 setuid 文件的执行的未经授权的访问，”CISA 解释说。“此 uid 映射错误允许本地用户提升他们在系统上的权限。”  
  
根据 2021 年 11 月的约束性作指令 （BOD） 22-01 的规定，美国联邦机构现在必须保护其网络免受针对添加到 CISA 已知利用漏洞目录中的 CVE-2023-0386 漏洞的持续攻击。  
  
网络安全机构已给联邦民事行政部门 （FCEB） 机构三周时间，以便在 7 月 8 日之前修补其 Linux 系统。  
  
“这些类型的漏洞是恶意网络行为者的频繁攻击媒介，并对联邦企业构成重大风险，”CISA 在一份公告中表示，该公告将 CVE-2023-0386 标记为自修补以来首次被积极利用。  
  
周二，Qualys 威胁研究小组 （TRU） 的安全研究人员还警告说，威胁行为者可以利用最近修补的两个本地权限提升 （LPE） 漏洞，在运行主要 Linux 发行版的系统上取得根。  
  
Qualys TRU 开发了概念验证漏洞，并成功以 CVE-2025-6019 为目标，以获得 Debian、Ubuntu、Fedora 和 openSUSE 系统的 root 权限。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】血的教训！OneDrive封号致用户30年数据一夜蒸发](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070231&idx=1&sn=b4728fc998486ff0fd771d9ae575bf00&scene=21#wechat_redirect)  
  
  
  
[【安全圈】印度汽车共享公司Zoomcar遭遇数据泄露，影响840万用户](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070231&idx=2&sn=cfec459e816fe68e0d64a2a002758abf&scene=21#wechat_redirect)  
  
  
  
[【安全圈】社工老招再现 Scattered Spider锁定美保险公司进行渗透](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070231&idx=3&sn=ea9efbc6d81fbe8844e8b5eeabe46afd&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Hacklink黑产操控Google搜索排名：数千被劫持网站助攻SEO投毒攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070231&idx=4&sn=73d4cfe9ab70201f37a36c2242fed9ee&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
