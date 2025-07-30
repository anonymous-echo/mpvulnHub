#  【安全圈】Dell Unity 企业存储系统现严重漏洞，攻击者借此可实现 root 权限接管   
 安全圈   2025-04-01 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliafKqvJroMyht7kEelicQjic3jichC39Jtlte4YG9N8icxa5GOxpZMTxZfWw1zDp8I2Em0ibcZhnLdfpng/640?wx_fmt=png&from=appmsg "")  
  
Dell Technologies 发布了一项关键的安全更新，以修复其 Unity 企业存储系统中存在的多个严重漏洞。这些漏洞可能会让攻击者以 root 权限执行任意命令、删除关键系统文件，并在无需进行身份验证的情况下开展其他恶意活动。  
  
安全研究人员发现了 16 个不同的漏洞，这些漏洞影响运行 5.4 版本及更早版本的 Dell Unity、Dell UnityVSA 和 Dell Unity XT 存储系统，其中最严重的漏洞在通用漏洞评分系统（CVSS）中的评分为 9.8 分。  
  
**Dell****Unity 存储系统的严重漏洞********CVE-2025-22398：远程 root 命令执行**  
  
CVE-2025-22398（CVSS 评分为 9.8）漏洞使得攻击者可以通过未经身份验证的远程命令执行以 root 权限完全接管系统。  
  
攻击者可以构造针对 Unity API 的恶意网络请求，注入能以完全管理员权限执行的操作系统命令。  
  
这一漏洞使各组织面临着被部署勒索软件、数据被窃取以及被安装持久后门程序的风险。  
  
Dell 发布的安全公告明确指出，对该漏洞的利用 “可能会导致系统被攻击者接管”，其接近满分的 CVSS 评分反映出该漏洞具有网络可访问性、攻击难度低以及会导致机密性 / 完整性 / 可用性完全丧失等特点。  
  
**CVE-2025-24383：特权文件删除**  
  
CVE-2025-24383（CVSS 评分为 9.1）漏洞使得攻击者能够以 root 权限通过未经身份验证的远程操作删除任意文件，从而对文件系统造成同样危险的破坏。  
  
攻击者可以删除关键的系统二进制文件、配置文件或数据存储，这有可能会使存储操作陷入瘫痪，或者为后续攻击创造条件。  
  
虽然由于该漏洞对机密性的影响较小（无影响对比高影响），其评分略低，但它与 CVE-2025-22398 漏洞具有相同的攻击途径和特权提升严重程度。  
  
**其他安全漏洞**  
  
该安全公告还详细说明了 CVE-2025-24381 漏洞，这是一个开放重定向漏洞，评分为 8.8 分，攻击者可能会利用该漏洞通过恶意重定向进行网络钓鱼攻击和会话窃取。  
  
进一步加剧风险的是多个本地特权提升漏洞（CVE-2024-49563、CVE-2024-49564、CVE-2024-49565、CVE-2024-49566、CVE-2025-23383、CVE-2025-24377、CVE-2025-24378、CVE-2025-24379、CVE-2025-24380、CVE-2025-24385、CVE-2025-24386），CVSS 评分为 7.8 分，这些漏洞使得低权限的本地用户能够以 root 权限执行命令。  
  
另外还有两个命令注入漏洞（CVE-2024-49601 和 CVE-2025-24382），CVSS 评分为 7.3 分，使得未经身份验证的远程攻击者能够执行影响程度较低的命令。  
  
Dell 对负责任地披露这些漏洞的安全研究人员表示感谢：“prowser” 发现了关键的远程命令注入漏洞，而来自 Ubisectech Sirius 团队的 “zzcentury” 和 “xiaohei” 发现了本地特权提升漏洞。  
  
**受影响产品及修复措施**  
  
这些漏洞影响了 Dell 广受欢迎的企业存储系统，包括运行 5.4 版本及更早版本的 Unity、UnityVSA 和 Unity XT。  
  
Dell 已发布了 Dell Unity 操作环境（OE）5.5.0.0.5.259 版本作为修复方案，并强烈建议所有客户立即进行升级。  
  
使用受影响的 Dell Unity 系统的组织应评估自身面临的风险，实施推荐的更新，并在这些关键漏洞尚未修复期间监控是否存在被攻击利用的迹象。  
  
来源：  
https://cybersecuritynews.com/multiple-dell-unity-vulnerabilities/  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】注意！黑客利用 DNS MX 记录动态创建超 100 品牌虚假登录页面](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068822&idx=1&sn=8cba37c3dfd85ad34b512670c7a79919&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Triton RAT 利用 Telegram 远程访问和控制系统](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068822&idx=3&sn=ce96b1255407d26cc95c8b44d7d6c835&scene=21#wechat_redirect)  
  
  
  
[【安全圈】威胁通告：黑客组织利用WordPress MU插件目录隐匿恶意软件实现远程代码执行](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068822&idx=4&sn=77b1848c9bb8693ceed4d6eb03368eb5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】外包保洁员段某泄露3项国家机密！国安部披露细节：其为满足个人私欲，主动联系境外间谍情报机关](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068802&idx=1&sn=a972008459c14da64c552bc0c08183bb&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
