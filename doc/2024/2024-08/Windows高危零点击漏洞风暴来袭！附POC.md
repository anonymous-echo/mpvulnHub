#  Windows高危零点击漏洞风暴来袭！附POC   
点击关注👉  马哥网络安全   2024-08-10 12:02  
  
点击上方  
蓝字  
，后台回复  
【  
合集  
】  
获取  
网安资源  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAlsibPLBWFYAlDhUsnJ5qH1jdXuNPwibuCR7nUdHApFSJibIOOrTOYxLP5lvicmZcZTgwLJbRrToRiaN3g/640?wx_fmt=png&from=appmsg "")  
  
**基本信息**  
  
国外网站上公开了微软Windows操作系统一个高危漏洞（CVE-2024-38077）的详情和概念验证代码。经分析确认，该漏洞获得CVSS 9.8的评分，是**Windows平台近十年来罕见的可以稳定利用、影响广泛的远程零点击(Zero-Click)/认证前（Pre-Auth) 漏洞**  
。研究人员针对该漏洞放出了稳定利用的验证视频并表示，这种漏洞已多年未曾出现。  
  
由于漏洞涉及远程桌面授权服务（Remote Desktop License Service)，研究者将其命名为**MadLicense（狂躁许可），**  
并表示还将进一步公开披露更多类似漏洞。  
  
**影响范围**  
****  
  
该漏洞影响范围广泛，涉及**Windows 2000后所有Windows服务器操作系统**  
：包括广泛使用的Windows Server 2008 R2/2012/2016，甚至波及微软内部预览版本：提供了“下一代安全技术”的Windows Server 2025系统。  
  
通过该漏洞，攻击者只须针对开启了相关服务的服务器发送特制数据包，**即可完全控制目标系统，获得最高的SYSTEM权限**  
，实现“低门槛、高回报”的攻击效果。上一个有如此影响力的Windows远程漏洞可能要追溯到2019年的BlueKeep（CVE-2019-0708）漏洞，相较BlueKeep，MadLicense的稳定性更高，且不受网络级身份验证（Network Level Authentication，NLA)的影响。  
  
研究人员的全网扫描结果显示，公网上至少有17万台活跃的Windows服务器开启了相关服务，而内网中受影响的服务器数量可能更多。鉴于该漏洞已有成熟稳定的利用证明和公开的验证代码，我们预计攻击者可能迅速开发出完整的漏洞利用方案。更令人担忧的是，这可能引发类似"永恒之蓝"的蠕虫级攻击，导致大规模网络安全威胁。  
  
**背景和相关补丁**  
****  
  
"狂躁许可"（CVE-2024-38077）漏洞针对的是Windows操作系统的远程桌面授权服务。该服务为Remote Desktop Services（RDS，即常见的远程桌面服务）提供认证和授权，确保只有授权用户或设备可访问RDS。远程桌面授权服务广泛存在于启用远程桌面的机器上。  
  
远程桌面默认仅允许两个同时会话，需购买许可证以启用更多会话。管理员在安装远程桌面（3389端口）时通常会选择安装远程桌面授权服务，导致许多开启3389端口的服务器同时启用了该服务。  
  
安全研究员于2024年5月初向微软报告此漏洞，微软随后在7月的例行补丁日修复。鉴于漏洞的严重性和广泛影响，微软特别为已停止安全更新的系统（如Windows Server 2008/2008 R2/2012/2012 R2）提供了补丁。  
  
**关于漏洞情报**  
****  
  
值得注意的是，截至目前，微软官方补丁公告仍将该漏洞标记为**"不太可能被利用"**  
（Exploitation Less Likely）。然而，补丁发布后稳定利用的证明和验证代码的迅速出现，似乎印证了这一评估的不准确性。  
  
微软的"可利用性分析"（Exploitability Assessment）通常是Windows、Office等产品用户安全团队和绝大多数第三方安全公司提供的漏洞情报的关键参考。但”  
狂躁许可“漏洞的案例凸显了**仅依赖官方或开源情报可能存在的风险和”不靠谱“**  
  
**如何验证和修复**  
****  
  
**手动检查******  
  
所有未安装2024年7月补丁的Windows服务器操作系统均受此漏洞影响。  
  
服务检查：验证Remote Desktop Licensing服务是否启动，相关补丁是否未安装。  
  
文件版本检查：查看lserver.dll文件版本，确定是否为易受攻击版本。  
  
**手动修复******  
  
用户可参考微软安全公告，手动安装相关补丁。对于无法安装补丁的情况，微软建议采取以下缓解措施：如非必要，关闭Remote Desktop Licensing服务。注意：此操作将影响远程桌面授权认证和分发，可能导致远程桌面出现问题影响正常业务或降低远程桌面安全性。同时，微软公告中提出：即便采取了上述缓解措施，微软仍强烈建议尽快修复漏洞以全面防护系统。  
  
内容转自乌雲安全  
  
（如有侵权请联系删除）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/INa3lxHH4I2aV3zCmfiaj4cXeQ2HQd6s53wJS36HYI65ib48fujDK8najfWiahicsljzsdT3dfVS8HHyxaviaSd8g2g/640?wxfrom=5&wx_lazy=1&wx_fmt=png&wx_co=1 "")  
  
  
**今日福利**  
  
  
**《八维一体网络安全精英课程》**  
  
**全天正课免费试听**  
，名额抢占中~  
  
也可来  
**主直播间**  
，跟老师近距离  
  
**扫描下方二维码，发你直播链接**  
  
👇  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkpI3RsdDLpI57uclJMVu5HmLa99TFJh4E3BgGKeObsYIItauCneHZ5zb4Y4b3UL7zkv1aHPJ7sfQ/640?wx_fmt=png&from=appmsg "")  
  
  
扫码发你上课链接  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkpI3RsdDLpI57uclJMVu5HLs5CeBf4HBjrcwfXdGdTkn9AwBvmBY0icYiac8G3IA1LDuI63fnff6kA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/UkV8WB2qYAnkkpVrLelBibsrB2w3pITQf1qGTxDmPL3EhYWI4cIOdYUyaK8hCUflbs6hpbl6QCEwiaUMIGyUNrVg/640?wx_fmt=gif&from=appmsg "")  
  
[●资料：终于有人把CISP题库分享出来了，考前快背！](http://mp.weixin.qq.com/s?__biz=MzkxMzMyNzMyMA==&mid=2247561335&idx=2&sn=c7f1bc8a9dfec561524faebe8dae3526&chksm=c17ce5c0f60b6cd6b9c1b1679526d4bc796bc4cd92f9749494af7bdd5b19b6f972c2d2ad8f44&scene=21#wechat_redirect)  
  
  
[●干货：防火墙是个什么东东？学安全的得懂吧](http://mp.weixin.qq.com/s?__biz=MzkxMzMyNzMyMA==&mid=2247535797&idx=1&sn=c93f92ba5926f7604f9c15a6cdb5d076&chksm=c17d5902f60ad014327180e1431854f61100bc859466cb75fbde56a3d8f7a530cf71c8cbf5bf&scene=21#wechat_redirect)  
  
  
[●课程：2024年八维一体全新安全培训（web安全+渗透测试+代码审计等）](http://mp.weixin.qq.com/s?__biz=MzkxMzMyNzMyMA==&mid=2247559335&idx=2&sn=1b82523d8f9dd61afd0f828f1b414dd1&chksm=c17cfd10f60b74065b8e0423861b06d7b399bd40b39de623d27e9bfe55bb86ffc346cf3e6bb0&scene=21#wechat_redirect)  
  
  
[●热点：黑客有多胆大？巴黎奥运会遭遇黑客攻击，并要求支付加密货币作为赎金](http://mp.weixin.qq.com/s?__biz=MzkxMzMyNzMyMA==&mid=2247561453&idx=1&sn=765543676c01aaaca6ed94e7585eb6ce&chksm=c17ce55af60b6c4c0e7832284305ac64e66f341da6b9feefe7c1389efd93112be3e304f76f0d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAnkkpVrLelBibsrB2w3pITQfU8PJV3Dl3vf29NibrLxUffztKHQGUL1ZD2gpl7N5KGAoSR5sDib2yCsg/640?wx_fmt=png&from=appmsg "undefined")  
  
**扫码咨询**  
  
  
扫码为你答疑解惑  
  
更多资料和课程免费咨询  
  
  
**关注马哥网络安全 获取更多学习福利:**  
  
  
  
  
  
后台回复“  
加群”，拉你进网安技术交流群  
  
  
后台回复“  
思维导图”，领web安全思维导图  
  
  
后台回复“  
面试题”，领网安高频面试题合集  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuyhG7ov7jias9RkFM1FOEDrAXFddqIJlBVau6xTf2r995bEhuSvKDv9g/640?wx_fmt=gif "")  
  
**点分享**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuCF8MCIU4Tza4W8QUQZwF2rjQ5Rq1yoZ9zgHS23H54f6K509I2w7goA/640?wx_fmt=gif "")  
  
**点在看**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDutiabZ8gOCxQpIIYNIIFE5njJDzRnVozgOjGzImicBOtNYaBdzWwPZ5uQ/640?wx_fmt=gif "")  
  
**点点赞**  
  
  
