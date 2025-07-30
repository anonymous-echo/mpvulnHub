#  FreeBuf周报 | 马斯克DOGE网站数据库存在漏洞；OpenSSH曝高危漏洞   
Zicheng  FreeBuf   2025-02-22 10:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、一周好文，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icKwLMcanFbC55QibEQZcicWzPbPuSK8toicWFKWJdb80lUEFmtot9C6x1ztKiaXqCFV7tZlVnEMt9rLw/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**资讯热点**  
  
  
### 1. 网络犯罪转向社交媒体，攻击量达历史新高  
  
****  
最新报告显示，2024年在线威胁急剧增加，创下历史新高。仅在10月至12月期间，就拦截了25.5亿次网络威胁，平均每秒高达321次。第四季度遭遇威胁的风险上升至27.7%，其中社交工程攻击占所有拦截威胁的86%。这表明网络犯罪分子正利用越来越复杂的心理策略欺骗受害者。  
  
### 2. 马斯克DOGE网站数据库存在漏洞，任何人可随意篡改内容  
  
  
埃隆·马斯克旗下的政府部门效率部（DOGE）推出的一个网站被发现存在严重的安全漏洞，导致未经授权的用户可以直接修改其内容。这一漏洞由两名网络开发专家发现，原因在于网站使用了一个未加密的外部数据库，使得任何知晓该漏洞的人都可以在网站上发布和显示内容。  
  
### 3. SonicWall防火墙认证绕过漏洞正遭大规模利用  
  
****  
网络安全公司警告称，SonicWall防火墙中存在的一个严重认证绕过漏洞正在被积极利用，该漏洞编号为CVE-2024-53704 。2025年2月10日，随着Bishop Fox的研究人员公开发布了概念验证（PoC）漏洞利用代码，未修补设备组织面临的风险大大增加。  
  
### 4. 黑客滥用Microsoft Teams会议邀请窃取用户权限  
  
  
在一次复杂的网络攻击活动中，代号为Storm-2372的黑客利用Microsoft Teams会议邀请实施“设备代码钓鱼”攻击。  
  
### 5. 安卓新安全功能：通话期间禁止修改敏感设置  
  
****  
谷歌在安卓 16 Beta 2 中推出了一项突破性的安全功能，旨在通过阻止用户在通话期间修改敏感设置来打击电话诈骗。这项功能目前在测试版中上线，可阻止用户启用侧载应用和授予辅助功能权限等设置，而这两者常被诈骗者利用。  
  
### 6. XCSSET信息窃取恶意软件卷土重来，针对macOS用户和开发者  
  
****  
近日，一种新型 XCSSET macOS 模块化恶意软件变体在攻击活动中现身，其目标是窃取用户的敏感信息，涵盖数字钱包数据以及合法 Notes 应用程序中的数据。  
  
### 7. 新型Go语言后门利用Telegram Bot API进行隐蔽命令控制  
  
  
网络安全研究人员近日揭示了一种新型的基于Go语言的后门程序，该后门利用Telegram作为命令与控制（C2）通信的机制。Netskope威胁实验室详细分析了该恶意软件的功能，并指出其可能源自俄罗斯。  
  
### 8. OpenSSH曝高危漏洞，可引发中间人攻击与DoS攻击  
  
  
OpenSSH是远程管理Linux和BSD系统的最常用工具，近期修复了两个高危漏洞。其中一个漏洞允许攻击者在特定配置下对OpenSSH客户端发起中间人攻击，冒充服务器以拦截敏感通信；另一个漏洞则可能导致CPU资源耗尽。  
  
### 9. 雅虎数据泄露事件：黑客涉嫌兜售60.2万个电子邮件账户  
  
****  
近期，一名化名为“exelo”的黑客涉嫌在地下论坛上兜售一个包含60.28万个雅虎电子邮件账户的数据库。该帖子声称，这些数据是“私密且非俄罗斯来源的”。完整的数据库售价未公开，但卖家据称向感兴趣的买家提供了5万个账户的免费样本作为测试。  
  
### 10. 9万个WordPress站点面临本地文件包含漏洞攻击  
  
****  
WordPress的Jupiter X Core插件存在严重安全漏洞，使得超过9万个网站面临本地文件包含（LFI）和远程代码执行（RCE）攻击的风险。  
  
  
**一周好文共读**  
  
  
### 1. Web源码泄露姿势 | 如何寻找泄露源码及黑灰源码  
  
  
本文内容主要帮助大家如何去寻找网站的源代码，在寻找的过程中我们应该多站在开发者的角度去思考。   
  
  
![1719383456_667bb5a05000ee7693c04.png](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icKwLMcanFbC55QibEQZcicWz6nm0IhicnD5Y6bxC6rj1vGcWIJAmCoiaLKkW5QHoQ4gCErUC3frSSqNQ/640?wx_fmt=jpeg&from=appmsg "")  
  
### 2. 利用 cve-2023-33476 进行远程代码执行  
  
****  
本文将重点讲解漏洞的利用开发过程，介绍在此过程中遇到的各种挑战，以及如何将这些挑战解决并最终实现远程代码执行，进而获得 Shell。  
  
  
![1](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icKwLMcanFbC55QibEQZcicWzq0uHSo3xHtscAHQRsKIDyBrnAnEeSibue9R5NHNYya0iag9zOyCrsbqw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 【CTF】Python Jail沙箱逃逸手法总结 PyJail All in One  
  
****  
本文整理了Python沙箱逃逸的一系列手法，包括针对字符串匹配、命名空间限制、audit hook、AST沙箱等。  
  
  
 ![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icKwLMcanFbC55QibEQZcicWzj8B8lfUwCzIcVDTE4H8icaHZAAqBxbYx8NO5dQg9oVwyQibx687sbOrA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
*点击  
【阅读原文】  
可查看完整文章内容，付费文章购买FVIP方可阅读全文。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
