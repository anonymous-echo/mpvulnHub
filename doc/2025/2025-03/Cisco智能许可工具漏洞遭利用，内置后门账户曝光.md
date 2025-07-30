#  Cisco智能许可工具漏洞遭利用，内置后门账户曝光   
 FreeBuf   2025-03-21 18:14  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38XwTgRA48WDosoh2GoRypxWsnXFJMlrXfqIyolibo3t6662H8nZs5NBOmnficOyGMgT7Q4X178c6Rg/640?wx_fmt=png&from=appmsg "")  
  
  
近期，攻击者开始针对未修复漏洞的Cisco智能许可工具（Cisco Smart Licensing Utility, CSLU）实例发起攻击，该漏洞暴露了一个内置的后门管理员账户。  
  
  
Cisco智能许可工具是一款Windows应用程序，允许管理员在本地环境中管理许可证和关联产品，而无需将其连接到Cisco基于云的Smart Software Manager解决方案。  
  
  
![Cisco](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38XwTgRA48WDosoh2GoRypxxzxZ8iaDzXD1f9tU3U7WlAnQoTicAdsx1ayaAjWxoPr1I3wxsYsWTfsA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**漏洞详情与被利用情况**  
  
  
  
Cisco于今年9月修复了这一安全漏洞（编号为CVE-2024-20439），并将其描述为“一个未公开的静态用户凭证，用于管理员账户”。未经验证的攻击者可以通过CSLU应用的API远程登录未修复的系统，并拥有管理员权限。  
  
  
此外，Cisco还修复了第二个严重的信息泄露漏洞（CVE-2024-20440）。未经验证的攻击者可以通过向易受攻击的设备发送特制的HTTP请求，访问包含敏感数据（包括API凭证）的日志文件。  
  
  
这两个漏洞仅影响运行易受攻击版本的Cisco智能许可工具的系统，并且只有在用户启动CSLU应用时才能被利用——CSLU默认不会在后台运行。  
  
  
Aruba威胁研究员Nicholas Starke对这一漏洞进行了逆向工程，并在Cisco发布安全补丁约两周后发布了一份技术细节报告，其中包括解码后的硬编码静态密码。  
  
  
**攻击者已开始利用漏洞**  
  
  
  
SANS技术研究院的研究主任Johannes Ullrich报告称，攻击者已开始在针对暴露在互联网上的CSLU实例的利用尝试中，结合使用这两个安全漏洞。  
  
  
Ullrich表示：“快速搜索并未显示[当时]有任何积极的利用活动，但包括后门凭证在内的细节在Cisco发布公告后不久，由Nicholas Starke在博客中公开。因此，我们现在看到一些利用活动并不奇怪。”  
  
  
尽管这些攻击的最终目标尚不清楚，但背后的攻击者还在尝试利用其他安全漏洞，包括一个公开有概念验证利用的信息泄露漏洞（CVE-2024-0305），该漏洞影响广州盈科电子的DVR设备。  
  
  
Cisco关于CVE-2024-20439和CVE-2024-20440的安全公告仍表示，其产品安全事件响应团队（PSIRT）尚未发现威胁行为者在攻击中利用这两个安全漏洞的证据。  
  
  
**Cisco产品的其他后门账户**  
  
  
  
CVE-2024-20439并不是Cisco近年来从其产品中移除的第一个后门账户。此前，该公司曾在Digital Network Architecture（DNA）Center、IOS XE、Wide Area Application Services（WAAS）和Emergency Responder软件中发现过硬编码凭证。  
  
  
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
  
