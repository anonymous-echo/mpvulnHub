#  立级修补！PuTTY曝出密钥泄露严重漏洞   
 安全内参   2024-04-18 18:08  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvYicJ84Et6f2yIhUHKo1JQuSrvOMvFBXL9m9IBQm8g3eSS1OfABntBA90E17UEXgGNxXaE6Dx69iaUQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
流行开源SSH客户端PuTTY近日发布了重要安全更新，修复了一个可泄露用户加密密钥的严重漏洞。受影响的PuTTY版本号为0.68至0.80，最新的PuTTY 0.81修复了此漏洞。  
  
  
依赖受影响PuTTY版本的其他程序（例如FileZilla、WinSCP、TortoiseGit和TortoiseSVN）也存在漏洞。这些产品也提供了相应的补丁程序或缓解措施。  
  
  
PuTTY是一款用于SSH、Telnet等网络协议的开源客户端程序，可帮助用户连接远程服务器并传输文件。德国鲁尔大学的两位研究人员发现，PuTTY客户端及其相关组件在使用“NISTP-521”的情况下，会“生成严重偏差的ECDSA随机数(nonce)”，从而导致私钥泄露。该漏洞编号为CVE-2024-31497。  
  
  
研究人员解释说：“恶意行为者只要监测到由使用相同密钥的任何PuTTY组件生成的大约60个有效ECDSA签名，就能够完全恢复NISTP-521密钥的私钥。”  
  
  
研究人员指出，这些所需的签名可以通过恶意服务器窃取，也可以来自其他来源，例如签名的Git提交记录。  
  
  
研究人员警告说：**“即使修复了源代码中的漏洞后攻击仍能进行（假设对手拥有大约60个漏洞未修复时的签名），因此所有用于PuTTY的NIST P-521客户密钥都应被视为已泄露。”**  
  
  
PuTTY开发人员也发布安全报告并解释说：“攻击者只需拥有几十条签名消息和公钥，就足以恢复私钥，然后伪造签名，冒充用户的身份进行登录操作（例如，登录您使用该密钥的任何服务器）。为了获得这些签名，攻击者只需短暂攻破用来验证密钥的服务器，或暂时访问保存密钥的Pageant程序的副本即可。”  
  
  
PuTTY开发人员敦促用户立即撤销受影响的密钥。美国国家标准与技术研究院(NIST)国家漏洞数据库中的CVE-2024-31497条目警告称，该漏洞可能导致供应链攻击。  
  
  
参考链接：  
  
https://www.openwall.com/lists/oss-security/2024/04/15/6  
  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
文章来源：GoUpSec  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  
