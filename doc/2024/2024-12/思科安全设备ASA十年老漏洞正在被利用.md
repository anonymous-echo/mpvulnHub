#  思科安全设备ASA十年老漏洞正在被利用   
老布  FreeBuf   2024-12-04 11:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
近期，思科系统公司（Cisco Systems）更新了关于CVE-2014-2120的安全公告，警告客户该漏洞已在野外被利用。CVE-2014-2120是一个影响思科自适应安全设备（ASA）软件的WebVPN登录页面的跨站脚本（XSS）漏洞。该漏洞最初于2014年披露，它允许未经身份验证的远程攻击者对WebVPN用户执行XSS攻击。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibkORq5ywCEzeVImYWSYHCJQ5y7nke8Q08BlO8IWNtGiaSPGxGz88hibd612Spz92MrfWQI5siaN9P1g/640?wx_fmt=jpeg&from=appmsg "")  
###   
  
**漏洞详情**  
  
  
### CVE-2014-2120漏洞源于WebVPN登录页面对一个参数的输入验证不足，攻击者可以利用这一点构造恶意链接，当受害者访问这些链接时，会在其浏览器中执行任意脚本。这种攻击可能导致攻击者在用户的浏览器上执行恶意代码，从而窃取会话令牌、修改页面内容或重定向到恶意网站。  
  
  
思科在其更新的安全公告中强调，利用此漏洞的攻击活动已经出现，因此迫切需要立即采取缓解措施。公司强烈建议客户升级到已修复的软件版本以修复此漏洞。然而，思科也指出，对于通过安全通知披露的漏洞，将不会提供免费的软件更新。客户需要通过常规支持渠道获取必要的软件升级。  
  
  
此外，网络安全和基础设施安全局（CISA）已于2024年11月12日将CVE-2014-2120添加到其已知被利用漏洞（KEV）目录中，进一步强调了组织解决此漏洞的紧迫性。  
  
  
**具体漏洞利用手法**  
  
  
###   
  
思科自适应安全设备（ASA）XSS漏洞的具体攻击手法如下：  
  
  
1. 注入恶意脚本或HTML：远程攻击者可以通过向一个未指定的参数注入任意的Web脚本或HTML代码，利用该漏洞。  
  
  
2. 利用用户输入：由于WebVPN登录页面未能正确验证用户输入，攻击者可以构造包含恶意脚本的输入，当这些输入被页面错误地作为脚本执行时，就可以实施XSS攻击。  
  
  
3. 会话劫持和信息泄露：攻击者可以利用XSS漏洞窃取用户的会话令牌、修改页面内容或重定向用户到恶意网站，进而进行会话劫持和敏感信息泄露。  
  
  
4. 脚本注入：攻击者通过将恶意脚本注入到网页服务器中，并在用户访问时执行这些脚本，达到攻击目的。这可以通过多种方式实现，如在输入框中提交恶意代码，或者构造特殊的URL以触发JavaScript执行。  
  
  
5. 反射型和存储型XSS：反射型XSS是指攻击者诱使用户点击一个链接，该链接包含恶意脚本，当用户点击后，脚本会在用户的浏览器中执行。存储型XSS则是将恶意脚本存储在目标服务器上，如在论坛帖子或用户评论中嵌入脚本，当其他用户访问这些内容时，脚本就会被执行。  
  
  
6. 利用Cookie和Session：攻击者可能会尝试通过XSS漏洞获取其他用户的Cookie，以此来冒充用户身份或执行其他恶意行为。  
  
  
综上所述，CVE-2014-2120漏洞的攻击手法主要涉及在WebVPN登录页面注入恶意脚本，利用用户输入的验证不足，以及通过脚本执行窃取用户信息或执行其他恶意行为。  
  
  
鉴于CVE-2014-2120漏洞已被证实在野外被利用，所有使用受影响版本的思科ASA软件的用户应立即采取行动，升级到最新的安全版本，以保护其网络不受此漏洞的影响。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651308240&idx=1&sn=96d32c8e6fa90561c84164ed75f4dca0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21&token=734903441&lang=zh_CN#wechat_redirect)  
  
