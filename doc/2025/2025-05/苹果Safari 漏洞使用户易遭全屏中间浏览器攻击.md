#  苹果Safari 漏洞使用户易遭全屏中间浏览器攻击   
Bill Toulas  代码卫士   2025-05-30 09:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**苹果公司的 Safari web 浏览器中存在一个弱点，可导致威胁人员利用全屏的中间浏览器 (BitM) 技术从毫不知情的用户处窃取账号凭据。**  
  
通过滥用 Fullscreen API（允许网页上的任何内容进入浏览器的全屏查看模式），黑客可利用该漏洞使基于 Chromium 浏览器上的防护措施的可见度变低，并诱骗受害者在攻击者受控窗口中输入敏感数据。  
  
SquareX 公司的研究人员观察到这种恶意活动的数量有所增多，并表示这类攻击对于 Safari 用户而言尤为危险，因为当浏览器窗口进入全屏模式时，Safari 浏览器并未正确提醒用户。  
  
  
**0****1**  
  
  
**BitM 攻击原理**  
  
  
  
  
常见的 BitM 攻击涉及诱骗用户与受攻击者控制的显示合法登录页面的远程服务器交互，而这是通过多种工具如开源的VNC浏览器客户端 noVNC 在受害者会话之上打开远程浏览器而实现的。  
  
由于登录流程发生在攻击者的浏览器中，这些凭据虽然被收集但受害者还成功访问了它们的账号。该攻击仍然需要诱骗受害者点击恶意链接，之后被重定向到模拟目标服务的虚假站点。然而，通过web浏览器中的赞助广告、社交媒体帖子或评论即可轻松实现这一要求。  
  
  
**0****2**  
  
  
**全屏欺骗**  
  
  
  
  
如果用户错过浏览器地址栏中的可疑 URL 并点击登录按钮，那么 BitM 窗口就会被激活。在被触发之前，该窗口仍然以最小模式隐藏于受害者之外。  
  
一旦被激活，受攻击者控制的浏览器窗口就会进入全屏模式并覆盖虚假网站，向用户显示他们想要访问的合法网站。安全解决方案如 EDR 或SASE/SSE 不会在这种情况发生后触发任何告警，因为该攻击滥用的是标准的浏览器API。研究人员解释称，基于 Chromium 的浏览器会在全屏被激活时发布告警。尽管很多用户会错过该告警，但它仍然可以降低 BitM 攻击带来的风险。  
  
然而，Safari 浏览器并未部署此类告警，而对于浏览器进入全屏模式的唯一迹象是很容易被错过的“一扫而过的”动画。苹果对此回应称“不会修复”这一问题，并解释称该动画是为了提示变化，而这已经足够了。苹果并未就此事置评。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[iLeakage 攻击可从Safari 窃取邮件和密码](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517995&idx=1&sn=6ee81b5e343be3de47e03753622cac5b&scene=21#wechat_redirect)  
  
  
[谷歌研究员详述已存在5年、已遭利用、已修复的 Safari 0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512458&idx=1&sn=08b25be264dda4e141186f4948c38a61&scene=21#wechat_redirect)  
  
  
[研究员发现macOS 版本Safari 浏览器中的严重漏洞，获奖10.5万美元](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510357&idx=1&sn=4984145d8ed807424407baf582f63fe9&scene=21#wechat_redirect)  
  
  
[0day影响 Chrome和 Safari，谷歌不修复](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247501665&idx=2&sn=a09093a7dcd1fc94b872c4ca7b46bfb1&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/apple-safari-exposes-users-to-fullscreen-browser-in-the-middle-attacks/  
  
  
题图：  
Pixabay   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
