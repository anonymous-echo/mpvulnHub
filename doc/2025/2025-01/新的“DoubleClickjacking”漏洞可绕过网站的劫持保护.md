#  新的“DoubleClickjacking”漏洞可绕过网站的劫持保护   
老布  FreeBuf   2025-01-02 11:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
安全专家揭示了一种新型的“普遍存在的基于时间的漏洞”，该漏洞通过利用双击操作来推动点击劫持攻击及账户接管，几乎波及所有大型网站。这一技术已被安全研究员Paulos Yibelo命名为“DoubleClickjacking”。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39fPU5Rw0RUNYM3e8jxsjzjVsRcIiaxW68ZaynV2ZSKZMh0nuZO218h5jpkNDtXSvADich8u5Mp5oxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Yibelo指出：“它并非依赖单一点击，而是利用双击的序列。这看似微小的变化，却为新的UI操控攻击敞开了大门，能够绕过所有现有的点击劫持防护措施，包括X-Frame-Options头部或SameSite: Lax/Strict cookie。”  
  
  
点击劫持，亦称作UI重定向，是一种攻击手段，诱使用户点击看似无害的网页元素（如按钮），进而导致恶意软件的安装或敏感信息的泄露。DoubleClickjacking作为这一领域的变种，它利用点击开始与第二次点击结束之间的时间差来规避安全控制，以最小的用户交互实现账户接管。  
  
  
具体步骤如下：  
> 1. 用户访问一个由攻击者控制的网站，该网站要么在无需任何用户操作的情况下自动打开一个新的浏览器窗口（或标签页），要么在点击按钮时打开。2. 新窗口可能模仿一些无害的内容，例如CAPTCHA验证，提示用户双击以完成操作。3. 在双击过程中，原始网站利用JavaScript Window Location对象悄悄重定向至恶意页面（如，批准恶意的OAuth应用程序）。4. 同时，顶层窗口被关闭，使用户在毫不知情的情况下通过批准权限确认对话框授予访问权限。  
  
  
  
Yibelo表示：“大多数Web应用程序和框架都认为只有单次强制点击存在风险。DoubleClickjacking引入了一层许多防御措施从未考虑过的内容。像X-Frame-Options、SameSite cookie或CSP这样的方法无法抵御这种攻击。”  
  
  
网站所有者可通过客户端手段消除这类漏洞，默认禁用关键按钮，仅在检测到鼠标手势或按键时激活。研究发现，诸如Dropbox等服务已经实施了此类预防措施。作为长远解决方案，建议浏览器供应商采纳类似X-Frame-Options的新标准来防御双击利用。  
  
  
Yibelo强调：“DoubleClickjacking是一种众所周知的攻击类别的变种。通过利用点击之间的事件时间差，攻击者能够在瞬间无缝地将良性UI元素替换为敏感元素。”  
  
  
此次披露距离研究人员展示另一种点击劫持变体（即跨窗口伪造，亦称作手势劫持）已近一年，该变体依赖于说服受害者在攻击者控制的网站上按下或按住Enter键或空格键以启动恶意操作。  
  
  
在Coinbase和Yahoo!等网站上，如果已登录任一网站的受害者访问攻击者网站并按住Enter/空格键，则可能被利用来实现账户接管。  
  
  
“这是因为这两个网站都允许潜在攻击者创建具有广泛权限范围的OAuth应用程序以访问其API，并且它们都为用于授权应用程序进入受害者账户的‘允许/授权’按钮设置了静态和/或可预测的‘ID’值。”  
  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
