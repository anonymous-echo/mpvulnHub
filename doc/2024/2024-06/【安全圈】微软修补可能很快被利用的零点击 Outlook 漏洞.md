#  【安全圈】微软修补可能很快被利用的零点击 Outlook 漏洞   
 安全圈   2024-06-17 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
个人信息  
  
  
发现该漏洞的研究人员 Morphisec 警告说，微软在2024 年 6 月补丁日更新中解决的一个漏洞可能会被利用来实现无需用户交互的远程代码执行 (RCE)。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgX66gWPDARMIwroCYja1d85iaXG9HnZicS8dHibYuXzxkaFaJCI5MmC1eibeIhdjlmvVbW19G22IsGkQ/640?wx_fmt=png&from=appmsg "")  
  
微软在其  
公告  
中表示，该安全漏洞编号为CVE-2024-30103（CVSS 评分为 8.8），可让攻击者绕过 Outlook 注册表阻止列表并创建恶意 DLL 文件。  
  
微软安全公告指出：“预览窗格是一种攻击媒介”，并补充说攻击复杂性较低，并且可以通过网络进行利用。Outlook 2016、Office LTSC 2021、365 Apps for Enterprise 和 Office 2019 均受到影响。  
  
尽管微软将该漏洞评定为“重要”，但发现该漏洞的 Morphisec 研究员却认为该漏洞为“危急”，并警告称攻击者可能很快就会开始利用该漏洞，因为它不需要用户交互。  
> “相反，当受影响的电子邮件被打开时，执行就开始了。这对于使用 Microsoft Outlook 自动打开电子邮件功能的帐户来说尤其危险。”Morphisec 研究员指出。  
  
  
Morphisec 表示，RCE 漏洞可能被利用来窃取数据、未经授权访问系统以及执行其他恶意活动。  
  
Morphisec 补充道：“此 Microsoft Outlook 漏洞可以在用户之间传播，无需点击即可执行。”  
  
据该网络安全公司称，利用此零点击漏洞非常简单，这使得它在初始访问时容易被大规模利用。  
> Morphisec 说：“一旦攻击者成功利用此漏洞，他们就可以以与用户相同的权限执行任意代码，从而可能导致整个系统被入侵。”  
  
  
Morphisec 研究员计划在今年夏天的 DEF CON 会议上发布技术细节和概念验证（PoC）漏洞。  
  
建议用户尽快更新 Outlook 客户端。据了解，攻击者以前曾利用零点击 Outlook 漏洞进行攻击。  
  
周二，微软发布了针对其产品中十多个远程代码执行漏洞的补丁，其中包括微软消息队列 (MSMQ) 中的一个严重漏洞。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaEzU03vTkiaRRLTKic2YQGlpibc3fs36Cickuibia9ltFMGBVXZaRmDoMAlR00YZLZm2kWVhmuesibY91dpA/640?wx_fmt=jpeg "")  
[【安全圈】卡巴斯基在中国生物识别访问系统中发现 24 个漏洞，凸显身份验证系统风险](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061675&idx=1&sn=23b2d19c63d917c220518dec1eac717c&chksm=f36e13abc4199abdf2a9d5996700e53cc44d51c931d8e45379dd798e7647543d2e6b35ee9f3b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgX66gWPDARMIwroCYja1d8s19qOHILhyib2s1icSfJX3GVce0d53rb4JZQnlrW8mgPo6SksXDibvQyA/640?wx_fmt=jpeg "")  
[【安全圈】遭遇攻击后需一个多月时间恢复，NicoNico 紧急开发“极简版”网站](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061675&idx=2&sn=7a9e6ab8bcc40ae71e0f4ba4678c57b7&chksm=f36e13abc4199abd4f05dce93f6682cb08848fedf53dc5f97a8bcbcc09610054a3a0b854e692&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgX66gWPDARMIwroCYja1d8I6LXib9BAbbIEzliadswtxlOImGadNtNmpMEek1ic766eq6r7Je7DxLHg/640?wx_fmt=jpeg "")  
[【安全圈】披露 11 起重大事件！美国政府发布 2023 网络安全年报](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061675&idx=3&sn=8e921517c372ec424114f5c30e091276&chksm=f36e13abc4199abd5984dfb6e08cc96db18176f46a9542b782abad7da0c7c1b73face367f021&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGojT4ibzfTbKacxjUWdoUHSljjF8wicSKFdYz17bjh4D2Wf7ZoAVp0YlWAwv2IZInhpQdP0rWbFXvw/640?wx_fmt=png "")  
[【安全圈】两名乌克兰人因涉嫌帮助传播亲俄宣传、窃听军用电话被捕](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061675&idx=4&sn=d227901769fa1d7aa5ed99e44f813881&chksm=f36e13abc4199abd39939d5ac55dfdd6a7e14c969640a3cce0a57d625459182450743c79b406&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
