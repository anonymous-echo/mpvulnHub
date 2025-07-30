#  【安全圈】Erlang/OTP SSH 远程代码执行漏洞 PoC 漏洞利用发布   
 安全圈   2025-04-18 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljhntItmv5VQwksRGXkNZ3CItxfY5NTKCDC3n6NcB0STYld9Hpu3oqdlhzW7ue7iaI37qKgmXJHnkg/640?wx_fmt=png&from=appmsg "")  
  
安全业界正面临一场前所未有的挑战——研究人员日前确认Erlang/OTP的SSH实现存在一个可导致远程代码执行的严重漏洞（CVE-2025-32433），该漏洞已被评定为CVSS最高分10.0的危险等级。攻击者无需任何认证即可执行任意代码，完全控制系统。  
  
这一关键漏洞由安全研究团队于2025年4月首次公开披露。问题根源在于SSH协议的消息处理机制存在缺陷，攻击者可在认证完成前发送连接协议消息。值得注意的是，该漏洞影响所有运行SSH服务器组件的Erlang/OTP版本，与底层系统版本无关。  
  
Horizon3攻击团队的研究人员已成功复现漏洞并开发出概念验证性攻击代码（PoC）。更令人担忧的是，研究人员在社交媒体上警示称："CVE-2025-32433的漏洞利用出乎意料的简单。公开PoC（概念验证代码）可能随时涌现。如正在关注此事，现在是立即采取行动的时候了。"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljhntItmv5VQwksRGXkNZ3CSWuExeC5iby5pNYKLuC1QjJBITsBUT45hUhIn9uiaI4nYiaGU7RZHQLEA/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞利用的简易性引发了安全专家的高度警觉。令人不安的是，已有匿名研究人员在Pastebin上公开了概念验证代码。安全专家指出，考虑到Erlang广泛应用于电信设备制造商的关键基础设施、物联网（IoT）和工业控制系统（OT）环境，这一漏洞可能造成特别严重的后果。  
  
网络安全专家将其评估为"极其危急"级别，警告称威胁行为者可能利用此漏洞进行包括完全系统接管在内的恶意活动。鉴于Erlang在电信行业的广泛应用，每个正在运行SSH服务的Erlang节点都面临潜在风险。  
  
目前，安全团队正争分夺秒地为受影响系统打补丁。业内建议所有采用Erlang/OTP SSH服务器的组织立即采取行动，检查系统状态并应用最新安全更新。随着公开漏洞利用代码的出现，专家预计针对该漏洞的攻击活动可能会迅速增加。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】2025年3月涉国内数据泄露事件汇总](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069139&idx=1&sn=24fbc69a002fda1ef551c67eb1103f53&scene=21#wechat_redirect)  
  
  
  
[【安全圈】苹果紧急修复两枚被用于定向攻击iPhone的零日漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069139&idx=2&sn=5fcd14bd8672d24bf7654cecc92d1518&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Windows Server 2025 重启错误导致与 Active Directory 域控制器的连接中断](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069139&idx=3&sn=29fd117a7b8972aab9256bc20ce63ced&scene=21#wechat_redirect)  
  
  
  
[【安全圈】4chan遭入侵？竞争对手Soyjak论坛黑客宣称泄露其源代码](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069139&idx=4&sn=38d5d027bcb05fd9de286c58a861220c&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
