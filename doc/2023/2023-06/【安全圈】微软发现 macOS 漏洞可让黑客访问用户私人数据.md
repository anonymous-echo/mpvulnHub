#  【安全圈】微软发现 macOS 漏洞可让黑客访问用户私人数据   
 安全圈   2023-05-31 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
恶意软件  
  
  
  
据BleepingComputer消息，苹果最近解决了一个由微软发现的macOS系统漏洞，该漏洞允许拥有 root 权限的攻击者绕过系统完整性保护 (SIP)以安装不可删除的恶意软件，并通过规避透明度同意和控制 (TCC) 安全检查来访问受害者的私人数据。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguWFllJZStzRV5QtCkoicg9CvltiaqY1jW6paGZIuSughn6TI7MCFvmNIzK9ib8TdIicAVicdqR2iaq3Lw/640?wx_fmt=jpeg "")  
  
  
该漏洞被称为Migraine ，由一组微软安全研究人员发现并报告给苹果，现在被追踪为CVE-2023-32369。苹果已在两周前的 5 月 18 日发布的macOS Ventura 13.4、macOS Monterey 12.6.6和macOS Big Sur 11.7.7安全更新中修补了该漏洞。  
  
  
系统完整性保护 (SIP)是一种 macOS 安全机制，可通过对根用户帐户及其在操作系统受保护区域内的功能施加限制来防止潜在的恶意软件更改某些文件夹和文件，其运作原则是只有由 Apple 签名或拥有特殊权限的进程（例如 Apple 软件更新和安装程序）才被授权更改受 macOS 保护的组件。  
  
  
此外，如果不重新启动系统并启动 macOS Recovery（内置恢复系统），就无法禁用 SIP，这需要对已经受损的设备进行物理访问。  
  
  
然而，微软的研究人员发现，拥有 root 权限的攻击者可以通过滥用 macOS 迁移助手实用程序来绕过 SIP 安全实施。研究证明，拥有 root 权限的攻击者可以使用 AppleScript 自动执行迁移过程，并在将其添加到 SIP 的排除列表后启动恶意负载，而无需重新启动系统和从 macOS Recovery 启动。  
  
  
任意绕过 SIP 会带来重大风险，尤其是在被恶意软件利用时，包括创建无法通过标准删除方法删除的受 SIP 保护的恶意软件。此外攻击面也得到扩大，并可能允许攻击者通过任意内核代码执行来篡改系统完整性，并可能安装 rootkit 以隐藏安全软件中的恶意进程和文件。  
  
  
绕过 SIP 保护还可以完全绕过TCC 策略，使攻击者能够替换 TCC 数据库并获得对受害者私人数据的无限制访问权限。  
  
## 已非第一次发现macOS 漏洞  
  
  
这不是微软研究人员近年来报告的第一个此类 macOS 漏洞。2021 年，微软报告了一个名为Shrootless 的 SIP 绕过漏洞，允许攻击者在受感染的 Mac 上执行任意操作，将权限提升为 root，并可能在易受攻击的设备上安装 rootkit。  
  
  
最近，微软首席安全研究员 Jonathan Bar Or 还发现了一个名为 Achilles 的安全漏洞，攻击者可以利用该漏洞绕过 Gatekeeper对不受信任应用的限制，以此来部署恶意软件。他还发现了另一个名为powerdir的漏洞，可以让攻击者绕过TCC来访问用户的受保护数据。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylguWFllJZStzRV5QtCkoicg9k0VABQRwiaDJfKrlDp2W2YpyeUeOCXicBGQSbYbAku3CiboEOsyxLkP9Q/640?wx_fmt=png "")  
[【安全圈】获利超千万元！“西游记”组合黑客团伙售卖强制刷机软件被逮捕](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652035571&idx=1&sn=57502d5192660dbaf419cdeee21e3066&chksm=f36ff5b3c4187ca510589a24349c5cae130bc27560fcb9f2c82fd83cafb7b4fd797d0c369e30&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylguWFllJZStzRV5QtCkoicg9tickxPyCVMYBw3V20F8rbw74edh7QNpjiaQf4J7F6wmrePjkjffR4fkA/640?wx_fmt=png "")  
[【安全圈】网络安全管理不当，一信贷公司被罚超3000万元](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652035571&idx=2&sn=253dc32d757b518a649fa0e20b4c02bc&chksm=f36ff5b3c4187ca52fc2a3bd52b5875d3487962469869722031f7dab41e73d9a69fa22f75596&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a0GRk0G2QBST43lVjYE1blrMgN1zV8FHGgXw8JU96hPDjLo5kiba0mkYIS1GAZxPAY2Nztfv2tiaHYLqwibcmmr5w/640?wx_fmt=png "")  
[【安全圈】不输密码也能转走你的钱，手机这个功能建议关闭！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652035369&idx=3&sn=4354e568918a5d72518a34b083b36615&chksm=f36ff569c4187c7f5aace4c88e52843a46bdfe9815402a717f2ed022c28e23a8c8d54ebf6604&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgibXEAXiapGDIjicyELHOEb4AYaQhzsMUrjw14AFdTlHcgfTict3pMqmvBD53icIrtSvoiaprq6vyoxMiaw/640?wx_fmt=jpeg "")  
[【安全圈】免费 VPN 服务 SuperVPN 泄露 3.6 亿用户隐私](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652035369&idx=4&sn=743ad7b43a172437ff5b6d56b76daf5a&chksm=f36ff569c4187c7f207e76839345cd9fb7d914c07fcb90165f3c9230a9fa3fa6cf86144f5586&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
  
