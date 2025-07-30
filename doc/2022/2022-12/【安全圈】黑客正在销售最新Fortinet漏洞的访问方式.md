#  【安全圈】黑客正在销售最新Fortinet漏洞的访问方式   
 安全圈   2022-12-01 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgU7AQyHMBto7BXAPaYHNSAib1svM50ppMoI1q5WiafHthfeLK5U1oZup9icyDPnia6MicatveFtibaG79g/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
Fortinet  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgU7AQyHMBto7BXAPaYHNSAPGKTZpKv2j2CyQcBUQpeuS2j7qzKVrVrlFrnhJowY6r9hS04wjVY5A/640?wx_fmt=jpeg "")  
  
安全厂商发现，稍早发现的Fortinet网络设备软件漏洞已经有黑客公开销售访问的方法。  
  
  
10月间Fortinet修补了零时差漏洞CVE-2022-40684，它是HTTP/HTTPS管理接口的验证绕过漏洞，可被远程滥用，风险值列为9.6，属于重大风险。这项漏洞影响多项产品，包括FortiOS、FortiProxy和FortiSwitchManager。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgU7AQyHMBto7BXAPaYHNSAnF2IgqMKic7ZRrgAOBkibvwz8icw6v2CWO7ib5SxA9sibjljSGqfs5v2PrQ/640?wx_fmt=jpeg "")  
  
Fortinet当时提醒用户应尽快更新，因为公开前已经遭到滥用。如今专门监控暗网上犯罪活动及漏洞情报的厂商Cyble发现，俄罗斯地下网络论坛上，已经有人公开发布消息，以销售访问Fortinet VPN设备的凭证资讯。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgU7AQyHMBto7BXAPaYHNSAMM0d6Q9h892mmicZ9OJgnJL1ibFyLp4GxPZb8hLnG475hrkkhibdRSyGg/640?wx_fmt=jpeg "")  
  
图片来源／Cyble  
  
  
Cyble发现的是“多个”未授权FortiOS设备的访问资讯，包括网址、管理员用户的SSH Key。分析这些访问资讯显示，攻击者企图将公开密钥加入到受害企业管理员账号中，借此冒充管理员访问Fortinet设备。  
  
  
根据资料，这些受害企业用的都是过时版本的FortiOS。研究人员相信，发布广告的攻击者应该是对CVE-2022-40684发动攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgU7AQyHMBto7BXAPaYHNSAFbMELfp9gSibiaqStVp3rPnGccfAjAJVNX8DddV4xZ9pH3x6tpJk3bDQ/640?wx_fmt=jpeg "")  
  
图片来源／Cyble  
  
  
通过冒充Fortinet管理员，攻击者可修改管理SSH密钥、添加本机用户、修改网络配置变更流量路径、下载系统配置资讯、抓取封包截取其他敏感系统或网络资讯，再于暗网销售。  
  
  
Cyble研究人员指出，针对Fortinet执行实例的攻击行动，从10月17日起就持续至今。这个时间点大约等同Fortinet第一波悄悄发通知用户更新软件的时间。  
  
  
研究人员呼吁用户尽快安装修补程序，因为网络上已公开的概念验证（PoC）程序及自动化工具，让攻击者在漏洞公布几天之内就能发动攻击。  
  
  
来源：十轮网  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgU7AQyHMBto7BXAPaYHNSAwL9kicakIzxHhgHqEjbLbmlHvu3Bpbic8LaLIhqpWUttB0Gqkk5MqzuA/640?wx_fmt=jpeg "")  
# 【安全圈】应对挑战！元宇宙可能成为 2023 年网络攻击的主要途径  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgU7AQyHMBto7BXAPaYHNSA53Ze5jYAPN0ziapYZJrlnkd3NtbGlQESPXaP0hb9tPj148OViac0U1pQ/640?wx_fmt=jpeg "")  
# 【安全圈】以威胁国家安全为由，美国禁止销售中兴、海康威视等电信和监控设备  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgU7AQyHMBto7BXAPaYHNSAmXyvUCX17HIorpmFE0ooiabBbr2QmINq3lx2Ro3iaCKbb209AJUVgiaTw/640?wx_fmt=jpeg "")  
# 【安全圈】宏碁电脑存在驱动程序漏洞，启动过程中可部署恶意软件  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgU7AQyHMBto7BXAPaYHNSAVQb4juM2yhB7iaMu6skKY12c1WLqp2QYy1ZKibj008VHEkjSIWMSSYEg/640?wx_fmt=jpeg "")  
# 【安全圈】新攻击利用Windows安全绕过 0 day 漏洞投放恶意软件  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
