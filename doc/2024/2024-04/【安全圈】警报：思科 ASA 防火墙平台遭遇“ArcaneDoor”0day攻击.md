#  【安全圈】警报：思科 ASA 防火墙平台遭遇“ArcaneDoor”0day攻击   
 安全圈   2024-04-25 19:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
网络攻击  
  
  
国家支持的专业黑客团队利用思科 ASA 防火墙平台至少两个0day漏洞，植入恶意软件于电信和能源部门网络。思科周三发布警告。  
  
据思科 Talos 报告显示，攻击者正在针对某些设备上运行的思科自适应安全设备（ASA）或思科 Firepower 威胁防御（FTD）产品中的软件缺陷进行攻击。他们利用这些漏洞植入恶意软件、执行命令，并有可能从受感染的设备中窃取数据。  
  
虽然活动已被标记为ArcaneDoor，利用了思科产品中已记录的两个软件漏洞（CVE-2024-20353 和 CVE-2024-20359），但思科公司的恶意软件猎人仍然不确定攻击者是如何入侵的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3EAoC2SJvl7BFgzkyxWUMtkxIiatS3mCVTIuc7MyvrLsYXv4mSZp3eFpSfMLN46pLv7sCWcVYxgw/640?wx_fmt=webp&from=appmsg "")  
  
思科 Talos 表示：“我们尚未确定此次活动中使用的初始访问向量。迄今为止，我们尚未发现预身份验证利用的证据。”  
  
思科解释说，ArcaneDoor是一个由国家级黑客组织发起的最新攻击示例，针对多个供应商的外围网络设备。针对这些攻击者而言，外围网络设备是进行间谍活动的理想入侵点。一旦在这些设备上获得立足点，攻击者可以直接进入组织、重新路由或修改流量，并监控网络通信。  
  
在 2024 年初，一位未透露姓名的客户向思科的 PSIRT 团队报告了 ASA 防火墙产品的“安全问题”，引发了一项调查。在调查过程中，最终发现了黑客活动（由 Talos 追踪为 UAT4356，由微软威胁情报中心追踪为 STORM-1849）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3EAoC2SJvl7BFgzkyxWUM3tuVZXEJ7FRUBUYw6sqyEgtvXmCNLFQT8mtnUctrvJTsJX3uwN0ZlQ/640?wx_fmt=webp&from=appmsg "")  
  
  
UAT4356基础设施  
  
该公司指出：“攻击者采用了定制工具，表现出对间谍活动的明确关注，以及对其目标设备的深入了解。这种行为特征是成熟的国家资助攻击者的标志。”  
  
思科指出，他们观察到黑客团队部署了两个后门，这些后门共同用于对目标进行恶意操作，包括配置修改、侦察、网络流量捕获/渗透以及潜在的横向移动。  
  
该公司发出警告称：“思科已与受害者和情报合作伙伴合作，发现了一个复杂的攻击链，该攻击链用于植入定制恶意软件并在少数客户中执行命令。”  
  
思科研究人员表示，通过网络遥测和情报合作伙伴提供的信息表明，黑客对刺探微软和其他供应商的网络设备感兴趣。  
  
思科表示：“无论您的网络设备供应商是谁，现在都是确保设备已正确修补、登录到中央安全位置并配置为具有强大的多因素身份验证 (MFA) 的时候了。”  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaXEzReHnUhzRpnvDWq1WITD63F9WfwtYa286WHygIxFYcmV0uRoVODV8YP4lkrGSNnMsmibQmOUWg/640?wx_fmt=jpeg "")  
[【安全圈】德媒称“中国黑客”攻击大众，我使馆驳斥：谣言，中方坚决否认！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058779&idx=1&sn=6e71c2ba4cae98656d0afe722a749172&chksm=f36e18dbc41991cd92e68109ce93fc4a5dc5d72ae471e6444abe10765a7c8ff3f31615ea2387&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3EAoC2SJvl7BFgzkyxWUMPgwiaOEibprrrdHJvqtbBmia0kO6857iblQR5ibbl2JhbKhblA4Vep9FpKQ/640?wx_fmt=jpeg "")  
[【安全圈】黑客滥用 QEMU 对企业进行网络攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058779&idx=2&sn=a67bfd4635d413b0b82d6a3b01a2587d&chksm=f36e18dbc41991cd2e5d6da761740eaa2bbbd5097c36011cb632f8156f43f450051a89738046&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3EAoC2SJvl7BFgzkyxWUMGtLh1RmQGS2Q7n90icUpemnUPmqHibN8LkCFaibE0nNTJmStQRnOibVHLQ/640?wx_fmt=jpeg "")  
[【安全圈】Consol Energy 遭遇网络攻击：据称俄罗斯网络军对此事负责](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058779&idx=3&sn=571800b18ba45cc4e1e75cb224cebc1c&chksm=f36e18dbc41991cd574ca18cfb00db43a6c06c8a5a8f5323705d6a12e08e360971c924417a82&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaXEzReHnUhzRpnvDWq1WITZ05dRaMkrtiaJcRbntr5pGZLicF037RmdAkb3JMmLWZFlUOJeqMgSkWg/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】俄黑客组织“沙虫”发力，乌克兰关基设施被破坏](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058779&idx=4&sn=a148c846379a48730f3ffbf6e7f71590&chksm=f36e18dbc41991cd1604e7f3c68dfcbaa97e4488a92f74d700f1e197444407c35ad388d1bd62&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
