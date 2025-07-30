#  【安全圈】黑客揭露空客EFB应用漏洞，飞行数据面临风险   
 安全圈   2024-02-03 19:15  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
多年来，网络安全研究人员一直专注于测试各种领域的安全性，包括电子飞行包（EFB）、物联网和车载应用程序。他们进行了深入的研究，最近发现了空客Flysmart+管理套件中的一个重大漏洞。这个漏洞在被披露后的19个月内得到了修复。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljDJ3HXFuNXMsyTrj3HGeoQ6MBNicnzJqKe8icHO7ibCG0LBB4Jj2V6pPsZ8icB7w4xo9UOfyiaJPlRcKw/640?wx_fmt=jpeg&from=appmsg "")  
  
Flysmart+ 是由空客旗下的IT服务公司NAVBLUE开发的应用程序套件，专为飞行员电子飞行包（EFB）设计。该套件的主要功能是实现航空公司数据的同步和安装到其他相关应用程序中。电子飞行包在航空领域扮演着关键角色，用于存储和管理重要的飞行数据和信息，对于航空公司的正常运营至关重要。  
  
根据2024年2月1日Pen Test Partners发布的研究，他们发现Flysmart+套件中的一个iOS应用程序故意关闭了应用传输安全（ATS）功能。这一问题可能会导致应用程序容易受到Wi-Fi拦截攻击，从而可能干扰飞机的发动机性能计算，进而引发机尾碰撞或跑道偏离事故。此外，目前的标准操作流程可能无法有效检测出任何潜在的篡改行为。这一发现引发了对飞行安全和电子飞行包的关注。  
  
根据之前的发现，Flysmart+应用程序因缺乏ATS（Application Transport Security，应用传输安全）保护而存在安全问题。ATS的主要目标是防止未加密的通信，但由于Flysmart+的设置问题，它允许不安全的HTTP内容加载。这一漏洞可能允许攻击者拦截和解密传输中的敏感信息。特别值得注意的是，航空公司通常会为飞行员提供在同一家酒店中转停留，这为攻击者提供了机会通过有针对性的Wi-Fi网络修改飞机的性能数据。Pen Test Partners成功利用这个漏洞来访问NAVBLUE服务器上的数据，包括包含飞机信息和起飞性能数据（PERF）的SQLite数据库，以及具有特定表名的数据。这一情况引发了对飞行安全和数据保护的担忧。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljDJ3HXFuNXMsyTrj3HGeoQEiaoZ3UelaQdpAltpjQVuAoBwx7ZpmWzfqONd0TIfk4kyTIFFMLjheQ/640?wx_fmt=jpeg&from=appmsg "")  
  
研究员从NAVBLUE服务器下载的数据（来源：Pen Test Partners）  
  
  
需要强调的是，数据库中的表格对于飞机性能至关重要，其中包括最小设备清单（MEL）和标准仪表离场程序（SID）等重要数据。这些数据直接影响着飞机的安全操作。例如，吉姆利滑翔机燃油耗尽事件中MEL和SID的误解可能导致严重的飞行问题。  
  
此外，不同单位之间的混淆，如美国加仑、英制加仑、升、千克和磅，可能会引发安全问题。这种单位的混淆可能导致误解和错误的数据转换，进一步增加了飞行风险。  
  
Pen Test Partners的合作伙伴安东尼奥·卡西迪强调：“我们已经与波音、汉莎航空和空客等公司合作，共同披露并成功修复了这一漏洞。对于航空行业来说，这是一项重大的安全和保障进步，有助于提高航空安全性和数据完整性。”这一合作为飞行安全和数据保护带来了更多保障。  
  
在2022年6月28日，安全研究人员向空客提交了有关漏洞的报告，而在次日，空客便确认了这一漏洞的存在。然后，在接下来的一个月内，空客成功复现了这一漏洞，并承诺将在2022年底之前在Flysmart+的新版本中进行修复。截至2023年2月22日，空中客车的漏洞披露计划（VDP）团队证实，他们已经在Flysmart+的最新版本中修复了该漏洞，并在2023年5月26日向客户通报了相应的缓解措施。这些重要的研究成果在2023年的DEF CON 31安全会议以及在都柏林的航空村和航空信息共享与分析中心（Aviation ISAC）上进行了广泛展示。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3aERot1joLyxQ5pAuhdebAnicXNgk78ofRz8WP3trhvVKV5EjYBFAlTmU7kHCic882yr6y6yAeWkg/640?wx_fmt=jpeg "")  
[【安全圈】ChatGPT被曝泄露私密对话，OpenAI称是其用户账号被盗所导致](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652053460&idx=1&sn=f2fb75dfe3876576b6b95f00dd24a862&chksm=f36e3394c419ba8291848dc4c11e437405beb6102f9af9b182a288c3632c38987e3d4ffcbe57&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3aERot1joLyxQ5pAuhdebJEJeXmJ7ZjYMPlaEaKwtT289PFNojvbjJHhFyb1emch1DpDasEpNicA/640?wx_fmt=jpeg "")  
[【安全圈】利用SIM卡交换窃取数百万加密货币，男子被判入狱](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652053460&idx=2&sn=3385508a5feab00efce273796c041a37&chksm=f36e3394c419ba820abd04c8ddf7ad9c1311cd1eade1c06a27f027c879358f164a81c45de3f2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3aERot1joLyxQ5pAuhdebyEzibxHhvOHdu6FaTWEyFvGUbsC5y6NrwbH7libO7wGZ1oRtc3iciaXSBA/640?wx_fmt=jpeg "")  
[【安全圈】花旗银行因数据安全性差被起诉](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652053460&idx=3&sn=861eb6bc239d60df518b413e8bd0ab67&chksm=f36e3394c419ba82b757d51c77215fa6612b2a846f1a2d9e42a93bf6f8df3ac8e458cf138f9d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj9s8WYsM8ZDUibNQPOb8Tlz8xcU6ficneAoWZJ36ADnTiaYoXtpyrY5hrgR36ERBtRxQwy4YtPjic0eQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】2700万美元的损失！江森自控遭受勒索软件攻击，影响较大](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652053460&idx=4&sn=58469ba5bee7bd65e8fef93d94ab1937&chksm=f36e3394c419ba824527839f449d2a23f74ffe318fd2a5b1288e2f4f74b59bb72df925fb11c9&scene=21#wechat_redirect)  
  
  
  
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
  
  
