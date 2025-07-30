#  【安全圈】安卓程序出现高危漏洞，CISA 要求联邦政府尽快修复   
 安全圈   2023-07-11 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
近日，CISA要求联邦机构尽快修补一个高危的内核驱动特权升级漏洞Arm Mali GPU，该漏洞已被列入到其积极处理的漏洞列表中，并在本月的安卓安全更新中得到解决。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgStmJCtNg1kEAxuaSHstDZbW9rzdfCicFHfjdBn8pKjQNibaNGooZZBicDia7h6mWhtgcJTLzmZnkwlg/640?wx_fmt=png "")  
  
 该漏洞（被追踪为CVE-2021-29256）是一种在释放后使用的漏洞，通过允许对GPU内存的不正当操作，让攻击者升级到root权限或者访问目标安卓设备上的敏感信息。Arm在公告中写道：“非特权用户可以对GPU内存进行不当操作，以访问已释放的内存，并可能获得root权限或披露信息。”此问题在Bifrost和Valhall GPU内核驱动程序r30p0以及Midgard内核驱动程序r31p0版本中得到修复。如果用户受到此问题的影响，建议他们尽快升级。  
  
随着本月安卓操作系统的安全更新，谷歌又修补了两个在攻击中被利用的安全缺陷。  
  
CVE-2023-26083是Arm Mali GPU驱动程序中的一个中等程度的内存泄漏缺陷，该漏洞于2022年12月被利用，是向三星设备提供间谍软件的漏洞链的一部分。  
  
第三个漏洞被追踪为CVE-2023-2136，被评为严重级别，是在谷歌的开源多平台2D图形库Skia中发现的整数溢出漏洞。值得注意的是，Skia与谷歌Chrome浏览器一起使用，而该浏览器在4月份被称为零日漏洞。  
  
**联邦机构被要求在未来3周内保护安卓设备**  
  
  
 据悉，美国联邦民事行政部门机构（FCEB）已被要求在7月28日之前保护他们的设备免受CVE-2021-29256漏洞的攻击，该漏洞今天被列入到CISA积极处理的漏洞列表中。  
  
根据2021年11月发布的具有约束力的操作指令（BOD 22-01），联邦机构必须彻底评估和解决CISA KEV目录中列出的所有安全缺陷。尽管该目录主要关注美国联邦机构，但也强烈建议私营公司优先考虑并修补目录中列出的所有漏洞。CISA也警告称：“这些类型的漏洞是网络中恶意行为者的常见攻击载体，会对联邦企业构成重大风险。”  
  
一周前，网络安全机构警告说，TrueBot恶意软件操作背后的攻击者利用了Netwrix Auditor软件中的一个关键的远程代码执行（RCE）漏洞，对目标网络进行初始访问。CISA也表示，分布式拒绝服务（DDoS）针对性地攻击美国多个行业部门的组织。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgStmJCtNg1kEAxuaSHstDZWDh6Vm3iaPPOMfx76Vmxnw65rJDWtfhSN4T2iclJribPqCwibA8KDk1XAQ/640?wx_fmt=png "")  
[【安全圈】5天内就能完成系统渗透，微软揭露BlackByte 2.0勒索软件的可怕速度和破坏性](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039099&idx=1&sn=95030c3a087824a307f8ac56b3569bce&chksm=f36fcbfbc41842edb253a93aa58e698def8fdc4adc182007e74affadabcf6fb4b9c596b0e41e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgStmJCtNg1kEAxuaSHstDZibbJO6IYOY4AJR67PH3FXYU1fO2fGrVAmPZtkalMppn22VUqp28qCibA/640?wx_fmt=png "")  
[【安全圈】Progress Software再现三个新漏洞，影响 MOVEit Transfer多个版本](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039099&idx=2&sn=0d8bce0029b11f2d06a770552611b615&chksm=f36fcbfbc41842ede5989bec69b1aad95cd9fb7baa7feec7e8d534c59397f8021fe1d7dbbcd4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgStmJCtNg1kEAxuaSHstDZn1rzk9bZShWPqqA3umsuzyK1GW9n394D00AB9BbfTd7HUb4Exthxgg/640?wx_fmt=jpeg "")  
[【安全圈】泄露数百万公民的数据！孟加拉国政府网站的名称已无法公开透露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039099&idx=3&sn=60b027a2b1d8eb128f5d4c96e20ab518&chksm=f36fcbfbc41842ed501a3593b61700678408be4348249b1fc9773f599eed44665e0b40c35eb8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgStmJCtNg1kEAxuaSHstDZ4UY5KSh64IibEzzKQe7kicWOmzCNiaMZ2HlibyWvxZWreBFcDZKb1vKyAQ/640?wx_fmt=png "")  
[【安全圈】速看，三万个太阳能光伏电站面临严重漏洞威胁](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039099&idx=4&sn=d04069a547c743f069aa3379c730c5f9&chksm=f36fcbfbc41842edb9e2a5dc86d157d02e505081f7edae3995a6b51ff432f3bc6dc45643e21c&scene=21#wechat_redirect)  
  
  
  
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
  
  
  
