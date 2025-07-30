#  【安全圈】Arm 发布安全公告：修复 Mali GPU 数据泄露漏洞   
 安全圈   2023-10-06 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylg1JZl4BeFzhiaQf3pJHLtic9licPa5oXB1hfLroaibYaY2QNW5eDWa8lpQMZt8xqyTaHNz2ed4jIR2bw/640?wx_fmt=png "微信图片_20230927143622.png")  
  
  
**关键词**  
  
  
  
**数据泄露 漏洞**  
  
  
   
Arm 于 10 月 2 日发布安全公告，表示 Mali GPU 驱动程序中存在漏洞，**现有证据表明已经有黑客利用该漏洞发起攻击。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliauAibRbjpDGRJJrWibKc5oxibdtfy1Micpr4bxx4AEw5B4bXica3ZTwEp8cNvhQGLicB8pmm1bNU66FnzA/640?wx_fmt=jpeg "")  
  
该漏洞目前追踪编号为 CVE-2023-4211，由 Google 威胁分析小组（TAG）和 Project Zero 的研究人员发现，随后报告给了 Arm 公司。  
  
目前关于该漏洞的细节并未公开，IT 之家查询官方公告，描述该漏洞是不当访问内存，可能存在泄露或者操纵敏感数据的情况。  
  
Arm 在公告中表示：" 本地非特权用户可以进行不正确的 GPU 内存处理操作，以访问已经释放的内存 "，并发现了相关证据表明该漏洞 " 可能受到有限的、有针对性的利用 "。  
  
以下驱动版本受到漏洞影响：  
  
Midgard（2013 年发布） GPU 内核驱动 : 从 r12p0 到 r32p0 的所有版本  
  
Bifrost（2016 年发布）GPU 内核驱动 : 从 r0p0 到 r42p0 的所有版本  
  
Valhall（2019 年发布）GPU 内核驱动 : 从 r19p0 到 r42p0 的所有版本  
  
Arm 第五代 GPU（2023 年 5 月发布）架构内核驱动 : 从 r41p0 到 r42p0 的所有版本。  
  
包括 Galaxy S20 / S20 FE, Xiaomi Redmi K30 / K40, Motorola Edge 40 和 OnePlus Nord 2 在内的手机，均使用 Valhall GPU。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylhw0kUGAqpE18ajrgEvr3icoNLp443yUqZRcQQU6x2MiaXYwbIrJg6u14bXJbdfFibLLSEfrbicZyzAAA/640?wx_fmt=png "")  
[【安全圈】谨防个人信息被骗取！同城约 “小姐姐”要求做任务，四川已有人中招！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045959&idx=1&sn=74dcc3e2eb3ce06a00e09f430df7a379&chksm=f36e2ec7c419a7d13bea8e411fcff11dea4e1cfaf2f48de22b2a5146ea2e5f3b1d9997e03ee7&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylhJHoyj9OkqW2LCYsic2XfKru6q8AeU2lVIMUYaf6UE0bMXALmyHNkabhg4UhbTglTrjYLibQnVYJXg/640?wx_fmt=jpeg "")  
[【安全圈】通信公司“内鬼” 批量提供手机卡 超6万张手机卡用来发涉赌短信](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045959&idx=2&sn=0490660b269351faef630f3b098c5144&chksm=f36e2ec7c419a7d167708c01124f809aa64cd2a01523d00d8974fc009e904628cc75c4f6cbe4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgN56SkB1wSaDen9O0NSjpjQReuSetyV6B285UDTnjliczibFR2hxGQico7micIlMbiaUKbicLO4X7tAprA/640?wx_fmt=jpeg "")  
[【安全圈】法国太空和国防供应商Exail遭黑客攻击，泄露大量敏感信息](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045959&idx=3&sn=cf1f51afbe9551c1fc2a579aab17e61c&chksm=f36e2ec7c419a7d1b59686337211dbd6ffd68d6e6f3edd23d1a5a19c63776b7df1d6e300d3fd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgN56SkB1wSaDen9O0NSjpjVz0iaAzj0QiaVhsMefORqph5j42pOnIJxicOTfXDWUUdxyGLPoYt8SwTw/640?wx_fmt=jpeg "")  
[【安全圈】谷歌为 libwebp 漏洞分配新的 CVE 编号，CVSS 评分 10 分。](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045959&idx=4&sn=175dfa0d6b5ecf6d5ae8df166a829bb4&chksm=f36e2ec7c419a7d14065b23e4d05b171c8c5bca81071ddf7682a0114aad546a04f65ace47f7d&scene=21#wechat_redirect)  
  
  
  
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
  
  
  
  
  
  
