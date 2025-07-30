#  【安全圈】黑客组织Clop发动零时差漏洞攻击，近600家企业遭殃   
 安全圈   2023-08-07 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
漏洞攻击  
  
  
      勒索软体黑客组织Clop发起MFT档案共享系统MOVEit Transfer零时差漏洞攻击，近六百家企业机构遭殃，亦有部分组织因IT服务供应商遭受攻击而受害，且规模持续扩大。  
  
      这起事故发生迄今快2个月，从当初指出攻击者的身份，到黑客组织坦诚犯案、公布受害组织名单，后来则有部分企业与公家机关证实遭遇相关攻击。但相较于先前的事故，这次有许多不同的地方。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6wiaMdsIDDHmX76ichBZC5fsYEdicMLQkVBkhxYZX5TRfwjHSic7WuCtYs6zRzSWD2jvLS1ibyd5vPfFUg/640?wx_fmt=png "")  
  
  
**事件的首度揭露源自零时差漏洞公告**  
  
  
     这起事件的曝光，主要与5月底Progress发布的漏洞公告有关。黑客针对Progress公司旗下MFT档案共享系统MOVEit Transfer的零时差漏洞，发动攻击，窃取组织存放的档案，且已有许多组织受害。  
  
      黑客利用的漏洞与Progress在5月31日公布的SQL注入漏洞有关──此漏洞能允许未经身分验证的攻击者取得数据库权限，而能截取MOVEit所采用的数据库内容。  
  
      而对于攻击者的身份，微软威胁情报团队于5日表示，根据他们的调查，很有可能就是勒索软体黑客组织Clop所为，理由是该组织也曾利用类似的漏洞来窃取资料，并向受害组织勒索。  
  
**受害企业与组织不断浮出台面，表明受到攻击**  
  
  
      在微软怀疑攻击者的身份后，黑客组织Clop开始有所行动，同时也有企业与政府单位表明受害。在这些组织当中，有不少MOVEit Transfer，是IT服务业者维护的系统。  
  
      最早证实遭到攻击的组织约于6月5日出现，包含了英国航空、英国广播公司（BBC）、薪资系统服务供应商Zellis、加拿大新斯科舍省政府等。  
  
      而对于微软的指控，Clop透露，这起攻击行动就是他们所为，并宣称开始发动攻击的时间是5月27日，但不愿透露入侵此种档案共享系统服务器的数量，仅表示他们即将向受害组织进行勒索，要求这些组织于6月14日前进行谈判。  
  
**黑客多次公布受害组织名单**  
  
  
      值得留意的是，虽然黑客声称有数百个组织受害，但他们分成多次公布部分名单，且初期每次的数量都不多，而使得遭到公布的组织都受到相当程度的关注。  
  
      勒索软件Clop于6月14日公布1份受害组织名单，总共列出13个对象，其中包含了石油公司壳牌、保险公司、格鲁吉亚大学、乔治亚大学系统等。  
  
      6月15日，这些黑客又公布14个受害组织。这些单位大部分来自美国，其中有3个为欧洲组织，分别是位于法国、瑞士、卢林堡的组织，而且，主要是金融服务业、但也有医疗保健、制药厂，以及科技产业。  
  
      6月16日美国东部时间上午，又有10个受害组织被黑客列入名单，值得留意的是，这次开始有亚洲的组织出现。截至目前为止，有58个组织被列于黑客的网站上。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6wiaMdsIDDHmX76ichBZC5fsYNyibIKlIvfBQCcxjzHHWGiaRzVBqqfciaVgJnenHOxjUOPe3KSczktXjw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6wiaMdsIDDHmX76ichBZC5fsYD9CUVEx9nPXfv6W8YolOamOxXxJwX73aIcE9pe5lj1CuicL6GI8Diaog/640?wx_fmt=png "")  
  
  
      从事件发生之后，Progress总共修补了6个CVE漏洞，不同程度的MOVEit Transfer修补层级，IT人员需要采取的更新步骤也不同，使得修补工作变得更为复杂。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljjjQNGoPb4H4chiaYLgjsMPbYcxRDfU9RIm2kgah5BkUjc8X7lpXObL3IUoVrDxeNuTL0aUTrUIYA/640?wx_fmt=png "")  
[【安全圈】特斯拉车机系统被越狱 可免费解锁付费功能](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041383&idx=1&sn=dbd7fd0f1fa42c428e763fb0e0dd4f6c&chksm=f36fdce7c41855f1e0a31747f4dca40c52da6f6349ab957ddafae0e9cd57d93cb78029548007&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljjjQNGoPb4H4chiaYLgjsMPFxrxSgAf36iboRn8y8dtKHZaN8j0uBayjLKjH49gvbAU8NRelcI203g/640?wx_fmt=png "")  
[【安全圈】武汉地震监测中心遭黑客袭击，360全力维护安全！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041383&idx=2&sn=db50b0447574cac8a06833de3ea3b5aa&chksm=f36fdce7c41855f184ad0ee7a3ab6c3ff2c9d1e322e493743de3e68303ec657795eb2497b02d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljjjQNGoPb4H4chiaYLgjsMPMKRwAsDTJ5HMj8icLIkM0JsIcmNiaiaBem2ibcZdU5e3AZ4aLU00Cegdaw/640?wx_fmt=png "")  
[【安全圈】数十万个人信息泄露 “中间商”竟赚百万“差价”？](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041383&idx=3&sn=007f24a7d3d639df2749b855df8b644d&chksm=f36fdce7c41855f1bbcbb746ccd2df65b9918b6057670b41e66a5554760d2205a7acef0dc5a3&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljjjQNGoPb4H4chiaYLgjsMPicWANKEVDdAkPTIeP0F5Gc78w77cNuRTia0Kwvv8rb1rkoQYzAQ63dag/640?wx_fmt=png "")  
[【安全圈】近40家企业受影响！微软揭示新网络攻击利用Teams传播](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041383&idx=4&sn=bc71f317b43409cc866ebb4b990784c7&chksm=f36fdce7c41855f1279277701cb64c67f50be6054863707624377c01991f863a6abbcaca4415&scene=21#wechat_redirect)  
  
  
  
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
  
  
