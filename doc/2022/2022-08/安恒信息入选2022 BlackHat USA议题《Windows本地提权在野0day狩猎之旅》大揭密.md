#  安恒信息入选2022 BlackHat USA议题《Windows本地提权在野0day狩猎之旅》大揭密   
原创 猎影 & 卫兵  网络安全研究宅基地   2022-08-12 12:06  
  
> 作者：jq0904  
  
  
2022年8月12日清晨，安恒信息中央研究院下属的猎影实验室、卫兵实验室的研究成果  
《Windows本地提权在野0day狩猎之旅》在BlackHat USA 2022大会发布。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AvAjnOiazvnfIHicYZC0QFC55qW9f3hGG2g5H3aC0ibW8GPDFZbTZdEreiaw5iar31bXc2unleibVb44iaB1sd5JdqtBQ/640?wx_fmt=jpeg "")  
  
议题中阐述到对于安全厂商和威胁狩猎人员，捕获在野0day漏洞是一件极具挑战的事情，研究员们基于过去多年历史技术案例复盘研究，提出一套有效的Windows本地提权漏洞检测方法，目前利用该方法多次捕获到Windows在野0day漏洞。此外通过对比不同方法的优劣，研究员们给出了对未来Windows本地提权漏洞的一些洞见。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvneTTZ9RPyxQfFODkzy9ET4dEazeMAiaZdbI9sZUIp6cl4wlovjWkib3eDibdD1PKtEvD1hze8c7CvgibA/640?wx_fmt=png "")  
  
  
## 演讲揭秘  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvneTTZ9RPyxQfFODkzy9ET4dVq4OnJE8IrWfRy46vNTqgInAYj1Ldc7SDOrAJCQp7voKNghkmMiaJHg/640?wx_fmt=png "")  
  
研究员指出，从2017年到2021年，微软一共披露了28个在野Windows本地提权0day，它们中大部分是Windows内核漏洞。这些漏洞通常被顶级APT组织使用，并且会造成巨大危害。对安全厂商来说，捕获一个这样的在野0day是一件非常有挑战性的事情。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnfIHicYZC0QFC55qW9f3hGG2vIIDeQNlUo5icOdpPlPnEUazjEmReueCVoN5E9wr3cibtSRz5TBic7Uibg/640?wx_fmt=png "")  
  
  
在2020年初，研究员们开始研究是否有可能捕获一个Windows本地提权在野0day，包括如何获取有价值的数据源及如何开发一套有效的检测方法。比如可以通过私有数据集、公共数据平台例如VirusTotal等解决数据源问题及  
动态检测和静态检测等  
从海量样本中捕获一个  
0day。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnfIHicYZC0QFC55qW9f3hGG2nPoz5EBGyTfOKYgyyRQXncApVweeLCkwQl3A51wa1qK0iajNlJv785g/640?wx_fmt=png "")  
  
研究员们从几个事实出发：“一些漏洞利用手法在一段时间内具有连续性，从攻击者视角进行思考可以帮助我们更好地防御，历史案例的手法已经被整个安全社区仔细研究过”，通过研究了超过50个CVE漏洞，涵盖了从2014年到2021年期间几乎所有的Windows本地提权在野0day和部分1day，并仔细统计了这些漏洞的发现厂商、使用组织、修补周期、初始披露文章、使用场景、被攻击的系统版本、漏洞模块、漏洞类型、利用手法、公开的分析博客、公开的利用代码、原始样本和其他信息，总结了相关规律和技巧。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnfIHicYZC0QFC55qW9f3hGG22OH3oIN6CQaltibDicqdicX0UpicUZBZ301KmTQC9w7wibQqibcEmicp7icXEw/640?wx_fmt=png "")  
### 研究员们基于另外几个事实：“一个新披露的漏洞可能会有变种，一个最新被攻击的模块可能会被整个社区fuzz或审计，一个攻击者也许还有一些相似的漏洞正在使用或还未使用，一种新的利用手法可能很快会被攻击者使用”，总结出需要从最新的漏洞和利用手法中学习的结论。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnfIHicYZC0QFC55qW9f3hGG2wtumexLZTW3YL8R2QgoXmsSS8AVvr3FiaTW8zp98KBH1GfHfKUsic5vQ/640?wx_fmt=png "")  
### 通过上述各方面信息收集及研究分析，研究员们选择比较了杀毒软件、沙箱、YARA等合适的工具及方法捕获在野的Windows本地提权漏洞，并最终选中YARA作为主要狩猎手法，详细介绍了如何将之前研究总结的经验转换为YARA规则。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnfIHicYZC0QFC55qW9f3hGG2MWly5ppWDxiccAmKNQ1nl30oh7huILjbtY0Bo2dIzgeIvBEHC6ibbZ0Q/640?wx_fmt=png "")  
  
研究员们通过介绍如何使用YARA及如何构建可行系统，阐述了系统化使用YARA捕获漏洞需思考的问题，并使用收集到历史样本、公开样本、自定义样本等对完成后的系统进行准确度测试、压力测试、规则性测试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnfIHicYZC0QFC55qW9f3hGG2IujoNMJ4vZvrBVEz3ftwbPQ8OpZ1q2LB1uOC7HBFUUjbcRIV52ic21w/640?wx_fmt=png "")  
  
在建立完一套行之有效的捕获系统后，研究员介绍了一年之中捕获大量Windows本地提权漏洞样本的其中包括“CVE-2021-1732”、“CVE-2021-33739”、“CVE-2022-24481”三个被成功捕获的漏洞案例。在介绍完案例后，研究员建议在研究捕获漏洞时，可以选择自己能力范围内最适合的方法，并仔细研究历史案例，同时留意那些新出现的在野漏洞的变种。他们预测，未来会可能出现更多clfs模块的漏洞，并且“Pipe Attribute”这种手法在未来可能会继续被使用，而且未来可能会有更多在野利用使用以下手法：  
- Arbitrary address
read/write with the help of WNF,
POC2021  
  
- Arbitrary
address read/write with the help of ALPC,
Blackhat Asia 2022  
  
- Arbitrary
address read/write with the help of I/O Ring,
TyphoonCon 2022  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnfIHicYZC0QFC55qW9f3hGG2ZnzzWKrcFxhvVxTL3lOcRUMptXYNX1U8CicyPSVfc2Qlm6lrXlnoicXQ/640?wx_fmt=png "")  
## 大会简介  
  
  
本次是中央研究院的研究成果第二次入选BlackHat USA议题。Blackhat USA作为全球最顶尖的安全技术会议，是全球安全界的盛会，从1997年至今已举办了25年，提供了最新的网络安全研究、发展和趋势等资讯。在2020年中央研究院海特实验室团队在BlackHat USA 2020上公布了一个安卓蓝牙的设计缺陷，并将其命名为BlueRepli。（[“BlueRepli”：海特实验室研究成果入选世界顶级安全大会Blackhat！](http://mp.weixin.qq.com/s?__biz=MzUyMDEyNTkwNA==&mid=2247483967&idx=1&sn=bcb92b0e078aaa56cf910fa46a6ba723&chksm=f9ee6e80ce99e796f4bdefa6bb10c781199997e97106175eecd1c2b5d14a647ab1fc0ac673ff&scene=21#wechat_redirect)  
  
）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvneTTZ9RPyxQfFODkzy9ET4dk73K9cUNXKwOfp8PhlYKhvJMVAibc5TBFDDBSG420Sd90HwxE0QlIgQ/640?wx_fmt=png "")  
  
**01**  
  
猎影实验室  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IjbQj47AO4nVc4W71jS1U8cVIeTyjCiaAfdTFVOZZVhUMMhVRbVKxVREhuKhZBXE2BMf4ibu8kF69Igmz03XajYg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
猎影实验室专注于APT攻击**发现、分析、检测、溯源、防御**等工作。  
  
依托安恒威胁情报大数据分析平台，通过海量威胁情报进行关联分析，发现了多起针对国内能源、海洋、教育、科研等行业的AP  
T攻击事件，并发布了多个高质量APT攻击分析报告。  
  
  
**02**  
  
卫兵实验室  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IjbQj47AO4nVc4W71jS1U8cVIeTyjCiaA7NMQgDZJuOMg0GrkmPwLvXsu55mFH8DfXnD2BRvKjSt9nVgSROZPAw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
卫兵实验室专注于**Web安全**，**移动安全和二进制安全**领域漏洞研究，  
漏洞研究成果参与blackhat、天府杯、强网杯、geekpwn等各大国内外知名安全会议和赛事。  
  
高级漏洞挖掘团队发现大量重量级安全漏洞，为全球各大公司（苹果、微软、Apache、Oracle、  
Paypal  
等）提供了众多安全漏洞成果输出。  
  
**03**  
  
海特实验室  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IjbQj47AO4nVc4W71jS1U8cVIeTyjCiaAc7ZUibe2mqQqJ7YAaibQDF4L2x1BWia7dybJZtlPOWVSFJToibyLy4t3Yw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
海特实验室专注于**硬件、固件、无线电**相关安全，  
主要工作包括物联网设备测试、物联网漏洞挖掘与物联网攻防设备研究。  
  
IoT安全研究团队，先后发现Google、Cisco、Juniper、PaloAlto、TP-Link、Goahead、Lua等知名厂商与相关IoT组件漏洞，参与BlackHat、HITB、ZeroNights、强网杯、GeekPWN等国内外会议演讲和竞赛，并自主研发多个创新性硬件设备。  
  
  
更多招聘详情请查看以下链接。  
  
[传闻中安恒信息有个神秘组织？？？](http://mp.weixin.qq.com/s?__biz=MzUyMDEyNTkwNA==&mid=2247485766&idx=1&sn=9be96d1d574ff065059614da492364d9&chksm=f9ee65f9ce99ecef8eb727310c6b52bb00af199524b700603debc7f2e80ebd5159c7c428e407&scene=21#wechat_redirect)  
  
