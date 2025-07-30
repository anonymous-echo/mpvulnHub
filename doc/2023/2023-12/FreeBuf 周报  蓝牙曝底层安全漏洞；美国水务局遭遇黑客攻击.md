#  FreeBuf 周报 | 蓝牙曝底层安全漏洞；美国水务局遭遇黑客攻击   
小王斯基  FreeBuf   2023-12-02 09:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、安全事件、一周好文和省心工具，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39K2Vw9h41E9SWkUbI3CsVILqcIRl6Ippoic4OSSUDlLjUEzyRrc6VuVGNuOKd38pRqGjOcqMNz5Rg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**热点资讯**  
  
  
## 1. SIM卡调换黑客被判入狱 8 年，罚金 120 万美元  
  
洛杉矶地区法院判处 25 岁的 Amir Hossein Golshan 八年监禁，并勒令其支付 120 万美元赔偿金。据悉，Golshan 罪名涉及 SIM 卡交换、商家欺诈、支持欺诈、账户黑客攻击和加密货币盗窃。  
###   
### 2. Black hat 大会 13 岁天才黑客：从 Python 到勒索软件  
  
在 2023 年 11 月 14 日至 16 日举行的中东和非洲黑帽大会上，一位年轻的演讲者受到了世人关注，他便是来自沙特阿拉伯的 13 岁男孩马可·利伯拉尔（Marco Liberale）。  
###   
### 3. 美国水务局遭遇黑客攻击，系统第一时间紧急下线  
  
美国网络安全和基础设施安全局（CISA）称其正在处理一起由伊朗黑客组织 "Cyber Av3ngers "发起的网络攻击事件，该攻击涉及主动利用 Unitronics 可编程逻辑控制器 (PLC)，攻击目标是美国宾夕法尼亚州西部的阿里基帕市水务局。  
###   
### 4. 警方摧毁了攻击 71 个国家的勒索软件组织  
  
七个国家的执法机构与欧洲刑警组织和欧洲司法组织共同发起了一次联合执法行动，成功在乌克兰境内逮捕了某勒索软件组织的核心成员。  
###   
### 5. 蓝牙曝底层安全漏洞，数十亿设备受影响  
  
来自 Eurecom 的研究人员近期分享了六种新型攻击方式，统称为"BLUFFS"，这些攻击方式能够破坏蓝牙会话的保密性，使设备容易受到冒充和中间人攻击(MitM)。攻击发现者 Daniele Antonioli 解释道，"BLUFFS"利用了蓝牙标准中两个以前未知的漏洞，这些漏洞与会话密钥的派生方式以及交换数据的解密过程有关。  
  
  
**安全事件**  
  
  
## 1. 滴滴崩了 12 小时，预计损失千万订单  
  
11 月 27 日晚上 11 点左右，“滴滴骑行不可以锁车了”、“滴滴怎么了，为啥打不到车”、“滴滴师傅的距离为啥那么远？”等热门话题迅速冲上各大媒体热搜榜单。很明显，滴滴那会已经崩了。昨晚发现滴滴崩了的打工人实在是太惨了，不仅加班至半夜，还发现滴滴打车无法使用，而高德打车订单爆炸，只能在瑟瑟寒风中等待网约车。  
###   
### 2. BlackCat 又下“黑手”！医疗保健巨头 Henry Schein 35TB 数据被窃  
  
美国医疗保健公司 Henry Schein 近日报告称，他们遭到了 BlackCat/ALPHV 勒索软件团伙的第二次网络攻击，而该团伙在十月份也曾侵入他们的网络。  
###   
### 3. 日本主要通讯应用 Line 遭攻击，数十万用户面临数据泄露风险  
  
日本最主要通讯应用程序 Line 的运营商、日本 LY 公司发布公告称，有攻击者通过附属公司的 NAVER Cloud 系统访问了其内部服务器，可能泄露了数十万条包含用户、员工和业务合作伙伴在内的数据。  
###   
### 4. 全球巨头通用电气疑被黑客入侵开发环境，泄露美国军事机密  
  
美国通用电气公司正在调查一名攻击者在网络攻击中侵入公司的开发环境，并泄露所谓被盗数据的指控。通用电气（GE）是一家业务涵盖电力、可再生能源及航空工业的美国跨国企业。  
###   
### 5. 数百所学校使用的应用程序泄漏未成年人数据  
  
Cyber news 研究小组近期发现由于系统配置错误，IT 公司 Appscook 泄露了大量敏感数据，其中包括未成年人的照片、家庭住址和出生证明。  
  
  
**一周好文共读**  
  
  
## 1. 攻防演练 | 记一次打穿某车企全过程  
  
这次网络攻防演练分为两个阶段一共十四天，前七天是私有资源阶段，后七天是公共资源池阶段。共有 12 支队伍参与比赛，我们公司全程只有两名选手参赛。由于公司从不提供一些辅助工具和人力资源，并且我俩近期连续参加了多场比赛，导致每次比赛后我俩都很内耗。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39K2Vw9h41E9SWkUbI3CsVIJQcUzjlNk08U7L2kE3CSTezQ3CrMeMNbn8QxRj61CDiaPfcVu21lCRA/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. MS Exchange 攻击日志分析二  
  
本文中将介绍如何使用这些日志数据来检测 CVE-2020-16875、CVE-2020-17144 漏洞攻击行为。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39K2Vw9h41E9SWkUbI3CsVIcOPKEb9r1o0qHJkyoHHz4gyDsd7TMaKj9ekxcMAgOv6Uem0oGoUoNg/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 以真实渗透视角剖析等级保护要求的防御能力  
  
首先我们以最通俗易懂的方式解释下，什么是渗透测试？简单来说它是一种检查计算机系统安全性的方法。就好像你拥有一把锁，你想知道这把锁有没有问题，是否容易开启。渗透测试就是一个人（渗透测试人员）尝试去开锁，看是否能够成功进入系统。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39K2Vw9h41E9SWkUbI3CsVIs1cQfiap8Of2OiafxGU7JXgfWJiaibLs9DMJPibryps9BnBVDo5EkKxTm5A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**省心工具**  
  
  
## 1. 如何使用 m4ngl3m3 基于字符串列表生成常见密码模式  
  
m4ngl3m3 是一款功能强大的常见密码模式生成工具，该工具可以帮助广大研究人员使用字符串列表来生成常见的密码模式。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39K2Vw9h41E9SWkUbI3CsVIeo3r7P6oMhSVAblVl2gR91ww5mVyjeqBEHh7H86l1JIdaZEvAbwVgg/640?wx_fmt=jpeg&from=appmsg "")  
  
### 2. WiFi-Pineapple-MK7_REST-Client：一款功能强大的 WiFi 安全渗透测试工具  
  
WiFi-Pineapple-MK7_REST-Client 是一款功能强大的 WiFi 安全渗透测试工具，支持广大研究人员针对目标 WiFi 设备执行近距离的接入操作，并通过渗透测试等方法和主动/被动形式对目标设备执行安全检测，识别和分析存在安全漏洞或错误配置的无线接入点设备，以提升无线网络环境的安全性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39K2Vw9h41E9SWkUbI3CsVI3LbM3BJCl5iciazXjLdoSh88K6YCzHIrRiarlwaCcibAzDtH6iaNRU0vZpQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 如何使用 BurpBounty 快速执行主动或被动安全扫描  
  
BurpBounty 是一个功能强大的 Burp Suite 扩展，该扩展允许我们通过非常直观的图形化界面和个性化定制规则，以简单快速的方式改进主动或被动扫描器。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39K2Vw9h41E9SWkUbI3CsVIzjKYnjlBMwdfRDGg6iaRXJaLEhpYOJHjlrbMibRibibt9H4miamibzdMFsGA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7VjpicfRmENW5Jzf1ec8Vub5ibnEQjSlchNRoD5fZNeib09msyqNeZjbWQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
https://www.bleepingcomputer.com/news/security/new-bluffs-attack-lets-attackers-hijack-bluetooth-connections/  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7rv5uiamoibTdp9P2ia0swfbiaV4uicHc9icqdtbRUlvMtLfRyDXHqJkQqfBg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491509&idx=1&sn=358062ec395fbcbe7b15c7c582631a5c&chksm=ce1ce52af96b6c3c9327439b4a74887b00d10c169601c2e26e79ac4105725a9559a908f64390&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491523&idx=1&sn=ec31589bf31dbe9fdc2b9e4db5321dcc&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491509&idx=1&sn=358062ec395fbcbe7b15c7c582631a5c&chksm=ce1ce52af96b6c3c9327439b4a74887b00d10c169601c2e26e79ac4105725a9559a908f64390&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491480&idx=1&sn=3c9a9f6f543968ad3c6d2fc02dc8bafb&chksm=ce1ce507f96b6c11aa34e03870dda998756564845ddeaf43bc200ea581bfad34ca73cfc77d12&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491456&idx=1&sn=8ad8dd55c50dd968a01b23a2fb1449b7&chksm=ce1ce51ff96b6c09d007b798eef16dd316d497c30502f0dda71124ce4284b7fa3b8dffaa77b6&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
