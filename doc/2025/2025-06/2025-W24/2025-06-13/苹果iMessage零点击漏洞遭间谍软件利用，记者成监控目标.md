> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323069&idx=2&sn=46c850fbda9bc82352ef57c89fdd96e8

#  苹果iMessage零点击漏洞遭间谍软件利用，记者成监控目标  
 FreeBuf   2025-06-13 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxQBA0eg0q5VAFpZC2GGFq84Rrric8tFLcwFFUqRIYCfxQiaWSnDJT4sXA/640?wx_fmt=jpeg "")  
  
### Part01  
### 漏洞详情与修复进展  
###   
  
苹果公司披露，其iMessage应用中存在的一个现已修复的安全漏洞曾被用于针对公民社会成员的复杂网络攻击。该漏洞编号为CVE-2025-43200，已于2025年2月10日通过iOS 18.3.1、iPadOS 18.3.1、iPadOS 17.7.5、macOS Sequoia 15.3.1等系统更新修复。  
  
  
苹果在安全公告中表示："处理通过iCloud链接分享的恶意制作照片或视频时存在逻辑缺陷"，并称已通过改进检查机制解决该问题。该公司同时承认，已发现该漏洞"可能被用于针对特定个人的极其复杂的攻击"。  
  
  
值得注意的是，此次更新还修复了另一个正在被利用的零日漏洞（CVE-2025-24200），但苹果此前一直未披露该漏洞存在的原因尚不明确。  
###   
### Part02  
### 记者遭针对性攻击  
###   
  
虽然苹果未透露利用CVE-2025-43200发动攻击的具体细节，但公民实验室（Citizen Lab）表示已发现法医证据，表明该漏洞被用于攻击意大利记者Ciro Pellegrino和一名未具名的欧洲知名记者，并植入Paragon公司的Graphite雇佣间谍软件。  
  
  
研究人员将该攻击描述为"零点击"攻击，意味着无需用户任何交互即可在目标设备上触发漏洞。研究人员Bill Marczak和John Scott-Railton指出："2025年1月至2月初，其中一名记者的设备在运行iOS 18.2.1系统时感染了Graphite间谍软件，目标用户难以察觉此次感染。"  
  
  
2025年4月29日，苹果向两名受害者发出高级间谍软件攻击警告。自2021年11月起，苹果开始向疑似遭受国家支持攻击者锁定的用户发送威胁通知。  
###   
### Part03  
### Graphite间谍软件运作机制  
###   
  
Graphite是以色列私营攻击组织（PSOA）Paragon开发的监控工具，可在无需用户操作的情况下获取消息、邮件、摄像头、麦克风和位置数据，隐蔽性极强。该间谍软件通常由政府客户以国家安全调查为名部署使用。  
  
  
公民实验室发现，两名记者均收到来自同一苹果账户（代号"ATTACKER1"）的iMessage信息，这些信息用于部署Graphite工具，表明该账户可能被单一Paragon客户用于实施攻击。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxrBJ9cPia5JwPKGJeReHxL5QUQQskQlngWJuVuuncpypD7q7nKcnwp6Q/640?wx_fmt=jpeg&from=appmsg "")  
  
### Part04  
### 意大利政府卷入争议  
###   
  
今年1月，Meta旗下WhatsApp披露该间谍软件曾被用于攻击全球数十名用户，包括Pellegrino的同事Francesco Cancellato。截至目前，已有7人被确认为Paragon间谍软件的受害者。  
  
  
本周早些时候，这家以色列间谍软件制造商宣布终止与意大利政府的合同，原因是意方拒绝让公司独立核实当局是否违反法律入侵调查记者的手机。但意大利政府表示这是双方共同决定，并出于国家安全考虑拒绝了该提议。  
  
  
意大利议会安全委员会（COPASIR）上周发布的报告证实，在获得必要法律授权后，意大利情报部门确实使用Graphite监控了少数人的手机，主要用于追查逃犯、打击非法移民、恐怖主义等活动。但报告明确表示Cancellato的手机不在监控之列，使得谁针对该记者的问题仍悬而未决。  
  
  
报告还揭示了Graphite的运作机制：操作员需通过用户名和密码登录才能使用该软件，每次部署都会生成详细日志，这些日志存储在客户控制的服务器上，Paragon无法访问。  
  
### Part05  
### 监管压力与行业影响  
###   
  
公民实验室指出："间谍软件受害者缺乏追责渠道，凸显欧洲记者持续面临这种高度侵入性的数字威胁，也暴露出间谍软件扩散和滥用的危险。"欧盟此前已对商业间谍软件的滥用表示担忧，呼吁加强出口管制和法律保障。此类事件可能加剧欧盟及各成员国层面的监管改革压力。  
  
  
苹果的威胁通知系统基于内部威胁情报，可能无法检测所有攻击实例。该公司强调，收到警告并不代表确认感染，仅表明检测到与针对性攻击相符的异常活动。  
  
### Part06  
### Predator间谍软件卷土重来  
###   
  
最新消息显示，Recorded Future的Insikt小组观察到与Predator相关的活动出现"复苏迹象"。这包括发现新的受害者端Tier 1服务器、莫桑比克的新客户，以及Predator基础设施与捷克实体FoxITech s.r.o.的关联。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkx0x6Tlny7chxichvWaW3ErPL8nKakMZXyTbJoATl02eWUzUqYWFmFcJw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
过去两年间，Predator运营商的活动已在安哥拉、亚美尼亚、埃及等十余个国家被发现。分析指出："这与Predator在非洲高度活跃的总体观察结果一致，其半数以上已知客户位于非洲大陆。这反映出间谍软件工具需求增长，特别是在面临出口限制的国家，以及为规避制裁和溯源而设计的日益复杂的企业架构。"  
  
  
**参考来源：**  
  
**Apple Zero-Click Flaw in Messages Exploited to Spy on Journalists Using Paragon Spyware**  
https://thehackernews.com/2025/06/apple-zero-click-flaw-in-messages.html  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651322946&idx=1&sn=c9cbbd848459bfe0a36fa121ff364ad0&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
