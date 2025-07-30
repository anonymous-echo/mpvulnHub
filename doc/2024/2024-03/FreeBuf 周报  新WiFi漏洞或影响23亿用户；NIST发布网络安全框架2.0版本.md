#  FreeBuf 周报 | 新WiFi漏洞或影响23亿用户；NIST发布网络安全框架2.0版本   
小王斯基  FreeBuf   2024-03-02 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、安全事件、一周好文和省心工具，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibjhfyhUldicfD7cT5ASbKsTzJwdIUS24O7byRzTkIQ041BbEWSRGIXPTLf3y9dgPkooNSMwjf5GZA/640?wx_fmt=png&from=appmsg "")  
  
  
**热点资讯**  
##   
### 1. SendGrid 最新网络钓鱼活动正在“瞄准”中小型企业  
  
卡巴斯基的网络安全专家发现了一种专门针对中小型企业新的网络钓鱼活动，攻击的方式包括利用电子邮件服务提供商(ESP) Twilio SendGrid 来访问客户邮件列表，以及利用窃取的凭证发送令人信服的网络钓鱼电子邮件等。  
  
### 2. 全新 WiFi 安全漏洞曝光，可能影响全球 23 亿安卓用户  
  
黑客可利用该漏洞创建一个克隆版WiFi热点并截取用户数据，有安全研究员证实，使用 WPA2/3 企业模式的 WiFi 网络存在风险。甚至可以说，全球有 23 亿安卓用户都可能受到这个漏洞的影响。  
  
### 3. 《中华人民共和国保守国家秘密法》修订发布，5 月 1 日正式实行  
  
2024 年 2 月 27 日，中华人民共和国第十四届全国人民代表大会常务委员会第八次会议修订通过《中华人民共和国保守国家秘密法》，自 2024 年 5 月 1 日起施行。  
  
### 4. 黑客借助 LabHost 平台对加拿大银行用户发起大规模钓鱼攻击  
  
网络钓鱼即服务（PhaaS）平台 "LabHost "一直在帮助网络犯罪分子攻击北美银行，尤其是加拿大的金融机构，近日的攻击活动明显增加。  
  
### 5. DDoS 攻击引发云服务提供商索要 10.4 万美元账单  
  
Reddit 某用户在遭受网络攻击后，Netlify 向他的简单静态网站开具了一张 10.4 万美元的账单。最初收到这个账单，该用户还以为是在开玩笑，与 Netlify 公司客服沟通后，账单降至 5225 美元。随着这个故事在网上的热度不断攀升，Netlify 公司 CEO 决定不向该用户收取任何费用。  
  
  
**安全事件**  
  
  
**1. 俄罗斯 APT28 组织隐秘攻击 Ubiquiti 路由器，以逃避安全检测**  
  
近日，美国联邦调查局与国家安全局、美国网络司令部及国际合作伙伴联合发布警告称，俄罗斯军方黑客正通过被入侵的 Ubiquiti EdgeRouters 来逃避检测。  
  
### 2. NIST 发布里程碑式网络安全框架2.0版本  
  
美国国家标准与技术研究院（NIST）对广泛使用的网络安全框架进行重要更新，新的 2.0 版旨在为所有受众、行业领域和组织类型提供参考，不论组织的网络安全成熟度如何皆可适用，涵盖了从最小型的学校、非营利性组织到最大的集团型企业与机构，旨在更有效地减少网络安全风险。  
  
### 3. WordPress 插件存在漏洞，500 万网站面临严重安全风险  
  
网络安全研究人员近期发现 WordPress  LiteSpeed Cache 插件中存在一个安全漏洞，该漏洞被追踪为 CVE-2023-40000，未经身份验证的威胁攻击者可利用该漏洞获取超额权限。  
  
### 4. 全球知名 AI 平台Hugging Face “惊现”上百个恶意 ML 模型  
  
JFrog 的安全团队发现 Hugging Face 平台上至少 100 个恶意人工智能 ML 模型实例，其中一些可以在受害者的机器上执行代码，为攻击者提供了一个持久的后门，构成了数据泄露和间谍攻击的重大风险。  
  
### 5. Windows 这个零日漏洞正在被黑客利用，以获取内核权限  
  
Lazarus 黑客组织正在试图利用 Windows AppLocker 驱动程序  appid.sys 中的零日漏洞 CVE-2024-21338，获得内核级访问权限并关闭安全工具，从而能够轻松绕过 BYOVD（自带漏洞驱动程序）技术。  
##   
  
**一周好文共读**  
##   
### 1. 为什么黑客这么喜欢攻击加密货币？  
  
根据加密货币追踪公司 Chainalysis 最新发布的《2024 年加密货币犯罪报告》，仅勒索软件从受害者处勒索的加密货币价值就超过了 10 亿美元，2022年为 5.67 亿美元。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibjhfyhUldicfD7cT5ASbKsT6q9hdlO90sYPULPohCURjojzicV2llTbQWQTUyvqRZibBB62BvRFEfibQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. AI 攻防：如何使用人工智能提升网络安全性  
  
AI 在网络安全的应用可以说是一场革命。它通过学习和理解网络流量模式，预测并识别潜在的威胁，从而提供更为高效、准确的网络安全保障。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibjhfyhUldicfD7cT5ASbKsTy1OYZfEBhsrppPhUSvcbjHQpibX3rIURAPYn1Hy37XrafpBZGsA3qibg/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 操作权限管理（二）| 数据安全自评估企业实践  
  
本文将在系统访问权限配置、运维支撑人员操作权限、超级管理员帐号权限以及敏感数据操作管理四个关键领域进行深入评估，并提出相应的整改建议，以进一步加强账号安全和权限管理的效能。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibjhfyhUldicfD7cT5ASbKsTa2bgAvicWGzLmialobFUr4qCocH6xfDVEyXwFicLMDUOTictMM6YRNiaFNA/640?wx_fmt=png&from=appmsg "")  
##   
  
**省心工具**  
##   
### 1. 如何在 Cobalt Strike 中使用 Payload-Generator 实现 Payload 自动化构建速  
  
Payload-Generator 是一款功能强大的安全测试脚本，该工具专为红队研究人员设计，可以帮助广大研究人员在 Cobalt Strike 中使用 Payload-Generator 实现 Payload 自动化构建。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibjhfyhUldicfD7cT5ASbKsTmvic3swtUg2icIzH1agtat7pLUXjfWrCviaY3VZpLICVYS0UrFZJPWoBQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. Linpmem：一款功能强大的 Linux 物理内存提取工具  
  
Linpmem 是一款功能强大的 Linux 物理内存提取工具，该工具专为 x64 Linux 设计，可以帮助广大研究人员在执行安全分析过程中快速读取 Linux 物理内存数据。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibjhfyhUldicfD7cT5ASbKsTC5zTRN9tPDjTTN4UFvZHlMNYTu0UtnAs5wzDdmm7H4HezSxk0g0WOw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. Smuggler：一款功能强大的 HTTP 请求走私和去同步安全测试工具  
  
Smuggler 是一款功能强大的 HTTP 请求走私和去同步安全测试工具，该工具基于纯 Python 3 开发，可以帮助广大研究人员针对应用程序的 HTTP 协议执行安全分析和测试。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibjhfyhUldicfD7cT5ASbKsTs4GvKibbwx49ibdRIPwErMYJQV04yhe7dLZ7Jg0PtiasHUWzB1UsRcjMQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492452&idx=1&sn=a097203d8764651efcbc134c51b89450&chksm=ce1f19fbf96890edd5319a931be92c41d07d67ecb5054b2b1a51f0aeee915706fac74fda523e&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492409&idx=1&sn=0989200153f6f4679af989e0852c8789&chksm=ce1f19a6f96890b01a5f5cab663742e640859aa44f27f3bb31eb0eca8c2fd920bdb9839a5c19&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
