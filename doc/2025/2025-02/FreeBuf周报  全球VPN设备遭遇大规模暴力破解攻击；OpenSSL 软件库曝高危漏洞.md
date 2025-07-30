#  FreeBuf周报 | 全球VPN设备遭遇大规模暴力破解攻击；OpenSSL 软件库曝高危漏洞   
Zicheng  FreeBuf   2025-02-15 02:05  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、一周好文，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibS68M2J8HH4TbtJCJa8icwgeTZnoJlKDKgvmH1XZBv3kSibrJ2njZHPdbxHPjPn78OjJ6mPiblZXKRA/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**热点资讯**  
  
  
## 1. 全球VPN设备遭遇大规模暴力破解攻击，280万IP地址参与其中  
  
一场大规模的暴力破解密码攻击正在进行中，攻击者利用近280万个IP地址，试图破解包括Palo Alto Networks、Ivanti和SonicWall在内的多种网络设备的登录凭证。  
###   
### 2. 臭名昭著的8Base勒索软件被查，4名嫌疑人被捕  
  
泰国警方2月10日宣布，一项执法行动已成功查封了臭名昭著的8Base勒索软件团伙，逮捕了与之相关的4名欧洲籍嫌疑人。  
###   
### 3. 苹果0-Day漏洞被用于“极其复杂”的特性攻击中  
  
近日，苹果公司发布了紧急安全更新，以修补一个0-Day漏洞，编号CVE - 2025 - 24200，由公民实验室 安全研究人员比尔·马尔扎克报告。该漏洞在有针对性的且“极其复杂”的攻击中被利用，“在设备锁定时禁用USB限制模式”。  
###   
### 4. OmniGPT疑似遭入侵：黑客泄露3400万条用户数据  
  
一名黑客声称已成功入侵 OmniGPT——一个由人工智能驱动的知名聊天机器人和生产力平台。此次事件导致3万名用户的电子邮件、电话号码以及超过 3400 万条（34270455）用户对话被泄露。这些数据由一位化名为“Gloomer”的黑客于2月9日上午在 Breach Forums 上发布。  
###   
### 5. Gcore DDoS报告揭示：DDoS攻击量同比增长56%  
  
Gcore最新的DDoS雷达报告，对2024年第三季度至第四季度的DDoS攻击数据进行了深入分析。报告显示，这一时间段内，DDoS攻击总量呈现出迅猛增长的态势，同比增长56%，其中最大攻击峰值更是飙升至前所未有的2Tbps，创下历史纪录。  
###   
### 6. 攻击者利用新零日漏洞劫持Fortinet防火墙  
  
Fortinet近日发布警告，称威胁攻击者正在利用FortiOS和FortiProxy中的一个新零日漏洞（CVE-2025-24472，CVSS评分为8.1）来劫持Fortinet防火墙。该漏洞是一个身份验证绕过问题，远程攻击者可以通过构造恶意CSF代理请求获取超级管理员权限。  
###   
### 7. OpenSSL 软件库曝高危漏洞，可实施中间人攻击  
  
OpenSSL 项目在其安全通信库中修复了一个高严重性漏洞，编号为 CVE-2024-12797。OpenSSL 软件库用于在计算机网络中实现安全通信，防止窃听并确保通信双方的认证。该库包含了安全套接层（SSL）和传输层安全（TLS）协议的开源实现。  
###   
### 8. 利用Microsoft Graph API，Outlook成恶意软件传播新渠道  
  
近日，研究人员发现了一种新型恶意软件系列，通过Microsoft Graph API利用Microsoft Outlook作为通信渠道。这一复杂的恶意软件包括一个自定义加载程序和一个后门，分别被称为PATHLOADER和FINALDRAFT。根据其复杂性和长期运行的特点，该恶意软件主要被用于网络间谍活动。  
###   
### 9. Windows存储系统0day漏洞，攻击者可远程删除目标文件  
  
Windows系统近日被曝出一个重大安全漏洞，攻击者可利用该漏洞远程删除受影响系统上的目标文件。该漏洞编号为CVE-2025-21391，于2025年2月11日披露，属于权限提升漏洞，严重性被评定为"重要"级别。  
###   
### 10. 特朗普政府拉长0day漏洞披露时间  
  
为了应对披露零日漏洞这一棘手的问题，美国政府早在 2010 年就设立了 “漏洞公平处理程序”（VEP）。但VEP的披露一直存在数字缺失与公众疑虑的问题，在特朗普政府执政期间，这种信息不透明的问题可能会变得更严重。  
##   
  
**一周好文共读**  
  
  
## 1. 企业级 Linux 挖矿实战揭秘，附应急专杀编写攻略  
  
日常工作中分配到一个Linux横向的分析处置任务，经过一系列分析后，发现这个黑产组织整体的攻击路径都是比较单一，拿下一台主机后，就是疯狂套娃，在执行挖矿任务的同时，还不忘记对内网横向攻击，进一步的拓展他的战果，进行进一步的牟利。  
  
  
![1719383456_667bb5a05000ee7693c04.png](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibS68M2J8HH4TbtJCJa8icwgyX8AxzyRmS19p7sZSeNvcFSrJ3cLU7Nus9fMicJ1lYsXn6hf0mMBdmw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. 新钓鱼技术——页面双生  
  
页面双生技术（Twin Pages）是一种高级的网络钓鱼攻击方式，通过构建两个相互依赖的网页——主页面和副页面，巧妙地利用目标在浏览网页时的行为模式进行攻击。   
  
  
![1](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibS68M2J8HH4TbtJCJa8icwgfyL1pNg4hPpwJHpyicdSkiafkUvNibRldqvauN4cPCfzkxOsd8uvSVTbw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 从 0 到 1：Linux 服务器应急排查实战指南  
  
在服务器运行过程中，网络安全攻击频发，常见威胁包括 挖矿病毒、蠕虫传播、DDoS 攻击、后门程序等。这些攻击不仅影响系统稳定性，还可能造成数据泄露或业务中断。对于系统运维和应急排查人员而言，如何在最短时间内识别攻击迹象、精准定位问题来源，并迅速采取应对措施，是一项至关重要的技能。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibS68M2J8HH4TbtJCJa8icwgoA4G6MqKlMlaFcScTV8fM8D8ibQZA6n2SkqtNjia9EmTCibP0O2xP776g/640?wx_fmt=jpeg&from=appmsg "")  
  
   
  
*点击  
【阅读原文】  
可查看完整文章内容，付费文章购买FVIP方可阅读全文。  
  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
