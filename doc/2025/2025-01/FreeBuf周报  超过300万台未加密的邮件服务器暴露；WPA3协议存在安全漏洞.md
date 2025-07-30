#  FreeBuf周报 | 超过300万台未加密的邮件服务器暴露；WPA3协议存在安全漏洞   
Zicheng  FreeBuf   2025-01-04 02:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、安全事件、一周好文和省心工具，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hn0NEUrP49TicibIIFQQQSqR4VTHTsW3CbzPNrdQ85icLPbGoE1CdAeMrdg/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**热点资讯**  
  
  
## 1. 用户集体起诉Siri“偷听”  
  
1月3日消息，科技巨头苹果公司同意支付9500万美元现金，以和解一项拟议的集体诉讼，该诉讼声称其Siri语音助手侵犯了用户的隐私。这份和解协议涵盖了2014年9月17日至2024年12月31日期间使用Siri的美国用户，涉及数千万人。  
###   
### 2. 日本最大的移动运营商因DDoS攻击导致服务中断  
  
日本最大的移动运营商 NTT Docomo Inc. 当地时间1月2日表示，一次分布式拒绝服务 （DDoS） 网络攻击导致运营中断，网站和一些服务在宕机大半天后才逐渐恢复。  
###   
### 3. 超过300万台未加密的邮件服务器暴露  
  
目前，超过300万台未启用TLS加密的POP3和IMAP邮件服务器暴露在互联网上，容易受到网络嗅探攻击。  
###   
### 4. Windows 曝9.8分漏洞，已有PoC及利用情况  
  
SafeBreach Labs的研究人员发布了关于Windows轻量级目录访问协议（LDAP）的一个关键漏洞的概念验证（PoC）和漏洞利用方法，该漏洞编号为CVE - 2024 - 49112。微软在2024年12月10日的补丁星期二更新中披露了此漏洞，其CVSS严重性评分高达9.8。  
###   
### 5. 亚太地区恐在2025年面临更多深度伪造、量子攻击威胁  
  
对于2025年，Palo Alto Networks 亚太及日本区总裁 Simon Green 认为亚太地区将迎来“AI 驱动的网络威胁”。他指出，深度伪造音频和视频攻击可能是这一趋势中最明显的表现形式。  
##   
  
**安全事件**  
  
  
### 1. 大量Chrome扩展程序遭黑客攻击，60万用户数据危险  
  
一场新的攻击活动针对知名的Chrome浏览器扩展程序，导致至少16个扩展程序被入侵，超过60万用户面临数据泄露和凭证被盗的风险。  
###   
### 2. 利用 DoS 漏洞可瘫痪 Palo Alto 防火墙  
  
Palo Alto Networks警告，称黑客正在利用CVE - 2024 - 3393拒绝服务漏洞，通过强制重启防火墙的方式，使其保护功能丧失。反复利用这一安全漏洞会让设备进入维护模式，必须手动干预才能恢复正常运行状态。  
###   
### 3. WPA3协议存在安全漏洞，黑客可获取WiFi密码  
  
研究人员成功结合中间人攻击（MITM）和社会工程学技术，绕过了Wi - Fi保护协议——WPA3 ，进而获取网络密码。此次研究由西印度大学的Kyle Chadee、Wayne Goodridge和Koffka Khan开展，这一研究揭示了最新无线安全标准存在的安全漏洞。  
###   
### 4. 老旧D-Link路由器成了僵尸网络的武器  
  
近期，两个名为“Ficora”和“Capsaicin”的僵尸网络在针对已停产或运行过时固件版本的D-Link路由器的攻击活动中表现活跃。受影响的设备包括个人和组织常用的D-Link型号，如DIR-645、DIR-806、GO-RT-AC750和DIR-845L。  
###   
### 5. 新的“DoubleClickjacking”漏洞可绕过网站的劫持保护  
  
安全专家揭示了一种新型的“普遍存在的基于时间的漏洞”，该漏洞通过利用双击操作来推动点击劫持攻击及账户接管，几乎波及所有大型网站。这一技术已被安全研究员Paulos Yibelo命名为“DoubleClickjacking”。  
##   
  
**一周好文共读**  
  
  
### 1. 初尝clickjacking技术  
  
Clickjacking是一种基于界面的攻击，通过点击诱饵网站上的其他内容，诱骗用户点击隐藏网站上的可操作内容。本文将解释什么是Clickjacking，描述常见的Clickjacking攻击示例，并讨论如何防范这些攻击。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hng8ysurPcM5WhmSm9qcChn34IGvdqI8kxmA6fZGSzj1G7aGPicSkS9BQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. 嵌套反序列化的危害：Magento XXE 漏洞分析（CVE-2024-34102）  
###   
  
为了深入了解此漏洞的危害性，本文将对其进行全面分析，并构建概念验证工具（PoC）来验证漏洞的实际可利用性。通过这种方式，将详细揭示漏洞的潜在影响及可能带来的安全风险，为读者提供深入的理解，帮助其在实际应用中采取有效的防护措施。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hn7pXplfjTnGxkwuWAV0jI2T2Jvsrq7lZicjibz9HAAtrEqZ2hjlHLwicdg/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. CCSIP 2024中国网络安全行业全景册（第七版）发布 | FreeBuf咨询  
  
本次全景册面向广大国内安全厂商，由厂商自主申报并填写信息征集表，经FreeBuf咨询团队审核后，将符合要求的厂商信息入驻至《CCSIP 2024中国网络安全产业全景册（第七版）》，为企业安全建设及产品选型提供参考。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hnuXjVeq20YhOvMqianEy8FTK6O8auibHdPReTunRV1icbfEKyUX9KMHV6Q/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**省心工具**  
  
  
### 1. Brakeman：针对Ruby on Rails应用的静态分析安全漏洞扫描器  
  
Brakeman是一款功能强大的静态安全分析工具，该工具旨在针对Ruby on Rails应用程序执行静态分析与安全漏洞扫描任务。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hnBnjwpqe7qIzjWrDXLNX6dZdA30u5VyeTjITkoLeM2Oia7bckKhb7zCg/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. AIL-framework：一款模块化信息泄露安全分析框架  
  
AIL-framework是一款功能强大的模块化框架，该工具可以用于对信息泄露场景执行安全分析。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hnxUwl56SK4BYEr5fsGAuicnVDSB82dlScng3klYUZVicQX5sDEPa6gKHw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. Knock：一款模块化的子域名扫描工具  
  
Knock是一款功能强大的模块化子域名扫描工具，该工具基于Python开发，旨在通过被动侦察和字典扫描快速枚举目标域上的子域。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hnFvcOy8t0Ip10Shtb9loJt2rbfTwu4r6rwFdr0BLcplSnib56ZaP1UIQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
