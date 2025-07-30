#  FreeBuf 周报 | 2024年网安最高处罚记录诞生；谷歌再提高Chrome漏洞赏金数额   
FB客服  FreeBuf   2024-08-31 09:31  
  
##   
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、安全事件、一周好文和省心工具，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39vt3r0UGG1tzwO3skkIoEcynC4C38Zx1CznUWuZNQuzNHibkc1YSd9zSeYqibT8D2N7hMcaibYT7Znw/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**热点资讯**  
  
  
## 1. 网络身份证是强制，会影响正常上网？公安部详细回应  
###   
  
公安部第一研究所研究员于锐指出，用户不是“持证”才能“上网”，而是在需要证明身份的场景中多了一种更加安全、方便的选择，不需要反复向各个平台提供明文的个人身份信息。同时，原有的身份认证方式仍可继续使用，没有网号、网证也可正常上网。  
###   
### 2. 审计发现 FBI 的数据存储管理存在重大漏洞  
  
据The Hacker News消息，美国司法部监察长办公室 （OIG） 的一项审计发现， FBI 在库存管理和处置涉及机密数据的电子存储媒体方面存在“重大漏洞”。  
###   
### 3. 2024年网安最高处罚记录诞生，Uber因违反GDPR被罚23亿  
  
近日，荷兰数据保护局指控Uber在未采取《通用数据保护条例》（下文简称：GDPR ）第五章规定的充分保障措施的情况下，将个人数据从欧洲经济区（EEA）转移至美国的服务器。荷兰数据保护局称其违反了GDPR 的规定，并对其处以罚款 23.18亿元（2.9亿欧元）罚款，这是荷兰数据保护局第三次对 Uber 处以行政罚款。  
###   
### 4. Mirai 僵尸网络发现新漏洞，能同时被攻守双方利用  
  
Mirai 僵尸网络在全球 DDoS 攻击中发挥了重要作用，特别是针对 IoT 设备和服务器的攻击。最近，Mirai的命令和控制服务器中发现了一个新漏洞，该漏洞允许攻击者执行DDoS攻击，但同时也能被安全人员用来进行反制。  
###   
### 5. Google 再提高 Chrome 漏洞赏金数额，最高可达25万美元  
  
近日，谷歌公司宣布通过其漏洞奖励计划报告的Google Chrome单一漏洞的最高奖励金额已超过25万美元。  
##   
  
**安全事件**  
  
  
## 1. 新型 Linux 恶意软件 “sedexp ”利用 Udev 规则隐藏信用卡盗刷器  
  
网络安全研究人员发现了一种新的隐秘 Linux 恶意软件，它利用一种非常规技术在受感染系统上实现持久性，并隐藏信用卡盗刷代码。  
###   
### 2. 又一全新恶意软件曝光！专门针对Windows、Linux 和 macOS 用户  
  
近日，网络安全研究人员发现了一个利用 “Cheana Stealer ”恶意软件的复杂网络钓鱼活动，该恶意软件是通过一个 VPN 钓鱼网站传播的。这次攻击的主要目标是各种操作系统的用户，包括 Windows、Linux 和 macOS。  
###   
### 3. 存在严重供应链安全风险，MLOps平台曝20多个漏洞  
  
网络安全研究人员警告称，在发现20多个漏洞后，机器学习（ML）软件供应链存在安全风险，这些漏洞可能被利用来针对MLOps平台。这些漏洞被描述为固有和实现方面的缺陷，可能会产生严重后果，从任意代码执行到加载恶意数据集。  
###   
### 4. 微软Sway在大规模二维码钓鱼活动中被滥用  
  
近期，一个大规模的网络钓鱼活动利用Microsoft Sway这一云基础的在线演示工具来搭建登陆页面，目的是为了诱使Microsoft 365用户泄露他们的登录凭证。  
###   
### 5. ServiceBridge泄露 3200万份文件，大量企业数据被曝光  
  
据Cyber News消息，安全研究员杰里迈亚-福勒（Jeremiah Fowler）发现了一个基于云的现场服务管理平台 ServiceBridge 暴露了大规模数据，其中包含合同、工单、发票、建议书、协议、部分信用卡号，甚至还有可追溯到 2012 年的 HIPAA 同意书。  
##   
  
**一周好文共读**  
  
  
## 1. 研发安全 | 一文吃透认证体系的内核  
  
认证，作为应用系统的大门，也作为研发安全的第一道门槛，很多师傅们与研发人员都清楚，本文从综合研发、安全（含SDL、安全测试）的视角，聊一聊认证的内核，即cookie、session、token、jwt。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39vt3r0UGG1tzwO3skkIoEctGlm7QmZgxCNggxRzGyVftjfNrf6wYwicX4TqnAwnwcnBFniahbYOuZw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. 2024年加密货币犯罪报告：勒索软件攻击者越来越利用社会工程学  
  
2024年上半年，尽管整体非法活动有所下降，但加密货币犯罪中的两类特定犯罪活动——被盗资金和勒索软件却在上升。报告详细分析了这些犯罪活动的趋势和背后的原因，并探讨了加密货币生态系统中的一些积极发展。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39vt3r0UGG1tzwO3skkIoEctAUnafkzDdHhpeFsW6QUictPVu4FYtQGTuosZTVTdVLhljAXj6LRaNQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 等保2.0 | TiDB数据库测评  
  
TiDB 是一个分布式 NewSQL 数据库，由 PingCAP 公司开发。它兼容 MySQL 协议和生态，支持水平扩展、强一致性和高可用性。TiDB 的设计目标是为在线事务处理（OLTP）和在线分析处理（OLAP）提供一站式解决方案，适用于互联网、金融、游戏、大数据等场景。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39vt3r0UGG1tzwO3skkIoEcjicdzotaPgC5zKUukibJm5kxBBdYNQQLMs4UkEVnTKOQDedoq4nKMjyA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**省心工具**  
  
  
### identYwaf：一款基于盲推理识别技术的WAF检测工具  
  
identYwaf是一款功能强大的Web应用防火墙识别与检测工具，该工具基于盲推理识别技术实现其功能，可以帮助广大研究人员迅速识别目标Web应用程序所使用的保护防火墙类型。   
  
  
****###   
### 2. 如何使用Kdrill检测Windows内核中潜在的rootkit  
  
Kdrill是一款用于分析 Windows 64b 系统内核空间安全的工具，该工具基于纯Python 3开发，旨在帮助广大研究人员评估Windows内核是否受到了rootkit攻击。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39vt3r0UGG1tzwO3skkIoEcg93gEictRnib9VCibvcgt3ZibNicXw7WhMTKJksxIzoRO2icu751dibaiaicdCA/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. PANIX：用于安全研究和渗透测试的高度可定制Linux持久性工具  
  
PANIX是是一款高度可定制的 Linux 持久性工具，可用于安全研究、检测工程、渗透测试、CTF 等。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39vt3r0UGG1tzwO3skkIoEcYUDxk9UZ9y666Bzh0VACHicl21TavyvibH0QLricAnD7RribceicWJKYrQQ/640?wx_fmt=jpeg&from=appmsg "")  
  
