#  FreeBuf周报 | Apache Avro SDK曝关键漏洞；Word神奇Bug会直接删除文件   
Zicheng  FreeBuf   2024-10-12 20:41  
  
##   
  
****  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、安全事件、一周好文和省心工具，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39s4z3cEJnp7CqFDd180p83Xo6uJFJhvS15c0ibtvvQ5ceBq68z4ib25ItYA5wISLujNvtmME1H41Og/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**项目地址**  
  
  
## 1. 入侵物理隔离的系统，这家APT组织怎么做到的？  
  
将机要系统与任何联网系统完全隔离通常被认为是最安全的防御措施，但随着黑客技术的发展，这道坚不可摧的安全屏障已不再牢固，甚至有一家专门针对政府设施下手的APT组织已研发出了两套工具集，对已隔离系统展开了全方位攻势。  
  
### 2. 损失高达1860亿美元，API风险防不胜防  
  
近日，Imperva 发布的《API和机器人攻击的经济影响报告》 ，指出组织每年因脆弱或不安全的API（应用程序编程接口）和机器人自动化滥用而损失940亿至1860亿美元。该报告强调，这些安全威胁占全球网络事件和损失的11.8%，强调了它们对全球企业日益加剧的风险。  
  
### 3. 微软 Word 曝“神奇Bug”，这样命名会直接删除文件  
  
据微软支持中心发布的消息称，如果用户在命名 Word 文件时使用大写文件格式（例如.DOCX 或.RTF 而不是.docx 或.rtf），或者在文件名中包含#符号，文件在保存时可能会被直接移入回收站。  
  
### 4. 黑客利用YouTube 平台传播复杂的恶意软件  
  
最近，卡巴斯基实验室的网络安全分析师发现，黑客一直在频繁利用 YouTube平台来传播复杂的恶意软件。通过劫持热门频道，黑客伪装成原始创作者发布恶意链接、对用户实施诈骗。  
  
### 5. 可导致设备崩溃，MMS协议被曝存在多个安全漏洞  
  
Claroty研究人员发现制造信息规范（MMS）协议中存在多个安全漏洞，一旦被黑客利用，将很有可能会对工业环境中造成严重影响。Claroty研究人员Mashav Sapir和Vera Mens表示，这些漏洞可能允许攻击者使工业设备崩溃，在某些情况下，还能实现远程代码执行。  
##   
  
**安全事件**  
  
  
##   
### 1. 新型僵尸网络针对 100 个国家发起 30 万次 DDoS 攻击  
  
近日，网络安全研究人员发现了一个名为 Gorilla（又名 GorillaBot）的新僵尸网络恶意软件家族，它是已泄露的 Mirai 僵尸网络源代码的变种。  
  
### 2. Apache Avro SDK曝关键漏洞，可在Java中执行任意代码  
  
Apache Avro Java软件开发工具包（SDK）中披露了一个关键安全漏洞，如果成功利用，可以在易受攻击的实例上执行任意代码。该漏洞编号为CVE-2024-47561，影响1.11.4之前版本的所有软件。Databricks安全团队的Kostya Kortchinsky被发现并报告了这个安全缺陷。  
  
### 3. Awaken Likho恶意组织利用高级网络工具对俄罗斯政府发起“猛攻”  
  
近日，俄罗斯政府机构和工业实体遭遇了一场名为“ Awaken Likho ”的网络活动攻击活动。卡巴斯基表示，攻击者现在更倾向于使用合法MeshCentral平台的代理，而不是他们之前用来获得系统远程访问权限的UltraVNC模块。这家俄罗斯网络安全公司详细说明了一场始于2024年6月并至少持续到8月的新活动。该活动主要针对俄罗斯政府机构、其承包商和工业企业。  
  
### 4. DumpForums论坛黑客声称从网络安全公司 Dr.Web 窃取了 10TB 数据  
  
据Cyber Security News消息，在著名的黑客论坛DumpForums上，有黑客声称对俄罗斯著名网络安全公司 Dr.Web进行了攻击，并窃取了惊人的10TB数据。  
  
### 5. Internet Archive 遭遇黑客攻击，导致 3100 万用户数据泄露  
  
威胁分子在九天前分享了 Internet Archive 的认证数据库，这是一个名为“ia_users.sql”的6.4GB SQL文件。该数据库包含注册会员的认证信息，包括他们的电子邮件地址、屏幕名称、密码更改时间戳、Bcrypt散列密码以及其他内部数据。  
  
  
**一周好文共读**  
  
  
  
**1. 数字化时代的隐患：如何应对API安全风险**  
  
API（应用程序编程接口）是现代软件架构的基础组件，使不同的软件应用能够无缝地进行通信、共享数据和执行复杂操作。随着组织越来越依赖API来连接其系统、服务和设备，解决API安全问题的必要性变得比以往任何时候都更加重要。随着对API依赖的加大，安全漏洞的风险也随之增加，这可能导致数据泄露、未授权访问及其他严重的安全事件。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39s4z3cEJnp7CqFDd180p8323nHs7IXXCUvhBHRMqbanuZmzViahPWiaGLJrp9wAjWQhjNKyqobCQ1g/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. 漏洞挖掘 | 分享几个白帽常用漏洞小技巧  
  
本文分享了几个最近看到的有趣技巧，包括编码绕过、Cloudflare WAF绕过、XSS绕过技术和OS命令注入的实际案例。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39s4z3cEJnp7CqFDd180p83n3cNQAGsW9zMiaGiahDKOMZ9ymfdpCuVy2PLIDcdRlKWN7RWO8Xhicxicw/640?wx_fmt=jpeg&from=appmsg "")  
###   
###   
### 3. Palo Alto：网络安全并购之王  
  
Palo Alto Networks在 2018 年开始了一场大胆的收购狂潮，推动其成为首家千亿美元以上的网络安全平台公司。这种积极的并购方式主要是由首席执行官Nikesh Arora 自 2018 年以来推动的，其重点是扩展公司在云安全、基于人工智能的安全和威胁情报方面的能力。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39s4z3cEJnp7CqFDd180p839YdOHf4Om7LCgQMIJxwwBnq5nGaoliaMDgAFibjz03zbLfXgsiaGk2euQ/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**省心工具**  
  
  
## 1. Gitxray：一款基于GitHub REST API的网络安全工具  
  
Gitxray是一款基于GitHub REST API的网络安全工具，支持利用公共 GitHub REST API 进行OSINT、信息安全取证和安全检测等任务。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39s4z3cEJnp7CqFDd180p83bHNL2sgZrTx0rfDsBfugzb7r05bSVas0v6YttZfp5jTLDrqpFPgCwg/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. ggshield：查找并修复基础设施即代码错误配置和硬编码密钥  
  
ggshield是一款针对基础设施及代码的安全检测工具，该工具支持查找并修复 400 多种类型的硬编码敏感数据和 70 多种类型的基础设施即代码配置错误。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39s4z3cEJnp7CqFDd180p830adh3rZGPAv4UXENvI87GtTWicdC7qeLCzKDheySRsvXRicGfzeXAuEQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. OXO：一款针对Orchestration框架的安全扫描引擎  
  
OXO是一款针对Orchestration框架的安全扫描引擎，该工具可以帮助广大研究人员检测Orchestration安全问题，并执行网络侦查、 枚举和指纹识别等操作。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39s4z3cEJnp7CqFDd180p83cfP3yCSibAO0kkY4JDQTtyGeZkw9N9soKJYFWqeibceKtLJA9yI82pdw/640?wx_fmt=jpeg&from=appmsg "")  
  
   
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
