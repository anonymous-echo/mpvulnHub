#  FreeBuf周报 | 谷歌AI大模型首次找到0Day漏洞；诺基亚被黑客攻击泄露大量数据   
Zicheng  FreeBuf   2024-11-09 14:53  
  
##   
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、安全事件、一周好文和省心工具，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icTXNCEg8couP3xtiaM6M1GWvhxMibyeht89FjiaoEiakoAaice9A75J8xN8GFKS2eJJxWge00EjS6BKqw/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**热点资讯**  
  
  
### 1. 重大突破，谷歌AI大模型首次找到0Day漏洞  
  
谷歌公司日前表示，旗下一款名为“Big Sleep”（前称 Project Naptime）的大语言模型（LLM）辅助框架在 SQLite 开源数据库引擎中发现了一个零日漏洞，并称这是该类型AI工具首次在实际广泛使用的软件中发现零日漏洞。  
###   
### 2. 谷歌云将在2025年底强制实施多因素身份验证  
  
谷歌公司日前宣布，在2025年底前，将对所有谷歌云帐户将强制进行多因素身份验证 （MFA），以增强账户安全性。  
###   
### 3. 黑客可以随意访问EA公司7亿用户账号  
  
游戏开发人员兼白帽 Sean Kahler 发现了一个影响 Electronic Arts （EA） 帐户系统的漏洞，可以在未经授权的情况下访问任何EA用户帐户（目前EA用户有大约7亿），包括游戏统计数据。  
###   
### 4. 乌克兰人遇到 GPS 欺骗：手机显示错误的位置和时间  
  
在过去的几天里，乌克兰用户一直在社交媒体上分享他们地图位置的屏幕截图，显示他们在俄罗斯领土内。据《基辅独立报》报道，一些用户的智能手机也开始出现时间会不正确变化的情况。  
###   
### 5. Ollama AI模型发现六大漏洞，能导致DoS攻击、模型中毒  
  
网络安全研究人员披露了 Ollama 人工智能模型中的六个安全漏洞，攻击者可能会利用这些漏洞执行各种操作。  
##   
  
**安全事件**  
  
###   
### 1. 诺基亚被黑客攻击，泄露大量内部敏感数据  
  
跨国电信巨头诺基亚正在调查一起数据泄露事件，有黑客声称获得了该公司及某第三方承包商公司的内部敏感数据。  
###   
### 2. 利用ZIP串联文件策略，攻击者对Windows用户传播恶意软件  
  
网络犯罪分子正在利用一种被称为 ZIP 串联文件的复杂规避策略来专门针对 Windows 用户。此方法将多个 ZIP 文件合并到一个存档中，使安全软件更难检测恶意内容。  
###   
### 3. 微软SharePoint RCE漏洞，安装火绒杀毒后导致安全防护崩溃  
  
微软SharePoint存在远程代码执行（RCE）漏洞，漏洞编号CVE-2024-38094（CVSS评分：7.2） ，并且正在被黑客利用，以此获取对企业系统的初始访问权限。  
###   
### 4. 近100万台存在高危漏洞的 Fortinet、SonicWall设备正暴露在公开网络中  
  
根据 Cyble 最新发布的漏洞报告，有近100 万台存在被积极利用漏洞的 Fortinet 和 SonicWall 设备正暴露在公开的互联网上。  
###   
### 5. 黑客300美元出售重大安全研究项目的访问权  
  
泄露论坛监测发现，名为Engineer（工程师）的黑客11月5日发帖称，以300美元出售Rapid7的Project Sonar项目中合作伙伴的访问账户。  
##   
  
**一周好文共读**  
  
  
## 1. CORS跨域资源共享漏洞 | 一次崎岖的学习记录  
  
同源策略（Same-Origin Policy）是浏览器的一种安全机制，用于限制一个源（域名、协议或端口号的组合）的文档或脚本如何与来自另一个源的资源进行交互。具体来说，同源策略阻止不同源之间的网页通过脚本访问对方的资源或执行恶意操作，这有助于保护用户数据安全和隐私。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icTXNCEg8couP3xtiaM6M1GW3v0bqEVRqOwYsiapNdfVYzxURSaZyLz9cUvCibXNtcfAkiaiap4Loa63Rw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. Linux内核dirtyCOW漏洞分析  
  
dirtyCOW（编号CVE-2016-5195）是一个常用于Linux本地提权的漏洞，可以修改操作系统中的任意文件，包括系统存储的账户信息文件，影响的Linux内核版本在2.6.22 到 4.9.x之间。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icTXNCEg8couP3xtiaM6M1GW5xk9SuRbKm5BhwY4ovIOSeL8cnfmib0rh7ialaK1icg2dEQ6Yicw4iaskLQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 僵尸网络攻击手法与防范方式  
  
了解僵尸网络的攻击手法和防范方式对于保护个人、企业和互联网基础设施的安全至关重要。本文将详细探讨僵尸网络的攻击技术以及相应的防御策略。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icTXNCEg8couP3xtiaM6M1GWiaKqbFtSUQbG6PNadREywWId2ibE54iaMboQz1KcvicdB51j4uObJygqQQ/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**省心工具**  
  
  
##   
### 1. MSSprinkler：一款针对MS账号的密码喷射安全测试工具  
  
MSSprinkler是一款功能强大的密码喷射安全测试工具，可以帮助广大研究人员从外部角度测试其 Microsoft Online 帐户的安全性。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icTXNCEg8couP3xtiaM6M1GWpJeLQuWDcXibaT8FrWVdcpA95WiceIUanv6GzaibefAY4NB9qiaDc68A0g/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. Fierce：一款针对非连续IP空间的DNS网络安全侦查工具  
  
Fierce是一款针对DNS的网络安全侦查工具，该工具可以帮助广大研究人员轻松针对非连续IP空间的DNS执行网络安全侦查任务。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icTXNCEg8couP3xtiaM6M1GWIp25DjoYMAJWytx9ESSibvyAdpGnbMBSYfS4HZw6HBSHubtnicEpfgtA/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. IPBan：一款用于拦截威胁行为的网络安全防护工具  
  
IPBan是一款功能强大的网络安全防护工具，可以帮助广大用户拦截网络威胁行为或僵尸网络。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icTXNCEg8couP3xtiaM6M1GWxbs2BOsts5xbUeQcx0WxA5AzxoSxXQicyO9yOoqf804vzLCuiaJrCBrQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
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
  
