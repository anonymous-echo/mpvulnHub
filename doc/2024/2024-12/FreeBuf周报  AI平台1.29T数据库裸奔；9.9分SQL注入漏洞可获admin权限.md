#  FreeBuf周报 | AI平台1.29T数据库裸奔；9.9分SQL注入漏洞可获admin权限   
Zicheng  FreeBuf   2024-12-28 02:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、安全事件、一周好文和省心工具，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IqicgFIHIYgvmz1PsVMxCwn9ADX0icdrsgUDElIXGxBf5w7hJ0niaFEbic50Y0DmGaticAZSmH15YqmQ/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**热点资讯**  
  
  
## 1. 账号和密钥明文存储，AI平台1.29T数据库裸奔  
  
近日，网络安全研究员Jeremiah Fowler透露，一家总部位于英国伦敦的人工智能开发平台Builder.ai，由于数据库配置错误，该平台遭遇了重大数据泄露事件，共计泄露数据超过300万条，1.29TB。  
  
### 2. AI可一键生成上万种恶意软件变体，88%能规避检测  
  
网络安全研究人员发现，借助大型语言模型（LLMs），可以大规模生成新型恶意的JavaScript代码变体，这些变体将更难被安全防护设备检测。  
  
### 3. 特朗普政府2.0：网安政策重大转向，CISA收缩，减少监管  
  
随着CISA（网络安全和基础设施安全局）的变革、公私合作的加强以及放松管制的承诺，新政府可能会彻底改变美国联邦政府在网络安全领域的角色。  
  
### 4. Adobe最新漏洞被披露，已有PoC代码流出  
  
Adobe近期发布了紧急安全更新，针对ColdFusion中的一个关键漏洞，该漏洞已有概念验证（PoC）代码流出。根据周一的公告，这个编号为CVE-2024-53961的漏洞源于路径遍历弱点，影响了Adobe ColdFusion 2023和2021版本，攻击者可借此读取易受攻击服务器上的任意文件。  
  
### 5. 看不到的尽头，回顾与展望哈以冲突以来的中东网络战  
  
自 2023 年 10 月以来，以色列和哈马斯之间爆发的冲突助长了中东国家之间的网络攻击，并在全球范围内将多个国家卷入其中。  
  
  
**安全事件**  
  
  
### 1. 热门npm包被植入加密挖矿软件，感染目标涉及中国  
  
近日，安全研究人员调查后发现，臭名昭著的APT组织Earth Koshchei（也被称为APT29或Midnight Blizzard）与一项大规模非法远程桌面协议（RDP）的恶意活动相关。  
###   
### 2. 日本航空遭黑客攻击，大量航班延误  
  
当地时间12月26日7时30分左右，据日本航空公司消息，连接该公司内部与外部的网络设备遭遇网络攻击，导致与外部通信的系统出现故障。日本航空公司方面称，截至当天10时，受网络攻击影响，至少有9个日本国内航班出现延误，最长约1小时，预计影响范围可能会进一步扩大。  
###   
### 3. 欧洲航天局被黑客入侵，部署JavaScript代码  
  
欧洲航天局（ESA）的官方网络商店遭遇黑客入侵，加载用于生成虚假Stripe支付页面的JavaScript代码。  
###   
### 4. Windows Defender成黑客武器，可禁用EDR  
  
安全专家发现了一种复杂的攻击技术，能利用 Windows Defender 应用程序控制 (WDAC) 来禁用 Windows 设备上的端点检测和响应 (EDR) 传感器，攻击者可以此绕过安全检测对系统发动攻击。  
###   
### 5. 9.9分的SQL注入漏洞，可获admin权限  
  
Apache软件基金会（ASF）已发布安全更新，修复了Traffic Control中的一个关键安全漏洞。若此漏洞被成功利用，攻击者便能在数据库中执行任意结构化查询语言（SQL）命令。该SQL注入漏洞被标识为CVE-2024-45387，在CVSS评分系统中获得了9.9分（满分为10分）。  
##   
  
**一周好文共读**  
  
  
## 1. Windows应急响应实战技巧  
  
为了有效应对Windows系统可能遭遇的安全事件，Windows应急响应指南显得至关重要。本文旨在为安全从业者、系统管理员以及普通Windows用户提供应对紧急安全事件的基本思路和操作方法。遵循本指南的建议，可以在安全事件发生时迅速采取行动，最大限度地减少损失，恢复系统的正常运行，确保数据的安全性和完整性。    
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IqicgFIHIYgvmz1PsVMxCwMUuKerhxfKXAgI6bwWNoAHdweVicGAjxQo3C27uJSx1ZLs12aRzCKtg/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. 针对Nacos漏洞猎杀的各种骚姿势  
  
本文让读者能够从零基础的小白也可以上手打Nacos的nday  
。主要介绍了NacosExploitGUI  
自动化工具的使用，以及使用这个工具打nday的手法，以及要是批量漏洞url怎么扫描利用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IqicgFIHIYgvmz1PsVMxCwPOLeia8Fia1vibDVfy6ID1vqdSJribGc6JB1zbOaogBwDa7DqEwEQyZWMw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. Firefox Animation CVE-2024-9680 漏洞分析  
  
本文深入分析在 Firefox 131.0.2 中修复的漏洞CVE-2024-9680。这个漏洞被解读为动画时间线中的“use-after-free”问题，且据报道已经在实际攻击中被利用。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IqicgFIHIYgvmz1PsVMxCwiaCn7uEYlTl6hlx7VDgaTN1dnwcjE1gRsuiaibScf5tFiaQghHVWQPI4Jw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**省心工具**  
  
  
## 1. Clair：一款针对应用程序容器的安全漏洞静态分析工具  
  
Clair是一款针对应用程序容器的安全漏洞静态分析工具，该项目完全开源，可以帮助广大研究人员针对应用程序容器（包括OCI和Docker）执行安全漏洞静态分析。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IqicgFIHIYgvmz1PsVMxCw32tmAyNTEia5wyN87PrDicBOjiafYiaHj6pWRMonsQlOdkgKYRRFgXxxxw/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. HookCase：一款针对maxOS的逆向工程安全分析工具  
  
HookCase是一款针对maxOS的逆向工程安全分析工具，广大研究人员可以利用该工具在macOS上或对操作系统本身进行安全调试或执行逆向工程分析。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IqicgFIHIYgvmz1PsVMxCw9bGibne8vW2KWiaVfCn3U21L9iaYdjQb9TDVeUdnHx65sqGg4f1iaQWFVA/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 如何使用SkyScalpel在云环境中对JSON策略执行安全分析与处理  
  
SkyScalpel是一款功能强大开源框架，用于在云环境中解析、混淆、反混淆和检测 JSON 策略。它提供了灵活且高度可配置的机制来处理 JSON 级混淆、IAM 策略转换以及在云安全环境中检测规避混淆技术。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IqicgFIHIYgvmz1PsVMxCwePNmwXicoWfm56ibLLXzpSjA5S43FTaBRpYkMcJur3FO5HgOMdV8w4hQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
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
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
