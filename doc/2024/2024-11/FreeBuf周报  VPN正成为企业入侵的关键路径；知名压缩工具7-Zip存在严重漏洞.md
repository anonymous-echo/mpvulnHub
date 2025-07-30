#  FreeBuf周报 | VPN正成为企业入侵的关键路径；知名压缩工具7-Zip存在严重漏洞   
Alpha_h4ck  FreeBuf   2024-11-30 02:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、安全事件、一周好文和省心工具，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibdicpTBMAWrconxBghTAHVMMAM1PtjgQiakK1QMhVtGyIjgFJpqXrwd2aQcGk9eupP1BZvQct7wuicg/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**热点资讯**  
  
  
## 1. VPN正在成为企业入侵的关键路径  
  
研究人员发现了Palo Alto Networks（CVE-2024-5921）和SonicWall（CVE-2024-29014）企业VPN客户端更新过程中的漏洞，这些漏洞可能被利用来远程执行代码。  
###   
### 2. 估值 1548亿美元！网安AI市场将迎来爆炸性增长  
  
网络安全市场中的AI价值正在经历前所未有的增长。根据Allied的一份市场研究报告，2022年市场价值为192亿美元，预计到 2032 年将达到惊人的1548 亿美元，复合年增长率（ CAGR ）为23.6%。  
###   
### 3. 微软或窃取你的Word、Excel文件以训练人工智能模型？  
  
微软在其生产力套件中的Connected Experiences选项已经引起了人们的恐慌，有人指责默认设置可能会允许微软使用客户的Word和Excel文档及其他数据来训练AI模型。  
###   
### 4. 索赔800万元，字节跳动起诉篡改代码攻击模型的实习生  
  
字节跳动公司近日正式就前实习生田柯宇篡改代码并攻击公司内部模型训练一案向北京市海淀区人民法院提起诉讼，该案已被法院受理。字节跳动在诉讼中请求法院判令田柯宇赔偿公司侵权损失共计800万元人民币及合理支出2万元人民币，并要求其公开赔礼道歉，以维护公司的合法权益和声誉。  
###   
### 5. Fortinet VPN服务器设计缺陷能隐藏攻击者行踪  
  
网络安全厂商Fortinet产品中的VPN 服务器存在一个设计漏洞，其日志记录机制能够隐藏成功实施暴力攻击的行为记录，无法让防御者察觉到系统可能已被入侵。  
##   
  
**安全事件**  
  
###   
### 1. 知名压缩工具7-Zip存在严重漏洞  
  
近日，主流文件压缩工具7-Zip被曝存在一个严重的安全漏洞，允许远程攻击者通过精心制作的存档执行恶意代码。该漏洞编号为CVE-2024-11477，CVSS评分7.8分，表明受影响版本的用户面临重大安全风险。  
###   
### 2. 微软又全球宕机11小时，多项核心服务无法使用  
  
11月25日，微软的多项核心服务（包括 365、Exchange Online、Teams 和 Outlook）再次遭遇全球性的大规模中断，用户随后在社交媒体上报告了一系列问题，如无法发送邮件、网站崩溃及出现错误页面。  
###   
### 3. 星巴克遭供应链攻击，回到纸质办公时代  
  
近日，星巴克的关键供应链管理软件提供商 Blue Yonder 遭遇勒索软件攻击，虽此次事件并未影响客户服务或商店运营，但却迫使星巴克恢复使用手动流程来管理员工日程安排和工资系统。  
###   
### 4. Firefox和Tor浏览器遭遇神秘0Day漏洞攻击  
  
近日，俄罗斯某APT组织被发现利用两个以前未知的漏洞攻击Windows PC上的Firefox和Tor浏览器用户。安全厂商ESET指出，这些零日漏洞攻击可能造成“广泛传播”，主要针对欧洲和北美的用户。  
###   
### 5. 关键的WordPress插件漏洞导致超400万网站暴露  
  
一个关键的认证绕过了漏洞被暴露在了WordPress的Really Simple Security（以前称为Really Simple SSL）插件中，如果此漏洞被利用，攻击者可以远程获得易受攻击网站的完全管理权限。  
##   
  
**一周好文共读**  
  
  
## 1. 红队实战 | linux 进程注入详解和实例  
  
本文聚焦于“真正的进程注入”技术，即针对实时运行进程的注入方法，而非涉及修改磁盘上的二进制文件、利用特定环境变量或借助进程加载进程的方式。  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibdicpTBMAWrconxBghTAHVMDwPRtUibicFSMwsgwPGNadajrma8ZibPB7AzPEqUTpOicOia84dzWS1jPCA/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. 案例技术分享：失效的身份验证及其防范策略详解  
  
本文深入探讨失效身份验证的概念、影响、常见原因以及有效的防范措施，旨在为构建更安全的数字生态系统提供指导。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibdicpTBMAWrconxBghTAHVMecicDyia4LMsW0q7vTGrn1dQErF15ertqbJJeZKaHpLIPfp9SAblYpVg/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 安全审计案例：绕过Apache Superset限制执行SQL注入  
###   
  
本文详细介绍了在一次审计过程中发现的一个严重漏洞，以及如何利用这一漏洞绕过 Apache Superset 的安全措施，执行任意 SQL 查询。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibdicpTBMAWrconxBghTAHVMv1WbNN37qABh84g5rib4ANzCsqib7tSBGBqDAhHTSXpTObciaBwD7ic9Ng/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**省心工具**  
  
  
## 1. GraphQL Cop：一款针对GraphQL API的安全审计工具  
  
GraphQL Cop是一个小型 Python 实用程序，用于针对 GraphQL API 运行常见的安全测试。GraphQL Cop非常适合在 GraphQL 中运行 CI/CD 检查。   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibdicpTBMAWrconxBghTAHVMuicAox73dHIIvOo505BZxHt825IXibhPpo95dHULtq9ibDIstriatfXIoQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 2. Diskover：一款基于Elasticsearch的开源文件系统索引工具  
  
Diskover是一款由 Elasticsearch 提供支持的开源文件索引器、文件搜索引擎及数据管理和分析工具。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibdicpTBMAWrconxBghTAHVMGKbsTiciaqaLyRzk4V8IIicjRZtbEUiahLEjWksyHPORFUhTlo9tIFcyFQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 3. 如何使用Kubesec执行Kubernetes资源安全风险分析  
  
Kubesec是一款针对Kubernetes的安全工具，在该工具的帮助下，广大研究人员可以轻松执行Kubernetes资源安全风险分析任务。   
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibdicpTBMAWrconxBghTAHVMgvS44TQPeh6kvgyQFjicN3yiaicm9bNVdOuhzBWBB3fJFF9NFzrZTeZsg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
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
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651308240&idx=1&sn=96d32c8e6fa90561c84164ed75f4dca0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21&token=734903441&lang=zh_CN#wechat_redirect)  
  
  
