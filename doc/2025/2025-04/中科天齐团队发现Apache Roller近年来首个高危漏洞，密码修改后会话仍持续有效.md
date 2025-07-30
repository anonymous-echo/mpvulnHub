#  中科天齐团队发现Apache Roller近年来首个高危漏洞，密码修改后会话仍持续有效   
 中科天齐软件安全中心   2025-04-17 10:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjIaDIAWia1PiajlSagQEJppDOKvagt96Klv6pqePrnJ40RBsEMsagaf6w/640?wx_fmt=png&from=appmsg "")  
  
  
点击  
**蓝字**  
  
关注**中****科天齐**  
  
  
中科天齐安全研究团队在Apache Roller开源博客平台发现一个重大高危漏洞，该漏洞可能允许恶意行为者在更改密码后保留未经授权的访问。中科天齐团队在发现漏洞后及时上报给Apache Roller项目维护团队，目前漏洞已被修复，团队成员孟海宁因发现并报告此漏洞获得致谢。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjoHPduvmc9p8dI9T4n57zv9bV8NRuq7AibI8rpqmrQH8gibI9Jia3hbiaZg/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞一经发现便迅速引发了国际网络安全领域媒体的广泛关注与热议。鉴于其潜在风险，我们郑重提醒广大用户，请务必高度重视并及时进行产品升级修复。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUj2Zeytc1RCBuhKUg1LibwFI3eZGsGlYHMOKmlFApUTicWtiaKhVIwOvAQw/640?wx_fmt=png&from=appmsg "")  
  
  
Apache Roller 是一个多用户博客平台，可以支持数千个博客和用户。它为群组博客提供对主题和模板、内容管理系统、集成搜索和三个权限级别(所有者、编辑者和起草者)的支持。  
  
  
**关于漏洞 CVE-2025-24859**  
  
  
该漏洞编号为 CVE-2025-24859，CVSS评分为最高危险等级的10.0，是 Apache Roller 近年来出现的第一个严重性漏洞。  
  
  
该漏洞与会话过期时间不足有关，当系统或应用程序在更改密码后无法使现有用户的活动会话失效时，就会出现此漏洞。  
  
  
攻击者可以利用此类会话管理漏洞以多种方式获利。例如，攻击者如果之前通过会话劫持攻击等手段获得了用户会话的访问权限，即使受害者更改了密码，他们仍然可以保持这种未经授权的访问。因为密码更改无效，他们将能够维持对受影响系统的持久性。  
  
  
**受影响版本**  
  
  
Roller 6.1.4 之前的所有版本。  
  
  
**修复方案**  
  
  
Apache Roller开源博客平台开发团队已在 6.1.5 版本中修复该漏洞，通过实施集中式会话管理机制，确保密码修改或用户禁用操作会使所有活动会话立即失效。  
  
  
**关于中科天齐**  
  
  
北京中科天齐信息技术有限公司由李炼博士于2018年创立。公司安全研究团队专注于程序分析与软件安全领域的前沿研究和产品开发。截至目前，团队已为开源社区发现并报告了数百个严重缺陷，并获得了100多个CVE编号。公司旗下的中科天齐软件源代码安全缺陷检测平台，能够高效检测软件源代码中的运行时缺陷、安全漏洞以及编码标准规范问题。该平台凭借其卓越的性能和精准的检测能力，已广泛应用于IT企业、政府机关、军工企业以及科研院所等多个领域，为软件安全保驾护航。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjBc7VNGibacCHdoGPlxJsYs8bZXEKtZPictOREMEQJMGD8RZqDNmp4L6g/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjTWL74MsARNJg1eOGPmr27ibzFwdAa8BoA84icBV1BKJiaG15piaRmzib51Q/640?wx_fmt=png&from=appmsg "")  
  
**往期阅读**  
  
****  
[大语言模型权限泛滥：自主性失控带来的安全风险](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496443&idx=1&sn=6495f96159957ab2fb1bef9e9f4918ba&scene=21#wechat_redirect)  
  
  
  
[Ubuntu安全限制遭突破：攻击者可利用内核漏洞提权](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496416&idx=1&sn=7294f581f4e0ae0bbae738b97f3a2b32&scene=21#wechat_redirect)  
  
  
  
[AI在社交媒体领域中的数据投毒攻击与偏差问题](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496392&idx=1&sn=2c453c0ff4c6b7a73f2adc32c7f63864&scene=21#wechat_redirect)  
  
  
  
[2025年十大最佳DevOps工具推荐](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496298&idx=1&sn=200e635e43d6b6c340e6881a6ba425ff&scene=21#wechat_redirect)  
  
  
  
[OWASP发布2025十大智能合约安全漏洞](https://mp.weixin.qq.com/s?__biz=MzU5Njc4NjM3NA==&mid=2247496231&idx=1&sn=144e76f1d7add444a1f7e0c82a0ce9a8&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjIaDIAWia1PiajlSagQEJppDOKvagt96Klv6pqePrnJ40RBsEMsagaf6w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjvcicpEt9Yxfpo4Y7zoUlCp9ly7OefwBJ0Rb0j7ghiad17ZjHmibiak3j6g/640?wx_fmt=png&from=appmsg "")  
  
软件源代码安全缺陷检测平台  
  
  
**软件安全 网络安全的最后一道防线**  
  
中科天齐公司由李炼博士创立  
  
以“中科天齐软件源代码安全缺陷检测平台  
  
（WuKong悟空）”为主打产品  
  
致力打造安全漏洞治理领域新生态的  
  
高新技术企业  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjqmIb5Xhn6iaC7nMvuTAyGfpq3wcNz6niaVtJGNnYMvxSM0J9gd1vibAfA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjuCh7vw2pryLVcSCeh7tYf7qFAxvWhuxMpql1ayibWwmWH9ZkC4ltBicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjqmIb5Xhn6iaC7nMvuTAyGfpq3wcNz6niaVtJGNnYMvxSM0J9gd1vibAfA/640?wx_fmt=png&from=appmsg "")  
  
**长按二维码关注我们**  
  
  
**联系方式：400-636-0101**  
  
**网址：**  
**www.woocoom.com**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjhD97GNaSx5Dgu80TicyMtohjvQWJPUuGemRjjI9X3zeLxwTwh6BCn0g/640?wx_fmt=png&from=appmsg "")  
  
  
  
点击在看  
  
分享给小伙伴  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Xx53Lt2eIAlIMicveBP7iaDYhib1iaOY3UUjibPjicqSq6UyOrnpGicXn4YYVJqZ0PIKM2DjL6BMqWQicyZ496CkbbA3bA/640?wx_fmt=gif&from=appmsg "")  
  
点击  
**阅读原文**  
，获得免费预约地址  
  
