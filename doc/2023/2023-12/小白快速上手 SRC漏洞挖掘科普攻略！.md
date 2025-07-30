#  小白快速上手 SRC漏洞挖掘科普攻略！   
原创 白猫不黑  网络安全自修室   2023-12-16 09:27  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lFubSBSogFqgicIHO1h77GiafPiaUPNMaqGFbhlVt4xgfibicIs2HQl7fUgltjzDdMtOWLmXcfiaticRwYHA4qohl55xA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/B2EfAOZfS1j0P2KhxNF226xt1M5SKuS7QzH64vfmiaqnJhbmgxWLlxDRYgE1SXmgvZ9F0wgFmibBHsIJgR9DX0ibndoby6FWbK3/640?wx_fmt=svg "")  
  
点击上方  
蓝字关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/I1YzhXxW8YCmS3UnN2FuDSNMViapCreWzUpaL8YgOTzLHsLIYzEicsNaJxrXpegibgFtSZHaros5M4C9NkMOFh7aiaEtbQoQibiaqH/640?wx_fmt=svg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lFubSBSogFqgicIHO1h77GiafPiaUPNMaqGFbhlVt4xgfibicIs2HQl7fUgltjzDdMtOWLmXcfiaticRwYHA4qohl55xA/640?wx_fmt=png "")  
  
  
1  
  
  
免责声明  
  
        
本公众号提供的工具、教程、学习路线、精品文章均为原创或互联网收集，旨在提高网络安全技术水平为目的，只做技术研究，  
谨  
遵守国家相关法律法规，请勿用于违法用途，  
如果您对文章内容有疑问，可以尝试加入交流群讨论或留言私信，如有侵权请联系小编处理。  
  
  
  
2  
  
  
内容速览  
  
  
### 前言  
  
随着网络安全的快速发展，黑客攻击的手段也越来越多样化，因此SRC漏洞挖掘作为一种新的网络安全技术，也在不断发展和完善。那么，作为一个网安小白如果想要入门SRC漏洞挖掘，需要掌握哪些知识呢？以下是本人通过多年从事网络安全工作的经验，综合网络上已有的资料，总结得出的指导SRC漏洞挖掘入门的详细介绍。  
### 一、SRC漏洞提交平台介绍  
#### 1、Bugcrowd  
  
Bugcrowd是一个专门为企业提供漏洞检测、漏洞挖掘、漏洞修复、防御安全相关服务的平台，为各大知名企业提供安全检测服务。其平台上拥有众多的专业安全研究人员，能够提供高水平的检测漏洞以及挖掘各种安全漏洞、备受业内人士的好评。  
#### 2、HackerOne  
  
HackerOne是一家提供漏洞悬赏计划(Vulnerability Reward Programs，简称VRP)的互联网公司，为全球知名企业提供漏洞检测服务。其平台也拥有大量安全研究人员，覆盖面广，支持多种开发语言、操作系统等技术，可以为企业提供多元化的安全检测方案。  
#### 3、Open Bug Bounty  
  
Open Bug Bounty 是一个公益性质的SRC平台，旨在为全球网站提供独立的漏洞检测服务。开发者与安全研究人员通过此平台可以自由交流、共同合作，为广大网民提供更稳定、更安全的网络环境。  
### 二、SRC漏洞挖掘的流程  
#### 1、了解漏洞类型  
  
在开始SRC漏洞挖掘前，首先需要掌握常见的漏洞类型，包括XSS漏洞、SQL注入漏洞、文件上传漏洞、逻辑漏洞等等。  
#### 2、挑选目标  
  
选择目标网站是SRC漏洞挖掘的重要一步，通常要考虑以下几个因素：  
- 网站的流量：挑选一些流量较大的网站，可能有更多的漏洞。  
  
- 网站的重要性：重要的网站可能会有更严格的安全措施，需要更多的技巧去挖掘漏洞。  
  
- 网站的开发语言和技术：根据网站的开发语言和技术，选择适合的工具进行扫描，提高检测漏洞的准确性。  
  
#### 3、使用工具扫描漏洞  
  
首先需要使用一些专业的漏洞扫描工具，例如Burp Suite、Nessus、Acunetix等。这些工具可以通过自动扫描和漏洞库等方式快的识别并报告常见的漏洞类型，但是仅靠工具扫描是不够的，仍需要手动挖掘漏洞。  
#### 4、手动挖掘漏洞  
  
手动挖掘漏洞是SRC漏洞挖掘中的重要环节，它可以深入到网站代码层面，探测出漏洞，提高SRC漏洞挖掘的效率和准确性。此时需要掌握一些编程和网络知识，如HTML、CSS、JavaScript、SQL等。  
#### 5、编写报告并提交  
  
当确认了漏洞后，需要将所发现的漏洞及其漏洞利用方法写成报告进行提交。包括漏洞的类型、漏洞的等级、漏洞的影响程度、以及漏洞的验证方式等信息。在提交时需要注意保护漏洞信息的安全性，不应该将漏洞具体细节和漏洞利用手法公开。  
### 三、需要具备的知识  
#### 1、编程语言  
  
了解至少一门编程语言是必要的，主要包括HTML、CSS、JavaScript和SQL等，在SRC漏洞挖掘中也需要掌握Python、Ruby、Perl等脚本语言，以及C、C++等低级语言。  
#### 2、网络知识  
  
需要掌握TCP/IP网络协议，了解HTTP、HTTPS、FTP等协议的工作原理，对网络封包格式有基本的认识。  
#### 3、数据库知识  
  
需要熟悉SQL语言，掌握数据库的基本概念和操作，了解常见的数据库管理系统。  
#### 4、操作系统  
  
需要对Linux、Windows等操作系统有基本的了解，熟练掌握常用的命令行工具和脚本语言。  
#### 5、工具使用  
  
需要掌握常见的SRC工具和漏洞扫描器，如Burp Suite、Nessus、Acunetix等，并了解它们的工作原理和使用方法。  
#### 6、安全知识  
  
需要了解基本的安全知识，如密码学、身份认证和授权、漏洞挖掘、安全加固等。  
### 四、注意事项  
#### 1、遵守法律  
  
SRC漏洞挖掘需要遵守法律规定，避免侵犯网站安全和用户隐私，同时需要遵循公司或组织的安全政策。  
#### 2、主动报告漏洞  
  
如果在SRC漏洞挖掘中发现了漏洞，应该主动报告给网站管理员或漏洞报告平台，以保护用户和网站的安全。  
#### 3、安全保密  
  
在进行SRC漏洞挖掘时需要注意保护漏洞信息和利用手法的安全性，不应该泄露给未经授权的人员。  
#### 4、持续学习  
  
SRC漏洞挖掘是一项不断学习和提高技能的过程，需要持续学习和积累经验，关注新的安全漏洞  
  
攻击技术  
#### 5、合理规划时间  
  
SRC漏洞挖掘需要一定的时间和精力，需要合理规划时间和任务，避免过于疲劳影响挖掘效果。  
#### 6、沟通交流  
  
在SRC漏洞挖掘中需要与团队成员和网站管理员进行沟通交流，及时解决问题并提供建 掌握利用漏洞的技巧在发现漏洞后需要掌握如何利用漏洞，从而验证漏洞的存在，及时提供修复建议。  
#### 总结  
  
SRC漏洞挖掘是一项需要技能和经验的工作，需要不断学习和提高，同时也需要遵守相关法律法规和道德准则，保护网站安全和用户隐私。  
  
由于篇幅有限就写到这里了，我整理好了一些SRC挖掘的资料，有需要的可以拉到文章底部获取口令~  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CJmsUqkbd34uF0Fb5a5T2MGMdQbmKxXqqfrLcy38jlON3gAJKkP3Fp2NslHFx1Zp2XotZm65ADmO766b1Sl8eQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CJmsUqkbd34uF0Fb5a5T2MGMdQbmKxXqxqPh4Viazo5EwNAdCSlOxqQ5QRT3ffJELC8lEGV9zMLiaibYHC4KxyQlA/640?wx_fmt=png&from=appmsg "")  
  
  
3  
  
  
获取方式  
  
资源获取  
  
  
关注公众号，回复如下消息获取  
  
口令：SRC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MiboTSicicER4Eu7bB0t77eQS4XrwHJicY59XmxRFM03aTILrkecux30UkrUeSkUiajAiaezO5OyxJ7l3CQiaQtDgMuxg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CJmsUqkbd36pMnUu9lMvf40F3JN5FUKOSrpHCAw9seVEGicB71ibdv5ibQYGjJhm9jjwsQicqpudhktuEib9nJwuRAg/640?wx_fmt=png "")  
  
  
如果想要系统学习网络安全技术  
  
不妨加入知识星球课程**《60天入门网络安全渗透测试》**  
  
从入门到案例，贴合实战  
  
轻松易懂、好玩实用  
  
限时领取  
  
[超值 | 一起学网络安全! 授人以鱼不如授人以渔!](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247496309&idx=1&sn=14e7e4ef7429582856b49a7a7f8dded9&chksm=e959a45ade2e2d4ccfaf1f149e46fc0f31822497baafaae90bcbedf3aff7d28271449a314126&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NuIcic2jibgNJzwoZYCo6ThfOoeX410mwuDxnOnv5za18VZJ7ib30pic2NSNnicziaONicvs1C9yMDr6zV40ADD9yPP7Q/640?wx_fmt=gif "")  
  
**知识星球**  
优惠券****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CJmsUqkbd355catpIf6ReSQESRT676k6HXVsCSeSb7nhHmrAQN45U3bVUpiaNZTmhBP3ibDqFVdogwR6rQ730SoA/640?wx_fmt=png "")  
  
  
跟着[60天路线（点我查看）](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247485451&idx=1&sn=5bc1f942ce151ba3bfc623dd2dd9c7d8&chksm=e95a5e24de2dd732f9b03547ebe7b7e5860c1fe5bfc0696e477bfdefbdb07db8d5baf830421f&scene=21#wechat_redirect)  
  
一起学  
  
期待你的到来！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaYxOy5X8RGxPAZqiaRBGicib19NaYicn41YO87QVc5QTGjGS7CtO8ibNmedthqbBFX4Kfd0XKC5tObg07A/640?wx_fmt=png "")  
  
  
往期推荐  
  
  
  
[从入门到入狱的技术，可以学，别乱用！](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247485451&idx=1&sn=5bc1f942ce151ba3bfc623dd2dd9c7d8&chksm=e95a5e24de2dd732f9b03547ebe7b7e5860c1fe5bfc0696e477bfdefbdb07db8d5baf830421f&scene=21#wechat_redirect)  
  
  
[网络安全学习方向和资源整理（建议收藏）](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486161&idx=1&sn=a59ad5f5ea0d8d4a73c5d56c49240ef7&chksm=e95a5cfede2dd5e835df2a06dadf1ea764ad17c896bd7e36a7ce4db543162ff436c6e7e8818d&scene=21#wechat_redirect)  
  
  
[一个web安全工程师的基础学习规划](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486067&idx=1&sn=7fc31c310c8990eff8507cd9ef8f57b8&chksm=e95a5c5cde2dd54a8ea5836fb918a2e75920b9d49427bbf0ba6e7d1551cbf854f1c758999701&scene=21#wechat_redirect)  
  
  
[资源 | 渗透测试工程师入门教程（限时领取）](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247485910&idx=1&sn=bc4011a1dbae5a578e778f225c6396cd&chksm=e95a5ff9de2dd6ef2c9f2b7aaf8cc27d4b01b49d52134edc34985e8068c3f5b91d130217309f&scene=21#wechat_redirect)  
  
  
[5年老鸟推荐10个玩Python必备的网站](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486066&idx=1&sn=ebebc764ff820a9ad39ca3bc76315627&chksm=e95a5c5dde2dd54bb8dca6f0c156d6dc27c86963b5d4021fc120b143e97f6087c800b8965796&scene=21#wechat_redirect)  
  
  
[推荐十个成为网络安全渗透测试大佬的学习必备网站！](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486441&idx=1&sn=ef05f9f88c27f38bc95338f6c6739d0f&chksm=e95a5dc6de2dd4d084fa141bd69c3ad173b565cd78ac3d4fcad2bc491b7722a6af0653fd3650&scene=21#wechat_redirect)  
  
  
[那些社工师不为人知的秘密。。。](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486187&idx=1&sn=ea79686a707d97c8e97ac131441bf6b5&chksm=e95a5cc4de2dd5d2b06da67a6c9a85c303265eaf8e83e78a6c28fcbc07c587c161693554ed18&scene=21#wechat_redirect)  
  
  
  
  
更多内容请关注公众号  
  
网络安全自修室  
  
▼  
  
回复:”  
网络安全入门教程  
“,领取系统网络安全学习教程!  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CJmsUqkbd36pMnUu9lMvf40F3JN5FUKOVgHppMwndKpVt9cicTibZIX4kd1MIhlE3hibJ8icfW3gibPnWKj5LL2TjEw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pzXcQtZJNFv2HrgJ7ZwMzgeB9QByfWTxydpkuOicXKlUjZp9HpFFlT50ibBdIicCSmkW2ibibJpb1M1d5aRe9MfcXbA/640?wx_fmt=png "")  
  
点个  
在看你最好看  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/sTJptKvBQLK8kA6B8BvyhLBiaicqchp7g1uS8Rv3VRyH7IOz0icMV5eoM23cyJWbicIaSjaxhABIbHvRp2736iaFcmicTq9GXganwC/640?wx_fmt=svg "")  
  
  
  
