> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247486117&idx=1&sn=fbc693d7fdf51436d9222548a07b33e6

#  伊朗 APT35 黑客使用 AI 钓鱼攻击以色列科技专家  
龙猫  星尘安全   2025-06-27 02:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/qTcIBaTRMWdjcGWCVUAKtpd05lBUJo0eJ4bg9ujlbhoFeMUcSBFia6tzfs0GPK3RRcLC8vysusEFvqicJ0VGicMtA/640 "")  
  
点击上方  
蓝字  
关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibV6vqVQpnKD9eLpCQAf69UFrxu8NdzsuFfBDKuKia0X9xJm2mFicP6xnfvpUSafPWB448zx1apYe9Tt76TgsJ12Q/640 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JmssGpneVHK2aNAIsS7yQ1icFsQMnHqJhsY5gGWBhGwlDF4mVgbdT6WG0ialZ1GdFOYblVeBCAQzTQhYbBFS7Wog/640 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vg2iaFhjMPt6AgOazbA1mP0RSD3zjTFfRPfjlUNTC5uwVMc1f6SZG3rR6RTEemOYPbmPiadyTBtquA/640?wx_fmt=png&from=appmsg "")  
  
6 月 26 日消息，Check Point 周三发布的一份报告显示，与伊朗伊斯兰革命卫队（IRGC）有关联的一个伊朗国家支持的黑客组织，发起了一场鱼叉式网络钓鱼活动，目标直指以色列的记者、知名网络安全专家和计算机科学教授。  
  
在部分活动中，攻击者通过电子邮件和 WhatsApp 消息，伪装成科技高管或研究人员的虚构助理，与以色列的技术和网络安全专业人士接触，并将与之互动的受害者引导至伪造的 Gmail 登录页面或 Google Meet 邀请页面。  
  
这家网络安全公司将此次活动归因于一个被其追踪为 “Educated Manticore” 的威胁集群，该集群与 APT35（及其子集群 APT42）、CALANQUE、Charming Kitten 等多个组织存在重叠。  
  
这个高级持续性威胁（APT）组织长期以来一直有通过精心设计的诱饵策划社会工程攻击的历史，他们会在 Facebook 和 LinkedIn 等各种平台上使用虚构的人物角色接近目标，诱使受害者在其系统上部署恶意软件。  
  
Check Point 表示，在 2025 年 6 月中旬伊朗与以色列爆发战争后，观察到了新一轮的攻击。此次攻击针对以色列个人，使用了虚假的会议诱饵，通过电子邮件或 WhatsApp 消息发送，且这些消息专门针对目标定制。由于这些消息布局结构化且没有任何语法错误，据信是使用人工智能（AI）工具制作的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vg2iaFhjMPt6AgOazbA1mP0m6lLQoPuDu0dnaH8lsOib8f65BUhg5B1hvUWVVexyQDQV4AcZRzLiceQ/640?wx_fmt=png&from=appmsg "")  
  
该公司标记的一条 WhatsApp 消息，利用两国当前的地缘政治紧张局势，诱使受害者参加会议，声称需要他们立即协助一个基于人工智能的威胁检测系统，以应对自 6 月 12 日以来针对以色列的网络攻击激增。  
  
正如在之前的 Charming Kitten 活动中所观察到的，初始消息中没有任何恶意内容，主要目的是获取目标的信任。一旦威胁行为者在对话过程中与目标建立了融洽的关系，攻击就会进入下一阶段，他们会分享链接，将受害者引导至能够获取其 Google 账户凭据的虚假登录页面。  
  
Check Point 称：“在发送网络钓鱼链接之前，威胁行为者会询问受害者的电子邮件地址，然后该地址会预先填写在 credential 网络钓鱼页面上，以增加可信度，并模仿合法的 Google 身份验证流程。”  
  
这款定制的网络钓鱼工具包通过 React 单页应用程序（SPA）和动态页面路由等现代网络技术，紧密模仿谷歌等人们熟悉的登录页面，还利用实时 WebSocket 连接发送窃取的数据，其设计能够隐藏代码，避免被进一步审查。  
  
这个虚假页面是一个定制网络钓鱼工具包的一部分，该工具包不仅可以捕获受害者的凭据，还可以捕获双因素身份验证（2FA）代码，从而有效实施 2FA 中继攻击。该工具包还集成了一个被动键盘记录器，用于记录受害者输入的所有击键，并在用户中途放弃该过程时将其泄露。  
  
部分社会工程工作还涉及使用谷歌网站域名来托管虚假的 Google Meet 页面，页面上有一张模仿合法会议页面的图片，点击图片上的任何位置都会将受害者引导至触发身份验证过程的网络钓鱼页面。  
  
Check Point 表示：“在伊朗与以色列冲突升级阶段，Educated Manticore 继续构成持续且高影响的威胁，尤其是对以色列境内的个人。”“该组织继续稳步运作，其特点是积极的鱼叉式网络钓鱼、快速设置域名、子域名和基础设施，以及在被识别后迅速拆除。这种敏捷性使其在高度审查下仍能保持有效性。”  
  
[从印巴网络战看基础设施安全：数字时代的 “电力绞杀”](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247486016&idx=1&sn=8c3bbb22d60f9a2bbb032b90781d4fec&scene=21#wechat_redirect)  
  
  
2025-05-12  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247486016&idx=1&sn=8c3bbb22d60f9a2bbb032b90781d4fec&scene=21#wechat_redirect)  
  
  
[“匿名者”发布 10TB 针对俄罗斯的泄露数据](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485995&idx=1&sn=c6ba5ca777702d9f4a389a0730b8afeb&scene=21#wechat_redirect)  
  
  
2025-04-26  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485995&idx=1&sn=c6ba5ca777702d9f4a389a0730b8afeb&scene=21#wechat_redirect)  
  
  
[亚东会遭美国黑客攻击，供应链安全为何如此重要](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485968&idx=1&sn=1ae07374cfe28fd4375d4fee539fdc6e&scene=21#wechat_redirect)  
  
  
2025-04-17  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485968&idx=1&sn=1ae07374cfe28fd4375d4fee539fdc6e&scene=21#wechat_redirect)  
  
  
[朝鲜 Lazarus 黑客通过 npm 包感染了数百人](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485824&idx=1&sn=8fc555539372337bcca7c69d9dd0dd0e&scene=21#wechat_redirect)  
  
  
2025-03-17  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485824&idx=1&sn=8fc555539372337bcca7c69d9dd0dd0e&scene=21#wechat_redirect)  
  
  
**喜欢此文的话，可以点赞、转发、在看 一键三连哦！**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vglcuxSMkmalibicmpOSAop2ebtW81WD17lIoywzweqOrtD2C7MiaU003Cdo8F8ZpWTqvY50VeDja9w/640?wx_fmt=png&from=appmsg "")  
  
  
  
