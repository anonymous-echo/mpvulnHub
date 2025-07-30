#  英特尔CPU曝新漏洞：每秒偷走17KB数据！新型芯片漏洞有多可怕   
看雪学苑  看雪学苑   2025-05-16 09:59  
  
近日，来自瑞士苏黎世联邦理工学院（ETH Zürich）的研究团队曝出一个震撼业界的发现：所有现代英特尔处理器都存在一个名为"分支特权注入"（BPI）的新型漏洞。这就像给黑客们配了一把万能钥匙，能绕过层层防护，直接窃取电脑内存中的敏感数据。更令人不安的是，这已经是2018年"幽灵漏洞"（Spectre）事件后，英特尔芯片第七年持续暴露同类安全隐患。  
  
  
据研究团队负责人卡维赫·拉扎维教授介绍，这个漏洞的可怕之处在于它能让攻击者"偷听"处理器的内部对话。想象一下，当你在电脑上处理银行账户时，黑客可以通过这个漏洞，像窃听隔壁房间谈话一样，窃取你的密码和交易信息。即使电脑系统设置了不同用户权限，黑客也能通过操控芯片的"预判功能"，突破安全防线。  
  
  
该漏洞被命名为CVE-2024-45332（危险等级5.7分），其攻击原理类似于让两个人在同个电话线上抢着说话。当处理器在切换不同用户权限时，黑客可以制造"预测竞赛"，诱骗芯片错误执行指令，从而盗取其他用户的内存数据。就像魔术师用快手法欺骗观众眼睛，黑客利用芯片的运算速度漏洞实施盗窃。  
  
  
无独有偶，荷兰阿姆斯特丹自由大学的网络安全团队同期曝光了名为"Training Solo"的新型幽灵攻击。这种攻击手法能突破现有防护，让黑客在无需高级权限的情况下，以每秒17KB的速度窃取系统核心数据。相关漏洞涉及CVE-2024-28956和CVE-2025-24495两个编号，影响范围覆盖英特尔第9-11代酷睿处理器及至强服务器芯片。  
  
  
面对连环暴击，英特尔已紧急发布微代码补丁。但安全专家指出，修补这类芯片级漏洞就像给高速行驶的赛车换轮胎——既要保证系统稳定，又要彻底堵住漏洞，操作难度极高。更令人担忧的是，这些漏洞利用的是芯片设计本身的缺陷，单纯依靠软件更新难以根治。  
  
  
普通用户该如何应对？专家给出三点建议：1.立即更新系统补丁；2.避免在公共电脑处理敏感信息；3.使用虚拟机等隔离环境处理重要数据。虽然这些措施不能百分百防护，但能大幅提高攻击门槛。  
  
  
值得关注的是，AMD公司也更新了安全指南，特别警示经典数据包过滤器（cBPF）可能带来的风险。这预示着芯片安全问题已超越单个厂商，成为整个行业的技术挑战。就像汽车行业面临的安全召回，芯片制造商或将面临更严格的设计规范。  
  
  
这场持续七年的"芯片攻防战"揭示了一个残酷现实：在追求运算速度的竞赛中，安全防护往往沦为牺牲品。当我们的手机、电脑甚至智能家电都搭载着这些"带病"芯片，数字时代的信息安全防线正在经受前所未有的考验。  
  
  
  
  
资讯来源：  
thehackernews  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
