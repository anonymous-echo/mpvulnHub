#  Ballista僵尸网络利用TP-Link漏洞，6千台设备被攻击   
 数世咨询   2025-03-14 16:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Y9btpvDIDqoibqicg4ckpS2pxBmabDxricX4zUxPXrr7kQU50QmuTicFA9HcFia1Z0pf2hRW7D2PqRtK3AFbFF8G4AA/640?wx_fmt=png&from=appmsg "")  
  
  
未打补丁的 TP-Link Archer 路由器正成为一种名为 Ballista 的新型僵尸网络攻击的目标，这是 Cato CTRL 团队最新发现的。  
  
**01**  
**攻击原理与传播方式**  
  
安全研究人员 Ofek Vardi 和 Matan Mittelman 在一份技术报告中表示：“该僵尸网络利用 TP-Link Archer 路由器中的远程代码执行漏洞（CVE-2023-1389），通过互联网自动传播。”该漏洞属于高危安全问题，会影响 TP-Link Archer AX-21 路由器，可能引发命令注入，进而导致远程代码执行。  
  
早在 2023 年 4 月，就有人利用该漏洞投放 Mirai 僵尸网络恶意软件，此后，  
**该漏洞还被用于传播其他恶意软件家族，比如 Condi 和 AndroxGh0st。**Cato CTRL 在 2025 年 1 月 10 日发现了 Ballista 活动，最近一次的利用尝试发生在 2025 年 2 月 17 日。  
  
攻击过程包括使用恶意软件投放器，一个名为“dropbpb.sh”的 shell 脚本，该脚本会从网络上获取并为多种系统架构（如 mips、mipsel、armv5l、armv7l 和 x86_64）在目标系统上执行主二进制文件。恶意软件一旦执行，就会在 82 端口建立加密的命令与控制通道，从而控制设备。  
  
**02**  
**恶意软件功能与自我保护机制**  
  
研究人员指出：“这使得攻击者可以运行 shell 命令，进一步开展远程代码执行和拒绝服务攻击。此外，恶意软件还会尝试读取本地系统上的敏感文件。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Y9btpvDIDqoibqicg4ckpS2pxBmabDxricXuKy5Uk2AkEPticgKSWibQLWBI2X8s2eFMwNkZQxxI2lm3GxQNxYfZROA/640?wx_fmt=png&from=appmsg "")  
  
该恶意软件支持以下命令：  
- flooder：触发洪水攻击  
  
- exploiter：利用 CVE-2023-1389 漏洞  
  
- start：与 exploiter 一起使用的可选参数，用于启动模块  
  
- close：停止模块触发功能  
  
- shell：在本地系统上运行 Linux shell 命令  
  
- killall：用于终止服务  
  
此外，该恶意软件能够在执行开始后终止自身的先前实例并擦除自身痕迹，并且还设计用于通过尝试  
**利用该漏洞传播到其他路由器**。  
  
**03**  
**攻击者背景与影响范围**  
  
网络安全公司表示，C2 IP 地址的位置（2.237.57.70）以及恶意软件二进制文件中存在意大利语字符串，表明有未知的意大利威胁者参与其中。不过，该恶意软件似乎仍在积极开发中，因为该 IP 地址已不再有效，并且存在一种新的投放器变体，使用 TOR 网络域名而不是硬编码的 IP 地址。  
  
**在攻击面管理平台 Censys 上的搜索显示，超过 6000 台设备受到 Ballista 的攻击，易受攻击的设备主要集中在巴西、波兰、英国、保加利亚和土耳其。该僵尸网络已发现针对美国、澳大利亚、中国和墨西哥的制造业、医疗保健、服务业和技术组织。**  
  
研究人员表示：“虽然这个恶意软件样本与其他僵尸网络有相似之处，但它与广泛使用的 Mirai 和 Mozi 等僵尸网络仍有区别。”  
  
* 本文为闫志坤编译，https://thehackernews.com/2025/03/ballista-botnet-exploits-unpatched-tp.html注：图片均来源于网络，无法联系到版权持有者。如有侵权，请与后台联系，做删除处理。  
  
— 【 THE END 】—  
  
🎉 大家期盼很久的#  
**数字安全交流群**  
来了！快来加入我们的粉丝群吧！  
  
🎁 **多种报告，产业趋势、技术趋势**  
  
这里汇聚了行业内的精英，共同探讨最新产业趋势、技术趋势等热门话题。我们还有准备了专属福利，只为回馈最忠实的您！  
  
👉   
扫码立即加入，精彩不容错过！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Y9btpvDIDqqPJv9p5ibKIhJXQjWHJmSlibSdib80Llfp8mlV0ibf7m47jyaVeGoFeorddtIuxS5liafTJRKHeSdLnaQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
😄  
嘻嘻，我们群里见！  
  
  
更多推荐  
****  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247514213&idx=1&sn=fa2d0412dbbce05ec48a9df909b7cfd3&chksm=c144cad8f63343ce0f383fc9d885c2c7ddcb3f3871270abea4c274775307858d350f60db3b54&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247513339&idx=1&sn=759f859d0cf7dd748d3dd83ce49cf4cc&chksm=c144c646f6334f5017581206b0da2af90d539c921614514e3eb40f6c80d846bece0e6b521067&token=824343009&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247513359&idx=1&sn=2f3bd51b24862de02cca6078688bafeb&chksm=c144c7b2f6334ea415adac810ce4803cdb3cd5e5ba194ff394b7278ebbb48cc830c8d405427a&token=824343009&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247514185&idx=1&sn=8015c07a68a5e2b6074efd2c77f20085&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247514336&idx=1&sn=e69b1126e86ab2c59c8ca8e315637031&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247530968&idx=1&sn=3d712e23b322ad37cee46d27adb08ed0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247512642&idx=1&sn=019eaa76285fa13f997dd4b2f58d6d2d&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247515942&idx=1&sn=bc9ba104b8eb1c0e914d90c8c9a34542&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247532302&idx=1&sn=2c6afc5d39c89c86f79020099ea44baa&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247512372&idx=1&sn=5d06a830f00953a0ab75157fc023ae56&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247534345&idx=1&sn=56523a8457ad7bd50325c480026e9ab9&scene=21#wechat_redirect)  
  
  
  
