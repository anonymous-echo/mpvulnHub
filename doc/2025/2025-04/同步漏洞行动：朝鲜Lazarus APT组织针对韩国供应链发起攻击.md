#  同步漏洞行动：朝鲜Lazarus APT组织针对韩国供应链发起攻击   
 FreeBuf   2025-04-27 10:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
  
与朝鲜有关的Lazarus组织在一项名为"同步漏洞行动"（Operation SyncHole）的网络间谍活动中，针对至少六家韩国企业发起攻击。  
  
  
卡巴斯基研究人员报告称，这个朝鲜背景的APT（高级持续性威胁）组织自2024年11月以来持续活跃，采用水坑攻击手法并利用软件漏洞针对韩国机构。受害企业涉及IT、金融、半导体和电信等多个行业，实际受影响数量可能更多。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib4oBhlHX3hicZ9icoFsrj5kkLCkZ5EzPnNj7HlpGn1I4eQxQlq09pHsHw9EU7dFhwSdToBZuwUMCMQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**01**  
  
  
  
**攻击技术分析**  
  
  
攻击者利用Innorix Agent软件中的"一日漏洞"（one-day vulnerability）进行横向移动，这一发现已通报韩国互联网与安全局（KrCERT/CC）。攻击工具包括ThreatNeedle后门程序、Agamemnon下载器、wAgent、SIGNBT和COPPERHEDGE等多种恶意软件。  
  
  
卡巴斯基在报告中指出："首次感染发现于去年11月，当时我们检测到Lazarus组织的标志性恶意工具ThreatNeedle后门程序的变种，攻击目标是一家韩国软件公司。该恶意软件在合法的SyncHost.exe进程内存中运行，并作为韩国本土开发的Cross EX软件的子进程创建。这可能是后续五家韩国机构遭入侵的起点。"  
  
  
韩国许多政府和银行网站要求用户安装特定安全软件以实现反键盘记录和数字签名等功能。这些程序持续在后台运行，成为极具吸引力的攻击目标。Lazarus组织利用Cross EX等软件的漏洞，专门针对韩国行业实施水坑攻击。恶意软件注入过程源自Cross EX，并以高系统权限执行，表明存在权限提升行为。韩国国家网络安全中心早在2023年就针对此类风险发布过安全公告[1, 2]，并与英国合作发布联合警告。2024年11月至2025年2月期间发生的所有事件均涉及相同执行模式和版本的Cross EX软件，证实这是一次有组织、有针对性的攻击行动。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib4oBhlHX3hicZ9icoFsrj5kkZDmQ8zH59RdMg8O7I8bsib63vX0z7bAATrOuxBiblxEI39AC0OuMK6Fw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**02**  
  
  
  
**攻击阶段演变**  
  
  
"同步漏洞行动"分为两个阶段：初期使用ThreatNeedle和wAgent恶意软件，后期转向SIGNBT和COPPERHEDGE。研究人员发现，在首次攻击被检测并响应后，攻击者修改了战术，在后续更频繁的多目标攻击中部署了三套更新的恶意软件链。  
  
  
报告进一步说明："我们根据至少六家受害机构的情况，总结出四条不同的恶意软件执行链。首次感染案例中发现了ThreatNeedle变种，但在后续攻击中，SIGNBT取代了其位置，标志着第二阶段开始。我们认为这是由于我们对首个受害者的快速响应迫使攻击者改变策略。在后续攻击中，Lazarus组织引入了包含SIGNBT在内的三套更新感染链，攻击目标范围更广、频率更高。这表明该组织可能意识到精心准备的攻击已暴露，从而开始大规模利用漏洞。"  
  
  
**03**  
  
  
  
**技术细节剖析**  
  
  
第一阶段攻击使用更新版的ThreatNeedle、wAgent和Agamemnon恶意软件。ThreatNeedle被拆分为Loader和Core组件，采用ChaCha20+Curve25519高级加密和系统持久化技术。wAgent包含AES-128-CBC解密功能，并通过GMP库实现RSA加密。Agamemnon使用Tartarus-TpAllocInject等新型方法投递有效载荷。攻击者特别利用韩国本土软件Innorix Agent进行横向移动，将恶意软件伪装成合法服务植入系统。  
  
  
第二阶段引入SIGNBT 1.2和COPPERHEDGE。前者专注于通过加密C2（命令与控制）通信投递有效载荷，后者用于内部侦察。整个行动展示了Lazarus组织向模块化、隐蔽化及本地定制化恶意软件的转型趋势。  
  
  
**04**  
  
  
  
**持续威胁预警**  
  
  
报告总结指出："Lazarus组织针对韩国供应链的专业化攻击预计将持续。我们过去几年的研究证明，韩国许多软件开发供应商已遭攻击，如果产品源代码被窃，可能会持续发现新的零日漏洞。攻击者正通过开发新恶意软件或增强现有恶意软件来降低被检测风险，特别是在C2通信、命令结构和数据传输方式等方面进行了强化改进。"报告最后附有本次攻击活动的入侵指标（IoC）。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319086&idx=1&sn=e2ff862babd7662c4fa06b0e069c03f2&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319171&idx=2&sn=9ae825f6633d32e60f1f2474c29e4e20&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319257&idx=1&sn=a603c646a53e3a242a2e79faf4f06239&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
