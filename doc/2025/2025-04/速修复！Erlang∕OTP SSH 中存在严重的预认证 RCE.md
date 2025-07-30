#  速修复！Erlang/OTP SSH 中存在严重的预认证 RCE   
Lawrence Abrams  代码卫士   2025-04-18 09:49  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Erlang/OTP SSH 中存在一个严重漏洞CVE-2025-32433，可导致在未认证的远程代码执行 (RCE) 后果。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTWEibOWyGpxJTM5MvVAXwIN2Wz1icd0NcEH1ia7oictLQb6jMKF4maLVkfeWYHHAzlB6VGy6WnL972SQ/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞由德国波鸿鲁尔大学的研究人员发现，CVSS评分为满分10分。所有运行 Erlang/OTP SSH 守护进程的设备均受该漏洞影响，建议用户升级至25.3.2.10和26.2.4修复该漏洞。  
  
Erlang 是一种编程语言，以容错性和并发性见长，因此常用于电信基础设施和高可用性系统中。Erlang/OTP 是构建于 Erlang 之上的库、设计原则和工具的集合，为远程访问提供各种组件如 SSH 应用。  
  
CVE-2025-32433是因不正确地处理由 Erlang/OTP SSH应用提供的SSH守护进程中的某些预认证协议信息造成的。OpenWall 漏洞邮件列表披露称，“该漏洞由 SSH 协议消息处理中的一个缺陷引发，可导致攻击者在认证前发送连接协议消息。”  
  
通过该漏洞执行的任何命令都将与 SSH 守护进程同样的权限运行。在很多情况下，该守护进程以 root 身份运行，可导致攻击者完全攻陷系统。  
  
以利用研究见长的 Horizon3 攻击团队提醒称已经复现该漏洞并发现“令人惊讶地容易”，并展示了在受影响系统上以root身份写文件的 PoC。该团队提到，“刚完成对 CVE-2025-32433的复现并快速拼凑了一个 PoC 利用——简单得让人惊讶。如果PoC 马上出现也不会惊讶。如果你在跟踪这个漏洞，那么是时候采取行动了。”  
  
强烈建议组织机构立即升级至已修复版本，以免该漏洞遭大规模利用。对于系统如无法轻易更新的工业或任务关键设备，建议仅将SSH访问权限限制给可信IP地址或者在非必要的情况下关闭SSH守护进程。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[NPM恶意包利用SSH后门攻击开发人员的以太坊钱包](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521235&idx=2&sn=99c13237279fea36d94e88deab21dab3&scene=21#wechat_redirect)  
  
  
[Citrix 提醒管理员手动缓解 PuTTY SSH 客户端漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519453&idx=1&sn=b108366a369534bc2bc55f5a5089d587&scene=21#wechat_redirect)  
  
  
[CISA 提醒注意已遭活跃利用的 Juniper 预认证 RCE 利用链](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518122&idx=1&sn=d6b5a20e45ee8897ed249a7bdde21ebb&scene=21#wechat_redirect)  
  
  
[大企业都在用的开源 ForgeRock OpenAM 被曝预认证 RCE 0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506349&idx=2&sn=c1cd744877e475629005b1d5af227712&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/critical-erlang-otp-ssh-pre-aut  
h-rce-is-surprisingly-easy-to-exploit-patch-now/  
  
  
  
题图：  
Pixabay   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
