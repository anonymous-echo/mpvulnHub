#  勒索团伙利用 Mitel VoIP 0day 发动攻击   
Ravie Lakshmanan  代码卫士   2022-06-27 18:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTmYNShsd3uibqmj0oZxSWCVn1V3N9YcqgMqS74ict9yvb50icx95UcCNNGLJOdNicTUQ6HHLWiaQdticWw/640?wx_fmt=png "")  
  
网络安全公司 CrowdStrike 公司指出，可疑的勒索团伙利用 Mitel VoIP 设备中的0day 漏洞 (CVE-2022-29499) 作为入口点实现远程代码执行并获得对该环境的初始访问权限。  
  
  
  
研究员发现勒索攻击源自位于网络边界上 Mitel VoIP 设备，他们还发现一个0day (CVE-2022-29499） 的exploit 以及攻击者擦除操作痕迹的几个反取证措施。  
  
该漏洞由Mitel 公司在2022年4月修复，CVSS评分为9.8分。该公司发布安全公告指出，“MiVoice Connect （MITEL Service Appliacnes – SA 100、SA400和Virtual SA）的Mitel Service Application 组件中存在一个漏洞，可导致恶意人员在Service Appliance 上下文中执行RCE。”  
  
该exploit 需要两个HTTP GET 请求从服务器检索某个特定资源，通过从受攻击者控制的基础设施获取恶意命令，触发远程代码执行。研究人员调查发现，攻击者利用该exploit 创建了一个反向shell，借此启动VoIP 设备上的 web shell (“pdf_import.php”)并下载开源代理工具 Chisel。  
  
之后该二进制被执行，不过首先将其更名为 “memdump”，并利用该工具作为“反向代理，使威胁行动者进一步通过 VOIP 设备跳转到该环境”。不过最后检测到该活动后，攻击者无法在网络进行横向移动。  
  
两周前，德国渗透测试公司 SySS 披露了 Mitel 6800/6900 座机中的两个漏洞（CVE-2022-29854和CVE-2022-29855），如被成功利用可导致攻击者获得设备的根权限。  
  
研究员指出，“及时修复对于保护边界设备至关重要。然而，当威胁行动者利用的是0day时，及时修复也是不相关的。应当隔离关键资产和边界资产。在理想情况下，如果威胁行动者攻陷了边界设备，则应该不会通过‘一跳’从受陷设备访问关键资产。”  
  
目前可从网络公开访问近2.15万台Mitel 设备，它们多数位于美国，其次是英国、加拿大、法国和澳大利亚。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[勒索攻击使林肯学院倒闭，哥斯达黎加进入国家网络安全紧急状态](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511738&idx=2&sn=d82e35a9248b96348545d858e506b672&chksm=ea949fd0dde316c62f1caf163de3998cfd2954ea97604d5c5225579efd15b7caeb66da726be3&scene=21#wechat_redirect)  
  
  
[供应链勒索攻击登场，REvil 利用0day 迫使安全事件响应工具 VSA部署勒索软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506143&idx=1&sn=0fd69c41c1963778218fdd886bf4f7cd&chksm=ea94e9b5dde360a365ef065e36eb9fc0b38e533f9501ba546f847f69a3e0680933b3e017fdc1&scene=21#wechat_redirect)  
  
  
[QNAP 提醒客户注意 eCh0raix 勒索攻击和 Room Server 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247504237&idx=3&sn=43c42792dfa40b987073b70e8a953e36&chksm=ea94e007dde36911528c383eb4c89b792f74533a57b421f44886b84e2a9c74ddc10199682202&scene=21#wechat_redirect)  
  
  
[iTunes 被曝未加引号的路径 0day：勒索软件如何利用它执行任意代码并逃避检测？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491175&idx=1&sn=eac59d57a3f007a5d2acbddef60b9cd1&chksm=ea972f0ddde0a61b26a7f1729264bb8836ecfb6a62c3f26efb466bc7a48b2efcd8be8ec32a71&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/06/hackers-exploit-mitel-voip-zero-day-bug.html  
  
  
题图：  
Pixabay License  
‍  
  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
