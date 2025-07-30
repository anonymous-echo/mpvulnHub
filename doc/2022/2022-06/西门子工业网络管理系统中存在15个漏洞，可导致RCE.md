#  西门子工业网络管理系统中存在15个漏洞，可导致RCE   
Ravie Lakshmanan  代码卫士   2022-06-21 17:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMThIz9axluNe2c2NRzcN1SNcQcEB7Fk3ffsSY8tTpNG8ZFubaaAuMrX4EhhyjmdibaxxWLFfQFXnOg/640?wx_fmt=png "")  
  
网络安全研究员披露了位于西门子 SINEC 网络管理系统 (NMS) 中的15个漏洞详情，其中一些漏洞可被攻击者组合利用，最终在受影响系统上实现远程代码执行。  
  
  
  
工业安全公司 Claroty 发布报告指出，“如果这些漏洞遭利用，可对网络上的西门子设备带来诸多风险，包括拒绝服务攻击、凭据泄露和在某些情况下的远程代码执行。”  
  
这些漏洞的编号是CVE-2021-33722至CVE-2022-22736，西门子已经在版本 V1.0 SP2 Update 1 中修复，该版本于2021年10月12日发布。西门子当时在安全公告中指出，“在一定条件下，最严重的漏洞可导致认证的远程攻击者以系统权限在系统上执行任意代码。”其中最主要的漏洞是CVE-2021-33723（CVSS评分8.8），可导致攻击者权限提升至管理员账户，并和路径遍历缺陷CVE-2021-33722（CVSS评分7.2）组合利用，远程执行任意代码。  
  
另外一个值得注意的缺陷和 SQL 注入有关（CVE-2021-33729，CVSS评分8.8），可被认证攻击者用于在本地数据库中执行任意命令。  
  
研究人员指出，“SINEC位于网络拓扑中一个强大的中心位置，因为它要求访问凭据、加密密钥和其它机密信息，使攻击者具有管理员访问权限以管理网络中的设备。从攻击者角度来看，执行这类远程攻击，滥用、访问并控制合法凭据和网络工具执行恶意活动，使攻击者能够执行侦察、横向移动和提权操作。”        
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[西门子修复因使用第三方组件引起的90多个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510855&idx=1&sn=0dada11bb41d898268db5ad0cb471f91&chksm=ea949a2ddde3133b08eb46032dead81cb9d3a1a0c23184bbf7a4feef3865e49a14a10cb49c54&scene=21#wechat_redirect)  
  
  
[工控2月补丁星期二：西门子、施耐德电气修复近50个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510474&idx=2&sn=87818e92c87a947611eea0423026cf83&chksm=ea9498a0dde311b68937435a613ba0af82df0b65e38a1b9c0b21a08820f9abc23d5820d955c0&scene=21#wechat_redirect)  
  
  
[工控补丁星期二：西门子、施耐德电气修复40个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510120&idx=3&sn=10fcfe44fd89efa7da7cbfc4f511bf60&chksm=ea949902dde31014585298b57b592dd4d60f0c3ab245333bd71e6fe3f2880b1ed79f84747e7d&scene=21#wechat_redirect)  
  
  
[NASA、西门子和大众都在用的 IoT 协议可遭滥用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509217&idx=2&sn=e90e4bca0d98ee5534f4d3bee0bada01&chksm=ea94958bdde31c9d22a024f5e1e86b3748f37febed5089ec1266083ae7b414263a3f08aa549f&scene=21#wechat_redirect)  
  
  
[NUCLEUS:13：西门子实时操作系统 Nucleus漏洞影响物联网设备等](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509038&idx=2&sn=76b3969165515fd1c383795ee93effa5&chksm=ea949544dde31c52eba874e50acf2a40da84c80270dff2115e19f09e7212ca2a7dbb721bb7d4&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/06/over-dozen-flaws-found-in-siemens.html  
  
  
题图：  
Pixab  
ay License  
  
  
  
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
