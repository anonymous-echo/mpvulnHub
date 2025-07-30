> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523333&idx=1&sn=7293c7dd1145ab18fd71d834ad208fe0

#  BeyondTrust：注意远程支持软件中的预认证RCE  
Sergiu Gatlan  代码卫士   2025-06-19 10:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**BeyondTrust发布安全更新，修复了位于远程支持 (RA) 和特权远程访问 (PRA) 解决方案中的一个高危漏洞，可导致未认证攻击者在易受攻击服务器上获得远程代码执行权限。**  
  
远程支持 (RA) 是 BeyondTrust公司推出的一款企业级远程支持解决方案，帮助IT支持团队通过远程连接到系统和设备的方式排除故障，而特权远程访问 (PRA) 是一款安全网关，确保用户仅可访问获得授权的特定系统和资源。  
  
该漏洞是一个服务器端模板注入漏洞，编号是CVE-2025-5309，由 Resillion 公司的研究员 Jorren Geurts 在 BeyondTrust RS/PRA的聊天特性中发现。  
  
BeyondTrust 公司在周一发布的安全公告中提到，“RS和PRA 组件未对传递给模板引擎的输入进行正确转义，导致存在潜在的模板注入漏洞。该漏洞可导致攻击者在服务器上下文中执行任意代码。值得注意的是，在RS 上下文中，无需认证即可实施利用。”  
  
BeyondTrust 在2025年6月16日修复所有的 RS/PRA 云系统，并建议未启用自动更新的客户手动应用补丁。无法立即部署补丁的管理员可通过启用公共门户 (Public Portal) 的SAML认证，缓解漏洞利用风险。同时他们应当禁用“代表名单 (Representative List)” 和“问题提交调查 (Issue Submission Survey)” 并确保会话密钥已启用，来强制使用会话密钥。  
<table><tbody><tr><td data-colwidth="196" valign="top" style="border: 1px solid rgb(29, 54, 82);background: rgb(221, 221, 221);box-sizing: border-box;padding: 5px 10px;"><p style="text-align:center;font-size: 15px;"><span style="font-size:15px;"><strong><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">产品</span></span></strong></span></p></td><td valign="top" style="border-top: 1px solid rgb(29, 54, 82);border-right: 1px solid rgb(29, 54, 82);border-bottom: 1px solid rgb(29, 54, 82);border-image: initial;border-left: none;background: rgb(221, 221, 221);box-sizing: border-box;padding: 5px 10px;"><p style="text-align:center;font-size: 15px;"><span style="font-size:15px;"><strong><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">已修复版本</span></span></strong></span></p></td></tr><tr><td data-colwidth="196" valign="top" style="border-right: 1px solid #1d3652;border-bottom: 1px solid #1d3652;border-left: 1px solid #1d3652;border-image: initial;border-top: none;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">RS</span></span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom: 1px solid #1d3652;border-right: 1px solid #1d3652;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="font-size:15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">24.2.2</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">至</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">24.2</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">，应用</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">HELP-10826-2 Patch</span></span></span></p></td></tr><tr><td data-colwidth="196" valign="top" style="border-right: 1px solid #1d3652;border-bottom: 1px solid #1d3652;border-left: 1px solid #1d3652;border-image: initial;border-top: none;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">RS</span></span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom: 1px solid #1d3652;border-right: 1px solid #1d3652;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="font-size:15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">24.3.1</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">至</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">24.3.3</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">，应用</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">HELP-10826-2 Patch</span></span></span></p></td></tr><tr><td data-colwidth="196" valign="top" style="border-right: 1px solid #1d3652;border-bottom: 1px solid #1d3652;border-left: 1px solid #1d3652;border-image: initial;border-top: none;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">RS</span></span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom: 1px solid #1d3652;border-right: 1px solid #1d3652;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="font-size:15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">24.3.4 </span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">和</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf=""> 24.3.x</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">的后续版本</span></span></span></p></td></tr><tr><td data-colwidth="196" valign="top" style="border-right: 1px solid #1d3652;border-bottom: 1px solid #1d3652;border-left: 1px solid #1d3652;border-image: initial;border-top: none;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">PRA</span></span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom: 1px solid #1d3652;border-right: 1px solid #1d3652;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="font-size:15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">25.1.1</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">，应用</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">HELP-10826-1 Patch</span></span></span></p></td></tr><tr><td data-colwidth="196" valign="top" style="border-right: 1px solid #1d3652;border-bottom: 1px solid #1d3652;border-left: 1px solid #1d3652;border-image: initial;border-top: none;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">PRA</span></span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom: 1px solid #1d3652;border-right: 1px solid #1d3652;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="font-size:15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">25.1.2</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">及后续版本</span></span></span></p></td></tr><tr><td data-colwidth="196" valign="top" style="border-right: 1px solid #1d3652;border-bottom: 1px solid #1d3652;border-left: 1px solid #1d3652;border-image: initial;border-top: none;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">PRA</span></span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom: 1px solid #1d3652;border-right: 1px solid #1d3652;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="font-size:15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">24.2.2</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">至</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">24.2.4</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">，应用</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">HELP-10826-2 Patch</span></span></span></p></td></tr><tr><td data-colwidth="196" valign="top" style="border-right: 1px solid #1d3652;border-bottom: 1px solid #1d3652;border-left: 1px solid #1d3652;border-image: initial;border-top: none;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">PRA</span></span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom: 1px solid #1d3652;border-right: 1px solid #1d3652;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="font-size:15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">24.3.1</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">至</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">24.3.3</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">，应用</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">HELP-10826-2 Patch</span></span></span></p></td></tr><tr><td data-colwidth="196" valign="top" style="border-right: 1px solid #1d3652;border-bottom: 1px solid #1d3652;border-left: 1px solid #1d3652;border-image: initial;border-top: none;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">PRA</span></span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom: 1px solid #1d3652;border-right: 1px solid #1d3652;padding:5px 10px;"><p style="text-align:left;font-size: 15px;"><span style="font-size:15px;"><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">25.1.1</span></span><span style="color: #333333;font-size: 15px;font-family:宋体;"><span leaf="">，应用</span></span><span style="color: #333333;font-size: 15px;font-family:Arial, sans-serif;"><span leaf="">HELP-10826-1 Patch</span></span></span></p></td></tr></tbody></table>  
  
虽然该公司并未提到该漏洞已遭在野利用，但近年来 BeyondTrust RS/PRA 漏洞已遭利用。近期，该公司在12月早期披露称攻击者使用 RS/PRA 中的两个0day漏洞（CVE-2024-12356和CVE-2024-12686）和PostgreSQL 中的一个0day漏洞（CVE-2024-1094）攻陷其系统。他们还在攻陷过程中窃取了一个 API 密钥，用于攻陷17个 RS SaaS 实例。  
  
不到一个月之后，美国财政部披露称其网络遭攻陷。CISA 在12月19日将 CVE-2024-12356 加入其必修清单，要求美国联邦机构在一周时间内保护其网络安全。  
  
BeyondTrust 向100多个国家的2万多名客户提供身份安全服务，其中75%的公司是全球财富100强公司。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[速修复！Erlang/OTP SSH 中存在严重的预认证 RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522791&idx=1&sn=b726626262a08aef9a0f09bf3d3332e0&scene=21#wechat_redirect)  
  
  
[CISA 提醒注意已遭活跃利用的 Juniper 预认证 RCE 利用链](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518122&idx=1&sn=d6b5a20e45ee8897ed249a7bdde21ebb&scene=21#wechat_redirect)  
  
  
[OpenSSH 修复预认证双重释放漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515493&idx=1&sn=10c488e3633714016c305152a77ee339&scene=21#wechat_redirect)  
  
  
[速修复！Netgear 61款路由器和调制解调器中存在多个严重的预认证RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509274&idx=1&sn=216d21cb49d9020ea39826423b5b770f&scene=21#wechat_redirect)  
  
  
[大企业都在用的开源 ForgeRock OpenAM 被曝预认证 RCE 0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506349&idx=2&sn=c1cd744877e475629005b1d5af227712&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/beyondtrust-warns-of-pre-auth-rce-in-remote-support-software/  
  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
