#  思科紧急修复 Emergency Responder 系统中的严重漏洞   
THN  代码卫士   2023-10-08 17:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**思科发布更新，修复了影响 Emergency Responder 的一个严重漏洞。该漏洞可导致未认证的远程攻击者利用硬编码凭据登录可疑系统。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMReDeafylOVYMG83WmGtKG3AoicRwaXuRp4qiaa9E0rzuntTCuaibL7GbO6ayBrLHyhxRteURfXPqbJw/640?wx_fmt=gif "")  
  
  
该漏洞的编号是CVE-2023-20101（CVSS评分9.8），因用于开发过程的根账户的静态用户凭据引发。思科在安全公告中指出，“攻击者可使用该账户登录到受影响系统，从而利用该漏洞。如遭成功利用，该漏洞可使攻击者登录到受影响系统并以根用户身份执行任意命令。”  
  
该漏洞影响思科 Emergency Responder Release 12.5(1)SU4，且已在12.5（1）SU5中修复。其它版本不受影响。思科表示，该漏洞是在开展内部安全检测时发现的并指出并未发现该漏洞遭在野恶意利用的情况。  
  
不到一周前，思科提醒称攻击者正在利用位于其IOS Software 和 IOS XE Software 中的漏洞CVE-2023-20109，可导致认证的远程攻击者在受影响系统上实现远程代码执行。  
  
因缺少临时缓解措施，因此建议客户尽快更新至最新版本进行缓解。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思科 BroadWorks 受严重的认证绕过漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517599&idx=2&sn=5f9a5852520d96bfe05fa6acf6b1202b&chksm=ea94b4f5dde33de35803a6bed6a97f99decb06ce2f8819f5b903779f2688af79045529facfc3&scene=21#wechat_redirect)  
  
  
[多个高危漏洞可导致思科交换机和防火墙遭 DoS 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517453&idx=2&sn=251402ddfd4c8a150b8758f1c605b2af&chksm=ea94b467dde33d7195d23ecc995280d0ef6b19557e14a8330945c641004b75bea1871b2c82a6&scene=21#wechat_redirect)  
  
  
[严重的思科 SD-WAN 漏洞可导致信息泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517089&idx=2&sn=d00e1d0fe24db8bf16d2d2b13ca24261&chksm=ea94b2cbdde33bdd104cf70c1e39dc9aa9a50a4a440cfb4040c51ffb19d02aa65883822b0e90&scene=21#wechat_redirect)  
  
  
[思科修复企业协作解决方案中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516704&idx=1&sn=6a051f71c4415e8ad5f9be754927a9e7&chksm=ea94b34adde33a5c62b6fd4ed5257ace796ceae62afe7d61ca91d818c2973aaa40cfbe68ff91&scene=21#wechat_redirect)  
  
  
[思科提醒：多款交换机存在多个RCE漏洞且利用代码已公开](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516520&idx=1&sn=b218e43205e7038adc4f452ffee4c6e2&chksm=ea94b002dde339147f0499b209d253c186277b9ecf0af4a44153ac18705dffd978ecbe379083&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2023/10/cisco-releases-urgent-patch-to-fix.html  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
