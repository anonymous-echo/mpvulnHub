#  MOVEit Transfer 软件中存在高危的认证不当漏洞   
THN  代码卫士   2024-06-26 17:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ96o7o8tSK8MTtzbSGK7gYA4U75zMbgtZvMsNlEaLH2iccZYZ8EFnW9Zk4jaBhUXPwicg1IC1HTyuQ/640?wx_fmt=gif&from=appmsg "")  
  
**Progress Software 公司的MOVEit Transfer 软件中存在一个高危漏洞 (CVE-2024-5806)，可导致攻击者绕过该平台的认证机制。就在被披露的数小时后，该漏洞已遭利用。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ96o7o8tSK8MTtzbSGK7gYR2tMedVs7c4zRtZX8Nc8sFDym1GMQY4LOZpsL9BRx2YtibNqtIKuONw/640?wx_fmt=gif&from=appmsg "")  
  
  
MOVEit Transfer 是一款可使用户在大规模企业中进行文件分享和协同的应用程序；去年曾被 CI0p 勒索团伙利用，导致至少160名受害者受影响，包括英国航空、西门子等。该利用的规模如此之大，甚至影响了 Verizon 公司在今年发布的DBIR报告结果。  
  
  
**受影响版本**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ96o7o8tSK8MTtzbSGK7gYfMHs05HibtP6T4IeMgUR7IOgcwxqHJS6a8tibX7K0bbU6gFPibFXPWic7w/640?wx_fmt=gif&from=appmsg "")  
  
  
  
CVE-2024-5806的CVSS评分为7.4，是位于 MOVEit SFTP 模块中的认证不当漏洞，“可在有限场景中导致认证绕过”。Progress 公司还在安全公告中提供了打补丁信息。该漏洞影响 MOVEit Transfer 早于2023.0.11的2023.0.0版本、早于2023.1.6的2023.1.0版本以及早于2024.0.2的2024.0.0版本。  
  
  
**已遭利用**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ96o7o8tSK8MTtzbSGK7gYfMHs05HibtP6T4IeMgUR7IOgcwxqHJS6a8tibX7K0bbU6gFPibFXPWic7w/640?wx_fmt=gif&from=appmsg "")  
  
  
  
管理员应当立即修复该漏洞，不仅因为MOVEit自去年的一系列事件后出现在网络犯罪分子的监控屏幕上，而且访问财富1000企业的内部文件是任何间谍APT组织严重的香饽饽。另外，非营利性组织 Shadowserver Foundation 发布简短说明表示，“就在今天漏洞详情发布非常短的时间内，我们就看到Progress MOVEit Transfer CVE-2024-5806 POST/guestaccess.aspx 利用尝试。”据报道网络上至少有1800个被暴露的实例（尽快并非所有实例均易受攻击）。  
  
Progress 公司并未提供该漏洞的任何详情，但 watchtower 公司的研究人员认为该漏洞“非常离奇”，并判断了两种攻击场景。在一种情况下，攻击者可使用一台恶意 SMB 服务器和有效的用户名（通过字典攻击获得）执行“强制认证”。另外一种场景是更为危险的攻击，攻击者可模拟系统上的任何用户。研究人员指出，“我们甚至能够在不登录的情况下将SSH公钥上传到服务器中，之后通过这些关键材料以任意用户的身份进行认证。自此，我们可以做用户能够做的任何事情，如读取、修改和删除此前受保护的且可能是敏感的数据。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[MOVEit 供应链攻击余波未了：汽车零部件巨头 AutoZone 中招](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518206&idx=3&sn=3f0e9637d2981e7c80ebe3739aa51c93&chksm=ea94b694dde33f824e903246e7436226e785689863de85df1c1a33d1592cbf70fc0b95968fa5&scene=21#wechat_redirect)  
  
  
[MOVEit集体诉讼或使软件厂商承担更多责任](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517466&idx=2&sn=a7aa85b77eb92748d62c4577a9cf813e&chksm=ea94b470dde33d6684a87afb1089915b903ea9ca72775180632b4717000489383d866deb4277&scene=21#wechat_redirect)  
  
  
[MOVEit 爆第三个 0day，美国多个联邦机构等受影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516743&idx=1&sn=3cb8165c2ddc920b17e02e78f61b7ee6&chksm=ea94b32ddde33a3b819e16044a6666b31db296c3fd4317448aa54816d9004cfa96e0a6d66c98&scene=21#wechat_redirect)  
  
  
[速修复MOVEit Transfer 中的这个新0day！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516712&idx=2&sn=a69d93a9d282a667bbbf33bc190b4dfb&chksm=ea94b342dde33a545caba266547e0a3d88b670ddfb23236984d8f468dfbefe639a55bb220239&scene=21#wechat_redirect)  
  
  
[MOVEit 文件传输软件0day被用于窃取数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516660&idx=1&sn=bb8f16701a800011a7e9bc8857cd59d2&chksm=ea94b09edde33988e2fee2cb9c23d0031149201a1722cfabc8899b76b31016a44a835836d8a9&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/remote-workforce/fresh-moveit-bug-under-attack-disclosure  
  
  
题图：  
Pexels  
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
  
