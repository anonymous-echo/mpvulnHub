#  Fortinet 提醒注意端点管理软件中的严重RCE漏洞   
SERGIU GATLAN  代码卫士   2024-03-14 17:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Fortinet 修复了位于 FortiClient Enterprise Management Server (EMS) 软件中的一个严重漏洞，可导致攻击者在易受攻击的服务器上获得远程代码执行 (RCE)。**  
  
  
FortiClient EMS 可使管理员管理连接到企业网络的端点，部署 FortiClient软件并在Windows设备上分配安全配置。该严重漏洞的编号是CVE-2023-48788，是位于 DB2 Administration Server (DAS) 组件中的一个SQL注入漏洞，由英国国家网络安全中心 (NCSC) 和Fortinet开发人员 Thiago Santana 发现并报送。  
  
该漏洞影响 FortiClient EMS 7.0（7.0.1至7.0.10）和7.2（7.2.0至7.2.2）版本，可导致未认证攻击者在复杂度低下的攻击场景中，以系统权限在未修复的服务器上获得RCE。  
  
Fortinet 发布公告指出，“FortiClientEMS 中SQL命令中使用的特殊元素中和不当漏洞（“SQL注入”）可能导致未认证攻击者通过特殊构造的请求执行越权代码或命令。”该公司并未透露漏洞是否已遭利用。  
  
Horizon3公司证实了该漏洞的严重性并表示下周将发布PoC 利用代码和深入分析。  
  
本周二，Fortinet 公司还修复了位于 FortiOS 和 FortiProxy 强制门户认证中存在的一个严重的界外写漏洞（CVE-2024-42789），可导致未认证的“内部攻击者”使用恶意构造的HTTP请求远程执行越权代码或命令。  
  
该公司本周修复了另外两个高危漏洞，即适用于 FortiManager 的 FortiWLM MEA 中的访问控制不当漏洞 (CVE-2023-36554)和位于 FortiClient EMS 中的CSV注入漏洞 (CVE-2023-47534)，可导致攻击者在易受攻击系统上执行任意命令或代码。  
  
上个月，Fortinet 公司披露了 FortiOS 操作系统和 FortiProxy web安全代理中的严重RCE漏洞（CVE-2024-21762），并提到“可能已遭在野利用”。一天后，CISA证实了这一结论，并要求联邦机构在七天内修复该漏洞。  
  
Fortinet 公司的漏洞常常被勒索团伙和间谍组织用于攻陷企业网络。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Fortinet 提醒注意严重的FortiSIEM命令注入漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518159&idx=1&sn=44370db9677abd274914bebd182e5446&chksm=ea94b6a5dde33fb3b7fce9d16af88a593ad5cafb43671cb75c4eb3e9d6055b3812e8a12d2e68&scene=21#wechat_redirect)  
  
  
[Fortinet 修复影响多款产品中的高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517693&idx=2&sn=ee2f37800cd4fde8239f203b3abcd5d3&chksm=ea94b497dde33d818a22818925aba4c372988566412b75f81318126b467d62a54093436d6e12&scene=21#wechat_redirect)  
  
  
[Fortinet：速修复 FortiOS、FortiProxy 设备中的严重RCE漏洞！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517034&idx=2&sn=0e6034be825eac879386635841578fa0&chksm=ea94b200dde33b16e5b00a74e6327aca06b3192a6c9501d14cc86edab7c248c3044a44ff1a9c&scene=21#wechat_redirect)  
  
  
[Fortinet 修复严重的 FortiNAC 远程命令执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516818&idx=3&sn=7524bc2288375bbf06f9574e73e15a00&chksm=ea94b3f8dde33aeeeb1313ae4cb6608ffa6876baa1ba49cbdac2b97cf5307198a79fd41eed8b&scene=21#wechat_redirect)  
  
  
[Fortinet 修复 Fortigate SSL-VPN 设备中严重的 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516712&idx=1&sn=db056d3f152e8f52867cc5021679e6f1&chksm=ea94b342dde33a543f8d7daaae604ffb6f0a65f865bf3fd926dfee86ad48be7d6460b9107d7d&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/fortinet-warns-of-critical-rce-bug-in-endpoint-management-software/  
  
  
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
  
