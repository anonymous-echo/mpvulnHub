#  速修复！Fortra GoAnywhere MFT 中存在严重的认证绕过漏洞   
Sergiu Gatlan  代码卫士   2024-01-24 17:53  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Fortra 提醒称 GoAnywhere MFT 7.4.1之前的版本中存在一个新的认证绕过漏洞，可导致攻击者创建新的管理员用户。**  
  
  
GoAnywhere MFT 用于保护与客户以及业务合作伙伴之间传输文件的安全，客户遍布全球各地。它支持协助法律合规和审计的安全加密协议、自动化、中心化控制以及多种记录和报告工具。  
  
新发现的漏洞编号是CVE-2024-0204，CVSS v3.1评分为9.8，可遭远程利用，越权用户可通过该产品的门户创建管理员用户。以管理员权限创建任意账户可导致设备遭完全接管。在 GoAnywhere MFT的案例中，它可导致攻击者访问敏感数据、引入恶意软件并可能在网络中进一步发动攻击。  
  
该漏洞影响 Fortra GoAnywhere MFG 6.0.1起的6.x版本、Fortra GoAnywhere MFT 7.4.0及更早版本，已在2023年12月7日发布的 GoAnywhere MFT 7.4.1 中修复。Fortra 公司建议所有用户安装最新更新（当前7.4.1）以修复该漏洞。  
  
Fortra 还提供如下两种手动缓解方法：  
  
1、删除安装目录中的 InitialAccountSetup.xhtml 文件并重启服务。  
  
2、用空文件替换 InitialAccountSetup.xhtml 文件并重启服务。  
  
值得注意的是，CVE-2024-0204由 Spark Engineering Consultants 公司的员工 Mohammed Eldeeb 和 Islam Elrfai 在2023年12月1日发现，距离现在已过去了很久的时间。  
  
Fortra 公司回应称，“我们没有发现该漏洞遭活跃利用的报告。漏洞已在2023年12月修复。不过，既然 Fortra 公司已发布缓解措施以及漏洞的搜索线索，如果 PoC 出现也不足为奇。  
  
  
**Clop 攻击 GoAnywhere MFT**  
  
  
  
2023年年初，Clop 勒索团伙利用位于 GoAnywhere MFT 中的一个严重的远程代码执行漏洞CVE-2023-0669，攻陷130家企业和组织机构。  
  
自2023年1月18日起，该漏洞就被当作0day漏洞利用。Fortra 公司在2023年2月3日发现了该漏洞的利用并在3天后发布补丁。  
  
遗憾的是，破坏已造成，Clop 勒索组织大规模窃取数据，影响全球组织机构，导致数据泄露、名誉受损和运营中断等。一些著名的受害者包括皇冠度假酒店集团、CHS、Hatch Bank、Rubrik、多伦多市、日立能源、宝洁、萨克斯第五大道等。  
  
Fortra 公司并未透露更多详情，仅在2023年4月中旬沟通了内部调查结果。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[多家大企业受GoAnywhere 0day 漏洞攻击影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516064&idx=1&sn=7fab64273f8adce01a48faf50055431f&chksm=ea948ecadde307dcd53290844da902ec142820effb62c358fda87676545eb9c2424da1575e72&scene=21#wechat_redirect)  
  
  
[日立能源证实受GoAnywhere攻击影响，数据遭泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515971&idx=1&sn=eec17b15763175ee40e7ceff0749f511&chksm=ea948e29dde3073f5b0f7a3684d38fd09d8ea2a1545f32fdb0d03f46cd192742987741c20e29&scene=21#wechat_redirect)  
  
  
[GoAnywhere 0day的首个受害者出现，CHS百万病患数据受影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515565&idx=2&sn=9f977b20406d11d9326758abfe4b1f97&chksm=ea948cc7dde305d162e43621927aa59b464f20b3c58f53371e378ef894fd790591ce9b4115ce&scene=21#wechat_redirect)  
  
  
[遭活跃利用的GoAnyWhere MFT 0day 补丁发布](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515504&idx=2&sn=59769cc0918ffbe4502f46bca1f3a6a9&chksm=ea948c1adde3050ccb386f6f3f2e1851f4b3aec399d1c496bf1ed6b4355e88d7aeb87a86d249&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/fortra-warns-of-new-critical-goanywhere-mft-auth-bypass-patch-now/  
  
  
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
  
