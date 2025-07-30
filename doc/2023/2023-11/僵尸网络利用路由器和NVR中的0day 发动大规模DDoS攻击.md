#  僵尸网络利用路由器和NVR中的0day 发动大规模DDoS攻击   
THN  代码卫士   2023-11-24 17:16  
  
，![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Akamai 公司本周发布安全公告指出，一起活跃的恶意软件活动正在利用两个具有远程代码执行 (RCE) 功能的两个 0day 将路由器和视频录像机纳入基于 Mirai 的分布式拒绝服务攻击 (DDoS) 僵尸网络中。**  
  
  
  
安全公告指出，“payload 针对具有默认管理员凭据的路由器和网络视频摄像机 (NVR)设备，成功后安装 Mirai 变体。”  
  
目前这两个 0day 漏洞的详情并未公开，以让两家厂商有足够实践发布补丁并阻止其它威胁行动者滥用。其中一个漏洞的修复方案预计在下个月发布。  
  
Akamai 公司最初在2023年10月底发现了这些攻击活动，不过目前幕后黑手还未找到。该僵尸网络被称为 “InfectedSlurs” 的原因是它在C2服务器中使用了种族歧视和冒犯性语言和硬编码字符串，是一个在2018年1月出现的 JenX Mirai 恶意软件变体。  
  
Akamai 表示还找到了其它恶意软件样本，它似乎与 hailBot Mirai 变体相关联，而NSFOCUS 公司分析认为后者出现在2023年9月。  
  
前不久，Akamai 详述了名为 “wso-ng” 的 web shell，它是 WSO 的“高级迭代”，集成了多种合法工具如 VirusTotal 和 SecurityTrails，同时在尝试访问时偷偷将登录界面隐藏在一个404出错页面中。该 web shell 的一个引人注意的侦查能力包括检索后续横向移动中的AWS 元数据并检索潜在的 Redis 数据库连接，以便获得对敏感应用数据的越权访问权限。微软在2021年曾表示，“web shell 可导致攻击者在服务器上运行命令以窃取数据或者将服务器用作其其它活动如凭据窃取、横向移动、额外 payload 部署或手不离键盘操作等的启动平台，从而使攻击者在受影响组织机构上获得持久性。”  
  
使用现成web shell 也被威胁行动者视作混淆归属的手段，这也是擅长情报收集的网络间谍组织的关键标志。攻击者使用的另外一个常用技术是使用受陷但合法的域名用作 C2 和传播恶意软件。2023年8月，Infoblox 披露了一起使用受陷 WordPress 网站的大规模攻击活动。该攻击按照某些条件将访客重定向至中间C2和字典域生成算法域，被归咎于 VexTrio 威胁组织。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[未修复的 Apache Tomcat 服务器传播 Mirai 僵尸网络恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517295&idx=1&sn=7f61402b12fbd46cb399a19ff93ca28e&chksm=ea94b505dde33c13b5e70aa9fdbdf02fc8dc58ac05568e19c5af6385458348da2464e9fa4c8b&scene=21#wechat_redirect)  
  
  
[Spring4Shell 漏洞已遭Mirai 僵尸网络利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511304&idx=2&sn=157f1ecf43e8268adf1d188b3bdab4db&chksm=ea949c62dde31574804aed120e44fb4c92f7d939f027277177016748f7508403563363b53f6e&scene=21#wechat_redirect)  
  
  
[警惕！Mirai 新变体带着11个新利用攻击企业设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489462&idx=2&sn=5e37f9a866349fb70248e1ccd2fdf1ba&chksm=ea9726dcdde0afcae9fa9f8641fc9203bcc29806396b12da2e07bd9d4c05bb0681ad834fbf07&scene=21#wechat_redirect)  
  
  
[Mirai 作者之一被罚 860 万美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488370&idx=2&sn=15fe33af93617e0a388f3cceadc58a75&chksm=ea972218dde0ab0e5537a684b60d50e1487e754bef2147349c2b4607bf32ee99bba50b1e1064&scene=21#wechat_redirect)  
  
  
[史无前例！Mirai 新变种 Okiru 攻击运行 ARC 处理器的设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486230&idx=1&sn=1c54d1b6a32efd56272e38bd1f442eae&chksm=ea973a7cdde0b36ab29a4cb6d571b28bcf4cb557942f36ee5c3c4e711078fea1d26efcfe839b&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/11/mirai-based-botnet-exploiting-zero-day.html  
  
  
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
  
