#  SonicWall紧急提醒：速修复多个严重的认证绕过漏洞！   
Sergiu Gatlan  代码卫士   2023-07-13 18:22  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**今天，SonicWall 紧急提醒客户修复影响 Global Management System (GMS) 防火墙和 Analytics 网络报告引擎软件套件的多个严重漏洞。**  
  
Sonicwall 公司今天共修复15个漏洞，其中一些可导致攻击者在绕过认证后，访问运行 GMS 9.3.2-SP1或更早版本以及 Analytics 2.5.0-R7或更早版本的本地系统。该公司表示，“这些负责任披露的漏洞包括4个CVSSv3 评级为‘严重’等级的漏洞，可导致攻击者绕过认证并可能导致敏感信息被暴露给越权人员。SonicWall PSIRT 强烈建议使用 GMS/Analytics本地版本的组织机构立即更新至相应的已修复版本。”  
  
管理员应立即更新至 GMS 9.3.3和 Analytics 2.5.2 版本的漏洞包括：  
  
- CVE-2023-34124: Web Service 认证绕过  
  
- CVE-2023-34133: 多个未认证SQL注入问题和安全过滤绕过  
  
- CVE-2023-34134: 通过Web Service的密码哈希读取  
  
- CVE-2023-34137: CAS 认证绕过  
  
  
  
未认证攻击者可在无需用户交互的低复杂攻击活动中远程利用这些漏洞。成功利用可导致攻击者越权访问数据。这些数据可能包括属于其他用户的信息或受攻陷应用中的任何数据。攻击者可在攻陷后操纵或删除该数据，对被入侵应用的内容或功能造成“永久性变更”。  
  
SonicWall PSIRT 尚未发现关于 PoC 利用代码的公开报告或漏洞已遭活跃利用的迹象。该公司的设备长久以来一直遭勒索攻击和网络间谍攻击。SonicWall 公司的产品用户遍布全球215个国家，商业客户达到50多万个，包括政府机构和全球的某些最大规模公司。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[SonicWall：速修复这个严重的SQL 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513049&idx=2&sn=9b4e39de28718716d2dad0696dbb15ff&chksm=ea9482b3dde30ba55fbdc6aea7895291e3f8acb934a5200d4ee93d5c849936ba0a05ff2b45d0&scene=21#wechat_redirect)  
  
  
[SonicWall 防火墙曝严重漏洞，有些设备仍无补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511136&idx=1&sn=b9b7456e062bb08200fdbdc2eaa75ecc&chksm=ea949d0adde3141ca564f0fa7af067b5cc82bbb8299d4462c5f18a441e7f041dd23bd011b8a7&scene=21#wechat_redirect)  
  
  
[SonicWall 紧急提醒：EOL 设备正遭勒索攻击！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506376&idx=2&sn=ae05ce4a02a7c67ce2b51c8666d9d55d&chksm=ea94e8a2dde361b442b0e183dd82340ba45f3fb441a98add4376def73c8dedc58d1a577714d1&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/sonicwall-warns-admins-to-patch-critical-auth-bypass-bugs-immediately/  
  
  
题图：Pixabay License  
  
  
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
  
