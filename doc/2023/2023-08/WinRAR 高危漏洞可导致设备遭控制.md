#  WinRAR 高危漏洞可导致设备遭控制   
THN  代码卫士   2023-08-22 17:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**WinRAR 工具中存在一个高危漏洞，可被用于在 Windows 系统上实现远程代码执行。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQESblthjLLPf9I8Tnbmrwia5Q9NUX3S8Jm5IISIXtXuBnaoOQdloyd7icjJiccfiboyrK7aymGZmKT9A/640?wx_fmt=png "")  
  
  
该漏洞的编号是CVE-2023-40477（CVSS评分7.8），是在处理恢复卷时触发的验证不当漏洞。ZDI 在安全公告中指出，“该漏洞是因缺乏对用户提供数据的验证不当造成的，可导致超过所分配缓冲区末尾的内存访问。攻击者可利用这一漏洞在当前进程上下文中执行代码。”  
  
成功利用该漏洞要求诱骗目标访问恶意页面或者打开设陷文档文件。一位名叫 goodbyeselene 的安全研究员发现并在今年6月8日告知厂商，后者在8月2日发布的 WinRAR 6.23中修复了该漏洞。  
  
WinRAR 的维护人员指出，“涉及界外写的漏洞已在 RAR4 恢复卷处理代码中修复。”最新版本还修复了另外一个漏洞，当用户双击特殊构造文档中的某项后，WinRAR 可启动错误文件”。Group-IB 公司的研究员 Andrey Polovinkin 报送了该漏洞。  
  
建议用户更新至最新版本，缓解潜在威胁。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2023中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=1&sn=8154b433ae2be87ccbae15bc0fb09a00&chksm=ea94b543dde33c55c168c44e830d62b03e9b34ca072871d10156273a3f282cab7ccc42b9b430&scene=21#wechat_redirect)  
  
  
[奇安信发布《2023中国软件供应链安全分析报告》开源软件供应链的系统化安全治理需加速落地](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517165&idx=1&sn=c9c0c224c7eb021b526c03c079891642&chksm=ea94b287dde33b912cfba6f6ea911ca71a9002d5ca0a6a099ed818f2e235940920185d993340&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[WinRAR 被曝已存在19年的RCE 漏洞，影响全球5亿用户](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489261&idx=3&sn=f052381d92ad571833279752278f1d6d&chksm=ea972787dde0ae91d07535733af0e80217ccc1c2d6bdec893fbeac24b069ef0891b6b311040d&scene=21#wechat_redirect)  
  
  
[勒索软件CTB-Faker使用WinRAR将数据锁定为带有密码保护的ZIP文件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485713&idx=1&sn=c64654801d9c7251f1f647bc0bf7a816&chksm=ea97387bdde0b16d3fd49b5a14caff5bd56489e51e002f994ef01fb79dcb7611badb77c9f10b&scene=21#wechat_redirect)  
  
  
[WinRAR 试用版曝漏洞：免费软件并不“免费“](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508508&idx=2&sn=7461abcdc3b2e72adf3cd86e791d8f0b&chksm=ea949376dde31a603153dfd8cd929ae8a410da926c310dc781dd6ae353980565f0ca7be3054e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/08/new-winrar-vulnerability-could-allow.html  
  
  
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
  
