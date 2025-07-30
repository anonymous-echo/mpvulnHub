#  Chrome 114 发布18个漏洞补丁   
Ionut Arghire  代码卫士   2023-06-01 17:44  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**本周，谷歌发布 Chrome 114，共修复18个漏洞，其中13个由外部安全研究员报告。**  
  
  
  
  
在这些由外部报送的漏洞中，8个属于“高危”级别，其中6个是内存安全漏洞。  
  
从所颁发的漏洞赏金来看，最重要的漏洞是CVE-2023-2929，它是位于 Swiftshader 中的界外写漏洞。研究员 Jaehun Jeong 为此获得1.5万美元的奖励。其次是CVE-2023-2930，它是位于 Extensions 中的释放后使用漏洞，为研究员获得1万美元的奖励。  
  
Viettel Cyber Security 公司的研究员在Chrome 浏览器的 PDF 组件中发现了三个释放后使用漏洞，每个均获得赏金9000美元。  
  
余下的三个高危漏洞是一个位于 Mojo 中的界外内存访问漏洞和两个位于 V8 JavaScript 和 WebAssembly 引擎中的类型混淆漏洞。这三个漏洞都是由谷歌 Project Zero 团队的研究员发现的，而按照谷歌的政策要求，他们均不会获得赏金。  
  
Chrome 114还修复了四个由外部研究员报送的中危漏洞，其中包括位于 Picture 和 Downloads 中的三个实现不当漏洞和一个位于 Installer 中的数据验证不充分漏洞。本次还修复了位于 Extensions API 中的一个低危实现不当漏洞。  
  
谷歌本次共颁发6.5万美元的奖励。本次发布的 Chrome 114.0.5735.90适用于 Linux 和 macOS，而 114.0.5735.90/91适用于 Windows 版本。  
  
谷歌并未提到这些漏洞遭恶意攻击的情况。  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Zoom 修复Windows 和 MacOS 平台上的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515248&idx=3&sn=efcb69755e1725002e1132202e9fd131&chksm=ea948d1adde3040cde57da5db0825a83b7d3aab9f8d9b9a0736d4fa3ad90a2a44810426cdecd&scene=21#wechat_redirect)  
  
  
[苹果紧急发布macOS和iOS安全补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513005&idx=4&sn=d917d7842e64544a3258d7d993033621&chksm=ea9482c7dde30bd1b1df774d8f19c6c8ba630dfa0e795ba0ef73db4a1d5ed532d9bcbef75ce1&scene=21#wechat_redirect)  
[微软详述影响苹果 iOS、iPadOS、macOS 设备的沙箱逃逸漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512944&idx=2&sn=d4eadd75c1a517158050fee4b426c96d&chksm=ea94821adde30b0ca1a9fe01b01d12a5925479f01abfd7dd02cf3d8fa29e782d5524bdf64933&scene=21#wechat_redirect)  
  
  
[西部数据app可导致Windows 和 macOS 提权](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511011&idx=1&sn=875472800b32dc8b11c92a6c49270a9c&chksm=ea949a89dde3139f3a9f85a1ace44ff2856996e021b7e086def08bc66230ec0ed14647c4ee59&scene=21#wechat_redirect)  
  
  
[开源的Linphone SIP 电话存在栈漏洞，可远程使客户端设备崩溃](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507604&idx=1&sn=7171a6a61d5cf51a7319a013f598da2d&chksm=ea94effedde366e814e7d08c75786a53f6282c8df842a1919c580db26ce46627ab86ccc64f4c&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/chrome-114-released-with-18-security-fixes/  
  
  
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
  
