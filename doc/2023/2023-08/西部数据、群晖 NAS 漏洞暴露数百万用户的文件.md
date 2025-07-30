#  西部数据、群晖 NAS 漏洞暴露数百万用户的文件   
Eduard Kovacs  代码卫士   2023-08-11 19:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**IoT 和工业网络安全公司 Claroty 在西部数据和群晖 NAS 产品中发现了多个严重漏洞，可暴露数百万用户的文件。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQa5hd3ugC4GVyXjDn1ibk4BGibibxibM2N48ApPd6PicavuSFJgfuZzycmXx3z1Pz84116nIa7dWzg8sQ/640?wx_fmt=png "")  
  
  
这些漏洞及利用已在2022年12月 ZDI 多伦多 Pwn2Own 大赛上展示。西部数据和群晖已发布补丁（某些情况下是自动推送）并发布安全公告，将漏洞告知客户。群晖发布了一份安全公告，西部数据分别在12月份、1月份和5月份发布三份安全公告。  
  
研究人员找到枚举所有西部数据云 NAS 设备的方法，对这些设备进行模拟，并通过厂商的 MyCloud 服务获得对每个系统的访问权限。攻击者可利用这些漏洞远程访问用户文件、执行任意代码并完全控制连接云的设备。  
  
研究人员解释称，“首先，我们枚举所有设备 GUID 并选择目标清单。之后我们模拟设备、窃取其云隧道并断联设备。设备所执行的任何请求都会发给我们，使我们获得设备管理员的认证令牌。通过使用新获取的权限，我们在设备上创建了新的共享，将其映射到 /tmp 目录。随后我们将反向 shell payload 写到该目录并通过云重启。不管设备在何时重启，都会执行我们的 payload，从而在设备上执行代码。”  
  
研究人员还发现一些漏洞，可用于模拟群晖NAS设备并强制 QuickConnect 云服务将用户重定向至遭攻击者控制的设备。攻击者可利用这些漏洞窃取凭据、访问用户数据并远程执行任意代码，从而控制设备并发动进一步的攻击。  
  
研究人员分析发现数百万西部数据和群晖 NAS 设备易受攻击。  
  
鉴于“基于远程已知信息而非机密的弱设备认证”，西部数据和群晖利用是很可能存在的，研究人员认为类似问题可能影响其它厂商的设备。  
  
Claroty 公司也分别就西部数据和群晖漏洞发布博客文章。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Pwn2Own大赛回顾：利用开源服务中的严重漏洞，攻陷西部数据My Cloud PR4100](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511095&idx=1&sn=e1f0122f82889cda652d6febbba2879c&chksm=ea949d5ddde3144b2fb52dbbfc2b76961538c21d7e9adc3e02bc2a3b4fb6d592755c393b2cf6&scene=21#wechat_redirect)  
  
  
[老旧漏洞不修复，西部数据存储设备数据遭擦除](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506050&idx=2&sn=1aec337eb2124f923735a0c56a366a53&chksm=ea94e9e8dde360fea2f893159acbc72d0814503a26f32a63e2c230cc5267b9b3b90b822f5b37&scene=21#wechat_redirect)  
  
  
[西部数据app可导致Windows 和 macOS 提权](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511011&idx=1&sn=875472800b32dc8b11c92a6c49270a9c&chksm=ea949a89dde3139f3a9f85a1ace44ff2856996e021b7e086def08bc66230ec0ed14647c4ee59&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/western-digital-synology-nas-vulnerabilities-exposed-millions-of-users-files/  
  
  
题图：Pexels License  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
