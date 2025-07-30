#  SmartPTT、SmartICS 工业产品存在多个严重漏洞，影响全球90国   
Eduard Kovacs  代码卫士   2022-04-25 18:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
  
安全研究员 Michael Heinzl在俄罗斯专业无线通信和工业自动化公司 Elcomplus 生产的工业产品中发现了多个漏洞，其中一些是严重和高危级别。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQn2ictYK52utpQA7mBEib4UceA7pyOezWHFPmvS0ibb5pvGgRbFVozGfoSnZYJNFQBXtKe2LrBn8WfQ/640?wx_fmt=png "")  
  
  
  
Heinzl 在 Elcomplus 公司的SmartPTT SCADA 产品中共发现9个漏洞。该产品结合了SCADA/IIoT 系统和专业无线电系统分派软件的能力。另外，专事SCADA和工业IoT 虚拟化平台的SmartICS 生产的产品因共享代码，也受某些漏洞影响。  
  
受影响产品遍布90个国家的2000多家组织机构，其中美国也在受影响范围之列，其网络安全和基础设施安全局 (CISA) 本周发布两份安全公告向组织机构通知相关漏洞情况。Heinzl 也分别为每个漏洞发布安全公告。  
  
这些安全漏洞包括路径遍历、跨站点脚本、任意文件上传、授权绕过、跨站点请求伪造和信息泄露等。这些漏洞如遭利用可导致攻击者上传文件、在系统上读或写任意文件、获取以明文形式存储的凭据、代表用户执行多种操作、执行任意代码以及提权访问管理员功能。在某些情况下，漏洞利用要求认证或用户交互（如点击链接或访问某些页面）。  
  
Heinzl在2021年4月通过CISA将漏洞告知厂商，后者于2021年年底发布补丁。  
  
这并非Heinzl 首次发现ICS漏洞。去年，他从日本电子巨头欧姆龙生产的XC-Programmer PLC 编程软件、富士电机的Tellus 工厂监控和操作产品、台达电子的DIAEnergie 工业能源管理系统和捷克工业自动化公司mySCADA 的myPRO HMI/SCADA 产品中发现了多个缺陷。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[横河电机修复多个工控产品漏洞，可用于破坏和操纵物理进程](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511248&idx=3&sn=6d653ec642fb58f61ba4c4e0e27b2c7b&chksm=ea949dbadde314ac1addd5c17fe3e64fac564986bf43f33a7ed4826d02cf47e4210f2518fcba&scene=21#wechat_redirect)  
  
  
[工控2月补丁星期二：西门子、施耐德电气修复近50个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510474&idx=2&sn=87818e92c87a947611eea0423026cf83&chksm=ea9498a0dde311b68937435a613ba0af82df0b65e38a1b9c0b21a08820f9abc23d5820d955c0&scene=21#wechat_redirect)  
  
  
[很多工控产品都在用的 CODESYS 软件中被曝10个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505442&idx=1&sn=645ef4a67cc6372f43f130a8137ab64b&chksm=ea94e748dde36e5e6a22fd7095c3617ac52b1376100a574a8020f04cef31b81c971ae57ad756&scene=21#wechat_redirect)  
  
  
[黑客利用 VPN 漏洞远程入侵工控系统](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494318&idx=2&sn=7af460bc2b0f47e0da6c30b6d6233027&chksm=ea94dbc4dde352d278e48f64575e076e8e5abdd893a4af68697b414b645431072d2b82c15dd1&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/several-critical-vulnerabilities-affect-smartppt-smartics-industrial-products  
  
  
题图：Pixabay License  
  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMQjfQ8ZhaOGYOwiaOkCe6UVnwG4PcibqI6sJ3rojqp5qaJa0wA2lxYb0VKwria7pHqS9rJwSPSykjMsA/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
