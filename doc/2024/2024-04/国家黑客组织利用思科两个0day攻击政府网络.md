#  国家黑客组织利用思科两个0day攻击政府网络   
Sergiu Gatlan  代码卫士   2024-04-25 17:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**思科提醒称，自2023年11月起国家黑客组织一直在利用位于 ASA 和 FTD 防火墙中的两个0day漏洞攻陷全球政府网络。**  
  
  
  
这些黑客被思科 Talos 称为 “UAT4356”，微软称为 “STORM-1849”，他们自2023年11月开始发动网络间谍活动 ArcaneDoor，渗透易受攻击的边缘设备。尽管思科尚未发现初始攻击向量，但发现并修复了攻击者利用的两个0day，即CVE-2024-20353（拒绝服务漏洞）和CVE-2024-20359（可持久的本地代码执行漏洞）。思科在2024年1月发现了 ArcaneDoor 活动并发现攻击者至少在2023年6月就已测试并开发了相关利用。  
  
  
**思科防火墙后门**  
  
  
这两个漏洞可导致攻击者在受陷的ASA和FTD设备上部署此前未知的恶意软件并维护可持久性。  
  
其中一个恶意软件植入是 Line Dancer，它是一款位于内存的 shellcode 加载器，有助于传播和执行任意 shellcode payload，以禁用记录、提供远程访问权限并提取被捕获的数据包。  
  
第二款植入是一款可持久的后门 Line Runner，它配有多种防御躲避机制以避免被检测到，并可使攻击者在被黑系统上运行任意Lua代码。思科表示，“该行动者利用定制工具，展示了其对间谍的关注以及所针对设备的深厚知识，说明是复杂的国家黑客组织。UAT4356 部署了两款后门 Line Runner 和 Line Dancer，用于执行恶意行动，包括配置修改、侦查、网络流量捕获/渗透以及潜在的横向移动等。”  
  
英国国家网络安全中心、加拿大网络安全中心以及澳大利亚网络安全中心发布联合公告提到，这些恶意人员通过访问权限实施如下目标：  
  
- 生成文本版本的设备配置文件，以便通过web请求进行提取。  
  
- 控制对设备系统日志服务的启用和禁用，以便混淆其它命令。  
  
- 修改认证、授权和审计配置，以便一些匹配某个标识符的受控设备能够在受影响环境中获得访问权限。  
  
  
  
  
**思科督促客户升级**  
  
  
本周三，思科发布安全更新修复了这两个0day漏洞，目前“强烈建议”所有客户升级设备修复软件，拦截任何攻击。  
  
思科还“强烈鼓励”管理员监控系统日志中是否存在非计划的重启、越权配置更改或可疑的凭据活动。思科表示，“不管网络设备提供商是谁，现在必须确保设备得到正确修复，登录到中央、安全位置并配置了多因素认证机制。”思科还在该安全公告中提供了验证ASA或FTD设备完整性的指南。  
  
本月早些时候，思科提醒注意针对全球思科、CheckPoint、Fortinet、SonicWall和 Ubiquiti 设备上VPN和SSH服务的大规模暴力破解攻击。今年3月份，思科还分享了针对思科Secure Firewall 设备上所配置的RAVPN服务的密码喷射攻击缓解指南。  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思科修复IMC 高危根提权漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519311&idx=1&sn=d41f0d79f130254f124a7ea7404a3b12&chksm=ea94bd25dde33433a3f6fee230eea0ec03c4f96a3c2c63e2978e87fe79ae4a7a724a521d65e4&scene=21#wechat_redirect)  
  
  
[思科提醒注意Small Business路由器中的XSS漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519231&idx=2&sn=b7b32d73cbe2046719780c03304729ce&chksm=ea94ba95dde333834c93da6e263ab3af72ce14f2a171799c65802dab992336cd0c1a96492159&scene=21#wechat_redirect)  
  
  
[思科IOS 漏洞可导致未认证的远程DoS 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519204&idx=2&sn=6fc646b9575f6837ef0f55d569c11709&chksm=ea94ba8edde33398e567236352d40e34414aa12c9e4bd4d838bff320754289021c2fafcc02b8&scene=21#wechat_redirect)  
  
  
[思科修复 Data Center OS 中的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518970&idx=1&sn=6962ea177a62fac9410b186624a2cd9a&chksm=ea94bb90dde332865540fed5893fa0fe3b2438bba6108c0ec68ea0e789667b29c274b976ec73&scene=21#wechat_redirect)  
  
  
[思科提醒注意通信软件中的严重 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518760&idx=2&sn=d82d599134c7b2a410f4ccfe05d73d96&chksm=ea94bb42dde33254d6f854bc5b194c69fc4038bdbac099637195d80d4e0b19bd6ede6758ace6&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/arcanedoor-hackers-exploit-cisco-zero-days-to-breach-govt-networks/  
  
  
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
  
