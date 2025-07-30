#  谷歌修复已遭利用的安卓内核0day漏洞   
Sergiu Gatlan  代码卫士   2024-08-06 18:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本月安卓共修复46个漏洞，包括被用于目标攻击中的一个高危远程代码执行 (RCE) 漏洞。**  
  
  
  
在这些漏洞中，其中一个是 0day 漏洞CVE-2024-36971，它是位于 Linux 内核网络路由管理中的一个释放后使用漏洞。攻击者需要系统执行权限才能实施成功利用，可导致某些网络连接的行为被修改。  
  
谷歌表示，“有证据表明，CVE-2024-36971可能被用于有限的针对性利用活动中”，威胁行动者可能在无需用户交互的前提下，在未修复设备上获得任意代码执行权限。  
  
谷歌威胁分析团队 (TAG) 的安全研究员 Clément Lecigne 发现并报送了该漏洞。谷歌尚未说明该漏洞是如何遭利用的以及攻击者的身份。谷歌在安全公告中提到，“这些问题的源代码补丁将在48小时内发布在安卓开源项目 (AOSP) 仓库中。”  
  
本月早些时候，谷歌修复了已遭利用的另外一个0day漏洞：位于 Pixel 固件中的高危提权漏洞CVE-2024-32896和GrapheneOS 发现的CVE-2024-29748。取证公司利用该漏洞，在无需 PIN 的情况下解锁安卓设备并获得对所存储数据的访问权限。  
  
谷歌在8月份发布两个补丁集，2024-08-01和2024-08-05安全补丁级别。后者包括第一个补丁集的所有安全修复一集第三方闭源和 Kernel 组件的补丁，如位于 Qualcomm 闭源组件中的严重漏洞CVE-2024-23350。  
  
值得注意的是，并非所有的安卓设备都需要应用2024-08-05的补丁级。设备厂商可优先部署第一个补丁集，拉通更新流程。不过，这并不一定意味着潜在利用的风险增加。  
  
虽然谷歌 Pixel 设备在发布后会立即接受每月安全更新，但其它厂商可能需要一些时间才能推出补丁，以便对安全补丁进行必要的测试，确保与多种硬件配置的兼容性。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Telegram 0day可导致攻击者将恶意安卓APK以视频形式发送](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520167&idx=2&sn=7d6a9321b744778cdce41dc0464f4c3d&chksm=ea94becddde337dbf9d65963d65e7f6e2f9177927248dd41b219d45baedcee3dee4ab9a1a397&scene=21#wechat_redirect)  
  
  
[微软7月补丁星期二修复142个漏洞，含4个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520029&idx=1&sn=1e2797120026ca6fbcf0a0d550923f4f&chksm=ea94be77dde337612f52534bfc0d5dbd0b500c89dbd45db3092f009b8ede7494801ad5f399da&scene=21#wechat_redirect)  
  
  
[大规模SMS窃取器活动感染113个国家的安卓设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520274&idx=2&sn=f33c51567cc245083a3bc121e2a4c968&chksm=ea94a178dde3286ebe53835ab2dee345efbd1d972e6226bb2b8f6b1eedb148aab02b6c2b891c&scene=21#wechat_redirect)  
  
  
[Crowdfense 出价3000万美元收购安卓、iOS和浏览器0day利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519250&idx=1&sn=a9eb759176bc25d080dd038567016edc&chksm=ea94bd78dde3346e8571088ffb3e1104df63785be22cebfc4b338fab213de9a5a83aec96d089&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
  
https://www.bleepingcomputer.com/news/security/google-fixes-android-kernel-zero-day-exploited-in-targeted-attacks/  
  
  
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
  
