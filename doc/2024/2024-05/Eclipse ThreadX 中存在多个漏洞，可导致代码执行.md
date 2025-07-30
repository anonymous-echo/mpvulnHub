#  Eclipse ThreadX 中存在多个漏洞，可导致代码执行   
Ionut Arghire  代码卫士   2024-05-30 17:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Humanativa 集团公布了物联网设备实时操作系统 Eclipse ThreadX 中的多个漏洞信息。**  
  
Eclipse ThreadX 平台此前被称为 “Azure RTOS”，最初由微软开发。微软在2024年1月将该技术贡献给 Eclipse 基金会，之后更名为 “Eclipse ThreadX”。Eclipse ThreadX 旨在为资源有限的设备设计，是一款用于实时应用程序的开源平台和高阶嵌入式开发组件。  
  
Humanativa 集团的研究员 Marco Ivaldi 分析了公开可获得的 ThreadX 源代码后发现了多个漏洞可导致内存损坏，且可被用于引发拒绝服务条件或执行任意代码。  
  
第一个漏洞编号是CVE-2024-2214，是数组大小检查缺失问题，可导致缓冲区溢出和内存覆写。第二个漏洞CVE-2024-2212产生的原因在于 ThreadX 中的 FreeRTOS 兼容性API 缺失对两个函数的参数检查，导致整数溢出、分配不足以及堆缓冲溢出后果。Ivaldi 表示，如攻击者能够控制易受攻击的函数，则可导致整数溢出，少量内存分配，从而导致堆缓冲溢出。  
  
第三个漏洞CVE-2024-2452影响转为深入嵌入式实时和物联网应用开发的 Eclipse ThreadX NetX Duo工业级TCP/IP 网络栈，可导致整数溢出、分配不足和堆缓冲溢出。研究人员解释称，“如攻击者能够控制 __portable_aligned_alloc()，则能够引发整数溢出和更小的分配，从而引发堆缓冲溢出。”  
  
研究人员已于2023年12月和2024年1月将这些漏洞报送给微软和 Eclipse基金会，且漏洞已在 Eclipse ThreadX 6.4.0中修复。  
  
另外，研究人员还报送了其它一些安全问题不过并未被ThreadX 维护人员视为漏洞，不过后者考虑将在未来的操作系统发布中通过改进代码的方式将其修复。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[严重的Cacti漏洞可导致攻击者执行远程代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519478&idx=1&sn=261efda4ddb82aa78c36feacfdea3f71&chksm=ea94bd9cdde3348aa6e1e2e11d32c2f4dcd20a5c517b0f4d90f0d2075e2da58c5d6e02ba60e4&scene=21#wechat_redirect)  
  
  
[合勤科技修复防火墙产品中的远程代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518947&idx=2&sn=8758a5f5ef83a075fb61fbed63159da1&chksm=ea94bb89dde3329f7456dbac7c02de7915e34069451108f060250d64c23c6f9145d80e39bcc4&scene=21#wechat_redirect)  
  
  
[Atlassian Confluence 远程代码执行漏洞(CVE-2023-22527)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518678&idx=1&sn=aedf682361f621f14474e78244d3242e&chksm=ea94b8bcdde331aa278b8d6c8fe7f1df9ec253aa21e960355a967894be85796756b54e173c95&scene=21#wechat_redirect)  
  
  
[Nimbuspwn：微软在Linux 操作系统中发现了多个提权缺陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511591&idx=1&sn=b2821056ec08d448999a6d1f0bc1c3a9&chksm=ea949f4ddde3165b34885b0802da21ef1ad96e1c18103920729d17fd3f3bb5a3fe24497b266b&scene=21#wechat_redirect)  
  
  
[NUCLEUS:13：西门子实时操作系统 Nucleus漏洞影响物联网设备等](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509038&idx=2&sn=76b3969165515fd1c383795ee93effa5&chksm=ea949544dde31c52eba874e50acf2a40da84c80270dff2115e19f09e7212ca2a7dbb721bb7d4&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/vulnerabilities-in-eclipse-threadx-could-lead-to-code-execution/  
  
  
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
  
