#  研究员披露修复两次的 Windows RDP 漏洞详情   
Ionut Arghire  代码卫士   2022-06-20 17:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSF3l35ZJV21sbRns4ljFBzZf8QoKMtN4qia91vx8Pd777cNT48w7hcTDVCM6ic3Rpe6ibXvk8DicHplg/640?wx_fmt=png "")  
  
身份  
安全公司 CyberArk 的研究员分享了关于 Windows 中  
远程桌面服务 （  
RDP） named 管道漏洞的详情，微软为修复该漏洞发布两轮补丁。  
  
  
  
该漏洞的编号是CVE-2022-21893，最初在2022年1月补丁星期二中修复，但分析修复方案后发现一个新的攻击向量尚未修复。4月份，微软修复编号改为CVE-2022-24533的该漏洞。  
  
CVE-2022-21893 是一个Windows 远程桌面服务漏洞，可导致低权限用户通过 RDP 访问机器以访问其它联网用户客户端机器的文件系统。该漏洞可导致攻击者查看并修改其它联网用户的数据，包括剪贴板内容、传输文件以及智能卡PINs。攻击者还可模拟登录该机器的其它用户并获得对受害者重定向设备的访问权限，这些设备包括USB设备、硬盘驱动等。  
  
CyberArk 公司指出，“这可导致数据隐私、横向移动和提权问题。”  
  
研究人员指出，该漏洞存在的原因是因为named 管道权限在远程桌面服务中处理不当，从而导致具有一般权限的用户能够“在其它联网会话中接管 RDP 虚拟频道。” 该公司解释称，“named 管道的创建方式可使系统上的每名用户以同样的名称创建额外的named管道服务器实例。”  
  
最初的补丁更改了管道权限，因此可防止一般用户创建 named管道服务器。然而，它并未解决和创建第一个管道服务器时相关联的风险，即用户可为后续实例设置权限的风险。  
  
研究人员指出，“假设以同样的名称创建多个管道实例，则传递给 CreateNamedPipe() 第一个调用的安全描述符可用于所有的实例。在后续调用中，可通过不同的安全描述符但会被忽略。因此，如攻击者创建了第一个管道实例，则可控制其它实例的权限。”  
  
2022年4月的补丁为新的管道生成新的GUID，从而阻止攻击者预测洗衣歌管道名称，而管道服务器是通过新的唯一名称创建的。此外，微软引入另外一个控制检查named 管道服务器进程ID 的当前进程ID。  
  
研究人员指出，“这是额外的控制保证，即使攻击者能够预测GUID，但攻击将无法起作用，因为它们会有不同的进程ID。在这种情况下，同样的进程创建了管道服务器和客户端（管道客户端句柄随后返回到调用进程），因此很容易执行该检查。通过这些更改，该漏洞的风险被合理地解决了。”  
  
技术详  
情可见：  
https://www.cyberark.com/resources/threat-research-blog/that-pipe-is-still-leaking-revisiting-the-rdp-named-pipe-vulnerability  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[警惕！这个微软Office 0day 已遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512040&idx=2&sn=471a3a8e0d63d1a8f6e3ef80341a47da&chksm=ea949e82dde3179403465e55b09d8a07b71abc9713b4e2d87959a9daf063f59c9b4fa6b6f4f1&scene=21#wechat_redirect)  
  
  
[Follina呢？IE呢？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512333&idx=1&sn=6128b41ba0c0e7cfb51d22309b0ef8b3&chksm=ea948067dde309710a0d113203e4191cd5f70ab1d6a99f6ebe4de65a44736cbd6332eaa8f924&scene=21#wechat_redirect)  
  
  
[微软反向 RDP 漏洞补丁不当，第三方 RDP 客户端易受攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493064&idx=1&sn=519c74d06bd95d3f76b3eb2693449215&chksm=ea94d4a2dde35db4de40170333d4c9d757477ebe3d860eae5bbd98855962ebfb470239d159b5&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/details-twice-patched-windows-rdp-vulnerability-disclosed  
  
  
题图：  
Pixab  
ay License  
  
  
  
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
