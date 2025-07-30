#  虚假WinRAR PoC exp 释放恶意软件VenomRAT   
Bill Toulas  代码卫士   2023-09-21 18:11  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**一名黑客正在GitHub 上传播虚假的 WinRAR 最新漏洞 PoC，试图通过恶意软件VenomRAT 来感染下载工具。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSxg65qmpvVjN13NNac2hWgtmY0QicKic0zbIicQ8xD2yO9bUGaSLM3esWvtD1Clcm41sQtD3F7DjWqg/640?wx_fmt=png "")  
  
  
Palo Alto Networks 公司Unit 42 研究团队发现了该虚假利用，并指出攻击者在2023年8月21日将恶意代码上传到 GitHub 平台。虽然攻击已不再活跃，但它强调了从 GitHub 获取PoC 并在未经过安全审查的情况下进行运行的风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSxg65qmpvVjN13NNac2hWgtmY0QicKic0zbIicQ8xD2yO9bUGaSLM3esWvtD1Clcm41sQtD3F7DjWqg/640?wx_fmt=png "")  
  
**传播WinRAR PoC**  
  
  
  
该虚假PoC 针对的是CVE-2023-40477。该漏洞是一个任意代码执行漏洞，攻击者可在 WinRAR 6.23之前的版本打开特殊构造的 RAR 文件时触发该漏洞。  
  
趋势科技ZDI 在6月8日发现并将该漏洞告知WinRAR，但在8月17日才将其公开披露。WinRAR 在8月2日发布的6.23版本中修复了该漏洞。  
  
昵称为“walersplonk”的威胁行动者利用该机会通过虚假 PoC 传播恶意软件。该恶意人员在 README 文件中包含了一份概述以及 Streamable 视频展示如何利用该 PoC，从而增加了对该恶意包的合法性。然而，Unit 42 报告称该 PoC 实际上是对CVE-2023-25157的修改版本，后者是影响 GeoServer 的严重的 SQL 注入漏洞。执行该 PoC 时并不会运行该 exp，而是创建一个批量脚本，下载编码的 PowerShell 脚本并在主机上进行执行。该脚本下载恶意软件 VenomRAT 并创建调度任务每隔三分钟运行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSxg65qmpvVjN13NNac2hWgtmY0QicKic0zbIicQ8xD2yO9bUGaSLM3esWvtD1Clcm41sQtD3F7DjWqg/640?wx_fmt=png "")  
  
**VenomRAT 感染**  
  
  
  
一旦 VenomRAT 在 Windows 设备上启动，就会执行键记录器，记录所有键击并将它们写到本地存储的文本文件中。  
  
之后，该恶意软件与 C2 服务器建立通信，并接收到如下九个命令之一，在受感染设备上进行执行：  
  
1.  
 plu_gin: 激活在注册表存储的插件。  
  
2.  
 HVNCStop: 停止 “cvtres” 进程。  
  
3. loadofflinelog: 从 %APPDATA% 发送离线键记录器。  
  
4.  
 save_Plugin: 将插件存储到硬件ID下的注册表。  
  
5.  
 runningapp: 显示活跃进程。  
  
6.  
 keylogsetting: 更新 %APPDATA% 中的键记录文件。  
  
7. init_reg: 删除硬件ID下软件注册表中的子键。  
  
8. Po_ng: 测量从PING到C2服务器与接受该命令的之间的时间。  
  
9.  
  filterinfo: 列出注册表中所安装app与活跃进程。  
  
由于该恶意软件可用于部署其它payload 和窃取凭据，执行该虚假 PoC 的任何人都可修改拥有账户的所有网站和环境中的密码。  
  
从研究人员分享的事件时间线可知，威胁行动者早在WinRAR 漏洞公开披露前就准备好攻击的基础设施和payload，之后等待构造欺骗性 PoC 的时刻。这表明这些攻击者未来可能会利用安全社区对新披露漏洞的高度关注来传播虚假 PoC。  
  
GitHub 上的虚假 PoC 是一种已为人熟知的攻击方法，威胁行动者用这种方法攻击其它犯罪分子和安全研究员。2022年末，研究人员发现数千个 GitHub 仓库推广多种漏洞的虚假 PoC 利用，其中多个仓库部署恶意软件、恶意 PowerShell 脚本、隐藏的信息窃取下载工具以及 Cobalt Strike 释放器。2023年6月，伪装成网络安全研究员的攻击者发布多个虚假 0day 利用，通过恶意软件攻击 Linux 和 Windows 系统。  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[WinRAR 高危漏洞可导致设备遭控制](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517421&idx=2&sn=dc8679fac09663662db54780d91b1a0b&chksm=ea94b587dde33c919ddad97730995e5dbd757afebf8436ee2cae3d3f3ecbc90788b004e929e9&scene=21#wechat_redirect)  
  
  
[WinRAR 试用版曝漏洞：免费软件并不“免费“](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508508&idx=2&sn=7461abcdc3b2e72adf3cd86e791d8f0b&chksm=ea949376dde31a603153dfd8cd929ae8a410da926c310dc781dd6ae353980565f0ca7be3054e&scene=21#wechat_redirect)  
  
  
[WinRAR 被曝已存在19年的RCE 漏洞，影响全球5亿用户](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489261&idx=3&sn=f052381d92ad571833279752278f1d6d&chksm=ea972787dde0ae91d07535733af0e80217ccc1c2d6bdec893fbeac24b069ef0891b6b311040d&scene=21#wechat_redirect)  
  
  
[勒索软件CTB-Faker使用WinRAR将数据锁定为带有密码保护的ZIP文件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485713&idx=1&sn=c64654801d9c7251f1f647bc0bf7a816&chksm=ea97387bdde0b16d3fd49b5a14caff5bd56489e51e002f994ef01fb79dcb7611badb77c9f10b&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/fake-winrar-proof-of-concept-exploit-drops-venomrat-malware/  
  
  
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
  
