#  上万台 Juniper 设备易受未认证RCE漏洞攻击   
Bill Toulas  代码卫士   2023-09-19 17:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**约1.2万台 Juniper SRX 防火墙和EX 交换机易受无文件远程代码执行漏洞影响，可导致攻击者在无需认证的情况下利用它。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTap9prq49883yN1Ee9PdaictnAyk7fD3owREA6a9WVlV3Yg3icyrQq2uDzrO8j4ztt5D4JfoBDmoBQ/640?wx_fmt=png "")  
  
  
8月份，Juniper 披露了多个“PHP环境变量操纵” (CVE-2023-36844/CVE-2023-36845) 和 “关键函数认证缺失” (CVE-2023-36836/CVE-2023-36847) 漏洞，它们仅为“中危”级别，CVSS 评分为5.3。然而，如果组合利用这些漏洞，则可视作严重的远程代码执行漏洞，CVSS评分达到9.8分。  
  
不久，watchtower 实验室发布技术报告发布了组合利用CVE-2023-36845和CVE-2023-36846的PoC，可通过将两份文件上传到易受攻击设备的方式实现远程执行代码。  
  
今天，VulnCheck 公司的漏洞安全研究员 Jacob Baines 发布另外一个 PoC 利用提到，只需CVE-2023-36845，绕过上传文件的要求，仍然能够实现RCE。他在 GitHub 上分享了一款免费的扫描器，帮助识别易受攻击的部署，结果表明数千台易受攻击的设备暴露在互联网上。报告解释称，“我们在本文展示了被Juniper 标记为‘中危’严重程度的漏洞CVE-2023-36845如何可在无需认证的情况下实现远程任意代码执行后果。我们已将多步骤（但非常好的）利用转变为可通过单个curl 命令就能编写的利用，且还影响更多（更老旧的）系统。”  
  
该漏洞的影响范围广泛且比所评级的“中危”级别的严重性更高，管理员必须立即采取补救措施。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTap9prq49883yN1Ee9PdaictnAyk7fD3owREA6a9WVlV3Yg3icyrQq2uDzrO8j4ztt5D4JfoBDmoBQ/640?wx_fmt=png "")  
  
**新的利用**  
  
  
  
Baines 表示自己购买了一台旧Juniper SRX210 防火墙用于测试，不过发现设备并不具有将文件上传到设备所需的 do_fileUpload() 功能，这实际上打破了 watchtower 的利用链。于是Baines 查看是否存在实现RCE的其它方式。  
  
Baines 发现可通过操纵环境变量的方式，绕过在目标服务器上上传两个文件的要求。Juniper 防火墙的 Appeweb web 服务器在运行 CGI 脚本时通过 stdin 来处理用户的HTTP 请求。攻击者可利用这一点诱骗系统识别伪 “file,”/dev/fd/o，并通过调整 PHPRC 环境变量和HTTP请求，显示敏感数据。  
  
接着，VulnCheck 利用 PHP 的 “auto_prepend_file” 和 “allow_url_include”特性通过 ://protocol 运行任意的PHP代码，而无需上传任何文件。  
  
话虽如此，CVE-2023-36845的CVSS评分为5.4，而从实际来看评分应当更高，因为无需组合利用其它任何漏洞即可实现RCE。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTap9prq49883yN1Ee9PdaictnAyk7fD3owREA6a9WVlV3Yg3icyrQq2uDzrO8j4ztt5D4JfoBDmoBQ/640?wx_fmt=png "")  
  
**影响和风险**  
  
  
  
CVE-2023-36845 影响EX系列和SRX系统的 Junos OS 版本如下：  
  
- 20.4R3-S8之前的所有版本  
  
- 21.1 版本 21.1R1及后续版本  
  
- 21.2R3-S6之前的21.2版本  
  
- 21.3R3-S5之前的21.3版本  
  
- 21.4R3-S5之前的21.4版本  
  
- 22.1R3-S3之前的22.1版本  
  
- 22.2R3-S2之前的22.2版本  
  
- 22.3R2-S2、22.3R3之前的22.3版本  
  
- 22.4R2-S1、22.4R3之前的22.4版本  
  
  
  
2023年8月17日，厂商通过发布安全更新修复了该漏洞。然而，由于最初评分较低，因此并未引起受影响用户足够多的重视，大多数人决定延迟应用修复。VulnCheck 网络扫描发现了14,951台Juniper 设备具有暴露在互联网上的 web 接口。从3000台设备样本来看，其中79%的设备易遭该RCE漏洞影响。如果将这一百分比应用到所有被暴露的设备，则互联网上可能存在1.18万台易受攻击设备。报告提到，Shadowserver 和 GreyNoise 发现攻击者侦查 Junos OS 端点，因此黑客已经利用该机会将CVE-2023-36845利用到攻击中。  
  
因此，Juniper 管理员必须尽快应用这些更新，因为该漏洞可用于获得对企业网络的初始访问权限。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA 发布未来三年的网络安全战略规划](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517346&idx=2&sn=f8b8d447e22f328cdc128ed00f298e18&chksm=ea94b5c8dde33cdeddbd3761e9725004df4716bf661a331900b198c60e54ea6f61ca0918869c&scene=21#wechat_redirect)  
  
  
[美国发布新的国家网络安全战略：软件安全责任转移，重视软件供应链安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515818&idx=1&sn=b5311898cb66921b319dbcd3daaaca1f&chksm=ea948fc0dde306d6047987b8223144cc81342c436e80e04c4a2d0b01b5b9c6248f3bc47053a7&scene=21#wechat_redirect)  
  
  
[美国国防部发布2018年网络战略](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488116&idx=1&sn=113a703ead708856522c5120bc15776f&chksm=ea97231edde0aa08e05d5606cf318f8b09391e1bb4c674fed4705d044317c1a668861ce0f7d0&scene=21#wechat_redirect)  
  
  
[美国国土安全部发布的网络安全新战略有哪些看点？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247487157&idx=1&sn=0109b8394c1e816088c5529d457660c1&chksm=ea973fdfdde0b6c9684301106b8d6e42f5bb8c3b8d07987edfbf9d7aa4ff057b0ecb8a3014a3&scene=21#wechat_redirect)  
  
  
[澳大利亚政府将重新考虑网络安全战略](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486067&idx=3&sn=0345ddcf866a9b80c1023ce07119cb8d&chksm=ea973b19dde0b20f9f54437c1197927412cfb73b2cee7c4937c52e5726e5514de07dcfdf2164&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/thousands-of-juniper-devices-vulnerable-to-unauthenticated-rce-flaw/  
  
  
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
  
