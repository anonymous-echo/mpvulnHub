> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458596239&idx=3&sn=d782404acf8421ef63b6789bd3a99a90

#  WinRAR现高危漏洞，恶意文件可致远程代码执行  
看雪学苑  看雪学苑   2025-06-24 10:03  
  
近期，WinRAR软件被发现存在一个严重的安全漏洞（CVE-2025-6218），  
该漏洞允许攻击者通过恶意档案文件执行任意代码。  
此漏洞的CVSS评分为7.8，属于高危漏洞，主要影响WinRAR处理档案文件中目录路径的方式。  
  
  
具体来说，这是一种目录遍历漏洞，  
攻击者可以利用精心制作的档案文件，其中包含特殊的目录遍历序列，从而绕过正常的安全限制，将文件写入到预期解压目录之外的位置。  
一旦成功，攻击者就能以运行WinRAR的用户权限执行恶意代码，可能导致系统完全被控制，且这种漏洞很容易与其他攻击手段结合，造成更严重的后果。  
  
  
从技术层面分析，该漏洞存在于WinRAR处理档案文件时的文件路径处理程序中。安全研究人员whs3-detonator发现了这一漏洞并上报，指出含有恶意目录路径的特殊档案文件能够操纵解压过程。攻击者需要诱使目标用户打开恶意档案文件或访问被恶意篡改的网页，这使得该漏洞容易受到社会工程学攻击的影响。攻击者会在档案文件结构中嵌入目录遍历序列，如“../”等相对路径标识符，从而实现路径遍历攻击，进而达到远程代码执行的目的。  
  
  
此次受影响的产品为RARLAB WinRAR（2025年6月19日之前发布的所有版本），其影响为远程代码执行（RCE），且需要用户交互（打开恶意档案文件或访问被篡改的网页）作为利用前提，CVSS 3.1评分为7.8（高危）。  
  
  
值得庆幸的是，RARLAB已经迅速发布了更新，建议用户尽快升级到WinRAR 7.11版本，鉴于该漏洞的高危级别以及可能导致针对系统的远程代码执行攻击，各组织机构应优先进行更新。  
  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
