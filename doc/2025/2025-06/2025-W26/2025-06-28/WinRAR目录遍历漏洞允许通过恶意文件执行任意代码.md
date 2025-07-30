> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQyODI4Ng==&mid=2247497115&idx=1&sn=4673c140780854d180246684f5bfb049

#  WinRAR目录遍历漏洞允许通过恶意文件执行任意代码  
 网络安全与人工智能研究中心   2025-06-28 02:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHibykdgfR7Bfd3D5gQ9smYkhUSicwuicfUyAydJhQTRo5N6XPD9LxvGALWdC7ZZVI2R6skN0r8WUhrjcA/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibwpXMNl16ibj6lYK4CFmqtsXcwZovoW6PnutFxkjSMaNkibTfRCg1JpPlLo6uv0icNyZIauKhv0tibSUA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part01**  
  
### 漏洞概述  
  
  
1. WinRAR软件中存在一个高危漏洞（CVE-2025-6218），攻击者可利用该软件处理压缩包内文件路径的方式执行任意代码  
  
  
2. 该漏洞允许攻击者使用特制的包含目录遍历序列的压缩文件，最终实现远程代码执行  
  
  
3. 漏洞利用需要用户交互，如下载或打开恶意压缩包，或访问被攻陷的网页  
  
  
4. RARLAB已发布安全更新，用户应立即升级至最新版本以保护系统安全  
  
  
**Part02**  
  
### 漏洞详情  
  
  
###   
  
RARLAB公司的WinRAR压缩软件中发现了一个严重安全漏洞，远程攻击者可通过恶意压缩文件执行任意代码。该漏洞编号为CVE-2025-6218，CVSS评分为7.8分，影响这款广泛使用的文件压缩工具处理压缩包内目录路径的方式。  
  
  
远程代码执行漏洞  
  
  
该目录遍历漏洞被正式记录为ZDI-25-409，对全球WinRAR用户构成重大安全风险。这个远程代码执行（RCE）漏洞允许攻击者在当前用户权限下执行恶意代码，但需要用户交互才能成功利用。  
  
  
漏洞的CVSS向量字符串AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H表明，在机密性、完整性和可用性方面都具有高度影响。漏洞利用机制主要基于压缩包内特制的文件路径，这些路径可能导致WinRAR进程遍历到非预期的目录。  
  
  
这种路径遍历攻击绕过了正常的安全边界，使攻击者能够将文件写入预期解压目录之外的位置。此类漏洞尤其危险，因为与其他攻击技术结合使用时，可能导致系统完全被攻陷。  
  
  
**Part03**  
  
### 技术分析  
  
  
技术分析显示，该漏洞存在于WinRAR处理压缩包文件的路径处理例程中。发现并报告该漏洞的安全研究员whs3-detonator确认，包含恶意目录路径的特制压缩文件可以操控解压过程。攻击需要目标用户访问恶意网页或打开恶意压缩文件，因此容易受到社会工程攻击。  
  
  
技术利用手段基于嵌入在压缩文件结构中的目录遍历序列。这些序列可能包含"../"等相对路径指示符，使攻击者能够导航到预期解压目录之外的位置。一旦成功，该漏洞便能在运行WinRAR的用户权限下执行任意代码。  
  
  
**Part04**  
  
### 风险因素  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibwpXMNl16ibj6lYK4CFmqtsXg5aCia0ovw4BE4lJstXyX1rppW2phVRavicsoiakO6SNAicLGcpyRdZxhA/640?wx_fmt=png&from=appmsg "")  
  
  
**Part05**  
  
### 缓解措施  
  
  
  
RARLAB已迅速响应这一关键安全问题，发布了WinRAR更新版本。建议用户升级至WinRAR 7.11版本，该版本具有更快的速度、改进的可用性和新的自定义选项。  
  
  
厂商已发布有关安全更新的详细信息，强调应用此补丁以防止潜在利用的重要性。由于该漏洞的高严重性评级以及针对系统的远程代码执行攻击可能性，各组织应优先考虑此更新。  
  
  
**参考来源：**  
  
WinRAR Directory Vulnerability Allows Arbitrary Code Execution Using a Malicious File  
https://cybersecuritynews.com/winrar-vulnerability/  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibykdgfR7Bfd3D5gQ9smYkhUMk71re53Z8Xju62nS9agGCNgUNjPibQP7YZthr22UXppftxLN0kp97A/640?wx_fmt=png&from=appmsg "")  
  
来源｜“FreeBuf”微信公众号  
  
编辑｜音叶泽  
  
审核｜秦川原  
  
  
  
