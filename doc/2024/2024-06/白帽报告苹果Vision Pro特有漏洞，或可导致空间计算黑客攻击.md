#  白帽报告苹果Vision Pro特有漏洞，或可导致空间计算黑客攻击   
 关键基础设施安全应急响应中心   2024-06-13 14:56  
  
苹果公司周一将 Vision Pro 虚拟现实头盔的操作系统 visionOS 更新到 1.2 版本，该版本修复了多个漏洞，其中包括可能是该产品特有的第一个安全漏洞，编号为 CVE-2024-27812。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ADshDICBtgvBdhgqzoUsX0PyBopCDIQ0QmkyZPm7pof32vxhcMJMDNibxdZXtXD8oPC22dyv8XUw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
visionOS 1.2 此次更新修复了近二十多个漏洞。其中绝大多数漏洞都存在于 visionOS 与其他苹果产品（如 iOS、macOS 和 tvOS）共享的组件中。这些漏洞可能导致任意代码执行、信息泄露、权限升级和拒绝服务（DoS）。  
  
其中，最突出的漏洞是 CVE-2024-27812。这似乎是 Vision Pro 耳机特有的唯一一个 CVE，因为除 visionOS 外，其他苹果产品的公告中都没有列出这个 CVE。  
  
据苹果公司称，CVE-2024-27812 与特制网页内容的处理有关，利用该漏洞会导致 DoS 攻击。苹果公司在公告中说：该问题已通过改进文件处理协议得到解决。  
  
Ryan Pickren 是苹果公司的网络安全研究员，在获得苹果公司批准之前，Pickren 未透露该漏洞的任何细节。但他表示，这和以往 Vision Pro 漏洞有着明显区别，这是Vision Pro 所特有的漏洞，并认为「这将有可能导致有史以来真正意义上的空间计算黑客攻击」。  
  
空间计算(spatial computing)技术可以参照现实的物理世界构建一个数字孪生世界，将现实的物理世界与数字的虚拟世界连接在一起。使我们能够进入并且操控 3D 空间，并用更多的信息和经验来增强现实世界。  
  
Vision Pro 作为虚拟现实代表产品，自发布日起就屡屡曝出存在严重的安全漏洞。  
  
此前麻省理工学院（MIT）一名博士生Joseph Ravichandran分享了苹果公司 visionOS 软件的一个内核漏洞，此时Vision Pro 头戴式耳机刚刚发布一天。该漏洞针对的是设备的操作系统，有可能被用来创建恶意软件、提供未经授权的访问或越狱，从而使任何人都可以使用耳机。  
  
Ravichandran在 X上发布帖子指出，这是世界上第一个针对 Vision Pro 的内核漏洞。为此苹果公司修改了用户指南，并指出对 vision OS 进行未经授权的修改会绕过安全功能，并可能导致许多问题，如安全漏洞、不稳定性以及被黑客入侵的 Apple Vision Pro 的电池寿命缩短。  
  
苹果公司强烈警告用户不要安装任何修改 visionOS 的软件，且由于未经授权修改 visionOS 违反了 visionOS 软件许可协议，因此可能会导致 Apple Vision Pro拒绝提供服务。苹果警告说，黑客攻击耳机可能导致iCloud、FaceTime和Apple Pay等服务中断，而使用推送通知的第三方应用程序也可能受到影响。  
  
**参考资料：**  
  
https://www.securityweek.com/apple-patches-vision-pro-vulnerability-used-in-first-ever-spatial-computing-hack/  
  
https://www.independent.co.uk/tech/apple-vision-pro-hack-jailbreak-b2491283.html  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
