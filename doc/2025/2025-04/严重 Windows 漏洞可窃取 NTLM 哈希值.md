#  严重 Windows 漏洞可窃取 NTLM 哈希值   
 Ots安全   2025-04-20 06:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tado6aEFCZDSvapes2FSkyQVfYC2tcD9ZbSPOolgpicFafwWULLd7EN9pCVmYGPgs42fh5hxUR3dkkA/640?wx_fmt=webp&from=appmsg "")  
  
黑客已开始积极利用新发现的 Windows 文件处理漏洞.library-ms，该漏洞可远程窃取用户 NTLM 哈希值。该漏洞编号为 CVE-2025-24054，已在微软 3 月份的安全更新中得到修复，但最初被认为不太可能被利用。然而，在补丁发布几天后，Check Point的研究人员就观察到了针对政府机构和私营企业的真实攻击。  
  
NTLM 是微软系统中使用的一种过时的身份验证协议，长期以来一直被认为不安全。尽管它不以纯文本形式传输密码，但截获的哈希值容易受到暴力破解或重放攻击。由于这些固有风险，微软已逐步淘汰 NTLM，转而采用 Kerberos 等更强大的替代方案。  
  
据 Check Point 称，攻击者正在分发包含 Dropbox 链接的网络钓鱼电子邮件，这些链接指向 ZIP 压缩包。这些压缩包中包含一个特制.library-ms文件——一种用于显示虚拟图书馆的合法 Windows 格式。然而，在本例中，该文件被配置为发起与攻击者控制的远程 SMB 服务器的连接。  
  
一旦提取存档，Windows 就会自动与该文件交互，并启动与远程服务器的连接。在此交互过程中，系统开始通过 NTLM 进行身份验证，无意中将用户哈希值发送到恶意服务器。令人担忧的是，只需与该文件进行一次交互（例如单击或查看其属性）即可触发该漏洞。  
  
后续事件表明，攻击手段愈发先进，.library-ms文件以独立附件形式发送，无需 ZIP 压缩。在这种情况下，只需下载文件（甚至无需打开）即可激活漏洞利用程序。这显著提高了威胁级别，尤其对于那些习惯于随意查看电子邮件附件的员工而言。  
  
该存档通常还包含其他带有扩展名的组件，例如.url、.website和.link，这些组件利用了较旧的 NTLM 哈希泄漏漏洞。这些组件似乎在主要漏洞利用失败时充当了后备机制。  
  
尤其令人担忧的是，触发该攻击所需的用户交互非常少。尽管该漏洞被归类为中等严重程度，但其实际后果可能远比这严重得多——从身份验证绕过到特权账户泄露。  
  
安全专家强烈敦促所有组织立即应用三月补丁星期二更新，并在不需要技术兼容性的地方完全禁用 NTLM 身份验证。  
  
广告  
  
[](https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247529175&idx=1&sn=e81fc82c778809f8b728b880e0097a35&scene=21#wechat_redirect)  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
