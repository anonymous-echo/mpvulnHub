#  Windows Server 2025 漏洞（BadSuccessor）暴露 Active Directory 帐户   
 Ots安全   2025-05-25 06:53  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tac1Bm9A5CrNtiag6BFQWGDbvz41BpNlo7gUkI6OmCIdRTia6azicamjbzoicFd40tTkY0BsEknQZttXicg/640?wx_fmt=webp&from=appmsg "")  
  
Windows Server 2025中发现了一个严重漏洞，威胁行为者可以利用该漏洞提升权限并访问 Active Directory 中的任意用户帐户。该漏洞存在于新推出的委托托管服务帐户 (dMSA) 功能中，该功能最初是为了抵御 Kerberoasting 攻击而实施的。讽刺的是，这项功能如今却成为了一种名为BadSuccessor 的新型攻击技术的基础。  
  
dMSA 功能旨在用更安全的替代方案取代旧版服务帐户。根据微软的文档，dMSA 会阻止使用原始帐户密码进行身份验证，并将身份验证请求重定向到本地安全机构 (LSA)，从而授予 dMSA 先前分配给其前任帐户的所有权限。此外，dMSA 还会自主识别使用旧版帐户的设备，并相应地扩展其影响力。  
  
Akamai的研究表明，在近 91% 的审计基础设施中，域管理员组以外的用户拥有足够的权限来实施攻击。该漏洞的危险在于 Kerberos身份验证的处理方式：在此过程中，密钥分发中心 (KDC) 不仅会在票据中嵌入 dMSA 的安全标识符 (SID)，还会嵌入被替换帐户及其关联组的标识符。  
  
这会产生一个漏洞：通过模拟迁移，攻击者可以将 dMSA 权限转移到任何其他帐户，包括拥有域管理员权限的帐户。至关重要的是，此操作无需访问原始帐户，只需拥有对任何 dMSA 对象属性的写入权限即可。一旦此链接被更改，dMSA 将立即继承所有权限，就像发生了合法迁移一样。  
  
尽管该漏洞可能造成灾难性后果，但微软仍将其严重程度评级定为中等，并表示利用该漏洞需要特定权限，因此尚未立即发布补丁。不过，目前修复程序正在开发中。  
  
在此期间，建议各组织限制 dMSA 的创建，并加强与其使用相关的访问控制。Akamai 还发布了一个PowerShell脚本，可帮助识别所有有权创建 dMSA 的实体，以及允许创建 dMSA 的组织单位。  
  
据研究团队称，此漏洞暴露了一条以前未知的隐蔽途径，可以入侵域中的任何用户帐户，授予相当于 DCSync 权限的访问权限——通常在针对域控制器的攻击中利用。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
