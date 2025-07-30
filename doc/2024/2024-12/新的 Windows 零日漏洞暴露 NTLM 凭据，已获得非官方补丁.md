#  新的 Windows 零日漏洞暴露 NTLM 凭据，已获得非官方补丁   
 Ots安全   2024-12-07 05:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taexwF9DfIWMChSmKW0eJs6mdg2TYnNxobDs1yDfjyaCYW04iaKOb9LichEw4EBAPXa4JzCayYnWgnoA/640?wx_fmt=webp&from=appmsg "")  
  
发现了一个新的零日漏洞，攻击者只需诱骗目标查看 Windows 资源管理器中的恶意文件即可捕获 NTLM 凭据。  
  
该漏洞由为 Windows 旧版本提供非官方支持的平台 0patch 团队发现，并已报告给微软。但目前尚未发布官方修复程序。  
  
据 0patch 称，该问题目前没有 CVE ID，影响从 Windows 7 和 Server 2008 R2 到最新的 Windows 11 24H2 和 Server 2022 的所有 Windows 版本。  
  
**无需点击的漏洞**  
  
0patch 一直隐瞒该零日漏洞的技术细节，直至微软提供官方修复程序，以防止引发大规模恶意利用。  
  
研究人员解释说，攻击只需在文件资源管理器中查看特制的恶意文件即可进行，因此无需打开该文件。  
  
0patch 解释道：“该漏洞允许攻击者通过让用户在 Windows 资源管理器中查看恶意文件来获取用户的 NTLM 凭据 - 例如，打开包含此类文件的共享文件夹或 USB 磁盘，或者查看之前从攻击者的网页自动下载此类文件的下载文件夹。”  
  
虽然 0Patch 没有分享有关该漏洞的更多细节，但 BleepingComputer 了解到它会强制将 NTLM 连接传出到远程共享。这会导致 Windows 自动向登录用户发送 NTLM 哈希，然后攻击者就可以窃取这些哈希。  
  
正如 反复证明的那样，这些哈希可以被破解，从而使威胁行为者能够访问登录名和纯文本密码。微软一年前宣布计划 在未来的 Windows 11 中取消 NTLM 身份验证协议。  
  
0patch 指出这是他们最近向微软报告的第三个零日漏洞，但该供应商尚未立即采取行动解决。  
  
另外两个漏洞分别是上个月底曝光的 Windows Server 2012 上的Mark of the Web (MotW) 绕过漏洞，以及10 月底披露的允许远程 NTLM 凭据窃取的Windows 主题漏洞。这两个漏洞目前仍未得到修复。  
  
0patch 表示，过去披露的其他 NTLM 哈希泄露漏洞，如PetitPotam、PrinterBug/SpoolSample和DFSCoerce，在最新的 Windows 版本中都没有得到官方修复，用户只能使用 0patch 提供的微补丁。  
  
**提供免费微补丁**  
  
0patch 将向其平台上注册的所有用户提供最新 NTLM 零日漏洞的免费微补丁，直到微软提供官方修复为止。  
  
PRO 和 Enterprise 帐户已经自动收到安全微补丁，除非其配置明确阻止这样做。  
  
要接收此非官方补丁，请在0patch Central上创建一个免费帐户，开始免费试用，然后安装代理并允许其自动应用适当的微补丁。无需重新启动。   
  
不想使用 0patch 提供的非官方补丁的用户可考虑使用“安全设置 > 本地策略 > 安全选项”中的组策略关闭 NTLM 身份验证，并配置“网络安全：限制 NTLM”策略。也可以通过注册表修改来实现。  
  
BleepingComputer 已联系微软询问该漏洞及其解决计划，但我们仍在等待回复。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
