#  Sunder：旨在利用 BYOVD 漏洞的 Windows rootkit   
 Ots安全   2025-04-25 11:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
模仿 Lazarus Group 的 FudModule rootkit的 Windows rootkit. 参考 这个版本的 Sunder 以 appid.sys 驱动程序漏洞为例，该漏洞被 Lazarus Group FudModule rootkit 利用。  
  
Sunder 的 GitHub 仓库中存在漏洞的驱动程序是戴尔的 dbutil_2_3.sys 驱动程序，因为它是一个简单的漏洞，因此更容易读取 rootkit 特定的代码。该驱动程序 已被微软屏蔽 。执行以下命令以允许被屏蔽的驱动程序 （Windows 11 上无需 bcdedit 命令）：  
  
```
bcdedit /debug on powershell -c Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config\ -Name VulnerableDriverBlocklistEnable 0shutdown -r
```  
  
  
此 rootkit 旨在利用各种内核漏洞。这允许您更改用于获取内核读写原语的易受攻击的驱动程序。更新易受攻击的驱动程序对于规避 Microsoft 的 阻止驱动程序列表至关重要。  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taceQtGiaZyH4CbibLNepj1CyOib5XbxawQfeibRicLnmpauAJIadwkIJc0yE4KN8mendcJlB2C3jMv3Htw/640?wx_fmt=webp&from=appmsg "")  
  
Sunder 包含以下有效载荷：  
- 令牌窃取——从任意进程窃取令牌（生成 cmd.exe，但可以修改为生成任意进程）  
  
- 令牌升级——为给定进程添加权限  
  
- ACL 编辑——无论完整性或 PPL 保护级别如何，都打开目标进程的句柄  
  
- 注意：ACL 编辑的偏移量仅针对 winlogon.exe 进行了测试，可能需要针对其他目标进程进行更新  
  
- 启用/禁用 PPL – 篡改过程 PPL 保护级别  
  
- 禁用 ETWti – 禁用 ETW 威胁情报（内核模式挂钩）  
  
- 清除进程回调 – 清除所有进程创建通知回调  
  
- 清除线程回调 – 清除所有线程创建通知回调  
  
- 清除 DLL 回调 – 清除所有 DLL 图像加载通知回调  
  
稳定  
  
dbutil_2_3.sys 漏洞 (CVE-2021-21551) 高度稳定。后利用功能对某些 Windows 结构体使用了硬编码偏移量；因此，在未经测试的操作系统版本上执行该 rootkit 可能会导致蓝屏死机 (BSOD)。  
  
该rootkit已在以下Windows版本上进行了测试：  
- Windows 10 专业版 19045  
  
- Windows 11 企业版 22621  
  
- Windows 11 企业版 26100  
  
项目地址：  
  
https://github.com/ColeHouston/Sunder?tab=readme-ov-file#requirements  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
