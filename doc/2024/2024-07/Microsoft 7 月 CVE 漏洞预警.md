#  Microsoft 7 月 CVE 漏洞预警   
 网新安服   2024-07-10 18:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6YakorxwBv9OVxREDT20IjMqvbKc4icFgxJwDAYgWl6ttLkvLpwKVoqw/640?wx_fmt=gif "")  
  
点击上方蓝字关注我们，获取最新消息  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6ibt323b0qdibplmTcL1ibSPicweE7SV0zUESdKqrNiaPxZmfslRIbXoWVzg/640?wx_fmt=png "")  
  
1  
  
基本情况  
  
7 月份，Microsoft 发布了 139 个漏洞补丁，解决了 Microsoft Windows 和 Windows 组件、Office 和 Office 组件、  
Azure、.NET 框架 和 Visual Studio、Defender for IoT、  
SQL Server、Windows Hyper-V、Bitlocker  
、Windows Secure Boot、Remote Desktop 和相关的问题  
。  
  
  
在本次公布的 139 个漏洞中，5 个被评为严重，133 个被评为重要，2 个被标记为 "已受攻击"  
。  
  
  
在本月的更新中，ZDI 列出了 5 个值得关注的漏洞，分别是 CVE-2024-38080、CVE-2024-38112、CVE-2024-38077、  
CVE-2024-38060、CVE-2024-38023  
。  
  
  
2  
  
漏洞等级  
  
**CVSS基本分数：**  
<table><tbody><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-38080</span></td><td width="259" valign="top" style="word-break: break-all;">7.8<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-38112</span><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);"></span></td><td width="259" valign="top" style="word-break: break-all;">7.5<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-38077</span></td><td width="259" valign="top" style="word-break: break-all;">9.8<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-38060</span></td><td width="259" valign="top" style="word-break: break-all;">8.8<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-38023</span></td><td width="259" valign="top" style="word-break: break-all;">7.2<br/></td></tr></tbody></table>  
###   
  
  
3  
  
漏洞描述  
  
**CVE-2024-38080：Windows Hyper-V 特权提升漏洞**  
  
该漏洞已被确认在野外利用，成功利用后可使本地用户提升至系统权限。该漏洞是由于 Windows Hyper-V 组件中的整数溢出而导致的，经过身份认证的本地用户可以触发整数溢出并以 SYSTEM 权限执行任意代码。因此，企业方面应尽快安装该补丁以防范潜在威  
胁。  
  
****  
  
**CVE-2024-38112：Windows MSHTML Platform 欺骗漏洞**  
  
  
该漏洞是由于输入验证不当而导致的，要利用此漏洞，远程攻击者需要诱使受害者执行特制文件。值得一提的是，该漏洞已被标记为在野利用。因此，  
对于企业而言，应尽快更新该补丁。  
  
  
**CVE-2024-38077：****Windows 远程桌面授权服务远程代码执行漏洞**********  
  
该漏洞允许未经身份验证的远程攻击者在受影响的系统上执行任意代码。漏洞是由 Windows 远程桌面授权服务中的基于堆的缓冲区溢出引起的。攻击者可以通过发送特制请求到受影响的服务来利用此漏洞，进而完全控制系统。该漏洞的 CVSS 评分高达 9.8，对于企业而言，应尽快部署修复补丁，以避免受到该漏洞的影响。  
  
  
**CVE-2024-38060：Windows Imaging Component 远程代码执行漏洞**  
  
该漏洞允许经过身份验证的攻击者在目标系统上执行任意代码。漏洞源于 Windows Imaging 组件中的边界错误。攻击者可以通过将恶意 TIFF 文件上传到服务器来利用此漏洞。企业应尽快安装补丁，以防范潜在的安全风险。  
  
  
**CVE-2024-38023：Microsoft SharePoint Server 远程代码执行漏洞**  
  
  
具有网站所有者或更高权限的经过身份验证的攻击者可以将特制文件上载到目标 SharePoint Server，并构建专门的 API 请求以触发文件参数的反序列化。这将使攻击者能够在 SharePoint Server 的上下文中执行远程代码。对于企业而言，  
应尽快更新该补丁。  
  
  
‍4  
  
安全建议  
  
‍  
  
可以采用以下官方解决方案及缓解  
方案来防护此漏洞：  
  
**Windows自动更新**  
  
Windows系统默认启用 Microsoft Update，当检测到可用更新时，将会自动下载更新并在下一次启动时安装。还可通过以下步骤快速安装更新：  
  
1、点击“开始菜单”或按 Windows 快捷键，点击进入“设置”。  
  
2、选择“更新和安全”，进入“Windows更新”（Windows Server 2012 以及 Windows Server 2012 R2 可通过控制面板进入“Windows更新”，步骤为“控制面板”-> “系统和安全”->“Windows更新”）。  
  
3、选择“检查更新”，等待系统将自动检查并下载可用更新。  
  
4、重启计算机，安装更新。  
  
系统重新启动后，可通过进入“Windows更新”->“查看更新历史记录”查看是否成功安装了更新。对于没有成功安装的更新，可以点击该更新名称进入微软官方更新描述  链接，点击最新的 SSU 名称并在新链接中点击 “Microsoft 更新目录”，然后在新链接中选择适用于目标系统的补丁进行下载并安装。  
  
**手动安装补丁**  
  
另外，对于不能自动更新的系统版本，可参考以下链接下载适用于该系统的 7 月补丁并安装：  
  
https://msrc.microsoft.com/update-guide/releaseNote/2024-Jul  
  
  
5  
  
参考链接  
  
```
```  
```
```  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OT1Aib4N17tOicAE1WiaS3ibBFkRvmNLYPgnjJib9OMGzuSeZfBdE1EHFI0QyyZZ10fkTdUkhibW90vhvua9AVWYoGng/640?wx_fmt=jpeg "")  
  
**白盾，实时阻断有害攻击**  
  
