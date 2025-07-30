#  Microsoft 4 月 CVE 漏洞预警   
 网新安服   2024-04-10 18:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6YakorxwBv9OVxREDT20IjMqvbKc4icFgxJwDAYgWl6ttLkvLpwKVoqw/640?wx_fmt=gif "")  
  
点击上方蓝字关注我们，获取最新消息  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6ibt323b0qdibplmTcL1ibSPicweE7SV0zUESdKqrNiaPxZmfslRIbXoWVzg/640?wx_fmt=png "")  
  
1  
  
基本情况  
  
4 月份，Microsoft 发布了 149 个漏洞补丁，解决了 Microsoft Windows 和 Windows 组件、Office 和 Office组件、  
Azure、.NET 框架 和 Visual Studio、  
SQL Server、DNS Server、Windows Defender、Bitlocker  
 和 Windows Secure Boot 相关的问题  
。  
  
  
在本次公布的 149 个漏洞中，3个被评为严重，142 个被评为重要，1 个被标记为 "已受攻击"  
。  
  
  
在本月的更新中，ZDI 列出了 4 个值得关注的漏洞，分别是 CVE-2024-29988、CVE-2024-20678、CVE-2024-20670、  
CVE-2024-26221  
。  
  
  
2  
  
漏洞等级  
  
**CVSS基本分数：**  
<table><tbody><tr><td width="258" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;background-color: rgb(255, 255, 255);">CVE-2024-29988</span></td><td width="258" valign="top" style="word-break: break-all;">8.8</td></tr><tr><td width="258" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;background-color: rgb(255, 255, 255);">CVE-2024-20678</span></td><td width="258" valign="top" style="word-break: break-all;">8.8</td></tr><tr><td width="258" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-size: 14px;letter-spacing: 1.53333px;text-align: left;background-color: rgb(255, 255, 255);">CVE-2024-20670</span></td><td width="258" valign="top" style="word-break: break-all;">8.1</td></tr><tr><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;">CVE-2024-26221<br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;">7.2<br/></td></tr></tbody></table>  
###   
  
  
3  
  
漏洞描述  
  
**CVE-2024-29988：SmartScreen 提示安全功能绕过漏洞**  
  
由于 SmartScreen 提示安全功能保护机制失效，未经身份认证的远程攻击者通过发送带有经特殊设计的文件，并诱使受害者与之交互，可以绕过 "网页标记"（Mark of the Web，MotW）功能，从而在目标系统上执行恶意代码。因此，企业方面应尽快安装该补丁以防范潜在威  
胁。  
  
****  
  
**CVE-2024-20678：远程过程调用运行时远程代码执行漏洞**  
  
  
此漏洞不需要管理员或其他提升权限，任何经过身份验证的用户都可能触发此漏洞。要成功利用此漏洞，需要经过身份验证的攻击者向 RPC 主机发送特制的 RPC 调用，这可能会导致在服务器端使用与 RPC 服务相同的权限远程执行代码。因此，对于企业而言，应尽快更新该补丁。  
  
  
**CVE-2024-20670：Outlook for Windows 欺骗****漏洞******  
  
外部攻击者可以发送经特殊设计的电子邮件，并诱使受害者点击执行邮件中的恶意 URL，从而导致建立从受害者到由攻击者控制的不受信位置的连接。这会将受害者的 Net-NTLMv2 哈希值泄漏到不受信任的网络，而后攻击者可以将其中继到另一个服务，并作为受害者进行身份验证  
。  
  
  
**CVE-2024-26221：Windows DNS 服务器远程代码执行漏洞**  
  
  
在基于网络的攻击中，  
此漏洞  
需要攻击者拥有查询域名服务 (DNS) 的权限。并且  
此漏洞存在一个计时因素，如果 DNS 查询计时正确，攻击者就可以在目标服务器上执行任意代码。  
因此，  
对于企业而言，应尽快更新该补丁。  
  
  
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
  
另外，对于不能自动更新的系统版本，可参考以下链接下载适用于该系统的 4 月补丁并安装：  
  
https://msrc.microsoft.com/update-guide/releaseNote/2024-Apr  
  
  
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
  
