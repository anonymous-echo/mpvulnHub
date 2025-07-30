#  Microsoft 11 月 CVE 漏洞预警   
 网新安服   2024-11-13 18:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6YakorxwBv9OVxREDT20IjMqvbKc4icFgxJwDAYgWl6ttLkvLpwKVoqw/640?wx_fmt=gif "")  
  
点击上方蓝字关注我们，获取最新消息  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6ibt323b0qdibplmTcL1ibSPicweE7SV0zUESdKqrNiaPxZmfslRIbXoWVzg/640?wx_fmt=png "")  
  
1  
  
基本情况  
  
11 月份，Microsoft 发布了 89 个漏洞补丁，解决了 Microsoft Office 和 Office 组件、  
Azure、.NET 和 Visual Studio、  
LightGBM、  
Exchange Server、SQL Server、TorchGeo、  
Hyper-V 和 Windows   
VMSwitch 相关的问题  
。  
  
  
在本次公布的 89 个漏洞中，4 个被评为严重，84 个被评为重要  
。  
  
  
在本月的更新中，ZDI 列出了 4 个值得关注的漏洞，分别是 CVE-2024-43451、CVE-2024-49039、CVE-2024-43639、  
CVE-2024-43498  
。  
  
  
2  
  
漏洞等级  
  
**CVSS基本分数：**  
<table><tbody><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-<span style="color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 1.53333px;text-decoration: none solid rgb(34, 34, 34);">43451</span></span></td><td width="259" valign="top" style="word-break: break-all;">6.5<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-<span style="color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 1.53333px;text-decoration: none solid rgb(34, 34, 34);">49039</span></span></td><td width="259" valign="top" style="word-break: break-all;">8.8<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-<span style="color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 1.53333px;text-decoration: none solid rgb(34, 34, 34);">43639</span></span></td><td width="259" valign="top" style="word-break: break-all;">9.8<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-<span style="color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 1.53333px;text-decoration: none solid rgb(34, 34, 34);">43498</span></span></td><td width="259" valign="top" style="word-break: break-all;">9.8<br/></td></tr></tbody></table>  
###   
  
  
3  
  
漏洞描述  
  
**CVE-2024-43451：Windows NTLM 哈希泄露欺骗漏洞**  
  
Windows 的 NTLM 存在哈希泄露欺骗漏洞。攻击者通过滥用 MSHTML，诱导用户与恶意文件进行最小交互（例如选择（单击）、检查（右键单击）等），从而可能泄露用户的 NTLMv2 哈希。攻击者可以利用这些哈希进行身份验证。该漏洞影响所有受支持的微软Windows 版本，并已存在在野利用，因此，企业方面应尽快安装该补丁以防范潜在威胁。  
  
****  
  
**CVE-2024-49039：Windows 任务计划程序权限提升漏洞**  
  
  
由于 Windows 任务计划程序中的身份验证存在缺陷，本地用户可以运行特制的应用程序，将其权限提升到中等完整性级别。该漏洞已存在在野利用，因此，  
对于企业而言应尽快更新该补丁。  
  
  
**CVE-2024-43639：****Windows Kerberos 远程代码执行漏洞**********  
  
攻击者可以通过发送正常的 HTTP 请求，使 Kerberos 代理访问指定的恶意服务器。恶意服务器通过返回特制的数据包，Kerberos 代理在解析响应时由于解析不当，导致远程代码执行。此漏洞不需要用户交互即可被利用，影响所有受支持版本的 Windows Server，因此，企业方面应尽快安装该补丁以防范潜在威胁。  
  
  
**CVE-2024-43498：.NET 和 Visual Studio 远程代码执行漏洞**  
  
该漏洞允许远程攻击者通过发送特制请求到受影响的 .NET Web 应用或加载特制文件到桌面应用中执行代码。由于这类攻击可在应用权限等级下执行代码，可能会与权限提升漏洞结合使用。建议用户尽快检查受影响的 .NET 和 Visual Studio 应用程序并进行相应的补丁更新。  
  
  
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
  
另外，对于不能自动更新的系统版本，可参考以下链接下载适用于该系统的 11 月补丁并安装：  
  
https://msrc.microsoft.com/update-guide/releaseNote/2024-Nov  
  
  
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
  
