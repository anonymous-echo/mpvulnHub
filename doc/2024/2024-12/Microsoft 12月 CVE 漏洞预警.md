#  Microsoft 12月 CVE 漏洞预警   
 网新安服   2024-12-11 10:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6YakorxwBv9OVxREDT20IjMqvbKc4icFgxJwDAYgWl6ttLkvLpwKVoqw/640?wx_fmt=gif "")  
  
点击上方蓝字关注我们，获取最新消息  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6ibt323b0qdibplmTcL1ibSPicweE7SV0zUESdKqrNiaPxZmfslRIbXoWVzg/640?wx_fmt=png "")  
  
1  
  
基本情况  
  
12 月份，Microsoft 发布了 72 个漏洞补丁，解决了 Windows 和 Windwos组件、 Microsoft Office 和 Office 组件、SharePoint、Hyper-V、Defender for Endpoint、System Center Operations Manager 相关的问题。  
  
  
在本次公布的 72 个漏洞中，17 个被评为严重，54 个被评为重要，1个被评为中等  
。  
  
  
在本月的更新中，ZDI 列出了 4 个值得关注的漏洞，分别是 CVE-2024-49138、CVE-2024-49112、CVE-2024-49117、CVE-2024-49063。  
  
  
2  
  
漏洞等级  
  
**CVSS基本分数：**  
<table><tbody><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-<span style="color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 1.53333px;text-decoration: none solid rgb(34, 34, 34);">49138</span></span></td><td width="259" valign="top" style="word-break: break-all;">7.8</td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-<span style="color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 1.53333px;text-decoration: none solid rgb(34, 34, 34);">49112</span></span></td><td width="259" valign="top" style="word-break: break-all;">9.8<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-<span style="color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 1.53333px;text-decoration: none solid rgb(34, 34, 34);">49117</span></span></td><td width="259" valign="top" style="word-break: break-all;">8.8<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-<span style="color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 1.53333px;text-decoration: none solid rgb(34, 34, 34);">49063</span></span></td><td width="259" valign="top" style="word-break: break-all;">8.4<br/></td></tr></tbody></table>  
###   
  
  
3  
  
漏洞描述  
  
**CVE-2024-49138：Windows 通用日志文件系统驱动程序提升权限漏洞**  
  
该漏洞允许通过身份验证的攻击者在受影响系统上运行特制的程序来获取该系统的SYSTEM权限。该漏洞已存在在野利用，因此，对于企业而言应尽快更新该补丁。  
  
****  
  
**CVE-2024-49112：Windows 轻量级目录访问协议 (LDAP) 远程代码执行漏洞**  
  
  
该漏洞允许未经身份验证的远程攻击者通过特制的LDAP调用来获取代码执行的权限，从而实现在LDAP服务的上下文中执行任意代码。建议用户尽快检查受影响的LDAP服务，并进行相应的补丁更新。  
  
  
**CVE-2024-49117：Windows Hyper-V 远程代码执行漏洞**********  
  
该漏洞允许通过身份验证的远程攻击者在来宾VM上向VM的硬件发送特制的文件操作请求，从而实现远程代码执行。此外，攻击者可能利用该漏洞来执行跨虚拟机攻击，从而损害更多的虚拟机，因此，企业方面应尽快安装该补丁以防范潜在威胁。  
  
  
**CVE-2024-49063：Muzic 远程代码执行漏洞**  
  
该漏洞允许未经身份身份验证的攻击者在受影响的应用触发反序列化时执行特制的负载，来获取代码执行的权限，从而实现任意代码的执行。建议用户尽快检查受影响的Muzic，并进行相应的补丁更新。  
  
  
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
  
另外，对于不能自动更新的系统版本，可参考以下链接下载适用于该系统的 12 月补丁并安装：  
  
https://msrc.microsoft.com/update-guide/releaseNote/2024-Dec  
  
  
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
  
