#  Microsoft 10 月 CVE 漏洞预警   
 网新安服   2024-10-09 18:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6YakorxwBv9OVxREDT20IjMqvbKc4icFgxJwDAYgWl6ttLkvLpwKVoqw/640?wx_fmt=gif "")  
  
点击上方蓝字关注我们，获取最新消息  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6ibt323b0qdibplmTcL1ibSPicweE7SV0zUESdKqrNiaPxZmfslRIbXoWVzg/640?wx_fmt=png "")  
  
1  
  
基本情况  
  
10 月份，Microsoft 发布了 117 个漏洞补丁，解决了 Microsoft Windows 和 Windows 组件、Office 和 Office 组件、  
Azure、.NET 框架 和 Visual Studio、适用于 Windows 的 OpenSSH、  
Power BI、Windows Hyper-V 和 Windows Mobile Broadband 相关的问题  
。  
  
  
在本次公布的 117 个漏洞中，3 个被评为严重，113 个被评为重要，2 个被标记为"在野利用"  
。  
  
  
在本月的更新中，ZDI 列出了 4 个值得关注的漏洞，分别是 CVE-2024-43573、CVE-2024-43572、CVE-2024-43468、  
CVE-2024-43582  
。  
  
  
2  
  
漏洞等级  
  
**CVSS基本分数：**  
<table><tbody><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-43573</span></td><td width="259" valign="top" style="word-break: break-all;">6.5<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-43572</span></td><td width="259" valign="top" style="word-break: break-all;">7.8<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-43468</span></td><td width="259" valign="top" style="word-break: break-all;">9.8<br/></td></tr><tr><td width="259" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);">CVE-2024-43582</span></td><td width="259" valign="top" style="word-break: break-all;">8.1<br/></td></tr></tbody></table>  
###   
  
  
3  
  
漏洞描述  
  
**CVE-2024-43573：Windows MSHTML Platform 欺骗漏洞**  
  
该漏洞是由于对用户提供的数据过滤不充分，远程攻击者可以诱使受害者点击特制链接，并在易受攻击的网站上下文中在用户浏览器中执行任意 HTML 和脚本代码。成功利用此漏洞可能允许远程攻击者窃取潜在的敏感信息、更改 Web 的外观页面，执行网络钓鱼等攻击。  
该漏洞已被标记  
在野  
利用，因此，企业方面应尽快安装该补丁以防范潜在威  
胁。  
  
****  
  
**CVE-2024-43572：Microsoft Management Console 远程代码执行漏洞**  
  
  
该漏洞的存在是由于 Microsoft 保存的控制台 (MSC) 文件验证不充分，远程攻击者可以  
诱使受害者打开特制文件并在系统上执行任意代码。该漏洞已被标记为在野利用，因此，  
对于企业而言，应尽快更新该补丁。  
  
  
**CVE-2024-43468：Microsoft Configuration Manager****远程代码执行漏洞**********  
  
Microsoft Configuration Manager 中发现了一个无需用户交互即可利用的漏洞。未经身份验证的攻击者可以通过向目标环境发送经特殊设计的请求来利用此漏洞，这些请求以不安全的方式处理，从而使攻击者能够在服务器或底层数据库上执行命令。  
  
  
**CVE-2024-43582：远程桌面服务远程代码执行漏洞**  
  
在 Windows 远程桌面协议中发现了一个会导致远程无身份验证攻击的漏洞。本漏洞需要攻击者赢得竞争条件，  
通过发送特制的 HTTP 请求，并在受害机器上以系统服务权限执行任意代码。因此，对于企业而言，  
应尽快更新该补丁，以  
防范潜在威  
胁。  
  
  
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
  
另外，对于不能自动更新的系统版本，可参考以下链接下载适用于该系统的 10 月补丁并安装：  
  
https://msrc.microsoft.com/update-guide/releaseNote/2024-Oct  
  
  
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
  
