#  Microsoft 6 月 CVE 漏洞预警   
 网新安服   2024-06-12 18:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6YakorxwBv9OVxREDT20IjMqvbKc4icFgxJwDAYgWl6ttLkvLpwKVoqw/640?wx_fmt=gif "")  
  
点击上方蓝字关注我们，获取最新消息  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OT1Aib4N17tPv5yWNBzpJW1HreoibdQRN6ibt323b0qdibplmTcL1ibSPicweE7SV0zUESdKqrNiaPxZmfslRIbXoWVzg/640?wx_fmt=png "")  
  
1  
  
基本情况  
  
6 月份，Microsoft 发布了 49 个漏洞补丁，解决了 Windows 和 Windows 组件、Office 和 Office 组件、Azure、Visual Studio、Dynamics Business Central等相关的问题。  
  
  
在本次公布的 49 个漏洞中，1个被评为严重，48 个被评为重要。  
  
  
在本月的更新中，ZDI 列出了 3 个值得关注的漏洞，分别是 CVE-2024-30080、 CVE-2024-30103、CVE-2024-30078。  
  
  
2  
  
漏洞等级  
  
**CVSS基本分数：**  
<table><tbody><tr><td width="258" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;background-color: rgb(255, 255, 255);">CVE-2024-30080</span></td><td width="258" valign="top" style="word-break: break-all;">9.8</td></tr><tr><td width="258" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-family: &#34;Microsoft YaHei UI&#34;, sans-serif;font-size: 14px;letter-spacing: 1.53333px;text-align: left;background-color: rgb(255, 255, 255);">CVE-2024-30103</span></td><td width="258" valign="top" style="word-break: break-all;">8.8</td></tr><tr><td width="258" valign="top" style="word-break: break-all;"><span style="color: rgb(34, 34, 34);font-size: 14px;letter-spacing: 1.53333px;text-align: left;background-color: rgb(255, 255, 255);"><span style="font-size: 14px;letter-spacing: 1.5px;text-align: left;text-wrap: wrap;">CVE-2024-30078</span></span></td><td width="258" valign="top" style="word-break: break-all;">8.8</td></tr></tbody></table>  
###   
  
  
3  
  
漏洞描述  
  
**CVE-2024-30080：Microsoft Message Queuing (MSMQ) 远程执行代码漏洞**  
  
  
该漏洞允许未经身份验证的攻击者通过向目标MSMQ服务器发送恶意的MSMQ数据包，从而实现在目标服务器上远程执行任意代码。值得注意的是，该漏洞还可被利用于在MSMQ服务器之间进行蠕虫攻击，因此建议相关用户尽快测试并部署漏洞补丁。  
  
****  
  
**CVE-2024-30103：Microsoft Outlook 远程执行代码漏洞**  
  
  
该漏洞允许攻击者绕过 Outlook 注册表阻止列表并允许创建恶意DLL文件，从而实现在目标服务器上远程执行任意代码。虽然攻击者在实现漏洞利用前，需要先获取有效的Exchange用户凭据，但是该漏洞可能发生在预览窗格中，因而该漏洞的修复同样不容忽视，所以建议相关用户尽快测试并部署漏洞补丁。  
  
  
**CVE-2024-30078：Windows Wi-Fi Driver 远程执行代码漏洞**********  
  
  
该漏洞允许未经身份验证的攻击者过向目标发送恶意的网络数据包，从而实现在目标系统上远程执行任意代码。虽然攻击者开展该漏洞利用的前提条件与目标系统使用同一Wi-Fi网络适配器，但是正因Wi-Fi被广泛的使用，导致该漏洞更容易被攻击者所关注，所以建议相关用户尽快测试并部署漏洞补丁。  
  
  
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
  
另外，对于不能自动更新的系统版本，可参考以下链接下载适用于该系统的 6 月补丁并安装：  
  
https://msrc.microsoft.com/update-guide/releaseNote/2024-Jun  
  
  
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
  
