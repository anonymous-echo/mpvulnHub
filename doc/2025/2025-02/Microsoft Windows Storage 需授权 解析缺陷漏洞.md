#  Microsoft Windows Storage 需授权 解析缺陷漏洞   
 上汽集团网络安全应急响应中心   2025-02-14 15:55  
  
**漏洞情报**  
  
  
  
  
  
**Microsoft Windows Storage 需授权 解析缺陷漏洞**  
  
  
**【 漏洞编号 】**  
  
CVE-2025-21391  
  
  
**【 情报等级 】**  
  
**高危**  
  
  
**【 漏洞描述 】**  
  
360漏洞云监测到微软发布2月安全公告，修复了多个安全漏洞，其中包含一个Microsoft Windows Storage 需授权 解析缺陷漏洞，由于Windows存储中的不安全链接，本地用户可以在系统上删除任意文件，造成文件和数据失控。  
  
  
**【 影响产品 】**  
  
<table><tbody><tr><td colspan="1" rowspan="1" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="99.0000%"><section style="text-align: center;font-size: 14px;"><p>windows 10 1703,windows 10 1803,windows 10 1507,Windows Server 2022,windows 11,windows 10,windows 10 1809,windows 10 1909,Windows Server 2019,windows 10 1607,Windows Server 2016,windows server 2025,Windows 11,Windows 10,windows 10 1709,windows 10 20h2,windows 10 21h1,windows 10 21h2,windows server 2022,windows 10 22h2,windows 10 1511,windows 10 2004,windows server 2019,windows server 2016,Windows Server 2025&lt;10.0.10240.20915,&lt;10.0.14393.7785,&lt;10.0.26100.3194,&lt;10.0.26100.3107,&lt;10.0.20348.3148,&lt;10.0.14393.7785&amp;&amp;&lt;11.0,&lt;10.0.22631.4890,&lt;10.0.25398.1425,&lt;10.0.17763.6893,&lt;10.0.20348.3207</p></section></td></tr></tbody></table>  
  
**【 解决方案与修复建议 】**  
  
**方法一**，使用Windows Update更新  
  
自动更新：  
  
Microsoft Update默认启用，当系统检测到可用更新时，将会自动下载更新并在下一次启动时安装。  
  
手动更新：  
  
1、点击“开始菜单”或按Windows快捷键，点击进入“设置”。  
  
2、选择“更新和安全”，进入“Windows更新”。  
  
3、选择“检查更新”，等待系统将自动检查并下载可用更新。  
  
4、重启计算机，安装更新系统重新启动后，可通过进入“Windows更新”->“查看更新历史记录”查看是否成功安装了更新。对于没有成功安装的更新，可以点击该更新名称进入微软官方更新描述链接，点击最新的SSU名称并在新链接中点击“Microsoft 更新目录”，然后在新链接中选择适用于目标系统的补丁进行下载并安装。  
  
**方法二**. 手动安装补丁  
  
Microsoft官方下载相应补丁进行更新。  
  
**安全更新下载链接：**  
  
https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-21391  
  
1.打开上述下载链接，点击漏洞列表中要修复的CVE链接。  
  
2.在微软公告页面底部左侧【产品】选择相应的系统类型，点击右侧【下载】处打开补丁下载链接。  
  
3.点击【安全更新】，打开补丁下载页面，下载相应补丁并进行安装。  
  
4.安装完成后重启计算机。  
  
