#  【漏洞预警】Microsoft Message Queuing UAF漏洞   
cexlife  飓风网络安全   2024-06-12 23:31  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu007mbe7xGhNj7ynIkbpYRbh1O4SQpNW9Q28ORVfOh3gicCKl6NEAVKwIia5q8Hw6kNChnBWia9Io48Rg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
在Windows消息队列服务MSMQ模块的HTTP处理程序中,存在一个由条件竞争引起的释放后重用（UAF）漏洞,这个缺陷是由于在RPC调用期间错误应用了变量锁,攻击者能够通过构造特定的HTTP请求来触发这个漏洞,这个漏洞允许未经验证的攻击者在受影响的系统上执行任意代码。**修复建议:**正式防护方案:**方法一:**使用Windows Update更新**自动更新:**Microsoft Update默认启用，当系统检测到可用更新时，将会自动下载更新并在下一次启动时安装。**手动更新:**1、点击“开始菜单”或按Windows快捷键，点击进入“设置”。2、选择“更新和安全”，进入“Windows更新”。3、选择“检查更新”，等待系统将自动检查并下载可用更新。4、重启计算机，安装更新系统重新启动后，可通过进入“Windows更新”->“查看更新历史记录”查看是否成功安装了更新。对于没有成功安装的更新，可以点击该更新名称进入微软官方更新描述链接，点击最新的SSU名称并在新链接中点击“Microsoft 更新目录”，然后在新链接中选择适用于目标系统的补丁进行下载并安装。**方法二:**手动安装补丁Microsoft官方下载相应补丁进行更新安全更新下载链接:https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-300801.打开上述下载链接，点击漏洞列表中要修复的CVE链接。2.在微软公告页面底部左侧【产品】选择相应的系统类型，点击右侧【下载】处打开补丁下载链接。3.点击【安全更新】，打开补丁下载页面，下载相应补丁并进行安装。4.安装完成后重启计算机。  
