#  假冒的微软Office插件工具通过SourceForge推送恶意软件   
胡金鱼  嘶吼专业版   2025-04-10 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
据了解，威胁者正在滥用 SourceForge 分发假冒的微软插件，这些插件会在受害者的电脑上安装恶意软件，以同时挖掘和窃取加密货币。  
  
SourceForge.net 是一个合法的软件托管和分发平台，还支持版本控制、错误跟踪以及专门的论坛/维基，因此在开源项目社区中非常受欢迎。  
  
尽管其开放的项目提交模式为恶意行为留下了很大的空间，但实际上通过它传播恶意软件的情况却极为罕见。  
  
卡巴斯基发现的新一轮攻击已影响到超过 4604 台系统，其中大部分位于俄罗斯。  
  
尽管恶意项目已不在 SourceForge 上，但卡巴斯基表示，该项目已被搜索引擎收录，吸引了搜索“办公插件”或类似内容的用户访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2893kR8dGvL5SbkVLfmSYudSsXR554Xn6L0icJAQBRs8K16TiaZaIiaODlL5uOlSPnZc52BbZ06hDX5Q/640?wx_fmt=png&from=appmsg "")  
  
源代码托管网站 SourceForge 上的恶意软件出现在搜索结果中  
# 假冒Office插件  
  
“officepackage”项目是一个Office插件开发工具的集合，其描述和文件是GitHub上合法的微软项目“Office-addin-scripts”的副本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2893kR8dGvL5SbkVLfmSYududTp1AHZlfX5l9QvZnc1lqmkSO6gHqsacj44iaDxGCtVt7LtI9ic9ibow/640?wx_fmt=png&from=appmsg "")  
  
恶意项目（左）和合法工具（右）  
  
然而，当用户在谷歌search（和其他引擎）上搜索office插件时，他们得到的结果指向“officpackage .sourceforge”。由SourceForge提供给项目所有者的单独的web托管功能提供支持。  
  
该页面模仿了一个合法的开发者工具页面，显示了“Office插件”和“下载”按钮。如果单击任何一个，受害者将收到一个包含密码保护的归档文件（installer.zip）和带有密码的文本文件的ZIP文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2893kR8dGvL5SbkVLfmSYudIVGdUh4ZB46HK0gSU9TaZBshJNlpsIGLm2FtRZ7z2oaUejicZlDiak7Q/640?wx_fmt=png&from=appmsg "")  
  
散布恶意软件的网站  
  
该归档文件包含一个MSI文件（installer.msi），其大小膨胀到700MB，以逃避AV扫描。运行它会删除‘UnRAR.exe’和‘51654.rar ’，并执行一个Visual Basic脚本，从GitHub获取批处理脚本（confvk.bat）。  
  
该脚本执行检查，以确定它是否在模拟环境中运行，以及哪些防病毒产品处于活动状态，然后下载另一个批处理脚本（confvz.bat）并解压缩RAR归档文件。  
  
bat脚本通过修改注册表和添加Windows服务来建立持久性。  
  
RAR文件包含一个AutoIT解释器（Input.exe）， Netcat反向shell工具（ShellExperienceHost.exe）和两个有效负载（Icon.dll和Kape.dll）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2893kR8dGvL5SbkVLfmSYudz3ibknqNicI8p7icbTAaTtUbdRD1syJIUgh3V2x6pYlibu9G8Mlp8xAuVw/640?wx_fmt=png&from=appmsg "")  
  
完整的感染链  
  
DLL文件是一个加密货币矿工和一个剪刀。前者劫持机器的计算能力，为攻击者的账户挖掘加密货币，后者监控剪贴板上复制的加密货币地址，并将其替换为攻击者控制的地址。  
  
攻击者还通过Telegram API调用接收受感染系统的信息，并可以使用相同的通道向受感染的机器引入额外的有效负载。  
  
这次活动是威胁者利用任何合法平台获得虚假合法性和绕过保护的另一个例子。所以建议用户应从可信的出版商那里下载软件，并在执行之前使用最新的反病毒工具扫描所有下载的文件。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/fake-microsoft-office-add-in-tools-push-malware-via-sourceforge/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2893kR8dGvL5SbkVLfmSYudSWmcumq5hfmoict9FDhdbrGQkYHdic9YYoIgEDPRgKZIpOv2a7QAicXwQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2893kR8dGvL5SbkVLfmSYudghiaODicicfkK46nQYXiaHamRdZ0RavkGYBoutHeBMpKW7pjqs5pRIlbZQ/640?wx_fmt=png&from=appmsg "")  
  
  
