#  黑客活动家利用 WinRAR 漏洞对俄罗斯和白俄罗斯发动攻击   
 网安百色   2024-09-06 19:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo6TLA19pviaCFfbrwwfDkd81KlLEPjVUhNmpUTv82EJhu2QnczPmf7nU0UicVQhD3icJZp2vicGaWur0w/640?wx_fmt=gif "")  
  
一个名为 Head Mare 的黑客组织与专门针对位于俄罗斯和白俄罗斯的组织的网络攻击有关。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljSmc2BCBnesBkpicYcLlyPCrjlCX6Ccdux26tf2vwu6wpMvQmibibhZEtkib9DXgibibtogFYibyPyroslA/640?wx_fmt=other&from=appmsg "")  
  
  
“Head Mare 使用更多最新的方法来获得初始访问权限，”卡巴斯基在周一对该组织的策略和工具的分析中说。  
  
“例如，攻击者利用了 WinRAR 中相对较新的 CVE-2023-38831 漏洞，该漏洞允许攻击者通过专门准备的存档在系统上执行任意代码。这种方法使该组织能够更有效地传递和伪装恶意负载。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljSmc2BCBnesBkpicYcLlyPCMkWPia5iaotBseXjvicn160Z1X5FHjYrgRP0GQzZM1BicWSKAMlqTUEPAg/640?wx_fmt=other&from=appmsg "")  
  
  
Head Mare 自 2023 年以来一直活跃，是在一年前开始的俄乌冲突背景下攻击俄罗斯组织的黑客组织之一。  
  
它还在 X 上保持存在，在那里它泄露了受害者的敏感信息和内部文件。该组织攻击的目标包括政府、交通、能源、制造业和环境部门。  
与其他可能旨在对两国公司造成“最大损害”的黑客行动主义角色不同，Head Mare 还使用 LockBit for Windows 和 Babuk for Linux （ESXi） 加密受害者的设备，并要求赎金以进行数据解密。  
  
其工具包的一部分还包括 PhantomDL 和 PhantomCore，前者是一个基于 Go 的后门，能够提供额外的有效载荷并将感兴趣的文件上传到命令和控制 （C2） 服务器。  
  
PhantomCore（又名 PhantomRAT）是 PhantomDL 的前身，是一种具有类似功能的远程访问木马，允许从 C2 服务器下载文件，将文件从受感染的主机上传到 C2 服务器，以及在 cmd.exe 命令行解释器中执行命令。  
  
“攻击者创建名为 MicrosoftUpdateCore 和 MicrosoftUpdateCoree 的计划任务和注册表值，以将其活动伪装成与 Microsoft 软件相关的任务，”卡巴斯基说。  
“我们还发现，该组织使用的一些 LockBit 样本具有以下名称：  
OneDrive.exe [和] VLC.exe。  
这些示例位于 C：  
\ProgramData 目录中，伪装成合法的 OneDrive 和 VLC 应用程序。  
  
已发现这两种工件都是通过网络钓鱼活动以带有双扩展名的商业文件形式分发的（例如，решение No201-5_10вэ_001-24 к пив экран-сои-2.pdf.exe 或 тз на разработку.pdf.exe）。  
  
其攻击武器库的另一个关键组成部分是 Sliver，这是一个开源 C2 框架，以及各种公开可用的工具（如 rsockstun、ngrok 和 Mimikatz）的集合，这些工具有助于发现、横向移动和凭据收集。  
  
根据目标环境，入侵最终导致部署 LockBit 或 Babuk，然后放下赎金票据，要求付款以换取解密器解锁文件。  
  
“Head Mare 组织使用的战术、方法、程序和工具通常与在俄乌冲突背景下针对俄罗斯和白俄罗斯组织的集群相关的其他组织相似，”俄罗斯网络安全供应商表示。  
“然而，该组织通过使用定制的恶意软件（如 PhantomDL 和 PhantomCore）以及利用相对较新的漏洞 CVE-2023-38831 在网络钓鱼活动中渗透受害者的基础设施而与众不同。  
”  
  
来源：黑客活动家利用 WinRAR 漏洞对俄罗斯和白俄罗斯发动攻击 (thehackernews.com)  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo6M60aLu6MNdy20VjcnyaGECz7d9mYhdbclWg7wibJsickPUrnmNyFcvsjSYUqq5OPVPEXfW1SwkXCw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo57Spb4ibrib8VUZd2ibdF9wHbvr4RwYJ4H2z6571icFIdSZXIpNH2YfW16ETwHh3ict3gtpW3W2fJqDmw/640?wx_fmt=gif "")  
  
长按添加关注，为您保驾护航！  
  
  
