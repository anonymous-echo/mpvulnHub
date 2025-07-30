> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2NzkxOTQ0OA==&mid=2247484573&idx=1&sn=aceeff40c7236693b32fabb68ee8ab3b

#  XDigo 恶意软件利用 Windows LNK 漏洞对东欧政府发动攻击  
原创 黑客节点  菜鸟学渗透   2025-06-26 00:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hZGcrKavvZnbA7gTcNAlhbqwXFVvFsXl4WoziaYYAyKA4afSsGoOB6qgL4GsibdFmPfU5XqCCpGicsGJ3t6zKXh4Q/640?wx_fmt=png&from=appmsg "")  
  
网络安全研究人员发现了一种基于 Go 的恶意软件 XDigo，该恶意软件曾在 2025 年 3 月针对东欧政府实体发动攻击。  
  
法国网络安全公司 HarfangLab表示，据称攻击链利用了一系列 Windows 快捷方式（LNK）文件，作为部署恶意软件的多阶段程序的一部分。  
  
XDSpy 是一种网络间谍活动的名称，该活动自 2011 年以来一直以东欧和巴尔干地区的政府机构为目标。白俄罗斯 CERT 于 2020 年初首次记录了该活动。  
  
近年来，俄罗斯和摩尔多瓦的公司成为各种攻击活动的目标，这些攻击活动传播 UTask、XDDown 和 DSDownloader 等恶意软件系列，这些恶意软件可以下载额外的有效载荷并从受感染的主机窃取敏感信息。  
  
HarfangLab 表示，他们观察到威胁行为者利用了 Microsoft Windows 中的一个远程代码执行漏洞，该漏洞在处理特制的 LNK 文件时触发。该漏洞 ( ZDI-CAN-25373 ) 已于今年 3 月初由趋势科技公开披露。  
  
趋势科技的零日计划 (ZDI) 当时表示：“LNK 文件中精心设计的数据可能会导致文件中的危险内容对于通过 Windows 提供的用户界面检查文件的用户不可见。” “攻击者可以利用此漏洞在当前用户的上下文中执行代码。”  
  
对利用 ZDI-CAN-25373 的 LNK 文件工件的进一步分析发现了一个由 9 个样本组成的较小子集，这些样本利用了由于微软未实施其自己的MS-SHLLINK规范（版本 8.0）而产生的 LNK 解析混淆缺陷。  
  
根据规范，LNK 文件中字符串长度的理论上限是可以用两个字节编码的最大整数值（即 65,535 个字符）。然而，Windows 11 的实际实现将存储的文本内容总量限制为 259 个字符（命令行参数除外）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hZGcrKavvZnbA7gTcNAlhbqwXFVvFsXlptoeUM2jyU57ia3RDlCKs8ndO9UrtbibE09c1jc9dqrFSdRhuIER19TA/640?wx_fmt=png&from=appmsg "")  
  
HarfangLab 表示：“这会导致令人困惑的情况，一些 LNK 文件根据规范和 Windows 的解析方式不同，甚至一些根据规范无效的 LNK 文件实际上对 Microsoft Windows 有效。”  
  
由于与规范存在偏差，人们可以专门制作一个 LNK 文件，该文件似乎执行某个命令行，甚至根据实现该规范的第三方解析器无效，同时在 Windows 中执行另一个命令行。  
  
将空格填充问题与 LNK 解析混淆结合起来的结果是，攻击者可以利用它来隐藏在 Windows UI 和第三方解析器上执行的命令。  
  
据称，这九个 LNK 文件是在 ZIP 档案中分发的，每个 ZIP 档案都包含第二个 ZIP 档案，其中包含一个诱饵 PDF 文件、一个合法但重命名的可执行文件以及一个通过二进制文件侧载的恶意 DLL。  
  
值得注意的是，BI.ZONE 上个月底记录了这一攻击链，该攻击链由其追踪的威胁行为者Silent Werewolf实施，目的是用恶意软件感染摩尔多瓦和俄罗斯公司。  
  
该 DLL 是名为 ETDownloader 的第一阶段下载程序，根据其基础设施、受害者特征、攻击时机、攻击策略和工具重叠性，它很可能是为了部署名为 XDigo 的数据收集植入程序。XDigo 被评估为恶意软件（“UsrRunVGA.exe”）的较新版本，卡巴斯基已于 2023 年 10 月对其进行了详细描述。  
  
XDigo 是一款文件窃取工具，可以收集文件、提取剪贴板内容并截取屏幕截图。它还支持通过 HTTP GET 请求执行从远程服务器检索的命令或二进制文件。数据泄露则通过 HTTP POST 请求进行。  
  
至少有一个确认目标位于明斯克地区，其他发现的文物表明袭击目标是俄罗斯零售集团、金融机构、大型保险公司和政府邮政服务。  
  
HarfangLab 表示：“这一目标定位与 XDSpy 过去针对东欧和白俄罗斯政府实体的追踪行为相一致。”  
  
“XDSpy 的重点还体现在其定制的逃避能力上，据报道，他们的恶意软件是第一个试图逃避 PT Security沙盒解决方案检测的恶意软件，PT Security 是一家为俄罗斯联邦的公共和金融机构提供服务的俄罗斯网络安全公司。”  
  
