#  VMware Tools 漏洞允许攻击者篡改文件以触发恶意作   
邑安科技  邑安全   2025-05-13 05:24  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tzFbKQRxa94xpNBC3ibmYnU9FqlpDxloibA0fAZUK7B7WTvMBmtIecyoW1RcNpueHNctJeibaJxtb6Q/640?wx_fmt=png&from=appmsg "")  
  
VMware Tools 中存在一个中等严重性漏洞，该漏洞可能允许具有有限权限的攻击者在虚拟机中纵文件并触发不安全的作。  
  
该漏洞被跟踪为 CVE-2025-22247，影响 VMware Tools 11.x.x 和 12.x.x 的 Windows 和 Linux 版本，其中 macOS 版本确认不受影响。  
  
由于目前没有解决方法，并且利用这些漏洞可能会损害受影响虚拟机的完整性，因此强烈建议及时修补。  
  
CVE-2025-22247：VMware Tools 不安全的文件处理  
  
根据 Broadcom 公告，不安全的文件处理漏洞允许“在客户虚拟机上具有非管理权限的恶意行为者篡改本地文件，从而在该虚拟机中触发不安全的文件作”。  
  
该漏洞的 CVSSv3 基本评分为 6.1，处于中等严重性范围内。Positive Technologies 的安全研究员 Sergey Bliznyuk 因发现该漏洞并向 VMware 报告而受到赞誉。  
  
在今年早些时候解决了其他几个 VMware 漏洞之后，我们又解决了这一最新的安全问题，其中包括影响 VMware ESXi 和 Workstation 的关键 TOCTOU 漏洞 （CVE-2025-22224），该漏洞可能导致越界写入和潜在的代码执行。  
  
在多个租户共享物理基础设施的虚拟化环境中，这种类型的漏洞尤其令人担忧。  
  
即使影响包含在客户机 VM 中，它也可以用作更大的攻击链的一部分，或用于虚拟机中的特权提升。  
<table><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong msttexthash="14330498" msthash="68" style="box-sizing: border-box;font-weight: bold;"><span leaf=""><span textstyle="" style="font-size: 15px;">风险因素</span></span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong msttexthash="3259074" msthash="69" style="box-sizing: border-box;font-weight: bold;"><span leaf=""><span textstyle="" style="font-size: 15px;">详</span></span></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section style="margin-top: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">受影响的产品</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section style="margin-top: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">VMware Tools 11.x.x、12.x.x （Windows/Linux）</span></span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section style="margin-top: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">冲击</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section style="margin-top: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">文件篡改允许在来宾 VM 中进行恶意作</span></span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section style="margin-top: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">利用先决条件</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section style="margin-top: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">来宾 VM 上的非管理权限</span></span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section style="margin-top: 8px;"><span leaf=""><span textstyle="" style="font-size: 15px;">CVSS 3.1 分数</span></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section style="margin-top: 0px;margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 15px;">6.1 （中等）</span></span></section></td></tr></tbody></table>  
缓解措施  
  
Broadcom 发布了 VMware Tools 版本 12.5.2，以修复 Windows 和 Linux 系统的漏洞。特别是对于 Windows 32 位系统，12.5.2 版本中包含的 VMware Tools 12.4.7 解决了该问题。  
  
Linux 用户应注意，他们各自的 Linux 供应商将分发解决 CVE-2025-22247 的 open-vm-tools 的修复版本，版本可能因 Linux 发行版和供应商而异。  
  
该漏洞会影响企业虚拟化基础架构中通常部署的 VMware 软件。  
  
VMware Tools 是一套实用程序，可增强虚拟机客户机作系统的性能并改进 VM 的管理。  
  
它包括支持提高图形性能、时间同步、剪贴板共享以及主机和来宾计算机之间文件传输功能的驱动程序。  
  
此安全更新是在 2025 年 3 月 VMware Tools 12.5.1 发布仅两个月后发布的，该版本解决了另一个被跟踪为 CVE-2024-43590 的安全漏洞。  
  
频繁的安全更新凸显了虚拟化软件供应商面临的持续安全挑战。  
  
强烈建议 IT 管理员尽快应用这些补丁，尤其是在虚拟机之间横向移动风险较高的多租户环境中。  
  
此漏洞没有可用的解决方法，因此修补是唯一有效的缓解策略。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/vmware-tools-vulnerability/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
