#  WinRAR漏洞造利用，俄罗斯黑客向乌克兰发送恶意软件   
 网络安全应急技术国家工程中心   2024-06-03 16:06  
  
#   
# 摘要  
  
与俄罗斯有关的威胁行为者FlyingYeti正在以乌克兰为目标进行网络钓鱼活动，以提供PowerShell恶意软件COOKBOX。  
  
Cloudflare研究人员发现了一名与俄罗斯有关的威胁行为者FlyingYeti（又名UAC-0149）针对乌克兰进行的网络钓鱼活动。专家们发表了一份报告，描述了破坏和延迟这种威胁活动的实时努力。  
  
在2022年2月24日俄罗斯入侵乌克兰之初，乌克兰暂停驱逐和终止未偿还债务的公用事业服务。暂停期于2024年1月结束，导致乌克兰公民承担巨额债务，并增加了财务压力。FlyingYeti运动利用这种焦虑，使用债务主题的诱饵诱骗目标打开嵌入消息中的恶意链接。打开文件后，PowerShell恶意软件COOKBOX会感染目标系统，使攻击者能够部署额外的有效载荷并控制受害者的系统。  
  
威胁参与者利用WinRAR漏洞CVE-2023-38831向目标感染恶意软件。  
  
Cloudflare表示，FlyingYeti的战术、技术和程序（TTP）与乌克兰CERT在分析UAC-0149集群时详细说明的战术、技巧和程序相似。  
  
至少从2023年秋天开始，UAC-0149就用COOKBOX恶意软件攻击乌克兰国防实体。  
  
Cloudflare发布的报告中写道：“威胁行为者将动态DNS（DDNS）用于其基础设施，并利用基于云的平台托管恶意内容和进行恶意软件指挥与控制（C2）。”。“我们对FlyingYeti TTPs的调查表明，这很可能是一个与俄罗斯结盟的威胁组织。该行为者似乎主要专注于针对乌克兰军事实体。”  
  
威胁行为者以基辅Komunalka公共住房网站的恶搞版本为目标用户(https://www.komunalka.ua)，托管在参与者控制的GitHub页面上（hxxps[：]//comunalka[.]GitHub[.]io）。Komunalka是基辅地区公用事业和其他服务的支付处理商。  
  
FlyingYeti很可能通过网络钓鱼电子邮件或加密信号消息将目标引导到此页面。在这个被欺骗的网站上，一个大的绿色按钮提示用户下载一个名为“Рахунок.docx”（“Invoice.docx”）的文件，而该文件下载了一个标题为“ЗаборгованасапоЖКП.rar”（“住房和公用事业债务.rar”）的恶意档案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6xxR28esic0edM4MaMm576QcRBLwkYJH7nPgpDziclDmpJlmTnibGHNPneSu9fWHjs2tiaPHq1ztUicTdw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
一旦打开RAR文件，CVE-2023-38831漏洞就会触发COOKBOX恶意软件的执行。  
  
RAR档案包含多个文件，其中一个文件的Unicode字符为“U+201F”，在Windows系统中显示为空白。此字符可以通过添加过多的空格来隐藏文件扩展名，使恶意CMD文件（“Рахунокнаоплару.pdf[unicode character U+201F].CMD”）看起来像pdf文档。该档案还包括一个良性的PDF文件，其名称相同，但没有Unicode字符。打开档案后，目录名称也与良性PDF名称匹配。这种命名重叠利用了WinRAR漏洞CVE-2023-38831，导致目标尝试打开良性PDF时执行恶意CMD。  
  
“CMD文件包含名为COOKBOX的Flying Yeti PowerShell恶意软件。该恶意软件被设计为持久存在于主机上，作为受感染设备的立足点。一旦安装，该COOKBOX变体将向DDNS域postposterk[.]serveftp[.]com请求C2，等待恶意软件随后运行的PowerShell cmdlet。”报告继续说道。“除了COOKBOX，还打开了几个诱饵文档，其中包含使用Canary Tokens服务的隐藏跟踪链接。  
  
  
  
原文来源  
：E安全  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
