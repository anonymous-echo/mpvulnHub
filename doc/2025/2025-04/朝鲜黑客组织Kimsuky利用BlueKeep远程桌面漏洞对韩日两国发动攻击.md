#  朝鲜黑客组织Kimsuky利用BlueKeep远程桌面漏洞对韩日两国发动攻击   
鹏鹏同学  黑猫安全   2025-04-22 23:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce8x84fVkELT0xBNiatI7ichWhsY3wicbV50KsA1u6IRNibico94Erge7Mk4cqaA650UNT6GrmL4icUp5aJg/640?wx_fmt=png&from=appmsg "")  
  
ASEC在调查一起安全事件时发现，与朝鲜有关的黑客组织Kimsuky（追踪编号Larva-24005）通过远程桌面协议（RDP）漏洞入侵目标系统。  
  
**漏洞利用与入侵手段**  
  
ASEC报告指出："部分系统通过RDP漏洞（BlueKeep，CVE-2019-0708）获得初始访问权限。虽然在受感染系统中发现了RDP漏洞扫描工具，但未发现实际使用证据。"攻击者还采用其他恶意软件传播方式，包括：  
- 通过电子邮件附件投递恶意文件  
  
- 利用Microsoft Office公式编辑器漏洞（CVE-2017-11882）  
  
**攻击链分析**  
1. **持久化控制**  
：入侵后安装MySpy恶意软件和RDPWrap工具维持远程访问  
  
1. **数据窃取**  
：最终阶段部署KimaLogger或RandomQuery键盘记录器  
  
1. **横向移动**  
：研究人员观察到攻击者利用被控系统向韩日两国发送钓鱼邮件  
  
**组织背景**  
  
Kimsuky（又称ARCHIPELAGO、Black Banshee等）自2013年被发现以来，长期受朝鲜侦察总局（RGB）指挥。该组织近期活动包括：  
- 2023年9月起针对韩、美、中、日等国的政府、能源和金融领域  
  
- 2024年2月通过鱼叉邮件分发forceCopy信息窃取木马  
  
- 使用伪造成Office文档的*.LNK快捷文件，触发PowerShell下载PebbleDash等恶意工具  
  
**技术特征**  
- 采用定制版RDP Wrapper绕过检测  
  
- 部署代理恶意软件穿透内网隔离  
  
- 使用多格式键盘记录器（含PowerShell脚本版）  
  
- forceCopy窃密程序可截取键盘输入并窃取浏览器数据  
  
**防御建议**  
  
ASEC已公开本次攻击的入侵指标（IoC）。建议机构：  
1. 立即修补CVE-2019-0708和CVE-2017-11882漏洞  
  
1. 监控RDP端口（3389）异常连接  
  
1. 警惕伪装成办公文档的快捷文件  
  
1. 部署终端检测响应（EDR）系统捕捉PowerShell恶意行为  
  
