> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650611281&idx=2&sn=0b13a7fa48b99eb7891098356636b07b

#  联想Windows目录可写文件漏洞可隐秘绕过AppLocker防护  
 黑白之道   2025-07-07 01:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
研究人员在联想预装Windows操作系统中发现一个安全漏洞——Windows目录下的可写文件 MFGSTAT 可使攻击者绕过微软AppLocker安全框架。该漏洞影响所有采用默认Windows安装的联想设备，对企业安全环境构成威胁。  
  
  
漏洞核心在于C:\Windows\目录下的MFGSTAT.zip文件存在错误权限配置，允许任何经过身份验证的用户对该位置进行写入和执行操作。  
  
  
关键发现：  
  
1. 联想Windows目录下可写的MFGSTAT.zip文件因权限配置错误可绕过AppLocker防护   
  
2. 利用NTFS备用数据流(ADS)在压缩文件中隐藏可执行文件，通过合法Windows进程运行   
  
3. 影响所有预装Windows的联想设备   
  
4. 可通过PowerShell命令或企业管理工具删除该文件  
  
  
**Part01**  
## 漏洞利用技术  
## NTFS备用数据流(ADS)  
  
  
攻击技术利用了NTFS备用数据流(ADS)这一鲜为人知的特性，攻击者可在看似无害的文件中隐藏可执行内容。TrustedSec公司的Oddvar Moe通过以下命令序列，将Microsoft Sysinternals的autoruns.exe工具嵌入存在漏洞的zip文件进行演示：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380mGfJnMjqmicdw8f31nCMV7ndQe367ictR2HO3tL66PPmHEWVbJ0XLTEJ6IbTPMqsHfXFuAlfApAg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
数据流注入后，攻击者可通过合法的Microsoft Office应用程序加载器执行恶意载荷：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380mGfJnMjqmicdw8f31nCMV5xOe7prhQhXE6kqjL4MTiaKBMB04jEIHYHjcwq8ZSR3THzUH8aKbkNQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这种"利用合法二进制文件"(LOLBin)技术通过受信任的Windows进程执行未授权代码，可规避传统安全监控系统。由于完全使用合法系统组件，该攻击向量使安全团队的检测工作变得异常困难。  
  
  
**Part02**  
## 漏洞历史与厂商响应  
  
  
该漏洞最初于2019年常规安全评估中发现，但直到2025年Moe重新调查时才引起关注。在确认该问题影响多代联想设备后，研究人员联系了联想产品安全事件响应团队(PSIRT)。联想回应第一时间提供修复指南，客户可按照修复指南操作来保障安全。  
###   
  
**Part03**  
## 缓解措施  
  
  
企业可通过多种方法立即实施修复。最直接的方式是使用PowerShell删除漏洞文件：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380mGfJnMjqmicdw8f31nCMVsDavVTyBeaO2bV7ricQVITqLOK6ep1cbiaU60YqOG8HesgANEFCkzjLw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
管理员也可使用带隐藏文件属性标志的命令提示符：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380mGfJnMjqmicdw8f31nCMVreGatGJiaSVcnnCYXG0w9E25VcCibyyJnEibkbh3wzdy2kftibBX0uicu9A/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
企业环境应利用组策略首选项、System Center Configuration Manager(SCCM)等管理工具确保所有受影响系统完成统一清理。该事件凸显了实施AppLocker部署时全面文件系统审计的重要性，即使微小疏忽也可能造成可绕过基础访问控制的安全漏洞。  
  
  
> **文章来源：freebuf**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
