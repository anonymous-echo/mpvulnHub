#  关于Windows远程桌面许可服务存在远程代码执行漏洞的安全公告   
 网络靖安司CSIZ   2024-08-23 17:00  
  
安全公告编号:  
CNTA-2024-0011  
  
  
  
2024年8月9日，国家信息安全漏洞共享平台（CNVD）收录了Windows远程桌面许可服务远程代码执行漏洞（  
CNVD-2024-34918  
，对应CVE-2024-38077）。未经身份认证的攻击者可利用漏洞远程执行代码，获取服务器控制权限。目前，该漏洞的部分技术原理和概念验证伪代码已公开，厂商已发布安全更新完成修复。CNVD建议受影响的单位和用户安全即刻升级到最新版本。  
  
**一、漏洞情况分析**  
  
Windows远程桌面许可服务（Remote Desktop License Service，RDL）是Windows Server操作系统的一个服务，用于管理和颁发远程桌面服务（RDS）的许可证，确保服务器拥有足够的授权许可。RDL服务不是Windows Server操作系统的默认启用服务。默认情况下，Windows服务器远程桌面服务仅支持两个并发会话，在启用RDP多并发会话支持时，需要手动安装RDL服务。  
  
2024年8月9日上午9时，研究人员在境外网站公开了RDL服务远程代码执行漏洞的部分技术原理和概念验证（POC）伪代码，该伪代码目前尚无法直接运行，研究者将其命名为狂躁许可（MadLicense）。RDL服务在解码用户输入的许可密钥包时，未正确验证解码后的数据长度与缓冲区大小之间的关系，从而导致堆缓冲区溢出。未经身份认证的攻击者利用该漏洞，通过远程向目标Windows Server服务器发送恶意构造的数据包，从而执行任意代码，实现对服务器的权限获取和完全控制。  
  
CNVD对该漏洞的综合评级为“高危”。  
  
 **二、漏洞影响范围**  
  
漏洞影响的产品和版本：  
  
Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server
Core installation)  
  
Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server
Core installation)  
  
Windows Server 2008 R2 for x64-based Systems Service Pack 1  
  
Windows Server 2008 R2 for x64-based Systems Service Pack 1  
  
Windows Server 2008 for x64-based Systems Service Pack 2 (Server
Core installation)  
  
Windows Server 2008 for x64-based Systems Service Pack 2 (Server
Core installation)  
  
Windows Server 2008 for x64-based Systems Service Pack 2  
  
Windows Server 2008 for x64-based Systems Service Pack 2  
  
Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core
installation)  
  
Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core
installation)  
  
Windows Server 2008 for 32-bit Systems Service Pack 2  
  
Windows Server 2008 for 32-bit Systems Service Pack 2  
  
Windows Server 2012 R2 (Server Core installation)  
  
Windows Server 2012 R2  
  
Windows Server 2012 (Server Core installation)  
  
Windows Server 2012  
  
Windows Server 2016 (Server Core installation)  
  
Windows Server 2016  
  
Windows Server 2019 (Server Core installation)  
  
Windows Server 2019  
  
Windows Server 2022, 23H2 Edition (Server Core installation)  
  
Windows Server 2022 (Server Core installation)  
  
Windows Server 2022  
  
          
Windows Server 2025 Preview    
      
  
****  
**三、漏洞处置建议**  
  
2024年7月9日，微软公司在7月的例行补丁日已发布补丁修复该漏洞，CNVD建议受影响的单位和用户即刻通过官方链接下载并更新至最新版本：  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077  
  
对于暂无法安装更新补丁的情况，微软公司建议在确认RDL服务非必要的前提下，采取关闭RDL服务等临时防范措施。  
  
  
  
  
感谢北京知道创宇信息技术股份有限公司、奇安信网神、长亭安全应急响应中心为本报告提供的技术支持  
  
  
  
  
  
