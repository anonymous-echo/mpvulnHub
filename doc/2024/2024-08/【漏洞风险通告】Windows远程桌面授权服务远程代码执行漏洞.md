#  【漏洞风险通告】Windows远程桌面授权服务远程代码执行漏洞   
 迪普科技   2024-08-09 23:21  
  
**1**  
  
**背景描述**  
  
  
Windows远程桌面授权服务即Windows Remote Desktop Licensing Service（RDL）是Windows Server操作系统的一个关键组件，负责管理和发放客户端访问许可证（CALs），确保远程桌面服务（RDS）环境中的用户连接符合微软的授权协议。受Windows远程桌面授权服务远程代码执行漏洞（CVE-2024-38077）的影响，Windows Server从2000版本到2025版本均存在远程代码执行漏洞，允许未经身份验证的攻击者实现远程命令执行，获取服务器权限。  
  
**近日，迪普科技监测到 Windows远程桌面授权服务远程代码执行漏洞利用伪代码在网上公开，漏洞编号为CVE-2024-38077，官方已于7月9日发布相应补丁，由于目前该漏洞在国内广受关注，迪普科技建议受影响用户及时进行修补并关注官网最新版本，做好相关防护措施。**  
  
**2**  
  
**严重等级**  
  
  
**!**  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0wRpPfN90ibBmpIcBichiabBf8Xs22GMcgl6E1jyW06dnITJNgf0p9CWVIX7Q4niaO2oGo9ib7yXuic26V2voicKVEyzdibqFdBw4kVW/640?wx_fmt=svg&from=appmsg "")  
  
  
**高危**  
  
  
**3**  
  
**漏洞描述**  
  
  
该漏洞是由于Windows远程桌面授权服务（RDL）在解码用户输入的许可密钥包时存在缺陷。当服务接收到许可密钥数据尝试将其解码，并存储到缓冲区时，未能正确验证解码后的数据长度与缓冲区大小之间的关系，导致了缓冲区溢出的问题。成功利用此漏洞可在目标服务器上执行任意代码，获取目标服务器的控制权限。  
  
**说明：**  
Windows 远程桌面授权服务（RDL）通常部署在启用了 Windows 远程桌面服务（端口 3389）的服务器上。但该漏洞利用并非通过 3389 端口直接进行，而是首先连接服务器的 135 端口（需要开启RDL）并发送访问请求，服务器随后返回一个动态高端口，用于连接 RDL 服务。  
  
**4**  
  
**影响范围**  
  
  
Windows Server 2008-34位系统  
  
Windows Server 2008-64位系统  
  
Windows Server 2008 R2-64位系统  
  
Windows Server 2012  
  
Windows Server 2012 R2  
  
Windows Server 2016 < 10.0.14393.7159  
  
Windows Server 2019 < 10.0.17763.6054  
  
Windows Server 2022 < 10.0.20348.2582  
  
Windows Server 2022,23H2 < 10.0.25398.1009)  
  
  
**5**  
  
**解决方案**  
  
  
**官方解决方案**  
  
目前微软已在7月例行安全更新中发布相应的补丁来修复此漏洞，受影响用户请及时进行更新，避免被利用。  
  
1）Windows Update自动更新。Windows系统默认启用Microsoft Update，可以通过自动更新来安装安全补丁。用户可以通过“设置”中的“更新和安全”选项来检查并安装可用的更新。  
  
2）下载补丁包进行更新。用户可以访问微软官方的安全更新指南或更新目录，根据受影响的系统版本下载相应的补丁程序，并按照微软提供的指南进行安装。  
  
https://msrc.microsoft.com/updateguide/vulnerability/CVE-2024-38077  
  
  
**临时解决方案**  
  
1）使用如下指令进入windows server排查是否开启远程桌面授权服务(Remote Desktop Licensing Service），该服务非默认安装启用：sc query | findstr "Remote Desktop'  
  
2）关闭Remote Desktop Licensing服务。  
  
  
**迪普解决方案**  
  
迪普科技安全研究院在监测到Windows远程桌面授权服务远程代码执行漏洞后，迅速采取了应急措施。  
  
1）使用迪普“慧眼检测平台”检测现网环境中是否存在Windows远程桌面授权服务远程代码执行漏洞。  
  
◆慧眼漏洞库版本：DP-Scanner1000-Scanner-R1.3.22-PATCH01  
  
2）迪普科技安全服务团队可协助客户完成现网安全风险评估，针对网络安全入侵事件，提供快速应急响应支撑服务以及专业的安全建设建议。  
  
迪普科技正在全力跟踪相关漏洞的最新进展，有疑问的客户也可联系迪普科技当地办事处售后人员或拨打客户服务热线电话：400-6100-598，进一步了解相关情况。  
  
END  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/X7M4u244hsxqFYraIQaA8AzNpBjxw7Chm4UqxHjutdneP3bJbhNVFVxvoeYU9OScLyZImuWLbBwDYia6gZthibiag/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
  
  
