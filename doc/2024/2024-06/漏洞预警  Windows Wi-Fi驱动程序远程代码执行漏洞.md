#  漏洞预警 | Windows Wi-Fi驱动程序远程代码执行漏洞   
浅安  浅安安全   2024-06-22 08:30  
  
**0x00 漏洞编号**  
- # CVE-2024-30078  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Microsoft Windows Wi-Fi Driver使制造商可以开发在设备平台上正常运行的通用驱动程序，提高WLAN驱动程序的质量，降低驱动程序包的复杂性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVleaDeU1ibPickZJzpKIF4Mcm9iaHXXSDJfzdooHoG4ZA4iaHupxCYLp8HtE2qPLEqYibUd5u3E3Nmiczw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-30078**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执  
行任意代码  
  
**简述：**  
Windows Wi-Fi驱动程序中存在输入验证不当漏洞，未经身份验证的攻击者可以向使用Wi-Fi网络适配器的相邻系统/设备发送恶意网络数据包，导致在无需用户交互的情况下实现远程代码执行。   
###   
  
**0x04 影响版本**  
- Microsoft Windows 10  
  
- Microsoft Windows 11  
  
- Microsoft Windows Server 2022, 23H2  
  
- Microsoft Windows Server 2019  
  
- Microsoft Windows Server 2016  
  
- Microsoft Windows Server 2012  
  
- Microsoft Windows Server 2008  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.microsoft.com/  
  
  
  
