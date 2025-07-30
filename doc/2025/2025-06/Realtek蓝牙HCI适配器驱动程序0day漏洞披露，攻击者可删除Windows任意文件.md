#  Realtek蓝牙HCI适配器驱动程序0day漏洞披露，攻击者可删除Windows任意文件   
会杀毒的单反狗  军哥网络安全读报   2025-06-03 01:00  
  
**导****读**  
  
  
  
Realtek 蓝牙主机控制器接口 (HCI) 适配器中发现了一个高严重性安全漏洞，这引起了设备制造商和最终用户的极大担忧。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaEIH1xTUuEtETLDsgja40cJ53iacGfLy0jenrzteOoPmfX7lW8z0Q4J1F6NXb4X70VR5yWKHLek7mQ/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞编号为CVE-2024-11857，于 2025 年 6 月 2 日披露。该漏洞允许具有标准用户权限的本地攻击者利用蓝牙堆栈进行权限提升。  
  
  
该漏洞的技术核心在于Realtek蓝牙HCI适配器对符号链接（symlinks）的处理不当。本地攻击者可以创建与适配器编程删除的特定文件同名的符号链接。  
  
  
当适配器执行删除时，它会跟随符号链接并删除攻击者指向的文件，从而实现任意文件删除。攻击者可以利用这一点来提升他们在系统上的权限，从而可能危及设备安全。  
  
### 技术细节和利用路径  
###   
  
该漏洞利用了一种典型的文件系统弱点，即符号链接或“链接跟踪”攻击。在这种情况下，具有普通用户权限的攻击者会创建一个符号链接，将针对良性文件的文件操作重定向到关键系统文件。  
  
  
当 Realtek 蓝牙 HCI 适配器尝试删除原始文件时，它会删除符号链接所针对的文件，该文件可能是系统配置或安全文件。  
  
  
这种任意文件删除可以与其他漏洞或错误配置结合起来，实现权限提升。  
  
  
该漏洞影响 Realtek 蓝牙 HCI 适配器 1.1.73.1 版本以下的所有版本。该漏洞目前没有补丁。  
  
  
该漏洞被归类为高严重性漏洞，CVSS v3.0 基本分数为 7.8，CVSS v4.0 基本分数为 8.5。  
  
  
漏洞公告：  
  
https://github.com/advisories/GHSA-vh52-rw4g-55j6  
  
  
新闻链接：  
  
https://gbhackers.com/realtek-bluetooth-driver-flaw/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
