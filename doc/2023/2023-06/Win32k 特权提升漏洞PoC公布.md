#  Win32k 特权提升漏洞PoC公布   
ang010ela  嘶吼专业版   2023-06-13 12:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
研究人员发布了CVE-2023-29336 Win32k 特权提升漏洞的PoC代码。  
  
近日，研究人员发布了CVE-2023-29336 Win32k 特权提升漏洞的PoC代码。  
  
Win32k子系统(Win32k.sys kernel driver)负责管理操作系统的窗口管理器、屏幕输入、输出，同时作为不同类型输入硬件的接口。Avast研究人员在其中发现了一个权限提升漏洞，漏洞CVE编号为CVE-2023-29336，CVSS V3.1评分7.8分，低权限的用户利用该漏洞可以提升权限到Windows SYSTEM权限级别。  
  
Avast 称其是在攻击活动中发现了该0 day漏洞，但未透露更多细节。5月9日，美国基础设施安全局（CISA）也发布漏洞预警，将该漏洞加入到已知的漏洞利用目录中。  
  
微软已于2023年5月的补丁日修复了该漏洞，并称该漏洞只影响老版本的Windows系统，包括老版本的Windows 10系统、Windows server、Windows8等，Windows 11系统并不受到该漏洞的影响。  
  
就在漏洞补丁发布后的一个月，web3安全公司Nume发布了CVE-2023-29336漏洞的技术细节，并发布了在Windows server 2016版本上的PoC漏洞利用代码。  
  
PoC代码参见：https://github.com/numencyber/Vulnerability_PoC/blob/main/CVE-2023-29336/poc.cpp  
  
PoC视频参见：https://www.youtube.com/embed/fDgq8FyXVvU  
  
Nume研究人员分析了Windows server 2016上的漏洞情况，发现Win32k只锁定了window对象，但没有锁定嵌套的菜单对象。因此，攻击者如果修改了系统内存中的特定地址，就可以实现菜单对象的修改或劫持。  
  
控制菜单对象就表明获得了其启动的程序对应的权限，虽然第一步并不能获得管理员级权限，但通过其他步骤可以实现更高权限的提升。  
  
研究人员在不同的内存布局操作方法、漏洞利用、内存读写函数上进行了测试，最终实现了可以稳定提升到system权限的PoC。  
  
Numen建议系统管理员关注与window对象相关的异常偏移的内存读写，因为这些异常行为可能表明漏洞正在被利用。研究人员建议用户尽快安装微软2023年5月发布的补丁。  
  
更多技术细节参见Numen的技术分析报告：https://www.numencyber.com/cve-2023-29336-win32k-analysis/  
  
参考及来源：https://www.bleepingcomputer.com/news/security/poc-released-for-windows-win32k-bug-exploited-in-attacks/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2960xSM6ffpbbP9Ia2P1zRYXxLYoP7KAff4PgicIq1lj33M80ibZKx3w3SOc3hDDVibiaMbZgjfY6s3jQ/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEjy5ZrpCcgr4BicXicPv08DSsrgibDcJQpvwkZoO4OqdIpJNhj6TO5xV0ic0AnVf7f2kcPnNevQlTtQ/640?wx_fmt=png "")  
  
  
