#  【安全圈】VM虚拟机重大漏洞！立即升级   
 安全圈   2024-03-09 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
虚拟化产品供应商 VMware 发布了一份安全公告，披露了四个高风险漏洞。这些漏洞允许黑客或恶意软件绕过沙盒和虚拟机管理器的防护，从而危及宿主机的安全。特别是其中的两个漏洞，彻底颠覆了 VMware 产品的基本使命：它们让恶意软件能够直接逃脱并感染宿主机，对其他宿主机、内部网络以及其他虚拟机构成了严重的威胁。  
  
  
影响范围还涵盖了用户所使用的 VMware Workstation Pro 虚拟机软件，因此建议用户选择卸载 VMware 或尽快进行更新，以防止安全漏洞带来的风险。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qcuWhlEY4HwQic4Tx0qBdnMVZicttE2twJicXQM4dAKeGficwtPHIQ3fpNXib62cvBYp8105jqdWdedH3lOvSNPJpg/640?wx_fmt=png&from=appmsg "")  
  
受影响的产品包括：  
  
VMware ESXi 8.0，需升级到 VMware ESXi80U2sb-23305545 版  
  
VMware ESXi 8.0 [2]，需升级到 VMware ESXi80U1d-23299997 版  
  
VMware ESXi 7.0，需升级到 VMware ESXi70U3p-23307199 版  
  
VMware Workstation Pro/Player 17.x 版，需升级到 17.5.1 版  
  
VMware Fusion 13.x 版，需升级到 VMware Fusion 13.5.1 版  
  
  
下载地址：  
  
使用 VMware Workstation Pro 虚拟机的用户请点击这里直接下载新版本覆盖升级：https://download3.vmware.com/software/WKST-1751-WIN/VMware-workstation-full-17.5.1-23298084.exe  
  
  
**下面是漏洞概述：**  
  
CVE-2024-22252 ：XHCI USB 控制器的 UaF（使用后释放）漏洞。拥有虚拟机本地管理权限的用户能够在宿主机上运行 VMX 进程中执行代码，这实质上意味着能够从沙箱中逃脱，直接对宿主机构成威胁。  
  
CVE-2024-22253：UHCI USB 控制器中的 UaF 漏洞，情况与 CVE-2024-22252 类似。  
  
CVE-2024-22254：越界后写入漏洞，此漏洞使得在 VMX 进程中拥有特权的人可以触发越界写入进而导致沙箱逃逸。  
  
CVE-2024-22255：UHCI USB 控制器中的信息泄露漏洞，具有虚拟机管理访问权限的人可以利用此漏洞从 VMX 进程中泄露内存。  
  
  
**临时解决方案：**  
  
根据漏洞的描述，有三个漏洞与 USB 控制器相关。因此，VMware推荐的一种临时应对措施是直接移除 USB 控制器，特别是在你暂时无法更新到最新版本时。  
  
移除 USB 控制器将使得所有虚拟或模拟的 USB 设备，比如 U 盘或加密狗，失去功能，同时也会禁用 USB 直通功能。然而，这并不会影响鼠标和键盘的使用，因为键鼠连接并不依赖 USB 协议，因此在删除 USB 控制器之后仍然可以正常使用。  
  
  
值得注意的是，像 Mac OS X 这样的某些虚拟机系统，本身并不支持 PS/2 接口的键盘和鼠标。这意味着，在这些系统中，如果没有 USB 控制器，将无法使用键盘和鼠标。  
  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaY4s7cbNlialLcFfic6dP6ic3LeibNUDnf00LziaXkzLpLZAxjZpJQnrZdvNYN6uB6oNehc72YIYAfuFQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】 非法买卖电话卡插入“猫池”实行诈骗，山西8人被抓！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055450&idx=1&sn=007f49be0e56e7576aa44bd3f1760893&chksm=f36e0bdac41982ccc43f21ca74097be329c6b1a89f51b340655dba1f6138299d7610772fe8d7&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaY4s7cbNlialLcFfic6dP6ic3DAwFYBGCxpgia5F7iaI0iaLCwf0ib9u3HwibkmPyx5KpDRCdHyhobiaHicVKA/640?wx_fmt=png&from=appmsg "")  
[【安全圈】思科VPN产品存在高严重性漏洞，目前已修补](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055450&idx=2&sn=76290840399ae43334be3f3581c2db5c&chksm=f36e0bdac41982cc4072cc5c81b23f86d3e3ef778fa1fb9a2f5677c56552fdd3c62ccd711376&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaY4s7cbNlialLcFfic6dP6ic3AT8IR7eypPS3kCQooEafMwDdhENAR49rVZzT6grPicYD2dt3rGYr6vQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】美国运通通知客户数据泄露，并提醒客户谨防诈骗](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055450&idx=3&sn=4d6b76a9fac97a205e209c11498bcad4&chksm=f36e0bdac41982ccf3e635f4174fd01546c8eb26c7a3b09c4561425026ec41a7878b3cc1341b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaY4s7cbNlialLcFfic6dP6ic3mmrgaQWPBcadOnknpGgLedVpJ8TgALC9WsW0EOIC9Ruw9js4BsuheA/640?wx_fmt=png&from=appmsg "")  
[【安全圈】比利时Duvel Moortgat啤酒遭受勒索攻击，生产目前暂停](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055450&idx=4&sn=a9e8519e3f6eea7dfb0895c6b01732f8&chksm=f36e0bdac41982cc5fa3c129eacb79d7407ffcbea4dd9b57d6cf998d41328d0a650913d52acc&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
