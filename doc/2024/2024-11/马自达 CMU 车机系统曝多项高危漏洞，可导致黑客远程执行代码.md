#  马自达 CMU 车机系统曝多项高危漏洞，可导致黑客远程执行代码   
安世加  安世加   2024-11-12 18:15  
  
11 月 10 日消息，安全公司趋势科技近日发现日本汽车制造商马自达旗下多款车型的 CMU 车机系统（Connect Connectivity Master Unit）存在多项高危漏洞，可能导致黑客远程执行代码，危害驾驶人安全。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/UZ1NGUYLEFjmVK3OHuncV1nkO3Zriaq6MTLkhgEx5sUWMFgvibqGZGC9MkjJr7TCzJlX1YhwjdxRCaT8o2J1so6Q/640?wx_fmt=png&from=appmsg "")  
  
  
IT之家获悉，这些漏洞影响 2014 至 2021 年款 Mazda 3 等车型，涉及系统版本为 74.00.324A 的车机，黑客只需先控制受害者的手机，接着趁受害者将手机作为 USB 设备连接到 CMU 车机系统之机，即可利用相关漏洞以 root 权限运行任意代码，包括阻断车联服务、安装勒索软件、瘫痪车机系统，甚至直接危及驾驶安全。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/UZ1NGUYLEFjmVK3OHuncV1nkO3Zriaq6MibEDicuEZkYk0BIjJI4rgVSicvibsREibC53k0HRGP8Is66WEClRhT11CSg/640?wx_fmt=png&from=appmsg "")  
  
▲ 涉及的 CMU 车机系统，图源趋势科技  
  
  
趋势科技表示，具体关键漏洞包括：  
  
CVE-2024-8355：DeviceManager 中的 iAP 序列号 SQL 注入漏洞。黑客可以通过连接苹果设备进行 SQL 注入，以 root 权限修改数据库，读取或执行任意代码。  
  
  
CVE-2024-8359、CVE-2024-8360 和 CVE-2024-8358：这些漏洞允许攻击者在 CMU 的更新模块中注入任意指令，从而实现远程代码执行。  
  
  
CVE-2024-8357：SoC 验证漏洞，由于 SoC 未对启动代码进行验证，使得黑客能够悄悄修改根文件系统，安装后门，甚至执行任意代码。  
  
  
CVE-2024-8356：影响独立模块 VIP MCU 的漏洞。黑客可通过篡改更新文件，将恶意镜像文件写入 VIP MCU，进一步入侵汽车 CAN / LIN 控制网络，威胁车辆整体安全。  
  
  
研究人员指出，相应漏洞的利用门槛较低，黑客只需在 FAT32 格式的 USB 硬盘上创建文件，命名为“.up”后缀即可被 CMU 识别为更新文件，从而执行多种恶意指令。结合上述漏洞，黑客即可通过恶意 MCU 固件实现对车载网络的控制，从而直接影响车辆的运行及安全。  
  
  
本公众号发布的文章均转载自互联网或经作者投稿授权的原创，文末已注明出处，其内容和图片版权归原网站或作者本人所有，并不代表安世加的观点，若有无意侵权或转载不当之处请联系我们处理！  
  
文章来源：IT之家  
  
**点击图片即可跳转**  
  
[](http://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247540573&idx=1&sn=4905af05cd4027398427f2f63fa060e3&chksm=fc7b5b80cb0cd296123c62f1e6a9881dcee148084179180934dd7ac9520e469c8605eb2802eb&scene=21#wechat_redirect)  
  
**点击图片即可跳转**  
  
[](http://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247540490&idx=1&sn=8d0fa1665ab08ef79c32f24c533cc464&chksm=fc7b5bd7cb0cd2c17b5c360e3a49e0ca2bcf14df07ffb9849e2690701298c18c2d49dd6fb3dd&scene=21#wechat_redirect)  
  
**点击图片即可跳转**  
  
[](http://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247540617&idx=1&sn=e0f834aa41ea18c25142064225a9f385&chksm=fc7b5b54cb0cd242d91f8caf91a52302d599b6ecb206b18c60671594e5aaecfd18a084dc5c7d&scene=21#wechat_redirect)  
  
  
  
  
安世加为出海企业提供SOC 2、ISO27001、PCI DSS、TrustE认证咨询服务（点击图片可详细查看）  
  
[](http://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247540448&idx=1&sn=165f2bc3b3233827b2c601a32073aca8&chksm=fc7b5a3dcb0cd32bc659d53ad5b9eb040f9b3cd6b6289e425c96abb0848d51cf08e178907778&scene=21#wechat_redirect)  
  
  
