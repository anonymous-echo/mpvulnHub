#  指纹传感器漏洞可在戴尔、联想、微软上绕过Windows Hello登录   
ang010ela  嘶吼专业版   2023-11-24 12:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
Windows Hello是使用PIN、面部识别或指纹来快速访问Windows 11设备的一种更个性化、更安全的方式，从3年前开始，微软便称使用Windows Hello登录Windows 10设备的用户已从2019年的69.4%增加到了84.7%。  
  
Blackwing Intelligence安全研究人员评估Windows Hello指纹认证使用的3款嵌入式指纹传感器安全时，发现了多个安全漏洞。攻击者利用这些漏洞可以绕过设备的Windows Hello指纹认证，受影响的设备包括戴尔Inspiron、联想ThinkPad、微软Surface Pro X等笔记本电脑。  
  
研究人员测试了微软Surface Pro X、联想ThinkPad T14、戴尔Inspiron 15使用的ELAN、Synaptics和Goodix嵌入式指纹传感器，所有受测指纹传感器都拥有自己的微处理器和存储的MOC芯片，允许指纹匹配在芯片内安全地进行。  
  
MoC处理器可以预防存储的指纹数据重放到主机进行匹配，但无法阻止恶意传感器模拟合法的传感器与主机进行通信，这可以在主机和传感器之间重放之前观察到的流量。为应对此类攻击，微软开发了安全设备连接协议（Secure Device Connection Protocol ），以确保指纹设备是可信的和健康的，指纹设备和主机之间的输入是受到目标设备保护的。  
尽管如此，安全研究人员仍然使用一个定制的Linux  Raspberry Pi 4设备发起中间人攻击，成功绕过了以上三款被测设备的Windows Hello认证。  
研究人员使用软件和硬件逆向工程破解了Synaptics传感器定制的TLS协议的加密实  
现，解码并重新实现了专用协议。  
  
在戴尔和联想笔记本上，认证绕过是通过使用合法Windows用户的ID来枚举有效的ID和注册攻击者指纹来实现的。对于微软Surface设备，其ELAN指纹传感器没有SDCP保护，使用的是明文的USB通信，也没有认证，在与含有传感器的Type C断开后就可以欺骗指纹传感器并从被欺骗的设备上发送有效的登录响应。  
  
研究人员称，微软通过SDCP为主机和生物设备之间提供了安全的通道，但设备厂商错误理解了其中的一些目标。此外，大多数设备是没有被SDCP保护的，研究人员甚至发现这3款笔记本设备中有2款设备未启用SDCP。  
  
完整技术分析可参见：https://blackwinghq.com/blog/posts/a-touch-of-pwn-part-i/  
  
参考及来源：https://www.bleepingcomputer.com/news/security/windows-hello-auth-bypassed-on-microsoft-dell-lenovo-laptops/![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icMKDYBpteI8CtaohicT9I7hZogn8icONAWMDzc2md2DFPBrbwz4pZz2qn5EGiaDKpTuibgKvG3BWRIfA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icMKDYBpteI8CtaohicT9I7hrSH4nEJfVsByyvfmbj3AYKOOo1jPliaHDDWIn1ibNKmRWUclvQ41saKg/640?wx_fmt=png&from=appmsg "")  
  
  
