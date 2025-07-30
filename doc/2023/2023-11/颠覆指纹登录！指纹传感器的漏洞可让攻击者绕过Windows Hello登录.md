#  颠覆指纹登录！指纹传感器的漏洞可让攻击者绕过Windows Hello登录   
 关键基础设施安全应急响应中心   2023-11-23 14:51  
  
一项新的研究发现了多个漏洞，这些漏洞可被用来绕过Dell Inspiron 15、Lenovo ThinkPad T14和Microsoft Surface Pro X 笔记本电脑上的Windows Hello身份验证。这些缺陷是由硬件和软件产品安全和攻击性研究公司Blackwing Intelligence的研究人员发现的，他们发现了嵌入到设备中的Goodix、Synaptics和ELAN指纹传感器的漏洞。这项研究在Microsoft进攻研究和安全工程 (MORSE)的赞助下实施的。指纹识别器利用的先决条件是目标笔记本电脑的用户已经设置了指纹身份验证。所有指纹传感器都是一种称为“片上匹配”( MoC ) 的传感器，它将匹配和其他生物识别管理功能直接集成到传感器的集成电路中。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVt67b9NtHicH0cmJegJIscFMUIwlQbBrLEwBt1pjvs2GNo2QTG3db2xf4GWnKlMhBh3IiavchY2sPw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
颠覆指纹登录  
  
Blackwing团队的Jesse D'Aguanno和Timo Teräs针对Microsoft Surface Pro X、Lenovo ThinkPad T14和Dell Inspiron 15上由ELAN、Synaptics和Goodix制造的嵌入式指纹传感器。  
  
所有测试的指纹传感器都是片上匹配 (MoC) 传感器，具有自己的微处理器和存储器，允许在芯片内安全地执行指纹匹配。  
  
然而，虽然MoC传感器阻止将存储的指纹数据重播到主机进行匹配，但它们本身并不能阻止恶意传感器模仿合法传感器与主机的通信。这可能会错误地指示成功的用户身份验证或重放之前观察到的主机和传感器之间的流量。  
  
为了抵御利用这些弱点的攻击，Microsoft开发了安全设备连接协议 (SDCP)，该协议应确保指纹设备可信且健康，并且指纹设备和主机之间的输入在目标设备上受到保护。  
  
尽管如此，安全研究人员利用定制的Linux驱动的Raspberry Pi 4设备，在所有三台笔记本电脑上使用中间人 (MiTM) 攻击成功绕过了 Windows Hello身份验证。  
  
在整个过程中，他们使用软件和硬件逆向工程，突破了Synaptics传感器自定义TLS协议中的加密实现缺陷，解码并重新实现了专有协议。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVt67b9NtHicH0cmJegJIscFsFD0aBpEsmutWgBwPtDW1Gv9siawtGXNmVvwqEpN6es57G5YnibnItdg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在戴尔和联想笔记本电脑上，通过枚举有效ID并使用合法Windows用户的ID注册攻击者的指纹来实现身份验证绕过（Synaptics传感器使用自定义TLS堆栈而不是SDCP来保护USB通信）。  
  
对于Surface设备，其ELAN 纹传感器没有SDCP保护，使用明文USB 信，并且没有身份验证，他们在断开包含传感器的键盘盖后欺骗指纹传感器，并从欺骗设备发送有效的登录响应。  
  
研究人员表示：“微软在SDCP设计上做得很好，可以在主机和生物识别设备之间提供安全通道，但不幸的是，设备制造商似乎误解了一些目标。”  
  
“此外，SDCP仅覆盖典型设备操作的非常狭窄的范围，而大多数设备都暴露出相当大的攻击面，而SDCP根本没有覆盖这些攻击面。”  
  
在发现三分之二的目标笔记本电脑上甚至没有启用安全设备连接协议 (SDCP) 后，Blackwing Intelligence建议制造生物识别身份验证解决方案的供应商确保启用SDCP，因为如果不切换它，将无助于阻止攻击在。  
  
这并不是基于Windows Hello生物识别技术的身份验证第一次被成功破解。2021年7月，微软发布了针对中等严重性安全漏洞（CVE-2021-34466，CVSS评分：6.1）的补丁，该漏洞可能允许攻击者欺骗目标的面部并绕过登录屏幕。  
  
更多类似漏洞尚未发现  
  
Jesse D'Aguanno的研究仅限于三台笔记本电脑，由三种型号的指纹识别器提供服务。类似的漏洞可能在世界上更多的芯片和更多依赖它们的计算机中仍未被发现和解决。  
  
Jesse D'Aguanno表示，“当然，无论是其他制造商还是Linux等其他环境，还是苹果生态系统，那里也都有潜力。”。  
  
不过，无论如何，他的研究并没有动摇他对生物识别技术的信心。  
  
Jesse D'Aguanno认为，有很多安全专业人士认为生物识别技术本身就很糟糕。实际上，他认为适当使用生物识别技术可以在很多方面增强安全性。它可以让你选择一个更长、更安全的口令，然后也可用于其他安全机制，例如生成更安全的加密密钥来保护你的数据。因此，生物识别技术的使用为你提供了这种程度的便利。   
  
Jesse D'Aguanno告诉Darkreading，制造商——Goodix、Synaptics和Elan——此后已经修补了他们的芯片。  
  
微软三年前表示，使用Windows Hello而不是口令登录Windows 10设备的用户数量从2019年的69.4%增长到84.7% 。  
  
延伸阅读  
  
微软安全响应中心 (MSRC)发布了演讲视频，为Blackwing Intelligence研究团队在BlueHat（10月23日）上的分享：题目为《A Touch of Pwn：攻击Windows Hello指纹验证》。该视频深入介绍了漏洞研究过程，其中涉及软件和硬件的全面逆向工程、发现自定义TLS中的加密实现缺陷以及解码和重新实现专有协议。研究过程从对生物识别身份验证的基本了解到成功绕过所有三个研究目标的 Windows Hello身份验证。演讲重点介绍了安全设备连接协议 (SDCP)、逆向工程以及创建自定义Wireshark解析器以了解USB上专有的主机到传感器通信协议的关键方面。它还引入了一种为高速设备创建USB MitM的独特方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVt67b9NtHicH0cmJegJIscF6wkaibMX5zRAnRpYPKl04XGicszgic20Pic3R3rZJnGMJ7o9VkyL7qCerA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**参考资源：**  
  
1.https://www.bleepingcomputer.com/news/security/windows-hello-auth-bypassed-on-microsoft-dell-lenovo-laptops/  
  
2.https://thehackernews.com/2023/11/new-flaws-in-fingerprint-sensors-let.html  
  
3.https://www.darkreading.com/vulnerabilities-threats/researchers-undermine-windows-hello-lenovo-dell-surface-pro-pcs  
  
  
  
原文来源：网空闲话plus  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
