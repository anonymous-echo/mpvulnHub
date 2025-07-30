#  已修补但仍然存在漏洞：Windows BitLocker 加密再次被绕过   
 Ots安全   2025-01-03 06:49  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tad8Eh30fibaTM0yN24SRibKIxZfhrykF39ZvBTBkPM7r6LKN6GBhpf9RwufI0Lx2YJr5p2gKAlxPpAw/640?wx_fmt=png&from=appmsg "")  
  
上周，混沌通信大会 (CCC) 披露了一项新发现，动摇了 Windows 受信任的 BitLocker 加密的基础。安全研究员 Thomas Lambertz 在他的演讲“Windows BitLocker：不用螺丝刀就能搞定”中揭露了一个明显的漏洞，该漏洞允许攻击者绕过 BitLocker 加密并访问敏感数据，即使在据称已修补该漏洞的系统上也是如此。  
  
该漏洞被称为“bitpixie”（CVE-2023-21563），最初由微软于 2022 年 11 月解决。然而，Lambertz 演示了攻击者如何通过安全启动利用过时的 Windows 引导加载程序来提取加密密钥。此攻击只需要对设备进行短暂的物理访问和网络连接 - 无需螺丝刀或硬件黑客攻击。  
  
根本原因在于 UEFI 中证书的存储空间有限，而 UEFI 是启动过程中的关键组件。预计新的安全启动证书要到 2026 年才会推出。作为临时措施，Lambertz 建议用户为 BitLocker 设置自定义 PIN 或通过 BIOS 禁用网络访问。然而，即使是基本的联网 USB 设备也可能为攻击提供便利。  
  
虽然普通用户可能不是主要目标，但对企业、政府和其他高安全性环境的影响却十分重大。只需短暂的物理访问即可完全解密设备，这引发了人们对数据保护的严重担忧。  
  
对于那些希望进一步探讨该主题的人，可以在 CCC 媒体中心网站上查看Lambertz 56 分钟演讲的完整录音。它深入探讨了技术复杂性，并解释了为什么解决此漏洞是一项如此艰巨的挑战。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tad8Eh30fibaTM0yN24SRibKIxibhm0A8ibsWu6CL1BvBFib2YiaR0XsXrwuCQM2Lzg9L07uM7Vrn6FiaJRibw/640?wx_fmt=png&from=appmsg "")  
  
**视频地址：**  
  
https://securityonline.info/patched-but-still-vulnerable-windows-bitlocker-encryption-bypassed-again/  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
