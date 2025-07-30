#  Windows BitLocker 漏洞暴露了 AES-XTS 加密   
 Ots安全   2025-01-23 05:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tafia8VicgibPGDmQPcA8SOV9JJQw4OMrSa0gshSNWOSn65YArsQs6dembriaopsDoLNPcRe2kYpCL97aw/640?wx_fmt=webp&from=appmsg "")  
  
Windows BitLocker全盘加密工具中存在一个中等严重程度的错误，导致 BitLocker 加密系统遭受针对 AES-XTS 加密模式的新型随机化攻击。  
  
新漏洞CVE-2025-21210凸显了全盘加密系统攻击的复杂性。一旦利用该漏洞，攻击者便可操纵密文块，从而将敏感数据以明文形式写入磁盘。  
  
Sectigo 高级研究员 Jason Soroko 解释说，BitLocker 使用 AES-XTS 加密来确保即使有人物理访问硬盘，他们也无法在没有密钥的情况下轻易读取数据手册。  
  
索罗科用一个类比来描述随机化攻击，他解释说，攻击者不是窃取或直接阅读书籍，而是巧妙地更改多本书中的某些页面（密文块）。他继续说道，当一页被篡改时，书的其余部分仍然完好无损，无法阅读。  
  
然而，通过仔细瞄准并反复修改这些页面的正确位置，攻击者可以让图书馆系统偶尔错放或泄露书中的敏感信息，索罗科说。随着时间的推移，这可能会导致部分数据以明文形式记录下来，从而有效地泄露机密信息而无需直接解密。  
  
“真正的危险在于，这种方法不需要直接破解加密，”Soroko 说。“相反，它操纵加密数据的处理方式，让攻击者能够绕过安全措施并访问敏感信息。团队应确保其加密软件已安装最新的安全补丁，限制对设备的物理访问，并监控系统中可能存在任何可能表明篡改的异常活动。”  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
