#  已打补丁但仍有漏洞 Windows BitLocker 加密再次被绕过   
 信息安全大事件   2025-01-06 11:58  
  
在混沌通信大会（CCC）上出现的一个新发现动摇了 Windows 可信赖的 BitLocker 加密技术的基础。安全研究员托马斯-兰伯茨（Thomas Lambertz）在其题为 “Windows BitLocker：没有螺丝刀也能拧紧 ”的演讲中暴露了一个明显的漏洞，该漏洞允许攻击者绕过 BitLocker 加密并访问敏感数据，即使是在据称已针对该漏洞打了补丁的系统上也是如此。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA7ASZdXH1gbyibSdfuk9PYtcNqZgetSKcY6iaSmRmicjHEGUXzJD9QhU9vUwibPlUMYSw9ibFlo12ic4DuQ/640?wx_fmt=png&from=appmsg "")  
  
这个被称为 “bitpixie”（CVE-2023-21563）的漏洞最初于 2022 年 11 月被微软解决。然而，Lambertz 演示了攻击者如何利用过时的 Windows 引导加载器通过安全启动来提取加密密钥。这种攻击只需要对设备进行瞬间物理访问和网络连接，无需使用螺丝刀或硬件黑客。  
  
其根本原因在于 UEFI 中的证书存储空间有限，而 UEFI 是启动过程中的一个关键组件。新的安全启动证书预计在 2026 年前无法获得。作为临时措施，Lambertz 建议用户为 BitLocker 设置自定义 PIN 或通过 BIOS 禁用网络访问。不过，即使是基本的联网 USB 设备也有可能为攻击提供便利。  
  
虽然普通用户可能不是主要攻击目标，但对企业、政府和其他高安全环境的影响却很大。只需短暂的物理访问就能完全解密设备，这引起了人们对数据保护的严重关注。  
  
对于那些希望进一步探讨这一话题的人，CCC 媒体中心网站上有兰伯特 56 分钟演讲的完整录音。它深入探讨了错综复杂的技术问题，并解释了为什么解决这一漏洞会带来如此艰巨的挑战。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006509" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
