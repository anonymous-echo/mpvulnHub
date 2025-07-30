#  【安全圈】Ghostscript开源PDF库中发现关键漏洞，需用户尽快更新   
 安全圈   2023-07-13 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljneYp850RJzeWxQxicFM3PokVwKpDFzeDz4cNmNQdyLajEBtfEg8gcibVKicYrzr5vCib096oJl7Es7Q/640?wx_fmt=jpeg "")  
  
在Linux中广泛使用的PostScript语言和PDF文件开源解释器Ghostscript被发现存在严重远程代码执行漏洞。  
  
该漏洞被标记为CVE-2023-3664，CVSS v3评级为9.8，影响10.01.2之前的所有Ghostscript版本，10.01.2是三周前发布的最新版本。  
  
据Kroll公司的分析师G. Glass和D. Truman称，他们针对该漏洞开发了一个概念验证（PoC）漏洞，在打开恶意特制文件时可触发代码执行。  
  
考虑到许多Linux发行版都默认安装了Ghostscript，而且LibreOffice、GIMP、Inkscape、Scribus、ImageMagick和CUPS打印系统等软件也使用了Ghostscript，因此在大多数情况下，触发CVE-2023-3664的机会非常多。  
  
Kroll还表示，如果Windows上的开源应用程序使用了Ghostscript的端口，那么该漏洞也会影响到这些应用程序。  
## Ghostscript漏洞  
  
CVE-2023-3664漏洞与操作系统管道有关，管道允许不同的应用程序通过将一个应用程序的输出作为另一个应用程序的输入来交换数据。  
  
问题源于Ghostscript中的 "gp_file_name_reduce() "函数，该函数似乎可以获取多个路径，并通过移除相对路径引用来简化路径以提高效率。  
  
然而，如果向该漏洞函数提供特制的路径，它可能会返回意外的结果，从而导致覆盖验证机制和潜在的漏洞利用。  
  
此外，当Ghostscript尝试打开一个文件时，它会使用另一个名为 "gp_validate_path "的函数来检查其位置是否安全。  
  
然而，由于存在漏洞的函数会在第二个函数检查之前更改位置细节，因此攻击者很容易利用这个漏洞，迫使Ghostscript处理本应禁止的文件。  
  
Kroll公司的分析人员创建了一个PoC，只要在任何使用Ghostscript的应用程序上打开EPS（嵌入式Postscript）文件，就会触发该PoC。  
  
因此，如果你是Linux用户，建议升级到最新版本的Ghostscript 10.01.2。  
  
如果你是在Windows上使用Ghostscript端口的开源软件，则需要更多时间来升级到最新版本。因此，建议在Windows中安装时格外小心。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljneYp850RJzeWxQxicFM3Poq8y9pAeLDYtgZj6ZJpjje4OhQHpqEgsOD4oPiabBP2uMiaXfLrghicb6A/640?wx_fmt=png "")  
[【安全圈】遭遇黑客攻击，HCA 医疗泄露 1100 万患者敏感信息](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039283&idx=1&sn=4347c0c1b89a7df9c339915e360b24d1&chksm=f36fc433c4184d2530bb72c19168d3d2d68b68f690e2defc4f9ec1474b7871067f85e0cf47b4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljneYp850RJzeWxQxicFM3Po0wmHHh7iaIPB9Zq1HaqEwnqM6JwwoRINmoVRBNwkRzWMAzoHS7TRkLw/640?wx_fmt=png "")  
[【安全圈】危险！哈佛大学网站现高危漏洞，可导致数据泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039283&idx=2&sn=40f2febe4085e40b1bf331a4e4975ec6&chksm=f36fc433c4184d255e4b460de41bbd49e4b2c5fdb040103b350f18c2e424c1d33bc59553b8af&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljneYp850RJzeWxQxicFM3PoMGmpBcuQXtkdw3DOyV2qIPdccCGqATic38tGfTGuHQEeg6F2LibzhZkA/640?wx_fmt=png "")  
[【安全圈】360日均阻断逾千次，RustDog钓鱼木马愈演愈烈](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039283&idx=3&sn=ee1475e6aafb37927c1765048527e66a&chksm=f36fc433c4184d25be8387d8a48233f3e3f0017205777aaadd96b170f5154d1e5e7cbb8720dc&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljneYp850RJzeWxQxicFM3Poejl1E8Cl19u5cuDPJpFNYiasicL3KjJsQgKkQc6f2cd55oWicDn7tHF0Q/640?wx_fmt=png "")  
[【安全圈】北约峰会遭遇RomCom黑客组织攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652039283&idx=4&sn=c5314239a821fd92193e8bc6fc3475cf&chksm=f36fc433c4184d25de025053af639284f66c41c9b6c2f8b9165181923c668e45efb9e268ab62&scene=21#wechat_redirect)  
  
  
  
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
  
  
