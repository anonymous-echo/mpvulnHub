#  【安全圈】Microsoft MSHTML 漏洞被利用来传播 MerkSpy 间谍软件工具   
 安全圈   2024-07-04 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
据观察，未知黑客组织利用 Microsoft MSHTML 中现已修补的安全漏洞传播名为MerkSpy的间谍软件监视工具，主要针对加拿大、印度、波兰和美国目标。  
  
  
Fortinet FortiGuard Labs 研究员 Cara Lin在上周发布的一份报告中表示：“MerkSpy 旨在秘密监视用户活动，获取敏感信息并在受感染系统上建立持久性。”  
  
  
攻击链的起点是一个 Microsoft Word 文档，其中表面上包含软件工程师职位的描述。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaExwsQCKA1om0LJ13TbM2GeVYXcibJaYYk3mfUl8tCTEyzBR6VODBoX251EciaY82hpvZKov2TT7Fpg/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
诱饵文档  
  
  
但打开该文件会触发CVE-2021-40444漏洞利用，这是   
MSHTML  
 中的一个高严重性漏洞，可能导致远程代码执行而无需任何用户交互。微软已在 2021 年 9 月发布的补丁更新中解决了该问题。  
  
  
在这种情况下，它为从远程服务器下载 HTML 文件（“olerender.html”）铺平了道路，然后在检查操作系统版本后启动嵌入式 shellcode 的执行。  
  
  
林解释说，“Olerender.html”利用“  
VirtualProtect  
”修改内存权限，从而允许将解码后的 shellcode 安全地写入内存”。  
  
  
“随后，‘CreateThread’ 执行注入的 shellcode，为从攻击者的服务器下载和执行下一个负载做好准备。此过程确保恶意代码无缝运行，从而促进进一步的利用。”  
  
  
该 shellcode 充当一个文件下载器，该文件的标题看似是“GoogleUpdate”，但实际上却包含一个注入器负载，负责逃避安全软件的检测并将 MerkSpy 加载到内存中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaExwsQCKA1om0LJ13TbM2GebKapAEibwGYvdR16TaiaPlaXIIO1ia4VkyYYicicLIDlSMhT43k2lfHdpmQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
攻击链  
  
  
该间谍软件通过更改 Windows 注册表在主机上建立持久性，以便在系统启动时自动启动。它还具有秘密捕获敏感信息、监视用户活动以及将数据泄露到黑客控制的外部服务器的功能。  
  
  
其中包括屏幕截图、按键、存储在 Google Chrome 中的登录凭据以及来自   
MetaMask  
 浏览器扩展程序的数据。所有这些信息都传输到 URL“45.89.53[.]46/google/update[.]php”。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDLQW996nP0FknIKIIsrFDibZEsOM03aUUYwTqhZA82GWKABZAPsBicW1Aac8bDnAqmf2vDXLtXd6Q/640?wx_fmt=jpeg "")  
[【安全圈】可获 root 权限，思科 NX-OS 零日漏洞修复已发布](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062520&idx=1&sn=fe43c7a39bc5a06b1c4e2934de8517d3&chksm=f36e6f78c419e66eb25c48ea0339a6f5741303ec3bc98d3ccd0573700ecddfbbb7d4fc4bb35c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5HmJHohtKbicUic2JlWJ2xGHufmrtVGbQhpMfGrA4AZxWWTX7XwgqA0lHPQS50TdQlZoPy1UiaPuMw/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】Windows 修复漏洞遭利用，推送恶意脚本](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062520&idx=2&sn=764d34aa1130ed7f83bd837c6a514c0e&chksm=f36e6f78c419e66e413059b9aaa771ab1b665e91d98232c678435a787fa8d94713d0da0c9480&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5HmJHohtKbicUic2JlWJ2xGIIkVKm4WbdN2wsKVTd0tHQiacN8F9t39dJ625FCiaNb4nhGJCT4dib8Vg/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】巴基斯坦 CapraRAT 间谍软件伪装成热门应用程序威胁印度 Android 用户](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062520&idx=3&sn=cd92e458da23905410eb6214c8aeddef&chksm=f36e6f78c419e66efacfa38611d38f8a4f09ee2185cffe39a40e5038f26d70cdc5eb690b3827&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDLQW996nP0FknIKIIsrFD3VwzNKKXfrFofVmNpN9FDv7oicUk0TrIOG4Hzqrq8Dt0nF0qZEOwlkw/640?wx_fmt=jpeg "")  
[【安全圈】Juniper 警告存在严重身份验证绕过漏洞（CVE-2024-2973，CVSS 评分为 10）](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062520&idx=4&sn=33ecb849545820707a62bfcb0b8c9a95&chksm=f36e6f78c419e66eebbbded12a5cc5f0ec54f274fdd57fa651a96f8090a6cf2cb8b0bddfd7b0&scene=21#wechat_redirect)  
                                                            
  
  
  
  
  
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
  
