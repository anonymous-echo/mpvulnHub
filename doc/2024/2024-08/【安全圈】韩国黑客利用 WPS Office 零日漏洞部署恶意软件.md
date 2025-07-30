#  【安全圈】韩国黑客利用 WPS Office 零日漏洞部署恶意软件   
 安全圈   2024-08-29 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
恶意软件  
  
  
据BleepingComputer消息，与韩国有关的网络黑客组织 APT-C-60近期一直在利用 Windows 版 WPS Office 中的零日漏洞，针对东亚地区目标部署 SpyGlace 后门。  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljibib6DAVHApmNb590Tn8hhcU2sGEczgmCWicYJ8Cib1cCct17Hl8e6x4t0faRO9EJNctdhHOYnVj4bQ/640?wx_fmt=jpeg&from=appmsg "")  
  
这个被跟踪为 CVE-2024-7262 的零日漏洞至少自 2024 年 2 月下旬以来就被用于野外攻击，影响了WPS 12.2.0.13110至12.1.0.16412之间的版本。今年3月，金山软件已经修补了该漏洞。  
  
CVE-2024-7262 存在于软件处理自定义协议处理程序的方式中，特别是 "ksoqing://"，允许通过文档中特制的 URL 执行外部应用程序。由于对这些 URL 的验证和消毒不当，该漏洞允许攻击者制作恶意超链接，从而导致任意代码执行。  
  
APT-C-60 通过创建MHTML 文件，在其中嵌入了隐藏在诱饵图像下的恶意超链接，诱使受害者点击并触发漏洞。  
  
恶意URL 参数包括一个 base64 编码命令，用于执行一个特定插件 (promecefpluginhost.exe)，该插件会尝试加载包含攻击者代码的恶意 DLL (ksojscore.dll)，该 DLL 作为 APT-C-60 的下载器组件，用于从攻击者的服务器（一个名为 "SpyGlace "的自定义后门）获取最终有效载荷 (TaskControler.dll)。  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljibib6DAVHApmNb590Tn8hhcbicjUicMuTHoeMoib8JwL9cBzK8e2pUSqkdABulAuH4XuiaH52HJUXxPWw/640?wx_fmt=jpeg&from=appmsg "")  
  
APT-C-60攻击概述  
  
此外，研究人员还发现了另外一个任意代码执行漏洞 CVE-2024-7263，该漏洞出现于针对 CVE-2024-7262的补丁缺陷当中。具体来说，金山软件虽然增加了对特定参数的验证，但一些参数（如 "CefPluginPathU8"）仍未得到充分保护，从而允许攻击者再次通过promecefpluginhost.exe指向恶意DLL的路径。目前该漏洞也于今年5月得到了修补。  
  
由于这两个漏洞利用具有较高的欺骗性，能诱使任何用户点击看起来合法的电子表格，安全专家建议WPS用户尽快升级至12.2.0.17119以上或最新版本。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgspLibGEkic5zqEGgGBbpBwyf5eic7UPxuicJb2ic8f57SZ26OFyVLvZhTQ39vY3p6ibQ1HqLicqyfoVWEg/640?wx_fmt=jpeg "")  
[【安全圈】美国哈利伯顿公司（Halliburton）遭受攻击，对全球能源行业产生影响](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063903&idx=1&sn=45bfa77f2b7d53c570659d84ce3bf1e1&chksm=f36e64dfc419edc9aa34c512b83572e289f162efd1b764884883c79069d55717d8ce37af94c4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgspLibGEkic5zqEGgGBbpBwyjrgbeibMgJh3WNcznxx7zXhYFdqq2MVN1BB5YDJkULChS6LJhP9TCYA/640?wx_fmt=jpeg "")  
[【安全圈】黑客使用鲜为人知的隐秘技术攻击东南亚高级别组织](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063903&idx=2&sn=87b76059045706ba5c3c26e0991ec3d9&chksm=f36e64dfc419edc9583453354dfa71fa746ead471cd97fbd9399f03f3d70c5704a690d6d4f5d&scene=21#wechat_redirect)  
  
  
【安全圈】网络身份证是强制，会影响正常上网？公安部详细回应  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgspLibGEkic5zqEGgGBbpBwyiaVOttBxUiaJECagpiamKds6y1NwplgIONlsibsES284InXr59mKj3IhHQ/640?wx_fmt=jpeg "")  
[【安全圈】微软Sway在大规模二维码钓鱼活动中被滥用](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063903&idx=3&sn=ca84d4783cca05e1b0ffe67433a29976&chksm=f36e64dfc419edc906c7a38517fade3afa85e621e0ea6e65f5c632a52e74a87889dee637cf3e&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgspLibGEkic5zqEGgGBbpBwysbEYNWwX1Uuw3tBIpibiaOju5slu9srfiabMahTm4ZvSLtoOWuFwuTKug/640?wx_fmt=jpeg "")  
[【安全圈】ServiceBridge泄露 3200万份文件，大量企业数据被曝光](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063903&idx=4&sn=f636662579b4259de097fd92da53510e&chksm=f36e64dfc419edc99239874da682ab526b676322eb948f30c5b15fbf3fb417c424b21fb472ef&scene=21#wechat_redirect)  
                         
  
  
  
  
  
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
  
