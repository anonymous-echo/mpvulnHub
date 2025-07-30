#  【安全圈】黑客利用 Windows SmartScreen 漏洞投放 DarkGate 恶意软件   
 安全圈   2024-04-22 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
恶意软件  
  
  
DarkGate 恶意软件操作发起的新一波攻击，利用现已修复的 Windows Defender SmartScreen 漏洞来绕过安全检查，并自动安装虚假软件安装程序。  
  
SmartScreen 是一项 Windows 安全功能，当用户尝试运行从 Internet 下载的无法识别或可疑文件时，它会显示警告。   
  
被追踪为 CVE-2024-21412 的缺陷是 Windows Defender SmartScreen 缺陷，允许特制的下载文件绕过这些安全警告。  
  
攻击者可以通过创建指向远程 SMB 共享上托管的另一个 .url 文件的 Windows Internet 快捷方式（.url 文件）来利用该缺陷，这将导致最终位置的文件自动执行。  
  
微软于 2 月中旬修复了该漏洞。出于经济动机的 Water Hydra 黑客组织此前就曾利用该漏洞作为零日漏洞 ，将其 DarkMe 恶意软件植入到交易者的系统中。  
  
有分析师报告称，DarkGate 运营商正在利用相同的缺陷来提高他们在目标系统上成功（感染）的机会。  
  
该恶意软件与 Pikabot 一起填补了去年夏天 QBot 破坏造成的空白 ，并被多个网络犯罪分子用于分发恶意软件。  
  
**DarkGate 攻击细节**  
  
该攻击从一封恶意电子邮件开始，其中包含一个 PDF 附件，其中的链接利用 Google DoubleClick 数字营销 (DDM) 服务的开放重定向，来绕过电子邮件安全检查。  
  
当受害者点击该链接时，他们会被重定向到托管互联网快捷方式文件的受感染 Web 服务器。此快捷方式文件 (.url) 链接到托管在攻击者控制的 WebDAV 服务器上的第二个快捷方式文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljVLuWibgbia9wrN8Ju2hmic10vt5zTP5qje7GmlMg6SB8JX2l2gxJiclnibpibMbDKciag6Axp90bSuokQA/640?wx_fmt=jpeg&from=appmsg "")  
  
利用 CVE-2024-21412 SmartScreen 漏洞  
  
使用一个 Windows 快捷方式在远程服务器上打开第二个快捷方式，可有效利用 CVE-2024-21412 缺陷，导致恶意 MSI 文件在设备上自动执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljVLuWibgbia9wrN8Ju2hmic10c2yibKB1gdNLM62vdZp0Wz3B5eibkbr92trN3ZEL4JsJFrNoicWBibEbBw/640?wx_fmt=jpeg&from=appmsg "")  
  
自动安装 MSI 文件的第二个 URL 快捷方式  
  
这些 MSI 文件伪装成来自 NVIDIA、Apple iTunes 应用程序或 Notion 的合法软件。  
  
执行 MSI 安装程序后，涉及“libcef.dll”文件和名为“sqlite3.dll”的加载程序的另一个 DLL 侧载缺陷将解密并执行系统上的 DarkGate 恶意软件负载。  
  
一旦初始化，恶意软件就可以窃取数据，获取额外的有效负载并将其注入正在运行的进程中，执行按键日志记录，并为攻击者提供实时远程访问。  
  
自 2024 年 1 月中旬以来，DarkGate 运营商采用的复杂且多步骤的感染链总结如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljVLuWibgbia9wrN8Ju2hmic10tpuljPQ9VP67qcwTwSkGItQpxBILl76wNUujSlibxL4ich2ClnjavLvA/640?wx_fmt=jpeg&from=appmsg "")  
  
DarkGate感染链  
  
该活动采用了 DarkGate 6.1.7 版本，与旧版本 5 相比，该版本具有 XOR 加密配置、新配置选项以及命令和控制 (C2) 值的更新。  
  
DarkGate 6 中提供的配置参数，使其操作员能够确定各种操作策略和规避技术，例如启用启动持久性或指定最小磁盘存储和 RAM 大小以规避分析环境。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljVLuWibgbia9wrN8Ju2hmic10gzZlVBPp6J7036fmvuRgAicvjiaiajxK8S9KXfYlZfXtrfIKoEYsthUHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
DarkGate v6配置参数  
  
减轻这些攻击风险的第一步是应用 Microsoft 的 2024 年 2 月补丁星期二更新，该更新修复了 CVE-2024-21412。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hD6xSAY3w3YmM8G5GmxzPjYyjgR6Xje4JUniba7Pwniaia6h0RGjhvoeDXn2Bhvbia2SAN8dKt3jwMGx1xhXCvkHQg/640?wx_fmt=jpeg "")  
[【安全圈】告破！以虚拟币大量贩卖个人信息！比特币又有大消息](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058517&idx=1&sn=0d343969458b703f2c4d475550752f90&chksm=f36e1fd5c41996c3d05fbcf5e4fcbae186cb16a1d34a6097bc02f6a3a8ee7f7ec83d4f6cd7b2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhDnXKGA8y5DCdLeSibbJkFkSHwd7ylicgXUyoibEmSib2g80H3ukiay49BVjdMWCiaxbd1f3k3kpwugXHQ/640?wx_fmt=png "")  
[【安全圈】一举查获作案设备2400余台！青岛警方重拳出击斩断电信网络诈骗链条](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058517&idx=2&sn=c744fa56b7d67c70adce0ede41a99d66&chksm=f36e1fd5c41996c32f6f0ca1109ef573d68da831308560817f327e6e7b22819aa9787cf7b2d5&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhDnXKGA8y5DCdLeSibbJkFkb9zTKgHVSiaKEib1QpQBxZpw3QR9I9rBEzUXhWES3wf2PlzPTQJQYCTw/640?wx_fmt=jpeg "")  
[【安全圈】GPT-4 化身黑客搞破坏，成功率 87%！OpenAI 要求保密提示词](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058517&idx=3&sn=b57cb5c8e5d4a2ecfa295053c9212e01&chksm=f36e1fd5c41996c3870cc2d5c35baaa57e216accd4b9095a73012cf1353f90c2d73d8f3789d3&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PBFhCIFb3MvibbtfWRMjfjYIdnVhRTJlLWibrCECbWvz2khKlBUculJ6IzWbrohEDyogqGAFar878XRTHLOTuiaDw/640?wx_fmt=png "")  
[【安全圈】kkFileView文件上传代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058517&idx=4&sn=1303a6dbc3664c88e254b4b87fb01967&chksm=f36e1fd5c41996c34b585970d20b8cc0c1a3677480443fdc65d50d87eabc75545cac8e979553&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
