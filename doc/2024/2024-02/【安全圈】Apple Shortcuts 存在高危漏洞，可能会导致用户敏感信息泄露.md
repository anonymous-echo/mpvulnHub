#  【安全圈】Apple Shortcuts 存在高危漏洞，可能会导致用户敏感信息泄露   
 安全圈   2024-02-27 19:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
Apple Shortcuts 应用程序中存在一个高严重性漏洞，可允许攻击者在不提示用户的情况下访问敏感信息。  
  
网络安全公司Bitdefender 解释说，该问题被标记为 CVE-2024-23204，影响 iOS 和 macOS 用户，只能通过某些操作触发，但允许攻击者绕过苹果管理敏感用户信息和系统资源访问的框架。  
  
该公司表示，该问题与 Shortcuts 后台进程有关，可以绕过透明、同意和控制 (TCC)，确保应用程序无法访问某些敏感信息，除非用户明确授予权限。  
  
Apple Shortcuts 是一款自动化应用程序，提供数百个内置操作，使用户能够通过文件管理、教育、智能家居集成等个性化工作流程来简化 iOS 和 macOS 上的任务。  
  
据 Bitdefender 称，该漏洞使得 Shortcuts 后台进程即使在沙箱中也可以访问一些敏感数据。通过使用快捷方式中的“扩展 URL”功能，网络安全公司能够绕过 TCC 并将照片的 Base64 编码数据传输到远程网站。  
> Bitdefender 指出：“该方法涉及在快捷方式中选择任何敏感数据（照片、联系人、文件和剪贴板数据），将其导入，使用 Base64 编码选项进行转换，最后将其转发到恶意服务器。”  
  
  
然后，攻击者可以使用 Flask 程序捕获传输的数据，以收集敏感信息以供将来利用。Apple 允许用户导出和共享快捷方式，攻击者可能会滥用此功能来传播易受 CVE-2024-23204 攻击的快捷方式并瞄准安装它们的用户。  
  
该漏洞已于 1 月份随着iOS 17.3 和 iPadOS 17.3以及 macOS Sonoma 14.3 的发布得到解决。  
  
苹果指出：“快捷方式可能能够在某些操作中使用敏感数据，而无需提示用户。建议用户尽快安装最新的iOS和macOS补丁。”  
  
  
来源：安全客  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaeD6a0GGZABALptKxZ5sY497riboF3Z4UCUFCic1VlD2cqKvrMuzuCWrXaicFHT4kLEHbbyTvmiacjpA/640?wx_fmt=jpeg "")  
[【安全圈】因缺乏网络安全监管，北京一公司网站被黑客改成赌博网站！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054638&idx=1&sn=feb9c9fcdbbe96df45b7410a4675f2d8&chksm=f36e082ec41981382c2ff235668d79d6c7a515411f3543e6ce576ad0f360517824bbc622520d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaeD6a0GGZABALptKxZ5sY4mnPlAozAZgJfVQ6x9zMib5pA9Viaz6YbxwpW2WLsp0LGALERTvSxYVxg/640?wx_fmt=jpeg "")  
[【安全圈】Microsoft 发布 PyRIT，能自动识别AI系统中的风险](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054638&idx=2&sn=45952fd664668f0379e5f4020e781a67&chksm=f36e082ec419813801b489d35e6573e651769206d86f6ee714337673e08d63ce30364c72d429&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaeD6a0GGZABALptKxZ5sY47XnhnCgaqNyM2s29Xd92clS8cAk7Ma6mrfQI20g12qvaRvCuibtvicpQ/640?wx_fmt=jpeg "")  
[【安全圈】澳大利亚电信公司 Tangerine遭遇攻击，23万人数据被泄密](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054638&idx=3&sn=d24c9abf42be001c6a8893151bca0d8b&chksm=f36e082ec4198138a22945d9719df6c0eefd704a942999891f5b2aa512c84533156bf162bb21&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaeD6a0GGZABALptKxZ5sY4eNJffV9XSI3XhriamoYzlqibqCHJVNzxPfdA1ibuvdXdYicrSfkf36bO0g/640?wx_fmt=jpeg "")  
[【安全圈】注意！ScreenConnect 漏洞正被广泛利用于恶意软件传播](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054638&idx=4&sn=cbc923d693bae84939d05031ec8bc252&chksm=f36e082ec4198138e0f691df6033b3aa7c38f1d1ce3a77082062a538c9b4f559c56911ef9ca5&scene=21#wechat_redirect)  
  
  
  
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
  
  
