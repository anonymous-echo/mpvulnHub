#  【安全圈】台湾合勤科技证实，Zyxel 修补防火墙产品中的远程代码执行错误   
 安全圈   2024-02-27 19:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
黑客勒索  
  
  
台湾网络设备制造商合勤科技（Zyxel）针对其防火墙和接入点产品中的多个缺陷推出了补丁，并警告说未打补丁的系统存在远程代码执行攻击的风险。  
  
Zyxel是一家一直在努力解决软件安全问题的公司，它记录了至少四个漏洞，这些漏洞使企业面临代码执行、命令注入和拒绝服务利用的风险。  
  
合勤科技公告的基本细节：  
  
CVE-2023-6397 - 某些防火墙版本中存在空指针取消引用漏洞，如果防火墙启用了“反恶意软件”功能，则基于 LAN 的攻击者可通过将构建的 RAR 压缩文件下载到 LAN 端主机上，从而造成拒绝服务 （DoS） 情况。  
  
CVE-2023-6398 - 某些防火墙和 AP 版本的文件上传二进制文件中存在身份验证后命令注入漏洞，该漏洞可能允许具有管理员权限的经过身份验证的攻击者通过 FTP 在  
  
微软今日面向 Beta 频道发布了 Windows 11 Insider Preview Build 22635.3212（KB5034845）更新。  
  
多项新功能将逐步推出，如果你想第一时间收到功能更新，可以打开设置中的“在最新更新可用后立即获取”开关。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaeD6a0GGZABALptKxZ5sY4NOQqrah53FVqWLQHg4H50o0PODF604icG2dia8HwwKNk9K8d4VI2R98A/640?wx_fmt=png&from=appmsg "")  
## 逐步推出到 Beta 频道的修复程序（打开开关可立即获取）  
  
### 任务栏  
  
修复了导致首次启动并登录后任务栏有时显示速度非常慢的问题。  
### 搜索  
  
修复了一项问题，如果用户的任务栏接近充满应用图标，当用户尝试打开搜索时，它会打开并立即关闭。  
## 向所有 Beta 频道用户推出的新功能  
  
### 小组件的新通知角标  
  
微软开始为小组件推出新的角标体验。当用户错过任务栏上的重要通知时，小组件角标就会进行提示。下面是小组件通知角标的示例，显示有三个错过的通知。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaeD6a0GGZABALptKxZ5sY4yI3db3xPxjwGlBpEluJd8rpKh9HnmJ7rehrb7pKSvbNH3gYVLqvWkA/640?wx_fmt=png&from=appmsg "")  
  
当用户打开小组件面板时，可以在面板的左上角看到错过的通知详细信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaeD6a0GGZABALptKxZ5sY4IQeIZYrsdwIp8oXFWOTO4k5Iwicjd284rweUh1c2zgibD2YYG4wPkic4Q/640?wx_fmt=png&from=appmsg "")  
## 逐步推出到 Beta 频道的更改和改进  
  
### 小组件  
  
微软对小组件进行了改进，使任务栏上的图标不再显得像素化或模糊。  
## 已知问题  
  
适用于 Microsoft Edge 用户的 Microsoft Defender 应用防护（MDAG）问题，在 MDAG 内浏览时可能会遇到无网络连接问题。解决方法是禁用 MDAG 企业策略或通过“打开和关闭 Windows 功能”卸载 MDAG 并重新启动。（IT之家注：Edge 的 MDAG 是一项已弃用的功能。）  
  
  
来源：IT之家  
  
  
  
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
  
  
