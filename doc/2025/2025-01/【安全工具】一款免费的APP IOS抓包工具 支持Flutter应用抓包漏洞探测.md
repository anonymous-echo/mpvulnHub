#  【安全工具】一款免费的APP IOS抓包工具 支持Flutter应用抓包|漏洞探测   
wanghongenpin  黑客白帽子   2025-01-12 13:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.6636094571400317&random=0.6219011309810436&random=0.21191420540585404 "")  
  
**感谢师傅 · 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.9829534454876507&random=0.2787622380037358&random=0.29583791053286834 "")  
  
  
由于，微信公众号推送机制改变，现在需要设置为星标才能收到推送消息。大家就动动发财小手设置一下呗！啾咪~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0y50hQk1TiaBIAnSjzqkmZcPS4TWvohHfHPTVUBWM2mFxcqwhiaZKaQM6S7t11fuiajZ2zZqXD5hJJmA/640?wx_fmt=png "")  
  
  
******【公告241027】回复关键字没有回复，如何获取方法******  
  
0x01 工具介绍   
**ProxyPin** 是一款免费开源的跨平台抓包工具，支持 Windows、Mac、Android、iOS 和 Linux。它可以拦截、检查并重写 HTTP(S) 流量，同时支持 Flutter 应用抓包。核心功能包括扫码连接设备、域名过滤、请求/响应修改（支持 JavaScript 脚本）、请求屏蔽、历史流量记录（支持 HAR 导出/导入），以及正则搜索和常用工具箱。基于 Flutter 开发，界面美观易用，非常适合调试与流量分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq66OwelFCiahibUib3AszQRt5x564Q3fHJgIHJaUibzaKFticlttO35KL3EicMbe5efIiap42XV0rKndglEQ/640?wx_fmt=png&from=appmsg&wxfrom=13 "")  
  
**下载地址在末尾**  
  
0x02 功能简介核心特性手机扫码连接: 不用手动配置Wifi代理，包括配置同步。所有终端都可以互相扫码连接转发流量。域名过滤: 只拦截您所需要的流量，不拦截其他流量，避免干扰其他应用。搜索：根据关键词响应类型多种条件搜索请求脚本: 支持编写JavaScript脚本来处理请求或响应。请求重写: 支持重定向，支持替换请求或响应报文，也可以根据增则修改请求或或响应。请求屏蔽: 支持根据URL屏蔽请求，不让请求发送到服务器。历史记录：自动保存抓包的流量数据，方便回溯查看。支持HAR格式导出与导入。其他：收藏、工具箱、常用编码工具、以及二维码、正则等Mac首次打开会提示不受信任开发者，需要到系统偏好设置-安全性与隐私-允许任何来源开源抓包工具 支持iOS/安卓/Windows/Mac/Linux全平台系统应该是目前支持最全的工具，全平台支持，您可以使用它来拦截、检查和重写HTTP（S）流量，ProxyPin基于Flutter开发，UI美观易用。0x03更新说明V1.1.6新增Hosts设置, 支持域名映射工具箱新增时间戳转换编辑请求发送快捷键和发送loading修复脚本编辑键盘弹出安全模式问题修复脚本URL编码问题修复请求屏蔽编辑多出空格问题修复ipad分享点击无效问题修复高级重放次数过多不执行问题修复请求重写bug应用黑白名单增加清除无效应用，添加过滤已存在应用0x04 使用介绍选择对应的版本进行安装即可使用以下操作以Windows为例，打开工具后会默认进行HTTP抓包操作，看到的界面如下图所示默认情况下我们只能抓取HTTP请求，无法抓取HTTPS请求需要点击顶部的【启用HTTPS代理】开关按钮，安装根证书到本机根据软件进一步提示安装根证书  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq66OwelFCiahibUib3AszQRt5xWLbRjzsocpz7zXbFUn9Ml093OCLW7VEPJgiae6CbiaBNTFlnsjHibF8KA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
最后再启用HTTPS代理，就能抓取HTTPS请求了  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq66OwelFCiahibUib3AszQRt5xFaTkPZpKYztz3ia84MicKsb7XwOYlgYzEZWGIYJKX2I0iamj9aheHrJ9A/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  

								  

									  

										  

											  
往期推荐  

										  

									  

									  

								[ 265种windows渗透工具合集--灵兔宝盒 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650962339&idx=1&sn=e05bc1fa240d96de64e878ee294e2550&chksm=8bac355cbcdbbc4af1869c838fab36d8edd1406cfbe2c355c2cc902026f5cc9a74bcb30fe177&scene=21#wechat_redirect)  

							  
  

								[ 记一次实战小程序漏洞测试到严重漏洞 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650962195&idx=1&sn=9f0a1c8f719fa30c9588bdd2593cfcc9&chksm=8bac35ecbcdbbcfa294fad1b56e1a2d024616b3e662443b4e5c54f1c3130d8bc5494bc667347&scene=21#wechat_redirect)  

							  
  

								[ CVE-2023-41362 mybb模板注入漏洞分析 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650962093&idx=1&sn=b880babe712b4dbdd35a881a54fd71f1&chksm=8bac3452bcdbbd44445cc2554b2391f6654d755afe030e7ef85deaf62721a142f70b03fa41bd&scene=21#wechat_redirect)  

							  
  

								[ 记一次实战小程序漏洞测试到严重漏洞 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650962002&idx=1&sn=c3d5dc01f62b5b616729c291359c4b35&chksm=8bac34adbcdbbdbbb9d102e2573ad4b8663024cc2285cf11ebe5560944d2e1da8fb181f7339c&scene=21#wechat_redirect)  

							  
  

								[ Nacos 综合利用工具推荐 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650961918&idx=1&sn=9b11a3e172a5206ac221393525245d3a&chksm=8bac3b01bcdbb2179ac1645c90f71776aff97cc15b96bda037a9828da4c5694fcb36311bc07a&scene=21#wechat_redirect)  

							  
  

								[ HOST碰撞漏洞挖掘技巧总结 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650961847&idx=1&sn=dadd1766ef960e7ffb6e2e44c37967cc&chksm=8bac3b48bcdbb25e5b1cb8806818f48133058622db90731021b8047938af3aca7468890763d9&scene=21#wechat_redirect)  

							  
  

								[ SRC挖掘奇特思路案例 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650961626&idx=1&sn=a068e1cb2e11f7abb57c0e8a31354304&chksm=8bac3a25bcdbb333261be7190836780495c65aeb64c6f48e8211545d99f055086732c43b3a36&scene=21#wechat_redirect)  

							  
  

								[ Vcenter综合渗透利用工具包 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650961430&idx=1&sn=c22a7dd6f2d41f272692a778cf9d7bc8&chksm=8bac3ae9bcdbb3fff0ad1fe28ab0e4a3b384d7c9216bc85f2fcbba55784673bf0e4611b04070&scene=21#wechat_redirect)  

							  
  

								[ burp插件 | FrameScan插件是一款插件化的指纹POC扫描插件 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650961338&idx=1&sn=098e0c5b1dbfe40164209cf72867b923&chksm=8bac3945bcdbb053eaa95f4f0b5df2311d5279e788ea502fc3247e68c1c0b07e4ca67bd72ef9&scene=21#wechat_redirect)  

							  
  

								[ 一款简单的后渗透免杀加载器，Bypass AV/EDR ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650961161&idx=1&sn=fe3af85946d0559caff137271c718ff1&chksm=8bac39f6bcdbb0e0680719b632219e4d0d0d0c40e049c2aead2a58ee6ff167c89fa71527a0fb&scene=21#wechat_redirect)  

							  
  
  
转自； Khan安全攻  
防实验室  
  
侵权请联系我删除，谢谢  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【****0112****】获取网盘**  
**下载链接**  
  
**二个月前资源汇总**  
  
https://kdocs.cn/l/cqEYzWfs0kUS  
  
  
  
声明：本公众号所分享内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！否则需自行承担，本公众号及原作者不承担相应的后果  
```
```  
  
