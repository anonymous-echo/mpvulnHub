#  【安全圈】Telegram曝零日漏洞，允许发送伪装成视频的恶意APK   
 安全圈   2024-07-24 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
- ESET Research在一个地下论坛上发现了一个针对Android Telegram的零日漏洞广告。  
  
- ESET将该漏洞命名为“EvilVideo”，并将其报告给Telegram，Telegram于7月11日更新了该应用程序。  
  
- EvilVideo允许攻击者发送恶意的有效载荷，这些载荷以视频文件的形式出现在Android的旧Telegram应用程序中。  
  
- 该漏洞仅影响Android Telegram 10.14.4及更早版本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj4PMgvkBiaamK5hbAN2K6UtlX2KtKiaPlBFeuVdo9D9jrZ2Quia9S4wvMtrzoiccpA7aqUibkM4Z0eP8g/640?wx_fmt=jpeg&from=appmsg "")  
近日， ESET研究人员发现了一个针对Android Telegram的零日漏洞，该漏洞名为“EvilVideo”，从今年6月开始在一个地下论坛出售，价格不详。利用该漏洞，攻击者可以通过Telegram频道、群组和聊天共享恶意的Android有效载荷，并使其看起来像是多媒体文件。  
  
“我们在一个地下论坛上发现了出售该漏洞的广告。在帖子中，卖家展示了在公共Telegram频道中测试该漏洞的截图和视频。我们识别出了有问题的频道，漏洞仍然可用，因此我们可以获得有效载荷并自己进行测试，”ESET研究员Lukáš Štefanko解释说。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj4PMgvkBiaamK5hbAN2K6UtQWkvu8qibfaUMrnUTOBl9H6PHuicKqK70RKytJXvFLMCOQIn9cLpnxbg/640?wx_fmt=jpeg&from=appmsg "")  
  
发布在地下论坛的帖子  
  
ESET Research对该漏洞的分析显示，它影响Telegram 10.14.4及更早版本。原因可能是特定的有效载荷是使用Telegram API制作的，因为它允许开发人员以编程方式将特制的多媒体文件上传到Telegram聊天或频道。该漏洞似乎依赖于攻击者能够创建一个有效载荷，将Android应用显示为多媒体预览，而不是二进制附件。一旦在聊天中分享，恶意有效载荷看起来就像是一个30秒的视频。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj4PMgvkBiaamK5hbAN2K6UtQI4JicPRjayQGvUJBFHkXEAicdYibPBglxohLCIVtl2V9PJvaNUTykcWw/640?wx_fmt=jpeg&from=appmsg "")  
  
漏洞利用的例子  
  
默认情况下，通过Telegram接收的媒体文件设置为自动下载。这意味着启用此选项的用户一旦打开共享的对话，就会自动下载恶意负载。虽然默认的自动下载选项可以手动禁用，但在这种情况下，仍然可以通过点击共享视频的下载按钮下载有效载荷。  
  
如果用户试图播放“视频”，会触发真正的Telegram弹出错误信息：“应用程序无法播放此视频，是否尝试使用外部播放器？”这是在合法的Android Telegram应用程序源代码中发现的原始Telegram警告，而不是由恶意负载设计和推送的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj4PMgvkBiaamK5hbAN2K6UtKPSJNxDMSTtAOVrNTe2FRicR2Gxb9Po0ibFRbWMjqveLaAQA9Yx7momQ/640?wx_fmt=jpeg&from=appmsg "")  
  
警告无法播放“视频”  
  
用户可以选择取消或尝试打开文件。但如果用户选择“打开”，他们还需要允许Telegram应用程序安装Android应用程序包（APK）。在安装之前，Telegram会要求用户启用未知应用程序的安装。因此，用户需要执行一系列操作才能激活恶意载荷，但伪装的文件和Telegram的错误分类仍然引起了明显的安全担忧。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj4PMgvkBiaamK5hbAN2K6Ut26OYcUfeytORGrYBefcyd56spFCv2YKmKIkWwQ51xjRAkpF0IPpASQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Telegram要求用户允许安装未知的应用程序  
  
在2024年6月26日发现EvilVideo漏洞后，ESET按照协调的披露政策向Telegram报告了该漏洞，但当时没有收到任何回应。7月4日，ESET再次报告了这个漏洞，当天，Telegram联系了ESET，确认其团队正在调查EvilVideo。随后，Telegam修复了这个问题，于7月11日发布了10.14.5版本。该漏洞影响到10.14.4之前的所有版本的Android Telegram，已在10.14.5版本中更新。  
  
  
参考来源：https://www.eset.com/uk/about/newsroom/press-releases/set-research-discovers-evilvideo-telegram-app-for-android-targeted-by-zero-day-exploit-sending-malicious-videos/  
  
https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GIRTzCSXSdG97Nq3x0zDvaIUuOOtwjXoL5UIKOibaRZ5IdrAqe7HIWOicFosibJPe3GaB6ibkzLPzStVGZ5jRdZM3Q/640?wx_fmt=png "")  
[【安全圈】这个研发网约车外挂的犯罪团伙被打掉](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063045&idx=1&sn=1fe2dfd0d1146d804c4e9cfd7a613698&chksm=f36e6905c419e01368976a53b74a33da85fd21975e8ed367eb8e3c61df5626d0a056851cf004&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtaUJxPWzIPVtnSdaANHzWcnibC8WVUkff0lSQxAmeHAicD9GZRByTgKiaeZxb3UZx6N27vsFqHxYAg/640?wx_fmt=jpeg "")  
[【安全圈】微软蓝屏，重启15次就能解决？IT疯狂吐槽](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063045&idx=2&sn=884f270cb78d0821f2fd4e980ff1ddbe&chksm=f36e6905c419e013d58848981fb87389d608095d3c900ef25f2c9edae251bbefd3fc4a26c73c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtaUJxPWzIPVtnSdaANHzWqmic7hGdribXcxaicFStjyX1ZTzhpiacbvzM2PBSWT0v1fpvnK8YeoMdQA/640?wx_fmt=jpeg "")  
[【安全圈】攻击者正滥用 URL 保护服务来隐藏网络钓鱼链接](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063045&idx=3&sn=4b21eab2094cde767919ceca792a1ddb&chksm=f36e6905c419e0135191fcd9511d01d03861755f6495436fc2774f21b566126d373d89d4f084&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtaUJxPWzIPVtnSdaANHzWrs7NPvib804FNBUBZyf3J8cNR41YPzazibsicqEWLA91hUlVMayGPOUCQ/640?wx_fmt=jpeg "")  
[【安全圈】注意！针对VMware ESXi 虚拟机的新型勒索软件“横空出世”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063045&idx=4&sn=f1f871643d45e45dc1101f3e39de2a7b&chksm=f36e6905c419e0138be495e9a893cf7e602c5d5f0f1beb511eb95a03ee91a58d1ddce3995e93&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
