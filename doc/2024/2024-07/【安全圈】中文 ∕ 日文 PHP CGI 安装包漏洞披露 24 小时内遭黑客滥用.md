#  【安全圈】中文 / 日文 PHP CGI 安装包漏洞披露 24 小时内遭黑客滥用   
 安全圈   2024-07-13 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
网络安全公司 Akamai 于 7 月 10 日发布博文，表示今年 6 月披露 PHP 漏洞 CVE-2024-4577 之后，**隔天就观测到网络上有大量攻击者尝试利用该漏洞发起攻击。**  
  
Akamai 表示在 6 月披露该 PHP 后 24 小时，就观察到大量针对蜜罐服务器的漏洞利用尝试。  
  
这些攻击包括传播名为 Gh0st RAT 的远程访问木马、RedTail 和 XMRig 等加密货币矿机以及名为 Muhstik 的 DDoS 僵尸网络。  
  
该漏洞的 CVSS 评分为 9.8 分（满分 10 分），影响 CGI 模式下的安装方式，**主要影响使用中文、日本语言的 Windows 版 PHP 安装程序**。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhtc9Ez4OQAr6O8TXBb1P61TpkJ9IBRoxqBuUqVJzcH40opcY5iayicBPTibb0wOiax3pv1y5rLIP8EDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Gh0st RAT 恶意软件样本 MITRE ATT&CK TTPs  
  
攻击者利用该漏洞，可以绕过命令行，将参数传递给 PHP 直接解释，漏洞本身问题在于 CGI 引擎没有转义软连字号 ( 0xAD ) ，没有将 Unicode 字符正确转换为 ASCII 字符，从而导致攻击者可远程代码执行（RCE）。  
  
PHP 目前已经发布版本更新，修复了该漏洞，目前敦促用户尽快升级到 8.1.29、8.2.20、8.3.8 版本，IT 之家附上受影响的版本如下：  
  
8.1.x 分支下，影响 8.1.29 此前版本  
  
8.2.x 分支下，影响 8.2.20 此前版本  
  
8.3.x 分支下，影响 8.3.8 此前版本  
  
PHP 8 版本  
  
PHP 7 版本  
  
PHP 5 版本  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljqu0XfvUvsKk4q5bN5gSSbkryossYYj148s0M5ZK61X0GsCaB5ald7P5wq9uRNjIZLnbtibu0KibNA/640?wx_fmt=jpeg "")  
[【安全圈】网络舆论战打响，俄罗斯虚假信息设施遍布欧洲](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062747&idx=1&sn=0752adb663f14a979fff14376d3633d7&chksm=f36e685bc419e14d8b99a2c8570e02b514c3767345df7b9bc44b1c85463caeeac04d4c8c9f8a&scene=21#wechat_redirect)  
     
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljqu0XfvUvsKk4q5bN5gSSbrlYGDby1LetViaiaMkCEnicQW9qzNlsicA0XqH5geN3jsA5R1ypGRIUo1Q/640?wx_fmt=jpeg "")  
[【安全圈】在线PDF工具暴露了数万份用户上传的文件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062747&idx=2&sn=4e89e5478e96a7d2f8ff761b514bface&chksm=f36e685bc419e14d1000d9fbbc670d7314e12320c94ce1094f3a8d79d648c78fef551f356a45&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljqu0XfvUvsKk4q5bN5gSSb6Olic9F99xqf1ibN6urUMiaHiaaJHDf0wpgLWwLibkGvaMUicFn3A5B7FjgA/640?wx_fmt=jpeg "")  
[【安全圈】谷歌发力争夺漏洞资源，漏洞赏金再提高5倍](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062747&idx=3&sn=ae5e5926e091aae0dab0734b1cf7101d&chksm=f36e685bc419e14d768fa9bc500a9857c94575572d048ff9c6bf974756a5d7b848315e991b37&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljqu0XfvUvsKk4q5bN5gSSbMBIFTPDJ98aguwSkOoT5wgxSJXhB13wDOAiaIt5ZjkotjmWEibfEQ3KQ/640?wx_fmt=jpeg "")  
[【安全圈】富士通遭受非勒索软件的蠕虫病毒攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062747&idx=4&sn=76ad330d200254b23011957c7e5da32e&chksm=f36e685bc419e14d91c10b4eac374ca479215179fd93d027c6a37df69d4178a097e0e1ed278a&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
