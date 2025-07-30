#  【安全圈】GitHub 被曝安全漏洞，可被黑客利用伪装成“微软”分发恶意软件   
 安全圈   2024-04-25 19:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
代码托管网站 GitHub 被曝高危严重漏洞，存在于 comment 文件上传系统中，**黑客利用该漏洞可以分发各种恶意软件。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3EAoC2SJvl7BFgzkyxWUM5cFt0WxePg6pDG9khgzZEzE7AcUvia6z7npknp03bicqchZmClSWV3AQ/640?wx_fmt=jpeg&from=appmsg "")  
  
用户可以将文件上传到指定 GitHub comment 中（即便该条 comment 并不存在），也会自动生成下载链接。此链接包括存储库的名称及其所有者，可能会诱使受害者认为该文件是合法的。  
  
例如上传到 GitHub 的文件 URL 地址可以表明来自微软，但事实上该项目代码中从未提及相关内容，IT之家附上两个案例如下：  
```
```  
  
而且该漏洞并不需要任何复杂的专业技术，只需要上传恶意文件到指定 comment 即可。攻击者可以在任何受信任的存储库中上传恶意软件，然后通过 GitHub 链接进行分发。  
  
而且这些链接属于 GitHub 官方 URL 域名，且后缀是“Microsoft”等官方储存库，因此用户很大几率认为该 URL 下载链接的内容是正规安全的。  
  
GitHub 目前已经删除了部分恶意软件链接，对尚未完全修复该漏洞。对于开发者而言，现阶段没有足够有效的方法阻止这种滥用，唯一的方案就是完全禁用 comment。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaXEzReHnUhzRpnvDWq1WITD63F9WfwtYa286WHygIxFYcmV0uRoVODV8YP4lkrGSNnMsmibQmOUWg/640?wx_fmt=jpeg "")  
[【安全圈】德媒称“中国黑客”攻击大众，我使馆驳斥：谣言，中方坚决否认！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058779&idx=1&sn=6e71c2ba4cae98656d0afe722a749172&chksm=f36e18dbc41991cd92e68109ce93fc4a5dc5d72ae471e6444abe10765a7c8ff3f31615ea2387&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3EAoC2SJvl7BFgzkyxWUMPgwiaOEibprrrdHJvqtbBmia0kO6857iblQR5ibbl2JhbKhblA4Vep9FpKQ/640?wx_fmt=jpeg "")  
[【安全圈】黑客滥用 QEMU 对企业进行网络攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058779&idx=2&sn=a67bfd4635d413b0b82d6a3b01a2587d&chksm=f36e18dbc41991cd2e5d6da761740eaa2bbbd5097c36011cb632f8156f43f450051a89738046&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh3EAoC2SJvl7BFgzkyxWUMGtLh1RmQGS2Q7n90icUpemnUPmqHibN8LkCFaibE0nNTJmStQRnOibVHLQ/640?wx_fmt=jpeg "")  
[【安全圈】Consol Energy 遭遇网络攻击：据称俄罗斯网络军对此事负责](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058779&idx=3&sn=571800b18ba45cc4e1e75cb224cebc1c&chksm=f36e18dbc41991cd574ca18cfb00db43a6c06c8a5a8f5323705d6a12e08e360971c924417a82&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaXEzReHnUhzRpnvDWq1WITZ05dRaMkrtiaJcRbntr5pGZLicF037RmdAkb3JMmLWZFlUOJeqMgSkWg/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】俄黑客组织“沙虫”发力，乌克兰关基设施被破坏](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652058779&idx=4&sn=a148c846379a48730f3ffbf6e7f71590&chksm=f36e18dbc41991cd1604e7f3c68dfcbaa97e4488a92f74d700f1e197444407c35ad388d1bd62&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
