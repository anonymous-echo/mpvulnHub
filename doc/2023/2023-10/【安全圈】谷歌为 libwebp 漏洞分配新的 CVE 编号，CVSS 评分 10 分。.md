#  【安全圈】谷歌为 libwebp 漏洞分配新的 CVE 编号，CVSS 评分 10 分。   
 安全圈   2023-10-05 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylg1JZl4BeFzhiaQf3pJHLtic9licPa5oXB1hfLroaibYaY2QNW5eDWa8lpQMZt8xqyTaHNz2ed4jIR2bw/640?wx_fmt=png "微信图片_20230927143622.png")  
  
  
**关键词**  
  
  
  
**漏洞**  
  
  
   
  
谷歌为 libwebp 漏洞分配新的 CVE 编号，CVSS 评分 10 分。  
  
Libwebp 是一个用于处理 WebP 格式图像编解码的开源库。9 月 6 日，苹果公司安全工程和架构（SEAR）部门和加拿大多伦多大学研究人员在 libwebp 库中发现了一个 0 day 漏洞，随后，谷歌将该漏洞分类为 Chrome 漏洞，CVE 编号 CVE-2023-4863，并于 1 周后修复了该漏洞。  
  
9 月 21 日，安全研究人员 Ben Hawkes 将该漏洞与 CVE-2023-41064 相链接被用于零点击的 iMessage 漏洞利用链以感染 iPhone 设备。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgN56SkB1wSaDen9O0NSjpjVz0iaAzj0QiaVhsMefORqph5j42pOnIJxicOTfXDWUUdxyGLPoYt8SwTw/640?wx_fmt=jpeg "")  
  
9 月 25 日，谷歌将该漏洞重新归类为了 libwebp 中的堆溢出漏洞，并为该漏洞重新分配了 CVE 编号 CVE-2023-5129，CVSS 评分 10 分。漏洞影响谷歌 Chrome 浏览器 116.0.5845.187 以前版本，漏洞的重新分类对使用 libwebp 开源库的项目带来重大影响，包括 1Password、Signal、Safari、Mozilla Firefox、Microsoft Edge、Opera 以及原生 Android web 浏览器。  
  
该漏洞存在于 libwebp 库使用的哈夫曼编码 ( Huffman Coding ) 算法 ReadHuffmanCodes ( ) 中。攻击者利用该漏洞可以通过恶意伪造的 HTML 页面实现越界内存写操作，引发软件崩溃、任意代码执行、敏感信息非授权访问等严重后果。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgN56SkB1wSaDen9O0NSjpjG8qrbaENX6MbkWfStjo2vEzfCct9WP7xVfDDcReuqRvicSQpxpjSnhA/640?wx_fmt=jpeg "")  
[【安全圈】MidgeDropper 新变种浮出水面](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045932&idx=1&sn=c5df548d723c459d40aef24a73350de1&chksm=f36e2e2cc419a73ac733a9a405076dc562df11a312e655df6e9f541c185c172998b20f628d8f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljzJxgENkjayhb6SWRDwZqXkaKbqpNibIvkhia9jF1ufWrowMXLPtLicCxoOh4dYmqEVNcAzc4E8t0yw/640?wx_fmt=jpeg "")  
[【安全圈】ShellTorch 缺陷使 AI 服务器面临代码执行攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045932&idx=2&sn=ecc621253025943a92afa8445f58b65b&chksm=f36e2e2cc419a73a89729f4dc33cfebcec992ee8ecf485e63088297fdbc2e0d497a999fd3d7f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljzJxgENkjayhb6SWRDwZqX3TTvYwsPQUvRh3YxuRzZVSicicYFZwPow9WibRmqdkREicybCaXFHsuKmg/640?wx_fmt=jpeg "")  
[【安全圈】EvilProxy 使用 Indeed.com 开放重定向进行 Microsoft 365 网络钓鱼](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045932&idx=3&sn=9f74a44a71aa600ac095261f2f8c1db5&chksm=f36e2e2cc419a73a416da9159a8cb9fa8f1efd1c70fb513994c06d7606e979547c279bc6d5d4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljzJxgENkjayhb6SWRDwZqXbHWCBiaXOZVYjgXXWKcelnumt1AZvNJrda0PTat2W5uBq8KMecUFMFg/640?wx_fmt=jpeg "")  
[【安全圈】新的“Looney Tunables”Linux 漏洞可在主要发行版上获得 root 权限](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652045932&idx=4&sn=406d3f951f7a0584d494afbc7fa1ce80&chksm=f36e2e2cc419a73a5e77a49475077f937740900a1c802a332de33dfebadb242b4b7561147b54&scene=21#wechat_redirect)  
  
  
  
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
  
  
  
  
  
  
