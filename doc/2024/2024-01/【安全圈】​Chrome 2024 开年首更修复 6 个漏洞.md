#  【安全圈】​Chrome 2024 开年首更修复 6 个漏洞   
 安全圈   2024-01-06 19:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
谷歌周三宣布了2024 年首个Chrome安全更新，解决了 6个漏洞，其中包括外部研究人员报告的4个漏洞。  
  
  
谷歌近日发布了一份公告，其中提到了四个涉及内存安全的高严重性安全缺陷。然而，虽然这些问题都受到了高度重视，但谷歌只对其中三个提供了漏洞赏金奖励。让我们一起来看看这些安全缺陷的详情。  
首先，CVE-2024-0222和CVE-2024-0223两个问题，它们都出现在图形渲染引擎ANGLE中。这些问题涉及到释放后使用漏洞和堆缓冲区溢出漏洞。这两个问题由Qrious Secure的研究人员报告，并且他们每个问题都因其重要性而获得了15,000美元的漏洞赏金奖励。  
第三个问题是CVE-2024-0224，出现在Chrome的WebAudio组件中，同样是释放后使用缺陷。针对这个问题，谷歌向报告该漏洞的研究人员，即蚂蚁集团光年安全实验室，提供了10,000美元的漏洞赏金奖励。  
这些赏金奖励是谷歌对安全研究人员积极参与漏洞报告和修复工作的一种肯定，也是鼓励更多人参与网络安全事业的方式。通过这些奖励，谷歌希望能够及时发现并解决潜在的安全威胁，确保用户的在线体验更加安全可靠。  
  
  
最新的 Chrome 更新还解决了 WebGPU 中的释放后使用漏洞。该错误被追踪为 CVE-2024-0225，谷歌尚未透露向报告研究人员支付的错误赏金金额。  
当释放内存分配时未清除指针时，就会出现释放后使用问题，通常会导致任意代码执行、数据损坏或拒绝服务。在 Chrome 中，如果黑客针对底层操作系统或特权进程中的缺陷，则可以利用释放后使用错误来规避浏览器的沙箱。  
  
  
谷歌长期以来一直致力于提高 Chrome 中的内存安全性，并强化了浏览器以防止利用释放后使用漏洞。  
尽管做出了这些努力，去年浏览器中还是记录了数十个释放后使用问题，其中大多数被评为“高危”。最新的 Chrome 迭代现已推出，适用于 macOS 和 Linux 的版本为 120.0.6099.199，适用于 Windows 的版本为 120.0.6099.199/200。Google 将 Chrome 的扩展稳定通道更新为 macOS 版本 120.0.6099.199 和 Windows 版本 120.0.6099.200。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMtKnaFsOIbPt9UE3Vsm6ShzCK0CwPhVM8ibVwHUwscZtt6668OCCv6OgvklmfBnmjQRLhkEYmWtw/640?wx_fmt=jpeg "")  
[【安全圈】宝马子域SAP重定向漏洞曝光：网络钓鱼和恶意软件传播风险](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051536&idx=1&sn=6eadb8dc4293ab4359a2530aff5012c1&chksm=f36e3410c419bd06ff06d10f69719b1078b7e6f9be5672a2164cbfc73cfdf00c838e21984229&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMtKnaFsOIbPt9UE3Vsm6S9ye9J89lNiaauZ7Qgn2lwagB7mVEBHKTJpqj2c4Asvl80msnMwIGSpw/640?wx_fmt=jpeg "")  
[【安全圈】农行系统崩上热搜，网友直呼“抢不到啊！”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051536&idx=2&sn=c3da3a86f0a360aa48db5ab910879b25&chksm=f36e3410c419bd06d63418c26636d99c3d4812223179d4442feb156177478bba7c5f9d0e0dc1&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMtKnaFsOIbPt9UE3Vsm6SKjsGSCPEjN7SYGTsSayWokv1dwU45EQz30C96FV2VLH4hTNbjxmp9g/640?wx_fmt=jpeg "")  
[【安全圈】为了打击图像造假问题，尼康、索尼和佳能将采用数字签名技术](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051536&idx=3&sn=f79b7f8707c1e38b058af27b9c473dc2&chksm=f36e3410c419bd06cdf03f6eb12134374d28af07eb6f32aca2c533dc15f4c3eaf3a2399e0a83&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhMtKnaFsOIbPt9UE3Vsm6SBicZhBTUlZbp3lrv5f0j4QEvKguSkoPicZDNGbQ1W7oXytWIqwwxvbSQ/640?wx_fmt=jpeg "")  
[【安全圈】黑客使用人工智能发动商业电子邮件欺诈！已影响多个国家](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652051536&idx=4&sn=75a9cfe708de1aa2b9ceb5e50f193b90&chksm=f36e3410c419bd065b5c9843923f2014a2969b3900d7ccd9e9b168737f75083d1719b26d9356&scene=21#wechat_redirect)  
  
  
  
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
  
  
