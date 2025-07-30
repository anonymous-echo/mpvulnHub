#  重定向跳转 -> XSS漏洞 -> 升级高危   
 迪哥讲事   2024-08-22 20:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/a7Ek898CZbLGNTlJVaurRxYxzbuf09SiaOmxvRWDPtcSWIpZmJ3rm1WOicZC0oibqibIYrHm5aeCDpKWu5ObobmWuw/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/a7Ek898CZbLGNTlJVaurRxYxzbuf09SiaXGCGBsWK7UbhibcgOEr2ODPv7z2VM5txPhPxBDwo6Tice8n2I1GMp23A/640?wx_fmt=gif "")  
  
点击上方  
蓝字关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/C3sn1R9OoIibBTbaGpEeezDSCNy3UGXgjMO4pUzJ5sCJylmHygQ3g339EMrnIUm40ZbflhibZiarHkwZXOxePOS1g/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NxP1XuxYia8jTiakvaVl51hd4hH98tVsdAcN8Lt0jtib4QPxpkw1ibCNffLZb5Zh6SIfcntA7AZTYoLqnhRgPeeLVA/640?wx_fmt=gif "")  
  
  
看到一个比较有趣的文章，有一定参考意义，比较适合小白体质。  
### 正文   
  
在 TikTok 上搜索时，我发现了一个常规的登录页面。我首先看了链接，没有找到任何有趣的参数。你正确登录以猜测重定向，然后将请求传递给入侵者以猜测重定向。  
  
最终，我得到了一个不同的响应，是的，我发现了一个开放的重定向漏洞！  
  
由于开放重定向的影响较低，我想要利用它达到更多的目的…… 是的，我知道你们在想着 XSS 漏洞。是的，你们猜对了，就是 XSS。  
  
Payload 就像这样：  
```
1javascript:alert(1)
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMogKV1gqHQt9YR1COMX5qWfQmwVficpLtib2jTLXu0ibgbkCmm4CibBd8C9W09RrgWiaamOyWicoIvrbA0w/640?wx_fmt=png&from=appmsg "")  
  
  
你以为我会停在这里吗！！！你错了，我总是尽力获取最高风险。继续搜索吧。  
  
是的，我还发现了泄露敏感账户信息的端点，例如 user_info。这通常是一个包含账户信息的页面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMogKV1gqHQt9YR1COMX5qWfur9Y9HZ2tTVxab5T6qicrq8pTqNpgoJs0ZlngUL3KuiaibbIXcMhyNs0Q/640?wx_fmt=png&from=appmsg "")  
  
  
例如，我们发现该端点在响应中检索到敏感信息。是的，我坐在那里思考着如何利用这个！我能获取这些信息吗？发送到我的服务器！  
  
是的，是的，是的！我获取了所有这些信息，还遗漏了一些非常敏感的端点。  
  
我们现在从跨站脚本攻击转向账户劫持，  
  
我编写了一个 payload，使受害者访问端点，将页面内容保存在一个名为 data 的变量中，然后将其重定向到我的服务器，并附带数据。  
  
这就是最终的利用过程：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMogKV1gqHQt9YR1COMX5qWfLZqYua1LUjNBF0qdc61rU1RiaWichK2t1utNG7KwIvp2IPOwRKPibmc6A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMogKV1gqHQt9YR1COMX5qWfI7nGMTHmbUCKMT1PpJiaNibqGdshzIaiaYjo4593G97NI1mkO9x3RzczA/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞利用的解释：  
  
想象一下，它将受害者引导到端点，从而泄露了他的账户名，然后将其保存在一个名为 data 的变量中，然后将其带着数据重定向到你的服务器，你就可以成功捕获它。  
  
所有的账户数据都已经被获取并完全被接管。  
  
举例来说，这是一个泄露账户名的端点。正如你所见，它成功地捕获了数据。别忘了，我找到了一些非常敏感的端点，我不想透露它们。  
  
这些是一些被捕获数据的图片，如你所见：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMogKV1gqHQt9YR1COMX5qWfk7McuHjDUs4lFXb39YOq9SibPdJv9QMHaVmsbSFagkTldGtIyicWsEcA/640?wx_fmt=png&from=appmsg "")  
  
  
这里我在命令提示符上收到了 JSON 数据，正如你所见，一切都变得混乱了，因为命令提示符无法读取一些代码，所以我将使用本地主机。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMogKV1gqHQt9YR1COMX5qWf3wCq6JycibtPhMmfQzveTDhfxibJLib2k21cgmSicI0UZQHKyySmrdZeog/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMogKV1gqHQt9YR1COMX5qWf3wCq6JycibtPhMmfQzveTDhfxibJLib2k21cgmSicI0UZQHKyySmrdZeog/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMogKV1gqHQt9YR1COMX5qWf3wCq6JycibtPhMmfQzveTDhfxibJLib2k21cgmSicI0UZQHKyySmrdZeog/640?wx_fmt=png&from=appmsg "")  
  
  
我已经获取了包含所有参数的 Cookie，现在我可以入侵这个账户了 ^-^ 希望你喜欢这个故事，你已经看到了结局。感谢阅读。  
  
我因此被奖励了 5000 美元。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/cxf9lzscpMogKV1gqHQt9YR1COMX5qWfDLSTtzNPETQnTnWBibwT9l6unrZtjjOjZqHibVf9sLwNkxV4nyYkdIibg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Thanks for  source from  
https://medium.com/@them7x/open-redirect-to-xss-and-account-takeover-ato-7ccd3a41d2a0##    
### 我的看法   
  
其实这里的payload可以作为一个模板，以后再次遇到此类漏洞的时候，可以去尝试使用它，多尝试国外的，此类漏洞要比国内的高好几倍  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vYXyePRSia2eTvCutQchicZ0zH9icCt4WZBUMbpovbWZXotywib3BBCCoX6FaO2NHXFEf6Z06bYzScyKcZdJpIcZCA/640?wx_fmt=png "")  
  
