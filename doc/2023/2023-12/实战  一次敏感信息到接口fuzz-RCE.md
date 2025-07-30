#  实战 | 一次敏感信息到接口fuzz-RCE   
 迪哥讲事   2023-12-06 21:38  
  
一次敏感信息到接口fuzz-RCE，开局一张图，一看就是高端局了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGERt3gj89m1Ww5jIOBaDib2yRDZGRricHibMIAgJL4CAUiamJRzcu1PGcSA/640?wx_fmt=png "")  
  
老规矩资产收集一遍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGRRbD92HbvWOHmgjeGiaBtNRColJgmYEslOnVgO5vZShF7NXiaE3kxR8Q/640?wx_fmt=png "")  
  
没其他子域名，多地ping下域名看下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGy0QTD8epX6nXosmDWickiaGGibVNDNoT1fWibPicwJQYCoJHhtAqcnkBPXA/640?wx_fmt=png "")  
  
难道不是cdn？国外ping也返回的是同ip  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGMCdXdJHvZqKIBABkFz3sI7BibrMc4MXEOfyhPHZDlmf7A9QgwpdOufA/640?wx_fmt=png "")  
  
除了已知的80和443  
  
还开放了8443，8466  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGaCfOCe7WcApeMAib2pSooAOcjia0tmzRNQBZXnNKZQIsicJrwnYzmBXHQ/640?wx_fmt=png "")  
  
扫下端口看下  
  
8443端口WEB端  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGxMNia3zUorP7KiaRz0UmibrHnziciajPFnoU8DDonbjBoQLI9TkVbw1B5CQ/640?wx_fmt=png "")  
  
梭哈，梭哈，梭哈  
  
扯远了，测试了许久没发现可以利用的点，尝试了下掉鱼，发现客服只想让我充钱  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGwWVkJWKFS2YHRI00hfdKGNDKuFDMJ3lbvp9PbSZoSu4Ok3FLQLkcIQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaG7y8OxlUpHo62I4gia2kb2HOQ0IQgyGcJUWC1UDoeNr2M60qLic9ICPrg/640?wx_fmt=png "")  
  
还得是晓晓，知道我没钱，还叫我去贷款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGhozuvJrKAdYGLQGquw7fj2XXOXvT9ibhZLIawK48EyEegL66n9Tx6oQ/640?wx_fmt=png "")  
  
不愧是真爱  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGfnic5KHn1LfHzRkP44D2uvJcXcxxWWREETZNmwia4yBepjsz0Dlv3QzQ/640?wx_fmt=png "")  
  
本来还想着继续跟她聊的，除了让我充钱，啥都不肯  
  
**回归正题**  
  
继续尝试深入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGic2zbeL2F52VmWbt2Gn1FVyniad9BuxDKJhLAdh9JBp8amWXJiazVx8ug/640?wx_fmt=png "")  
  
缺少访问令牌.....，本来到这里不想看了的  
  
但还是抱着试一下的心态fuzz下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGUh8icoB7b2scEf9QB5cjt0AI4ZdhMMF8icBJicjH85rr7X6gvWssVUqNg/640?wx_fmt=png "")  
  
Api/config 返回200  
  
打开看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaG5scn4ic0qM6YHCXZhqmjUgarHM0bZAjdJHXRq3sa4XiaIeGDLXmHJpkw/640?wx_fmt=png "")  
  
激动的心颤抖的手，虽然是内网ip，但试着访问下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGBCQboQbPA9RqCK9OCLibeHHTYbgU0VApsjxzvUQhdaF6k8noeP8BoTw/640?wx_fmt=png "")  
  
令牌+1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaG5Tu1y6179JPJQsPp5w5aea7bahqEpTfVibpEJCibViatMdpZb3EWvpqicA/640?wx_fmt=png "")  
  
空白页？可调用吗，fuzz下接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaG27V76miavicXIic0bPMPNiaKpFBDboXqic078CjPJZ0MCBtuxN57fTmZ1Ew/640?wx_fmt=png "")  
  
然后为了证实下写个脚本判断页面是不是为空，怕参数没值不返回东西就写了个默认1的值  
  
开始fuzz  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGOf1x7dEUsrwU2ibBgZv0ZGCg4zwcCqLPO3R3VknVruicEKlxk9UL3ggg/640?wx_fmt=png "")  
  
希望这不就来了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGUzS3NYKZLzSMBicMbO3M5ia0hQeo8rLdhK32ybekXQoS408TgDDahjBQ/640?wx_fmt=png "")  
  
不会是rce吧，试一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGp2DFCT9XBeBiaXwSSPdT6GFDPc4ghtZ6dNQQe4dz8iaT3w6JPHiaeLY3w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGILylibNbsu9zzKS0xBsuKibGzpphm8VnTM6NJuBFqdk06nq8MbWhP8Mw/640?wx_fmt=png "")  
  
能获取到，再试下获取当前用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8Qfeuvou9eozHcb0mcvWHA2dbSBEaGGeOsiak4rsPibaicib5Fu5DmtnfjQic7k5Y1GRib2hu918oyFj9t2TLoQ1Vw/640?wx_fmt=png "")  
  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
## 福利视频  
  
笔者自己录制的一套php视频教程(适合0基础的),感兴趣的童鞋可以看看,基础视频总共约200多集,目前已经录制完毕,后续还有更多视频出品  
  
https://space.bilibili.com/177546377/channel/seriesdetail?sid=2949374  
## 技术交流  
  
技术交流请加笔者微信:richardo1o1 (暗号:growing)  
  
  
