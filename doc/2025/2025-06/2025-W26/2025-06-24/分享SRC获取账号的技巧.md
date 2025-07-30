> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247485834&idx=1&sn=0092e31f3845bde2965bb15b82c90832

#  分享SRC获取账号的技巧  
原创 锐鉴安全  锐鉴安全   2025-06-24 07:53  
  
声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
关注公众号，设置为星标！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4ricRiaXQ6WVVlTAgCW8HUbC2rHkicA2rpDNEPAGyiatRibqB9LN5NyHcqLCmbibM1siaumqF5Yu6UtSsYA/640?wx_fmt=png "")  
  
  
一、背景  
  
挖掘src时，只有一个登录页面，测完登录页面的相关等功能，没出洞，就完事了？不然，可以探测隐藏的注册功能，注册账号进一步深入挖掘登录后的功能漏洞。怎么去探测，这种情况，怎么搞？相信各位师傅也遇到过同样的问题。接下来分享几个技巧，获取账号登录系统。  
  
  
二、技巧分享  
  
技巧一：寻找隐藏注册页面  
  
在日常src挖洞过程中，发现很多系统开发人员，隐藏了注册功能，但可以通过拼接路径，访问到注册页面。路径关键字：register。这个是高频路径关键字，建议各位收藏，作者在挖掘过程中，遇到过相当多。除了直接使用这个关键字，还需要关注下js文件。  
  
  
某次src，在登录页面如https://xxxx/com/login，将login替换为register，直接访问注册页面。如下页面只有一个登录入口，前端页面无任何注册相关的入口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6Nl0bjGbavtwj8gc4oaRV0uVMRk9HOVwLOASZC1DUZpS7gUiaUUw922wzMzqJs3XeLLnKolYShibeQ/640?wx_fmt=png&from=appmsg "")  
  
  
将login替换为register，访问到隐藏的注册入口，直接注册账号。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6Nl0bjGbavtwj8gc4oaRV0JaM8dRk65Ww4uribhibiaEDnMibJD9RcZAhtXZwJ1IibDclfxOVaFvrQ0icA/640?wx_fmt=png&from=appmsg "")  
  
  
  
技巧二：通过接口注册用户  
  
第一个技巧可以通过js文件或者关键字拼接等方式，进行注册账号；有时候开发会进行js处理，过滤很多使用不到的信息。那这时候，需要进行fuzz。还是需使用关键字register。  
  
  
某次src，在登录页面未找到注册功能，拼接路径也无页面回显。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6Nl0bjGbavtwj8gc4oaRV0sdtVVOiaicnyAHlBW6oRZzhAbRCs1lS6hQmVwdtjyf7V1qzCicAeicymhQ/640?wx_fmt=png&from=appmsg "")  
  
  
在登录功能输入账号密码，抓包。有经验的师傅，一看就是“若依”的页面，再看下接口特征/prod-api。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6Nl0bjGbavtwj8gc4oaRV0dAD9uhvktpC3UpfxgOHLu4pBCdOV9FDFV7WMCmc2uLia8Eg7s3wHIEg/640?wx_fmt=png&from=appmsg "")  
  
  
这时候fuzz，将login替换为register，将验证码code和uuid替换为login页面刷新页面后的，直接注册账号成功。  
  
各位师傅后续遇到若依站可以参考这个方法注册账号。记住这个方法，目前若依站实在太多了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6Nl0bjGbavtwj8gc4oaRV07d5BXk0ibkujfibIjkXpSibbAxE2AFlicoygiclLr9Y2Iyqu2IYRk8mCKaw/640?wx_fmt=png&from=appmsg "")  
  
  
使用注册的账号123456登录系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6Nl0bjGbavtwj8gc4oaRV0uVasm9xktRH9rt46PicNLxuhuAlGVTic5eFJR1X0FRchdW5xzAnpSZ6Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
技巧三：互联网搜索引擎  
  
主要使用google语法  
  
site:xxx.com "登录|注册"  
  
相关的语法有很多，各位师傅可以在细搜下。  
  
  
往期好文推荐  
  
[通过隐藏接口发现ruoyi和druid漏洞](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247485719&idx=1&sn=80c65694743eb5e5397583d0620d9b99&scene=21#wechat_redirect)  
  
  
[【渗透测试】UEditor漏洞挖掘实战](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247483787&idx=1&sn=7fe88690fa76a2717670672ac500b3ee&scene=21#wechat_redirect)  
  
  
[【漏洞挖掘】Minio对象存储漏洞挖掘](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247483930&idx=1&sn=2689a7fea3787e5d6637c50254aebad6&scene=21#wechat_redirect)  
  
  
[SRC挖洞必备技巧及案例分享](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247485449&idx=1&sn=c3745d89c364e18d82b09c349fd09541&scene=21#wechat_redirect)  
  
  
[挖洞赚钱必备清单，推荐收藏](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247485452&idx=1&sn=67aa5d74b0c6944e5e802e11b2c6d925&scene=21#wechat_redirect)  
  
  
[拿来即用SQL注入POC，亲测好用](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247485347&idx=1&sn=295383c5facaf1c481ac363d502b770e&scene=21#wechat_redirect)  
  
  
[好文推荐！针对SSO认证绕过技巧！](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247485275&idx=1&sn=f210d8e8027507feaf2d735e16a864af&scene=21#wechat_redirect)  
  
  
[【漏洞挖掘】swagger未授权漏洞利用](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247484484&idx=1&sn=dcde56e7fceac94cffbec52f7ef09005&scene=21#wechat_redirect)  
  
  
[文件预览组件kkfileview被玩坏了，没想到这么多漏洞](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247484074&idx=1&sn=d4e633e1d08544954150f90362f211d5&scene=21#wechat_redirect)  
  
  
[【渗透测试】针对混淆JS代码的动态调试技巧](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247483935&idx=1&sn=6076e8a54ccc9169777087517df1f943&scene=21#wechat_redirect)  
  
  
[【漏洞挖掘】APP渗透测试必备](https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247484263&idx=1&sn=b13b066eca0cb0eeecbd04af903b062d&scene=21#wechat_redirect)  
  
  
