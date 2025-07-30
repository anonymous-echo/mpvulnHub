> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMjg3NzU0Mg==&mid=2247485843&idx=1&sn=ca62e1d7b5c26a512d859425e8012da6

#  Bypass 403漏洞挖掘  
原创 锐鉴安全  锐鉴安全   2025-06-27 07:19  
  
声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
关注公众号，设置为星标！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4ricRiaXQ6WVVlTAgCW8HUbC2rHkicA2rpDNEPAGyiatRibqB9LN5NyHcqLCmbibM1siaumqF5Yu6UtSsYA/640?wx_fmt=png "")  
  
  
一、背景  
  
日常开展SRC漏洞挖掘，在开启某插件（下载链接见文末）过程中，被动扫描发现bypass403后访问的页面，进一步发现多个漏洞，记录分享下过程。  
  
  
二、实战过程  
  
SRC时，日常开启动插件的被动扫描功能，此操作为常规操作，出洞率不错，但仅限于java站。建议各位师傅使用，因带扫描攻击特征，对于测试带了waf的安全软件的站点，可能会被封禁止IP。  
  
如图所示，java场见的高频漏洞该插件已覆盖。  
  
在评估某站点时，无意间看到该插件漏洞功能版提示出洞。此截图暂无具体漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4HlqhHI5UfWsTgee7gPC34tx4X1ueqxBU4z2VQV1udtbkHPUp3PjUylAQAqlD4nib6o26OtQ4rr8A/640?wx_fmt=png&from=appmsg "")  
  
  
此处假设为：https://xxxx.edu.cn/api/user-service/v2/api-docs;.js。在浏览器访问此链接，访问成功，泄露了大量的api接口信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4HlqhHI5UfWsTgee7gPC34kGJlyPWOH7j3LglVNl5dDCejvVZCJ5fKKIF4PeibrDraf9oJibt3wWxg/640?wx_fmt=png&from=appmsg "")  
  
但如果去了符号“;,”，在浏览器则提示403,说明此插件在扫描过程中进行403 bypass。  
  
针对泄露的接口，由于工具误报率较高，未使用相关的工具进行接口探测，作者人工进行了排查。经过排查，发现存在任意注册用户及未授权访问用户信息问题。  
  
  
漏洞一：任意用户注册  
  
在https://xxx.edu.cn/api/user-service/touristLoginByPhone 此接口处存在任意用户注册，前端页面无注册功能，通过此功能注册任意用户，并获取登录凭证。此处的phone根据后端报错提示告知。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4HlqhHI5UfWsTgee7gPC347iajYsCrZoQB2LXX6iaUiciakP55oH4LZa9Heq8aqqOiaxmMBl3U2F9o4Rw/640?wx_fmt=png&from=appmsg "")  
  
  
使用登录接口获取登录凭证。  
  
登录接口地址：https://xxxx.edu.cn/api/user-service/touristLoginByPhone  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4HlqhHI5UfWsTgee7gPC34Zk35uDCLgsdXTNT7w47GJF6jQ6BYoWwnAiaRIzvcWlPZE4RrPBUSicibg/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞二：未授权查询用户信息  
  
在接口https://xxxx.edu.cn/api/user-service/userInfo/getUserInfoByUserId处存在未授权查询用户信息漏洞。  
  
通过遍历id可以获取整站的用户信息。此处以获取管理员信息为例。id为1为管理员信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4HlqhHI5UfWsTgee7gPC34w5h7mB1m6s4NJDUbHjydJljTZ4lhoTkZ3RQGfvVCKZozvMHicM2Yhxg/640?wx_fmt=png&from=appmsg "")  
  
  
工具获取方式:关注公众号并回复250627获取下载链接！  
  
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
  
  
