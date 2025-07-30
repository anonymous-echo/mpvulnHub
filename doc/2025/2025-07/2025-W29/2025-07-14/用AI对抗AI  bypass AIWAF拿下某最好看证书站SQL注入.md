> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247550972&idx=1&sn=b7a0e17d48eaf0fc1488c978e12d26df

#  用AI对抗AI | bypass AIWAF拿下某最好看证书站SQL注入  
原创 zkaq-花雨  掌控安全EDU   2025-07-14 04:01  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  花雨 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
  
****# 1. 资产收集  
  
首先，像这种证书站，又是最好看的类型的肯定很多人挖，我们如何在其中找到别人挖不到的点？思路就是走小众，走你平时觉得不会出洞的路子。  
  
我的思路就是找编程语言使用人数最冷门的语言去测，这样被语法打到的概率就降低很多。  
  
引用文章：[https://mp.weixin.qq.com/s?__biz=MzA5NzAyNTcxOA==&mid=2651444006&idx=1&sn=a59b5ca3019a5ed50ce1025e851d9ff3&chksm=8a1deea5ab2a620ee4f826e81b5cb6541dd96e10bfba00d688222e85463dd5ae2388789e3077&scene=27](https://mp.weixin.qq.com/s?__biz=MzA5NzAyNTcxOA==&mid=2651444006&idx=1&sn=a59b5ca3019a5ed50ce1025e851d9ff3&chksm=8a1deea5ab2a620ee4f826e81b5cb6541dd96e10bfba00d688222e85463dd5ae2388789e3077&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRunxvrhZLolaSzzuQpqGE5tfiaNRYXicUcbTvSZtSk7VGZhJRCTSa3O7g/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到 Ruby 使用的是最少的，于是我直接 quake 直接搜 domain=xxx.edu.cn&&app=ruby 搜出来直接秒了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRKkusONTbu9bsjYCIwY6rbNF2d3riaO6WIL82tT2Uw8UVhs0mSoCu1Bg/640?wx_fmt=png&from=appmsg "")  
  
  
在交互多的地方随手输入字符，然后插件帮忙扫就行了，不用自己手动去测。  
  
这里找冷门的开发语言还有一个点:  
  
很多站的搜索功能都是要么加个 wbtreeid 参数（edu 喜欢的统一 java 搜索框架，基本注入无望）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRmeicosd24ubuVy2SmwFqSZBpItN7lF36YXxAP3kmAYAVgDhj6mPGM6Q/640?wx_fmt=png&from=appmsg "")  
  
  
要么就是 WebPlusPro（统一搜索引擎，也是无望注入的东西）  
  
因为 java 类的搜索框都喜欢搞这种统一的形式所以我就想找非 java 类也冷门的编程语言。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRsKvAufme31wXRicBT2KibCb2OnpEX4cLzJ5CCsGFXPyoxjMMpajB49ow/640?wx_fmt=png&from=appmsg "")  
  
最后，在 app:ruby 搜索出的站直接打开，随时一搜就出 SQL 注入了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRicHmNogm0qk3L8FRTwBgIicvvLpssj1MvDO7J6eVIxNGRY2NkBm5du0g/640?wx_fmt=png&from=appmsg "")  
  
# 2 .SQL 注入  
  
我这里用到的 SQL 注入扫描插件是 Detsql，下载链接：https://github.com/saoshao/DetSql/  
  
我个人的喜好配置是这样：能禁用域名黑名单能最好防止自己测到杂包，还有参数黑名单能帮助我们测一些不必要的参数，常见误报参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRvD2yial3PTFwTTibE9yF6tnfcWghNxMpibicmfJqO7e52BGI6gcTFFP0Jg/640?wx_fmt=png&from=appmsg "")  
  
  
这个插件比较人性的就是多少概率为 SQL 注入，这里引号直接报错出 SQL 语句了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bR6dTKueAmXM92CuCIpqy3PkAsckFvRIrzERMYiaf8JTxe2DTH0N6BZzw/640?wx_fmt=png&from=appmsg "")  
  
出 SQL 语句这种情况是最好的，能直观看出数据库类型，找对应 payload 就行。  
  
丢 AI 还原 SQL 语句，然后我看看出来是 LIKE 模糊查询的 SQL 注入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRqrh4WicoLNKQAs0OkrKAuojFRm2HqYJ98n98MYh2hp4zxMJTZZCRumQ/640?wx_fmt=png&from=appmsg "")  
  
1、构造SQL注入payload  
  
万能 SQL，发现为某亭 waf  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRysaCgB7He1pa5Po8d33ibr7Fkdib3ibQUogM0muxbuSQIic6VubBuGrL2g/640?wx_fmt=png&from=appmsg "")  
  
这里省略大部分测试 SQL 函数过程：放我比较经典 payload 被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRGDLDh69rgZeBsKU7mQtQhd2crUaWB7Cy6yJf8m7IrAAcZliaaASFbibw/640?wx_fmt=png&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRgPHeK6VRFXJw2BiaIONEkXuIBHOULQe0Zl2QhFl9GJ4z0wB0u7RP65w/640?wx_fmt=png&from=appmsg "null")  
  
  
这里我用了编码加密了 payload，发现还是被拦截，说明这个 AI 自带解码分析功能的，所以多重编码也无济于事，反而容易被识别解析成攻击代码。  
  
发现每次响应时间都会不同慢慢变长，说明这个 waf 是存在数据分析的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRI7Qxjof64txSvviaicP7H2sHyGd4soeXGD416aIpHicDnKsEErgakQ61Q/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRSasxMSicydwVRUiaIRgry5PSr1NBlrrG008NzkEdcIqM5yG0Q7QYoEWA/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRz7uk4EjCsclO45AXQXich9EtRsKCibh04ibhUNZssu1YVlkJh1icVcX7cw/640?wx_fmt=png&from=appmsg "null")  
  
  
通过 AI 分析我的 payload 是一个攻击的 payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRFWtJ6OI4a3vwVoLcVaic1Cmn3qe0boX7MNSV99dAp88EVmFQAgv37mw/640?wx_fmt=png&from=appmsg "")  
  
通过尝试，发现这个 waf 为 AIwaf，我是这样判断的。  
  
2、 闭合单引号并添加无效关键字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRRRicZ4jwssJtNYafOzcFju7yuwtPFEvD5DnNrTLbLiblJx71NxNibhq4g/640?wx_fmt=png&from=appmsg "")  
  
报错原因:invalid_keyword 是非法标识符，触发语法错误，这里神奇的是 waf 居然没有拦截。  
  
这个看起来并不像注入但却会引发数据库报错存在' AND 也放我过去了，说明这里 AI 并没有把我当做一条攻击的 payload。  
  
3、绕过AIwaf  
  
那么通过这条信息，只要我们找到能让攻击 payload 看起来不像闭合注入就行了。  
  
4、构造不闭合，形似逃逸。  
  
拦截：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRb0Bu6zDabZuASLb3Vh9t1b3YC5AqeCTppoCcw49yA634Fwlb9cm1xg/640?wx_fmt=png&from=appmsg "")  
  
  
不拦：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bR7CDNrcYibod8MkEvx64c441tWTibojmbAiagBC7OErADXhbpnSEnaibXrg/640?wx_fmt=png&from=appmsg "")  
  
  
似乎可以利用这种让 AI 认为，这不是通过闭合造成常见 SQL 注入报错。  
  
利用%'|| payload'看起来是正常数据包已闭合无注入样式绕过AIwaf。  
  
拦截：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRbnmXGB2WYTXPxrl6eGiaw4q7DtnmlMAw08s37vOJjHWkv5Ds1ibKJWTQ/640?wx_fmt=png&from=appmsg "")  
  
  
很好select user()直接不拦了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRejgicSZRWXTzy89OZW8P7hvdcZPoryCyI7Wha2hLbcpuUFicxV36VnZA/640?wx_fmt=png&from=appmsg "")  
  
  
拦截：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRqOUQJW623lu7mHDbY2JcWBQyCwanRQma3xrHV4YSBhxykaKBibxZZIw/640?wx_fmt=png&from=appmsg "")  
  
  
拿下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRiamGFtX20iax91Kvuvl8HfYbp7MQmBm8gIOw2ToBNLGGRCmYbxZp2IeQ/640?wx_fmt=png&from=appmsg "")  
  
  
3.分析 AIwaf 机制  
  
一、把我们绕过的符合 payload 丢给 AI 分析看看  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bR6PcdPverS3nrWibXrxXym7vreMEZ1cX04E8vKrsRd5AicHOUVQ49L5BQ/640?wx_fmt=png&from=appmsg "null")  
  
  
① 闭合单引号：虽然这里 AI 把%'当做'%'闭合风险来识别，但是后续加了 || 来进行连接，实际 SQL 语句就会变成'%&'看起来就不像是注入了。  
  
② 拼接与运算：||&''尝试利用字符串连接和按位与操作，在这 AI 似乎只是认为可能语法上面存在逻辑混乱，却没法真正判断是否有实际注入语句  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bR5DG7CU8pcLHWI9ia1X0bruzBPXBbdibsJJy0ZnwIUicJpeqZFv2uO21Tw/640?wx_fmt=png&from=appmsg "null")  
  
  
③ AI 把潜在的危险列出来了，第一点是语法错误且此数据库为 MySQL 数据库不支持，可能放行我 payload 的原因是我的注入语句包含的是 MySQL 的用户名为 user(),所以 AI 就判断我的 payload 是安全的，并不会对 MySQL 数据库造成影响从而绕过。  
  
④ AI 把会真正触发注入的 payload 列出来了，说明这里 AI 认为我的注入需要具体的布尔和时间盲注才能导致攻击者注入出具体库信息，所以 AI 就把我的 payload 认为是一条正常的搜索语句，并不是实际对 MySQL 造成危害的注入语句，放行了。  
  
二、把我们注入出用户名 payload 丢给 AI 分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco5xC3k3P8xf2ibz7ZHWc0bRyKes60msRjq9HnxviaJed1E3MNQZpTqCTvWW7BNz8ictuLGHu2N8OWNA/640?wx_fmt=png&from=appmsg "null")  
  
  
①gtid_subset(user(),1)将当前用户名（如'root@localhost'）作为 GTID 集合传递给函数，但1不是合法的 GTID 格式，导致函数报错。  
  
这里配合前面符号逃脱 AI 分析，AI 就认为这个 payload 没有实际引号不闭合导致 SQL 语句报错这样具备威胁的字眼和格式错误导致 AI 错误分析这是一条正常语句所以放行了。  
  
②||是字符串连接符（部分数据库中），&是逻辑与操作符。  
  
这里 AI 没有给出威胁信息，说明 AI 分析为 payload 安全所以放行。  
  
③攻击者通过判断页面是否报错或响应时间差异，实现**布尔盲注**  
或**时间盲注**  
。  
  
这里 AI 给出了需要**布尔盲注**  
或**时间盲注**  
才能实现注入，我的 payload 中没有这样的 payload 字眼，所以 AI 直接无敏感放行了。  
#### 总结： AI 是把这种 payload 当做错误逻辑的 SQL 语句尝试，而并非是实际布尔盲注或时间盲注那样直接对数字进行猜解的 注入语句，所以 AI 默认此语句为无危害语句所以直接放行了。  
  
  
   
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**没看够~？欢迎关注！**  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+交流群+靶场账号**  
哦  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******分享后扫码加我！**  
  
**回顾往期内容**  
  
[我与红队：一场网络安全实战的较量与成长](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247550558&idx=1&sn=589aa46a61b9ab02ab953ccb9539b1d3&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[重生HW之感谢客服小姐姐带我进入内网遨游](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247549901&idx=1&sn=f7c9c17858ce86edf5679149cce9ae9a&scene=21#wechat_redirect)  
  
  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  
