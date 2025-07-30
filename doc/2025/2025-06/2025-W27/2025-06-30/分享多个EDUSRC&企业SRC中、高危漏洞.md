> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247550619&idx=1&sn=334f45681027caca456d36252eeb3866

#  分享多个EDUSRC&企业SRC中、高危漏洞  
原创 zkaq-TobiSec  掌控安全EDU   2025-06-30 04:01  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  TobiSec 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
  
# 0x1 前言  
  
这次EDUSRC&企业SRC分享漏洞，都是之前挖的且都修复的，然后再分享几个前段时间有意思的案例给师傅们，像最近挖了几次众测，收获都还行，但是漏洞没有修复，暂时先不做分享（赏金还没有发，怕寄寄了）。  
  
其实我看了很多师傅分享的企业SRC漏洞，说实话并没有想的那么高级，一个漏洞大几千，其实主要是人家师傅细节，且愿意肝，很多我们小白没有发现的地方，人家师傅都会去测试，所以人家能赚钱，其次就是分享EDUSRC漏洞了，最近也是旁边好多师傅在平台提交了通杀漏洞，sql注入、接口未授权、未授权绕过、敏感信息泄露接口通杀漏洞等。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnIdkaErvzASDMb5KR9jlnsgl0MFaeicViaoYPoO14fTIlBu6FtESk8aIQ/640?wx_fmt=png&from=appmsg "null")  
  
# 0x2 有意思的众测案例  
  
这个众测案例中漏洞目前已经都修复了，所以拿出来给师傅们分享下两个漏洞都是高危（众测给的高点），漏洞没有那么牛逼，其实就是我之前经常分享的挖微信小程序楼——sessionkey泄露和数据包分析的手法，但是又不是那种直接能看出来的，要是没有那么细节的师傅们可能就容易错过这个漏洞。  
  
因为这个众测目标大多都是服务行业，酒店、旅游什么的多，像这样的资产，app和微信小程序功能和资产肯定偏多，功能多，漏洞相对来说就好测试点，这里直接从小程序入手。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnWagm6xaufUglLA2FeyVicNMAmG3cb3BTgsRr4sVEqlW7sYgzf8ibxm2A/640?wx_fmt=png&from=appmsg "null")  
  
  
可以看到这里小程序很常见的手机号一键登陆，很容易出那种sessionkey三要素泄露，伪造用户信息未授权登陆漏洞  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnuGBIfuWt1icYvvTSjASJwCJPw4DdWm8TN1rhcZRxWichoBAuO1r8doQw/640?wx_fmt=png&from=appmsg "null")  
  
  
这个小程序也不例外，也存在这个泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnWc3dGNDfyYeAU91pyT9ceo5KHS8LcUiaMibWqomrXvZNlYLrsnSCppmg/640?wx_fmt=png&from=appmsg "")  
  
  
然后解密得到如下，182开头的手机号  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnEibNu2Sz6WjPY8jd2qVibWPWXdwibQDdFZWpicL2dcW1UCmLu6eiaCcjHhQ/640?wx_fmt=png&from=appmsg "null")  
  
  
老规矩，这里直接改成我别的手机号，然后加密，再重新退出182的账户，点击上面的手机号一键登陆，直接抓包，然后把数据包进行替换（我166的手机号加密字段）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnf0p80znM30ib4af8VtHUd6Puv8fKfGeaLbTiaBia0yp7iazKWAozfqYmow/640?wx_fmt=png&from=appmsg "")  
  
按道理直接放包就可以登陆成功，但是这里直接点击放包，登陆失败了，这里猜测之前可能有师傅搞众测已经交过漏洞，那边后端对这里做了校验，行不通了。  
  
但是峰回路转，我直接在重现测试，然后我直接看返回包，发现返回包出现了下面两个参数，且都是明文显示（看到这两个参数心里很开心，因为很大概率存在漏洞）  

```
{&#34;phoneNumber&#34;:&#34;xxxxxxxxx&#34;,
&#34;purePhoneNumber&#34;:&#34;xxxxxxxxxx&#34;}
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnrXNib4p3zhNCvPe3ghbLNlgpHxibibic9eBKA6wYNRcuWzm953aOtX082w/640?wx_fmt=png&from=appmsg "")  
  
  
后面我直接修改一键登陆页面的返回包中的这两个参数，修改成我166的手机号，直接可以登陆成功  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnKaCZAjIOkZX66CrRG3BmLtJoSWiblDE7xgxMOFx8Xrkmu6y0ODkBmtw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnNicTmQguxbiaTt9XjYBmu0nt4gcU6oOy46p7Z4WXeW3mRz7icgibY4Ajibw/640?wx_fmt=png&from=appmsg "")  
  
  
然后还有一个比较有意思的案例下次再分享，刚才没有找到之前的报告了，不太好分享，等下次找到了报告再做分享，因为漏洞已经修复了，复现不了了。  
# 0x3 EDUSRC案例分享  
### 一、接口未授权  
  
这个漏洞是前段时间在js里面找到的接口（目前已经修复了，找不到了），可以通过这个接口，加上学号遍历学生的学籍信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnFTXUrFjytkxPnHCrq8MUeQ6YlBibvYv4AQIb59OYCUAXJ1QKdHKw7rQ/640?wx_fmt=png&from=appmsg "")  
  
  
接口如下，可以通过遍历学号拿到敏感信息  

```
xxxxxx/xxxxx/Student/RecommendationForm.aspx?Xsxh=学号
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdneIDrugkrmRibL4K4uhv1KkKKItBhBKoibIiciaJBnbrRqQdI9lth7ZmbkA/640?wx_fmt=png&from=appmsg "")  
  
  
学号直接能够网上找到，直接算EDU高危漏洞了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnQh7zpZ6OSp6iabfs3xibWzzCol7hlBLyNJ8tMfyLGvGXdFgbsVugmYZg/640?wx_fmt=png&from=appmsg "")  
  
### 二、SQL注入漏洞  
  
这个漏洞是存在搜索栏这个地方  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnnAKM6TENPpGv4bWStXkPmxOJzlvjEXZuF6RHr6kzoBKn9PI6iaXq4BQ/640?wx_fmt=png&from=appmsg "null")  
  
  
输入1'，网页报错同时爆出绝对路径，初步判定为POST型注入  
  
然后直接使用burp抓包分析请求，并保存至txt文件中  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdn1A7IamjXgXOSemNVmFkroibXBb6E9KkasPKCUNoeT49l3uzfEuD2bWA/640?wx_fmt=png&from=appmsg "null")  
  
  
打开sqlmap进行注入，此处可以通过注入获取库名，表名等  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdnEb8RY7WSEj4j9syJtAfkTbvpTViblJlOYGia4t433tjnejR9NS2IC88g/640?wx_fmt=png&from=appmsg "null")  
  
  
最终在数据库中拿到了管理员admin的账号密码，成功登陆后台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoMXCY1z24mYWia8CfshSjdny0kxliagFBmPl1XDAItzibSr7IctEF9icqUNRNAPXo02J6Aicrv3zzl1lQ/640?wx_fmt=png&from=appmsg "")  
  
# 0x4 总结  
  
这篇文章到这里就分享结束了，文章案例不多，但是有些漏洞的细节，师傅们可以关注下，个人感觉挖掘企业src包括众测，然后和EDUSRC对比起来还是有区别的，EDUSRC漏洞要求相对来说高点，比如一些敏感数据泄露，在企业src包括众测等敏感信息泄露的定义不同，  
  
然后上面给师傅们分享了我之前的众测案例包括EDUSRC的案例漏洞，希望师傅们可以多看看，最后祝愿师傅们多挖洞，多得src赏金！  
  
   
  
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
  
