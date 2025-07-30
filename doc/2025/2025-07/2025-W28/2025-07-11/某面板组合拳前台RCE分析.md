> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247550870&idx=1&sn=a8857963542ca382f89e8d8dddc4863f

#  某面板组合拳前台RCE分析  
原创 zkaq - cs  掌控安全EDU   2025-07-11 07:01  
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  cs 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn  ）**  
# 1、背景  
  
今天在群里看到有人分享了 某 面板（xxxnel）的前台RCE组合漏洞。  
  
正好周末有空，便尝试分析了一下。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxgc05icK7wOxTau3VwXZxOTeia5TmYgEzmjHupULZZ7NdlMiafwpb5NNbA/640?wx_fmt=png&from=appmsg "")  
  
# 2、漏洞复现  
  
复现过程本文不再赘述，详情可参考原文：  
  
[https://mp.weixin.qq.com/s/nU1qFi01Ig2Stwzo__oRUQ](https://mp.weixin.qq.com/s?__biz=Mzg4MzkwNzI1OQ==&mid=2247486343&idx=1&sn=5d6b5ed29ee6c4cfbb7d1471d61c62b5&scene=21#wechat_redirect)  
  
（原文已被删除）  
# 3、本地分析  
  
首先从官网下载并安装至本地 虚拟机 环境。  
  
可以注意到该面板的端口和后台登录 URI 都是随机生成的。这某种程度上增加了安全性（虽然长度不长，但数字+字母的组合还需要一定时间的爆破，基本能被WAF拦截）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxPV6gEsg0hribZSV9My8hSV5pfeXE00zCEfVibWEtEAOuVBicOqRkWDA7g/640?wx_fmt=png&from=appmsg "")  
  
看完文章的第一反应是后端接口存在未授权访问漏洞，因此可以直接修改返回数据包绕过权限验证。本地环境搭建完毕后，登录发现返回了JWT。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxJFBgIvrShb98Znib2icFdJoCnabfxjYB26C3tAu0GI8CfsibKJxm94X3Q/640?wx_fmt=png&from=appmsg "")  
  
  
找一个接口去掉认证 token，发现不能未授权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxEzHhYRnesnrQDPIlVnqj5NOTIXOibGUGfdet1k92P9j0hgvWAWyicqfw/640?wx_fmt=png&from=appmsg "")  
  
最初的思路错了，随机想到是否可能是因为 JWT 密钥被硬编码导致的。  
# 4、寻找硬编码  
  
定位运行程序 pid，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxM5jI7iacUAlQ8J2pt5PeDHxkeevl83Ucw34ErKtJyDcX9NmpahJccpg/640?wx_fmt=png&from=appmsg "")  
  
定位运行程序本体，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxRl4FhMwsQWn8zHCAR6dxHjTeSVR0zEOhXG0L2f6XhYUknxZxksgOFg/640?wx_fmt=png&from=appmsg "")  
  
确认为 go 编译程序，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxHiahNJY14INKhYYjblPD2CAsxFVuW7TuJdaX9AOMj0vmvwZibNC9HnnA/640?wx_fmt=png&from=appmsg "")  
  
使用 ida 打开，定位到关键函数，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxrI6I6cvY7FS1DdTJsx2vKSoKYrI1ZLyBkicAiadoglre7pDVI7RiasWtA/640?wx_fmt=png&from=appmsg "")  
  
继续向上跟，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxmdG7Lm0xcKztdk814tb79nsF6E13Vg7hu1C8FKt6WmiaTSMaOeyjvOg/640?wx_fmt=png&from=appmsg "")  
  
还原伪代码，  

```
func GetToken(userId int64, account string, tempUser bool) string {  
    // **拿密钥**  
    key := config.String(&#34;jwt.signing_key&#34;)  
    ...  
    jwtInstance := Jwt{SigningKey: []byte(key)}  
    claims := CustomerClaims{ ... }  
    // **生成token**  
    tokenStr, _ := jwtInstance.CreateToken(claims)  
    return tokenStr  
}  
```

  
结论一目了然  
- 配置项名称："jwt.signing_key"  
- 实际存储地：服务的配置中心或者本地 config 文件  
返回程序运行目录，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcprlVCJNQZCz7DF2ZwLyLWxp5u0nwKibiaVEd2VUQz9QdMlCV7HfbJ9mSYgVhe2GUNibr2V5JJ0hyS2A/640?wx_fmt=png&from=appmsg "")  
  

```
/xx/panel/config.json
```

  
  
关键配置类似如下：  

```
xxx
   &#34;jwt&#34;: {
        &#34;signingKey&#34;: &#34;xxx1973&#34;,
        &#34;issuer&#34;: &#34;xxx&#34;,
        &#34;expireSeconds&#34;: 604800
    },
xxx
```

  
  
经过重装虚拟机验证，发现每次配置均一致，说明密钥为默认固化，未做随机化处理。  
# 5、漏洞修复  
  
在写作本文时，官方尚未修复该缺陷  
  
  
**修复建议：**  
- 安装时自动生成随机密钥，避免采用固定值  
- 除校验 JWT 签名外，还应校验当前用户是否存在于数据库中  
# 6、补充  
  
分析过程中还发现，尽管端口和后台URI是随机的，但实际攻击场景下如何定位这些信息，以及如何利用该漏洞，都是值得进一步探讨的话题。  
  
实际系统中这部分是可以绕过的，  
这就当做一个小彩蛋，各位自己寻找吧  
  
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
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[重生HW之感谢客服小姐姐带我进入内网遨游](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247549901&idx=1&sn=f7c9c17858ce86edf5679149cce9ae9a&scene=21#wechat_redirect)  
  
  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
