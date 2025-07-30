#  教育edusrc-越权漏洞案例集合   
 迪哥讲事   2024-03-08 23:20  
  
免责声明:由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
  
  
  
1  
  
# 清华大学越权漏洞  
  
  
  
  
LOVE  
  
# 通过越权漏洞修改他人信息  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgOOQhAhCQv3uG5lXv3rxpzL4ZRStZtjazES638ypQTNO8Mb2icBCBicbQ/640?wx_fmt=jpeg&from=appmsg "")  
  
首先我们需要注册两个用户  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgA1BxQJLfHHeXgIpp4UZoNHPJjQf9MAXaEicR7E1aSXGPjs0yYXPIf4Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgibKsrMwermnntot3X9y4WEcsQlBShWCVUXictf2TmicxBkLNJdaNbrcBQ/640?wx_fmt=jpeg&from=appmsg "")  
  
用户1:Pwn777  
  
用户2:Own777  
  
之后我们登录用户1  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgrZ8kichasT2pnxKJBRYfic1icL3g9OqibhhKElHt0icpfggssM9aib00kalQ/640?wx_fmt=jpeg&from=appmsg "")  
  
这里要求上传头像,我们点击叉叉即可  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkg94pnB9brPKyu5TLUxxdTuwUtnqic9s45PBwL8ADGcFl2PMFZEsP7tcg/640?wx_fmt=jpeg&from=appmsg "")  
  
这里是我们的个人信息,编辑好后点击确认,Burp进行抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkggNW8qowrHLm4MarSib0kEibFQVE0r4VKKqSu1zEIOib13wHZVlDLpT6Dg/640?wx_fmt=jpeg&from=appmsg "")  
  
该越权漏洞出现在id中,只需要知道id的值即可越权修改他人信息,修改成功如图的响应包是200,并且是errCode:”200”  
  
我们登录用户2,同理抓包记录这个id值  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgxDFIjU9Fsic2veiaL9DEgkn6LSHTLuOicCJBsRneJhNe25XNsgiaJM7ftQ/640?wx_fmt=jpeg&from=appmsg "")  
  
点击确认进行抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgPLarqI1Tr9WuTiaibnf3Xt2M8Zq69iaicjon1iaBnWsaicpgPPjAjbuPzeew/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到该用户2的id值  
  
用户1的id值:id=a4ebed7d2abe4139b9b38f07aeb4e221  
  
用户2的id值:id=306b773cc8944242ae0503aed01f8000  
  
接下来我们在用户2中将Burp放到重发器修改该id值为用户1的id值  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkghGkYtJIPtOyZ701T8znVvZX4XvI8tbQbNpzX37LaStuYFOHKibWzCjA/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到响应包也是正常响应200,之后我们退出用户2,登录用户1查看是否被用户2越权修改了信息  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgHHd6icmo65zRicRQaZVZIcfYLyjR1T9cY1jUaGp6vdUhmGLia0hsZxYvw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgRZVG8TAngfNBlxjklDICjQLNBygn4k1LjeLw7qRQJgx9xWoWqPIYKw/640?wx_fmt=jpeg&from=appmsg "")  
  
发现信息全部变成了用户2的信息,成功越权修改  
  
  
  
  
  
  
2  
  
# 上海交通大学越权漏洞  
  
  
  
  
LOVE  
  
# 通过越权获得管理员才有的权限+越权修改他人信息  
  
  
上交大某科研系统  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgBf31v94lYBhqK40EKciatEMdRUNYIwPC4ProiaeuXkM0CF90icEWywpTg/640?wx_fmt=jpeg&from=appmsg "")  
  
在该请求包中拦截响应包  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgG5htdiaaFuL24B0jSNiaAm0lalicS0MAATic4eFZictew0OT7RLqSo0GEvQ/640?wx_fmt=jpeg&from=appmsg "")  
改为true  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgrn1SiaU8EYLGG6NXGFwnd0mcLu9Ed8cyW4QLH9Oy7oy3SV8gA3XMftw/640?wx_fmt=jpeg&from=appmsg "")  
  
点击切换的时候开启抓包也是对userinfo这个请求包拦截响应包改true  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgOYYwLfGXibX0s5SOOrR0f9WicBmNibLIEXicmYRNXD7kf4dTicDI6uXKLkQ/640?wx_fmt=png&from=appmsg "")  
  
并且也有了创建的权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgk2dnozEhmePiaAXqPoZ10sibicticUcVMVMWHw3qv7AaFLWS7q236zdCUw/640?wx_fmt=png&from=appmsg "")  
  
上交大某地方历史数据库越权+1  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgwNibfCI4gcbs0nibqkWP83F6JAjXPRVQ1wiaRxqCBN9LMNXCPsd5t4SXg/640?wx_fmt=jpeg&from=appmsg "")  
  
在注册处注册两个账号  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgkIGria7EauVSSh3R3hIF61OIXnulls5LibgbJqNA8Lsc76Pib3Iv910IA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkg0QalBkkJCFQMMgIzcDpby5Lbibgc4whxicT6DvKT7QbkF5eiaQjH94cPQ/640?wx_fmt=jpeg&from=appmsg "")  
  
然后登录账号1  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgckR1JuasapzMWClLyryRUDNSwaqztwssiaJiczaFRjH9D1p1Yp87qQgQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkg7l2JhPPSjlGOtLJXKpNVAqib9KSJnu4Qvwqz9neCicIOw4ueiae3OV25A/640?wx_fmt=jpeg&from=appmsg "")  
  
在我的个人中心编辑生日,性别,省份等信息后,点击保存按钮抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgyS0dnqStuSdvZ4SsPNSDvvvNnWVQiaaZVUZyzGfLRqur1gibMsvAnH4Q/640?wx_fmt=jpeg&from=appmsg "")  
  
我们可以通过修改UserID处造成水平越权修改他人信息1881924****的账号UserID为3204864记录下来后,我们登录另一个账号1987683****  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgpLj2TJaff1sB1ibzgO6OKWUvEXSwqYtOI8yYwRRRPLu5jricmwBGc7MA/640?wx_fmt=jpeg&from=appmsg "")  
  
也是同样的,这里编辑好相应内容后点击保存按钮抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgfoiaspy30NLrWYvOHkJCSO643YNG3XdGQAMSicRe8jOvyMLeGZC2j6fA/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到这个账号的UserID为3204865,并且响应包有我们账号2的手机号1987683****,说明我们在编辑这个账号我们改成3204864  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgwKzRUSbJLibKJ4uTcZaicpqVXAHTHoA5hRVQtU2v86v6WEhg2VkviascQ/640?wx_fmt=jpeg&from=appmsg "")  
  
成功越权,返回包也为200状态码，并且内容从1987683****变为了1881924****此时登录回账号1可以看到已经被账号2修改了  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgVRjMyaVicOUKw5rrSGXMBicD2oRMq1tPJ962a7HejKBNYexSzOQCYk3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
  
#   
  
  
3  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1R0nzLARpjNTZOet7UskXiboBFFJljN2Kl9qJP9gqz1pAtiagOOwZGTRIMm0p3RkDc1VdwcuGqIWXG/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1R0nzLARpjNT6ia6xj4UKmgwD3tLFQCicCcJVROy7LicgOpcPEpLCdHRVGEZuoGia2UWxhyNpgA1U8kl/640?wx_fmt=svg&from=appmsg "")  
  
# 复旦大学水平越权漏洞  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1R0nzLARpjNTaD3ovr7NoJWoHIdjzWCNzzfpeINVA7frBy4oq93Bwntrfia5UbVf4SUvZt5tngANY/640?wx_fmt=svg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1R0nzLARpjNTbEbxhDQMibcGlS1bo6iceopJHFmIiaon98noP4fjTHgiaGW2bQ8fMc0t4a6apkDCMk0h/640?wx_fmt=svg&from=appmsg "")  
  
  
LOVE  
  
# 通过越权漏洞接管他人账户  
  
  
复旦地理信息平台越权分别注册两个用户,分别是quan和Pwn  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgM4UvAiaFbXALqbZsuAg1tcXWeRcZJuCpU1r1ico1uvYsZ8icUXDe8149Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkg6N6yMU51ARvBhwOaia1NovKNf1AEjlaCBL8WyRLFBbmn8VAoKzH716w/640?wx_fmt=jpeg&from=appmsg "")  
  
注册后首先登录Pwn用户  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkghVQ8JPMGZIDxqWZ3Q984Oia4YAT0UMOchUwmhwtibwzZ9yoW3dNVaoeA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgOrb0SdKt8qMZecibgXfmL9hKGbWqmTuebFdhxCzQJlqdPJEAAXBy6Mw/640?wx_fmt=jpeg&from=appmsg "")  
  
点击数据库  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkg4lYsIIhwAzgicJqu6t2Ph5KCunTYCf2lpUrVfNLX0s0bSnl2WaWmvdw/640?wx_fmt=jpeg&from=appmsg "")  
  
再点击头像处  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgmAGWh0eg9goXicghb030zOEzFriaEcU35XFOfzXrcsLic7M4wfSyvzYFg/640?wx_fmt=jpeg&from=appmsg "")  
  
我这里使用的是火狐的Cookie插件,造成越权的原因在于  
  
username和userId,他们都是固定的值,该Cookie的用户凭证使用了固定的键和值作为验证,从而形成任意用户水平越权  
  
我们再登录quan用户查看  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgcW4xqdjKVKQBNohdbyBNYOcTYCFGBhXM2iaa14bYjoQdkTgXUpF98fQ/640?wx_fmt=jpeg&from=appmsg "")  
  
记录这两个用户的username和userId  
  
Cookie:  
  
用户1:  
  
username:quan  
  
userId:3c0018e4-cb90-4cc4-bb89-162ce3c6ce13  
  
用户2:  
  
username:Pwn  
  
userId:829d46e9-885a-4236-9194-f926e7caf853  
  
我们在quan用户进行更换username和userId  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgPbUkf2LSBC1YroW8vIbTxkVJJjfNgFllof76jFesIpZuU5gwLI9g5g/640?wx_fmt=jpeg&from=appmsg "")  
  
改好后进行刷新  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgZ4PJTFjlCHNAD7Ach56vzL97lCWvVSFwCwl2PzHR5yeiacPnK5NTCdw/640?wx_fmt=jpeg&from=appmsg "")  
  
成功越权Pwn用户  
  
也就是说,攻击者只需要知道username和userId即可任意越权用户  
  
  
  
  
  
#   
  
4  
  
# 辽宁省交通高等专科学校越权漏洞  
  
  
  
  
LOVE  
  
# 通过越权漏洞查看对方信息  
  
  
首先在注册页面注册两个账号  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgKLbAQVjRdiabB7ozVmv5RBWlFVt3GJAdnCh2fz4vnkyBdTzZ7DEQsvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
这里分别注册了Pwn和Kwn  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgNSG2w8RiaRr8g3eQG2ibfesKZA4O8dicOqOjGjWBoMWUic6S5MYLD04btg/640?wx_fmt=jpeg&from=appmsg "")  
  
然后分别登录  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkg0iaBJ9Qvy2fMQyedPQDCYvjV3JE2ToFRK9vM8dJuib4TWZmJolohfv1A/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkg5lAXoQLJKKEmMzjGI205l2fR9kCtGL9BKdpMu5CBa2Kxmh5OS3wH8g/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkglNBWxicNoOB3iaLpn9T50I0RNM9fHnOrbcpibX0IunTmJaibWFicicibAKg4Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgkcng85lEHjqXqKqWEyrDNUy7EWyKq5mR409CdxEicayGRTAOicNia9B1Q/640?wx_fmt=jpeg&from=appmsg "")  
  
正常情况下,只能看到自己的信息,包括手机号,姓名通过在Burp的历史抓包处发现可以越权获取其他人的信息  
  
只需要知道对方用户名即可  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgZDdgQWGsQ4ATpCuiaiagP7c2EFqG56AGibGAEP5goIagBa2WfILIAAulg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkguOucXzvJkglIGb7giavicTzmqSzOBnjibOjKnQAms3E7zvzzMQyGdRgXQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8omZA5HXGRiaicRPQibT8LdWkgBxa7ZPFZgQwqlVqYniaRB7hutAtHAycuv7VaRRYGoSoXghVOg8qicJ9A/640?wx_fmt=jpeg&from=appmsg "")  
  
POST /dev-api/index/index/profile?userName=知道对方的用户名  
  
POST数据为:  
  
{"userName":"对方用户名"}  
  
  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
  
  
11  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1R0nzLARpjNTAu43nwk6rFBa4aVQ34RvbQtZR5VlbG4Djib2LmibgvCb2azwnsvEUngXjEG1icl82Xp/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1R0nzLARpjNTtalw3reuxKdib2BTqd8US93J1O5z2dYqTicZIoDKony1rebvdTqPjaoTxFGHEbzYicn/640?wx_fmt=svg&from=appmsg "")  
  
  
