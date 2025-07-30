> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247519635&idx=2&sn=d1cb62c4e47b738de4b25b0c546c8072

#  EDUSRC | 证书站小程序漏洞挖掘思路及方法  
 渗透安全团队   2025-07-08 02:15  
  
   
# 一、信息收集思路及技巧  
  
注：这一段信息收集思路及技巧是笔者借鉴我大湘安无事的大佬--沫颜 WEB 安全的思路。具体的可以看这个链接[Edu教育src证书信息收集思路及技巧（二）](https://mp.weixin.qq.com/s?__biz=Mzk1NzY0MjY2NA==&mid=2247483963&idx=1&sn=1ed5067bfb400db8904d8899d01d444e&scene=21#wechat_redirect)  
  
  
每个小程序是需要备案后才能上架的。那我们想要查询到这些小程序的信息就需要用到下面这个网站：  
  
https://beian.miit.gov.cn/  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfZOu94W8EcTIsJMvBc1DC6PWaDcgMPU5I2t5Mc9phibtkcR9LciceqhvQ/640?wx_fmt=png&from=appmsg "null")  
  
  
好用示例：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf3eibtk3snTTSGSe98hlu7VHMlFUMUaAFTicGqs9EyU269wAS05yqLyrQ/640?wx_fmt=png&from=appmsg "null")  
  
  
直接在 wx 中搜索清*大学小程序，杂七杂八而且很多其他大学或者公司的小程序。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfVWmoVQtdC132Xxs5dAcscHTfCqOMog28BTtGTicsebWTia35FssDHxAg/640?wx_fmt=png&from=appmsg "null")  
  
  
在这个网站能直接查询到 42 条小程序信息。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfzNkjX5Fuen2icVR85HrrOExVpAorCXzIxg5zLF1Fsf2glGFebVnNuEw/640?wx_fmt=png&from=appmsg "null")  
  
  
比如说这个 清  
选 这个小程序，你在微信里翻到底，翻到 g 都找不到的。但是这时候我们如果自己手动去搜这个清  
选名字，能搜到，而且是标注了清  
大学事业单位的所以百分比是属于清  
大学的漏洞的。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfibATP8JXSsuKLhY8tER1mcibGr2p3qh6R0yzo4I4dM04BvJ1q4t4Dzww/640?wx_fmt=png&from=appmsg "null")  
  
  
这就是**出洞的关键所在，去找一些边缘资产，去挖一些别人没碰过的站点。出洞的几率会大大提升！！**  
# 二、第一个证书站小程序  
### （1）任意账户登录  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfM6unZSshW2HKWEVKcsRuW7licIWy8d2CK32Sm8m7SQRW0zhBicUvV9ibg/640?wx_fmt=png&from=appmsg "null")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfwJ509MxI2Pg0G0aaxEiceDrAakRLUc2xrwGprPWEzzG8k5pSEWAp1Tw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfLFibXTOeBASpEf3ROibhI6skiaFtwgXhfywzwoeoib6RNe35XliaQslibAbQ/640?wx_fmt=png&from=appmsg "")  
  
点击登录并 BP 抓包  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfoWRLnu1uQdoFWK8ApvZgJ4Yciay5YFiaHic70lUB3JxJLcdkffHbvUCHQ/640?wx_fmt=png&from=appmsg "null")  
  
  
像 wx 小程序，这种授权一键登录的，有漏洞的几率很大。它就是获取微信绑定的手机号，然后根据手机号返回账户信息。像 session_key、iv、encrydata 三要素泄露，账户接管等等这些漏洞就经常在这里产出。  
  
这里我们虽然只有 encry 和 iv 但是不影响，直接拦截返回包，可以看到 phoneNumber 和 purePhoneNumber 就是我们 wx 绑定的手机号 18*********。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf7ctkKGCDKpKHbS7z7GqWZE7vOTfYAFuq514pnX6braWS922KLTz5pQ/640?wx_fmt=png&from=appmsg "null")  
  
  
将phoneNumber和purePhoneNumber参数修改成其他手机号,放包  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfu8j9kkWbHAfGXrzXYQr6UEw5lJ96F1zuPOcgOP9C3E5VE3TwHA3UbQ/640?wx_fmt=png&from=appmsg "null")  
  
  
下一个数据包我们的手机号就变了  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfpeA3c3EsVoVXCgpoQmEmQ0Kl3wWQRrtLLwZJPzkdCDbPn0fD7icgdjA/640?wx_fmt=png&from=appmsg "null")  
  
  
再下一个数据包账户信息和手机号都变了，到这里我们的任意账户漏洞其实已经基本完成了。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf77Q7d3Rgiaw2LwGOkEicw5ficoCqP9pVOxWVUgtpys63rxxoXnuyry0zg/640?wx_fmt=png&from=appmsg "null")  
  
### （2）验证码转发漏洞  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfmGGDfkAiaSvZe1RLiagmbnOIiaGKqWibe1yCiaZHbcgQnfk0NLiaw7t4lAbA/640?wx_fmt=png&from=appmsg "null")  
  
  
这里我们原本是 18 开头的手机号，点击更换手机号。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfB0yGjjUWQ79sQicZACRUQPofGqoah7t0pwG48WrlI5tXK8m9d4XD4Iw/640?wx_fmt=png&from=appmsg "null")  
  
  
输入 19 开头的新的手机号码。点击下一步并抓包。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfBx7s0o0oib1OksCcJuOnNMpeQMicXbYV0PbbpzLPkJj9JQ1W1YiaSLOwA/640?wx_fmt=png&from=appmsg "null")  
  
  
这里应该是确认更换的手机号为 19 开头的  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfKXCJgaofetyv35BZvn3431u3UNtp9U4bs6qTumNuQFRibNzOHlXSxwg/640?wx_fmt=png&from=appmsg "null")  
  
  
这个数据包，就是发送验证码的数据包，关键就在这里，将 mobilePhone 改成其他手机号。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf7RoLyj25wgy1rhjlJicBtu9bK3xlaJTyEb538E6hUqBN7E7xTbD2ib3g/640?wx_fmt=png&from=appmsg "null")  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfaO8cEibqiaf4rtpsEGhRB9yicgwx0m4icGM09uLqSTA53hdeaEemicaF1Og/640?wx_fmt=png&from=appmsg "null")  
  
  
成功接收，非 19 开头手机号码接收到验证码。这里后期我也测试过，我怕 18 开头的手机号是我原本的手机号它本来就能接收验证码，所以我拿朋友 的手机号验证了，确实是存在验证码转发，只要第一个数据包的手机号不变，那么修改的手机号就不会变，第二个数据包就是验证码转发的关键。  
# 三、第二个证书站小程序  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf5OCAXetSvNPMUaWzVdcO7wQQ2CdeXoF71DH8ZFtUonA9PjwiaJGyMKw/640?wx_fmt=png&from=appmsg "null")  
  
### （1）账户接管漏洞  
  
分享一个收集教师手机号码的方法  
  
site:edu.cn "微信同号"/“联系电话” filetype:xls/doc/pdf  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfMYZZLqKefqCHcdTjtHL7QzJQLsKUS9Dia0HJ2u6lxD1eibcnJWYfv97w/640?wx_fmt=png&from=appmsg "null")  
  
  
这里我就找到了很多老师的联系电话  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfxe7xdLpRmRcibEWUJicJNiahPQGbNacbFJ0lic6WzaouzlC5UrhHyGnEuQ/640?wx_fmt=png&from=appmsg "null")  
  
  
这里的一键快捷登录不一样，因为它下面标识了，仅支持客户用户内部使用，所以我们是快捷登录不了的，这就是我找教师联系电话的原因。  
  
点击一键快捷登录并抓包  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf1BHNsY9TN2Nny9bzWiclfeZZlTnzKJqJ030t4Vcfld82ek1aMcRA52Q/640?wx_fmt=png&from=appmsg "null")  
  
  
、  
  
获取到这个数据包后，将 mobile 替换成教师手机号  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfn4h2ricAgnmLhyeo6A6B2AUDS0eotyWqegibsjLvrShukL9aumwn4hIw/640?wx_fmt=png&from=appmsg "null")  
  
  
因为我测试过程中登录失败了很多次，所以出现这个数据包的时候我就知道出货了，360 为用户 id 号（这也是后面的一个漏洞做了铺垫）  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfJyPAbso7effsS7fPV2p1SMPQBpBEM8Xh3iaNUZ6x5G8DEckrAxkkuLA/640?wx_fmt=png&from=appmsg "null")  
  
  
直接接管用户。一堆信息泄露。  
### （2）越权漏洞 1  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfqPEafu8PVibtTj8SnOYn6PD5vvaTSsNC5lgAQXn4246ibXkQRGWH0sOQ/640?wx_fmt=png&from=appmsg "null")  
  
  
点击我的并抓包  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfyNicNhrUNeJ2mviaREKzFYEUnPic5dTLXypxdeVUTr9hXJQxVrBNCVNZg/640?wx_fmt=png&from=appmsg "null")  
  
  
将 360 也就是用户 id 号替换成其他数字即可获得其他账户信息  
  
这里替换成 366  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjffELLHicXrucUveEkkBEj0fY56IqXctujVtPbllw8JvU2DEVicz5heKsg/640?wx_fmt=png&from=appmsg "null")  
  
  
这里信息已经变了，之前是女，现在是男至于其他信息不好露出，见谅见谅。  
### （3）越权漏洞 2  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfic9qtrFbWRicWSdicoE8GHJxm90wE6ibgB5L4R7WR6TguuNDOlAWuFSwaw/640?wx_fmt=png&from=appmsg "null")  
  
  
上传签章处，本来想测试文件上传，但是测完一遍发现无货呀，但柳暗花明又一村  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfsDiaId8mqcqkhZOGOia2bSAyuSu9uhZ1npNrQEQBa6iaIrbjfCO1r92Vw/640?wx_fmt=png&from=appmsg "null")  
  
  
点击预览签章  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjfMl8bHRtVJc03DnC4SPgNUznRdISEtMql2cTHXXjvzPC8ibMH1XetZrg/640?wx_fmt=png&from=appmsg "null")  
  
  
发现也是 36*用户 id 控制的  
  
直接替换即可越权获取他人电子签名  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLIK6uDKZHKobhkqVfOsjf95aO7HkaBBcdHB0JHt0hjmuRgsqic4KI8nibibJwxPFJZ1JoYuQfEibdnA/640?wx_fmt=png&from=appmsg "")  
  
盗用签名的危害也是很大的。  
  
可能会有经济、名誉、法律责任等损失，所以这个漏洞危害也是很大的。  
  
  
   
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CR7oAqnjIIbLZqCxwQtBk833sLbiagicscEic0LSVfOnbianSv11PxzJdcicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CRBgpPoexbIY7eBAnR7sWS1BlBAQX51QhcOOOz06Ct2x1cMD25nA6mJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247513602&idx=1&sn=98045772ff9aebe8792552e32523bf83&chksm=c1764badf601c2bbcc199da519611ac8c36c17e5a0554fe32ab9d9769403a495187058f19f3d&scene=21#wechat_redirect)  
  
 			                  
  
  
**信 安 考 证**  
  
  
  
需要考以下各类安全证书的可以联系我，下方扫码回复  
**考证**  
进交流群，价格优惠、组团更便宜，还送【  
渗透安全团队  
】知识星球**1**  
年！  
<table><tbody><tr style="outline: 0px;"><td data-colwidth="557" width="557" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;"><p style="outline: 0px;"><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;"><span leaf="">CISP、PTE、PTS、DSG、IRE、IRS、</span></span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;"><span leaf="">NISP、</span></span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;"><span leaf="">PMP、CCSK、CISSP、ISO27001...</span></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**教程如下图**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8C3Gu1libJC0muV1WmOFa3XM3fTyOiaOJYPgCiaHV6gkJJBia6Fjeds9w9pxxyyPNJhbcfK3I1tcGueTg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
**推荐阅读**  
  
  
  
**干货｜史上最全一句话木马**  
  
  
**干货 | CS绕过vultr特征检测修改算法**  
  
  
**实战 | 用中国人写的红队服务器搞一次内网穿透练习**  
  
  
**实战 | 渗透某培训平台经历**  
  
  
**实战 | 一次曲折的钓鱼溯源反制**  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
  
  
  
  
