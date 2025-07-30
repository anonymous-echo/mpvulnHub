#  漏洞挖掘 | EDU小通用漏洞分享   
 渗透安全团队   2024-03-26 23:05  
  
前言  
  
又是没事干的一天，写一下之前挖的两个通用漏洞。随缘挖，没有技术含量勿喷。  
## 1.信息搜集  
  
首先就是信息搜集，挖edu没账号怎么办呢？sg妹子不行，咱就找能自己注册的站。  
- Hunter：web.title=”XX大学”&&web.body=”注册”  
  
- Fofa：host=”.edu.cn” && body=”注册” && country=”CN”  
  
语句可以自己调整，增加自己想要搜的关键字，比如忘记密码，找回密码等![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgyo8KxL6xIibzNlVA2ic747y6OyV45KtkufF5lW48hYQVJtgyNVx3GYpQ/640?wx_fmt=png&from=appmsg "")  
可以看出还是能搜到不少可以注册的站的，这么多够你测了吧。然后导出资产，批量打开去测呗，这里推荐一个小插件可以批量打开网站。Bulk URL Opener  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgOGVfjfsUxaI6Jc8gbu5J0pmu4D1DBv4Y6u3XYrhl54PDs1zjBQtxnQ/640?wx_fmt=png&from=appmsg "")  
  
直接复制网站url到界面就可以打开了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgAm64K7eCyXdOicosopiahkbxFerFA2yBoKVlSEhXpdBZibFBr4y48JKVA/640?wx_fmt=png&from=appmsg "")  
## 2.漏洞挖掘  
#### A洞  
  
接着就是漏洞挖掘过程，这里找到是某个学校的实验教学的网站，这一看就有注册，然后我们直接注册一个账号进去测试一下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgMJmGiafw6aQJ4NjKOeRNuwMuGSEjicF2A79MmDk5zyPf8WCcCt3q8lbw/640?wx_fmt=png&from=appmsg "")  
  
登陆之后找到个人中心。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgTNtiaJBhbdw4L8WMY8koBHzRC5ppATMwd5PbJr3pU6aYpfuaoibEGibXw/640?wx_fmt=png&from=appmsg "")  
这里抓包可以看到传参很多，有数据交互的地方首先就想到要测sql注入，所有这里就简单用单引号测试了一下，果然还真有报错。比如通讯地址：test后面拼接单双引号，发现存在SQL注入报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgzGjup6mleFLrN0e0oeCtgYaqiaIMk9HfpRxw3TTsIvmrmY7X1bOeGnQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgwpKub4RHSibJohyAhJiaYnnGqJkQzSFA3SkqOmP3p7yAc1O3rWgc4skQ/640?wx_fmt=png&from=appmsg "")  
最后直接放到sqlmap跑出注入点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgEO3xT5sfuBB3NS3vpQrCo9W1NWbcxcTUsYkg5OJJeebh5wiabMxozDw/640?wx_fmt=png&from=appmsg "")  
#### B洞  
  
第二个洞也是机缘巧合之下找到一个未授权的接口。也是找一个可以注册的实验室的站。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgGJibc2ticK0OOsdRsLs8CnqT63bs6u3MdTd1qz4kia8e5gNIYB74zcVDg/640?wx_fmt=png&from=appmsg "")  
  
这里注册进去之后先把功能都点一点，然后找到一个未授权的接口，在burp历史记录里面。访问之后发现是一个重置的界面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqnrqJAmBp9CawibZsc2sEFgZFPVZdKvedkdRnic0ibDicNRqvvVQvPd3OOd2ouOCfNDFdrkgwMFESWdA/640?wx_fmt=png&from=appmsg "")  
完美！！！  
## 总结  
  
这两个通用漏洞，也是通过注册账号后才发现的。可以肯定的是，这些网站有了账号之后才能发现更多的功能点，功能点多了，漏洞就会有了。所以多去找点账号，或者这种能注册的站进去之后再测试。可能会有更多收获。  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
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
  
  

								[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489372&idx=1&sn=5e14ba5fa59059fb1ee405e56ef90d40&chksm=c175eaf3f60263e5ef5415a8a9fc134f0890fdb9c25ab956116d17109baf98b3bd6bed572a2d&scene=21#wechat_redirect)  

			                  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
  
