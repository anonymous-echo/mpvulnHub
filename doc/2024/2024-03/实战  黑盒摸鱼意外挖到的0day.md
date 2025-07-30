#  实战 | 黑盒摸鱼意外挖到的0day   
 渗透安全团队   2024-03-26 23:05  
  
前言  
## ## 一、前言 本文所涉及的漏洞已提交至CNVD并归档，涉及站点的漏洞已经修复，敏感信息已全部打码。## 二、漏洞挖掘过程 随手摸鱼，开局fofa搜一波系统管理然后海选，相中了这个xx系统管理中...  
  
本文所涉及的漏洞已提交至CNVD并归档，涉及站点的漏洞已经修复，敏感信息已全部打码。  
## 二、漏洞挖掘过程  
  
随手摸鱼，开局fofa海选，相中了这个xx中心。![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09ppqM7eM9MHcj2zkbIFbAPUcNuBateiajeBhr8um3KgRXknFRib38qy8jA/640?wx_fmt=png&from=appmsg&random=0.10915070705626362 "")  
登录框嘛，老规矩，掏出大字典跑一波弱口令![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pyKo9ibZboWYFmSt7QMXsOMCRE1icPG1qSDAuZpZC1ZDr1BicMxY224szg/640?wx_fmt=png&from=appmsg&random=0.2784647276865877 "")  
emmm，发现密码是加密的，并且加密脚本也没有写在前端，但是没关系，用户名还没加密，本来就是随手摸鱼，输一个最常见的弱口令123456，然后掏出我的用户名大字典（其实众所周知很多时候密码跑不出来改为跑用户名会有大惊喜）。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pI4ZxEdiccIJWqc81DNBibkFH8LywDa4zznYIIickXib4yXCPiaiaPVbT00UA/640?wx_fmt=jpeg&from=appmsg&random=0.3388130711471167 "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09puPqvhZquaqLmaUBw8TKeePLA1Mhiaf6oTBibk1nMgY50icCyibCEia0JBpQ/640?wx_fmt=png&from=appmsg&random=0.0932208328310371 "")  
好家伙，经典test用户，开门红，摸进去看一下，界面长这样![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09peITqdibLemicibItJwbW3ZlbuXTXdqz8FX5lw5jFPZDQ7r0a8cK58InMA/640?wx_fmt=png&from=appmsg&random=0.7324104281692125 "")  
看了一圈没什么太值得注意的地方，于是点了一下信息保存![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pibpIuyMRdO8jq00Cw3oMN0ajic59Een17g3Gn8U921UzrziaTSIfMia88Q/640?wx_fmt=png&from=appmsg&random=0.7641313593997505 "")  
这里挨着测了下sql和xss，嗯，都没有![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pFQHWB4Xc4TXNQJf731bia7heyk3Va6Q4Cr4poZwfK4Eic0FWvYiaqRGYA/640?wx_fmt=jpeg&from=appmsg&random=0.2732253359045491 "")  
回过头来看着这个userId参数，直觉告诉我这里得出一个经典的越权漏洞。先放着，修改了一下loginName和userName两个参数为admin，发现页面没有任何变化，然后修改了一下userId，随手打了个002110，还是没啥变化emmm，反手把这个参数丢进Intruder从 001980遍历到002100，最终发现当userId为002000时，用户可成功越权至admin用户![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pC2cXzqrU17XDlVHq4o86rI8gNvCvcEhJiauP9cEfK7tSnOFmdZD7icgA/640?wx_fmt=png&from=appmsg&random=0.5175783647796628 "")  
测到这里本来准备交洞下播了，又突然想到这个系统怕不是目标单位自己开发的，于是到首页找了下特征fofa一波![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHlKT16icufYiaYw7zMwyY09pY46Sl9Vn2VV4ygTnGKMIyibKibgmQMlqmngy18zxnJfBsrRRIR9V8bmQ/640?wx_fmt=png&from=appmsg&random=0.2721100472181057 "")  
好家伙，281个站点，顺着网去找了下公司，发现这个洞各项要求都符合颁发证书的条件，于是反手提交CNVD并嫖了个证书。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHlKT16icufYiaYw7zMwyY09poKMrciby0hNMYbmXbumewKteibYibCeY1eXXhicqa2IsXDk7z5dxibugxFw/640?wx_fmt=jpeg&from=appmsg&random=0.09353027811627701 "")  
  
## 三、结语  
  
黑盒摸鱼，纯属运气。日常挖洞中遇到什么xx系统、xx管理中心出洞的时候都可以找特征fofa一波试试，涉及大量站点那就赚翻了~  
  
  
声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。**所有渗透都需获取授权**  
！  
```
文章来源: https://forum.butian.net/share/202文章作者：长相安如有侵权请联系我们，我们会进行删除并致歉
```  
  
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
  
  
  
  
