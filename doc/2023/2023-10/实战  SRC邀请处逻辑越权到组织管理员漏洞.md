#  实战 | SRC邀请处逻辑越权到组织管理员漏洞   
 渗透安全团队   2023-10-09 23:53  
  
前言  
  
由于微信公众号推送机制改变了，快来  
**星标**  
不再迷路，谢谢大家！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DungicHdGVdJpoQp8uIUIs13xBa1eTRSObiczwsfbtDvKU0ibAfkHegDGV2o4daf95jVdO9rnFeny7A/640?wx_fmt=png "")  
  
1.在挖掘某src漏洞时候信息收集的时候收集到某小程序 该小程序的主要功能是帮助购买此服务的公司管理项目和销售员工的  
这里我们准备两个测试账号(A和B)  
2.我们登录进去该小程序，按照正常步骤流程注册个公司账户对该小程序进行试用，新建个公司项目后登录进去，点击公司管理，得先去客户项目选项处新建个项目才能进行后续操作![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrQszicYtuatsnO9wfBTk1QA2up9ntU3h8PsiaPmGT0JxYhJkmcPJGILD6Xb18djCicwcdLmr6bTGvkg/640?wx_fmt=png "")  
  
3.新建完项目后 我们返回主页 点击我们 点击邀请成员操作![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrQszicYtuatsnO9wfBTk1QAWeV4ehLWBtxsTgZeHzX0tnIcCuI3SEy41iaLsODI9vI6cVZMgEHwLiaQ/640?wx_fmt=png "")  
  
4.我们选择随意一个低于公司管理员的权限，例如这里  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrQszicYtuatsnO9wfBTk1QA6LPiaVLEWFIAkXxAcCYlHyBiaNjcnTws5FyC7v6RQCk2icprpx0hGFxSQ/640?wx_fmt=png "")  
  
5.邀请一个招聘专员的权限 然后将邀请链接发送到测试账号B![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrQszicYtuatsnO9wfBTk1QAvXgujy8efvcYBuWl1HaCEl7ku4icNFgLDWuYmLNDE7asjukxKyZCFJg/640?wx_fmt=png "")  
  
6.然后切换到另外的测试账号B，点击邀请连接进去，然后点击加入组织的时候进行抓包  
重点来啦！！！这里我们可以看到包中有个role_id参数 这里是对邀请成员进组织时的权限的，因为role_id可控，所有我们是否可以将其改成组织管理员的role_id将其由招聘专员提升成组织管理员权限呢![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrQszicYtuatsnO9wfBTk1QAOc08aXqPnEUR4u3ArktypiaRo0SRhoXmDAYDxl2XJVQkokHuK774GtA/640?wx_fmt=png "")  
  
发包过去 返回success![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrQszicYtuatsnO9wfBTk1QAcb7nia887Azaeh4y0lZxe730zJcbAVOFems7GPvZmKarwiaM7nZs5uxg/640?wx_fmt=png "")  
  
返回A账号 进入该项目 可以看到成功通过邀请链接将低权限的邀请更改为项目管理员权限![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrQszicYtuatsnO9wfBTk1QAfuGscCdnqXpItiaruibXe0ksPdotNfib1Ymm18be440F2g8BH28Q3gVhw/640?wx_fmt=png "")  
  
且通过上面的报文可以看到公司id是可以进行爆破遍历操作的，我们也可以对id进行爆破加入其他人的公司![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrQszicYtuatsnO9wfBTk1QAyQOkaCXaQGDCHzqFjI3ZZU1GeD8icZ2Scdbscb50fqe1VFcNdHAj0Lw/640?wx_fmt=png "")  
  
  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CKksEIzZyEb3tEFGzGYSXfribrG4jKOkRKGKYb7zk7MTNZPT6Wp3bLd2BPhuFHddIL6sqrg1d2qHQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8D0bS8ibc3XhFcDYkVusFvc3c6onthQpPGZn4v32rpOp7CeFiamGdeC7JBk0mGVsiciazLp3z0SIJAtnQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
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
  
