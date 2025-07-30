#  Web实战 | 一次空白页面的“妙手回春”嘎嘎出严重漏洞   
 渗透安全团队   2023-11-27 22:53  
  
**前言**  
  
某次企业SRC的一次实战。其中通过信息收集发现了一个站点，这里为内部系统，访问的时候居然直接一片空白，是空白页面。难道空白页面就没有漏洞吗？我就偏偏不信这个邪，上手就是干！  
  
# 过程  
  
  
https://x,x.com/打开页面啥也没有，一片空白：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBfSQDGjX1I690kSqU4C8eXeibpJlTiadOTkfcS9PS4HszgQVGjUrAIibfA/640?wx_fmt=png&random=0.07213884653641034 "")  
  
其中这里按下键盘中的F12，通过审计js后，发现接口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBLqrSUKKRSgpfynLxodCicZzOtUI3Xicg4RZtn2micHvjEPdHQX8qrNYAA/640?wx_fmt=png&random=0.19557784796515598 "")  
  
其中的一个接口/api/plugin/directory/getLastUsedDirId拼接后，如下提示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBNiaza5zcQDiadoKBakO7nNJp4UmAOI12vnEqMpo0aicDBkjnbURnKiaMpg/640?wx_fmt=png&random=0.09479990235204028 "")  
  
其中响应包中响应的“插件分类不能为空”让我百思不得其解，不知道是缺了什么参数。那么这里就再回到js中看看吧，果然，给我发现了端倪：这里再查看js，发现其中给出提示，原来是header要加如下字段：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBCW9KbPtkuohI3LUjZfoHFDD3wOviaAGtquPV8WVQwJZfpjibRKSnPmicQ/640?wx_fmt=png&random=0.9314731080680552 "")  
  
那么我加了其中一个字段category，发现成功，但是却又报了非法用户登录。那么这里就必须需要Authorization认证字段了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNB7NZU6hgeX8AJ3ibVSicZ0zrVO8PiaKh5Ujxg3HOQ4ot7w9oic8P71gPLTw/640?wx_fmt=png&random=0.40616364115686543 "")  
  
因此这里就又碰到了一个棘手的问题，Authorization认证字段这个一般都是成功登录系统后才会赋予给用户的一个值，而这个地方连页面都是空白的，那么这里到底去哪里寻找Authorization认证字段的值呢？  
  
这里贯彻着遇事不决看js的思想，继续来审计js，终于发现了解决方法：其中在js中发现了login接口。这里存在该逻辑漏洞：id:t.id||"1234",name:t.name||"1234",organizationCode:t.organizationCode||-1。这里用了||或，那么言下之意就是如果不知道id、name和organizationCode的话，就可以直接id参数和name参数都填1234，organizationCode填-1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNB58jiaic8SoP4QoLjhBxJGK7IdzvWWE43NicgPOlLEheLj6DVZmRrXUDRw/640?wx_fmt=png&random=0.021024411978582735 "")  
  
login接口，这里真成功了，其中获取到data  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBdfBIdmibWn9XzrQicSibKricVyvPKzQlZunRd3BCDdAic92Z3V769PAic5cQ/640?wx_fmt=png&random=0.9830275295463213 "")  
  
那么这里猜测data的值即为那个Authorization认证字段的值，这里填入：  
  
发现成功调用接口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBEhcn7DvycGV77KMYsM5Nwics5bNCMflI1sq8LBIBrLsvgBKCcXdLevw/640?wx_fmt=png&random=0.040977472780316715 "")  
  
那么这里其中的接口就都可以成功调用了：  
  
像这里的获取内部数据等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNB8OpFJuRM4f99mlbOP8n9tj6U1KLaGEchlrtibMdZtpEFbyianvuUiaPGw/640?wx_fmt=png&random=0.8817740755062293 "")  
  
这里最关键的一个接口来了：这里通过js审计到查看oss配置信息的接口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBshQmO0pcUvahRYH2lo0xruj5gHJpriaRIHicqLRiaB8BUjTFdDZ3l2ZsQ/640?wx_fmt=png&random=0.8195903571728733 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNB8DfPXgoreHB8UPunia1cE9L0ke2M5Ljrsoc62sFyfjbyVdMmia3jasqA/640?wx_fmt=png&random=0.26489394331895744 "")  
  
这里因为是阿里云的，所以这里直接使用oss browser来进行利用，利用成功：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNB9kSSW8zj00oibFYYdYH9XDibFVTpOuRYfZOwaZ9iaZblInu0vovwtL81A/640?wx_fmt=png&random=0.17588934257201294 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBqpcvJegS3hmIwUJtiadFPOCcgniboFJ8sKEzockPVUX5rE7djx7la1Iw/640?wx_fmt=png&random=0.3377665544993145 "")  
  
这些直接可以下载到后端的源码：  
  
其中反编译出来直接为后端源码，泄露许多严重敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBRPXjEWIPOmzVsmiaAHCC5N5UyhtxRfwlibvsHNVJE9IF3zasjkJicIWpA/640?wx_fmt=png&random=0.6356645644593688 "")  
  
后端的配置信息：  
  
其中还有数据库密码等等敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBMOcqQnuNK9icibwK3raJPcicBDm1iaPvRVicGzc24dnYbkXPeUnd01hGyBg/640?wx_fmt=png&random=0.9952358054188977 "")  
  
反编译出来的后端源码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgGm4mp8ibevLHehEx52DiazNBnlJo6BBvVlHXEWZ9bWLx99BwickjpB5SsIfWg4eSiccqjbWTpk9q1nuQ/640?wx_fmt=png&random=0.48680140119181114 "")  
  
最后的最后，当然也是给了严重的漏洞等级，舒服了！  
```
来源：https://forum.butian.net/share/2510
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
  
