#  Windows客户端漏洞挖掘(红队角度)   
 渗透安全团队   2023-12-18 22:56  
  
## 0x01 前言  
##   
  
周五的时候看了key佬的演讲受益良多呀，来水水，写下目前针对Windows客户端类程序的部分挖掘入口吧，然后分享一下随手挖的很简单很简单的案例。  
  
传统客户端  
  
监听类的:  
  
这里说的监听类的，指的就是安装客户端后启动的端口服务，这个思路WEB、设备类的0Click几乎都是这样，Windows客户端这块看具体业务了也可能有，比如历史上某远控软件RCE、某VPN RCE。走的HTTP逆起来还是比较简单的，前阵子搞金融的私有协议的可难玩一些，不过还好最后交差了。  
  
非监听类的  
  
第一种:  
  
虽然这种没有对外监听，但是有命令行或者图形化操作的功能，这种可以针对其程序功能挖掘，思路要打开，用来1Click或者提权等，举个简单的应用，比如某些程序安装之后是以System运行的，此时如果  
存在RCE或加载DLL  
的相关操作都是可以用来本地提权的，  
还有就是有些白签名程序，存在直接  
RCE或加载DLL都  
有绕过如某卫士、某  
擎信任链检测  
的效果。  
  
第二种:  
  
伪协议很多客户端其实都有伪协议，可以分析其功能来决定如何  
利  
用。  
案例的话比如钉钉的这个漏洞POC，通过伪协议可以加载JS配合C  
hromium V8漏洞来达到1 Click RCE的效果  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWljGA2u4ap26OXmEToaa824U1sWyxLWicXcgz45tOjM33hKTkPnpqjDA/640?wx_fmt=png&from=appmsg "")  
  
WEB类客户端：  
  
比较主流的应该是这三个CEF、QtWebEngine、Electron都是基于Chromium引擎可以尝试Chromium漏洞，其中Electron还基于NodeJs，因为NodeJs的特性导致可以轻松RCE，其他两个应该是不行。  
  
所以对于这种第一个是XSS配合NodeJs语法，比如蚁剑与Clash出现过的1 Click RCE都是功能点XSS搭配NodeJs来RCE。  
  
有些情况下NodeIntegration为False不能直接使用NodeJs原生语法RCE，这个时候如果  
ContextIsolation为False(默认就是False)，就可以寻找Preload.js中的自定义API来寻找漏洞点。  
  
参考如下解释。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWUKicUkYqLYzGq4gFPOjz25UNPIhYGoqbCOnerAoXicq7C6Pu78BDe4dg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWrUx0zpved2LrpY3yPzeMF88hyBFClfqW1Gv6pIcFHTg6XpPW4hIcqg/640?wx_fmt=png&from=appmsg "")  
  
第二个还是伪链接，跟传统客户端不同的是，如果找一个可以加载JS的伪链接，就可以配合上面提到的NodeJs特性或者P  
reload  
.js。  
  
这  
次还看到key佬分享了一个使用WKE自定义前端渲染的漏洞案例，首先找到了一个可以加载任意JS的伪链接，然后寻找WkeJSbindFunction来看JS语法与本地函数的绑定情况，围绕这块去找Sink点。  
  
下面来看一下前天随手挖的两个案例吧。  
## 0x02 漏洞分析与利用       
  
第一个：  
  
发现安装某软件被控端之后开启两个服务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWEq9c2mnm1WRE4yxUaIoiayRHs8mibnAibVIrvQq6CgKZUyVY2JbOORHxg/640?wx_fmt=png&from=appmsg "")  
  
OSPLinkProxy服务对应LinkProxy.exe。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczW8Qu8CLR21RKP9lAC7xL0iaeUicrSML4icxhZhtWJ6qJ75ke9ab1glI7uA/640?wx_fmt=png&from=appmsg "")  
  
访问对应对应服务端口33580。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWvGf00VjBvziaISUX8yqf6GwhHAzzLhiaHzh02TicyDlwdgp9z3wJ3VibXA/640?wx_fmt=png&from=appmsg "")  
  
发现一个路由。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWelbONtaQ2mMZhCL4tGBgHQSLbyVjzGtNkSyJQqLHHLNtJ6LGhlghnQ/640?wx_fmt=png&from=appmsg "")  
  
接收名为"param"的参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWREP3crQV5RwxicgV94RRqrElLMhicMdVy4y3XA4hoOmZgGib9UlBvRFnA/640?wx_fmt=png&from=appmsg "")  
  
对接收的参数内容进行了一次默认码表的Base64解密。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWGicWztDia0MaLnoFeqDuqky4cjqicCM7w5iaUywHGnnL5OZaZtFibviceAmQ/640?wx_fmt=png&from=appmsg "")  
  
调用CreateProcessAsUserA传递"OpenLinkProxy.exe ShellExecute"拼接param解密后的内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWqSP6yicSnOGdJfLvSWxFTUy4LEP4y7c2rZMeXonqwCq7QDeZpeQHUGg/640?wx_fmt=png&from=appmsg "")  
  
逆向OpenLinkProxy发现最终调用ShellExecute且可传递执行的文件与参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWDcNf8qStuKv4JJjMoTNqicvrUviaNbT6dHGqSuJdQZjdOu5KMibs3kbtw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWmP9eD9rsfQxb1Z0MmxDwU19HYy4QmwgxXD7csuZH1sOxzziaHkuxlhw/640?wx_fmt=png&from=appmsg "")  
  
测试可以执行。这种也可以单独利用，上面提到过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczW3xOGufHuvmfYB6LMLJoiagFlZZpHuWZiaGvtWl5JpMic6OQStBLfic1icEw/640?wx_fmt=png&from=appmsg "")  
  
IPC调用成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8OCDvYCI13rgYLYxJo5kiczWmt506AdhZNRDZYicVDicgcKXD7icQViaEIAzZYDVichurvILK5W6a9Zf2Gw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8O8PJhoK0sAzYzDlqjwGmnGCwqy3HXic3DXQHIJD2hOia4PKsMquibgFtc7uxiaXG6zjw0qBcWTj8G8Kg/640?wx_fmt=png&from=appmsg "")  
  
第二个：  
  
不过多解释了，很简单LoadLibrary可控，GetProcAddress无参调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8O8PJhoK0sAzYzDlqjwGmnGdp6V6fuOXGvs2ZvbbjFmumaIuZj5JU69yoeF5pBzibZxtEJBoPt0gmQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8O8PJhoK0sAzYzDlqjwGmnGicR8akAAcc3IsyfOWiaeWxuB2aQZn69Ry33mib0RSOgziaZ0Xonicib2ucxg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8O8PJhoK0sAzYzDlqjwGmnG68blL3raTJx6bQILwGSDNTzJrhS3X886FkD0rD9qiaWnia5cj4DPvuCg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8O8PJhoK0sAzYzDlqjwGmnG444N5gibRTBsF4G5zU57xWzxgntkdrDQuicbHplPU5ffsmdLK1rsT79g/640?wx_fmt=png&from=appmsg "")  
  
签名程序且  
高权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8O8PJhoK0sAzYzDlqjwGmnG0k8XO5CqbZ8JmauHUbOEp99d8xGr1ftc2y4BnUSHXP1hHWyWXjz6gQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8O8PJhoK0sAzYzDlqjwGmnGNvgfIJdOA9pcXL1aDGdF89BsyFicc3AEYwGDPNa9PB7LAZt5VClIibPw/640?wx_fmt=png&from=appmsg "")  
## 0x03 小密圈‍‍‍‍‍‍‍‍  
  
  
  
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
  
