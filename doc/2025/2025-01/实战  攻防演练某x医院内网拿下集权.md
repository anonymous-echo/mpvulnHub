#  实战 | 攻防演练某x医院内网拿下集权   
 渗透安全团队   2025-01-10 03:16  
  
前言  
  
医院还是比较好打的  
  
  
‍  
  
外网打点  
‍  
‍  
‍  
‍  
  
  
  
通过目标某医院资产发现一个协同办公系统，这样登录界面（厚码保命）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXbzAevUewfSSL8NAbiaenr4dd92th7e5kA6hB0ONvSV0smFEgQcfG4tjg/640?wx_fmt=png&from=appmsg "")  
  
  
登录没有验证码，admin变种字典爆破启动，经过很快获得正确密码adminxxx  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXb733x47YBpExjthqruBzZyGBqLpXJoeb8eSichopNeiaClfOSAmGHrYMQ/640?wx_fmt=png&from=appmsg "")  
  
  
然后找到文件上传设置，增加上传后缀  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXbxJFiauuQdgpZrclUZibTgo8FvyicDRPLqLh4y8Iib0uvx7TVrfgLRlrj4Q/640?wx_fmt=png&from=appmsg "")  
  
  
随便找一个上传点，传上去后访问失败，然后换免杀马，直接报500，随后想到ASP站点，最近获取到webshell上线CS，随后修改shell.aspx中的payload.cs代码，上传后访问木马，没有报错，并成功上线CS。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXbX44ryw4VLDvTzhrPrfILzXECBy6pTibptMNQXyxB7nSkGicYOCJQohaA/640?wx_fmt=png&from=appmsg "")  
  
  
低权限用户，不要紧直接上提权插件成功获取system权限。  
  
  
  
  
内网  
‍  
‍  
‍  
‍  
  
  
  
查看本机的网络信息、是否出网（已经确定可以出网）、读取远程登录账户密码、上传frp搭建反代、上传远控关闭杀软  
  
是否开启了远程桌面服务，使用以下命令查看。REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections  
  
0x1表示关闭；0x0表示开启  
  
  
  
  
**踩坑点**  
  
上传gotohttp进行远程连接桌面，上传没有问题，但是远程连接后是黑屏，当时没有解决，也没有在意，后来在群里一个人也遇到这个情况，有个佬给出了解决方法，需要降权，不能用system权限进行启动，连接。  
  
  
获取到内网地址信息，但是密码抓去不到，随后用命令开启Guest用户并加入管理员组。  
  
  
反向代理把流量代理出来，登录  
Guest用户  
成功登录服务器  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXbLZI9K956J6wK6mlNq5cGMmBWBibhZ1DHiawp1KtIQfHttsiaGTnZa3EaQ/640?wx_fmt=png&from=appmsg "")  
  
  
用fscan扫描C段和B段，开启内网遨游  
  
用Windows取证工具znrobber.exe扫描本机信息，获取账号密码组成字典以便后续进行密码喷撒  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXbq6gfWy2icEObm02uzJhrKVicZ6KlH1iakiaVzhUqia4YXPsYlX3JlBHXemA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXb2AofqLkibHkIkCemMExyuxmguviblZtdxH93PJ3T7ictfuQjVodwEQrdg/640?wx_fmt=png&from=appmsg "")  
  
  
  
用netspy探测可到达网段（获取192.168网段）  
  
和网段探测工具  
  
fscan发现大量数据库和服务器弱口令，weblogic-RCE  
  
然后根据扫描的系统进行挨个访问，获取部分系统管理员权限。  
  
弄完之后，发现资产没有达到预期的效果，很是疑惑  
  
后来再慢慢翻网站上传的文件信息，获取到了100.100.x.x地址和大量病例信息，用登录后的服务器成功访问100.100.x.x段  
  
再次用fscan神器扫描  
  
通过收集到的密码和弱口令进行爆破，获取到很多web系统权限  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXbAd1AhodkbtuapyOpzicQhE4al725CqeoKsHKcIoLWobj8spSwY8xJeQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXbrxjSLYTBTqvLsPmmvA5ibdAKNz0jeN68FBcHKc5iavYSXic3fpJuK3f2g/640?wx_fmt=png&from=appmsg "")  
  
  
  
mssql弱口令通过工具执行命令上线CS，也算个刷分技巧吧。  
  
最后在100段发现了心心念念的VMware-VirtualCenter  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXbkODNBR3y3Pqo36mksVI5s4LF3gMicYf8MNxZqu0GyomQNHVCbCS2GicA/640?wx_fmt=png&from=appmsg "")  
  
  
有一整个C段都是VMware-VirtualCenter页面，通过历史漏洞最终只获取了2个webshell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZCtvaaOQSmRsA7rAhZws4KhxBTCQgXbqzHAq7Raps67ewcK0HRkic6eqKaU49GDicaoaedyibhEsmet2icl7UGy6A/640?wx_fmt=png&from=appmsg "")  
  
  
结束.  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
  
  
  
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
  
  
[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247513602&idx=1&sn=98045772ff9aebe8792552e32523bf83&chksm=c1764badf601c2bbcc199da519611ac8c36c17e5a0554fe32ab9d9769403a495187058f19f3d&scene=21#wechat_redirect)  

			                  
  
  
**信 安 考 证**  
  
  
  
需要考以下各类安全证书的可以联系我，下方扫码回复  
**考证**  
进交流群，价格优惠、组团更便宜，还送【  
渗透安全团队  
】知识星球**1**年！  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;"><td width="557" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;"><p style="outline: 0px;"><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;">CISP、PTE、PTS、DSG、IRE、IRS、</span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;">NISP、</span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.51px;">PMP、CCSK、CISSP、ISO27001...</span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**教程如下图**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8C3Gu1libJC0muV1WmOFa3XM3fTyOiaOJYPgCiaHV6gkJJBia6Fjeds9w9pxxyyPNJhbcfK3I1tcGueTg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
