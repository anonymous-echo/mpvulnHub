#  漏洞图形化GUI一键利用工具（Spring-Core-RCE漏洞）   
zangcc  橘猫学安全   2024-03-27 16:50  
  
0x01 工具介绍  
  
  
springboot core 命令执行漏洞，CVE-2022-22965漏洞利用工具，基于JavaFx开发，图形化操作更简单，提高效率。  
0x02 安装与使用  
  
① 这里我用vulfocus的靶场来进行测试，启动靶场后，输入url，先点击“发送payload”按钮。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0JJXjA8siccyCdcZVhtSKYib7p9CMKjrtwcR2RLOZ63VdkFI5ia1iczaibUQiarbgczJj7FGYpuJM3s5iczgCicKhZmbcw/640?wx_fmt=png&wxfrom=13&tp=wxpic "")  
  
② 点击完发送payload之后，会显示发送paylaod之后的响应包html内容，然后再第二个文本框内就会显示完整的url，📢注意！！这个文本框我设置了不可编辑，使用者是修改不了的，我是怕大家乱改，导致后面的命令执行不成功，所以直接干脆不准修改了，只做显示的输出。如下图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0JJXjA8siccyCdcZVhtSKYib7p9CMKjrtwAxbib8WfdxXGkPlK2iaj1en9iccBcsrFNao8lHcpbqfiaSeojFicoiaNdJKA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
③ 显示完url之后，就可以点击第二个按钮，rce检测了，这里直接就执行whomai，可以把命令执行的结果回显到大的文本框里，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0JJXjA8siccyCdcZVhtSKYib7p9CMKjrtwMw7N1h5rSgR1eFPv3wchrXXSHXPP2U0mKVtQZ58RzcosLxhqTzsTMQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
④ 如果想执行其他命令，就可以在下面的小文本框里执行其他命令，这里直接 ls /tmp,命令执行成功，拿到flag。其他命令也是可以的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0JJXjA8siccyCdcZVhtSKYib7p9CMKjrtwByictME2yHaJwsQ2k0syHeR0lMeYxkvDBvMOxcm7RlnFSFTFRXicuZ5w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
0x03 项目链接下载  
  
  
  
https://github.com/zangcc/CVE-2022-22965-rexbb  
  
如有侵权，请联系删除  
  
**推荐阅读**  
  
[实战|记一次奇妙的文件上传getshell](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495718&idx=1&sn=e25bcb693e5a50988f4a7ccd4552c2e2&chksm=c04d7718f73afe0e282c778af8587446ff48cd88422701126b0b21fa7f5027c3cde89e0c3d6d&scene=21#wechat_redirect)  
  
  
[「 超详细 | 分享 」手把手教你如何进行内网渗透](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495694&idx=1&sn=502c812024302566881bad63e01e98cb&chksm=c04d7730f73afe267fd4ef57fb3c74416b20db0ba8e6b03f0c1fd7785348860ccafc15404f24&scene=21#wechat_redirect)  
  
  
[神兵利器 | siusiu-渗透工具管理套件](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495385&idx=1&sn=4d2d8456c27e058a30b147cb7ed51ab1&chksm=c04d69e7f73ae0f11b382cddddb4a07828524a53c0c2987d572967371470a48ad82ae96e7eb1&scene=21#wechat_redirect)  
  
  
[一款功能全面的XSS扫描器](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495361&idx=1&sn=26077792908952c6279deeb2a19ebe37&chksm=c04d69fff73ae0e9f2e03dd8e347f35d660a7fd3d51b0f5e45c8c64afc90c0ee34c4251f9c80&scene=21#wechat_redirect)  
  
  
[实战 | 一次利用哥斯拉马绕过宝塔waf](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495331&idx=1&sn=94b63a0ec82de62191f0911a39b63b7a&chksm=c04d699df73ae08b946e4cf53ceea1bc7591dad0ce18a7ccffed33aa52adccb18b4b1aa78f4c&scene=21#wechat_redirect)  
  
  
[BurpCrypto: 万能网站密码爆破测试工具](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495253&idx=1&sn=d4c46484a44892ef7235342d2763e6be&chksm=c04d696bf73ae07d0c16cff3317f6eb847df2251a9f2332bbe7de56cb92da53b206cd4100210&scene=21#wechat_redirect)  
  
  
[快速筛选真实IP并整理为C段 -- 棱眼](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495199&idx=1&sn=74c00ba76f4f6726107e2820daf7817a&chksm=c04d6921f73ae037efe92e051ac3978068d29e76b09cf5b0b501452693984f96baa9436457e4&scene=21#wechat_redirect)  
  
  
[自动探测端口顺便爆破工具t14m4t](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495141&idx=1&sn=084e8231c0495e91d1bd841e3f43b61c&chksm=c04d6adbf73ae3cdbb0a4cc754f78228772d6899b94d0ea6bb735b4b5ca03c51e7715b43d0af&scene=21#wechat_redirect)  
  
  
[渗透工具｜无状态子域名爆破工具（1秒扫160万个子域）](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495099&idx=1&sn=385764328aff5ec49acddab380721af0&chksm=c04d6a85f73ae393ffab22021839f5baec3802d495c34fb364cbdd9b7cb0cf642851e9527ba7&scene=21#wechat_redirect)  
  
  
  
**查看更多精彩内容，还请关注**  
**橘猫学安全**  
  
  
**每日坚持学习与分享，觉得文章对你有帮助可在底部给点个“**  
**再看”**  
  
