#  工具 | 漏洞挖掘小工具-SeeMore   
 渗透安全团队   2025-05-26 07:05  
  
介绍  
  
1、在某系统发现在导入文件时，文件内容没有进行过滤导致存储型xss注入，可以发送任何人或提交模板（管理员会审查）危害挺大的，然后提交漏洞后他进行了修复。  
  
2、但是  
程序员只是将导入功能的元素添加"display: none;"隐藏起来了， 但是这个功能还是存在，所以可以通过将"display: none;"删除达到显示导入功能（二次绕过）。  
  
3、这里再提供一思路，在第2次修复后，程序员可能只是将页面对应的代码段删除，但是后端的api仍然存在，可以利用之前的数据包（可能需要修改Cookie） 进行重放攻击。  
  
但是如果每次都要去手动修改不可见元素为可见就太麻烦了，还可能错过一些可利用的功能点，所以就做了这个插件可以显示隐藏的可点击（重点）元素，不会将一些无用的文本弹窗等显示出来造成页面的不美观，下面讲讲这个插件的应用场景以及安装方法。  
  
如果大家在使用过程中遇到了bug或一些没有成功显示的元素，可以提交到issues中，作者会尽快完善匹配规则，感谢大家支持。  
  
使用  
  
  
1、这里以Webgoat靶场为例  
  
![PixPin_2025-03-01_19-58-08](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgFSE34z9hic3a9MXRI1HI2aqibn8yGQjgIPkSjr1oGTMIyhOdY5XRNhbxb6LwDmbB0bPrlsGEicWHm9g/640?wx_fmt=png&from=appmsg "")  
  
2、点击 Show Hidden 即可，显示出隐藏的按钮。点击 recover 即可恢复之前的页面。  
  
![PixPin_2025-03-01_20-00-28](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgFSE34z9hic3a9MXRI1HI2aqBaibq3BDGbmEyxiajVJhlIde9b4pBvxqHdmVTYCXqpibm0ed4WHzOI5Sg/640?wx_fmt=png&from=appmsg "")  
  
3、安装教程，Google 打开 chrome://extensions/ 链接，开启开发者模式，点击"加载以解压的扩展程序"，选择下载解压后的文件夹导入即可。  
  
![PixPin_2025-03-01_20-02-55](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgFSE34z9hic3a9MXRI1HI2aqtSbZ4MwNrb7AzR1BE2Bicc6fia4KvfH1Lch3micgY7M7QmvZ9iaVFibSELA/640?wx_fmt=png&from=appmsg "")  
  
![PixPin_2025-03-01_20-03-24](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgFSE34z9hic3a9MXRI1HI2aqZKeLbtczXQvDb11Ms0eqp7ic8F6TjK6vBIjOqjLhFAH72Je4d24BZEg/640?wx_fmt=png&from=appmsg "")  
  
#### V1.0.1更新  
  
  
1、添加显示通过 <!-- 注释隐藏起来的可点击内容，这个页面存在隐藏的功能框  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgFSE34z9hic3a9MXRI1HI2aqeVPsxUtmicBDzGVNAdaVg2cbibfHaAsBvgyzEIoe9ic67cCVb1ffNmAqA/640?wx_fmt=png&from=appmsg "")  
  
2、点击 Show Hidden 显示功能  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgFSE34z9hic3a9MXRI1HI2aqzDuQ2ecx2uic9zlLV7ejicjg3FpSydNYhmo2l53bljgZiakCK34ARu8FA/640?wx_fmt=png&from=appmsg "")  
  
#### v1.0.2更新  
#### 修复部分bug（注释功能）  
#### 案例补充  
  
  
发现上传功能，可以上传任意后缀但是对于大多数文件不解析，但可以解析html文件  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgFSE34z9hic3a9MXRI1HI2aq1wtkxIP8sbh57zk0QjaYo0Hiadg3r3P3qyK6srAoEF3osMwUTd4NUZQ/640?wx_fmt=png&from=appmsg "")  
  
项目地址  
  
**https://github.com/Bbdolt/SeeMore**  
  
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
  
****  
  
