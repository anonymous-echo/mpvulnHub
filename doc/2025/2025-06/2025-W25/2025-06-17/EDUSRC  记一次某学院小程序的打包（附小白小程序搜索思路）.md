> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247519617&idx=2&sn=1483881110233d318e2992b31c8bacef

#  EDUSRC | 记一次某学院小程序的打包（附小白小程序搜索思路）  
 渗透安全团队   2025-06-17 09:33  
  
****  
**本文涉及的相关漏洞均已修复，文章中敏感信息均已做打码处理哦！**  
  
作为一个挖洞两月半的小白，众所周知挖 WEB 还是太吃操作了，有没有简单的上分挖洞方式呢，有点兄弟有的，那肯定是微信小程序吖  
  
这里分享一下自己的小程序搜索思路吧：  
1. 1. 首先肯定是微信搜索框，量大从优，但是毕竟只要是带校名的都能搜，你能找到别人也能找到  
  
1. 2. 然后就是官方的 ICP 备案查询，这个有个优点就是能查到一些并不带校名的小程序，这样别人就不能直接在微信搜索框搜到，找一些偏远资产，也就是说小程序的事业单位确实是某学校，但是该小程序的名称里没有该大学名字（这也是从其他师傅那里学来的）  
  
附上地址：  
  
https://beian.miit.gov.cn/#/Integrated/recordQuery  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUl9vBOW5TpNOUQegsldU93mw7ic6sATlCy6JB4LQ2OCQbWD9lXBG0S9Q/640?wx_fmt=png&from=appmsg "null")  
  
  
3.还有发现小蓝本也可以，也能查找学校，详细页里面的新媒体也能看到该学校的各种公众号服务号包括小程序，虽然量也很多，但是存在里面有一些老站点或者小程序已经关站的情况哦  
  
附上地址：  
  
https://sou.xiaolanben.com/pc  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORU5svUSMpibblZicpgIkxAph28uF5rfDptlqT83hVKzHibPnA2oUSbTcUtA/640?wx_fmt=png&from=appmsg "null")  
  
  
接下来就是小白实战辣，其实算运气好，没啥操作捏（给佬磕头）  
  
首先通过 ICP 备案查询找到的某学院服务大厅  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUG8H5I12Xot5LOOXSuIKUJ1uFic2kibBK0kAzxnOnDCkxV3gNBic1s7n2Q/640?wx_fmt=png&from=appmsg "null")  
  
  
一．任意学生用户登录（勉强算是嘿嘿）  
  
发现可直接选择学号姓名登录，只要是该校学生都可以登录  
  
——这里小思路，关于找学校的姓名学号，其实可以直接问 AI，我一般是直接问小爱同学（很方便），都会帮你直接在网上收集然后返回噢，但是注意别直接问姓名学号，我一般都换个方式问，比如搜某个学校获奖学号等，因为学号也算是敏感信息，直接问学生姓名学号不会给你说的。如果实在没有，直接抖音小红书搜学生卡，没有办法辣！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORU7r3HgLn9KmgibZRuPTf7yI9ywvqE0qxjzk6H5Vjia8BySII6lk4tibmiag/640?wx_fmt=png&from=appmsg "null")  
  
  
此处用姓名学号成功登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUV37PpVELRssMTM6PdWzHZ1AwhqTVXbdibOZ8EJeXIuTfJFu0ZrATTmA/640?wx_fmt=png&from=appmsg "null")  
  
  
二．信息泄露（点击就送）  
  
点击办事大厅——学生学籍变更申请表，包括其他几个审核功能点，注意burp历史都泄露了审核老师的敏感信息（包括姓名，身份证号，电话，邮箱）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUDZ7MCLj4RN2D5HqLQc5aG8uBfojBuLoIAosuYdOc9rqX69VPlVAO9g/640?wx_fmt=png&from=appmsg "null")  
  
  
继续点击添加审核人  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUojLxDPuZGab1RCcjwg1ee4xGR2S9TeicIeiagOo7qEudbQjoW4zhQFrQ/640?wx_fmt=png&from=appmsg "null")  
  
  
输入任意数字直接暴露大量人员敏感信息（一看就没有鉴权），此处只输入2（平时看到带参数的可以试试数字/null/放空等）  
  
按理可直接暴露全校人员敏感信息并进行登录，这里估计限制了返回长度  
  
然后也可以重放修改name参数，也可将IdentityId改为1，换个数字又是另一批泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUnWbIoBI4hfckAgG77OabzCAxeiaWS9ZbblqDlIicjTyQk7gM3unbLzibg/640?wx_fmt=png&from=appmsg "null")  
  
  
三. 管理审核人员任意登录  
  
因为前面功能点泄露了党委书记的工号和姓名和电话  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUSfh1jMFr8HSJichj8WRjEHo33gwClLgx6VZkIJ7YianibmFYeRKz8WsNQ/640?wx_fmt=png&from=appmsg "null")  
  
  
退出小程序，开启拦截重新进入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUUpiaGIccanWLbz06rZZOuG9qBzxK1G3IkJONOba3icZynMdclnbzhzCw/640?wx_fmt=png&from=appmsg "null")  
  
  
此参数直接修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUYT877ibvfD1A4Fz5OxG9Eta3iaQh3A8ibvFEnEpjHrJGDq9jx7tkTwe9A/640?wx_fmt=png&from=appmsg "null")  
  
  
放行请求包，关闭拦截，成功登录党委书记账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUHTxWk0V4gZFs5QOx5XFFIibJowafp7z2kkFO7DmWvMbNj03Xv56eibEw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUMKen23lUf36aS3pxiauGyiaNuUxJjUESG5OEiajfKiaQWPjpPWYmeiafXYg/640?wx_fmt=png&from=appmsg "null")  
  
  
同理根据泄露信息重新登录其他管理人员的账号（全校都可）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUr0afCCY7yrLkKRJzhOVuW2eCdq4m0qxVwGwywicdusZYh3EFzUP4kTg/640?wx_fmt=png&from=appmsg "null")  
  
  
最后感谢师傅们赏脸！  
  
   
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
****  
  
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
  
  
  
  
