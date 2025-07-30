#  工具 | Jeecg-Boot综合漏洞利用GUI   
MInggongK  渗透安全团队   2024-07-18 22:21  
  
由于微信公众号推送机制改变了，快来  
**星标**  
不再迷路，谢谢大家！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DungicHdGVdJpoQp8uIUIs13xBa1eTRSObiczwsfbtDvKU0ibAfkHegDGV2o4daf95jVdO9rnFeny7A/640?wx_fmt=png "")  
  
  
**1**►  
  
**工具介绍**  
  
  
Jeecg综合漏洞利用工具集成了多模块漏洞利用，包括一键漏洞检测，单独选择模块检测,cmdshell模块，文件上传模块，批量检测模块等 v3.0版本内置的标准库外，在检测模块加入了okhttp的三方库，支持https网站检测，以及优化了基于jeecg queryUser漏洞的接口测试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEoFkDicJMK2wsccZUMm0VdZyNBibQWec51ZrfI7t2HANlUU5w6lQ8Hfzeg/640?wx_fmt=png&from=appmsg "")  
  
  
一键检测模块，选择模块  
  
jeecg-boot queryFieldBySql远程命令执行漏洞  
  
jeecg-boot testConnection远程命令执行漏洞  
  
JeecgBoot jmreport/loadTableData SSTI模板注入漏洞  
  
jeecg-boot-queryTableData-sqli注入漏洞  
  
jeecg-boot-getDictItemsByTable-sqli注入漏洞  
  
Jeecg-Boot qurestSql-SQL注入漏洞  
  
jeecg-boot commonController 任意文件上传漏洞  
  
jeecg-boot jmreport任意文件上传漏洞  
  
jeecg-boot-querySysUser信息泄露漏洞  
  
jeecg-boot-checkOnlyUser信息泄露漏洞  
  
jeecg-boot-httptrace信息泄露漏洞  
  
  
接口测试模块：  
  
jeecg-boot-querySysUser信息泄露漏洞  
  
jeecg-boot-checkOnlyUser信息泄露漏洞  
  
  
cmdshell模块:  
  
jeecg-boot queryFieldBySql远程命令执行漏洞  
  
jeecg-boot testConnection远程命令执行漏洞  
  
JeecgBoot jmreport/loadTableData SSTI模板注入漏洞  
  
  
文件上传模块:  
  
jeecg-boot commonController 任意文件上传漏洞  
  
jeecg-boot jmreport任意文件上传漏洞  
  
  
批量检测模块：  
  
jeecg-boot queryFieldBySql远程命令执行漏洞  
  
jeecg-boot testConnection远程命令执行漏洞  
  
JeecgBoot jmreport/loadTableData SSTI模板注入漏洞  
  
jeecg-boot-queryTableData-sqli注入漏洞  
  
jeecg-boot-getDictItemsByTable-sqli注入漏洞  
  
Jeecg-Boot qurestSql-SQL注入漏洞  
  
  
  
  
**2**►  
  
**工具使用**  
  
  
**MInggongK**  
  
默认模块可一键扫描所有漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEoFkDicJMK2wsccZUMm0VdZyNBibQWec51ZrfI7t2HANlUU5w6lQ8Hfzeg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEoLj8RACaX3pblMgYluZfibDBtxhzic6WrHrhvgDibNpdEE6516Eo1ez0Dw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEoIbHSibibibn1uDMWOvBxGWC9fQ8licJDd1vrkV1cmgpCTbFH0fV7QRnEYg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEoyIZjtWpH1Pv7ictKSo3xXialBY1DtF5CTIhHZ51UicyOVpVvYw44AObUQ/640?wx_fmt=jpeg&from=appmsg "")  
  
选择模块可单独选择你要检测的漏洞  
  
cmdshel模块  
  
如存在jeecg-boot queryFieldBySql远程命令执行漏洞  
  
选择cmd模块的jeecg-boot queryFieldBySql远程命令执行漏洞  
  
输入你要执行的命令即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEo7PLK6llnbJxwHcEgt8KiaDqdC4SoCcU7NrXpxR5zhb6XwKytXzGI4eg/640?wx_fmt=png&from=appmsg "")  
  
文件上传模块：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEohUgTnZEcV43CLtbdNs6zYgJOib1ic3ibTDXia3On9LUun3cOK7LaZnUYZA/640?wx_fmt=jpeg&from=appmsg "")  
  
如存在jeecg-boot jmreport任意文件上传漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEoHia4KQN3AibEGUUiaedZ51veS5fo698FRbBcyJ7AUEjhnfZyTrdT3eeOQ/640?wx_fmt=png&from=appmsg "")  
  
shell不再内置，支持用户自定义上传，输入你的shell代码，文件名，点击上传即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEoLCBKKPLg8KmW1Frk2CriaO85JRfakwNuibxN4uFiaqqKAoSql9C2jWzAA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEomNeJncW2yHtbxKUtEOp0OEAsVluvz82kSsuP9SlRwUaU8Zg6sLR1Sw/640?wx_fmt=png&from=appmsg "")  
  
批量检测模块：  
  
下载jeecgExploitss jar程序，本地新建文本urls.txt  
  
选择你要检测的模块，点击检测，即可开始批量检测  
  
批量检测，默认只输出存在漏洞的网站  
  
后续根据版本优化再添加其他的批量检测模块  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BRO0nnEic7tZicqM58z3seEotXdw1ibILmkSBdvGscPDZtpRKBnibe0Xbqial3mtxtkUlYB0z6x5ZicI0g/640?wx_fmt=png&from=appmsg "")  
  
**3**►  
  
**工具获取**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
**翻到文章最底部点击“阅读原文”下载链接**  
  
  
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
  
