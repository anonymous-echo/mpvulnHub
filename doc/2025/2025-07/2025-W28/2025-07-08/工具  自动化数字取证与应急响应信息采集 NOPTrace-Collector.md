> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247519635&idx=1&sn=e9f73654e2b789cda6434a4097d62974

#  工具 | 自动化数字取证与应急响应信息采集 NOPTrace-Collector  
 渗透安全团队   2025-07-08 02:15  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，  
安全性自测  
，  
大家都要把工具当做病毒对待，在虚拟机运行。  
  
  
**0x01 工具介绍**  
  
NOPTrace-Collector 是基于 OpenForensicRules 标准化数字取证与应急响应信息采集规则格式规范开发的采集器。该项目采用 Go 语言开发，具有跨平台兼容性，支持 Windows、Linux 和 macOS 系统。  
  
**0x02 安装与使用**  
  
1. 默认配置加载  
  
直接执行二进制程序会自动加载执行目录同级的 configs 目录下的所有配置文件，包括子目录中的配置文件。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xqg6XmMxibmbsMz8z0kkB6mzb0sQB9hyCLRIJNhPMahyvMdibng0N8f7w/640?wx_fmt=png&from=appmsg "")  
  
注意： 是执行目录同级的 configs 目录，而不是二进制程序所在目录的同级 configs 目录。  
  
2. 指定配置文件夹  
  
使用 -C 参数指定要加载的配置文件夹：  

```
./noptrace-collector -C /path/to/configs
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xgibmyv2XTyOyMBdbHiaYVzvqLFWqdSq7VAMEOqRrkECO9u5d7aCBDm8A/640?wx_fmt=png&from=appmsg "")  
  
3. 指定单个配置文件  
  
使用 -c 参数指定要加载的单一配置文件：  

```
./noptrace-collector -c config.yaml
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xAM0yQgcYNTwD6T3cS88pGvp6Bqz4Pq7haGQ5sro029gN8HyJibvicEIQ/640?wx_fmt=png&from=appmsg "")  
  
4. 配置文件校验  
  
校验配置文件夹  
  
使用 -V 参数校验某个文件夹中所有配置文件的合法性：  

```
./noptrace-collector -V /path/to/configs
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xFM7OMdW4qbiaCgSWEGCBxnCticzeDPFgnj1zeLQeBdABicb6uSp06pruw/640?wx_fmt=png&from=appmsg "")  
  
校验单个配置文件  
  
使用 -v 参数校验单一配置文件的合法性：  

```
./noptrace-collector -v config.yaml
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xjbtzqe2yVvIJxrdhYicrthS6m8DOvNMTtUAOBFtsicTr5EHlDPh1GdIA/640?wx_fmt=png&from=appmsg "")  
  
5. 输出目录配置  
  
使用 -o 参数指定收集输出的结果目录。如果未指定，默认会在执行目录同级的 ./ForensicCollections 中输出结果。  
  
./noptrace-collector -o /path/to/output  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xmfWjAic3lXxgicE7P8E4qQNW7MzIEIxAicrY8UwPJwL6svoFbCnibqvm1w/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xP7KUZGGdt6XLpiacMLER7xw7xwvNxia5CpG05K05AqAiaP4wq1vAIg1sA/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xBDn0VhfyCcbqYiatVWU4faJc1TgAb3RL0ot3ficqnjicEPTcdw4tvHe5Q/640?wx_fmt=png&from=appmsg "")  
  
6. 结果解析  
  
收集结果保存为单一的 SQLite 数据库文件 ForensicResults.db，便于传输和分析。使用 -p 参数解析收集到的文件：  

```
./noptrace-collector -p ForensicResults.db
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xtdeaasCBSr8M9jLtFJKThTW3kEosWFNCRDJKsrPicW8QokicbSW7CclA/640?wx_fmt=png&from=appmsg "")  
  
工具下载地址：  
  
  
https://github.com/Just-Hack-For-Fun/NOPTrace-Collector  
  
  
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
  
  
