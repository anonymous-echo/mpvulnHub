#  浙大恩特客户资源管理系统 Quotegask_editAction SQL注入漏洞   
Superhero  Nday Poc   2024-10-20 15:44  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
浙大恩特客户资源管理系统是一款针对企业客户资源管理的软件产品。该系统旨在帮助企业高效地管理和利用客户资源，提升销售和市场  
营销的效果。  
  
  
**01******  
  
**漏洞概述**  
  
  
浙大恩特客户资源管理系统 Quotegask_editAction 接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
body="script/Ent.base.js"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIN0NBVZNPyhZAnra5SoDbdOYejKuibYlwWkMvuaFYPlNEOJXibyQhXZsOsHNZaXwMvicZTJFox8yYZQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
延时5秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIN0NBVZNPyhZAnra5SoDbdFhKVdGwJibF7QdTgaG2DnOOibNmXnKwChOg5Z2uvFCrKWBQx6clrm64g/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIN0NBVZNPyhZAnra5SoDbdQn4x2CpursojDZoHv46TCFesp1icaS6eOb7Yd0hFZCiamNIypupia8Nicg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIN0NBVZNPyhZAnra5SoDbd6CCgPDmazhGXzXqpbwkJLgmPFjJib2xbFM77ibicjS1Th31SC6kiaG4A8Q/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIN0NBVZNPyhZAnra5SoDbdzMxs4OT5rCOzkKw6vrn3R9HXEc1NcUicx2YoSfM2DcnNOibTzAAUH3PA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIN0NBVZNPyhZAnra5SoDbdsbj7O2qvRACnbsLaHE3mxuZ14lCf13urhsVyUalSMicu3APuOLwyTXA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、  
关闭互联网暴露面设置接口访问控制，对用户提交数据信息严格把关，多次筛选过滤  
  
2、 对用户数据内容进行加密，采用SQL语句预编译和绑定变量  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保证每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
