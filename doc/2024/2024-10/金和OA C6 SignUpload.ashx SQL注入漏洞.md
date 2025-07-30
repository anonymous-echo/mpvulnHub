#  金和OA C6 SignUpload.ashx SQL注入漏洞   
Superhero  Nday Poc   2024-10-08 21:38  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
金和OA协同办公管理系统软件（简称金和OA），本着简单、适用、高效的原则，贴合企事业单位的实际需求，实行通用化、标准化、智能化、人性化的产品设计，充分体现企事业单位规范管理、提高办公效率的核心思想，为用户提供一整套标准的办公自动化解决方案，以帮助企事业单位迅速建立便捷规范的办公环境。  
  
  
**01******  
  
**漏洞概述**  
  
  
金和OA C6 SignUpload.ashx 接口处存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
app="金和网络-金和OA"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJQjxDricJaEhtTzuVUibJv5BdkgPs3E23EwU2qLqO661ATdlRHJrcUWmjdJBwbf7LtgzxPZw5DQL2g/640?wx_fmt=png&from=appmsg "")  
  
  
  
**03******  
  
**漏洞复现**  
  
延时5秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJQjxDricJaEhtTzuVUibJv5ByiahibZk2zAYwcEibUBiabRh7uFxHFj5Pkfnk4Gz3I6ibozqmjs1XAa7mXg/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJQjxDricJaEhtTzuVUibJv5BBDkxHicyRqdUlQDu3MGlbuSp6wCVncZ3skHx93VzzBldgWVsmXN24aw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJQjxDricJaEhtTzuVUibJv5BfxAGic7XVkkhRwIEeYGB0eXhAsliark0qjxGaW9UdooGMk2Zc1NqJ3Gw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJQjxDricJaEhtTzuVUibJv5BL8l9NIs3fjaqZK3nq0RbfrObFc2b5uwyJE7DP5GJ9y71cBTlUkv3qQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJQjxDricJaEhtTzuVUibJv5BJSSzzNcyMeib2AziaSSyFrI17AVt866ibbTXtymuaLL1mOSca7UbDlQFw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、使用预编译  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保证每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
