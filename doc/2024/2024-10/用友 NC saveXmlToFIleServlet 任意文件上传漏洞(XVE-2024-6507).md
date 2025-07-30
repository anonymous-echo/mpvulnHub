#  用友 NC saveXmlToFIleServlet 任意文件上传漏洞(XVE-2024-6507)   
Superhero  Nday Poc   2024-10-16 20:42  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
用友NC是一款企业级ERP软件。作为一种信息化管理工具，用友NC提供了一系列业务管理模块，包括财务会计、采购管理、销售管理、物料管理、生产计划和人力资源管理等，帮助企业实现数字化转型和高效管理。  
  
  
**01******  
  
**漏洞概述**  
  
  
用友 NC saveXmlToFIleServlet接口处存在任意文件上传漏洞，，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
app="用友-UFIDA-NC"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKlsIMlvTB3IGjtqCmsVia2gAfWVWxunBLrEzGwIUsPgUAqbILxkr52Mo6U4OBmNcUaR8xUNjFS13A/640?wx_fmt=png&from=appmsg "")  
  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKlsIMlvTB3IGjtqCmsVia2gqdWyTh95ZAjWB9xOQ7mWNgFHuPiaSjdvaDWUXhdiccPA69eEU67No6PQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKlsIMlvTB3IGjtqCmsVia2g7ROqm6g9BhiaicMJDgykelxHueVYrCCrfOEpt0d1ChicgDG1riaiaZQPZrA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKlsIMlvTB3IGjtqCmsVia2g2pDMrtib8B5glNOibNnCBys9SOZHa3JD4IgF0aKaiakWic0UXVla74W3yA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKlsIMlvTB3IGjtqCmsVia2g665ydv1Wd5ibDQgzwmLqsiaZzuy6Xc6EYUYAXk45rdSY73sicr4kicIzzw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKlsIMlvTB3IGjtqCmsVia2gv04xaKYzia3TNzejhs0jB4iczJqWyWiaaGX8uAFZQEghAKyLIxSdFLtHw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、打对应补丁，重启服务，各版本补丁获取方式如下：  
  
补丁名称：patch_portal65_saveXmlToFIleServlet文件上传安全漏洞  
  
补丁编码：NCM_NC6.5_000_109902_20240329_GP_676119018  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保证每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
