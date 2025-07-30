#  灵当CRM getMyAmbassador SQL注入漏洞   
Superhero  nday POC   2025-01-21 06:49  
  
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
  
  
灵当CRM是一款专为中小企业打造的智能客户关系管理工具，由上海灵当信息科技有限公司  
开发并运营。广泛应用于金融、教育、医疗、IT服务、房地产等多个行业领域，帮助企业实现客户个性化管理需求，提升企业竞争力。无论是新客户开拓、老客户维护，还是销售过程管理、服务管理等方面，灵当CRM都能提供全面、高效的解决方案。是一款功能全面、用户友好、支持定制化、数据分析  
强大且价格合理的CRM软件，是中小型企业实现销售、服务、财务一体化管理的理想选择。  
**01******  
  
**漏洞概述**  
  
  
灵当CRM getMyAmbassador 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="crmcommon/js/jquery/jquery-1.10.1.min.js" || (body="http://localhost:8088/crm/index.php" && body="ldcrm.base.js")
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLmR7nsX2OpYicoP2nyiaRz6O0tUSNttDWViangic7OJ4S9pzGCXme7kAU5T3SLcbk314PU32FEqichl1Q/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLmR7nsX2OpYicoP2nyiaRz6OObCOGKhc7CLdNKoia3JMmtqwK8cUOf11UFpiaFAxlym96b2UmAGso2DQ/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLmR7nsX2OpYicoP2nyiaRz6OPzEUK3EQ46MT6QWqsZnMTwu9wU35jWZWXic168E3EGatAT1lKf67Ogw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLmR7nsX2OpYicoP2nyiaRz6OOicac4zL7tDMLdq3sJYIibyliciaVmEDDLmTa1sEKTaWTRzicxkRDrUK1lQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLmR7nsX2OpYicoP2nyiaRz6O6NbVkCEuoMJibwBkiaEia30xVbsRBdS2vpK5Lhu5ibggzHaWZs421smElg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLmR7nsX2OpYicoP2nyiaRz6OMyqicluuFHT92zn5iaSkyLTRSysMdqxRBRWLm4KNDANNGduxUcoc8abQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
