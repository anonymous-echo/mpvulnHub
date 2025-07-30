#  赛诸葛数字化智能中台系统 login SQL注入漏洞   
Superhero  nday POC   2025-02-07 06:09  
  
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
  
  
赛诸葛数字化智能中台系统是一款为企业级客户提供数智化转型升级的 软件产品，旨在帮助企业实现推广、销售到服务、管理全链条的打通，形成一体化闭环式服务。系统以赛诸葛平台为基础，涵盖了CRM(客户关系管理)、SCRM(社会化客户关系管理)、ERP(企业资源计划)、OA(办公自动化)、B1(商业智能)、MES(制造执行系统)等一系列产品。这些产品包含但不限于广告、获客、销售、客户、订单、生产、库存、合同、财务、审批、人事、培训等管理运营工具和技术服务。  
**01******  
  
**漏洞概述**  
  
  
赛诸葛数字化智能中台系统 login 登录接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="static/index/image/login_left.png" || icon_hash="1056416905"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUwrvfibl0dvwSibUUicMc4DmRHkbibsTHMpLMYhYbcGmMyoyib0aloYaibqzg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
查询当前数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUAABDmDls3ZSXDLiazrDu48Gj3uDfx3pu1RZzWcyUBbGc3mgcXXzDnag/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUs3DiaKmp8jACD0T1gPIxKAib1XYXvFibbf9UGabJkC03ILdwzRkiamck4g/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUWcqYB2xpVWAhso1NCa1on3Fezk4dE4ytOZbpVBJOLOHSXzwSsNGibBA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUPqkZeic9sx667yI0zY6pEAGThmLJUIiaMrGTrIrJVibHNZEoEicWjr7Xiag/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLVy5iavYzqKicd9yBDCOpfKUqrPaic4zarCIrtsegMULdspH0GuXnfAbWWOqiaHdT3PhZ9CAicfXWHJQg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新7-10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
