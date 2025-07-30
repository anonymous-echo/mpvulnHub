#  JeecgBoot passwordChange 任意用户密码重置漏洞   
Superhero  nday POC   2025-01-12 13:39  
  
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
  
  
Jeecg Boot是一个企业级低代码开发平台，基于前后端分离的架构，融合了SpringBootSpringCloud、Ant Design、Vue、Mybatisplus、Shir0、JWT等多种主流技术，旨在帮助企业快速构建各种应用系统，提高开发效率，降低开发成本。采用最新主流的前后分离框架，使得开发更加灵活，易于维护和扩展。而且拥有强大的代码 生成器，可以一键生成前后端代码，极大地提高了开发效率。同时，代码生成器还提供了自定义模板风格的功能，满足不同项目的需求。可以应用在任何J2EE项目的开发中，尤其适合SAAS项目、企业信息管理系统(MIS)、内部办公系统(OA)、企业资源计划系统(ERP)、客户关系管理系统(CRM)等。  
**01******  
  
**漏洞概述**  
  
  
JeecgBoot 框架passwordChange接口存在任意用户密码重置漏洞，未经身份验证的远程攻击者可以利用此漏洞重置管理员账户密码，从而接管系统后台，造成信息泄露，导致系统处于极不安全的状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/sys/common/pdf/pdfPreviewIframe"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI5LbaJSx4tAofwFickFJnpbhKkKjom7Kn6OLMwhkElMiby3tslubjrMK69FMeVOIJiacJGe7JC8ia4ZQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI5LbaJSx4tAofwFickFJnpbtsNufIicfzGuhhy7eSQPSFOcCngmSF0JovTmQ5TFaXf2FZofpj4nMiag/640?wx_fmt=png&from=appmsg "")  
  
PS：有些环境无jeecg-boot目录   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI5LbaJSx4tAofwFickFJnpbnOAesONMpKeaezJJWtWFzmToVwOs2aicib1ebtox5ETibZ4zWyIAYvJdw/640?wx_fmt=png&from=appmsg "")  
  
尝试登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI5LbaJSx4tAofwFickFJnpb1B1AwiaOIr1p6yvWwnknGtATflMv0DQWjJEr5YWHzdZ8DYOcp9cuibTg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI5LbaJSx4tAofwFickFJnpbeCUzTIDGx2liadCTtEicPY94PlMqGgb7tJbTabcVPsSkcKFK8H7tblJg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI5LbaJSx4tAofwFickFJnpbkBbRA74Tfn9mOLia4UnELXqu2JCJxibOpyia1stib5V490Vqs1LdHibia8Ig/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI5LbaJSx4tAofwFickFJnpbO4DNLgibOEqAa6maH1vba8zwxydYjbQFBwzwMV2bRYEB494pnjlytOg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
厂商已尚未提供漏洞修补方案，请关注厂商主页及时更新：  
  
https://www.jeecg.com/  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
