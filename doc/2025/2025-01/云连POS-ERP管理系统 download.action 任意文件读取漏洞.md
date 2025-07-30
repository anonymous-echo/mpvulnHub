#  云连POS-ERP管理系统 download.action 任意文件读取漏洞   
Superhero  nday POC   2025-01-14 08:09  
  
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
  
  
云连POS-ERP  
管理系统  
作为一种综合的管理  
软件  
，旨在为企业提供全面、  
高效的  
业务管理解决方案。基于云计算技术，集POS收银与ERP管理功能于一体的综合管理系统。它通过网络对企业的各类信息进行集中、统一和实时的管理，帮助企业实现销售、库存、财务等业务的全面数字化管理。系统具有用户友好的操作界面和简单直观的操作流程，使得用户可以快速上手并熟练使用。同时，系统还提供了多种数据导出方式，方便用户实时导出各类报表、销售数据、库存数据等，极大地提高了工作效率。  
**01******  
  
**漏洞概述**  
  
  
云连POS-ERP管理系统 download.action 存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
title="Powered By chaosZ"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIDuJSXAx8m2bQaYc4bYvib3ib3IIHGzia8ZvkzMCg2tlAbpiaXO2qhVp2wjxsyMnhY6BI50X9GlADkBg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIDuJSXAx8m2bQaYc4bYvib3sjNE0Kcia4RqK6icWjJo5Z56icSHQ59cNM4L5KiabuY0gcWicicQR2jFge7Q/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIDuJSXAx8m2bQaYc4bYvib3PCgyoMRHCUoYeRuvVymDCsD9qGx7kzP5cchs7yol9gJpyIuZicyHOAA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIDuJSXAx8m2bQaYc4bYvib3dUCplzSHniccPbEww7wLchkP9luiarOuMplbeRY2bQoaL7zHWUviaFS4A/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIDuJSXAx8m2bQaYc4bYvib3cA82fZRLyllLfliawNvH1IqsfCib2iaOrWNwnHZJ6OzKKANlVYSrXeibSw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
升级至安全版本或打补丁  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
