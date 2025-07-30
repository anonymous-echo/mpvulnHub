#  泛微移动管理平台E-mobile error接口存在远程命令执行漏洞 附POC   
2025-4-22更新  南风漏洞复现文库   2025-04-22 14:54  
  
   
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 泛微移动管理平台简介  
  
微信公众号搜索：南风漏洞复现文库  
该文章 南风漏洞复现文库 公众号首发  
  
泛微e-mobile,由高端OA泛微专业研发,是业内领先的移动OA系统,提供移动审批,移动考勤,移动报表,企业微信等丰富办公应用,支持多种平台运行,灵活易用安全性高。  
## 2.漏洞描述  
  
泛微e-mobile遵循以客户为中心，以企业中的事务为导向的出发点，帮助企业构建以员工为核心的移动统一办公平台。e-mobile可满足企业日常管理中的绝大部分管理需求， 诸如市场销售、项目、采购、研发、客服、财务、人事、行政等；同时e-mobile可帮助企业实现面向不同用户量身定制的移动办公入口，包括企业员工、供应商、代理商、 合作伙伴、投资费以及终端客户等整个供应链条上的关系主体，满足为企业全方位的移动办公需求。泛微移动管理平台E-mobile error接口存在远程命令执行漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
移动管理平台  
![泛微移动管理平台E-mobile error接口存在远程命令执行漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YobkyIltDaR4wUw92QoVqMMS1Dbj1cRa6X8sKiapk4UBTLZZbuicMialNsJBYpAagOw2ykWDrsdnPyw/640?wx_fmt=png&from=appmsg "null")  
  
泛微移动管理平台E-mobile error接口存在远程命令执行漏洞  
## 4.fofa查询语句  
  
title="移动管理平台-企业管理"  
## 5.漏洞复现  
  
漏洞数据包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YobkyIltDaR4wUw92QoVqMPOciaKhdXYqaV5CDag4D6lfMlhJTSO1OznwyoCImaNuhichibYw4DgsiaA/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YobkyIltDaR4wUw92QoVqMyrxm0S4WFia1gGFIVsic3H7Ux3mIbiaAhY21TXFoOefjzIunlHZ5zkvpw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YobkyIltDaR4wUw92QoVqMePHKJQNWdtS41Sb0RyxtzHPhUVTPBYiaNNoj5mOdGPgicPLwiaDNIhmVw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YobkyIltDaR4wUw92QoVqM7tCVqZz5JKM30zUUw3nfdicsXCHMeRzqa6l9a3gTnUAp8wVWfiazBnUg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YobkyIltDaR4wUw92QoVqMmiaOrBl05udWFxJiac8SlbXicvW0WZg2Mj31ib98bBOXl8VWbkGl5YBiatw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YobkyIltDaR4wUw92QoVqMm5BF9ibVw7uyLwlDUCmN2b2cQS0g0Fib35MJMkIFu9jOuOoIzBSn2o5g/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
   
  
  
  
