#  泛微e-cology 9 x.FileDownloadLocation接口存在SQL注入漏洞 附POC   
2025-2-20更新  南风漏洞复现文库   2025-02-20 11:52  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 泛微e-cology 9 x.简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
泛微e-cology 9 x  
## 2.漏洞描述  
  
泛微e-cology是一款由泛微网络科技开发的协同管理平台，支持人力资源、财务、行政等多功能管理和移动办公。泛微e-cology 9 x.FileDownloadLocation接口存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
泛微e-cology 9 x  
  
![泛微e-cology 9 x.FileDownloadLocation接口存在SQL注入漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3akYtQBxFAWbLZ5rIyoibwLH7VbBDd7A2UYqFRdib86EN1gD6D0GeeSdgnWMLYz9icPYawENElOdoTIw/640?wx_fmt=png&from=appmsg "null")  
  
泛微e-cology 9 x.FileDownloadLocation接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="doCheckPopupBlocked"  
## 5.漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3akYtQBxFAWbLZ5rIyoibwLHUlAXORIrwSeERwu58boG3M0qs7tbQot5uZVVCHibc1kDgQURHdAon9g/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3akYtQBxFAWbLZ5rIyoibwLH9mYLzWcrDjw2icmERpNl2owFNIUM5G0YnBG1Psp589RUJG8rrdJrOMQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3akYtQBxFAWbLZ5rIyoibwLHfMHwF1kzUS5vrX4vibiaqsWGT0iaHPHXR2kAkahO1ibtL6Og5nxE9QjZpg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3akYtQBxFAWbLZ5rIyoibwLHgQfY3qzR70gvPMlTKRDHuFVcSzt9Picjox78ibzZZIFiczh0BATEl4QPQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3akYtQBxFAWbLZ5rIyoibwLHdj09AJyHsPrOtIok13xV5VEmCicubBxpLhibtD6eYRG9aM297Ou6cEJg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3akYtQBxFAWbLZ5rIyoibwLH8japmwG5tSHCPCluk3lunVos69CgLGDooUDyibmicSKNkYhRjTWRLsiag/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
  
