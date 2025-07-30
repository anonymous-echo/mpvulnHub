#  漏洞预警 用友 UFIDA NC portal/pt/office/checkekey 接口存在 SQL 注入漏洞   
2025-2-18更新  南风漏洞复现文库   2025-02-18 22:12  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 用友 UFIDA NC 简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友网络是全球领先的企业与公共组织软件、云服务、金融服务提供商。提供营销、制造、财务、人力等产品与服务，帮助客户实现发展目标，进而推动商业和社会进步。  
## 2.漏洞描述  
  
用友 UFIDA NC 是用友推出的大型企业数字化平台。用友 UFIDA NC portal/pt/office/checkekey 接口存在 SQL 注入漏洞，攻击者可利用该漏洞获取数据库控制权。  
  
CVE 编号:  
  
CNNVD 编号:  
  
CNVD 编号:  
## 3.影响版本  
  
用友 UFIDA NC  
  
![用友UFIDA NC portal/pt/office/checkekey接口存在SQL注入漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3Y9YEXsib2qUtiaeicdhicuxurQPwUrsRMmcMFAvOR59HIFjmNjiaxKSkpTnFQ47HAOL8leFmKmdVbDzoQ/640?wx_fmt=png&from=appmsg "null")  
  
用友UFIDA NC portal/pt/office/checkekey接口存在SQL注入漏洞  
## 4.fofa 查询语句  
  
app="用友-UFIDA-NC"  
## 5.漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y9YEXsib2qUtiaeicdhicuxurQS8eicHAj0STticicZUlUbDd46MuKaxAHniaW3GS8WyFc4x5LpP1tWIojUA/640?wx_fmt=jpeg&from=appmsg "null")  
  
可以跑 sqlmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3Y9YEXsib2qUtiaeicdhicuxurQKueIhJKJag7hQCPNKiasSSMOtq5JEsFyBkpZvAOvnvsviaMiay9uibJcPw/640?wx_fmt=png&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描 POC 及 POC 工具箱已经上传知识星球：南风网络安全  
1: 更新 poc 批量扫描软件，承诺，一周更新 8-14 个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费 fofa 查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y9YEXsib2qUtiaeicdhicuxurQZYwPx2jr5qCTXiaMN937QRSm1qBtk8UBVCmYwbu8FvyCIKXm0ianNIjw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y9YEXsib2qUtiaeicdhicuxurQlSrcjsu2jmMvN1ic02A2y0FbXQQ55xAicMS0MJmdTiaWxGmKmawvfWjNg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y9YEXsib2qUtiaeicdhicuxurQDOqsTntCY0k9eVo74qh4ObyHAOSicZuGnbXfdKCYJicpjbMbIQvSkQ2w/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y9YEXsib2qUtiaeicdhicuxurQtPDX52X26kbkGeJFeKkowQjBcV13mbmWt2VL7ohbicGkHxMIdaUbIFg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Y9YEXsib2qUtiaeicdhicuxurQGn3ITemQiaDbnWJrFGPMvxVyQmVsmhIB0GFL8yNweHd9VYBBaUHtElg/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修复方案，请关注厂商主页更新： https://www.yonyou.com/  
## 8.往期回顾  
  
  
  
