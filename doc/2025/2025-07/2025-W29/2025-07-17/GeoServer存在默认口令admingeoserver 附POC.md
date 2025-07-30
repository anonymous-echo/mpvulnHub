> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMzYzMTE5OA==&mid=2247484350&idx=1&sn=aa3db900309caf2a179befd3484960f2

#  GeoServer存在默认口令admin:geoserver 附POC  
南风徐来  南风网络安全   2025-07-16 10:14  
  
   
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. GeoServer简介  
  
微信公众号搜索：南风漏洞复现文库  
该文章 南风漏洞复现文库 公众号首发  
  
GeoServer  
## 2.漏洞描述  
  
GeoServer存在默认口令admin:geoserver  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
GeoServer  
  
![GeoServer存在默认口令admin:geoserver](https://mmbiz.qpic.cn/sz_mmbiz_png/iaqvSyvCKQTvdXuHXr2OPI77kweQ5YseMHYKCiblGXJfT3SaWOcnQtFXBduB8YcseLcBYnia7icUgvupMico7Kkvoeg/640?wx_fmt=png&from=appmsg "null")  
  
GeoServer存在默认口令admin:geoserver  
## 4.fofa查询语句  
  
app="GeoServer"  
## 5.漏洞复现  
  
GeoServer存在默认口令admin:geoserver  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaqvSyvCKQTvdXuHXr2OPI77kweQ5YseMM6LTPpsiaCiaXicV1vAf933dUa32edWvhic58ABBicqArIib7WwHuKFMH3UA/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaqvSyvCKQTvdXuHXr2OPI77kweQ5YseMUiasOu5aVaEUwictzj3uDVvnq7cAiahp5vvaL1jgUjNRvE7ib8KWmkDGCw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaqvSyvCKQTvdXuHXr2OPI77kweQ5YseMXXmGZRHc5BadGmLwM4S3d3lwNJSIy1PxG4F3V7vicGp9VW5Wu2rPExw/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
修改为强口令，账号密码八位数以上，包括大小写字母，数字，特殊字符。  
## 8.往期回顾  
  
默认口令项目长期维护，会陆续添加各种系统地默认口令，已添加项目如下：  
  
1、litemall存在默认口令 账号admin123 密码admin123  
2、Apache APISIX API网关存在默认口令 账号admin 密码admin  
3、nps内网穿透服务器 默认口令 账号admin 密码123  
4、  
GeoServer存在默认口令admin:geoserver   
  
   
  
  
