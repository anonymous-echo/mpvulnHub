#  通天星CMSV6车载定位监控平台merge接口存在SQL注入漏洞 附POC   
南风漏洞复现文库  南风漏洞复现文库   2024-06-25 20:02  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 通天星CMSV6车载定位监控平台简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
通天星CMSV6车载主动安全监控云平台  
## 2.漏洞描述  
  
通天星CMSV6车载主动安全监控云平台实现对计算资源、存储资源、网络资源、云应用服务进行7*24小时全时区、多地域、全方位、立体式、智能化的IT运维监控，保障IT系统安全、稳定、可靠运行。通天星CMSV6车载定位监控平台merge接口存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
通天星CMSV6车载主动安全监控云平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKm0XQMGVNX3v8fGR9eWjupYReKJ2T1JDfkuO8pdRoGxklyRrn6MtYqH6TxKjU6yb6FKAUUPTicCg/640?wx_fmt=jpeg&from=appmsg "null")  
  
通天星CMSV6车载定位监控平台merge接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="/808gps/"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/point_manage/merge  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3bKm0XQMGVNX3v8fGR9eWjuNCvpdzZzXQmxEALRD2PicWIZb11hmAFMfJ8eu0ht1Km7wsIYlMmLyyA/640?wx_fmt=png&from=appmsg "")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKm0XQMGVNX3v8fGR9eWjuLflxOJaUwFhpiaTQjrXQ8LImvIDH2y8Hy9cD7e1snYw9Eicb3KSBKxkw/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKm0XQMGVNX3v8fGR9eWjujAsPzZBWNHoOKokRUFWZ7UMmsnXA5s8Bt0oIQGL39h3degEwDRxVtA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKm0XQMGVNX3v8fGR9eWju8LFWaF6FTELQ4K7cesDic10IGb67ibarB9R12z7jsRo58WCT9PiclbNCw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKm0XQMGVNX3v8fGR9eWjuX5hF0OoZkY7BO1fABrwVWZMUrp8JPIibYPicFsgoQpgYtR5Ut3aQ9p7g/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bKm0XQMGVNX3v8fGR9eWjuNghBVNCJkibjkNHv8abdRYsb6SRrCwbE1yawgHe4IfTLRicp7gJJ6EaQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
  
