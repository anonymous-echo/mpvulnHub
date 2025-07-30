#  EnGenius路由器usbinteract.cgi接口存在远程命令漏洞 附POC   
2025-4-24更新  南风漏洞复现文库   2025-04-24 15:20  
  
   
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. EnGenius路由器简介  
  
微信公众号搜索：南风漏洞复现文库  
  
该文章 南风漏洞复现文库 公众号首发  
  
EnGenius路由器  
## 2.漏洞描述  
  
EnGenius路由器是EnGenius公司的一款室内无线接入点，存在安全漏洞。远程攻击者利用该漏洞可以通过控制器连接参数执行任意操作系统命令。EnGenius路由器usbinteract.cgi接口存在远程命令漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
EnGenius路由器  
  
![EnGenius路由器usbinteract.cgi接口存在远程命令漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3bbfP5jdUchWkb4vWCGjcdk6g2ficgOzhZicoOdQ6Kt0azIzlWhJAxoqBMV0tO2RVaaEUBnybYHrtpA/640?wx_fmt=png&from=appmsg "null")  
  
EnGenius路由器usbinteract.cgi接口存在远程命令漏洞  
## 4.fofa查询语句  
  
body="/web/images/guest.png"&&body="/web/images/admin.png"  
## 5.漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbfP5jdUchWkb4vWCGjcdkeTibEG04oD5j9HNk1eTPMwFaaJicav4djeWnmYBL9g7HYDDic4WWSfg2Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
  
  
2: 免登录，免费fofa查询。  
  
  
3: 更新其他实用网络安全工具项目。  
  
  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbfP5jdUchWkb4vWCGjcdk2XicfoKwkV8Nw6RDGNgia4JaUxcMvnprAtc9ictggeXKrOpynlibRprPag/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbfP5jdUchWkb4vWCGjcdkwNtPUOptdfszVEyiabxPVhYAwQiawEMhC3Hbr3uHe2gcXuzhQFHicHUqg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbfP5jdUchWkb4vWCGjcdkb31uyibbNiaWfVCkdricQeTH84kU73BQM2cyzVxArvRiaOGvU2FTrkG56w/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbfP5jdUchWkb4vWCGjcdk3y8WS6ibN7bibMpibNibODRxIN5zvvicSsBszjEHmOj68sGDOfyicqic4JmCQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bbfP5jdUchWkb4vWCGjcdkok2RAKm3dhyOM3PF1R3PGSq36n84SrwbCMFiaE2g082nrU7RGrP7kdA/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
   
  
  
  
