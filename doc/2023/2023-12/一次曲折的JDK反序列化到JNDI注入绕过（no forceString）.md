#  一次曲折的JDK反序列化到JNDI注入绕过（no forceString）   
sha****ock5  Z2O安全攻防   2023-12-02 21:48  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号不为此承担任何责任。  
  
# 文章正文  
  
  
## JDK原生反序列化漏洞发现和绕过的过程  
  
最近的一次渗透项目中，通过nmap扫到一个Jetty的服务。用dirsearch扫到/metrics/路径，但是再后面就扫不出来了。从客户提供的Windows账号RDP登录上去，找到开启这个端口的服务，用Everything找到一个zip安装包，拖回来安装分析。安装的时候注意到有一个设置代理的选项，将其设置为我的burp的地址，等待后续可能的惊喜发生。安装完成之后，对其加入调试参数，然后把依赖jar包导入IDEA待调试。选择一些感兴趣的调试点开始调试。  
### 1、通过设置代理，发现反序列化的endpoint（从客户端）  
  
最开始主要是希望找到/metrics/  
后面到底有啥，于是随便GET、POST请求尝试一下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYJVJyF9rDEEjBcq7iaX8JwTBjWpQpML2rCFWdnCtLFNebt4Pyn3z8BAA/640?wx_fmt=png&from=appmsg "null")  
  
  
请求响应完了之后并没有结束，看到burp里有这样一条记录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bY4CXJagnLwY2FGBX2Bk7mpT3C4mjsGbOrun7WJhCjJl2wPDqpIyichHA/640?wx_fmt=png&from=appmsg "null")  
  
  
通过http请求在网络中进行了序列化对象的传输。  
于是我先是把POST的body直接设置为ysoserial/Urldns.jar（探测gadget）的payload，但是dnslog没有任何反应。我想如果反序列化成功的话，至少应该有一个探测Windows/Linux的记录吧。可见发送的探测payload没有被反序列化成功。  
同时，注意到burp的响应中出现了貌似Exception的stackTrace的样子。  
（不过截图放了一个命令行输错了的情况）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYJaq87asH3PiatztRLjFERd49LkgJGTdZu66tVVu5Xx5NrZnAchCGZQg/640?wx_fmt=png&from=appmsg "null")  
  
在客户端代码中通过设置合适的断点，找到发起HTTP请求的地方，复制，用Java代码构造请求。  
### 2、观察request/response，设置正确的数据格式、输出服务端Exception  
  
由于当时我已经有客户端依赖的jar包，我就在IDEA里搜一下这个返回的响应类：ResponseMessage。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYLtP2LDZIURUn99tpcs1CM9QNxaFY5Wsey7e19Mgz7ePspv5jiczFuoA/640?wx_fmt=png&from=appmsg "null")  
  
发现客户端里有这个类。于是对响应的对象进行readObject还原，然后取出里面的Exception对象，打印stackTrace。  
```
ResponseMessage responseMessage = readResponse(connection.getInputStream());
System.out.println(responseMessage);
responseMessage.getException().printStackTrace();
```  
  
通过分析异常栈知道，对于客户端请求的序列化数据，服务端并不是直接反序列化成对象，而是先读取了一个Integer类型，然后根据这个Integer数值，读取这样大小的后续字节，然后进行反序列化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYtDIpF14uLXy4yfEyXW9JPgoMt8b0731yYPZIsVZib0Zq74kswaYA3pA/640?wx_fmt=png&from=appmsg "null")  
  
  
于是修改之后再发送。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYMbbbgrFxO2fteicp1K13IcFibtYA7P8icgtqU8DibsuUneicLsNptt6librA/640?wx_fmt=png&from=appmsg "null")  
### 3、反序列化gadgets探测  
  
最近正好在学习Jackson + Spring-aop的gadget，索性先用这个试试，还好这次终于成功走入了反序列化利用的流程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bY7m3pjnQFrU5ZdvJP87moqqnL6YGIyJ7DjPhGdoSWQ8otMFsFLDOhJw/640?wx_fmt=png&from=appmsg "null")  
  
  
虽然服务端没有spring-aop依赖。  
  
这里没有使用Urldns.jar进行gadgets探测，由于拿到了客户端的依赖jar，可以先分析一下这里都有什么好东西，也许服务端跟这个差不多。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYROR8miaISCToVdkQppLjic6DLhOVjoW75BicnCic8b0zyJ7TQQDib2VA6vg/640?wx_fmt=png&from=appmsg "null")  
  
  
经过分析，得到这个结果：  
- • jython（没有这个依赖）  
  
- • Commons-Collections（版本是2系列，fixed, 关键的类都不再Serializable）  
  
- • Groovy（版本为2.4.21， fixed）  
  
- • commons-fileupload（版本为1.3.3，fixed）  
  
- • Commons-Beanutils（没有1系列，只有2）  
  
注意到，根据客户端的推测，服务端用的是commons-beanutils2，https://github.com/melloware/commons-beanutils2奇怪之前没见过，github 0 star。不过大概看了一下，关键的gadget依然存在，只是改了一下包名。修改包名，在本地测试，发现是能用的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYRjHFyd7bru3u1eu6ddIjj1udfg2micH6FMU8UgOsn7iakKr1iaVOWTeVQ/640?wx_fmt=png&from=appmsg "null")  
  
  
构造好payload发送给服务端，结果报了这个错：  
```
java.lang.UnsupportedOperationException: When Java security is enabled, support for deserializing TemplatesImpl is disabled. This can be overridden by setting the jdk.xml.enableTemplatesImplDeserialization system property to true.
at java.xml/com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.readObject(TemplatesImpl.java:270)
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bY9iaImX7KWEjzpLyTDcU0IEiatJpJ6jmK9ySLfP8picxD1GyHhOBYxSPvQ/640?wx_fmt=png&from=appmsg "null")  
  
当时看到这里只是想怎么覆盖掉这个属性jdk.xml.enableTemplatesImplDeserialization为true，后来才知道其实这里是因为开启了SecurityManager。参考  
这篇文章 尝试了各种绕过都失败了。它的策略比较严格。  
### 4、从反序列化到JNDI注入  
  
分析一下不依赖Commons-Collections的CommonsBeanutils2这个gadget，  
```
java.util.PriorityQueue#readObject
    ...
    java.util.Comparator#compare
        org.apache.commons.beanutils2.BeanComparator#compare
        org.apache.commons.beanutils2.PropertyUtils#getProperty
            ...
            Xxx#getYyy() （条件：Serializable、利用空参数的getter方法）
            com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#getOutputProperties（现有的）
```  
  
这里利用TemplatesImpl的getOutputProperties是用的最广的一个getter了，因为它存在于jdk中，而且能自定义任意类，可以进行各种扩展（内存马等），但是这条路目前被堵了。得换个别的getter。忘记在哪里看到的了，据说各种dataSource里很方便能getConnection()然后使用jdbc url。不过经过探测服务端没有postgresql、mysql、h2等数据库驱动，只有Oracle的。于是放弃了jdbc url这条路。最后找到了oracle.jdbc.rowset.OracleCachedRowSet#getConnection，这个方法可以通过getter方法将反序列化转到JNDI注入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYBPewj6kE5LbCAFkeb5tejrWHKwuibLKIMaIqRib4wnnarZTgKUSD7icCg/640?wx_fmt=png&from=appmsg "null")  
  
从前面的报错已经知道服务端使用了jdk高版本，所以得想如何绕过JNDI注入的限制。绕过限制主要就是两方面：  
- • 1、利用反序列化  
  
- • 2、利用本地javax.naming.spi.ObjectFactory 中的javax.naming.Reference携带payload  
  
不过反序列化就不考虑了，不然也不会转来JNDI注入。ObjectFactory？看看目标环境有什么？首先想到的当然是用著名的Tomcat自带的依赖org.apache.naming.factory.BeanFactory中的Reference的forceString属性。只需要找一个接受单String类型的参数的方法完成RCE即可，对其方法名没有限制。@浅蓝师傅总结了很多（ELProcessor、Groovy等），很富裕不用担心没有。需要担心的是Tomcat版本是否在范围内。因为Tomcat7没有加入这个功能，而Tomcat高版本（9.0.63、8.5.79）移除了这个功能。  
这里讨论了官方商量删除forceString功能，  
这里可以看到9.0.63确实移除了forceString这个功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYSQROJXKQm2pvxu9FfDZYkKSj4mG4QP1V034qo8iaD4Us2vAgCupI2FQ/640?wx_fmt=png&from=appmsg "null")  
  
不死心？本地试试就知道了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYIOg2wN92qSO9eb6pLxDmpicdicqTTvFJHbRzuDBFuhbTmuInczV17otw/640?wx_fmt=png&from=appmsg "null")  
  
  
那服务端版本是多少？  
随便发一个包让服务端报错即可：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYZvY59gIFSiamkQcb2jzl8uVXt4nY39Z7KInbl9YgfpQuINpJ6zMczVA/640?wx_fmt=png&from=appmsg "null")  
  
  
9.0.64，是修复的版本了。  
所以，好走的forceString这条路已经不通了。  
可用的选择：  
- • 1、（反序列化getter）当时是从反序列化的getter转过来的，既然不通，要不试试别的getter方法？  
  
- • 2、 （JNDI注入setter）被堵这条路只是不能用xyz(String payload)这样的方法，但是有没有好的setAbc(String payload)的恶意方法？  
  
### 5、No forceString：反序列化getter/JNDI注入setter?  
  
通过学习《探索JNDI攻击》 from @浅蓝 on 2022北京网络安全大会，知道虽然不能通过forceString来RCE，但是依然存在其他的方法可以进行敏感的操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYN1MqzFxgzO4xPjDWH28xpATooTpXfMO3Eb7TticYPGdoic6TtmD1fuFw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYa1COtJ4sh2Lmp6znMAYIz0b8ouulHGdtkPx528UAhVtvGLxlTQmIWw/640?wx_fmt=png&from=appmsg "null")  
  
在他的ppt里介绍了使用commons-configuration(2)/groovy + tomcat- jdbc.jar实现System.setProperty()的效果。我理解一下，这里的原理是，首先找到一个特殊的ObjectFactory：org.apache.tomcat.jdbc.naming.GenericNamingResourcesFactory(tomcat- jdbc.jar)。与org.apache.naming.factory.BeanFactory(catalina.jar)相比，它支持调用某个类中的所有的方法，包括static的方法，只要以set开头。而org.apache.naming.factory.BeanFactory是根据属性去找对应的setter方法（有abc这个属性，才会去调用setAbc(String value)这个方法）。理解如有错误还请指正。  
  
附org.apache.naming.factory.BeanFactory  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYnNeZwRe8HGlP8jjl4Tgx9BPh6aCtibzM6xlnQJe0vcfkwbPv0eKV0Ig/640?wx_fmt=png&from=appmsg "null")  
  
org.apache.tomcat.jdbc.naming.GenericNamingResourcesFactory：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bY2f7paC22E1U4uzTc19UhleeRgX6t84ZOpGJRJy6ic7ppabHhwknU1Gw/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bY3Mic03A4o9Euof0ZDQGOQzNuouaWlHegzdbib7GyfXSfgr3QYDJPWOvA/640?wx_fmt=png&from=appmsg "null")  
  
而另外一个特殊的类是org.apache.commons.configuration2.SystemConfiguration(commons- configuration2-  
.jar)或者org.apache.commons.configuration.SystemConfiguration(commons- configuration-.jar)。它的setSystemProperties方法可以设置系统属性，也就是  
```
System.setProperty()
```  
  
setSystemProperties方法接收一个String类型的参数，叫做fileName，但是实际上最后它会被构造成一个URL对象，所以可以传入的不仅是一个本地文件，也可以是一个网络请求，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYnEuKxDFfVPqwiasyZ9Z2V3tS28sEjjicXuV7bk4B61D0H4K8LHfY1k5A/640?wx_fmt=png&from=appmsg "null")  
  
  
所以我们可以在自己控制的web服务器上放一个文件，里面的内容是每行一个  
```
key=value
```  
  
想到之前失败的TemplatesImpl，不是因为jdk.xml.enableTemplatesImplDeserialization系统属性的问题吗？这里找到机会了，先把这个属性给改了。满怀欣喜的再发送payload，结果又报了这个错：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYxR6GpibAd8vic8eCADpoibqhmepy5oM11qjXG35qTu8neJVu9NTsSbokg/640?wx_fmt=png&from=appmsg "null")  
  
Well, not so bad. 至少说明设置系统属性的gadget生效了。这个系统属性改了，依然无法利用成功。有没有别的系统属性值得改的呢？  
### 6、应用启动后System.setProperty()能绕过JNDI注入限制吗?  
  
又想到浅蓝师傅在ppt里提到的，可以试试修改这两个作为JNDI注入缓解措施的系统属性：  
```
com.sun.jndi.ldap.object.trustURLCodebase=true
com.sun.jndi.rmi.object.trustURLCodebase=true
```  
  
继续测试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYdV8aozGohRRKsQtg9BetnHeojYJw0528g6fLgc92xAuVJvPKGsj8KQ/640?wx_fmt=png&from=appmsg "null")  
  
修改完之后，发现使用JNDIExploit的/Basic/Command/依然不成功。于是尝试本地搭建环境试试是否真的能成功。  
  
我先用Spring环境（其实就是java-sec-code）试试：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYhespRXP5xAvcFicfYxicM86UW455d7F18ZbUYsXwDrJwabQnUxI68cvQ/640?wx_fmt=png&from=appmsg "null")  
  
  
关键的点就在这个类：com.sun.naming.internal.VersionHelper  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYuGjfAiaibDqSD5aVze4ANu2x68vxR8B1icKgJkfURj5mia8dl13Td8CsOg/640?wx_fmt=png&from=appmsg "null")  
  
  
在loadClass的时候，会判断其private static final的属性TRUST_URL_CODE_BASE  
值，只有为true的时候，才能从远程URL拉取class。而这个值在这个类第一次被加载的时候，就会根据当时的系统属性com.sun.jndi.ldap.object.trustURLCodebase  
而赋值。所以即便后续我们在代码里将系统属性设置为true了，TRUST_URL_CODE_BASE  
也不会再从系统属性中取值了。所以我们的利用不赶趟儿了。  
下图可以看出，spring-boot启动的时候就会加载这个类：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYhespRXP5xAvcFicfYxicM86UW455d7F18ZbUYsXwDrJwabQnUxI68cvQ/640?wx_fmt=png&from=appmsg "null")  
  
开始我以为只是spring-boot会这样，我们的目标环境是tomcat可能不是这样。之后我又在tomcat的环境下测试了一遍。发现使用不进行绕过的JNDI注入利用/Basic/Command/依然失败。还是倒在了这个TRUST_URL_CODE_BASE上。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYAOTmCuiaBg0etLnWgfUt3ykbLiaWuL9QSK3Blj0JyjH2DQJbTu2kYR6Q/640?wx_fmt=png&from=appmsg "null")  
  
  
为了让我们观察到这个属性被赋值的时刻，同样是设置了调试参数为server=y,suspend=y  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYacnCib2ricJZWU72U7giaLTeX5SSucK5wgqR9VlJO3OT6v8WOBako97PA/640?wx_fmt=png&from=appmsg "null")  
  
调用栈为：  
```
<clinit>:67, VersionHelper (com.sun.naming.internal)
<clinit>:87, ResourceManager (com.sun.naming.internal)
init:232, InitialContext (javax.naming)
<init>:184, InitialContext (javax.naming)
createMBeans:99, GlobalResourcesLifecycleListener (org.apache.catalina.mbeans)
lifecycleEvent:82, GlobalResourcesLifecycleListener (org.apache.catalina.mbeans)
fireLifecycleEvent:123, LifecycleBase (org.apache.catalina.util)
setStateInternal:423, LifecycleBase (org.apache.catalina.util)
setState:366, LifecycleBase (org.apache.catalina.util)
startInternal:923, StandardServer (org.apache.catalina.core)
start:183, LifecycleBase (org.apache.catalina.util)
start:772, Catalina (org.apache.catalina.startup)
invoke0:-1, NativeMethodAccessorImpl (jdk.internal.reflect)
invoke:62, NativeMethodAccessorImpl (jdk.internal.reflect)
invoke:43, DelegatingMethodAccessorImpl (jdk.internal.reflect)
invoke:566, Method (java.lang.reflect)
start:345, Bootstrap (org.apache.catalina.startup)
main:476, Bootstrap (org.apache.catalina.startup)
```  
### 7、MemoryUserDatabaseFactory(Tomcat)的XXE/文件写入到RCE  
  
这时候实在没什么思路了，去知识星球里问问大佬们。  
  
星主挺热心的，这里表示感谢。遗憾的是，根据星主提示的org.apache.batik.swing.JSVGCanvas#setURI这个gadget测试发现目标并没有这个依赖。  
  
还是回来继续看@浅蓝的文章。XXE/Tomcat文件写入RCE？(org.apache.catalina.users.MemoryUserDatabaseFactory)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYD7A4aTWAfTpMFZAAHeibdwqmI1MRYl3tLFgoo6zcatY7qg2Vmf3Z2JQ/640?wx_fmt=png&from=appmsg "null")  
  
先理解一下这个XXE的原理，它是后续RCE的前导。其原理是MemoryUserDatabaseFactory设置pathname，后续会转换成URL，然后进行database#open()的时候，从pathname指定的URL中取得xml内容进行解析。可以说是blind SSRF=> blind XXE。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bY7YVulPialeq2DLWPicsiaxwVPaoHFKDr1mh9daHmvmf2Zn3IC4ZKWaINQ/640?wx_fmt=png&from=appmsg "null")  
  
这个factory利用开始看那篇文章的时候扫到过，但是想到目标是Linux，据说还得自己找创建目录的方法先略过了。这下实在没招，再硬着头皮看看这个有没有戏吧。由于RCE需要创建目录，先看看XXE吧，虽然是个blind XXE。兴许能读到一些敏感的文件，帮忙后续的利用？结果，由于blind XXE的局限性，只能读取到/etc/hostname。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYOtt62zgRWaRF2ic98wWvV6E0O0eyQib142L3fftyvzWdYQ9vl04wXqVw/640?wx_fmt=png&from=appmsg "null")  
  
再看看RCE的原理。看这张图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYeicTKnVOGl2STFCh46pa5NbbDpico4OHpkGeJ8j9m81IaHRicBzScrITQ/640?wx_fmt=png&from=appmsg "null")  
  
注意到这里的database.save()。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYN5hP23eauY3GicYLQq7UtlsqrHgKx61yicfjAeGInahONDE1MZFyw7aQ/640?wx_fmt=png&from=appmsg "null")  
  
就是tomcat会根据之前设置的pathname值在System.getProperty("catalina.base")下创建pathname + ".new"这样的文件（不用担心，后续会重命名回来）。  
  
看到这里，疑惑构造File的第二个参数能路径穿越吗？在Windows上测试一下：  
```
private static void test3() {
        File file = new File(System.getProperty("java.io.tmpdir"), "lalala/../../../test_temp_cqq3.txt");
        // File file = new File(System.getProperty("java.io.tmpdir"), "../../../test_temp_cqq2.txt");
        // File file = new File(System.getProperty("java.io.tmpdir"),"test_temp_cqq.txt");
        try {
            FileWriter writer = new FileWriter(file);
            writer.write("Hello, this is a test string.");
            writer.close();
            System.out.println("Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYqYADQdHibkdTmaJ5BISOdwAo40xS2SEMca5icgDoP9qlzv5lDWbrpAUg/640?wx_fmt=png&from=appmsg "null")  
  
  
Windows下确实可以无视这里的lalala，直接跳目录。Linux下没有测试，应该是不能的。  
从pathname这个名字，以及创建pathname + ".new"这样的文件，可以看出tomcat这里的用意也是期待传入的是一个相对路径的文件名。只不过这里由于URL比File更宽泛被abuse了。  
  
需要担心的是，对于http://xxx/yyy 这样的文件名，如果中间路径比如http:不存在，tomcat会自动帮你创建吗？tomcat并不会不帮你创建。你得自己想办法让System.getProperty("catalina.base")路径下有这样一个目录，Tomcat才会给你写入从pathname得到的文件内容。具体的代码在isWritable()方法中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bY4icLREw38dUnDWJ5kzqNldvPic26ePxfWh3yUzqsXib5YPSGLuwcHmb6A/640?wx_fmt=png&from=appmsg "null")  
  
  
后续需要找到在System.getProperty("catalina.base")  
目录下，创建任意目录，比如http:  
的办法。  
看到@浅蓝文章里说的他用的办法是org.h2.store.fs.FileUtils#createDirectory(String)  
，需要配合forceString。但是现在已经不能用forceString了。还是得自己找。  
先看看手里有什么可以用来创建目录的？  
  
手里有  
- • System.setProperty()；  
  
- • 任意public类的public的setAbc(String payload)，可以是static的；  
  
- • 实现Serializable接口类的getXyz()方法，类的属性可以随便设置。  
  
问了一下ChatGPT，创建目录的API至少有：  
- • Files.createDirectory  
  
- • Files.createDirectories（父目录不存在则创建、直到创建完整目录）  
  
- • File.mkdir  
  
- • File.mkdirs（父目录不存在则创建、直到创建完整目录）  
  
最开始还是希望从JDK里找到的，这样可以方便下次使用。尝试创建jdk的codeql数据库，但是碰到一堆问题，先不折腾了。直接grep然后手动确认吧。先找到com.sun.org.apache.xalan.internal.xsltc.compiler.XSLTC，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYmC02VzU9rOuBtTvFlHpov26hWWqGSDBkZTf3AficHq5A7V3HKgvayEA/640?wx_fmt=png&from=appmsg "null")  
  
  
看似有希望，但是它没有空参数的构造器，放弃。  
又找到org.graalvm.compiler.debug.DiagnosticsOutputDirectory，但是它并不是Serializable。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYB6zQXgQ2HU8CBqxHzibdB8nSG3cUn4EewJTnHcKMrCBbJE4bAa853Xg/640?wx_fmt=png&from=appmsg "")  
  
  
算了吧，直接找项目中的代码吧，先能RCE了再说。  
找到了两个，其中一个是通过getOutputStream来创建目录的，就用这个了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYpSzvCGYfZHEJ2iaic1SL2EdZDTiauKdAKr8wlR0uFMcGS7LA8JkrRdvwg/640?wx_fmt=png&from=appmsg "null")  
  
构造序列化payload：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bY51Bb2YAicfLMZg9HTcDppGibZCkCacIAmlC1lwuia9Np3HibfibF8nr8iaBw/640?wx_fmt=png&from=appmsg "null")  
```
Serializable payload8 = XyzFileMkdir1.getObject("/opt/tomcat/aaa/bbb/http:/192.168.176.1:8888/whatever");
```  
  
成功创建这样的目录：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYh9cIt240aOIvk8RIEvOh214JFpEyIQRibsrViaickJiaffbn0j2Fo0q5Qg/640?wx_fmt=png&from=appmsg "null")  
  
然后实现文件写入：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYJkTJR3vIxDllAuYMaQyxcs3piaXstccD7PoZiceDjxs7v6ziaGd84hkibQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYv4n5H2kxEq4KWTn11KYTwRuFmHNcNZHTicYLic8uBhAM2lqG5tRbttFw/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYuYuTjmCbKRGk8Kw9fia7SicDQAgtIRUTCaUrfr99KxDbPrvnPHAKGOaQ/640?wx_fmt=png&from=appmsg "null")  
  
至此，终于实现了RCE。  
## References  
- •   
探索高版本 JDK 下 JNDI 漏洞的利用方法  
  
- •   
探索JNDI攻击  
  
文章来源：https://xz.aliyun.com/t/13127  
  
# 技术交流  
  
  
### 知识星球  
  
  
致力于红蓝对抗，实战攻防，星球不定时更新内外网攻防渗透技巧，以及最新学习研究成果等。常态化更新最新安全动态。专题更新奇技淫巧小Tips及实战案例。  
  
涉及方向包括Web渗透、免杀绕过、内网攻防、代码审计、应急响应、云安全。星球中已发布**510+** 安全  
‍资源，不定时分享未公开或者小范围公开的漏洞，针对网络安全成员的普遍水平，并为星友提供了教程、工具、POC&EXP以及各种学习笔记等等。([点我了解详情](http://mp.weixin.qq.com/s?__biz=Mzg2ODYxMzY3OQ==&mid=2247496923&idx=1&sn=523f413df2d53de64fd48fbb081be790&chksm=ceab1f9bf9dc968da974eec5e34003d8a937884d2732fda7fac190360fd2a1a5290db090d8e9&scene=21#wechat_redirect)  
)  
  
‍  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuYibmMGxmHsJG443MHGHz7bYbJWvjeX6rGWeCZdk8u50xjYfibbCeMR9MEGPIYRiaAuVgY7ktO7vavrA/640?wx_fmt=jpeg "")  
  
  
****  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。**（QQ群可直接扫码添加）**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKubCcJREicLMkEHIMkCDkGbfwqdiaWZUJtQ8ZNbMVFNTh7JyHdg69vRN2tBVbicNBAIWdgPQfjHoDxVmw/640?wx_fmt=png "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“**  
**书籍****" 获取 网络安全相关经典书籍电子版pdf**  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
  
****  
点个【 在看 】，你最好看  
  
  
  
