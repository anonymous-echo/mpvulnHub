#  漏洞分析｜死磕Jenkins漏洞回显与利用效果   
原创 14m3ta7k@  GobySec   2023-06-27 18:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/GGOWG0fficjLTMIjhRPrloPMpJ4nXfwsIjLDB23mjUrGc3G8Qwo770yYCQAnyVhPGKiaSgfVu0HKnfhT4v5hSWcQ/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkWkohOwe2fQaYYu2NBOMgyAclN7bdgF8e1yMicuJ4aOfSqibQtnHHIJbA/640?wx_fmt=png "")  
  
  
G  
o  
b  
y  
社  
区  
第  
   
2  
8  
   
篇  
技  
术  
分  
享  
文  
章  
  
全  
文  
共  
：  
9135  
   
字  
   
   
   
预  
计  
阅  
读  
时  
间  
：  
20  
   
分  
钟  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
  
 **01 背景**  
##   
  
近期我们发起了一个 Goby 漏洞挑战赛的活动，在活动期间收到了大量的反馈信息，延伸出一系列在编写 PoC 漏洞检测与利用中考虑场景不全的问题，我们针对发现的各种场景用市面上常见的工具进行了一些列的对比工作，发现市面上工具在检测原理与利用流程上普遍存在很多同质化的问题，如漏洞的检查中并未全面的考虑实际被检测的环境情况多样性的问题：  
包括漏洞本身无回显、目标靶机不出网、系统兼容性差（win,linux）以及产品版本兼容性不高等问  
题。  
  
**本文以 Jenkins 反序列化漏洞作为优化案例，分享我们的解决漏洞问题的方式。**  
首先，用户反馈了Jenkins 漏洞无法利用的问题。在漏洞分析过程中，发现之前的 EXP 利用中依赖了一个 jar 包，由于 Goby 没有外挂该 jar 包导致漏洞的无法利用。如果我们重新加入这个 jar 包的话，会使 Goby 程序变得臃肿，且这种利用方式没有回显效果，这并不符合 Goby 简洁高效、多版本兼容性、具有直接的回显效果的漏洞标准。因此，我们通过分  
析 CVE-2017-1000353 的相关材料，研究 Jenkins 的回显功能，最终在 Goby 上完成了高版本  
兼容、一键命令执行、反弹 shell 的效果，让漏洞利用变得更加简洁、直观、高效。  
<table><tbody><tr><td width="171" valign="top" style="word-break: break-all;background-color: rgb(187, 187, 187);text-align: center;"><span style="font-size: 15px;">工具/效果<br/></span></td><td width="171" valign="top" style="word-break: break-all;background-color: rgb(187, 187, 187);text-align: center;"><span style="font-size: 15px;">修改前<br/></span></td><td width="171" valign="top" style="word-break: break-all;background-color: rgb(187, 187, 187);text-align: center;"><span style="font-size: 15px;">修改后<br/></span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">执行命令<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">支持<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">支持<br/></span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="letter-spacing: 0.578px;text-wrap: wrap;font-size: 15px;">命令回显</span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">不支持</span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">支持<br/></span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="letter-spacing: 0.578px;text-wrap: wrap;font-size: 15px;">利用过程</span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="letter-spacing: 0.578px;text-wrap: wrap;font-size: 15px;">第三方工具发包</span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">一键命令执行<br/></span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;"><span style="letter-spacing: 0.578px;text-wrap: wrap;">依赖环境</span><br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="letter-spacing: 0.578px;text-wrap: wrap;font-size: 15px;">第三方jar包</span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">无需<br/></span></td></tr><tr><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">便捷性<br/></span></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;text-align: center;"><span style="letter-spacing: 0.578px;text-wrap: wrap;font-size: 15px;">操作简单</span></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">操作简单<br/></span></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
  
   
**02****漏洞分析**  
  
Jenkins cli 序列化代码执行漏洞（CVE-2017-1000353）是在 cli 接口中出现的，当服务端在处理   
download  
请求时，会调用   
download()  
方法，并等待一个   
upload   
请求。在收到   
upload  
请求后，将请求内容作为输入流传入到创建的   
Channel   
对象中。在创建   
Channel  
对象时，会同时创建一个子线程来读取序列化对象，读取对象过程中调用了   
readObject(  
)  
   
方法，从而导致反序列化漏洞的出现。  
  
漏洞是出在 cli 接口处理响应信息中出现的，当 http 请求头中的   
Side  
 的值为   
download  
 时，会调用   
server.download(req,rsp);  
 对请求信息进行处理。  
  
‍  
```
private class CliEndpointResponse extends HttpResponseException {
  @Override
  public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException, ServletException {
    try {
      UUID uuid = UUID.fromString(req.getHeader("Session"));
      rsp.setHeader("Hudson-Duplex","");
      FullDuplexHttpChannel server;
      if(req.getHeader("Side").equals("download")) {
        ......
        try {
          server.download(req,rsp);
        } finally {
          duplexChannels.remove(uuid);
        }
      } else {
        duplexChannels.get(uuid).upload(req,rsp);
      }
    } catch (InterruptedException e) {......}
  }
}
```  
  
在类的   
downlod()  
 方法中，首先会挂起等待，用于检测是否成功接收到了   
upload  
 请求，当从   
upload  
 请求中读到了内容后，会创建一个   
Channel  
 对象，在创建    
Channel  
 对象时会将   
upload  
 的请求内容传入进去。  
Channel  
 内部会进行多次   
this  
 调用。  
```
public synchronized void download(StaplerRequest req, StaplerResponse rsp) throws InterruptedException, IOException {
  ......
  try {
      channel = new Channel("HTTP full-duplex channel " + uuid,
      Computer.threadPoolForRemoting, Mode.BINARY, upload, out, null, restricted);
  ......
  } finally {......}
}
```  
  
在   
Channel()  
 的一系列   
this  
 调用后，最终会调用   
transport.setup()  
 方法，  
```
@Deprecated
public Channel(String name, ExecutorService exec, Mode mode, InputStream is, OutputStream os, OutputStream header, boolean restricted) throws IOException {
  this(name,exec,mode,is,os,header,restricted,null);
}
  ......
protected Channel(ChannelBuilder settings, CommandTransport transport) throws IOException {
  ......
  transport.setup(this, new CommandReceiver() {
        public void handle(Command cmd) {
            commandsReceived++;
            lastCommandReceivedAt = System.currentTimeMillis();
            if (logger.isLoggable(Level.FINE))
                logger.fine("Received " + cmd);
            try {
                cmd.execute(Channel.this);
            } catch (Throwable t) {
                logger.log(Level.SEVERE, "Failed to execute command " + cmd + " (channel " + Channel.this.name + ")", t);
                logger.log(Level.SEVERE, "This command is created here", cmd.createdAt);
            }
        }
    ......
    });
    ACTIVE_CHANNELS.put(this,ref());
}
```  
  
在   
setup()   
方法中会通过   
new ReaderThread(receiver).start();  
创建一个子线程。  
```
@Override
public void setup(Channel channel, CommandReceiver receiver) {
    this.channel = channel;
    new ReaderThread(receiver).start();
}
```  
  
线程中会调用   
ClassicCommandTransport   
类的   
read()   
方法。  
```
@Override
public void run() {
    final String name =channel.getName();
    try {
        while(!channel.isInClosed()) {
            Command cmd = null;
            try {
                cmd = read();
            } catch (SocketTimeoutException ex) {
                if (RDR_FAIL_ON_SOCKET_TIMEOUT) {
                    LOGGER.log(Level.SEVERE, "Socket timeout in the Synchronous channel reader."
                            + " The channel will be interrupted, because " + RDR_SOCKET_TIMEOUT_PROPERTY_NAME 
                            + " is set", ex);
                    throw ex;
                }
            }
            ......
        }
    }
}
```  
  
该方法中功能包含一个   
Command   
类的   
readFrom()  
 方法，会对传入的字节流进行   
readObject()  
 操作，从而导致了反序列化代码执行。  
```
public final Command read() throws IOException, ClassNotFoundException {
    try {
        Command cmd = Command.readFrom(channel, ois);
        if (rawIn!=null)
            rawIn.clear();
        return cmd;
    } catch (RuntimeException e) {// see JENKINS-19046
        throw diagnoseStreamCorruption(e);
    } catch (StreamCorruptedException e) {
        throw diagnoseStreamCorruption(e);
    }
}
```  
```
static Command readFrom(Channel channel, ObjectInputStream ois) throws IOException, ClassNotFoundException {
  Channel old = Channel.setCurrent(channel);
  try {
    return (Command)ois.readObject();
  } finally {
    Channel.setCurrent(old);
  }
}
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
  
   
**03**  
****  
**漏洞利用**  
  
在分析完漏洞原因后，我们需要思考如何构造 Payload 利用漏洞。由于 Jenkins 中包含了   
org.apache.commons.collections  
 依赖项目，我们则就可以尝试用 CC 链进行反序列化攻击，但在 Jenkins 的黑名单中禁止了 CC 链的直接反序列化，则就需要找到一条链绕过黑名单的限制。  
### 3.1 序列化黑名单  
  
在漏洞分析章节中提到，  
Channel()  
 方法会经过一系列的 this 调用，该过程中调用了   
ChannelBuilder  
 类的   
negotiate()  
 方法，该方法在 return 时调用了中的   
makeTransport()  
 方法，返回了一个   
ClassicCommandTransport  
 对象，在创建该对象过程中，会创建一个   
ObjectInputStreamEx  
 对象并在传参过程中调用该类的 getClassFilter() 方法，  
getClassFilter()  
 方法返回了一个   
ClassFilter.DEFAULT,ClassFilter.DEFAULT  
 最终会返回了一个定义好的黑名单类列表，其中就包含了 CC 链中的相关类。  
```
private static final String[] DEFAULT_PATTERNS = {
    "^bsh[.].*",
    "^com[.]google[.]inject[.].*",
    "^com[.]mchange[.]v2[.]c3p0[.].*",
    "^com[.]sun[.]jndi[.].*",
    "^com[.]sun[.]corba[.].*",
    "^com[.]sun[.]javafx[.].*",
    "^com[.]sun[.]org[.]apache[.]regex[.]internal[.].*",
    "^java[.]awt[.].*",
    "^java[.]rmi[.].*",
    "^javax[.]management[.].*",
    "^javax[.]naming[.].*",
    "^javax[.]script[.].*",
    "^javax[.]swing[.].*",
    "^org[.]apache[.]commons[.]beanutils[.].*",
    "^org[.]apache[.]commons[.]collections[.]functors[.].*",
    "^org[.]apache[.]myfaces[.].*",
    "^org[.]apache[.]wicket[.].*",
    ".*org[.]apache[.]xalan.*",
    "^org[.]codehaus[.]groovy[.]runtime[.].*",
    "^org[.]hibernate[.].*",
    "^org[.]python[.].*",
    "^org[.]springframework[.](?!(\\p{Alnum}+[.])*\\p{Alnum}*Exception$).*",
    "^sun[.]rmi[.].*",
    "^javax[.]imageio[.].*",
    "^java[.]util[.]ServiceLoader$",
    "^java[.]net[.]URLClassLoader$"
};
```  
  
### 3.2 黑名单绕过  
  
jenkins  
 的黑名单限制了 CC 链利用的相关类，但   
SignedObject  
 类没有在黑名单中，  
SignedObject  
 类在创建对象时可以传入一个序列化类型的对象，并且   
SignedObject  
 类的   
getObject()  
 方法中会对传入的序列化对象进行反序列化操作，即调用   
readObject()  
 方法，这里的   
readObject()  
 方法并没有对限制 CC 类的使用，从而可以传入构造的序列化对象进行反序列化恶意执行代码。因此，需要构造一个调用链去调用   
SignedObject  
 类的   
getObject()  
 方法的利用链，从而绕过 CC 链的黑名单的限制，进行反序列化攻击。  
### 3.3 CC 利用链绕过的流程  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfk96ohU58fOWBJqF6n1lYlg9jFp8O6otAce55YDdWqnfsWFubCvZdNPg/640?wx_fmt=png "")  
  
### 3.4 Payload 分析  
  
在对   
ReferenceMap  
 类进行反序列化时，会默认调用其   
readObject  
 方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkg5yhLwTk4UEbGRlNeRzUwnS8yoiaAggeeMwmj4Yr682YIJ3594maNMg/640?wx_fmt=png "")  
  
doReadObject  
 方法对序列化流进行读取，分别复制给 key 和 value，并调用 put 方法，将其放到一个 map 中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfk8MEnQGvlUsekrQqia0dRKRvicriaiac49cP0ib9ddeALFFNHUPHWWXdUfCQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkwVIz2hbM3L6LZ6O56XanKSJTbsKbuVncOhrljibCL1eHqY5rNvD2E1g/640?wx_fmt=png "")  
  
在 put 方法中，调用了   
isEqualKey  
 方法对传入的两个 key 做比较。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkJibicEZvWphGtOzTibgtTCJWQmdcF9NXNbhx1JE0xpBZMU20Z8brRcx1A/640?wx_fmt=png "")  
  
由于传入的 key 是   
CopyOnWriteArraySet  
 对象因此会调用该对象的   
equals  
 方法  
。![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkkibknRia90XBON1NiaJ8wxE9K68BHibeMfsIcD9CwdOXPFR8v80x1NsjNg/640?wx_fmt=png "")  
  
  
在   
CopyOnWriteArraySet.equals()  
 方法中调用了   
eq()  
 方法判断传入的两个对象是否相等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkibw75K1Gt18wGK9ugPEq0uSXQ6icjFRLUpyFLibTjS7QTfVdPJVvOrjTQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkITDyYZoRicOfkpfoTsuc5LdiaGyQ4icriboh3ic2gk7BBmg1bZmbGGgozzw/640?wx_fmt=png "")  
  
由于在处理   
CopyOnWriteArraySet  
 的   
equals  
 方法中传入的对象是   
CopyOnWriteArraySet  
 包装的   
ConcurrentSkipListSet  
 对象和   
ListOrderedSet  
 对象，因此会调用   
ConcurrentSkipListSet  
 对象的   
equals  
 对象将   
ListOrderedSet  
 对象传入进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkkeJFD41Nv5e06PHcMgFYjbd0qpC99DY10hEDssmf8wicuN1rQmy4gJA/640?wx_fmt=png "")  
  
在 Payload 中，由于将   
ListOrderedSet  
 对象的   
collection  
 替换成了   
JSONArray  
 对象。因此在调用   
containsAll  
 方法中，会调用   
JSONArray  
 类的   
containsAll  
 方法对传入的   
ConcurrentSkipListSet  
 对象进行处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkZG6eGBACLFEiaHYibic65ibKp3ntqq5rLtdiaaBYKz2TnJJgU76NqWEZz0w/640?wx_fmt=png "")  
  
再经过   
JSONArray  
 类内部的方法遍历元素，当传入的元素是一个对象时，则就是将其转换成 JSON 对象并使用   
PropertyUtils.getProperty()  
 方法获取其中的属性值，在获取属性值的过程中通过反射机制调用了该   
SignedObject  
 对象的   
getObject()  
，完成了 CC 链的入口点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfk0mo3taQEcExBKZeiaYVQqBCs536G6caibdPx4fbaxqFuib0A6ibJyz7NBg/640?wx_fmt=png "")  
```
 *   JSONArray.containsAll() ->
 *    JSONArray.containsAll() ->
 *     JSONArray.fromObject() ->
 *      JSONArray._fromCollection() ->
 *       JSONArray.addValue() ->
 *        JSONArray.processValue() ->
 *         JSONArray._processValue() ->
 *          AbstractJSON._processValue() ->
 *           JSONObject.fromObject() ->
 *            JSONObject._fromBean() ->
 *             JSONObject.defaultBeanProcessing() ->
 *              PropertyUtils.getProperty() ->
 *               PropertyUtilsBean.getProperty() ->
 *                PropertyUtilsBean.getNestedProperty() ->
 *                 PropertyUtilsBean.getSimpleProperty() ->
 *                  PropertyUtilsBean.invokeMethod() ->
 *                   SignedObject.getObject() ->
```  
### 3.5 SignedObject 类  
  
在   
SignedObject  
 类的构造方法中传入了一个 Serializable 类型对象，并将其序列化并保存到了   
content  
 属性中，在   
SignedObject  
 的   
getObject()  
 方法中对   
content  
 进行了反序列化操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkelkCB9VbB0odlYVEoAibibUNXPqtQtmPpdnOyVGAyHBFP8HMEzefBbXA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkDNSAzovUYjiaSKMlzptCtOqFBt8Viavb1EJNUfUFk61picRKoaX1pBibAA/640?wx_fmt=png "")  
### 3.6 漏洞修复  
  
官方的修复方式是将   
SingedObejct  
 类加入了黑名单。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkY6XVFSQU9lBfnhfEWZgOIDcicQvwyjhA9AClM6QCiazxpicoImeYOg2SA/640?wx_fmt=png "")  
  
##  04 回显利用  
  
上面我们已经绕过了 CC 链的黑名单限制，这时，我们就需要思考如何进行漏洞的利用效果，市面上的主流工具如 vulhub 给出的利用方式是通过 jar 包生成执行系统命令的序列化对象，但利用过程比较繁琐，无法便捷有效的展示漏洞利用效果。  
  
针对 jenkins 的 http 请求和 servlet 的处理是基于 jetty 服务器实现的，在jetty服务器的回显马   
jetty789Echo.jsp  
(https://github.com/feihong-cs/Java-Rce-Echo/blob/master/Jetty/code/jetty789Echo.jsp)   
中给出了 jetty 的两种回显方式。由于 CVE-2017-1000353 漏洞在利用过程中创建了 channel 的特性，并将漏洞的 download 和 upload 类型的 http 请求传入了进去。这时我们就可以通过反射获取这个 channel 中的http 属性，并通过传入 http 消息头中的某些字段进行读取传入的命令内容将其执行，并将执行结果在写入到响应包中，这样就完成了整个回显过程。  
  
反射获取   
channel  
 对象中的   
underlyingOutput  
 属性。  
```
Field underlyingOutputField = channel.getClass().getDeclaredField("underlyingOutput");
underlyingOutputField.setAccessible(true);
Object underlyingOutput = underlyingOutputField.get(channel);
Object httpConnection;
```  
  
在   
underlyingOutput  
 属性的   
_channel  
 和   
this$0  
 的属性中保存了 http 请求响应的相关信息，通过反射获取   
_channel  
 和   
this$0  
 的属性并赋值给   
httpConnection  
 对象。  
```
try{
  Field _channelField = underlyingOutput.getClass().getDeclaredField("_channel");
  _channelField.setAccessible(true);
  httpConnection = _channelField.get(underlyingOutput);
    }catch (Exception e){
  Field connectionField = underlyingOutput.getClass().getDeclaredField("this$0");
  connectionField.setAccessible(true);
  httpConnection = connectionField.get(underlyingOutput);
}
```  
  
获取到 http 信息后，再通过反射获取请求头中的命令执行 cmd 字段的值，并将其执行，写入到响应中。  
```
Object request = httpConnection.getClass().getMethod("getRequest").invoke(httpConnection);
Object response = httpConnection.getClass().getMethod("getResponse").invoke(httpConnection);
String cmd = (String) request.getClass().getMethod("getHeader", String.class).invoke(request, "cmd");
OutputStream outputStream = (OutputStream)response.getClass().getMethod("getOutputStream").invoke(response);
String result = "\n"+exec(cmd);
outputStream.write(result.getBytes());
outputStream.flush();
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIgSOPO7icKl65OE4C9CYQfkd7gKWkHXK7w5S2WDrfMAcbFs2EA5M26v2a05gu8Vx3C30sbawwxD7A/640?wx_fmt=png "")  
  
这些技术都集成在了 Goby 上，在 Goby 上就可以体验到 CVE-2017-1000353 漏洞一键命令执行、反弹 shell 的功能。  
  
##   
##  05 效果对比  
  
请  
<table><tbody><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;background-color: rgb(187, 187, 187);"><span style="font-size: 15px;">工具/效果<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;background-color: rgb(187, 187, 187);"><span style="font-size: 15px;">Goby<br/></span></td><td width="217" valign="top" style="margin-bottom: 0.5rem;text-align: center;white-space: pre-wrap;font-size: 14px;outline: 0px;color: rgb(34, 34, 34);letter-spacing: 0.544px;background-color: rgb(187, 187, 187);font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: inherit;orphans: 4;"><span style="outline: 0px;font-size: 15px;">CVE-2017-1000353-SNAPSHOT-all.jar</span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">执行命令<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">支持<br/></span></td><td width="237" valign="top" style="word-break: break-all;text-align: center;"><span style="letter-spacing: 0.578px;text-wrap: wrap;font-size: 15px;">支持</span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">命令回显<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="letter-spacing: 0.578px;text-wrap: wrap;font-size: 15px;">支持</span></td><td width="237" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">不<span style="font-size: 15px;letter-spacing: 0.578px;text-wrap: wrap;">支持</span></span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">利用过程<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">一键命令执行<br/></span></td><td width="237" valign="top" style="margin-bottom: 0.5rem;text-align: center;white-space: pre-wrap;font-size: 14px;outline: 0px;color: rgb(34, 34, 34);letter-spacing: 0.544px;background-color: rgb(255, 255, 255);font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: inherit;orphans: 4;word-break: break-all;"><span style="outline: 0px;font-size: 15px;">手工生成序列化数据包，执行脚本发送 payload</span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">依赖环境<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">无需<br/></span></td><td width="237" valign="top" style="margin-bottom: 0.5rem;text-align: center;white-space: pre-wrap;font-size: 14px;outline: 0px;color: rgb(34, 34, 34);letter-spacing: 0.544px;background-color: rgb(255, 255, 255);font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: inherit;orphans: 4;"><span style="outline: 0px;font-size: 15px;">java、python</span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">便携性<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">操作简单<br/></span></td><td width="237" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 15px;">操作繁琐<br/></span></td></tr></tbody></table>  
## 最后感谢 @irelia 师傅的漏洞问题反馈，已奖励红队版15天。我们期待更多师傅真诚反馈产品问题，这对 Goby 的进步至关重要。可加入微信群：公众号发暗号“加群”。  
  
##  06 参考  
  
https://github.com/vulhub/CVE-2017-1000353  
  
https://github.com/r00t4dm/Jenkins-CVE-2017-1000353  
  
https://paper.seebug.org/295/  
  
https://github.com/feihong-cs/Java-Rce-Echo  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png "")  
  
  
**最新****Goby 使用技巧分享**  
**：**  
  
[• ](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247510124&idx=1&sn=de3aef91a47b6472d987c2fb7e6f3f6e&chksm=eb8443ccdcf3cadaa4c0ceb1905e14a9d7f3f01bf44f272bd0821c7359db0a847d8533c7abe2&scene=21#wechat_redirect)  
[su18 | Goby反序列化漏洞打入内存马【利用篇】](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247521997&idx=1&sn=d3c444f95c97f06b1d24240a91bd898d&chksm=eb847d6ddcf3f47b0c50ab4a97b2adbee3241149d9a3ac5a56958e76ac33ede48e0bbd108952&scene=21#wechat_redirect)  
  
  
[• su18 | Goby利用内存马的一些技术细节【技术篇】](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247527264&idx=1&sn=7ccd2536dbe00cc13d655e4b13fe6fa9&chksm=eb8480c0dcf309d6daa2c6b25c73524b8ded42a3e835b510a6113557c630e01f0f8dbc5b3a83&scene=21#wechat_redirect)  
  
  
[• 14m3ta7k | 跨越语言的艺术：Weblogic序列化漏洞与IIOP协议](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247527734&idx=1&sn=93073a73437cfee6dd2c91dce0331a48&chksm=eb848696dcf30f80bd676f6000ec92283893ecce08ec2abe571d0a4d908b0f9046512259b727&scene=21#wechat_redirect)  
  
  
[• 14m3ta7k | Weblogic CVE-2023-21931漏洞挖掘技技巧：后反序列化利用](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247527913&idx=1&sn=f3dce554430b75bc9bd5c1e76dde5587&chksm=eb848649dcf30f5f829b8e51a85390b2581f29b0a164d67fa164609f84c9ddd6f72de2231100&scene=21#wechat_redirect)  
  
  
[• ](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247510124&idx=1&sn=de3aef91a47b6472d987c2fb7e6f3f6e&chksm=eb8443ccdcf3cadaa4c0ceb1905e14a9d7f3f01bf44f272bd0821c7359db0a847d8533c7abe2&scene=21#wechat_redirect)  
[kv2 | 死磕RDP协议，从截图和暴破说起](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247528393&idx=1&sn=74961047a04f95115cb9eab084b1baef&chksm=eb848469dcf30d7fc97318feb7a4c1584dd9ed447d50e679a1a233914f245db1f943c2aa72c5&scene=21#wechat_redirect)  
  
  
  
更  
多  
   
>  
>  
   
   
技  
术  
分  
享  
  
  
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
l  
   
/  
漏  
洞  
分  
析  
   
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
  
  
