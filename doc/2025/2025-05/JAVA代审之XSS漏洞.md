#  JAVA代审之XSS漏洞   
T3Ysec  T3Ysec   2025-05-05 15:06  
  
一般来说，  
XSS 的危害性没有 SQL 注入的大，  
但是一次有效的 XSS 攻击可以做很多  
事情，  
比如获取 Cookie、  
获取用户的联系人列表、  
截屏、  
劫持等。  
根据服务器后端代码  
的不同，  
XSS 的种类也不相同，  
一般可以分为反射型、  
存储型以及和反射型相近的 DOM  
型。  
漏洞危害有：  
窃取 Cookie，  
键盘记录，  
截屏，  
网页挂马，  
命令执行。  
  
### XSS 常见触发位置  
  
  
1．JSP 表达式  
  
“<%=变量 %>”是“<% out.  
println(变量);  
 %>”的简写方式，  
“<%=%>”用于将已声  
明的变量或表达式输出到外网页中。  
  
下面两种形式的写法实现的效果是相同的，  
都是将变量输出到网页中。  
  
形式一：  
  
```
<%=msg%>
<% out.println(msg); %>

```  
  
  
形式二：  
  
```
<% String msg = request.getParameter('msg');%>
<%=msg%>

```  
  
  
2．EL  
  
EL（Expression Language，  
表达式语言）是为了使 JSP 写起来更加简单。  
EL 的灵感  
来自于 ECMAScript 和 XPath 表达式语言，  
它提供了在 JSP 中简化表达式的方法，  
使得 JSP  
的 代 码 更 加 简 化 。  
 例 如 ：  
“ <%=request.  
getParameter("username")%> ”等价于  
“${param.  
username}”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X2dze5v2iauLzoLaG9fXCLCR60hVIKDTD8o7ACLoKibEvytCriaAMKJfOcwj5iaZO5ELMw9nZZc1WdQtvibhdjicg7qA/640?wx_fmt=png&from=appmsg "")  
  
1）  
out>标签  
out>标签用来显示一个表达式的结果，  
与<%= %>作用相似，  
它们的区别是，  
  
out>标签可以直接通过“.  
”操作符来访问属性，  
如下：  
  
```
<c:out value="${user.getUsername()}"

```  
  
  
2）  
if>标签  
if>标签用来判断表达式的值，  
如果表达式的值为 true，  
则执行其主体内容：  
  
```
<c:if test="${user.salary > 2000}"
<p>我的工资为： value="${user.salary}"</p>

```  
  
  
3）  
forEach>标签  
forEach>标签的作用是迭代输出标签内部的内容。  
它既可以进行固定次数的迭代  
输出，  
也可以依据集合中对象的个数来决定迭代的次数：  
  
```
<table>
<tr><th>名字</th><th>说明</th><th>图片预览</th></tr>
<c:forEach items="${data}" var="item">
<tr><td>${item.advertName}</td><td>${item.notes}</td><td><img src="${item.defPath}"/></td></tr>
</c:forEach>
</table>
<ul>
<li><a href='?nowPage=${nowPage-1}'>←上一页</a></li>
<c:forEach varStatus="i" begin="1" end="${sumPage}">
<c:choose>
<c:when test="${nowPage==i.count}">
<li class='disabled'>${i.count}</li>
</c:when>
<c:otherwise>
<li class='active'><a href='?nowPage=${i.count}'>${i.count}</a></li>
</c:otherwise>
</c:choose>
</c:forEach>
<li><a href='?nowPage=${nowPage+1}'>下一页→</a></li>
</ul>

```  
  
  
3．ModelAndView 类的使用  
  
ModelAndView 类用来存储处理完成后的结果数据，  
以及显示该数据的视图，  
其前端  
JSP 页面可以使用“${参数}”的方法来获取值：  
  
```
package com.demo.controller; 
import org.springframework.stereotype.Controller; 
import org.springframework.web.bind.annotation.RequestMapping; 
import org.springframework.web.servlet.ModelAndView;

@RequestMapping("mvc") 
@Controller
public class TestRequestMMapping { 
 @RequestMapping(value="/getMessage ") 
 public ModelAndView getMessage(){ 
 ModelAndView modelAndView = new ModelAndView(); 
 modelAndView.setViewName("messgae"); 
 modelAndView.addObject("meggage", "Hello World"); 
 return modelAndView; 
 } 
}

```  
  
  
4．ModelMap 类的使用  
Spring 也提供了 ModelMap 类，  
这是 java.  
util.  
Map 实现的，  
可以根据模型属性的具体  
类型自动生成模型属性的名称：  
  
```
Public String testmethod(String someparam,ModelMap model){ 
 //省略方法处理逻辑
 //将数据放置到 ModelMap 类的 model 对象中，第二个参数可以是任何 Java 类型
 Model.addAttribute("key",someparam); 
 return "success"; 
}

```  
  
  
5．Model 类的使用  
Model 类是一个接口类，  
通过 attribue()添加数据，  
存储的数据域范围是 requestScope：  
  
```
Public String index1(Model model){ 
 Model.addAttribute("result","后台返回"); 
 Return "result"; 
}

```  
  
  
### 常规XSS代码审计  
  
  
```
<%=
${ 
<c:out 
<c:if
<c:forEach 
ModelAndView 
ModelMap 
Model 
request.getParameter 
request.setAttribute 
response.getWriter().print() 
response.getWriter().writer()

```  
  
  
  
### XSS 漏洞修复  
  
  
前面已经讲过导致 XSS 漏洞的主要原因是输入可控并且没有经过过滤便直接输出，  
  
因此防御 XSS 漏洞一般有以下几种方法。  
  
（1）编写全局过滤器实现拦截，  
并在 web.  
xml 进行配置。  
下面将给出一个网上使用较  
多的拦截器样例。  
  
WEB.  
xml  
  
```
<filter>
      <filter-name>loginFilter</filter-name>
      <filter-class>com.ygj.control.XSSFilter</filter-class>
  </filter>
  <filter-mapping>
      <filter-name>XSSFilter</filter-name>
      <url-pattern>*.jsp</url-pattern>
  </filter-mapping>
  <filter-mapping>
      <filter-name>XSSFilter</filter-name>
      <url-pattern>*.do</url-pattern>
  </filter-mapping>

```  
  
  
配置过滤器：  
  
```
public class XSSFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }
    @Override
    public void destroy() {
    }
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws
            IOException, ServletException {
        chain.doFilter(new XSSRequestWrapper((HttpServletRequest) request), response);
    }
}

```  
  
  
实现包装类：  
  
```
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
public class XSSRequestWrapper extends HttpServletRequestWrapper {
    public XSSRequestWrapper(HttpServletRequest servletRequest) {
        super(servletRequest);
    }
    @Override
    public String[] getParameterValues(String parameter) {
        String[] values = super.getParameterValues(parameter);
        if (values == null) {
            return null;
        }
        int count = values.length;
        String[] encodedValues = new String[count];
        for (int i = 0; i < count; i++) {
            encodedValues[i] = stripXSS(values[i]);
        }
        return encodedValues;
    }
    @Override
    public String getParameter(String parameter) {
        String value = super.getParameter(parameter);
        return stripXSS(value);
    }
    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
        return stripXSS(value);
    }
    private String stripXSS(String value) {
        if (value != null) {
            // NOTE: It's highly recommended to use the ESAPI library and uncomment the followingline to 
            // avoid encoded attacks. 
            // value = ESAPI.encoder().canonicalize(value); 
            // Avoid null characters 
            value = value.replaceAll("", "");
            // Avoid anything between script tags 
            Pattern scriptPattern = Pattern.compile("(.*?)", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");
            // Avoid anything in a src="http://www.yihaomen.com/article/java/..." type of e-xpression 
            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE |
                    Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
            scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE |
                    Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
            // Remove any lonesome tag 
            scriptPattern = Pattern.compile("", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");
            // Remove any lonesome tag 
            scriptPattern = Pattern.compile("", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE |
                    Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
            // Avoid eval(...) e-xpressions 
            scriptPattern = Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE |
                    Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
            // Avoid e-xpression(...) e-xpressions 
            scriptPattern = Pattern.compile("e-xpression\\((.*?)\\)", Pattern.CASE_INSENSITIVE |
                    Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
            // Avoid javascript:... e-xpressions 
            scriptPattern = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");
            // Avoid vbscript:... e-xpressions 
            scriptPattern = Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE);
            value = scriptPattern.matcher(value).replaceAll("");
            // Avoid onload= e-xpressions 
            scriptPattern = Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE |
                    Pattern.MULTILINE | Pattern.DOTALL);
            value = scriptPattern.matcher(value).replaceAll("");
        }
        return value;
    }
}

```  
  
  
（2）采用开源安全控制库（OWASP）企业安全应用程序接口（ESAPI）实现，  
类似的还有谷歌的 xssProtect 等。  
  
```
// HTML Context 
String html = ESAPI.encoder().encodeForHTML("<script>alert('xss')</script>"); 
// HTML Attribute Context 
String htmlAttr = ESAPI.encoder().encodeForHTMLAttribute("<script>alert('xss')</script>"); 
// Javascript Attribute Context 
String jsAttr = ESAPI.encoder().encodeForJavaScript("<script>alert('xss')</script>");

```  
  
  
（3）对所有字符采用 HTML 实体编码。  
  
```
<%
 String Str = "<script>alert('XSS')</script>"; 
 Str = Str.replaceAll("\"","&quot;"); 
 Str = Str.replaceAll("&","&amp;"); 
 Str = Str.replaceAll("\\(","&#40;"); 
 Str = Str.replaceAll("<","&lt;"); 
 Str = Str.replaceAll(">","&gt;"); 
 Str = Str.replaceAll("\'","&#39;"); 
 Str = Str.replaceAll("\\)","&#41;"); 
 out.println(Str); 
%>

```  
  
  
  
参考很多这里就不注明了，因为我觉得这些知识点没什么可以扩展  
  
