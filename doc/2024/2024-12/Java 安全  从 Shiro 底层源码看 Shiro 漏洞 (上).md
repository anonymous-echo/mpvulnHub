#  Java 安全 | 从 Shiro 底层源码看 Shiro 漏洞 (上)   
原创 Heihu577  Heihu Share   2024-12-02 15:23  
  
## 前言  
> 声明：文中涉及到的技术和工具，仅供学习使用，禁止从事任何非法活动，如因此造成的直接或间接损失，均由使用者自行承担责任。  
  
  
Shiro 的漏洞已爆出很多年, 我们只关心到了它如何触发, 有时并没有想过这个框架是干嘛的, 甚至没有分析过该框架的底层运行逻辑, 那么本篇文章, 让大家从开发者的角度, 来观察 Shiro 漏洞.  
  
从开发者为什么使用 Shiro, 到 Shiro 底层运行逻辑, 再到 Shiro 漏洞原理刨析.  
  
并不会像某些文章一样, 只是把漏洞点点明一下, 用 Payload 打一下, 就说这个漏洞已经“研究明白”了.  
  
本篇文章分为三个部分:  
  
第一部分来介绍 Shiro 的基本使用, 清晰的感受到 Shiro 框架给程序员带来的便捷.  
  
第二部分来介绍 Shiro 底层源码的分析, 感受该框架设计的精妙.  
  
第三部分来介绍 Shiro 漏洞分析, 在这里我们会梳理底层源码分析的流程, 一步一步涉及到漏洞点的产生, 顺便记载一下 Shiro 的攻击姿势.  
  
本篇文章目录如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVMaF4T825k8OVfx4QYica8ZHK5kP28CPToQR7sxfDHjIhCb8UNvLeX1w/640?wx_fmt=png&from=appmsg "")  
  
image-20241019215104183.png  
> 由于文章过长, 笔者将分为两篇进行发布.  
  
## 权限管理  
### 概念  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVkmcSp9wjpPCXZoeSouxOqTtzhpVMw9QOkYJHV33mbhPmsB6cajWib8A/640?wx_fmt=png&from=appmsg "")  
  
image-20241006163451124.png  
  
为了实现不同身份登录系统, 出现的功能模块不一样. 这个需求叫做权限管理.  
- 学生登录后, 出现的功能模块为: 选课, 成绩查询, 课程表  
  
- 老师登陆后, 出现的功能模块为: 学生管理, 成绩录入  
  
那么有了这个基础的概念之后, 我们再看一个比较复杂的权限管理案例:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVE8iaOqKIrXZuHM5T4ibbMZHY8Dx2ODLMOmAictsficZcBHLl2pCZFxqdnA/640?wx_fmt=png&from=appmsg "")  
  
image-20241006165849875.png  
### 具体实现  
#### 第一种方式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVzicSPSDDYU0IqltsVbibdVYn5jzibDpFOybTw6LgIBRjFH8oqu5ZibksVw/640?wx_fmt=png&from=appmsg "")  
  
image-20241006171521654.png  
  
这种方式适用于权限管理比较单一, 用户少, 每类用户权限固定的场景. 根据不同的页面来实现功能不一致的情况.  
  
这种方式的缺点则是, 假设需要在销售人员主页增加新的功能时, 我们需要修改index1.html页面内容, 增加上新的功能, 需要后期慢慢维护.  
  
这种基于页面的开发, 是不建议的.  
#### 第二种方式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVq0KbaT3hncREcoOI6iaWiaBHj2icqlTjZVCOLic6m3m9I4pnNfslB8Wkgw/640?wx_fmt=png&from=appmsg "")  
  
image-20241006192212959.png  
  
这一种设计是RBAC (基于角色的访问控制)的基本原型, 也不是最终版本, 看起来已经实现动态的显示功能效果了. 但是这里会存在一个问题.  
  
假设我们新增了一个Heihu577用户, 那么我们就需要在用户权限表中增加很多权限, 那么假设Heihu577用户所需要的权限与liucheng用户权限一致, 那么用户权限表中又需要给Heihu577用户分配很多权限id, 直到与用户liucheng的权限id是一致的, 这样大大减少了灵活性.  
  
那么这里我们需要引入角色的概念,角色是什么？我们不妨看下图进行理解.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVvPRyzRandkicDNUiaVz46jScXicnhg6y0Ty4BlpvcBkUL8BvVprUanSsA/640?wx_fmt=png&from=appmsg "")  
  
image-20241006194328473.png  
  
现在的权限分配, 是根据角色的, 我们只需要指明某个用户是某个角色, 即可得到该角色的具体权限. 而这么做的弊端则是, 假设A & B用户是同一角色, 而我们希望某一功能只给A用户而不给B用户, 这个时候怎么办呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVDt39PQZicTtlogswOiblISDKQwyLsPMyAwKFwDI7AaCgY42uI2NDeGlw/640?wx_fmt=png&from=appmsg "")  
  
image-20241006202455328.png  
  
我们只需要增加一个用户权限表, 将额外的权限分配给具体用户即可, 当然随着业务逻辑的复杂, 我们的表也跟着复杂化了. 那么除了表结构的设计, 还需要我们程序设计的思想:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVXlibrNhufuZdAHuIjJHMy8HMGAx7FMwDPZv7pC1e6rDhPaPAGsz1nUA/640?wx_fmt=png&from=appmsg "")  
  
image-20241007135554675.png  
  
而这里过滤器/拦截器部分我们也可以自己写流程, 判断当前是否是登录状态, 是否有SESSION等. 当我们考虑不全面时程序也可能出现BUG.  
  
而这种情况我们也可以选择使用安全框架, 帮助我们在应用系统开发过程完成认证以及授权的工作. 而安全框架类似于一个保安的角色:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVl9sxPN2ZaVS3g3rdvQZayz9K9pKsVn3dVxO0hZPhWAib5daSqG5s0oA/640?wx_fmt=png&from=appmsg "")  
  
image-20241007140346688.png  
  
这是一个演唱会的案例, 根据你的门票类别, 到达具体的座位, 当然这一切都需要你去告诉这个保安如何匹配规则, 换到程序里, 我们也仅仅做一个配置即可. 而这里我们就可以选择使用 Shiro, Shiro 就做了这些事情, 类似于 Shiro 的框架还有很多, Spring Security, OAuth2等.  
## Shiro  
  
Shiro 的核心功能如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV9CRiaDeLOl40d34edjmQMtQBibIm5S4V8w5p2acLibTCuGAnL9hQkArng/640?wx_fmt=png&from=appmsg "")  
  
image-20241007141857444.png  
  
Authentication 认证: 验证用户是否有相应的身份 - 登录认证.  
  
Authorization 授权: 对已经通过认证的用户, 检查是否具有某个权限, 或者角色, 从而控制是否能够进行某种操作.  
  
Session Management 会话管理功能: 用户认证成功后创建会话, 在没有退出之前, 当前用户所有信息都保存至当前会话中 (具备 SESSION 功能), 可以在 Java SE 中使用.  
  
Cryptography 密码管理: 对敏感信息进行加密.  
  
支持的特性:  
- Web Support: Shiro 提供了过滤器, 可以通过过滤器拦截 Web 请求来处理 Web 应用的访问控制.  
  
- Caching 缓存支持: Shiro 可以缓存用户信息以及用户的角色权限信息, 可以提高执行效率.  
  
- Concurrency: Shiro 支持多线程应用.  
  
- Testing: 提供测试功能.  
  
- Run As: 允许一个用户以另一种身份去访问.  
  
- Remember Me: 记住密码功能.  
  
Shiro 是一个安全框架, 不提供用户权限的维护. 用户的权限管理需要我们自己去设计.  
### Shiro 核心组件  
  
Shiro 的运行流程为如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVJRlTIa00MadicPyJX2TOjh0WFKz8VfgibPXmuPYMAra6jXoSoyVpliayg/640?wx_fmt=png&from=appmsg "")  
  
image-20241007150213823.png  
  
这里 Subject 的创建是由 SecurityUtils 进行创建的, 后面我们代码会给出案例, 官方给出的图如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVJM54KDEW8kgFPa9up1habBC9vUutOThfBcGzFYwT9pSV9XQOYTdqnA/640?wx_fmt=png&from=appmsg "")  
  
image-20241007150235043.png  
### 基于 Java SE 基本使用  
  
在pom.xml文件中进行引入依赖:  
```
<dependencies>
    <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-core</artifactId>
        <version>1.4.1</version>
    </dependency>
</dependencies>

```  
  
因为本次的Realm从文件中获取数据, 所以这里创建/resources/shiro.ini文件, 内容如下:  
```
[users] # 定义两个用户信息 用户名=密码,角色1,角色2...
heihuUser=heihuPass,seller # 账号名:heihuUser 密码:heihuPass 销售人员
hacker=123456,ckmgr # 账号名:hacker 密码:123456 仓管人员
admin=admin888,admin # 账号名: admin888 密码: admin888

[roles] # 定义角色与对应的权限 角色名=权限1,权限2,权限3...
seller=order-add,order-del,order-list # 销售人员的权限
ckmgr=ck-add,ck-del,ck-list # 仓管人员权限
admin=* # * 表示所有权限

```  
> 这里的注释在实际运行代码时, 要将其删掉, 否则将报错!  
  
  
随后我们创建测试程序:  
```
Scanner scanner = new Scanner(System.in); // 接收外部传递来的账号密码
System.out.print("请输入用户名: ");
String username = scanner.nextLine();
System.out.print("请输入密码: ");
String password = scanner.nextLine();

DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager(); // 准备 SecurityManager
defaultSecurityManager.setRealm(new IniRealm("classpath:shiro.ini")); // 设置 Realm
SecurityUtils.setSecurityManager(defaultSecurityManager); // 将 SecurityManager 设置到 SecurityUtils 工具类中
Subject subject = SecurityUtils.getSubject(); // 通过 SecurityUtils 获取 subject 对象

System.out.println(subject.isAuthenticated()); // 判断 subject 是否通过认证, 这里是 false
subject.login(new UsernamePasswordToken(username, password)); // 通过 subject对象.login 进行认证, 通过账号密码进行认证, 认证失败则抛出异常
System.out.println(subject.isAuthenticated()); // 判断 subject 是否通过认证, 如果登录成功, 这里为 true, 如果登陆失败, 上一行代码已经抛出异常了.

```  
  
由于登录失败会抛出异常, 所以我们这里可以使用try-catch进行捕获, 加入到我们的业务逻辑中:  
```
Scanner scanner = new Scanner(System.in); // 接收外部传递来的账号密码
System.out.print("请输入用户名: ");
String username = scanner.nextLine();
System.out.print("请输入密码: ");
String password = scanner.nextLine();

DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager(); // 准备 SecurityManager
defaultSecurityManager.setRealm(new IniRealm("classpath:shiro.ini")); // 设置 Realm
SecurityUtils.setSecurityManager(defaultSecurityManager); // 将 SecurityManager 设置到 SecurityUtils 工具类中
Subject subject = SecurityUtils.getSubject(); // 通过 SecurityUtils 获取 subject 对象

try {
    subject.login(new UsernamePasswordToken(username, password)); // 通过 subject对象.login 进行认证, 通过账号密码进行认证, 认证失败则抛出异常
    System.out.println("登陆成功!");
} catch (IncorrectCredentialsException e) {
    System.out.println("登陆失败!");
} catch (UnknownAccountException e) {
    System.out.println("用户名不存在!");
}
// 如果看注释吃力, 可以根据 《Shiro 核心组件》中的流程进行理解

```  
  
当然了, 登录成功后, 我们可以判断当前的角色是什么角色, 也可以判断当前的用户是否具备某个权限:  
```
Scanner scanner = new Scanner(System.in); // 接收外部传递来的账号密码
System.out.print("请输入用户名: ");
String username = scanner.nextLine();
System.out.print("请输入密码: ");
String password = scanner.nextLine();

DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager(); // 准备 SecurityManager
defaultSecurityManager.setRealm(new IniRealm("classpath:shiro.ini")); // 设置 Realm
SecurityUtils.setSecurityManager(defaultSecurityManager); // 将 SecurityManager 设置到 SecurityUtils 工具类中
Subject subject = SecurityUtils.getSubject(); // 通过 SecurityUtils 获取 subject 对象

try {
    subject.login(new UsernamePasswordToken(username, password)); // 通过 subject对象.login 进行认证, 通过账号密码进行认证, 认证失败则抛出异常
    System.out.println("登陆成功!");
    System.out.println(subject.hasRole("seller")); // 判断角色: hacker 登录后返回 false, heihuUser | admin 登录后返回 true
    System.out.println(subject.isPermitted("order-del")); // 判断权限: 当前用户是否由 order-del 权限, heihuUser 登录返回 true, hacker 登录返回 false
} catch (IncorrectCredentialsException e) {
    System.out.println("登陆失败!");
} catch (UnknownAccountException e) {
    System.out.println("用户名不存在!");
}

```  
  
其中流程如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVXMA9D1EoPiapsAzicQICTBHcC5vric8wUK4hP5Juny5YZXbZfsQ26vePw/640?wx_fmt=png&from=appmsg "")  
  
image-20241007174301593.png  
  
而IniRealm只不过是实现了AuthorizingRealm接口,Shiro框架提供出来了罢了, 其中IniRealm实现了doGetAuthorizationInfo & doGetAuthenticationInfo方法, 这两个方法会根据传递过来的token类型来进入到具体的方法.  
### SpringBoot 整合 Shiro  
#### IniRealm  
  
如果我们想在SpringBoot中进行使用Shiro, 那么我们肯定是需要围绕如下环节进行研究.  
  
创建 pom.xml:  
```
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.5.3</version>
</parent>

<dependencies>
    <dependency> <!-- 导入 shiro-spring, 会自动引入 shiro-core, shiro-web -->
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-spring</artifactId>
        <version>1.4.1</version>
    </dependency>
    <dependency> <!-- springboot 没有提供对 shiro 的自动配置, shiro 的自动配置需手动完成 -->
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency> <!-- 引入 thymeleaf 模板引擎 -->
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
    <dependency> <!-- 引入 lombok -->
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
    </dependency>
    <dependency> <!-- 引入 druid-spring-boot-starter, 自动配置 Druid -->
        <groupId>com.alibaba</groupId>
        <artifactId>druid-spring-boot-starter</artifactId>
        <version>1.1.17</version>
    </dependency>
    <dependency> <!-- 会自动引入 mybatis, mybatis-spring, spring-boot-starter-jdbc -->
        <groupId>org.mybatis.spring.boot</groupId>
        <artifactId>mybatis-spring-boot-starter</artifactId>
        <version>2.2.2</version>
    </dependency>
    <dependency> <!-- 引入 mysql 扩展 -->
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <version>8.0.28</version>
    </dependency>
    <dependency> <!-- 引入 SpringBoot 测试依赖 -->
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
    </dependency>
</dependencies>

```  
  
创建/resources/application.yml:  
```
server: # 设置启动端口
  port: 80

spring:
  thymeleaf: # 设置 thymeleaf 模板存放位置
    prefix: "classpath:/templates/"
    suffix: ".html"
  datasource:
    druid: # 设置数据库连接
      url: jdbc:mysql://localhost:3306/shiro?useSSL=true&characterEncoding=utf-8&useUnicode=true
      username: root
      password: root
      driver-class-name: com.mysql.cj.jdbc.Driver
  mvc:
    static-path-pattern: /static/** # 设置静态资源访问路径
  web:
    resources:
      static-locations: classpath:/static/** # 设置静态资源保存目录

mybatis:
  mapper-locations: classpath:mappers/*.xml # 设置 mybatis mapper文件存放位置, 用于扫描
  type-aliases-package: com.heihu577.bean # 设置 JavaBean 存放位置

```  
  
定义com.heihu577.MainApp类:  
```
@SpringBootApplication
public class MainApp {
    public static void main(String[] args) {
        ConfigurableApplicationContext ioc = SpringApplication.run(MainApp.class, args);
    }
}

```  
  
因为Shiro需要我们手动配置, 所以我们定义com.heihu577.config.ShiroAutoConfiguration类如下:  
```
@Configuration
public class ShiroAutoConfiguration {
    @Bean
    public IniRealm getIniRealm() { // 先使用 IniReal 做演示
        IniRealm iniRealm = new IniRealm("classpath:shiro.ini");
        /* classpath:shiro.ini 文件内容如下:
            [users]
            heihuUser=heihuPass,seller
            hacker=123456,ckmgr
            admin=admin888,admin

            [roles]
            seller=order-add,order-del,order-list
            ckmgr=ck-add,ck-del,ck-list
            admin=*
        */
        return iniRealm;
    }

    @Bean
    public SecurityManager getSecurityManager(IniRealm iniRealm) {
        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        defaultWebSecurityManager.setRealm(iniRealm); // 要想完成校验, 需要 Realm
        // SecurityUtils.setSecurityManager(defaultWebSecurityManager); // 设置 SecurityUtils 下的 SecurityManager
        return defaultWebSecurityManager;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean(); // 准备一个拦截器, 用于拦截用户请求
        shiroFilterFactoryBean.setSecurityManager(securityManager); // 进行数据校验的核心是 SecurityManager, 所以这里需要配置 SecurityManager
        // 配置拦截规则...
        HashMap<String,String> filterMap = new HashMap();
        filterMap.put("/", "anon"); // anon 匿名用户可访问
        filterMap.put("/login", "anon"); // 对 login.html 不拦截
        filterMap.put("/register", "anon"); // 对 register.html 不拦截
        filterMap.put("/user/login", "anon");
        filterMap.put("/**", "authc"); // authc 认证用户可访问
        filterMap.put("/static/**", "anon"); // 对 /static/** 都不拦截
        // user: 使用 RememberMe 用户可访问
        // perms: 对应权限可访问
        // role: 对应角色可访问
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterMap); // 将规则设置进来
        shiroFilterFactoryBean.setLoginUrl("/login"); // 设置默认的登录界面
        shiroFilterFactoryBean.setUnauthorizedUrl("/"); // 设置未授权访问的跳转URL
        return shiroFilterFactoryBean;
    }
}

```  
  
随后定义com.heihu577.controller.PageController && com.heihu577.controller.UserController控制器如下:  
```
@Controller
public class PageController {
    @RequestMapping(value = {"/"})
    public String index() {
        return "index"; // 跳转 thymeleaf 下的 index.html 模板引擎
    }

    @RequestMapping("/login")
    public String login() {
        return "login";
    }
}

```  
```
@Controller
@RequestMapping("/user")
public class UserController {
    @Resource
    private UserServiceImpl userService; // 自动注入 userService

    @PostMapping("/login")
    public String login(String username, String password) {
        try {
            userService.login(username, password);
            System.out.println("登陆成功!");
            return "index"; // 登录成功去 index 页面.
        } catch (Exception e) { // 使用 try-catch 进行判断登录状态
            System.out.println("登录失败!");
            return "login"; // 登录失败去 login 页面, 若想要注入数据, 使用 Model 即可
        }
    }
}

```  
  
定义两个模板如下:  
```
<!-- index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>主页</title>
</head>
<body>
    <h1>Hello World!</h1>
</body>
</html>
<!-- login.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登录表单</title>
</head>
<body>
    <form action="/user/login" method="post">
        u: <input type="text" name="username"/><br>





        p: <input type="password" name="password"/><br>





        <input type="submit">
    </form>
</body>
</html>

```  
  
定义com.heihu577.service.UserServiceImpl如下:  
```
@Service
public class UserServiceImpl {
    public void login(String username, String password)  throws Exception { // 登陆失败会抛出异常, 登陆成功没返回值
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);
        Subject subject = SecurityUtils.getSubject();
        subject.login(usernamePasswordToken); // 发送登录请求.
    }
}

```  
  
最终可以实现用户登录, 判断账号密码是否正确. 当前为了学习方便, 使用了 IniRealm 进行演示, 其中思路如下.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVA6qIIkv1SwKQ86c9DDwY1h0c7GX4gcvgTQT5nLbDOxyH1ricGWZsDyQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241008121529770.png  
  
而如果我们想要使用JdbcRealm, 那么我们则需要配置相应的Realm.  
#### JdbcRealm  
  
其中JdbcRealm需要创建如下表结构:  
```
CREATE TABLE `users`(
	id int primary key auto_increment,
    username varchar(60) not null unique,
    password varchar(60) not null,
    password_salt varchar(20)
);
-- 创建五个用户如下
INSERT INTO `users`(username, password) VALUES('zhangsan', '123456');
INSERT INTO `users`(username, password) VALUES('lisi', '123456');
INSERT INTO `users`(username, password) VALUES('wangwu', '123456');
INSERT INTO `users`(username, password) VALUES('zhaoliu', '123456');
INSERT INTO `users`(username, password) VALUES('chenqi', '123456');

CREATE TABLE `user_roles`(
	id int primary key auto_increment,
    username varchar(60) not null,
    role_name varchar(100) not null
);
-- 给这五个用户分别增加如下角色
-- admin 系统管理人员
-- cmanager 库管人员
-- xmanager 销售人员
-- kmanager 客服人员
-- zmanager 行政人员
INSERT INTO `user_roles`(username, role_name) VALUES('zhangsan', 'admin');
INSERT INTO `user_roles`(username, role_name) VALUES('lisi', 'cmanager');
INSERT INTO `user_roles`(username, role_name) VALUES('wangwu', 'xmanager');
INSERT INTO `user_roles`(username, role_name) VALUES('zhaoliu', 'kmanager');
INSERT INTO `user_roles`(username, role_name) VALUES('chenqi', 'zmanager');

CREATE TABLE `roles_permissions`(
	id int primary key auto_increment,
    role_name varchar(100) not null,
    permission varchar(100) not null
);
-- admin 具备所有权限
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("admin", "*");
-- 库管人员具备的权限
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("cmanager", "sys:c:save");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("cmanager", "sys:c:delete");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("cmanager", "sys:c:update");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("cmanager", "sys:c:find");
-- 销售人员具备的权限
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("xmanager", "sys:c:find");

INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("xmanager", "sys:x:save");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("xmanager", "sys:x:delete");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("xmanager", "sys:x:update");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("xmanager", "sys:x:find");

INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("xmanager", "sys:k:save");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("xmanager", "sys:k:delete");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("xmanager", "sys:k:update");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("xmanager", "sys:k:find");
-- 客服人员所具备的权限
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("kmanager", "sys:k:update");
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("kmanager", "sys:k:find");
-- 行政人员
INSERT INTO `roles_permissions`(`role_name`,`permission`) VALUES("zmanager", "sys:*:find");

```  
  
当前表结构如果想要查询具体用户是否具有某种权限的话, 关系如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVYdPdno2XGy8CASXibcHDIjiblqtGRs1G4AjZ3XhWafYuLQRawClia3Pgw/640?wx_fmt=png&from=appmsg "")  
  
image-20241008154258677.png  
  
那么此时我们修改ShiroAutoConfiguration类代码如下:  
```
@Configuration
public class ShiroAutoConfiguration {
//    @Bean
//    public IniRealm getIniRealm() { // 先使用 IniReal 做演示
//        IniRealm iniRealm = new IniRealm("classpath:shiro.ini");
//        return iniRealm;
//    }

    @Bean
    public JdbcRealm getJdbcRealm(DataSource dataSource) {
        JdbcRealm jdbcRealm = new JdbcRealm();
        jdbcRealm.setDataSource(dataSource); // druid-spring-boot-starter 已经配置好了, 直接引用即可
        jdbcRealm.setPermissionsLookupEnabled(true); // 默认开启认证功能, 需手动开启授权功能
        return jdbcRealm;
    }


    @Bean
    public SecurityManager getSecurityManager(JdbcRealm ream) {
        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        defaultWebSecurityManager.setRealm(ream); // 要想完成校验, 需要 Realm
        // SecurityUtils.setSecurityManager(defaultWebSecurityManager); // 设置 SecurityUtils 下的 SecurityManager
        return defaultWebSecurityManager;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        HashMap<String,String> filterMap = new HashMap();
        filterMap.put("/", "anon");
        filterMap.put("/login", "anon");
        filterMap.put("/register", "anon");
        filterMap.put("/user/login", "anon");
        filterMap.put("/**", "authc");
        filterMap.put("/static/**", "anon");

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterMap); // 将规则设置进来
        shiroFilterFactoryBean.setLoginUrl("/login"); // 设置默认的登录界面
        shiroFilterFactoryBean.setUnauthorizedUrl("/"); // 设置未授权访问的跳转URL
        return shiroFilterFactoryBean;
    }
}

```  
  
修改完具体Realm后, 我们的功能也成功生效了.  
##### Shiro 标签使用  
  
当我们登录成功后, 需要显示当前用户信息, 以及对应的权限功能入口, Shiro 提供了一套标签, 可以应用于 Thymeleaf, jsp 中。  
  
当前我们的环境是 Thymeleaf, 所以我们必须在pom.xml中导入依赖:  
```
<dependency> <!-- 引入 shiro 标签依赖 -->
    <groupId>com.github.theborakompanioni</groupId>
    <artifactId>thymeleaf-extras-shiro</artifactId>
    <version>2.1.0</version>
</dependency>

```  
  
随后我们需要在我们的配置类中定义一个Bean:  
```
@Bean
public ShiroDialect getShiroDialect() {
    return new ShiroDialect();
}

```  
  
随后我们在具体模板中进行声明引用即可:  
```
<html lang="en" xmlns:th="http://www.thymeleaf.org" xmlns:shiro="http://www.pollix.at/thymeleaf/shiro">

```  
  
修改/resources/templates/index.html文件内容如下:  
```
<!DOCTYPE html>
<html lang="en" xmlns:shiro="http://www.pollix.at/thymeleaf/shiro">
<head>
    <meta charset="UTF-8">
    <title>主页</title>
</head>
<body>
<shiro:guest>
    欢迎游客访问 | <a href="/login">登录</a> <!-- 当用户没有登录时会显示该内容 -->
</shiro:guest>
<shiro:user>
    欢迎用户名为: <shiro:principal/> 的用户访问! <br>




 <!-- 当前已经登陆成功的状态, 会显示该内容 <shiro:principal/> 获取当前用户名 -->
    <hr>
    当前用户角色为:
    <shiro:hasRole name="admin"> 超级管理员</shiro:hasRole> <!-- 判断当前的角色 -->
    <shiro:hasRole name="cmanager"> 库管人员</shiro:hasRole>
    <shiro:hasRole name="xmanager"> 销售人员</shiro:hasRole>
    <shiro:hasRole name="kmanager"> 客服人员</shiro:hasRole>
    <shiro:hasRole name="zmanager"> 行政人员</shiro:hasRole>
    <hr>
    <br>




当前所拥有的权限为: <br>





    <hr>
    仓库管理
    <ul>
        <shiro:hasPermission name="sys:c:save"><li><a href="#">入库</a></li></shiro:hasPermission>
        <shiro:hasPermission name="sys:c:delete"><li><a href="#">出库</a></li></shiro:hasPermission>
        <shiro:hasPermission name="sys:c:update"><li><a href="#">更新仓库</a></li></shiro:hasPermission>
        <shiro:hasPermission name="sys:c:find"><li><a href="#">查找仓库</a></li></shiro:hasPermission>
    </ul>
    <hr>
    销售管理
    <ul>
        <shiro:hasPermission name="sys:x:save"><li><a href="#">保存订单</a></li></shiro:hasPermission>
        <shiro:hasPermission name="sys:x:delete"><li><a href="#">删除订单</a></li></shiro:hasPermission>
        <shiro:hasPermission name="sys:x:update"><li><a href="#">更新订单</a></li></shiro:hasPermission>
        <shiro:hasPermission name="sys:x:find"><li><a href="#">查询订单</a></li></shiro:hasPermission>
    </ul>
    客户管理
    <ul>
        <shiro:hasPermission name="sys:k:save"><li><a href="#">新增客户</a></li></shiro:hasPermission>
        <shiro:hasPermission name="sys:k:delete"><li><a href="#">删除客户</a></li></shiro:hasPermission>
        <shiro:hasPermission name="sys:k:update"><li><a href="#">修改客户</a></li></shiro:hasPermission>
        <shiro:hasPermission name="sys:k:find"><li><a href="#">查询客户</a></li></shiro:hasPermission>
    </ul>
</shiro:user>
</body>
</html>

```  
  
不同用户登录效果:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVvrbGS5WZVOT7AAkRibF9VvpAn6mjEk2viaFfqbPgt6ic8ibLdw9LJ3mOfQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241008180754620.png  
#### 自定义 Realm  
  
在真正的项目中, 我们不会使用Shiro提供的JdbcRealm, 而是使用自定义Realm, 配合我们的MyBatis, 以及自定义表结构进行联合使用.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV3Le2UKf7wPzhgVRkuZgictcxjr6eNIlnmoMmhLiakXMvYVozS8ctOCCQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241008184622995.png  
##### 表结构定义  
  
那么下面我们来定义这些表:  
```
-- 用户信息表
CREATE TABLE `tb_users`(
	user_id int unsigned primary key auto_increment,
    username varchar(60) not null unique,
    password varchar(60) not null,
    password_salt varchar(60)
);
INSERT INTO `tb_users`(username, password) VALUES('zhangsan', '123456');
INSERT INTO `tb_users`(username, password) VALUES('lisi', '123456');
INSERT INTO `tb_users`(username, password) VALUES('wangwu', '123456');
INSERT INTO `tb_users`(username, password) VALUES('zhaoliu', '123456');
INSERT INTO `tb_users`(username, password) VALUES('chenqi', '123456');

-- 角色信息表
CREATE TABLE `tb_roles`(
	role_id int unsigned primary key auto_increment,
    role_name varchar(60) not null
);
INSERT INTO `tb_roles`(role_name) VALUES('admin'); -- 系统管理员
INSERT INTO `tb_roles`(role_name) VALUES('cmanager'); -- 仓管
INSERT INTO `tb_roles`(role_name) VALUES('xmanager'); -- 销售
INSERT INTO `tb_roles`(role_name) VALUES('kmanager'); -- 客服
INSERT INTO `tb_roles`(role_name) VALUES('zmanager'); -- 行政

-- 权限信息表
CREATE TABLE `tb_permissions`(
	permission_id int primary key auto_increment,
    permission_code varchar(60) not null,
    permission_name varchar(60)
);
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:c:save", "入库");
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:c:delete", "出库");
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:c:update", "修改");
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:c:find", "查询");

INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:x:save", "新增订单");
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:x:delete", "删除订单");
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:x:update", "修改订单");
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:x:find", "查询订单");

INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:k:save", "新增客户");
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:k:delete", "删除客户");
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:k:update", "修改客户");
INSERT INTO `tb_permissions`(`permission_code`,`permission_name`) VALUES("sys:k:find", "查询客户");

-- 用户角色表
CREATE TABLE `tb_urs`(
	uid int not null,
    rid int not null
);
INSERT INTO `tb_urs` VALUES(1,1); -- 第1个用户是第1个角色 (zhangsan 是 admin 角色)
INSERT INTO `tb_urs` VALUES(2,2);
INSERT INTO `tb_urs` VALUES(3,3);
INSERT INTO `tb_urs` VALUES(4,4);
INSERT INTO `tb_urs` VALUES(5,5);

-- 角色权限表
CREATE TABLE `tb_rps`(
	rid int not null,
    pid int not null
);
INSERT INTO `tb_rps` VALUES(2,1); -- 仓库管理员拥有四个权限
INSERT INTO `tb_rps` VALUES(2,2);
INSERT INTO `tb_rps` VALUES(2,3);
INSERT INTO `tb_rps` VALUES(2,4);
INSERT INTO `tb_rps` VALUES(3,5); -- 销售人员具有九个权限, 包含客服人员的权限, 以及仓库查询权限
INSERT INTO `tb_rps` VALUES(3,4);
INSERT INTO `tb_rps` VALUES(3,6);
INSERT INTO `tb_rps` VALUES(3,7);
INSERT INTO `tb_rps` VALUES(3,8);
INSERT INTO `tb_rps` VALUES(3,9);
INSERT INTO `tb_rps` VALUES(3,10);
INSERT INTO `tb_rps` VALUES(3,11);
INSERT INTO `tb_rps` VALUES(3,12);
INSERT INTO `tb_rps` VALUES(4,11); -- 客服人员具有两个权限, 查询和修改
INSERT INTO `tb_rps` VALUES(4,12);
INSERT INTO `tb_rps` VALUES(5,12); -- 行政人员具备所有查询功能
INSERT INTO `tb_rps` VALUES(5,8);
INSERT INTO `tb_rps` VALUES(5,4);

```  
  
由于是自定义Realm, 所以查询数据的操作应该由我们自己手动完成, 所以这里我们应该配合我们的MyBatis进行查询数据信息.  
##### DAO 设计  
  
因为我们需要从数据库中拿数据, 那么我们这里可以参考一下JdbcRealm做了什么:  
```
public class JdbcRealm extends AuthorizingRealm {
   protected static final String DEFAULT_AUTHENTICATION_QUERY = "select password from users where username = ?";
    protected static final String DEFAULT_SALTED_AUTHENTICATION_QUERY = "select password, password_salt from users where username = ?";
    // ↑ 根据用户名查询用户信息
    protected static final String DEFAULT_USER_ROLES_QUERY = "select role_name from user_roles where username = ?";
    // ↑ 查询具体用户名的角色名称
    protected static final String DEFAULT_PERMISSIONS_QUERY = "select permission from roles_permissions where role_name = ?";
    // ↑ 根据角色名查询权限列表
}

```  
  
当然如果我们想要自定义Realm, 我们也需要制定这些业务场景的查询语句. 为了使用我们的 MyBatis 联动 Realm, 这里我们重新建立一个干净的项目.  
  
引入依赖:  
```
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId> <!-- 引入 parent -->
    <version>2.5.3</version>
</parent>
<dependencies>
    <dependency> <!-- 导入 shiro-spring, 会自动引入 shiro-core, shiro-web -->
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-spring</artifactId>
        <version>1.4.1</version>
    </dependency>
    <dependency> <!-- springboot 没有提供对 shiro 的自动配置, shiro 的自动配置需手动完成 -->
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency> <!-- 引入 thymeleaf 模板引擎 -->
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
    <dependency> <!-- 引入 lombok -->
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
    </dependency>
    <dependency> <!-- 引入 druid-spring-boot-starter, 自动配置 Druid -->
        <groupId>com.alibaba</groupId>
        <artifactId>druid-spring-boot-starter</artifactId>
        <version>1.1.17</version>
    </dependency>
    <dependency> <!-- 引入 shiro 标签依赖 -->
        <groupId>com.github.theborakompanioni</groupId>
        <artifactId>thymeleaf-extras-shiro</artifactId>
        <version>2.1.0</version>
    </dependency>
    <dependency> <!-- 会自动引入 mybatis, mybatis-spring, spring-boot-starter-jdbc -->
        <groupId>org.mybatis.spring.boot</groupId>
        <artifactId>mybatis-spring-boot-starter</artifactId>
        <version>2.2.2</version>
    </dependency>
    <dependency> <!-- 引入 mysql 扩展 -->
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <version>8.0.28</version>
    </dependency>
    <dependency> <!-- 引入 SpringBoot 测试依赖 -->
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
    </dependency>
</dependencies>

```  
  
application.yml:  
```
server:
  port: 80

mybatis:
  type-aliases-package: com.heihu577.bean
  mapper-locations: classpath:mappers/*.xml

spring:
  datasource:
    druid:
      url: jdbc:mysql://localhost:3306/shiro2?useSSL=true&useUnicode=true&characterEncoding=utf-8
      username: root
      password: root
      driver-class-name: com.mysql.cj.jdbc.Driver

```  
  
定义Bean:  
```
package com.heihu577.bean;

@Data
public class User {
    private Integer userId;
    private String username;
    private String password;
    private String passwordSalt;
}

```  
  
MainApp:  
```
@SpringBootApplication
@MapperScan("com.heihu577.mapper")
public class MainApp {
    public static void main(String[] args) {
        ConfigurableApplicationContext ioc = SpringApplication.run(MainApp.class, args);
    }
}

```  
###### UserMapper 根据用户名查询用户信息  
  
定义Mapper接口:  
```
public interface UserMapper {
    // 根据用户名, 查询用户信息
    public User queryUserByUserName(@Param("username") String username);
}

```  
  
随后我们创建/resources/mappers/UserMapper.xml:  
```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "https://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.heihu577.mapper.UserMapper">
    <resultMap id="user" type="User">
        <id property="userId" column="user_id"/>
        <result property="username" column="username"/>
        <result property="password" column="password"/>
        <result property="passwordSalt" column="password_salt"/>
    </resultMap>
    <select id="queryUserByUserName" resultMap="user" parameterType="String">
        SELECT * FROM `tb_users` WHERE `username` = #{username}
    </select>
</mapper>

```  
###### RoleMapper 根据用户名查询角色信息  
```
public interface RoleMapper {
    // 根据用户名, 查询出角色名称
    public Set<String> queryRoleByUserName(@RequestParam("username") String username);
    /** 涉及到联表查询
     * SELECT * FROM tb_users INNER JOIN tb_urs ON tb_users.user_id = tb_urs.uid INNER JOIN tb_roles ON tb_urs.rid = tb_roles.role_id;
     * +---------+----------+----------+---------------+-----+-----+---------+-----------+
     * | user_id | username | password | password_salt | uid | rid | role_id | role_name |
     * +---------+----------+----------+---------------+-----+-----+---------+-----------+
     * |       1 | zhangsan | 123456   | NULL          |   1 |   1 |       1 | admin     |
     * |       2 | lisi     | 123456   | NULL          |   2 |   2 |       2 | cmanager  |
     * |       3 | wangwu   | 123456   | NULL          |   3 |   3 |       3 | xmanager  |
     * |       4 | zhaoliu  | 123456   | NULL          |   4 |   4 |       4 | kmanager  |
     * |       5 | chenqi   | 123456   | NULL          |   5 |   5 |       5 | zmanager  |
     * +---------+----------+----------+---------------+-----+-----+---------+-----------+
     *
     */
}

```  
  
定义Mapper文件:  
```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "https://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.heihu577.mapper.RoleMapper">
    <select id="queryRoleByUserName" resultType="String" parameterType="String">
        SELECT role_name FROM tb_users
        INNER JOIN tb_urs ON tb_users.user_id = tb_urs.uid
        INNER JOIN tb_roles ON tb_urs.rid = tb_roles.role_id
        WHERE username = #{username};
    </select>
</mapper>

```  
###### PermissionMapper 根据用户名查询权限信息  
```
public interface PermissionMapper {
    public Set<String> queryPermissionByUserName(@RequestParam("username") String username);
}

```  
  
定义Mapper文件:  
```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "https://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.heihu577.mapper.PermissionMapper">
    <select id="queryPermissionByUserName" resultType="String" parameterType="String">
        SELECT permission_code FROM tb_users
        INNER JOIN tb_urs ON tb_users.user_id = tb_urs.uid
        INNER JOIN tb_roles ON tb_urs.rid = tb_roles.role_id
        INNER JOIN tb_rps ON tb_rps.rid = tb_roles.role_id
        INNER JOIN tb_permissions ON tb_permissions.permission_id = tb_rps.pid
        WHERE username = #{username};
    </select>
</mapper>

```  
##### 自定义 Realm 设计  
  
定义如下Realm:  
```
public class MyRealm extends AuthorizingRealm { // 自定义 Realm 通常继承 AuthorizingRealm
    @Resource
    private UserMapper userMapper;
    @Resource
    private RoleMapper roleMapper;
    @Resource
    private PermissionMapper permissionMapper;

    /**
     * @return 当前 Realm 名称, 可自定义名称
     */
    @Override
    public String getName() {
        return "MyRealm";
    }

    /**
     * 准备好授权数据, 授权数据就是当前用户的角色, 当前用户的权限信息, 所以我们只需要准备这些数据, 返回给 SecurityManager 即可.
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.iterator().next(); // 得到已经登录成功的用户名, 实际上获取到的内容是 doGetAuthenticationInfo 方法中 new SimpleAuthenticationInfo(用户名, 用户密码, 当前Realm名称) 中的第一个参数
        Set<String> roles = roleMapper.queryRoleByUserName(username); // 通过用户名得到角色名称
        Set<String> permissions = permissionMapper.queryPermissionByUserName(username); // 通过用户名得到权限信息

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setRoles(roles); // 将数据库查询出来的信息封装到 AuthorizationInfo 中
        info.setStringPermissions(permissions);

        return info;
    }

    /**
     * 准备好认证数据, 我们无需操心比对, 比对最终交给 SecurityManager, 我们只需要提供数据就可以了.
     * 而认证数据, 我们只需要提供 账号,密码 即可.
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // subject.login(token) 会调用到这里
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token; // 认证时, 强制转换
        String username = usernamePasswordToken.getUsername(); // 得到用户名
        User user = userMapper.queryUserByUserName(username); // 从数据库中查询该用户名, 得到该用户信息
        if (user != null) {
            // 成功从数据库中查询到用户, 我们就将用户的信息封装到 AuthenticationInfo 中, SimpleAuthenticationInfo 是 AuthenticationInfo 的子类
            return new SimpleAuthenticationInfo(username, user.getPassword(), this.getName());
            // new SimpleAuthenticationInfo(用户名, 用户密码, 当前Realm名称)
        }
        return null;
    }
}

```  
  
我们只需要重写doGetAuthenticationInfo方法, 并且返回AuthenticationInfo类型的数据即可,AuthenticationInfo类型的数据中封装的就是用户的账号与密码信息.  
  
重写doGetAuthorizationInfo方法, 并且返回AuthorizationInfo类型的信息,AuthorizationInfo中包含了用户的角色, 权限信息.  
  
重写getName方法, 为我们的自定义Realm增加一个名称.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVRUCFpMLMia3aJbXvx4dlFMNGOic5HjO5nJsHgUsmVWr5FNH9nric2ZicAQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241009172138655.png  
  
从上面可以看到的是, 我们自定义Realm成功参与了自己的数据库查询逻辑在里面, 我们使用了MyBatis从数据库中取数据, 将数据放入到返回对象中. 因为比对工作是由SecurityManager完成的, 所以我们这里只需提供数据即可, 无需加入自己的业务逻辑判断. 当然, 为了验证方便, 我们依然使用之前的login.html, index.html, UserServiceImpl, PageController, UserController进行做测试即可.  
  
最终运行效果:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV8QUxdVRwdDZrrmOBF1NT07ex8Kc8sSKjeHEsFW8C4uQm7RHMxZoB7w/640?wx_fmt=png&from=appmsg "")  
  
image-20241009174342555.png  
  
不同的用户, 不同的角色, 具有不同的权限.  
##### Layui 优化界面  
  
去 https://www.layuicdn.com/docs/v2/demo/admin.html 中拷贝代码, 并且下载 Layui 所需要的 css 与 js.  
  
并且将 Layui 中的 CSS 与 JS 放入到/resource/static目录下, 定义/resources/templates/index.html文件内容如下:  
```
<!DOCTYPE html>
<html xmlns:shiro="http://www.pollix.at/thymeleaf/shiro">
<head>
    <base href="/"> <!-- 一定要加入这一行代码, 避免 CSS, JS 引用出错. -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>layout 管理系统大布局 - Layui</title>
    <link rel="stylesheet" href="./layui/css/layui.css">
</head>
<body>
<div class="layui-layout layui-layout-admin">
    <div class="layui-header">
        <div class="layui-logo layui-hide-xs layui-bg-black">layout demo</div>
        <!-- 头部区域（可配合layui 已有的水平导航） -->
        <ul class="layui-nav layui-layout-left">
            <!-- 移动端显示 -->
            <li class="layui-nav-item layui-show-xs-inline-block layui-hide-sm" lay-header-event="menuLeft">
                <i class="layui-icon layui-icon-spread-left"></i>
            </li>

            <li class="layui-nav-item layui-hide-xs"><a href="">nav 1</a></li>
            <li class="layui-nav-item layui-hide-xs"><a href="">nav 2</a></li>
            <li class="layui-nav-item layui-hide-xs"><a href="">nav 3</a></li>
            <li class="layui-nav-item">
                <a href="javascript:;">nav groups</a>
                <dl class="layui-nav-child">
                    <dd><a href="">menu 11</a></dd>
                    <dd><a href="">menu 22</a></dd>
                    <dd><a href="">menu 33</a></dd>
                </dl>
            </li>
        </ul>
        <shiro:user>
            <ul class="layui-nav layui-layout-right">
                <li class="layui-nav-item layui-hide layui-show-md-inline-block">
                    <a href="javascript:;">
                        <img src="x" alt="图片显示错误" class="layui-nav-img">
                        <shiro:principal/>
                    </a>
                    <dl class="layui-nav-child">
                        <dd><a href="">Your Profile</a></dd>
                        <dd><a href="">Settings</a></dd>
                        <dd><a href="">Sign out</a></dd>
                    </dl>
                </li>
                <li class="layui-nav-item" lay-header-event="menuRight" lay-unselect>
                    <a href="javascript:;">
                        <i class="layui-icon layui-icon-more-vertical"></i>
                    </a>
                </li>
            </ul>
            <shiro:user>
    </div>

    <div class="layui-side layui-bg-black">
        <div class="layui-side-scroll">
            <!-- 左侧导航区域（可配合layui已有的垂直导航） -->
            <ul class="layui-nav layui-nav-tree" lay-filter="test">
                <li class="layui-nav-item layui-nav-itemed">
                    <a class="" href="javascript:;">仓库管理</a>
                    <dl class="layui-nav-child">
                        <shiro:hasPermission name="sys:c:save">
                            <dd><a href="javascript:;">入库</a></dd>
                        </shiro:hasPermission>
                        <shiro:hasPermission name="sys:c:delete">
                            <dd><a href="javascript:;">出库</a></dd>
                        </shiro:hasPermission>
                        <shiro:hasPermission name="sys:c:delete">
                            <dd><a href="javascript:;">更新仓库</a></dd>
                        </shiro:hasPermission>
                        <shiro:hasPermission name="sys:c:delete">
                            <dd><a href="">查找仓库</a></dd>
                        </shiro:hasPermission>
                    </dl>
                </li>

                <li class="layui-nav-item layui-nav-itemed">
                    <a class="" href="javascript:;">销售管理</a>
                    <dl class="layui-nav-child">
                        <shiro:hasPermission name="sys:x:save">
                            <dd><a href="javascript:;">保存订单</a></dd>
                        </shiro:hasPermission>
                        <shiro:hasPermission name="sys:x:delete">
                            <dd><a href="javascript:;">删除订单</a></dd>
                        </shiro:hasPermission>
                        <shiro:hasPermission name="sys:x:delete">
                            <dd><a href="javascript:;">更新订单</a></dd>
                        </shiro:hasPermission>
                        <shiro:hasPermission name="sys:x:delete">
                            <dd><a href="">查询订单</a></dd>
                        </shiro:hasPermission>
                    </dl>
                </li>

                <li class="layui-nav-item layui-nav-itemed">
                    <a class="" href="javascript:;">客户管理</a>
                    <dl class="layui-nav-child">
                        <shiro:hasPermission name="sys:k:save">
                            <dd><a href="javascript:;">新增客户</a></dd>
                        </shiro:hasPermission>
                        <shiro:hasPermission name="sys:k:delete">
                            <dd><a href="javascript:;">删除客户</a></dd>
                        </shiro:hasPermission>
                        <shiro:hasPermission name="sys:k:update">
                            <dd><a href="javascript:;">修改客户</a></dd>
                        </shiro:hasPermission>
                        <shiro:hasPermission name="sys:k:find">
                            <dd><a href="">查询客户</a></dd>
                        </shiro:hasPermission>
                    </dl>
                </li>

            </ul>
        </div>
    </div>

    <div class="layui-body">
        <!-- 内容主体区域 -->
        <div style="padding: 15px;">内容主体区域。记得修改 layui.css 和 js 的路径</div>
    </div>

    <div class="layui-footer">
        <!-- 底部固定区域 -->
        底部固定区域
    </div>
</div>
<script src="./layui/layui.js"></script>
<script>
    //JS
    layui.use(['element', 'layer', 'util'], function () {
        var element = layui.element
            , layer = layui.layer
            , util = layui.util
            , $ = layui.$;

        //头部事件
        util.event('lay-header-event', {
            //左侧菜单事件
            menuLeft: function (othis) {
                layer.msg('展开左侧菜单的操作', {icon: 0});
            }
            , menuRight: function () {
                layer.open({
                    type: 1
                    , content: '<div style="padding: 15px;">处理右侧面板的操作</div>'
                    , area: ['260px', '100%']
                    , offset: 'rt' //右上角
                    , anim: 5
                    , shadeClose: true
                });
            }
        });
    });
</script>
</body>
</html>

```  
  
最终运行结果:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV0gvrbx6ibmzkOfU5EyS158gGx99d80WMKZD2fh0V77JZjiczcHmm0zgg/640?wx_fmt=png&from=appmsg "")  
  
image-20241010135443863.png  
##### 项目打包  
  
在pom.xml文件中增加如下内容:  
```
<build>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
        </plugin>
    </plugins>
</build>

```  
  
随后用maven打包即可:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVbKszTAsgajiajpyN6K3l0yTCZiaIZYQwMxEIa9VadDlQpb7S7SQO0CkQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241009175453962.png  
  
如果在别的机器进行部署, 这里数据库链接等信息一定要配置好, 否则项目启动不来.  
#### Shiro 加密  
  
加密的过程如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVapXqfNChVnoBVxYNzaDylbQW5HXKSVjQhz8CicrpsyAliaaCcOib33UlA/640?wx_fmt=png&from=appmsg "")  
  
image-20241010192638014.png  
  
研究这部分内容, 我们需要将数据库中Password值都改为MD5处理后的值, 过程如下:  
```
mysql> SELECT * FROM tb_users;
+---------+----------+----------+---------------+
| user_id | username | password | password_salt |
+---------+----------+----------+---------------+
|       1 | zhangsan | 123456   | NULL          |
|       2 | lisi     | 123456   | NULL          |
|       3 | wangwu   | 123456   | NULL          |
|       4 | zhaoliu  | 123456   | NULL          |
|       5 | chenqi   | 123456   | NULL          |
+---------+----------+----------+---------------+
5 rows in set (0.00 sec)

mysql> UPDATE `tb_users` SET password = md5(password);
Query OK, 5 rows affected (0.54 sec)
Rows matched: 5  Changed: 5  Warnings: 0

mysql> SELECT * FROM `tb_users`;
+---------+----------+----------------------------------+---------------+
| user_id | username | password                         | password_salt |
+---------+----------+----------------------------------+---------------+
|       1 | zhangsan | e10adc3949ba59abbe56e057f20f883e | NULL          |
|       2 | lisi     | e10adc3949ba59abbe56e057f20f883e | NULL          |
|       3 | wangwu   | e10adc3949ba59abbe56e057f20f883e | NULL          |
|       4 | zhaoliu  | e10adc3949ba59abbe56e057f20f883e | NULL          |
|       5 | chenqi   | e10adc3949ba59abbe56e057f20f883e | NULL          |
+---------+----------+----------------------------------+---------------+
5 rows in set (0.00 sec)

```  
  
那么接下来我们看一下如何使Shiro支持MD5的验证, 我们在配置类中增加如下代码:  
```
@Bean
public HashedCredentialsMatcher hashedCredentialsMatcher() {
    HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
    hashedCredentialsMatcher.setHashAlgorithmName("md5"); // 设置数据库存储的密码格式
    hashedCredentialsMatcher.setHashIterations(1); // 经过几次加密, 如果是2的话则是该含义: md5(md5(值))
    return hashedCredentialsMatcher;
}

@Bean
public MyRealm myRealm(HashedCredentialsMatcher hashedCredentialsMatcher) {
    MyRealm myRealm = new MyRealm();
    myRealm.setCredentialsMatcher(hashedCredentialsMatcher); // 将加密算法设置给 Realm
    return myRealm;
}

```  
  
其这样设计的含义如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVmauTHA3A5leFK7J718CXLqoQic1xQYqpQrM9BTQwMp4vfuoob4h9dpA/640?wx_fmt=png&from=appmsg "")  
  
image-20241010153841128.png  
  
我们只需要将加密规则封装到Realm中, SecurityManager中的Authenticator就会根据matcher的加密规则来进行校验.  
##### 用户加盐  
  
此功能模块我们最好还是配合上用户注册功能进行测试, 定义如下UserController:  
```
@PostMapping("/register")
public String register(String username, String password){
    try {
        userService.insertUser(username, password);
        return "login";
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

```  
  
定义UserServiceImpl::insertUser方法:  
```
@Service
public class UserServiceImpl {
    @Resource
    private UserMapper userMapper;

    // ...

    public void insertUser(String username, String password) throws Exception {
        // Md5Hash md5Hash = new Md5Hash(password); // 进行 MD5 加密
        String salt = "mysalt"; // 实战中盐可以随机
        password = new Md5Hash(password, salt).toHex(); // md5(盐 + 密码)
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        user.setPasswordSalt(salt); // 设置盐
        userMapper.insertUser(user); // 最终将盐也添加进去.
    }
}

```  
  
而UserMapper接口定义如下:  
```
public void insertUser(User user);
/* 实现:
	<insert id="insertUser" parameterType="User">
        INSERT INTO `tb_users` VALUES(NULL, #{username}, #{password}, #{passwordSalt});
    </insert>
*/

```  
  
随后我们在MyRealm::doGetAuthenticationInfo方法中将盐返回给SecurityManager:  
```
@Override
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    // subject.login(token) 会调用到这里
    UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token; // 认证时, 强制转换
    String username = usernamePasswordToken.getUsername(); // 得到用户名
    User user = userMapper.queryUserByUserName(username); // 从数据库中查询该用户名, 得到该用户信息
    if (user != null) {
        // 成功从数据库中查询到用户, 我们就将用户的信息封装到 AuthenticationInfo 中, SimpleAuthenticationInfo 是 AuthenticationInfo 的子类
        return new SimpleAuthenticationInfo(username, user.getPassword(), ByteSource.Util.bytes(user.getPasswordSalt()), this.getName()); // 注意这里的 ByteSource.Util.bytes(user.getPasswordSalt()) 用于返回盐
        // new SimpleAuthenticationInfo(用户名, 用户密码, 当前盐, 当前Realm名称)
    }
    return null;
}

```  
  
测试完毕后, 我们需要将数据库其他用户账号密码统一改为加盐模式, 否则其他用户无法登录:  
```
mysql> update tb_Users set password_salt = '7788', password = MD5(CONCAT(password_salt, '123456')) WHERE user_id < 6; -- 其他用户密码统一设置为123456
Query OK, 5 rows affected (0.11 sec)
Rows matched: 5  Changed: 5  Warnings: 0

mysql> SELECT * FROM tb_Users;
+---------+----------+----------------------------------+---------------+
| user_id | username | password                         | password_salt |
+---------+----------+----------------------------------+---------------+
|       1 | zhangsan | e97e4623f9bb7f1280233bfbe2793e70 | 7788          |
|       2 | lisi     | e97e4623f9bb7f1280233bfbe2793e70 | 7788          |
|       3 | wangwu   | e97e4623f9bb7f1280233bfbe2793e70 | 7788          |
|       4 | zhaoliu  | e97e4623f9bb7f1280233bfbe2793e70 | 7788          |
|       5 | chenqi   | e97e4623f9bb7f1280233bfbe2793e70 | 7788          |
|       6 | heihu577 | d23170a6c09cb22ef2b690406d86cd64 | mysalt        |
+---------+----------+----------------------------------+---------------+
6 rows in set (0.00 sec)

```  
#### 退出登录  
  
在我们的ShiroAutoConfiguration::ShiroFilterFactoryBean中, 我们增加如下代码:  
```
@Bean
public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
    ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
    shiroFilterFactoryBean.setSecurityManager(securityManager);
    Map<String, String> hashMap = new HashMap<>();
    hashMap.put("/", "anon");
    hashMap.put("/login", "anon");
    hashMap.put("/static/**", "anon");
    hashMap.put("/logout", "logout"); // 访问则退出登录
    shiroFilterFactoryBean.setFilterChainDefinitionMap(hashMap);
    shiroFilterFactoryBean.setLoginUrl("/login");
    shiroFilterFactoryBean.setUnauthorizedUrl("/");
    return shiroFilterFactoryBean;
}

```  
  
当我们访问/logout时, 就会退出登录. 当然也可以在前端页面加入该功能:  
```
<shiro:guest>
    <ul class="layui-nav layui-layout-right">
        <li class="layui-nav-item layui-hide layui-show-md-inline-block">
            <a href="/login">
                登录
            </a>
        </li>
    </ul>
</shiro:guest>
<shiro:user>
    <ul class="layui-nav layui-layout-right">
        <li class="layui-nav-item layui-hide layui-show-md-inline-block">
            <a href="javascript:;">
                <img src="x" alt="图片显示错误" class="layui-nav-img">
                <shiro:principal/>
            </a>
            <dl class="layui-nav-child">
                <dd><a href="">Your Profile</a></dd>
                <dd><a href="">Settings</a></dd>
                <dd><a href="/logout">Sign out</a></dd> <!-- 单机则退出登录 -->
            </dl>
        </li>
        <li class="layui-nav-item" lay-header-event="menuRight" lay-unselect>
            <a href="javascript:;">
                <i class="layui-icon layui-icon-more-vertical"></i>
            </a>
        </li>
    </ul>
    </shiro:user>
</div>

```  
#### 授权  
  
用户登陆成功之后, 要进行响应的操作就需要有对应的权限; 在进行操作之前对权限进行检查 - 授权.  
  
权限控制通常有两类做法:  
- 不同身份的用户登录，不同的操作菜单（没有权限的菜单不显示）  
  
- 对所有用户显示所有菜单，当用户点击菜单以后再验证当前用户是否有此权限，如果没有则提示权限不足。  
  
##### HTML 授权 - shiro 标签  
  
我们使用<shiro:hasRole name="角色名">,<shiro:hasPermission name="权限名">, 可以判断当前角色是否具有某种权限, 从而显示在页面上, 例如:  
```
<shiro:hasRole name="kmanager"> <!-- 是否是 kmanager 角色 -->
    <li class="layui-nav-item layui-nav-itemed">
        <a class="" href="javascript:;">客户管理</a>
        <dl class="layui-nav-child">
            <shiro:hasPermission name="sys:k:save"> <!-- 是否具有 sys:k:save 权限 -->
                <dd><a href="javascript:;">新增客户</a></dd>
            </shiro:hasPermission>
            <shiro:hasPermission name="sys:k:delete">
                <dd><a href="javascript:;">删除客户</a></dd>
            </shiro:hasPermission>
            <shiro:hasPermission name="sys:k:update">
                <dd><a href="javascript:;">修改客户</a></dd>
            </shiro:hasPermission>
            <shiro:hasPermission name="sys:k:find">
                <dd><a href="">查询客户</a></dd>
            </shiro:hasPermission>
        </dl>
    </li>
</shiro:hasRole>

```  
  
最终运行效果如图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVEEYMOG6VHzWC0lZE6VPzd5AUDTJRobynx0nMfjd7kJ35L2gfs9D1CQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241011144244662.png  
  
可以发现zhaoliu和lisi登陆上显示的功能模块是不同的.  
##### 过滤器授权 - 修复越权  
  
当然, 我们上面lisi用户是不存在查询客户权限的, 那么当lisi通过一些手段得到了查询客户的API路径, 则会造成越权漏洞, 我们可以本地模拟一下这个环境.  
  
在PageController中定义方法:  
```
@RequestMapping("/xFind")
public String kFind() {
    return "k_find"; // 定位到 /resources/templates/k_find.html 文件
}

```  
  
定义k_find.html页面:  
```
<!DOCTYPE html>
<html lang="en" xmlns:shiro="http://www.pollix.at/thymeleaf/shiro">
<head>
    <meta charset="UTF-8">
    <title>查询客户页面</title>
</head>
<body>
<h3>查询客户主页</h3>
<h4>当前用户: <shiro:principal/></h4>
</body>
</html>

```  
  
随后定义/resources/templates/index.html模板, 在该模板中增加一个iframe, 以及超链接跳转:  
```
<shiro:hasPermission name="sys:k:find">
	<dd><a href="/kFind" target="MainIframe">查询客户</a></dd>
    <!-- 其他内容... -->
</shiro:hasPermission>
<div class="layui-body">
    <iframe width="100%" height="780" name="MainIframe"></iframe>
</div>

```  
  
随后我们查看zhaoliu (具有查询客户权限)以及wangwu (不具有查询客户权限)的两种访问情况:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVD9wMPcsRJHCINVU0nQwNBEUgfVJdC5vavn3MEuXJicc687NHMkanJlA/640?wx_fmt=png&from=appmsg "")  
  
image-20241011150624816.png  
> 实际场景 wangwu 也存在查询客户的权限, 因为 <shiro:hasRole> 标签功能被隐藏了, 测试的时候最好使用zhangsan & zhaoliu进行测试.  
  
  
这样就造成了一个越权漏洞, 而修复方法也很简单, 我们只需要对/kFind这个路由增加权限判断即可, 那么我们配置ShiroFilter如下:  
```
@Bean
public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
    ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
    shiroFilterFactoryBean.setSecurityManager(securityManager);
    Map<String, String> hashMap = new HashMap<>();
    hashMap.put("/", "anon"); // / 支持匿名访问
    hashMap.put("/login", "anon"); // login 支持匿名访问
    hashMap.put("/static/**", "anon"); // static 下的内容随便访问
    hashMap.put("/logout", "logout"); // 访问则退出登录
    hashMap.put("/kFind", "perms[sys:k:find]"); // 当前用户存在 sys:k:find 权限才允许访问
    shiroFilterFactoryBean.setFilterChainDefinitionMap(hashMap);
    shiroFilterFactoryBean.setLoginUrl("/login");
    shiroFilterFactoryBean.setUnauthorizedUrl("/"); // 当权限不允许时, 跳转的路径
    return shiroFilterFactoryBean;
}

```  
  
配置完毕后不存在sys:k:find权限的用户直接访问/kFind会被拦截.  
##### 注解授权 - 修复越权  
  
除了上面的方法, 我们也可以在PageController::kFind上面定义注解:  
```
@RequestMapping("/kFind")
@RequiresPermissions("sys:k:find") // 如果当前用户具备该权限, 那么才让访问.
public String kFind() {
    return "k_find"; // 定位到 /resources/templates/k_find.html 文件
}

```  
  
当然定义完毕后, 我们需要在ShiroAutoConfigruation类中进行定义该注解所需要的Bean：  
```
@Bean
public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
    DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
    advisorAutoProxyCreator.setProxyTargetClass(true);
    return advisorAutoProxyCreator;
}

@Bean
public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
    AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
    advisor.setSecurityManager(securityManager);
    return advisor;
}

```  
  
如果当前用户不存在sys:k:find权限, 那么会显示如下内容:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVKicbZv1UfYMiaE5etVowNDiasd6icJplWztoianbl0IlOHYgJTicwvLoxCkw/640?wx_fmt=png&from=appmsg "")  
  
image-20241011155902077.png  
  
并且IDEA中会收到抛出来的异常信息:  
```
org.apache.shiro.authz.AuthorizationException: Not authorized to invoke method: public java.lang.String com.heihu577.controller.PageController.kFind()

```  
  
那么这种情况我们应该如何处理呢？这里我们可以通过Spring全局异常来将其跳转到某个页面中去即可.  
```
package com.heihu577.exception;

@ControllerAdvice
public class ErrorHandler {
    @ExceptionHandler(AuthorizationException.class)
    public ModelAndView handleException(Exception e) {
        ModelAndView modelAndView = new ModelAndView("index"); // 认证失败跳转到主页
        modelAndView.addObject("exception", e);
        System.out.println("进入异常处理...");
        return modelAndView;
    }
}

```  
##### 手工授权 - 修复越权  
  
当然我们也可以使用subject进行判断, 代码如下:  
```
@RequestMapping("/kFind")
// @RequiresPermissions("sys:k:find")
public String kFind() {
    Subject subject = SecurityUtils.getSubject();
    if (subject.isPermitted("sys:k:find")) {
        return "k_find"; 
    } else {
        return "index";
    }
}

```  
#### Shiro 缓存使用  
  
我们看一下下面这个问题, 在MyRealm中增加输出语句:  
```
@Override
protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    String username = (String) principals.iterator().next(); // 得到已经登录成功的用户名, 实际上获取到的内容是 doGetAuthenticationInfo 方法中 new SimpleAuthenticationInfo(用户名, 用户密码, 当前Realm名称) 中的第一个参数
    Set<String> roles = roleMapper.queryRoleByUserName(username); // 通过用户名得到角色名称
    Set<String> permissions = permissionMapper.queryPermissionByUserName(username); // 通过用户名得到权限信息
    System.out.println("我在授权...."); // 增加该语句
    SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
    info.setRoles(roles); // 将数据库查询出来的信息封装到 AuthorizationInfo 中
    info.setStringPermissions(permissions);

    return info;
}

```  
  
那么我们登录随意一个用户进行测试:  
> 登录lisi:  
> 我在授权.... (显示12次)  
  
  
其原因则是我们/resource/templates/index.html中使用了<shiro:hasPermission>进行判断, 每使用一次<shiro:hasPermission>就会调用一次MyRealm::doGetAuthorizationInfo方法.  
  
下面在pom.xml文件中进行引入缓存:  
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-cache</artifactId>
</dependency>
<dependency>
    <groupId>net.sf.ehcache</groupId>
    <artifactId>ehcache</artifactId>
</dependency>
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-cache</artifactId>
    <version>1.4.1</version>
</dependency>
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-ehcache</artifactId>
    <version>1.4.1</version>
</dependency>

```  
  
当然了, 准备了ehcache就需要定义/resources/ehcache.xml文件:  
```
<?xml version="1.0" encoding="UTF-8"?>
<ehcache>
    <diskStore path="java.io.tmpdir/Tmp_EhCache"/>
    <defaultCache eternal="false" maxElementsInMemory="10000" overflowToDisk="false" diskPersistent="false"
                  timeToIdleSeconds="1800" timeToLiveSeconds="259200" memoryStoreEvictionPolicy="LRU"/>
</ehcache>

```  
  
随后我们在ShiroAutoConfiguration中进行配置:  
```
// ... 其他代码
@Bean
public EhCacheManager ehCacheCacheManager() {
    EhCacheManager ehCacheManager = new EhCacheManager();
    ehCacheManager.setCacheManagerConfigFile("classpath:ehcache.xml");
    return ehCacheManager;
}

@Bean
public SecurityManager securityManager(MyRealm myRealm, EhCacheManager ehCacheManager) { // 增加一个 EhCacheManager 参数
    DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
    securityManager.setRealm(myRealm);
    securityManager.setCacheManager(ehCacheManager); // 配置到 Realm 中去
    return securityManager;
}

```  
  
修改完毕后, 我们再次授权就不会每次都访问数据库了.  
#### SESSION 管理  
  
在 Shiro 中我们可以进行管理SESSION, 例如: 设置 SESSION 多少秒过期等操作.  
```
@Bean
public DefaultSessionManager getDefaultSessionManager() {
    DefaultSessionManager defaultSessionManager = new DefaultSessionManager();
    defaultSessionManager.setGlobalSessionTimeout(15); // 15 毫秒后 session 失效
    return defaultSessionManager;
}
@Bean
public SecurityManager securityManager(MyRealm myRealm, EhCacheManager ehCacheManager) {
    DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
    securityManager.setRealm(myRealm);
    securityManager.setCacheManager(ehCacheManager);
    securityManager.setSessionManager(getDefaultSessionManager()); // 将 Session Manager 放入到 Security Manager 中
    return securityManager;
}

```  
#### RememberMe  
  
我们日常的记住密码功能, 实现思路如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVMHdqT7PWzH6fbeqm85QyNJTajeSGdvTKNlONgtvLfaOHYwoicBtUxmw/640?wx_fmt=png&from=appmsg "")  
  
image-20241011205011371.png  
  
可以看到, 是基于COOKIE进行操作的.  
  
Shiro对页面访问的权限分为三个级别:  
- 未认证 - 可访问的页面, 例如: 登录入口.html, 注册入口.html  
  
- 记住我 - 可访问的页面, 例如: 个人信息.html  
  
- 已认证 - 可访问的页面, 例如: 转账.html  
  
而大概的流程如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV7pr21BL7eiazS3SMdrGFx1AnOrSkGHHGwraF7zUzNsBT9yC0lHX8mAg/640?wx_fmt=png&from=appmsg "")  
  
image-20241011210229970.png  
  
为了方便测试, 我们修改/resource/templates/login.html文件内容如下:  
```
<form action="/user/login" method="post">
    u: <input type="text" name="username"/><br>





    p: <input type="password" name="password"/><br>





    记住我: <input type="checkbox" name="rememberMe"><br>





    <span th:text="${msg}" style="color:red"></span>
    <input type="submit">
</form>

```  
  
因为rememberMe是基于Cookie的, 所以我们需要在SecurityManager中增加CookieManager, 那么我们在ShiroAutoConfiguration中进行定义:  
```
@Bean
public CookieRememberMeManager getRememberMeManager() { // 支持 RememberMe, 并设置 Cookie
    CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
    SimpleCookie simpleCookie = new SimpleCookie("rememberMe"); // 让服务器检查 rememberMe 键, 这里必须设置
    simpleCookie.setMaxAge(60); // 60 秒后过期
    cookieRememberMeManager.setCookie(simpleCookie);
    return cookieRememberMeManager;
}

@Bean
public SecurityManager securityManager(MyRealm myRealm, EhCacheManager ehCacheManager) { // 定义 SecurityManager
    DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
    securityManager.setRealm(myRealm);
    securityManager.setCacheManager(ehCacheManager);
    securityManager.setSessionManager(getDefaultSessionManager());
    securityManager.setRememberMeManager(getRememberMeManager()); // 设置 RememberMeManager
    return securityManager;
}

```  
  
随后我们在UserController::login页面中进行接收rememberMe传递来的数据:  
```
@PostMapping("/login")
public ModelAndView login(String username, String password, @RequestParam(defaultValue = "false", required = false) String rememberMe) {
    ModelAndView modelAndView = new ModelAndView();
    try {
        userService.checkLogin(username, password, rememberMe); // 传递给 userService
        modelAndView.setViewName("index");
    } catch (Exception e) {
        modelAndView.addObject("msg", "登陆失败!");
        modelAndView.setViewName("login");
    } finally {
        return modelAndView;
    }
}

```  
  
那么UserServiceImpl::checkLogin的定义如下:  
```
public void checkLogin(String username, String password, String rememberMe) throws Exception {
    Subject subject = SecurityUtils.getSubject();
    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
    if ("on".equals(rememberMe)) { // 如果选中, 那么直接设置 rememberMe 为 true
        token.setRememberMe(true);
    }
    subject.login(token);
}

```  
  
随后我们在ShiroAutoConfiguration中进行配置ShiroFilter的具体页面的权限分配:  
```
@Bean
public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
    ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
    shiroFilterFactoryBean.setSecurityManager(securityManager);
    Map<String, String> hashMap = new HashMap<>();
    hashMap.put("/", "user"); // 设置为 记住我 访问
    /**
     * anon 未认证可访问
     * user 记住我可访问 (已认证也可以访问)
     * authc 已认证可访问
     * perms 必须具备具体的权限才可以进行访问
     * logout 退出登录
     */
    hashMap.put("/login", "anon"); // login 支持匿名访问
    hashMap.put("/static/**", "anon"); // static 下的内容随便访问
    hashMap.put("/logout", "logout"); // 访问则退出登录
    hashMap.put("/kFind", "authc, perms[sys:k:find]"); // 当前用户已登录, 并且存在 sys:k:find 权限才允许访问
    shiroFilterFactoryBean.setFilterChainDefinitionMap(hashMap);
    shiroFilterFactoryBean.setLoginUrl("/login");
    shiroFilterFactoryBean.setUnauthorizedUrl("/");
    return shiroFilterFactoryBean;
}

```  
  
假设我们SESSION默认设置为1000毫秒就失效, 也就是1秒后就失效.  
  
那么这个案例, 当我们wangwu登录后 (勾选记住我), 主页面是可以进行访问的 (因为设置了记住我), 但是功能模块却访问不了 (因为设置了已认证). 如图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVk19QFOvbMtxoI0aK9XpDVrscdY3FLZbgROgsbtT8FDAfxCLicR2gUdg/640?wx_fmt=png&from=appmsg "")  
  
image-20241011214324971.png  
#### 多 Realm 配置  
  
对于多 Realm 配置也好理解, 参考下图即可:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVnh0aO9uicZ0n7e82VjNtwLYFnAB38U7iaOuFD1icTyKicYUdaXr1dl8rAg/640?wx_fmt=png&from=appmsg "")  
  
image-20241012102525409.png  
  
对于第一种业务场景: 当我们的用户表分布在两个不同的数据库时, 我们可以将两个数据库的信息封装到Realm中, 随后当token请求过来时,SecurityManager会从MySQL&&Oracle中拿到数据, 对token进行比对. 我们称这种方式为: 链式配置.  
  
对于第二种业务场景: 用户登录时, 指明登录的类型, 如果是User类型, 那么就会采用UserRealm, 去用户表中拿数据进行比对. 如果是Manager类型, 那么就会采用ManagerRealm, 去管理员表中拿数据进行比对. 我们称这种方式为: 分支配置.  
  
这两种不同的业务场景, 都是多Realm配置所实现的功能.  
##### 链式配置  
  
为了更好的清楚它们之间的关系, 我们需要创建一个新的项目, 以便清楚的知道它们之间的关系:  
  
pom.xml:  
```
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId> <!-- 引入 parent -->
    <version>2.5.3</version>
</parent>

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId> <!-- 从 parent 中引 thymeleaf -->
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId> <!-- 从 parent 中引 web -->
    </dependency>
    <dependency> <!-- 导入 shiro-spring, 会自动引入 shiro-core, shiro-web -->
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-spring</artifactId>
        <version>1.4.1</version>
    </dependency>
    <dependency> <!-- 引入 shiro 标签依赖 -->
        <groupId>com.github.theborakompanioni</groupId>
        <artifactId>thymeleaf-extras-shiro</artifactId>
        <version>2.1.0</version>
    </dependency>
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
    </dependency>
</dependencies>

```  
  
随后定义com.heihu577.config.ShiroAutoConfiguration:  
```
@Configuration
public class ShiroAutoConfiguration {
    @Bean
    public ManagerRealm managerRealm() { // 定义一个 ManagerRealm
        return new ManagerRealm();
    }

    @Bean
    public UserRealm userRealm() { // 定义一个 UserRealm
        return new UserRealm();
    }

    @Bean
    public DefaultWebSecurityManager securityManager() {
        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        Collection<Realm> realms = new LinkedList<>();
        realms.add(userRealm());
        realms.add(managerRealm());
        defaultWebSecurityManager.setRealms(realms); // 将 UserRealm ManagerRealm 同时放到 SecurityManager 中
        return defaultWebSecurityManager;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean() {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager());
        LinkedHashMap<String, String> linkedHashMap = new LinkedHashMap<>();
        linkedHashMap.put("/", "authc"); // 主页需要登录才能访问
        linkedHashMap.put("/index", "authc"); // 主页需要登录才能访问

        linkedHashMap.put("/static/**", "anon"); // 静态资源随意访问
        linkedHashMap.put("/login", "anon"); // 登录界面随意访问

        shiroFilterFactoryBean.setFilterChainDefinitionMap(linkedHashMap); // 将路由配置设置到 ShiroFilter 中
        shiroFilterFactoryBean.setLoginUrl("/login"); // 未登录默认跳转到 /login 中
        shiroFilterFactoryBean.setUnauthorizedUrl("/login"); // 未授权默认跳转到 /login
        return shiroFilterFactoryBean;
    }
}

```  
  
随后定义UserRealm && ManagerRealm, 内容如下:  
```
@Slf4j
public class UserRealm extends AuthorizingRealm {
    @Override
    public String getName() {
        return "UserRealm";
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        log.info("UserRealm::doGetAuthenticationInfo 认证...");

        AuthenticationInfo authenticationInfo =
                new SimpleAuthenticationInfo(upToken.getUsername(), "123456", getName()); // 如果密码是 123456 那么 UserRealm 登录成功
        return authenticationInfo;
    }
}

```  
  
可以看到,UserRealm这里提供的数据信息, 不管账号是多少, 只要密码是123456即可登录成功, 定义ManagerRealm定义如下:  
```
@Slf4j
public class ManagerRealm extends AuthorizingRealm {
    @Override
    public String getName() {
        return "ManagerRealm";
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        log.info("ManagerRealm::doGetAuthenticationInfo 认证...");

        AuthenticationInfo authenticationInfo =
                new SimpleAuthenticationInfo(upToken.getUsername(), "654321", getName()); // 如果密码是 654321 那么 ManagerRealm 登录成功
        return authenticationInfo;
    }
}

```  
  
如果密码是654321, 那么ManagerRealm即可登录成功. 配置两个比较简单的Realm进行测试.  
  
随后我们定义PageController:  
```
@Controller
public class PageController {
    @RequestMapping({"/", "/index"})
    public String index() {
        // 返回 index 主页面
        /* resources/templates/index.html 文件内容如下:
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>个人主页</title>
            </head>
            <body>
                <h3>Hello World!</h3>
            </body>
            </html>
        */
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        /* resources/templates/login.html 文件内容如下:
        	<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Title</title>
            </head>
            <body>
                   <form action="#" method="post">
                        <!-- 对 /login 发送 POST 登录请求 -->
                        user: <input type="text" name="username"><br>





                        pass: <input type="password" name="password"><br>





                        type: <input type="radio" value="User" name="loginType"> 普通用户
                              <input type="radio" value="Manager" name="loginType"> 管理员
                        <br>





                        <input type="submit" value="login">
                   </form>
            </body>
            </html>
        */
        return "login"; // 若是 get 形式访问, 那么直接返回 登陆表单 界面
    }
}

```  
  
当然也少不了SpringBoot主程序:  
```
@SpringBootApplication
public class MainApp {
    public static void main(String[] args) {
        ConfigurableApplicationContext ioc = SpringApplication.run(MainApp.class);
    }
}

```  
  
最终使用admin 111111进行登录, 控制台输出如下:  
```
2024-10-12 12:31:43.353  INFO 21884 --- [p-nio-80-exec-6] com.heihu577.config.realm.UserRealm      : UserRealm::doGetAuthenticationInfo 认证...
2024-10-12 12:31:43.353  INFO 21884 --- [p-nio-80-exec-6] com.heihu577.config.realm.ManagerRealm   : ManagerRealm::doGetAuthenticationInfo 认证...
2024-10-12 14:08:46.558 ERROR 21884 --- [p-nio-80-exec-7] com.heihu577.controller.UserController   : 登录失败!

```  
  
可以看到,UserRealm && ManagerRealm都进行了账号密码的认证处理,  
###### 源码分析  
  
下面我们通过源代码的形式, 看一下底层做了什么.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVtghVqoTHQ3juTRKVaGVp98UWkNd0pg4rf0B47wz6knO8HHZCibJ91UA/640?wx_fmt=png&from=appmsg "")  
  
image-20241012155019026.png  
  
将过程梳理如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVGkmqGo130HoHEiagLpkX5JBTAul3MiaPicVx0ibkwMLkdGF0np8mLdQibFQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241012155050906.png  
  
我们可以看到的是,token最终传递到ModularRealmAuthenticator::doAuthenticate方法中, 若我们在该方法中增加如下判断, 即可实现分支配置:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVmWRbeXfia7C3TXtLOibL43faBHNuELoOMVuR9s5iaiclOakCtYax4Nib7sg/640?wx_fmt=png&from=appmsg "")  
  
image-20241012160913980.png  
  
但是问题是, 图中的loginType我们从哪里进行获取呢？AuthenticationToken这个参数默认是UsernamePasswordToken, 这个里面只能封装用户名和密码信息, 并不能封装登陆类型信息, 所以在这里我们需要自定义token. 那么整体实现该功能流程如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVic5YxXluamSch2cAZzFYB46PXIzc2lxXlX89QgrnYnNOQMokfjmebdA/640?wx_fmt=png&from=appmsg "")  
  
image-20241012161930310.png  
##### 分支配置  
  
含义很简单, 我们需要如下情况:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVD9E2LCrubDoSgiapIqNxqBbQoGR2HGtYq6sJ8kIqs34VwRlQZgfakqg/640?wx_fmt=png&from=appmsg "")  
  
image-20241012164223556.png  
  
我们的自定义Realm已经完成, 所以在这里我们需要自定义Authenticator以及自定义Token, 那么我们先来自定义Token:  
```
public class MyToken extends UsernamePasswordToken {
    private String loginType;

    public MyToken(String username, String password, String loginType) {
        super(username, password);
        this.loginType = loginType; // 在 UsernamePasswordToken 原有基础上新增一个 loginType 属性
    }

    public String getLoginType() {
        return this.loginType;
    }

    public void setLoginType(String loginType) {
        this.loginType = loginType;
    }
}

```  
  
由于Token最终传递到ModularRealmAuthenticator::doAuthenticate方法中, 所以在这里我们需要一个子类, 来继承ModularRealmAuthenticator类, 并重写doAuthenticate方法:  
```
public class MyAuthenticator extends ModularRealmAuthenticator {
    @Override
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        Collection<Realm> realms = getRealms();

        Collection<Realm> myRealm = new ArrayList<>();
        MyToken myToken = (MyToken) authenticationToken; // 拿到 myToken
        String loginType = myToken.getLoginType();

        for (Realm realm : realms) { // 对所有 Realm 进行遍历
            // 当前的 Realm 只可能是 ManagerRealm && UserRealm, 而这两个 Realm 我们都重写了 getName 方法.
            if (realm.getName().startsWith(loginType)) {
                // 在这里我们就可以通过这两个 getName, 来对外部 HTTP 请求来的参数值进行判断
                myRealm.add(realm); // 满足条件, 那么直接将我们的 realm 添加进去
            }
        }

        if (myRealm.size() == 1) { // ModularRealmAuthenticator 类中是对 realms 做判断, 而我们这里对 myRealm 做判断
            return doSingleRealmAuthentication(myRealm.iterator().next(), authenticationToken);
        } else {
            return doMultiRealmAuthentication(myRealm, authenticationToken);
        }
    }
}

```  
  
定义完自定义Authenticator后, 我们需要将其设置到SecurityManager中, 如下:  
```
public MyAuthenticator getMyAuthenticator() {
    return new MyAuthenticator();
}

@Bean
public DefaultWebSecurityManager securityManager() {
    DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
    defaultWebSecurityManager.setAuthenticator(getMyAuthenticator()); // 将我们的自定义 authenticator 设置进去
    Collection<Realm> realms = new LinkedList<>();
    realms.add(userRealm()); // 自定义 Realm
    realms.add(managerRealm()); // 自定义 Realm
    defaultWebSecurityManager.setRealms(realms);
    return defaultWebSecurityManager;
}

```  
  
最后我们修改UserController中的登录逻辑如下:  
```
public class UserController {
    @PostMapping("/login")
    public String login(String username, String password, String loginType) {
        // 若是 POST 形式访问, 那么接收前台发送过来的账号密码信息, 使用 Subject 进行登录认证
        Subject subject = SecurityUtils.getSubject();
        try {
            MyToken myToken = new MyToken(username, password, loginType); // 使用自定义 token
            subject.login(myToken);
            return "index"; // 登录成功跳转到主页
        } catch (Exception e) {
            log.error("登录失败!");
            return "login"; // 登录失败跳转到登录页
        }
    }
}

```  
  
如果使用普通用户登录, 控制台输出:  
```
2024-10-12 16:57:08.850  INFO 19188 --- [p-nio-80-exec-2] com.heihu577.config.realm.UserRealm      : UserRealm::doGetAuthenticationInfo 认证...

```  
  
如果使用管理员用户登录, 控制台输出:  
```
2024-10-12 16:59:18.027  INFO 19188 --- [p-nio-80-exec-6] com.heihu577.config.realm.ManagerRealm   : ManagerRealm::doGetAuthenticationInfo 认证...

```  
## Shiro 底层分析  
### 基础环境搭建 - SpringBoot  
  
和上面我们学习 Shiro 使用的步骤一样, 在这里我们会启动一个干净的环境.  
  
pom.xml:  
```
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId> <!-- 引入 spring-boot-starter-parent -->
    <version>2.5.3</version>
</parent>

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId> <!-- 引入 web 模块 -->
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId> <!-- 引入 thymeleaf 模块 -->
    </dependency>
    <dependency>
        <groupId>com.github.theborakompanioni</groupId>
        <artifactId>thymeleaf-extras-shiro</artifactId> <!-- 引入 shiro 标签 -->
        <version>2.1.0</version>
    </dependency>
    <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-spring</artifactId> <!-- 引入存在漏洞版本的 shiro -->
        <version>1.2.3</version>
    </dependency>
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId> <!-- 引入 commons-collections 链 -->
        <version>3.2.1</version>
    </dependency>
</dependencies>

```  
  
引入完毕后, 紧接着我们准备我们的ShiroAutoConfiguration:  
```
@Configuration
public class ShiroAutoConfiguration {
    @Bean
    public MyRealm getMyRealm() {
        return new MyRealm(); // 用于实现, 账号任意, 密码heihu577登录成功的机制
    }

    @Bean
    public ShiroDialect shiroDialect() {
        return new ShiroDialect(); // 用于支持 shiro 标签的使用
    }

    @Bean
    public CookieRememberMeManager getRememberMeManager() { // 支持 RememberMe, 并设置 Cookie
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
        SimpleCookie simpleCookie = new SimpleCookie("rememberMe"); // 让服务器检查 rememberMe 键, 这里必须设置
        simpleCookie.setMaxAge(60); // 60 秒后过期
        cookieRememberMeManager.setCookie(simpleCookie);
        return cookieRememberMeManager;
    }

    @Bean
    public DefaultWebSecurityManager getSecurityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(getMyRealm()); // 设置为自定义 Realm, 进行校验
        securityManager.setRememberMeManager(getRememberMeManager()); // 设置 RememberMe 控制器, 用于支持 RememberMe 功能
        return securityManager;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean() {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(getSecurityManager()); // 设置安全管理器

        HashMap<String, String> filterChainDefinitionMap = new HashMap<>(); // 准备过滤好需过滤的 URL
        filterChainDefinitionMap.put("/", "user"); // 设置为记住我可访问, 如果不是记住我的状态, 后面会跳转到登录页面
        filterChainDefinitionMap.put("/index", "user"); // 设置为记住我可访问, 如果不是记住我的状态, 后面会跳转到登录页面
        filterChainDefinitionMap.put("/**", "authc"); // 其他所有页面必须已认证才可以访问
        filterChainDefinitionMap.put("/login", "anon"); // 登陆页面, 所有人可访问
        filterChainDefinitionMap.put("/user/login", "anon"); // 登录处理口, 所有人可访问
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);

        shiroFilterFactoryBean.setLoginUrl("/login"); // 默认登录页面
        shiroFilterFactoryBean.setUnauthorizedUrl("/login"); // 未认证的情况, 也跳转到登录页面
        return shiroFilterFactoryBean;
    }
}

```  
  
当然了, 这里我们也需要引入我们的自定义Realm:  
```
public class MyRealm extends AuthorizingRealm {
    @Override
    public String getName() {
        return "MyRealm";
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null; // 授权过程暂且不实现
    }

    @Override // 认证时所调用的方法
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        String username = token.getUsername();
        // 用户名任意, 密码为 heihu577 则登录成功
        return new SimpleAuthenticationInfo(username, "heihu577", this.getName());
    }
}

```  
  
其自定义Realm的实现很简单, 我们只重写了doGetAuthenticationInfo认证方法, 让其账户名任意, 密码只要是heihu577就可以登录成功.  
  
定义所需要的控制器:  
```
// 专门应用于页面的控制器
@Controller
public class PageController {
    @GetMapping("/login")
    public String login() {
        return "login";
        /*
        	resources/templates/login.html 定义如下:
        	<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>用户登录</title>
                <base href="/">
            </head>
            <body>
                <form action="user/login" method="post"> <!-- 这里发送的控制器请求在 UserController 进行接收 -->
                    u: <input type="text" name="username"><br>





                    p: <input type="password" name="password"><br>





                    rememberMe: <input type="radio" name="rememberMe"><br>





                    <input value="登录" type="submit">
                </form>
            </body>
            </html>
        */
    }
    @RequestMapping({"/", "/index"})
    public String index() {
        return "index";
        /*
        	resources/templates/index.html 定义如下:
        	<!DOCTYPE html>
            <html lang="en"xmlns:shiro="http://www.pollix.at/thymeleaf/shiro">
            <head>
                <meta charset="UTF-8">
                <title>主页面</title>
            </head>
            <body>
                <!-- 打印出当前用户名 -->
                <h3>Hello User: <shiro:principal/></h3>
            </body>
            </html>
        */
    }
}
// 登录处理请求的控制器
@Controller
@RequestMapping("/user")
public class UserController {
    @PostMapping("/login")
    public String login(String username, String password, boolean rememberMe) {
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);
        usernamePasswordToken.setRememberMe(rememberMe); // rememberMe 的设置根据前端表格请求来决定.
        try {
            subject.login(usernamePasswordToken); // login 中有 序列化 | 反序列化操作
            System.out.println("--------登陆成功!");
            return "index"; // 登录成功跳转到主页面
        } catch (AuthenticationException e) {
            System.out.println("--------登陆失败!");
            return "login"; // 登录失败跳转到登录表单
        }
    }
}

```  
  
定义完毕后, 我们定义MainApp进行SpringBoot的启动:  
```
@SpringBootApplication
public class MainApp {
    public static void main(String[] args) {
        ConfigurableApplicationContext ioc = SpringApplication.run(MainApp.class);
    }
}

```  
### ShiroFilterFactoryBean 工作原理  
  
在我们之前的配置所了解到,ShiroFilterFactoryBean是用来配置一个Filter过滤器的, 但是为什么只要定义ShiroFilterFactoryBean这么一个Filter, 那么就会自动注入到SpringBoot容器中？它的工作原理是怎么样的？  
  
为了思路清晰, 所以我们需要研究SpringBoot底层是如何自动创建Filter的, 笔者在这里准备建立一个新项目, 其中准备MyAutoConfiguration, 配置如下:  
```
@Configuration
public class MyAutoConfiguration {
    @Bean
    public FilterRegistrationBean filter01() {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter((request, response, chain) -> { // 使用 lambda 表达式
            System.out.println("filter01...");
            chain.doFilter(request, response);
        });
        filterRegistrationBean.addUrlPatterns("/*"); // 指明路径
        filterRegistrationBean.addUrlPatterns("/filter01"); // 指明路径, 多加一个过滤器进行匹配
        return filterRegistrationBean;
    }

    @Bean
    public Filter filter02() { // 没指明路径
        return (request, response, chain) -> {
            System.out.println("filter02...");
            chain.doFilter(request, response);
        };
    }
}

```  
  
这两个filter很简单:  
  
filter01这个Bean是通过SpringBoot官方API提供的FilterRegistrationBean进行注入Filter. 并且这里指明了该Filter过滤的路径为:/*与/filter01.  
  
filter02这个Bean是通过创建一个Filter的Bean来指明一个Filter, 该Filter并没有定义过滤路径.  
  
下面我们正常访问主页面看一下执行效果:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV5E0QCaESINepYZRQtQOTbPFoMaxw7H3uXyQkzkB5EaepRJe4zWzmsQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241014121940830.png  
  
我们可以看到的是,filter01 && filter02都已经成功注入到了SpringBoot容器中, 并访问/filter01之后, 这两个filter都响应到了.  
  
那么我们接下来会想,filter02并没有配置UrlPatterns, 而他注入到SpringBoot容器中的UrlPatterns又是什么呢？  
#### SpringBoot 注入 filter 原理  
  
在我们之前的SpringBoot基础中有提到, SpringBoot底层会创建一个Tomcat容器, 其中Tomcat容器的调用链如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVUPHczYUB82Wf2maxoRsj828tzZIEvW38SGgoQGXmEfPr67TkSgjgfw/640?wx_fmt=jpeg&from=appmsg "")  
  
这张图说明了SpringBoot创建Tomcat容器并Spring创建Bean的整个过程, 在图中我们可以看到ServletWebServerApplicationContext::onRefresh方法会创建Tomcat并启动, 过程如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVTTQj9kQ6p12xQeg6bXBltZYt7sy143BVhYwpQES59GIfcdynQyB5DQ/640?wx_fmt=png&from=appmsg "")  
  
image-20241014141511053.png  
  
在ServletWebServerApplicationContext::createWebServer方法中, 会对Tomcat进行启动操作, 但是通过上图我们可以看到,factory.getWebServer(getSelfInitializer())这个方法会将ServletWebServerApplicationContext:selfInitialize方法当作第一个参数调用进去中, 我们并不需要关心什么时候调用到该方法的, 因为对于容器的初始化工作会走到这里.  
##### getServletContextInitializerBeans 方法分析  
  
下面我们来看一下红框圈住的getServletContextInitializerBeans方法做了什么:  
```
protected Collection<ServletContextInitializer> getServletContextInitializerBeans() {
    return new ServletContextInitializerBeans(getBeanFactory());
}

```  
  
这个方法返回了Collection<ServletContextInitializer>实例可以看到,ServletContextInitializerBeans是返回值, 那么该返回值一定是Collection实例, 我们看一下ServletContextInitializerBeans类的关系图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVOj8o01qcHLhfWeEd68JH2Z5Og2kRZKfEFElVkiaDib5Cz7vSe3VkJsBg/640?wx_fmt=png&from=appmsg "")  
  
image-20241014153628465.png  
  
实现了Collection接口, 那么我们看一下这个类的构造方法做了什么:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVannvRvWibZfCNChS8mb2iahnFfOUCq0aErHgShiaaibfp0vGMibgj50028Q/640?wx_fmt=png&from=appmsg "")  
  
image-20241014155728685.png  
  
最终会对initializers这个LinkedMultiValueMap进行增加键值操作,LinkedMultiValueMap是由Spring提供的Map, 我们看一下LinkedMultiValueMap是什么样的:  
```
LinkedMultiValueMap<String, String> linkedMultiValueMap = new LinkedMultiValueMap<>();
linkedMultiValueMap.add("key1", "test01");
linkedMultiValueMap.add("key1", "test02");
linkedMultiValueMap.add("key2", "test03");
System.out.println(linkedMultiValueMap); // {key1=[test01, test02], key2=[test03]}

```  
  
与常规Map不同的是, 该Map存储类型是{键1=ArrayList,键2=ArrayList...}这样的, 那么我们看一下最终这个initializers的数据结构是什么样的:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVfs4hn6ibxUiaWpoIXQxKDYbgcQUXxrxZ1AokQN6fFbEgWRlick1pvia5hA/640?wx_fmt=png&from=appmsg "")  
  
image-20241014160610001.png  
  
那么接下来分析一下addAdaptableBeans方法做了什么.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVZzJj169AI1hibUDKucqo1hufICZpbAekZGliaMnCqCngnuVrMtTTWKqg/640?wx_fmt=png&from=appmsg "")  
  
image-20241014162844597.png  
  
可以从图中看到, 最终将当前容器所有的实例化Filter的Bean, 封装为了FilterRegistrationBean, 仍然加入到了initializers这个成员属性中去, 那么当前的initializers属性结果如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVTfYa4LQib46EAlLOZRm4eAMudu2pWZ3jKWibiccsdU8Lr8Gvwf6BarSDA/640?wx_fmt=png&from=appmsg "")  
  
image-20241014163159127.png  
  
其中我们的filter01, filter02成功的加入到了该成员属性中去! 而在每一次对ServletContextInitializerBeans实例进行遍历时, 就会调用到iterator()方法, 该方法定义如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVibFJzKtV17oq6FibG6PQuNBYB1JUs0q2zNREEnWCbrDvTJ2icLSl5F14g/640?wx_fmt=png&from=appmsg "")  
  
image-20241014163848152.png  
  
到现在我们终于理解了, 为什么filter02仅仅只返回了一个Filter, 却可以直接的注入到我们的SpringBoot容器中去, 原来一个普通的Filter会被FilterRegistrationBeanAdapter进行创建成一个FilterRegistrationBean! 当然现在还没有开始注入, 真正的注入点还是回到我们之前的遍历点.  
##### 注入机制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV5MYDh1zAgIjUqBEQzlT34EbeE58pVKceVbibwM09Pk4Uz2aYf51mH2g/640?wx_fmt=png&from=appmsg "")  
终于把getServletContextInitializerBeans方法分析完毕了, 而我们知道,FilterRegistrationBean是ServletContextInitializer的子类, 而调用它的onStartUp过程如下:![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV16jRQJmxy1VVBE1KCyW83aMNKuEVicc065Xvw0S3kicSO7jOWTWiavZtg/640?wx_fmt=png&from=appmsg "")  
可以从图中直观的看到我们增加Filter的完整调用流程了, 只不过还有一个问题, 我们的filter02是没有配置匹配路径的, 下面我们来看一下configure方法对路径的处理:  
```
protected void configure(D registration) {
    registration.setAsyncSupported(this.asyncSupported);
    if (!this.initParameters.isEmpty()) {
        registration.setInitParameters(this.initParameters); // 设置 InitParameter 参数
    }
}

@Override
protected void configure(FilterRegistration.Dynamic registration) {
    super.configure(registration);
    // ... 其他代码
    if (servletNames.isEmpty() && this.urlPatterns.isEmpty()) {
        // 当 servletName 没有配置, urlPatterns 没有配置, 则会设置为默认的路径配置
        // private static final String[] DEFAULT_URL_MAPPINGS = { "/*" };
        registration.addMappingForUrlPatterns(dispatcherTypes, this.matchAfter, DEFAULT_URL_MAPPINGS);
    }
    // ... 其他代码
}

```  
  
如果当前Filter并没有给具体的路径的话, 就会给出默认的/*, 至此, 整个Filter注入机制梳理清晰.  
#### ShiroFilterFactoryBean 机制  
  
回到我们的环境中, 我们来看一下ShiroFilterFactoryBean的类结构.![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV8WDgtxEGtQNk7JzXyjiaicLfMutRxmoiamzOSG3BPVyQT8ndiboek9PNUA/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到的是,ShiroFilterFactoryBean一共实现了两个Spring的接口, 分别是FactoryBean && BeanPostProcessor, 这两个接口相信大家也不陌生,FactoryBean是工厂类, 而BeanPostProcessor是后置处理器.  
> 基础部分参考: https://mp.weixin.qq.com/s/bCL9M4a5VD0lWNWiuzWX8Q  
  
##### FactoryBean::getObject 得到了什么  
  
当Spring扫描所有Bean时, 如果发现该Bean是属于FactoryBean, 那么就会调用该FactoryBean的getObject方法, 而ShiroFilterFactoryBean::getObject方法中定义的方法如下:  
```
public Object getObject() throws Exception {
    if (instance == null) {
        instance = createInstance(); // 调用 createInstance 方法
    }
    return instance;
}

protected AbstractShiroFilter createInstance() throws Exception {
    SecurityManager securityManager = getSecurityManager();
    if (securityManager == null) {
        String msg = "SecurityManager property must be set.";
        throw new BeanInitializationException(msg);
    }
    if (!(securityManager instanceof WebSecurityManager)) {
        String msg = "The security manager does not implement the WebSecurityManager interface.";
        throw new BeanInitializationException(msg);
    }
    FilterChainManager manager = createFilterChainManager();
    PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();
    chainResolver.setFilterChainManager(manager);
    return new SpringShiroFilter((WebSecurityManager) securityManager, chainResolver); // 最终返回 SpringShiroFilter 实例
}

private static final class SpringShiroFilter extends AbstractShiroFilter {
    protected SpringShiroFilter(WebSecurityManager webSecurityManager, FilterChainResolver resolver) {
        super();
        if (webSecurityManager == null) {
            throw new IllegalArgumentException("WebSecurityManager property cannot be null.");
        }
        setSecurityManager(webSecurityManager);
        if (resolver != null) {
            setFilterChainResolver(resolver);
        }
    }
}

```  
  
而我们打开SpringShiroFilter类图, 我们就可以看到, 该类是一个Filter:![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVtgCYib7WBLBEuNa6H8QXxgfibBLQaicJrdS2qG1KPDDtHH2l2uw9scD3g/640?wx_fmt=png&from=appmsg "")  
那么, 该 Filter 会注入到我们的 WEB 容器中. 并且路径匹配为 /*.  
##### OncePerRequestFilter  
  
OncePerRequestFilter这个Filter是SpringBoot提供的, 它确保了在一次完整的HTTP请求中, 无论请求经过多少次内部转发, 过滤器的逻辑都只会被执行一次. 笔者在这里定义如下:  
```
@Component // 让 SpringBoot 扫描到
@WebFilter(urlPatterns = "/*") // 定义是一个 Filter, 并且定义 url 解析规则
public class MyFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("Filter");
        filterChain.doFilter(request, response);
    }
}

```  
  
随后我们随机访问, 即可在控制台中输出Filter, 在这里笔者就不贴图了. 而我们的SpringShiroFilter也是继承于OncePerRequestFilter, 所以当每次请求过来时, 会调用AbstractShiroFilter::doFilterInternal方法.  
#### SpringShiroFilter 运行原理分析  
  
那么下面我们开始分析SpringShiroFilter到底做了什么事, 从我们最开始的Shiro配置代码段开始:![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV1bLnOoS3Qt5S88nF1icvdtQFEPRAQUjXj481Pib6udOf5JzMqQVpateA/640?wx_fmt=png&from=appmsg "")  
可以看到的是, 我们的配置信息代码段, 只不过是对该类进行了一系列设置, 设置之后, 由于该类是工厂类 (FactoryBean), 所以会调用该类的getObject方法.  
> 功能总结: 从配置文件中进行配置 ShiroFilterFactoryBean, 只是在对 ShiroFilterFactoryBean 的属性做赋值处理.  
  
##### getObject 核心逻辑  
###### FilterChainManager::DefaultFilterChainManager  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVmujiaKfUBPV9na6PdDEUwYWibAkRY0gS092Syp0BBlZreibQHhhuA5z3w/640?wx_fmt=png&from=appmsg "")  
  
image-20241014194426754.png  
> 功能总结:  
> DefaultFilterChainManager 维护了两个属性: filters, filterChains  
> filters: 是 Shiro 本身就存在的 Filter 数组, 记载权限与对应Filter的关系, 例如: anon 对应了 AnonymouseFilter  
  
  
如类名一样,DefaultFilterChainManager::filters成员属性放置了Shiro自带的权限校验的Filter. 一共有11个Filter在其中. 那么我们继续往下观察.![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaV57dQRyibSpsOBOtguyrTpPl6ibKWecthOkXC6PjmW6617pEyxdTKVpSw/640?wx_fmt=png&from=appmsg "")  
  
  
接下来这个applyGlobalPropertiesIfNecessary方法做的事情, 则是将刚才11个Shiro提供的默认Filter进行遍历. 判断这11个Filter中, 是否是AccessControlFilter, AuthenticationFilter, AuthorizationFilter的实例, 如果是的话, 那么将ShiroFilterFactoryBean::对应属性设置到具体Filter中去.  
  
而ShiroFilterFactoryBean::对应属性在我们的ShiroAutoConfiguration配置文件中, 是由程序员自己设置的, 我们在刚开始也讲过了.  
> 遍历 filters, 设置特殊 filter 中的属性值为程序员在配置类中定义的值.  
> 例如:  
> shiroFilterFactoryBean.setLoginUrl("/login"); // 默认登录页面  
> shiroFilterFactoryBean.setUnauthorizedUrl("/login"); // 未认证的情况, 也跳转到登录页面  
> 会设置到 AuthorizationFilter, AccessControlFilter 中去.  
  
  
那么我们接着往下看:![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6ic0COibiavmjQHsRpiaaR1EaVX5iccjZfgpgq7o2scmoNr0LOrq5nkfiaDvjAS8y5zFmTgIrhF85YIdvQ/640?wx_fmt=png&from=appmsg "")  
  
  
乍一看感觉流程很复杂, 但其实我们将其梳理简单的话是这样的:  
```
{("/","user"),("/index","user"),("/**","authc"),("/login","anon"),("/user/login","anon")} 
这是当前已经配置好的 Map, 通过 Value 值, 找到对应的 Filter, 例如: user 对应了 UserFilter, /** 对应了 userFilter...

最终生成如下 Map, 作为 filterChain 的属性:

{("/", SimpleNamedFilterList[UserFilter]), ("/index",[UserFilter]),("/**",[FormAuthenticationFilter])...}

```  
> 处理 filterChains, filterChains 是由如下配置生成出来的  
> filterChainDefinitionMap.put("/", "user");  
> ...  
  
### Ending...  
  
由于篇幅限制, 笔者将发布《Java 安全 | 从 Shiro 底层源码看 Shiro 漏洞 (下)》，请大家陆续关注...  
  
