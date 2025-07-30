#  SpringSecurity权限绕过漏洞-好玩   
原创 A1xxNy  猎洞时刻   2024-12-24 13:44  
  
## 一、spring security 简介  
  
        spring security 的核心功能主要包括：  
- 认证 （你是谁）  
  
- 授权 （你能干什么）  
  
- 攻击防护 （防止伪造身份）  
  
-   
    SpringSecurity和Apache shiro一样，都是安全框架，负责整个系统的认证和授权。  
  
    那有师傅就要问了，明明shiro之类的漏洞更多，他们凭什么叫安全框架？其实原因就是SpringSecurity和Apache shiro一样都会使用很少的配置代码，就能对系统的全部路径、全部接口进行访问权限和认证的配置。如果不使用安全框架，你自己去写安全认证代码，可能代码又臭又长，并且可能漏洞百出。  
  
还有师傅在复现POC的时候，经常发现路径会带;.css 、 / 、 /;../、/index/../admin 之类，这些其实都是为了绕过安全管理框架的匹配(也包括开发自写的权限鉴定匹配)，从而造成访问权限的绕过。  
  
  
对于SpringSecurity的绕过，主要分为三大类。  
  
1.antMatchers 配置认证绕过  
  
2.regexMatchers 配置认证绕过  
  
3.useSuffixPatternMatch 绕过  
  
下面的演示就是，如果无需登录访问接口绕过成功，就直接返回内容。  
  
如果绕过失败，就直接弹出登录窗口。  
  
一、antMatchers 配置认证绕过  
  
代码部分解释：  
- .antMatchers("/admin").hasRole("ADMIN")  
：仅允许ADMIN  
角色的用户访问/admin  
。  
- .antMatchers("/**").permitAll()  
：允许所有用户访问应用中的所有其他路径。  
```
@EnableWebSecurity
@Configuration
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 配置从内存中加载认证信息
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder)
                .withUser("admin")
                .password(passwordEncoder.encode("123456"))  // 使用加密后的密码
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password(passwordEncoder.encode("123456"))  // 使用加密后的密码
                .roles("USER");
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()  // 使用 Spring Security 默认的登录页面
                .and()
                .httpBasic();
    }
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774jR1ASrawLRT1BuW20EglViaGhJRqLXj3746ZxibEG84dJlOrkPECBnsw/640?wx_fmt=other&from=appmsg "")  
  
全部接口分为下面四个：  
  
/admin  
  
/admin/work  
  
/user  
  
/user/wrok  
# 实战绕过  
  
/admin 需要登录  
  
/admin? 绕过失败-需要登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774y8P7PcBficAplicRrheSd1bOHPRLC9UcHicaU6PCxeUiaIjFyvabnBeiaPw/640?wx_fmt=png&from=appmsg "")  
  
  
/admin/ 绕过成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774poTEr6UsB6sCepILIUwWZM9560DR7Igic2J7K4QUSyJyb6q7lFTDe3w/640?wx_fmt=png&from=appmsg "")  
  
/admin/work 绕过成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I17740gr8hTC3vRFd7vra9a9yIicsEQc5VMGh2GhbLhpibp3pEMPYbGSJGDzw/640?wx_fmt=png&from=appmsg "")  
  
/admin/??? 绕过成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I177416a52ADNNHLt2ZUtY5ZV97lfL6uBByeFo4IZV3YxVaRlia9iba60guxg/640?wx_fmt=png&from=appmsg "")  
## 其他路径测试  
  
对于/user/和/user/work也可以直接访问的，因为本身也做了路径匹配。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I17744WsPN2CayFZIfz9War5LYmSSeXW2trWPZ5Qghibwr5AJSmeXxsKZoeA/640?wx_fmt=png&from=appmsg "")  
  
但是对于没有做路径匹配的，也可以直接访问！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774KP0rBwiaVJKLKt0NQjoG49htvspT4u00SXwnP6iaEQkPH0AsYLOE3vrQ/640?wx_fmt=png&from=appmsg "")  
  
总结  
  
在使用  
.antMatchers()进行鉴权，如果写的配置存在错误，就会存在多种绕过方式，比如后缀添加斜杠等方式。  
  
# 修复方案：  
  
mvcMatchers("/admin").access("hasRole('ADMIN')")  
  
或者使用  
  
antMatchers("/admin/**").access("hasRole('ADMIN')")  
  
写法防止认证绕过。  
  
  
regexMatchers 配置认证绕过  
  
代码部分解释：  
1. .regexMatchers("/admin").access("hasRole('ADMIN')")  
-   
- 这条规则要求访问/admin  
路径的请求必须具有ADMIN  
角色。  
1. .antMatchers("/**").access("anonymous")  
-   
- 这条规则允许所有请求通过，**不需要身份验证**  
，即匿名用户可以访问所有路径。  
- anonymous  
  
允许未登录的用户访问所有路径，这意味着没有进行身份验证的用户也能访问所有的请求。  
```
@EnableWebSecurity
@Configuration
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 配置从内存中加载认证信息
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder)
                .withUser("admin")
                .password(passwordEncoder.encode("123456"))  // 使用加密后的密码
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password(passwordEncoder.encode("123456"))  // 使用加密后的密码
                .roles("USER");
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .regexMatchers("/admin").access("hasRole('ADMIN')")
                .antMatchers("/**").access("anonymous")
                .and()
                .formLogin()  // 使用 Spring Security 默认的登录页面
                .and()
                .httpBasic();
    }
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774jg6xMXpAkXLYY1XnKCavpibrcVXXsFNZbUX1s00ht8yq125CiabsM0Gw/640?wx_fmt=other&from=appmsg "")  
  
全部接口分为下面四个：  
  
/admin  
  
/admin/work  
  
/user  
  
/user/wrok  
# 绕过测试  
  
/admin 需要登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774zjjFg7Tarujby9LPibHrdeAiaNKuwL1pibYOnl3Ad0FKnLpZMp0UxDy6w/640?wx_fmt=png&from=appmsg "")  
  
/admin;  报错  
  
/admin;css 报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774SxXAEaL2BRkD3qe9GDA3dTMpKHCCsQr4ZsiagEc7icYw9OeuSS6gEictg/640?wx_fmt=png&from=appmsg "")  
  
/admin/ 直接绕过鉴权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774QzPpw9ictP6R85fEcYtZqmgiafETWjKKBvYJDxqo7meO0icuqnJM8eV5A/640?wx_fmt=png&from=appmsg "")  
  
/admin? 直接绕过鉴权  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I177419hCCyzibDIib2lllDDXj7N4zpiaibuWLOJLppVIk1rOUHdkEUlDPH8p6Q/640?wx_fmt=png&from=appmsg "")  
  
  
非设置路径，可以直接全部访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774icl5zOCpmAZRSP16fibXtpSg69RHpVYibcwSZricM9ucOhJW0CyC8hjfPQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774NXQIACtmXv6qicHNndq9JMxFfw3C466pkko0nZqibn3xp3YKiazAtYACw/640?wx_fmt=png&from=appmsg "")  
  
如果不存的话会报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774YZ1XxRl5wrupqWoZdEP4LLjyjbibibicKy7AHE3nCu4bNWWeLDrFRku5Q/640?wx_fmt=png&from=appmsg "")  
  
  
总结  
  
在使用  
.regexMatchers()进行鉴权，如果写的配置存在错误，就会存在多种绕过方式，比如后缀添加斜杠和添加问号直接绕过。  
#   
# 修复方案  
  
Matchers没使用类似/test.*  
的方式，在传入/test?  
时候，正则会匹配不上，不会命中/test  
的规则。  
  
.regexMatchers("/test.*?").access("hasRole('ADMIN')")  
#   
# useSuffixPatternMatch 绕过  
# 这个是一个spring-webmvc低版本造成的漏洞，在低版本中  
  
useSuffixPatternMatch  
  
配置默认值为  
true  
  
，表示使用后缀匹配模式匹配路径。  
  
如  
/path/abc  
  
路由也会允许  
/path/abc.xxx  
  
、/path/abc.asas  
等增加  
.xxx  
  
后缀形式的路径匹配成功。  
```
需要满足条件：springboot <= 1.5.22.RELEASE
对应的mvc版本，即为<=4.3.25
```  
  
实战测试  
  
修改springboot的版本为1.5.22.RELEASE，这样对应的spring-web的mvc版本就为4.3.25, 是存在这个漏洞的。  
  
这里注意，修改springboot的版本，相关是spring组件版本都会进行修改，这里就是降低，并且springboot 1.x 只能低版本jdk运行，记得修改为jdk8！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774nzNF16zWFNn5HrL34bVKcgsmTylmq0amMGOZp7xycoa3QKiaIawGayw/640?wx_fmt=png&from=appmsg "")  
#   
  
全部接口分为下面四个：  
  
/admin  
  
/admin/work  
  
/user  
  
/user/wrok  
  
  
regexMatchers无漏洞写法配置测试-绕过失败  
  
就是这种配置呢，就是本身不存在漏洞的，就是  
正确写法，但是因为Spring MVC版本在<=4.3.25导致存在了漏洞，下面进行验证猜测。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774lTHuVLnibzkH0nriagPLOqhsa57icP50Vsdl6JCPWNDVe3c9Mt5bM8Nug/640?wx_fmt=png&from=appmsg "")  
  
  
/admin/和/admin?和/index/../admin/ 都无法绕过了！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774PSwmlhFib97cmykic3Xn10UEuia3lhBEhscibFiaibKmAQkccJ2c3ibgP695A/640?wx_fmt=png&from=appmsg "")  
  
但是/admin.sdasd也不能绕过。。。  
  
服了，还是得添加上那个，其他路径可以通过的代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774VO5J2wcSpKRic4pMSraaw33DNYiagicMXaxmcjQJX4714icDHrh2yps25Q/640?wx_fmt=png&from=appmsg "")  
  
结果还是无法绕过！！！  
  
/admin/和/admin?和/index/../admin/ 都无法绕过了！！！  
  
/admin.dasda失败！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774uiavhD6tDRayMchCRaCtWPibiaxvPdVaYSIAq4sia2ibHpwyBdUuRnqK3eA/640?wx_fmt=png&from=appmsg "")  
  
这里就发现就算是低版本存在绕过漏洞，但是如果使用的  
regexMatchers  
的写法，就会导致无法绕过。  
#   
  
# antMatchers无漏洞写法配置测试-绕过成功  
# 这里改写成使用antMatchers进行权限的判定，当然，下面的配置也是正确写法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I17743Yh1APvOCOSJywC1zpyRzUpqKPD6G9RqD2zartzEvJZUiajcOCctbYQ/640?wx_fmt=png&from=appmsg "")  
  
/admin/   /admin?   /admin/work 全部失败  
  
唯独！！！  
  
http://127.0.0.1:8082/admin.dasda  
绕过成功 ！！！（利用漏洞成功，在后面添加任意后缀进行绕过）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I17748tc0f5Qs0JWUbJ26UdXm90CKqicOBSIPIlibkXCoGhibQeq758Mg053uQ/640?wx_fmt=png&from=appmsg "")  
  
  
# 总结  
  
如果Spring MVC版本在<=4.3.25，这种情况下，如果后端是使用的antMatchers进行匹配，无论是写的防护多好，都会存在漏洞！如果是regexMatchers无漏洞写法，就没法绕过！！  
  
  
版本问题，可以直接看Spring MVC版本，也可也看springboot的版本  
springboot <= 1.5.22.RELEASE也行！  
  
  
  
  
                     
#  第二期漏洞挖掘培训课表  
  
     目前  
猎洞时刻漏洞挖掘第二期已经刚开课，涉及  
企业赏金SRC，众测赏金，线下项目渗透和安全行业工作能力提升，  
目前价格仅需1299，每期都可以永久学习，并且赠送内容200+的内部知识星球，  
保证无保留教学，酒香不怕巷子深，可以打听已经报名学员，我这边是否全程干货！绝对对得起师傅们花的钱！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibLa2nWbr7dz1mZbLD0Z5V8sJBObRqNFjJeQgBBtXNj2viaYbzHRwHpJOH4iaVMaguHQfpv6Yt8G8jg/640?wx_fmt=png&from=appmsg "")  
 ![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibLa2nWbr7dz1mZbLD0Z5V8Ip69tIWtNziawm2GsSicwC8KYVpynb35BdovzGWO4j1QiccBY92F7s68g/640?wx_fmt=png&from=appmsg "")  
     
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibLa2nWbr7dz1mZbLD0Z5V8PHRMTF6ibEfr6p28RWhBBuC35KUy9dCck6Dzf01lCvEGXp1pZAkWGfw/640?wx_fmt=png&from=appmsg "")  
    
  
     一句话，一千出头的价格，最对最强的性价比，绝对是我无保留教学，童叟无欺，全靠真实无保留教学，才能快速吸引这么多学员的信任！****  
  
**有师傅之前被**  
**割韭菜课程坑怕过**  
**，来我这里报名后，不仅价格便宜不少，内容全程干货教学，直接逐帧学习，无论是赏金挖掘还是工作项目，都进步神速！**  
  
**以下均为师傅们真实反馈！！无任何造假内容****！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I1774ZolqqbDqficaHTiaG2YKMzVI1oUl8RyibIc5KV09sHicNic7ZJNVGaYFYKA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8OoZc1tP1ibRaj24tc2wJE9ibgJmksjy652G26Bh6XfErXpE3CQF2UbJ7lORvKzdsXSUsDjyXKEkyQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8OoZc1tP1ibRaj24tc2wJE9giawuuElJrd2QCWPqfOCcnTFXF6xJQB5ZicN3yROZhzdGpPVovDU7eqw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8OoZc1tP1ibRaj24tc2wJE99glxlsnfUYeGHk2a2RicmBJKoF6ZCnMozrnp2Ch5rRy7Cv5Y4BanicVw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8OoZc1tP1ibRaj24tc2wJE9M59mRPrqz3A88poABibNqVqNuc3GwSKSps24jstk1HMGsahjMk4aE6Q/640?wx_fmt=png&from=appmsg "")  
# 报名联系方式  
  
不仅仅课程报名可以加我，加入交流群，和好友列表扩充都可以加我  
  
(便宜的课程不一定差，正所谓**小作坊用料猛**  
😵)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9gncFtT0HhkzYu2u8yXlib6h2VztLcgLX6mZficssfnPvkg89EKl1u1UPOXaTTjICbprbnHPjbAzHQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9PSbRVFIhtPHU6V49I177483siaEwTzQv0H5WXtazaj2Q91Q0hBnMMs6ITJnRMQ75icVSxQ3ias5wPw/640?wx_fmt=png&from=appmsg "")  
  
