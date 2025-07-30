#  致远OA rest接口重置密码漏洞分析   
 船山信安   2024-02-27 00:00  
  
### 复现环境  
  
致远 V7.1SP1  
### 补丁分析  
  
致远官方在2023年8月发布了rest接口重置密码漏洞补丁，补丁链接https://service.seeyon.com/patchtools/tp.html#/patchList?type=%E5%AE%89%E5%85%A8%E8%A1%A5%E4%B8%81&id=175  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYaQIKmia8yytNKicZtC0W8ibbBY237fyib8vIg8vbMyt8OBqXb3MbHgqEgQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYweS2BLIg7JFuZf5Nlvk7C5Cia0Ra1leXZoicCgO8UJwjXrt7QWyGvjoQ/640?wx_fmt=png&from=appmsg "")  
  
致远是通过jersey框架实现REST接口，通过配置init-param参数来添加过滤器类，添加后，在进入到资源类之前，会先进入到过滤器类，一些校验的逻辑就可以写在过滤器中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYlcR39rSVjicrP5WZMSpUsMq6ic9cb3Tiat28U1ibwYrnia7cbjX0tZNmVLQ/640?wx_fmt=png&from=appmsg "")  
  
rest接口重置密码漏洞补丁的工作原理是通过将用户角色权限与资源访问权限的逻辑写在ResourceCheckRoleAccessFilter类中，在ResourceCheckRoleAccessFilter的filter方法中，会以访问资源类的类名及方法名和当前用户作为参数调用RestCheckRoleAccessManagerImpl的checkRole方法，验证当前用户是否具有访问资源类的权限，如果不具备访问权限，则抛出异常。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYTibXdFGmxNg7QTjMVbXkAJUC7CYhjGdoyy0Hywl6u21AyzcHGAAu8Wg/640?wx_fmt=png&from=appmsg "")  
  
在补丁包中checkRoleAccessInfo.properties配置文件中，定义了com.seeyon.ctp.rest.resources.MemberResource类中方法已经对应的用户访问权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uY1RSxlp13j9ogxCwf0SDDv1wGprUTiaZ04wqhXrcNkribIzD1CMTcuiayg/640?wx_fmt=png&from=appmsg "")  
  
在MemberResource.class的changePassword方法中，可通过指定memberid和password对用户密码进行修改。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYb1muSuFyxHSNByphYks3dK5rfBSKiaCdicsULtUABFG2liaqBOJ4p1UzQ/640?wx_fmt=png&from=appmsg "")  
  
致远中存在一些自带的用户，这些用户的memberid值都是固定的，正常情况下，我们可以通过changePassword方法修改system等用户的密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYicA1fvWICKicibppnt4wv9B3TtEpRd0iaQATxhVCpLwfHRnNWtmpmXSjqQ/640?wx_fmt=png&from=appmsg "")  
```
seeyon-guest -6964000252392685202
system -7273032013234748168
audit-admin -4401606663639775639
group-admin 5725175934914479521
```  
### rest接口权限校验  
  
在CTPSecurityFilter.class的doFilter方法中，根据uri的特征，分别有7种权限校验的方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uY24ZAlBtDvIMeWZdV3ibw0m4x5EypaNqV4kyQUia4d7CfHwSa9gbLqdfA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYQibofX5CbyfxyOMSTa8JvjveJPqGWryvWlLxiclZfZjmMpl5hWOIxdkA/640?wx_fmt=png&from=appmsg "")  
  
当uri的前缀为/seeyon/rest/时，会调用RestAuthenticator.class的authenticate方法进行验证，该接口仅支持token进行认证，不允许使用Session。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYI66axkib7YLsEqpHn697UvAm1FnKPlSfq7WiaeGeN9iaGISrzIdh8Uyiaw/640?wx_fmt=png&from=appmsg "")  
  
在致远的开放平台描述了toekn的获得方式，https://open.seeyon.com/book/ctp/restjie-kou/gai-shu.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYTWY5A6SUqwQaVJVsUWVJNz0Ct4EGF432c180gPRhpEqPvaG83WWhLA/640?wx_fmt=png&from=appmsg "")  
  
两个步骤，1、登录系统用户创建一个rest用户，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uY9T7he6ABDgEZuygvB4wrA1N5XpMLsNmXicibrMeaia4tmMVicXNaLPuAyQ/640?wx_fmt=png&from=appmsg "")  
  
2、通过/seeyon/rest/token/{restusername}/{password}接口获取token  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uY9bJlZNvzG7byZkZQNxKuN6icSsJbKc3AHSFeEWC4V02Tek5nOmVVVicA/640?wx_fmt=png&from=appmsg "")  
  
获取到token以后，就可以调用changePassword方法修改密码了，调用路径/seeyon/rest/orgMember/{id}/password/{password}，这里将system用户密码修改为123456。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uY61icH0yjY85wTw883cSM1qFVSJU7YpQUic2IQQiayVfHKAP38n4KyiaIUw/640?wx_fmt=png&from=appmsg "")  
  
通过system管理员创建rest用户，在通过rest用户获取token，最后通过token访问接口修改密码，利用的前提需要一个管理员账号，难免有些鸡肋。而访问rest接口只能是token，而token只能通过管理员创建rest用户拿到，看起来是个死结，实际上大佬们的思路是另辟蹊径。  
### 权限绕过  
  
回到CTPSecurityFilter.class的doFilter方法中，在进入到rest接口的权限校验方法前，会先判断是不是SpringController的请求。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uY8s6LAKkSsRSZKYouz6Ij9AJL0Pf9JJwLbAcYPKnYowfgwkthMUj9nQ/640?wx_fmt=png&from=appmsg "")  
  
当uri的后缀为.do或者 .do;jessionid=的时候，那么就会进入到SpringControllerAuthenticator的authenticate方法中进行验证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYlUe7VibhFXaoR0FjRlYjNCMLp38BDQmF5JjZSNc93ShqT57FVEGHkVw/640?wx_fmt=png&from=appmsg "")  
  
而rest接口修改密码的路由为/seeyon/rest/orgMember/-7273032013234748168/password/123456，123456为我们需要修改的密码，当把密码写成123456.do或者123456.do;jessionid= ，即可让该请求走SpringControllerAuthenticator的authenticate方法中进行验证，所以只需要普通用户的权限就可以修改管理员的密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYRGdialx2LXm3RoS6I0atW4W8X8qSwlOor7EsXfFbdrL7BLPbUzaT61A/640?wx_fmt=png&from=appmsg "")  
### 武器化利用思考  
  
致远中存在一些接口，是可以RCE的，但是设置了访问权限，当拿到管理员权限以后，我们可以通过管理员权限为普通用户赋予一些访问权限，然后调用这些接口实现RCE，另一个是通过管理员权限创建普通用户留后门。  
### 修复  
  
在致远 8.2之后版本的CTPSecurityFilter.class中，除验证uri路径以.do结尾以外，还验证了该uri是否为rest接口，限制了普通用户禁止通过SpringController的验证逻辑去访问rest接口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYkiaKHYLMyrmfYUXE7yOpqKxn1KR8FS5ddBw2pibbUM0XXJiaW28mmXVhQ/640?wx_fmt=png&from=appmsg "")  
  
来源：https://xz.aliyun.com/ 感谢【  
1815098357643864  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYDcRGmHxP7YAwFajfhicicLLl4Teoicr5icYhrWGVQlc7Vj4XeOuWT7BIFw/640?wx_fmt=jpeg&from=appmsg "")  
  
群聊已满，想入群的可以加浪师父的微信进入。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNeMiaksyrAy8QNHwCIQV5uYXEXfzb75dC1gMneTGkBWP23ACXUD1uFEIyz1XwKzx7BVKicoSibgHC3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
