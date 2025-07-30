#  JTopCMS审计之目录穿越漏洞   
原创 庆尘qc  Daylight庆尘   2023-12-10 10:04  
  
**一、环境部署**  
  
1.1、官方网站  
   
  
https://www.jtopcms.com/  
  
1.2、下载地址  
   
  
https://gitee.com/mjtop/JTopCMSV3/releases/tag/JTopCMSV3.0.2-OP  
  
1.3、所需环境  
<table><thead><tr><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;font-variant:normal;text-transform:none;font-weight:bold;mso-bidi-font-weight:bold;">名称</span></span><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;"></span></span></p></td><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;font-variant:normal;text-transform:none;font-weight:bold;mso-bidi-font-weight:bold;">版本</span></span><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;"></span></span></p></td></tr></thead><tbody><tr><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;">JTopCMS</span></span></p></td><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;">V3版本（开源版本）</span></span></p></td></tr><tr><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;">Java版本</span></span></p></td><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;">JDK1.7+即可</span></span></p></td></tr><tr><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;">mysql</span></span></p></td><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;">5.5.29</span></span></p></td></tr><tr><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;">Tomcat</span></span></p></td><td width="264" valign="top" style="border-top:none;border-left:none;border-bottom:none;border-right:none;padding:0pt 5.4pt 0pt 5.4pt;"><p style=""><span style="mso-bookmark:一环境部署;"><span style="font-family:Cambria;mso-ascii-font-family:Cambria;mso-fareast-font-family:Cambria;font-variant:normal;text-transform:none;">Tomcat7+即可</span></span></p></td></tr></tbody></table>  
1.4、修改配置  
  
在JTopCMSV3-JTopCMSV3.0.2-OP\WebContent\WEB-INF\config\cs.properties配置文件中修改端口信息（与配置的Tomcat保持一致）与数据库连接信息      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWFY6g9QTATjvEQYIglUbgicHiaqGjvzaBmWlcyZvQic4icvgeIGkj1Lkia3Q/640?wx_fmt=png "")  
  
  
1.5、启动项目  
  
启动项目之后，来到后端管理登录页面：  
  
http://127.0.0.1:7089/login_page  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWzYEXmBK7TIicT0vDibW4vHcIdOxiaUl3HRX55YgjpUBIQKtA5Yu46xIuA/640?wx_fmt=png "")  
  
  
登录账号密码为 admin/jtopcms      
  
**二、代码审计**  
  
今天我们只针对这个应用的目录穿越漏洞进行审计，而目录穿越漏洞一般伴随  
文件上传/下载/删除  
等功能，所以我们先查找一下该程序是否存在文件上传/下载/删除功能  
  
那审计一个项目时如何快速定义到系统的下载功能呢？  
  
1、项目中的  
使用文档  
或  
用户手册  
。  
  
2、部署环境后通过  
抓取下载数据包  
确定接口名后全局搜索接口名  
  
3、使用经典  
关键字  
download等进行全局搜索即可  
  
               
  
这里通过关键字检索，我们发现了两个疑似文件下载的接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWdT4QkytG65Zibf6mprlj9Kibp2STszyrrB4lfB6FI5UC9ZYKoYFiak2ZQ/640?wx_fmt=png "")  
  
  
下面我们分别来对这两个下载功能的接口进行追踪与漏洞测试  
  
                   
  
**1、/downloadback.do**  
  
（1）功能点定位  
  
首先定位到映射代码位于  
BackupSystemController类  
中，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSW7GIbTpsJyGr6mNs2KddK5e6DGHV9icpglKxu8hibuWVlptIS6euxo3Ag/640?wx_fmt=png "")  
  
  
再定位到请求该接口的jsp文件中，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSW1DdGWJlGl2uxIFGlC7mgnWGnn2Fa6Mo9Lld0YOhic4icMeOnvpORe9cg/640?wx_fmt=png "")  
  
  
通过方法名—downloadBak和该jsp文件名ManageBackup.jsp猜测该功能是一个  
备份文件管理功能  
，并且在备份下载功能中调用了该接口  
  
所以来到后台寻找该功能点，成功定位到下载功能点，并且确实存在备份文件下载功能，功能点位于      
  
                   
  
•  
  
后台->系统配置->系统备份管理  
  
                   
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWWMeIJZf1owsJZ38KrWfF1gLOY1H0KM6Sksq5yialwVbYMDqVicCmqXcA/640?wx_fmt=png "")  
  
  
抓个包再次验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWE9SicicLjdUPRMNrNCtsiaIoC735nYbDe7vP94jeSEMiaKT2yZ4BWz1ZSQ/640?wx_fmt=png "")  
  
  
进一步确认了该功能点调用了  
/downloadback.do接口  
  
  
（2）源代码审计  
  
1、Controller层  
      
  
根据请求包来看，  
target，pw，downFileInfo  
，这三个参数都有可能与文件下载功能有关，  
  
我们给下载备份这个功能点  
下一个断点  
，再调试项目，看看程序的执行流程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWRibpcia9GOCxe8sCwicLKg7LRNojs5vm1iboEOklFDvG6LR20lQSUZVpLw/640?wx_fmt=png "")  
  
  
简化后的流程代码如下  
  
```
@RequestMapping( value = "/downloadBak.do", method = { RequestMethod.POST } )                
    public String downloadBak( HttpServletRequest request, HttpServletResponse response )                
        throws UnsupportedEncodingException                
    {                
        // 将请求传入的参数存储在Map对象                
        Map params = ServletUtil.getRequestInfo( request );                
               // 通过session判断用户身份是否合法                
        .....                
               // 从请求中获取target参数的值，赋值为targetbak                
        String targetBak = ( String ) params.get( "target" );                
                      // 获取系统的真实路径并赋值给base变量                 
        String base = SystemConfiguration.getInstance().getSystemConfig().getSystemRealPath();                
                      // 构建一个如下的字符串，并赋值testbakroot                 
        String testBakRoot = base + "__sys_bak__" + File.separator + targetBak;                
               // 检查了名为testBakRoot的路径是否指向的是一个文件,并为其创建File对象                
        ......                
               // 开始下载File对应的文件                
        ......                
                      // 关闭流                
        ......                
        // 抛出异常                
        ......
```  
  
  
分析上面的代码，可以看我们传入的target会被直接拼接到如下路径，在这段代码中并没有防范  
```
{base}/_sys_bak_/{target}
```  
  
  
base在我的项目中的值如下  
```
E:/WorkSpace/Javawork/JTopCMSV3-JTopCMSV3.0.2-OP/target/ROOT
```  
  
  
即拼接后的备份完整路径为（假设备份文件名为bak.zip,即target为bak.zip）  
```
E:/WorkSpace/Javawork/JTopCMSV3-JTopCMSV3.0.2-OP/target/ROOT/_sys_bak_/bak.zip
```  
  
  
于是我在  
  
•  
  
E:\WorkSpace\Javawork\JTopCMSV3-JTopCMSV3.0.2-OP\target\ROOT  
  
目录下新建了一个  
a.txt  
，再请求  
/downloadbak接口  
,传入的  
target的值改为..\a.txt  
，尝试拼接为如下的接口进行读取a.txt，从而验证任意文件下载漏洞  
  
E:\WorkSpace\Javawork\JTopCMSV3-JTopCMSV3.0.2-OP\target\ROOT\_sys_bak_\..\a.txt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWydkuagp8ibmDbT5AwhgvF1Wia2YJrbZOyKVxXHzdeibsrZpw7yGHzc2ibA/640?wx_fmt=png "")  
  
  
结果如下      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWzxmc8eeGQ1ib87hvXBhdeJNbTTrQWJPHxa5O0HM1A1HYN83mLf5Kacg/640?wx_fmt=png "")  
  
  
可以看到被拦截了，并且给出提示：包含非法字符  
  
控制台打印如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWnzxP19pbXQGYpgwDfGFl0WhBRmRGeSnl5c2EAjOFVFjgyWbwQMW7ibw/640?wx_fmt=png "")  
  
  
这里我们思考一下，刚才我们Controller层代码中并没有检测target的合法性，但现在我们传入恶意的target又被拦截了，说明了什么？说明这个downloadbak请求到达Controller类代码之前被拦截并执行了检测，第一时间就想到了去看看Spring的配置文件中是否配置了拦截器  
  
2、interceptor层  
  
果不其然，在其中找到了这样一段Spring MVC的拦截器配置代码，如下  
  
<  
mvc  
:  
interceptors  
>  
                  
      
             
// 第一个拦截器  
                  
             
             
<  
mvc  
:  
interceptor  
>  
                  
             
             
             
  
                  
             
             
             
<  
mvc  
:  
mapping path  
=  
"/**"  
   
/>  
                  
             
             
             
<  
bean   
class  
=  
"cn.com.mjsoft.cms.common.interceptor.SpringMVCFlowExeTokenAndTraceInterceptor"  
   
/>  
                  
             
             
  
mvc  
:  
interceptor  
>  
                  

                    
      
             
// 第二个拦截器  
                    
             
             
<  
mvc  
:  
interceptor  
>  
                    
             
             
             
<  
mvc  
:  
mapping path  
=  
"/survey/clientVote.do"  
   
/>  
                    
             
             
             
<  
mvc  
:  
mapping path  
=  
"/guestbook/clientAddGb.do"  
   
/>  
                    
             
             
             
<  
mvc  
:  
mapping path  
=  
"/content/clientAddContent.do"  
   
/>  
                    
             
             
             
<  
mvc  
:  
mapping path  
=  
"/content/clientEditContent.do"  
   
/>  
                    
             
             
             
<  
mvc  
:  
mapping path  
=  
"/content/deleteContentToTrash.do"  
   
/>  
                    
             
             
             
<  
mvc  
:  
mapping path  
=  
"/clientAddComment/clientAddComment.do"  
   
/>  
                    
             
             
             
<  
mvc  
:  
mapping path  
=  
"/deleteComment/deleteComment.do"  
   
/>  
                    
             
             
             
<  
mvc  
:  
mapping path  
=  
"/resources/clientDf.do"  
   
/>  
                    
             
             
             
<  
mvc  
:  
mapping path  
=  
"/member/*.do"  
   
/>  
                    
             
             
             
<  
bean   
class  
=  
"cn.com.mjsoft.cms.member.interceptor.MemberActScoreInterceptor"  
   
/>  
                    
             
             
  
mvc  
:  
interceptor  
>  
                    

                      
      
             
// 第三个拦截器  
                      
             
             
<  
mvc  
:  
interceptor  
>  
                      
             
             
             
<  
mvc  
:  
mapping path  
=  
"/member/*.do"  
   
/>  
                      
             
             
             
<  
bean   
class  
=  
"cn.com.mjsoft.cms.member.interceptor.MemberSendMessageInterceptor"  
   
/>  
                      
             
             
  
mvc  
:  
interceptor  
>  
                      

                        
      
             
// 第四个拦截器  
                        
             
             
<  
mvc  
:  
interceptor  
>  
                        
             
             
             
<  
mvc  
:  
mapping path  
=  
"/content/addContent.do"  
   
/>  
                        
             
             
             
<  
mvc  
:  
mapping path  
=  
"/content/editContent.do"  
   
/>  
                        
             
             
             
<  
mvc  
:  
mapping path  
=  
"/content/clientAddContent.do"  
   
/>  
                        
             
             
             
<  
mvc  
:  
mapping path  
=  
"/content/clientEditContent.do"  
   
/>  
                        
             
             
             
<  
bean   
class  
=  
"cn.com.mjsoft.cms.content.interceptor.DeleteTempFileWhenUploadErrorInterceptor"  
   
/>  
                        
             
             
  
mvc  
:  
interceptor  
>  
                        

                          
  
mvc  
:  
interceptors  
>  
                    
  
可以看到配置了四个拦截器，这里能够匹配到/resources/donloadbak.do请求的只有第一个拦截器  
  
这里提一下以下两种情况  
  
1、如果有多个拦截器都能匹配，则拦截顺序默认按照配置拦截器的顺序进行  
  
2、Spring MVC中，可以通过在配置文件中使用  
mvc:interceptor-ref  
标签来引用并配置拦截器，并使用order属性来  
指定它们的顺序  
，这样的话拦截顺序则变为指定顺序      
  
回到正题，经过上面的分析，我们的/resources/downloadbak.do请求会先被第一个拦截器处理，所以我们跟过去看看第一个拦截器类（即SpringMVCFlowExeTokenAndTraceInterceptor类）的内容，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWZqKaDlnjjqtIPibP1gI0s4ickskRibXLKhx8sibn666vQ51bRyPria1U1Pg/640?wx_fmt=png "")  
  
  
可以看到这个类实现了Spring的  
HandlerInterceptor  
接口，用于拦截请求并执行一些前置和后置的处理，这里我们要分析它对拦截的请求的检测逻辑，所以主要分析前置处理代码，即preHandle方法      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWRHNVKqvn9S2TDg91Xia0e7sZ34wRtiaia6ibH8v4j6H4QUlJlz44deDjrw/640?wx_fmt=png "")  
  
  
简单看了下preHandle方法，只是进行了权限校验，也没有对参数特殊字符的处理  
  
Controller类中没有处理，Controller类之前的拦截器也没有处理，那还有什么能够在Controller类和拦截器之前对请求进行处理呢？答案就是  
过滤器（Filter）  
  
3、Filter层  
  
过滤器的配置可以到Web应用的配置文件web.xml文件中查看，如下      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSW8icP9LpbUreOjX7QkCSfhfgnwZ7hJ7iakSrn3Zn2x1uXwFPIDzB9SPiag/640?wx_fmt=png "")  
  
  
可以看到这里配置了两个过滤器，第一个拦截的是所有请求，第二个拦截的是.do结尾的，我们刚才被拦截的请求是  
  
/sources/downloadbak  
  
所以会被第一个Filter拦截，我们定位到到第一个Filter对应的Filter实现类中，即InterceptFilter类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWHRMdFNJ6k21a1Q6Lt7SMzViaj6G6A2DToKPd1DrruNlqria9wBASR5HA/640?wx_fmt=png "")  
  
      
  
可以看到InterceptFilte类虽然名字叫InterceptFilte（拦截器），但其实实现的是Filter接口的一个自定义过滤器，因为刚才控制台打印了如下两句话  
  
[2023-12-09 15:54:27,756] FATAL  
  - danger char->..  
                  
[2023-12-09 15:54:27,757] FATAL  
  - IP->172.24.86.134,非法动作->target=../a.txt&pw=,URL->http://172.24.86.134:8090/resources/downloadBak.do  
  
说明是我们传入的  
target=../a.txt  
中带了  
".."  
被识别为危险字符了，所以先搜索一下  
".."  
字符，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWXdV2DFzolcnayIsxIyYhN4z0mO9Z82G4BicoLRLIdHNv62J8hJD7lcA/640?wx_fmt=png "")  
  
  
在静态代码块中成功找到定义，而且这个  
$6的内容看着也像黑名单字符，所以我们先试着追踪一下  
$6的流转  
  
可以看到288行调用当前类的  
$1方法时，将  
$6作为参数传入了方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWfyVgPlcv8h2CUicMk66VwMhjlGxaLLQeib6DhNwocWfLM7qYVc8GjU0Q/640?wx_fmt=png "")  
  
  
我们分析一下_$1方法，如下      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWAhlWOfYYZjibFtABctwiblrbYfyCicr0xwLmylboRx29IxX8vGAESRsJg/640?wx_fmt=png "")  
  
  
经过分析，发现确实就是它导致了我们的..被拦截，分析流程如下  
  
private  
   
boolean  
 _$  
1  
(  
String  
 var1,   
String  
[]  
 var2,   
String  
 var3,   
boolean  
 var4  
)  
   
{  
                  
    _$  
13.d  
ebug  
(  
"{SYSTEM Adjudgement} 将验证参数:"  
   
+  
 var1  
);  
                  
      
// 判断var1是否为空，为空就退出  
                  
      
......  
                  
      
//不为空就继续执行  
                  
      
if  
   
(  
var1  
.  
startsWith  
(  
"http://"  
))  
   
{  
                  
             
             
//如果URL以 "http://..." 开头，检查它是否与已知站点的URL匹配，或者是否包含特定危险字符。  
                  
             
             
//如果匹配或包含危险字符，记录错误日志，返回 false 表示不安全。  
                  
       
}  
                  
       
// 如果var4=true  
                  
       
             
// 就检查var1是否包含危险字符  
                  
       
             
// 包含的话就打印错误信息并退出返回false  
                

                  
       
// 如果var4=false   
                  
             
             
// 就检查var1是否包含危险字符和“=”号  
                  
       
             
// 包含的话就打印错误信息并退出返回false  
                

                  
      
return  
   
true  
;  
                  
      
                  
}  
  
简单来说这段代码就是用于检测  
var1  
是否包含提前定义好的危险字      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWTRV8sPTWPpMRPdb8UFmnCuj8OeFWp17o3N5ticSICodnQIcRibLPGR9w/640?wx_fmt=png "")  
  
  
所以刚才我们的控制台上会出现   
danger char->..  
这个信息  
  
因为刚才的判断代码返回false，即我们的输入不安全，所以这里的288内的代码块会被执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWz8K24Jic6OgKbwic8JYJFBZtuMib8WzvyanBY7aficXFTU39VdNOnpAhYQ/640?wx_fmt=png "")  
  
  
导致var55被赋值为false，从而执行第299行代码，即调用  
$1方法，  
$1方法打印出本次导致错误的动作信息，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWIXOdcuRgDlVQpVibNAkLibvmhySaz1E98tFJLgtiaFoDvYK8pXZfiaag4w/640?wx_fmt=png "")  
  
  
这也就解释了我们控制台的第二句打印  
  
IP->172.24.86.134,非法动作->target=../a.txt&pw=,URL->http://172.24.86.134:8090/resources/downloadBak.do  
      
  
所以这个  
/downloadbak.do  
下载接口是有特殊字符过滤的，我在这里试了很久，但还是没有办法绕过，即没有办法配合目录穿越 ../ 来读取任意位置的敏感文件，所以我个人认为这里暂时是没有漏洞的。  
  
进入下一个下载功能点。  
  
**/downloadresfile.do**  
  
(1)功能点定位  
  
首先定位到关键代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSW60UViaxvibLAEuDCR6Nqlo76EsoF70NeRnDujlWCchlPkDnRQ0tELmLA/640?wx_fmt=png "")  
  
  
可以看到关键代码位于  
ManageSiteFileAndCheckController类  
中，再请求到定位该接口的jsp文件中，如下      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSW7EmtEScK8jHj4h0GS7fPFvfwcdN3jia1kwjyCic1tjn7HxgkSJCwXesA/640?wx_fmt=png "")  
  
  
成功定位到  
ManageTemplate.jsp  
文件中，并且还传入了一个  
entry参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWlWZcNvdL7qHSFn4MYyka4rz4ZSXjVXbmNZzRibGa7WUafaz9aL67DHg/640?wx_fmt=png "")  
  
  
根据文件名和文件信息确认该功能点为模板管理功能的下载功能，如下      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWicu8ncNdJltKGRGkXk1Tx0e62lZgRwib5Bkpah7vicpnTAdAianFgTTZfA/640?wx_fmt=png "")  
  
  
  
(2)源代码审计  
  
根据上一个下载的功能点，我们知道了请求参数的值中  
不能包含指定的危险字符  
，基于这个前提，我们再来审计一下这个下载的功能点  
  
审计上一个下载点的时候，我们已经把  
过滤器  
和  
拦截器  
分析过了，这里就不分析了，直接看Controller类的代码，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWZEmSCBB8u0icPMlVk2N7JRRZ3exzcy2cvbE3ZJTuA693xoEe1m2GMdw/640?wx_fmt=png "")  
  
  
•  
  
1、先分析211-219行，从请求中获取  
mode、entry、downFileInfo参数的值  
,并且entry和downFileInfo两个参数还经过了  
SystemSafeCharUtil.decodeFromWeb方法  
处理  
  
•  
  
2、校验用户身份是否合法  
  
•  
  
3、根据日期随机生成一串字符，拼接.zip，形成一个类似下面这样的  
压缩文件名  
  
*  
sys_template_temp  
*  
demo_2023_465461  
.  
zip  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWsGmBSfzLEpAibpkSHsziafTY6EKgNh9tcSqTEd7BDMV2Tp1NIP9FHucg/640?wx_fmt=png "")  
  
  
发现在267行拼接了压缩文件名，跟进  
getFullPathByManager方法  
来到  
ResourcesService.java类  
中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWzWrWjp5PC44FXaPJjwKBNZVlg66RP6w4uTrebK6k2dljtCBbUFrrEQ/640?wx_fmt=png "")  
  
  
主要代码如上，简单来说该方法就是把zipName中的*  
替换为路径分隔符（""或者"/"）  
,再  
过滤掉一些敏感字符  
,再与根路径进行拼接，最终得到类似如下的  
fullZipPath  
  
E  
:  
\Work  
```
Space\Javawork\JTopCMSV3-JTopCMSV3.0.2-OP\target\ROOT\demo\sys_template_temp\demo_2023_465461.zip
```  
  
  
\\ 其中  
*  
sys_template_temp  
*  
demo_2023_465461  
.  
zip  
为传入的zipName  
(  
entry  
)  
  
                   
  
后面的代码简单的说就是  
基于根目录  
，压缩  
template（entry参数的值）  
文件夹下的  
block（downloadfileinfo参数的值）文件夹下的内容  
并复制到  
sys_template_temp目录  
下，同时  
供用户下载  
      
  
所以就从头梳理了一下，想起了最开始获取请求的  
entry、downFileInfo参数的值  
时，获取后调用了  
SystemSafeCharUtil.decodeFromWeb方法  
，所以我们追踪  
SystemSafeCharUtil.decodeFromWeb  
方法，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSW3r7qdNMHCaFykn7NoUWPbnBwiazAHzOmktSJMe6WibH4ZCs8lc53wBng/640?wx_fmt=png "")  
  
  
可以看到该方法将传入的input参数进行了一次  
url解码  
后，再调用  
decodeDangerChar()方法  
，我们继续追踪该方法      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWPKOfNwRoXLUrjeiapqOQAbP4N4EibQJjrVusUueThgM7HaJjYcA0jgYg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWdpUgAo1NFSRN6w6YGPXLLiaRwPGe78ug3YszyGSQ4YcNwwVQLf27CuA/640?wx_fmt=png "")  
  
  
通过代码可以得知该方法主要用来完成替换危险字符的操作，如果路径中存在一些危险字符的话就会被该方法替换为指定字符，同时我观察到  
  
•  
  
*!4*  
 则会被替换成  
".."  
   
  
•  
  
*!11*  
 会被替换成  
"\"  
  
这样说的话路径中存在   
*!4*  
*  
!11*  
的话就会变为  
"..\"  
,这样是不是就又可以向上遍历目录了？  
  
于是我们来尝试读取一下电脑上的其他文件，例如  
  
E:\info.txt  
  
经过我们上面的分析，得出下载的  
文件根目录  
在      
```
E:\WorkSpace\Javawork\JTopCMSV3-JTopCMSV3.0.2-OP\target\ROOT\demo
```  
  
  
根据传入的  
entry  
和  
downFileInfo  
  
最后构成  
```
E:\WorkSpace\Javawork\JTopCMSV3-JTopCMSV3.0.2-OP\target\ROOT\demo\{entry}\{downFileInfo}
```  
  
  
所以我们把downFileInfo修改为要读取的info.txt，entry也利用多个  
*!4*  
*  
!11*  
穿越到E盘的根目录，  
  
尝试形成如下的文件链接  
```
E:\WorkSpace\Javawork\JTopCMSV3-JTopCMSV3.0.2-OP\target\ROOT\demo\template\..\..\..\..\..\..\..\..\info.txt
```  
  
  
从而读取到  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWLlY2O3RBevY7oKV2bUxHwYRiaI5yJO3eRTolgJvZ8EibSicrk0cJNguUg/640?wx_fmt=png "")  
  
  
成功读取到目标文件      
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk9thAVc8DTUDqG1K2msHOSWqOlDqlbicKeeKEvYKQ6A3sxnOq7q7PT0gtYfKX51m2LDynyJTNPUicicw/640?wx_fmt=png "")  
  
  
**三、总结**  
  
到这里，JTopCMS的下载功能的目录穿越漏洞就审计完毕，看到Power7089师傅在讲解目录漏洞时讲了这个CMS的下载功能存在任意文件下载漏，就想着试一试自己能不能找到，在第一个下载点的审计花了很久，因为一直没找到“../”是怎么被拦截下来的，并且找到拦截代码之后尝试绕过也试了很久，还是没绕过去，审计第二个就比较容易了，直接在Controller类中就跟踪到了问题代码，审计完之后再和Power7089师傅的审计过程比对一下，发现确实是恶意字符替换导致的问题，这里贴一下Power7089师傅审计该漏洞的文章链接  
  
[https://power7089.github.io/2022/11/29/JavaWeb代码审计实战之配合JtopCMS实战讲解目录穿越漏洞/]()  
  
  
最后，真的想吐槽一下，开发人员添加这个替换恶意字符的操作的意义是什么？明明Filter中都已经做了很好的拦截操作了，比如第一个下载的功能点，全靠Filter拦截，第二个下载点非要多此一举，替换后的字符和Filter中拦截的字符有些都是重复的，替换的意义是什么，真有点没搞明白。      
  
