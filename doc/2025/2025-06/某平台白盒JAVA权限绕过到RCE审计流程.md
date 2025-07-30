#  某平台白盒JAVA权限绕过到RCE审计流程   
原创 知名小朋友  进击安全   2025-06-01 08:04  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
一、前言  
  
朋友给到一套源码xx系统的，这里尝试进行审计，其实发现这个源码是一个Struts2框架的，所以一开始没有太去关注一些别的东西，一股脑去看相关的struts2的配置文件了。  
  
#### 二、配置文件寻找  
  
这里其实寻找配置文件还是比较简单的，这里我们直接搜索Action即可规定文件后缀为.xml  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70yVVO4pr03123akudiaSmSMtEgSShXVnpAjKvOzCvnCDsFvpFFbkHibew/640?wx_fmt=png&from=appmsg "")  
  
寻找到对应的配置文件之后就好说了，剩下的就进行正常的审计流程即可。  
  
  
三、展示容错  
  
这里进行审计首先第一个比较好的信息是，在struts2当中的配置文件当中没有存在相关的拦截器等信息，这里还是比较开心的以为可以随便访问。  
  
  
第二个比较坏的信息就是没有一个路径作为跟路径让我进行访问，后来询问了很多大佬之后我才明白，action的name就可以当作开头。  
  
  
第三个就是这里的method属性没写的话是默认调用exec什么的，这里{1}就是你url后面跟的什么方法名称就调用什么方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70chyzvOF6NEJnpOgTibjMJZn1mASO2xvaSNHIZ6Dj441YicIISrbXqEQA/640?wx_fmt=png&from=appmsg "")  
  
这里进行根路径直接的调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70wyBtSRBIYmiaWjianRoznPDto2gPicBibher4drf5ydUt69YpOtNb1fvfg/640?wx_fmt=png&from=appmsg "")  
```
http://ip/departmentAddressTree_{1} => http://ip/departmentAddressTree_getContent.do
```  
  
    
  这样子调用，但是还是没有成功，最后才知道了，还要求加一个.do结尾或者.action结尾。  
  
四、鉴权绕过分析  
  
这里访问了半天都跳转到了登陆页面，无法成功进入对应的代码当中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70FYZJkGPib2TU5HibVibL9bg5yoDn9NCTskTicKahXjRyRicXhGsbGA6QdnQ/640?wx_fmt=png&from=appmsg "")  
  
这里明明struts2当中不存在对应的拦截器为什么登陆不上去，回到了web.xml当中寻找。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE7049qOMj3ibciaicjXiapAIqAibZ8KMhb6ma0VvQwdfl29P1lcJcXibdQSoJkA/640?wx_fmt=png&from=appmsg "")  
  
应该是这个拦截器原因跟入这个拦截器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70ClbDiaBlQ4jKDiaQVWm4IcSp8qrj5k4ytFVmia121RqASNVajZbaJteyQ/640?wx_fmt=png&from=appmsg "")  
  
跟入父类。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70GcyibfAYz8TG2JMEE1hRt6kRUSam8y9tJhlLUicmDwyO1CaaknPoHswQ/640?wx_fmt=png&from=appmsg "")  
  
    找到了正常的doFilter方法，这里首先获取了url使用两种方式，下面那种是存在风险的。然后进行sVaildLogin方法判断登陆之后才可以进入到判断url的if当中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE7046lu9s1fSiaibUN6J595j3KytV4HdDTPe9AUpXS9PNeL28DqmCtJ2EZA/640?wx_fmt=png&from=appmsg "")  
  
跟入isValueLogin方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70f8ialicCaVNCI8AllgTJFdQNM4J0cSJ2p0PG0IuGa04shjUMib3VribRtQ/640?wx_fmt=png&from=appmsg "")  
  
是一个接口，寻找实现类。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70Qlrfye6wibZ8pydyJ2vnFAOwlBcehiaPzic16TVTanjicjeNg4GEO83Mug/640?wx_fmt=png&from=appmsg "")  
  
实现类直接就是true顺利进入到了url的判断当中，回到拦截器当中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70w0fWSvf4pXnjhtQLNNJ89hZaFaf7icc3Pgl2NmiboBniaO0ppy4zCXTmw/640?wx_fmt=png&from=appmsg "")  
  
这里两个判断首先判断其实也就是判断是否包含Skip的路径。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE7083raCRQfOCHjv6diagfWshbyIM63NmNxJt8knl8h6bESIdsgvcuTWtA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70sgpXPicw8zSmLiaIa8k71G1Udr9kuX45FTWuWOVAicPtKGn5PKDVNhbEg/640?wx_fmt=png&from=appmsg "")  
  
另外一个就是直接判断是否包含png等各种信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70fnvblGp8mXVbbUuFcLonoXbrpic0erlRribK92lzhhdtlicf52WKo2YVA/640?wx_fmt=png&from=appmsg "")  
  
满足任意一个判断直接就进行放行了。  
  
  
五、鉴权绕过  
  
    访问后台路径并且使用;.png进行绕过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70PnfeHtBaE22WqiabC8OrxLIYz2xlAMNSZ0dXyJx5kicCPLZzT2ziaAyAA/640?wx_fmt=png&from=appmsg "")  
  
成功绕过拿下！  
  
使用白名单路径绕过也可以： ..;/来跳出目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE707OjvELhk74rUjjmFMq3RJmaKvX8DYTK3q43cwMcQOXGGdI8TyHqhtA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVVmpDwulfkp76e9lF0cE70c7giaBLYSnDLibgV9eUjnst9nIP2rNicCUQX3fyUEnaV5Foj3vy6lf81w/640?wx_fmt=png&from=appmsg "")  
  
后台还存在一个任意文件上传，配合鉴权绕过可以直接进行前台RCE，这里就不写出来分析过程了。  
  
六、完结  
  
  
代码审计第四期，富含PHP、JAVA、NET代码审计，顺带APP、小程序、WEB当中参数逆向以及JAVA工具二开与SRC案例讲解，其中多多0day讲解，实战案例分析，不拿着靶场去做，想学习速速报名了。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhUicibrBmrZ2iazoDJic2RyDklw4547e6aNia1OEMntI6wGqRdvr87XVgUdiaiczwW67bRO3iayvd7H7bZoeQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
