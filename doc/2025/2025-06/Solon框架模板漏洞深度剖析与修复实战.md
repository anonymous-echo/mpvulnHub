#  Solon框架模板漏洞深度剖析与修复实战   
原创 标准云  蚁景网络安全   2025-06-04 09:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5znJiaZxqldyq3SBEPw0n6hCXNk6PmR3gyPFJDUCibH91GiaAHHKiaCpcsfnQJ2oImQunzubgDtpxzxNHONU88CypA/640?wx_fmt=gif&from=appmsg "")  
  
   
  
## 前言  
  
分析发现 Solon 框架在3.1.0版本上存在一个有意思的模板漏洞，对这个漏洞进行简单分析后，发现整个漏洞的利用链是非常有意思的。同时发现最新版的修复方式过于简单，询问 AI 后，AI 也认为修复也是不完善的安全修复，于是进行一系列的绕过尝试，最后还是没有利用成功，简单进行分享。  
## 环境搭建  
  
‍  
### Solon 框架简介  
  
Solon 是一个轻量级的 Java 应用开发框架，类似于 Spring Boot ，但更加轻量。支持多种模板引擎，包括 Beetl、FreeMarker、Velocity 等。在模板处理方面，Solon 采用了灵活的渲染器映射机制，也是出现这个漏洞的关键原因。  
### 测试环境搭建  
  
https://solon.noear.org/start/build.do?artifact=helloworld_jdk8&project=maven&javaVer=1.8  
  
可以下载 solon 的项目模板 并进行修改  
  
修改一下 pom.xml 文件 设置 solon 的版本为 3.1.0  
  
将原本的视图插件 solon-view-freemarker 替换为以下的任意一种  
```
<dependency>    <groupId>org.noear</groupId>    <artifactId>solon-view-enjoy</artifactId></dependency><dependency>    <groupId>org.noear</groupId>    <artifactId>solon-view-beetl</artifactId></dependency><dependency>    <groupId>org.noear</groupId>    <artifactId>solon-view-thymeleaf</artifactId></dependency><dependency>    <groupId>org.noear</groupId>    <artifactId>solon-view-velocity</artifactId></dependency>
```  
  
‍  
  
在 DemoController.java 中 添加代码 并启动运行  
```
    @Mapping("/templates")    public ModelAndView templates(Context ctx) throws IOException {        ModelAndView modelAndView = new ModelAndView(ctx.param("templates"));        return modelAndView;    }
```  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnYBYENtxOpialhHuGBibCBtFKna52Gm3wAibrTvf836FJgtNXfE3RsrCww/640?wx_fmt=png&from=appmsg "null")  
  
## 漏洞验证与分析  
### 漏洞验证  
  
我们选用视图插件solon-view-velocity，不同的视图插件对跨目录的处理有所不同，之后会对此进行详细解释  
```
<dependency>    <groupId>org.noear</groupId>    <artifactId>solon-view-velocity</artifactId></dependency>
```  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnak7LPibs6R2J3y4CAGuKoFEyVEjXuQkicic1mJicGoCbNtTFfAnrkxR0LA/640?wx_fmt=png&from=appmsg "null")  
  
  
可以看到传入的参数通过 ../ 实现了跨目录的文件读取并将内容解析到页面上  
### 核心调用链分析  
  
通过调试对这个漏洞进行分析  
  
遇到这种情况有一个小的 tips 我们可以通过尝试加载一个不存在的文件，这样 idea 的控制台中会输出相对详细的调用链，方便我们下断点进行调试分析。  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnlATDeeh9MZYj30uHYMibricR72Flr0rdicEvxkVqR6H4EpTJp5kDibcVnw/640?wx_fmt=png&from=appmsg "null")  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQn8jVmiaq6flDuibZU3LaI9o4FicI5LwKc8ROlKOhicUYmXT2icNicjL637MaA/640?wx_fmt=png&from=appmsg "null")  
  
  
org.noear.solon.core.handle.RenderManager#render  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnPGxHYAeXOAslsibwJDE8vXpqo4xAna8YEh0DlicxdxJhaYNCHxIwEygQ/640?wx_fmt=png&from=appmsg "null")  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQny9wtHKV7eYEZwEd5UUTWr0neVnsYSoOl77Qn6P6uYXR4icOXpavic3FQ/640?wx_fmt=png&from=appmsg "null")  
  
  
这里会根据文件后缀来选择视图插件，如果没有匹配的就选择用默认渲染器来处理  
  
org.noear.solon.view.velocity.VelocityRender#render  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnCiaVibRkR7gorhTvg07w0KhjmlV78fEbDONYJS7zmFDKWfROTQkrx5Bg/640?wx_fmt=png&from=appmsg "null")  
  
  
org.noear.solon.view.velocity.VelocityRender#render_mav  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnCTNTKg4dciam7shVG3ibv0u0TBbicicOUL8GKKcoBZzdLnBenqz7ibkWzHg/640?wx_fmt=png&from=appmsg "null")  
  
  
org.apache.velocity.runtime.RuntimeInstance#getTemplate(java.lang.String, java.lang.String)  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnTKibTnUZJ8b8J0UibUl3NDCqsbZb14AS6VfkLuvNlVk3kI4sdO5TdSQA/640?wx_fmt=png&from=appmsg "null")  
  
  
org.apache.velocity.runtime.resource.ResourceManagerImpl#getResource  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnelI83x2hSkCK77ibcGyias0acp0pzBrvuKWajDw8dZs48h9wXFe7cDbw/640?wx_fmt=png&from=appmsg "null")  
  
  
‍  
  
整体流程顺下来应该是  
  
用户输入 → Context.param() → ModelAndView() → RenderManager.render()→ 模板引擎处理  
  
在模板引擎处理之前没有对模板文件的路径进行处理和限制，这样一来如果模板引擎处理的时候没有对模板文件的路径进行处理时，就会产生任意文件读取漏洞。  
  
我们可以尝试看看利用别的视图插件看看效果如何。  
### solon-view-freemarker 为什么不可以  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnk11NTmnd7JffBtHbVmGJBxoS6zCbL4KzGZ9lPxqHZ4bdrm6iccdRJHA/640?wx_fmt=png&from=appmsg "null")  
  
  
我们看到 freemarker 对 模板文件的路径进行了处理，不允许跨目录的访问  
  
org.noear.solon.view.freemarker.FreemarkerRender#render  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnZt27YH5BDL16cqbIJadZJ6fzQdyeNEdmaNLHV13D3ibYszD0Z9ndMeQ/640?wx_fmt=png&from=appmsg "null")  
  
  
org.noear.solon.view.freemarker.FreemarkerRender#render_mav  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQneQtvJQONaC3nRfMQibr6c1SJ6atOagqaZNqG76umpxibkicgQFADHNgZQ/640?wx_fmt=png&from=appmsg "null")  
  
  
freemarker.template.Configuration#getTemplate(java.lang.String, java.lang.String)  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQn7rnO1HuicOibTMnP23QPVvoqBeDZoS1tJiahqOhzgzibhuYfk2mqzKOT7w/640?wx_fmt=png&from=appmsg "null")  
  
  
freemarker.template.Configuration#getTemplate(java.lang.String, java.util.Locale, java.lang.Object, java.lang.String, boolean, boolean)  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnVruHibP6vMafj3FH6sGjZ4sQSkcWu1E4bg3rX0Sfezy1dk6NUB9iblZw/640?wx_fmt=png&from=appmsg "null")  
  
  
freemarker.cache.TemplateCache#getTemplate(java.lang.String, java.util.Locale, java.lang.Object, java.lang.String, boolean)  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnJ4Z65tZKPZVyMtkbQ80w66W0lXAhohgrfeeoyxlX4E4SNXEWVfexnA/640?wx_fmt=png&from=appmsg "null")  
  
  
调用 name = templateNameFormat.normalizeRootBasedName(name);  
 来对传入的模板文件名进行处理  
  
freemarker.cache.TemplateNameFormat.Default020300#normalizeRootBasedName  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQngEhPeB3ULubgWaia2kOLkV2AOdDDkSpee4aMHZtm5wNCIQP4Qg4r1aw/640?wx_fmt=png&from=appmsg "null")  
  
  
对传入的参数进行规范化处理，以确保安全并处理路径中的特殊序列。  
## 漏洞修复  
  
org.noear.solon.core.handle.RenderManager#getViewRender  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/5znJiaZxqldy2COaxL8F56qTdpgd3hjQnhXiaWGQf7rdzibACA5ZLvndsgypqvLdS8tu47IiaSlsdN2kl7dnOAZmtg/640?wx_fmt=png&from=appmsg "null")  
  
image  
  
我们注意到修复方式是添加了这一部分代码  
```
 if (mv.view().contains("../") || mv.view().contains("..\\")) {            // '../','..\' 不安全            throw new IllegalStateException("Invalid view path: '" + mv.view() + "'");        }
```  
  
看起来处理方式简单粗暴，实际上是非常有效的  
  
用户输入 → Context.param() → ModelAndView() → RenderManager.render()→ RenderManager.getViewRender()安全检测  
→模板引擎处理  
  
在模板引擎处理之前就添加了对传入路径的检测，一次 url 编码无法绕过，两次 url 编码虽然可以绕过检测，但是实际处理时，找不到文件所在的位置，再加上并不是从根目录开始读取文件的，最前面还存在目录限制，所以这样一来就无法利用这个漏洞了。  
  
   
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNTIwNTkyNg==&mid=2247549615&idx=1&sn=5de0fec4a85adc4c45c6864eec2c5c56&scene=21#wechat_redirect)  
  
