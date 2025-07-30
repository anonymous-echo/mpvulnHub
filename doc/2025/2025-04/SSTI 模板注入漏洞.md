#  SSTI 模板注入漏洞   
原创 信安魔方  锐鉴安全   2025-04-28 10:24  
  
声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
请大家关注公众号支持，不定期有宠粉福利  
  
  
Part-01  
  
    基础  
知识  
     
  
SSTI 是服务器端模板注入(Server-Side Template Injection)的英文首字母编写。模板引擎支持使用静态模板文件,在运行时用 HTML 页面中的实际值替换变量/占位符,从而让 HTML 页面的设计变得更容易。当前广泛应用的模板引擎有 Smarty、Twig、Jinja2、FreeMarker 及 Velocity 等。若攻击者可以完全控制输入模板的指令,并且模板能够在服务器端被成功地进行解析,则会造成模板注入漏洞。  
  
  
SSTI 漏洞在 Python 和 PHP 中非常常见,以至于一提起 SSTI 漏洞人们第一个想到的往往是 Python 中的 Flask。其实 SSTI 漏洞在其他语言中同样存在,如本章我们提到的Java 中的 SSTI 漏洞。下图介绍了常见模板及编程语言中,  
模板注入的常见的检测标签及可进行检测的工具如下红色框，渗透测试时，看见此特征，可尝试SSTI注入尝试。  
  
  
一般而言,SSTI 漏洞的危害有:任意代码执行,获取 SHELL,破坏服务器完整性等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4aQ1vdqiby3y8A3SNNXpIiaIYyicngWfDhib89OynBEFLH0UynQykBGDeibTOBOyGvsMHpbh396OMKM6Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4aQ1vdqiby3y8A3SNNXpIiaIkN8x2PaUVmTQEYiavqs7FJ6ux4RKkDNBGRgkpGUp2EDf8NYvC9Ywnow/640?wx_fmt=png&from=appmsg "")  
  
  
  
Part-02  
  
SSTI漏洞发现方法  
  
  
SSTI 漏洞与模板引擎有关,那么在对 SSTI 漏洞进行代码审计时只需搜索模板引擎的关键字即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4aQ1vdqiby3y8A3SNNXpIiaIWt3TOztQke48vCCE6d60WWM8XQ66MNpwsnogTd7B0vk4j2WZvbVTVw/640?wx_fmt=png&from=appmsg "")  
  
通过搜索关键字,我们可以快速地找到关键代码片段。  
```
private static void velocity(String template){
Velocity.init();
VelocityContext context = new VelocityContext();
context.put("name", "QCCP");
context.put("level", "code safe");
StringWriter swOut = new StringWriter();
Velocity.evaluate(context, swOut, "test", template);
}
```  
  
  
Demo 较为简单,通读代码很容易发现其主要功能是:将从 URL 中获取 template 参数传入模板引擎进行渲染,在此过程中未对 template 做任何过滤。也就是说,这里的输入完全可控,那么我们便可以构造恶意语句使其渲染恶意代码,以达到任意代码执行的目的。  
```
template=%23set($e=%22e%22);$e.getClass().forName(%22java.lang.Runtime%22).getMethod(%22getR
untime%22,null).invoke(null,null).exec(%22open%20-a%20Calculator%22)
```  
  
  
代码执行情况。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4aQ1vdqiby3y8A3SNNXpIiaI70A4wLsvVzTX4fZOJF7GpuNFWLPiaoYvVQyTfPgkNnoQOicib6k3LwsQg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
