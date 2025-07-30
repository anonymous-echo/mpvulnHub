#  从代码看Java反序列化漏洞   
原创 信安魔方  锐鉴安全   2025-04-22 04:44  
  
声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
请大家关注公众号支持，不定期有宠粉福利  
  
  
Part-01  
  
    基础  
知识  
     
  
   
  
  Java 是面向对象编程的,当你想把某个对象存储起来以便长期使用时,便  
需要用到 Java 反序列化。最常见的反序列化情况便是服务器的 SESSION,当有大量用户  
并发访问,就有可能出现庞大数量的 SESSION 对象,内存显然不够用,于是 Web 容器便会将 SESSION 先序列化到硬盘中,等需要使用时,再将保存在硬盘中的对象还原到内存中,这个存储再拿出来的过程便是序列化和反序列化的过程。  
  
  一般来说,把对象转换为字节序列的过程称为对象的序列化,把字节序列恢复为对象的过程称为对象的反序列化。与 PHP 反序列化漏洞一样,一旦用户输入的不可信数据进  
  
行了反序列化操作,那么就有可能触发序列化参数中包含的恶意代码。这个非预期的对象  
  
产生过程很有可能会带来任意代码执行,以便攻击者做进一步的攻击。  
  
  在 Java 中反序列化漏洞之所以比较严重的原因之一是:Java 存在大量的公用库,例如 Apache Commons Collections。而这其中实现的一些类可以被反序列化用来实现任  
  
意代码执行。WebLogic、WebSphere、JBoss、Jenkins、OpenNMS 这些应用的反序列化漏洞能够得以利用,便是依靠了Apache Commons Collections。当然反序列漏洞的根源并不在于公共库,而是在于  
 Java 程序没有对反序列化生成的对象的类型做限制。  
  
  Java 反序列化漏洞一般有以下几种危害:任意代码执行,获取 SHELL,对服务器进行  
  
破坏。  
  
  Java 反序列化是一个全新的知识点,无论你之前是否了解过 Java 反序列化,接下来  
  
都将带领大家一同回顾学习 Java 序列化和反序列化的过程。提到 Java 的序列化与反序列化,我们不得不提及其序列化过程与反序列化过程。  
ObjectOutputStream 类的 writeObject() 方法可以对参数指定的 obj 对象进行序列化操作,并将得到的字节序列写到目标输出流中。相反的,ReadObject()方法则是从源输入流中读取字节序列,再将其反序列化为对象并返回。这有点类似于 PHP 中的 serialize()与  
unserialize()。  
  
  
      
  
     
   
Part-02  
  
java反序列化代码  
  
  
一、序列化  
  
    对于序列化的例子,我们可以先写一个 Person 类,内容如下:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP40o4OCF0iaNjibP7SKcBvB9r6tolo7ibSnzafT7hQCxMvLXSR27mdRZBHSnNAc9Jao5mKibk67DOpOYQ/640?wx_fmt=png&from=appmsg "")  
  
    
接着,我们编写一个包含序列化和反序列化的类 TestObjSerializeAndDeserialize 分别对其进行操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP40o4OCF0iaNjibP7SKcBvB9rI7OSOXTZqR10Nx8I3M6eff20A1mmDsukKmXUtEpUibcd6sUibwZic2RhA/640?wx_fmt=png&from=appmsg "")  
  
  运行 TestObjSerializeAndDeserialize 得到的结果。  
  
                   
 ![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP40o4OCF0iaNjibP7SKcBvB9rXHFQhqaRH9h0yibqchcKrA5GHq6NBQpfRwqIu0xgJUoEsMQvQ2cg4Ow/640?wx_fmt=png&from=appmsg "")  
  
  
  打开 Person.txt 文件可以发现以下内容。  
重点是ACED0005，序列化特征，面试重点，可以记下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP40o4OCF0iaNjibP7SKcBvB9rCwhBiaGGsN9GELfibTicWZicUicsaKupay5VQIOrAcDWaAlR9OnnJv44ibHQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
二、反序列化  
  
  readObject()在反序列化过程中起到了至关重要的作用,接下来让我们再看一个例子,首先编写一个 Evil 类,内容如下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP40o4OCF0iaNjibP7SKcBvB9rVpibsj8FMVZR2wxqYOUdAlxQ5fRhjTrNfm4mWlqqaBECmR8TjQZNusA/640?wx_fmt=png&from=appmsg "")  
  
  接着,编写我们进行序列化操作的类 SerializeAndDeserialize。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP40o4OCF0iaNjibP7SKcBvB9rKgu8kMRRFhPMdyAWISCF19hgxN3IicAdnRyjqxcGBmfnHBZJARkroTw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP40o4OCF0iaNjibP7SKcBvB9rNpmcmpQcF2slt2cjUL0EbULD6LGSZQcRxntuvZTZUtSGLUptKJohicw/640?wx_fmt=png&from=appmsg "")  
  
  
    运行编译出来的类,我们会发现成功地执行了“open -a Calculator”,从这里我们可以发现在序列化与反序列化编写不当的情况下,极有可能引发任意代码执行漏洞,反序列化，如下图。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP40o4OCF0iaNjibP7SKcBvB9rtxicKaHzqWvvhFDyuHBfh4IkZrGeKx71iciavDA2k3pfAul5f0Jtm7A2A/640?wx_fmt=png&from=appmsg "")  
  
  
三、如何发现反序列化漏洞  
  
    反序列化漏洞和其他基础漏洞一样,也需要特定的触发条件。我们在白盒审计时只需要通过搜索源代码中的这些特定函数即可快速地定位到可能存在问题的代码块。主要函数如下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP40o4OCF0iaNjibP7SKcBvB9r3Dgnictu3gLF9KAdcoddME6LZtUfr6doNxfTK8KFqSJBVPkSianC3siaw/640?wx_fmt=png&from=appmsg "")  
  
  
  当我们通过搜索关键函数或库,找到存在反序列化操作的文件时,便可开始考虑参数是否可控,以及应用的 Class Path 中是否包含 Apache Commons Collections 等危险库(ysoserial 所支持的其他库亦可)。同时满足了这些条件后,我们便可直接通过 ysoserial 生  
成所需的命令执行的反序列化语句，进一步验证漏洞是否存在。  
  
