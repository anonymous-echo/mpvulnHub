#  代码审计:jar-analyzer 分析漏洞 Apache Commons Text RCE   
原创 uname  黑伞安全   2023-12-03 17:59  
  
争取B站每周更新！文章投稿来自  
uname 。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvjDWiaiamaBr5dk4F5EaMCJHmz10icJUoT9eML7Dq0CwMicY7buRtgpRmTNw/640?wx_fmt=png&from=appmsg "")  
  
Jar Analyzer 是一个分析 Jar 文件的 GUI 工具：  
- 支持大 Jar 以及批量 Jars 分析  
  
- 方便地搜索方法之间的调用关系  
  
- 分析 LDC 指令定位 Jar 中的字符串  
  
- 一键分析 Spring Controller/Mapping  
  
- 对于方法字节码和指令的高级分析  
  
- 一键反编译，优化对内部类的处理  
  
- 一键生成方法的 CFG 分析结果  
  
- 一键生成方法的 Stack Frame 分析结果  
  
- 自定义 SQL 语句进行高级分析  
  
漏洞环境Apache Commons Text  
  
CVE-2022-42889 Apache Commons Text 1.5 <= Apache Commons Text <= 1.9  
  
org.apache.commons.text.lookup.StringLookup 的实例。从 1.5 版到 1.9 版，攻击者可构造恶意文本，使得Apache Commons Text 在解析时执行任意恶意代码。  
  
Apache Commons Text 1.9  
  
使用  
jar-ayalyzer  
分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvjmapVZYpe7HugEd2EWibzTMUFmf0SvYcLYIC9LTiaJMQo6icib4aYR4yH2A/640?wx_fmt=png&from=appmsg "")  
  
导入后点击start engine。我们知道CVE-2022-42889主要触发点是lookup调用了ScriptEngine的eval方法造成代码执行。  
  
方法一： 在search类别里进行搜索  
  
这里可以得到org.apache.commons.text.lookup$lookup方法调用了scriptEngine.eval。然后key可控， script =
keys[1]，所以慢慢往上走就可以了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvj05VmpRfxOgrFlp10UaVmcKmXGLenlx3qHGLoGrYzYKdYefQ0UOicricg/640?wx_fmt=png&from=appmsg "")  
  

				  
  
方法二：b站刚发视频如下  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvj5mFLicP0KrSFu0OHm2iaD31H3kjXqxmZ97YgPCNBVz7JZruYPMYibtaXA/640?wx_fmt=png&from=appmsg "")  
  
在call界面，有caller，callee两个界面。caller表示哪个方法调用了lookup方法，callee表示lookup里调用了什么方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvjMhGkHHpF6Ae7mMw53wLgYuGXEfnQ5WDcDS6wabP01E5IJGHd510RkQ/640?wx_fmt=png&from=appmsg "")  
  
往上来到了StringLookup接口，上面是调用，下面是实现类。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvjb6AchCm07AzdoU9sXmHpiavCdOfTYicOHno8n0uAv3koZK1dZt1XxNBw/640?wx_fmt=png&from=appmsg "")  
  
也可以在impl里面查看接口的实现类。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvj6zgfj9vkmiaicsV1kDYfXJPE3M15VIpXqr848CEmKFVbhE6BCQNV6r0Q/640?wx_fmt=png&from=appmsg "")  
  
往上来到了 org.apache.commons.text$StringSubstitutor#resolveVariable, 可以看到都可传。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvjVbESb3icricJiccAPVdBxxcomlBFKZaZuvVL0MIX51HricXA3kicVgvDqxQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvj3ZkiayaA57dEic5euzdUXo0FkvuXY70iaQRu3Tq16Pf18vEYar0XT1wTw/640?wx_fmt=png&from=appmsg "")  
  
org/apache/commons/text/StringSubstitutor#substitute，之间如果有别的调用，慢慢分析也就有很多其他的触发链，但这个好像并没有  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvjZD9drfev1hEjhvDUYtejJiadSo2uctMkEicgLyU6I8naomulmSl0icVibw/640?wx_fmt=png&from=appmsg "")  
  
最后可以看⻅replace调用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvjr2ACl4euYXibBf5QoRjjayVicJd8EM2OYRibibpD8OibKQK0vic0DsZ49o4Q/640?wx_fmt=png&from=appmsg "")  
  
都是差不多的处理。  
  
漏洞深度利用参考：  
https://forum.butian.net/share/1973  
  
Poc  
```
StringSubstitutor stringSubstitutor = StringSubstitutor.createInterpolator();
stringSubstitutor.replace("${script:javascript:2 + 2});
```  
  
  
参考：  
  
https://lists.apache.org/thread/n2bd4vdsgkqh2tm14l1wyc3jyol7s1om  
  
https://forum.butian.net/share/1973  
  
https://github.com/jar-analyzer/jar-analyzer  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrADvRRowCmc7KCjXSvljvjPc9zSuahKlnsKTXnjGgLPK1ibx1EIiaEWO7zYa9E5ZPl8zDfCficEltBQ/640?wx_fmt=png&from=appmsg "")  
  
