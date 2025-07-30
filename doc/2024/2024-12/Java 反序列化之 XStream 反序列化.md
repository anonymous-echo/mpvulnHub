#  Java 反序列化之 XStream 反序列化   
 蚁景网安   2024-12-04 08:30  
  
## 0x01 XStream 基础  
### XStream 简介  
  
XStream 是一个简单的基于 Java 库，Java 对象序列化到 XML，反之亦然(即：可以轻易的将 Java 对象和 XML 文档相互转换)。  
### 使用 XStream 实现序列化与反序列化  
  
下面看下如何使用 XStream 进行序列化和反序列化操作的。  
  
先定义接口类  
  
**IPerson.java**  
```
public interface IPerson {  
    void output();  
}
```  
  
接着定义 Person 类实现前面的接口：  
```
public class Person implements IPerson {  
    String name;  
    int age;  
  
    public void output() {  
        System.out.print("Hello, this is " + this.name + ", age " + this.age);  
    }  
}
```  
  
XStream 序列化是调用 XStream.toXML() 来实现的：  
```
public class Serialize {  
    public static void main(String[] args) {  
        Person p = new Person();  
        p.age = 6;  
        p.name = "Drunkbaby";  
        XStream xstream = new XStream(new DomDriver());  
        String xml = xstream.toXML(p);  
        System.out.println(xml);  
    }  
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKweFtOJlOgztnuGIVL1K3zGBQPeznhiauElIribJY3XRib4tK4VThlnu0rg/640?wx_fmt=png "null")  
  
XStream 反序列化是用过调用 XStream.fromXML() 来实现的，其中获取 XML 文件内容的方式可以通过 Scanner() 或 FileInputStream 都可以：  
  
**Deserialize.java**  
```
import com.thoughtworks.xstream.XStream;  
import com.thoughtworks.xstream.io.xml.DomDriver;  
  
import java.io.File;  
import java.io.FileInputStream;  
import java.io.FileNotFoundException;  
import java.util.Scanner;  
  
public class Deserialize {  
    public static void main(String[] args) throws FileNotFoundException {  
//        String xml = new Scanner(new File("person.xml")).useDelimiter("\\Z").next();  
        FileInputStream xml = new FileInputStream("G:\\OneDrive - yapuu\\Java安全学习\\JavaSecurityLearning\\JavaSecurity\\XStream\\XStream\\XStream-Basic\\src\\main\\java\\person.xml");  
        XStream xstream = new XStream(new DomDriver());  
        Person p = (Person) xstream.fromXML(xml);  
        p.output();  
    }  
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwZU9aNQmphFZDQdTL0cLwy0Pp4jZWIwOuHKQeBLLItagyXWqArkZ1ibA/640?wx_fmt=png "null")  
### XStream 几个部分  
  
XStream 类图，参考  
XStream 源码解析：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwfL15XDc13FWNiawRefeRLuFGhRurKOlicJQsQm09utMxtJllJf3h9mPg/640?wx_fmt=png "null")  
  
主要分为四个部分：  
#### MarshallingStrategy 编码策略  
- • marshall : object->xml 编码  
  
- • unmarshall : xml-> object 解码  
  
两个重要的实现类：  
- • com.thoughtworks.xstream.core.TreeMarshaller : 树编组程序  
  
- • 调用 Mapper 和 Converter 把 XML 转化成 Java 对象  
  
> 其中的 start 方法开始编组  
  
  
其中调用了 this.convertAnother(item) 方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwqNiaoWAEPTwMQUvZlrP00rVIiaSbN4IRWAx685zaaaGPkK8DtWUYfbxA/640?wx_fmt=png "null")  
> convertAnother 方法的作用是把 XML 转化成 Java 对象。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKw1HbfbtRd9icDyywicicgHKDFdfThzPWFq69lWQ6GMSzetiaJ5PDhUz8kvg/640?wx_fmt=png "null")  
#### Mapper 映射器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKweTjQmFaEfZMiaP8jaicwTX3iaHG3Hp1qyxC0PHibK92yJkiahKCnckSfIqA/640?wx_fmt=png "null")  
  
简单来说就是通过 mapper 获取对象对应的类、成员、Field 属性的 Class 对象，赋值给 XML 的标签字段。  
#### Converter 转换器  
  
XStream 为 Java 常见的类型提供了 Converter 转换器。转换器注册中心是 XStream 组成的核心部分。  
  
转换器的职责是提供一种策略，用于将对象图中找到的特定类型的对象转换为 XML 或将 XML 转换为对象。  
  
简单地说，就是输入 XML 后它能识别其中的标签字段并转换为相应的对象，反之亦然。  
  
转换器需要实现 3 个方法，这三个方法分别是来自于 Converter 类以及它的父类 ConverterMatcher  
- • canConvert 方法：告诉 XStream 对象，它能够转换的对象；  
  
- • marshal 方法：能够将对象转换为 XML 时候的具体操作；  
  
- • unmarshal 方法：能够将 XML 转换为对象时的具体操作；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwHalP7UXGKkTw9mA4OvR67zsT4Zrs1NBRQNEFcYuOtdEtlneh171dUQ/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwVcLhGGYmC9ncwOhAfMbXdtp8pGx69mDeqIiang7evtAk5K5Lnq1J6dg/640?wx_fmt=png "null")  
  
具体参考：http://x-stream.github.io/converters.html  
  
这里告诉了我们针对各种对象，XStream 都做了哪些支持。  
#### EventHandler 类  
  
EventHandler 类为动态生成事件侦听器提供支持，这些侦听器的方法执行一条涉及传入事件对象和目标对象的简单语句。  
  
EventHandler 类是实现了 InvocationHandler 的一个类，设计本意是为交互工具提供 beans，建立从用户界面到应用程序逻辑的连接。  
  
EventHandler 类定义的代码如下，其含有 target 和 action 属性，在 EventHandler.invoke()->EventHandler.invokeInternal()->MethodUtil.invoke() 的函数调用链中，会将前面两个属性作为类方法和参数继续反射调用：  
```
public class EventHandler implements InvocationHandler {  
    private Object target;  
    private String action;  
    ...  
      
    public Object invoke(final Object proxy, final Method method, final Object[] arguments) {  
        ...  
                return invokeInternal(proxy, method, arguments);  
        ...  
    }  
      
    private Object invokeInternal(Object proxy, Method method, Object[] arguments) {  
        ...  
              
                Method targetMethod = Statement.getMethod(  
                             target.getClass(), action, argTypes);  
                ...  
                return MethodUtil.invoke(targetMethod, target, newArgs);  
            }  
            ...  
    }  
  
    ...  
}
```  
  
这里重点看下 EventHandler.invokeInternal() 函数的代码逻辑，如注释：  
```
private Object invokeInternal(Object var1, Method var2, Object[] var3) {  
//-------------------------------------part1----------------------------------  
//作用:获取interface的name,即获得Comparable,检查name是否等于以下3个名称  
        String var4 = var2.getName();  
        if (var2.getDeclaringClass() == Object.class) {  
            if (var4.equals("hashCode")) {  
                return new Integer(System.identityHashCode(var1));  
            }  
  
            if (var4.equals("equals")) {  
                return var1 == var3[0] ? Boolean.TRUE : Boolean.FALSE;  
            }  
  
            if (var4.equals("toString")) {  
                return var1.getClass().getName() + '@' + Integer.toHexString(var1.hashCode());  
            }  
        }  
//-------------------------------------part2----------------------------------  
//貌似获取了一个class和object  
        if (this.listenerMethodName != null && !this.listenerMethodName.equals(var4)) {  
            return null;  
        } else {  
            Class[] var5 = null;  
            Object[] var6 = null;  
            if (this.eventPropertyName == null) {  
                var6 = new Object[0];  
                var5 = new Class[0];  
            } else {  
                Object var7 = this.applyGetters(var3[0], this.getEventPropertyName());  
                var6 = new Object[]{var7};  
                var5 = new Class[]{var7 == null ? null : var7.getClass()};  
            }  
//------------------------------------------------------------------------------  
            try {  
                int var12 = this.action.lastIndexOf(46);  
                if (var12 != -1) {  
                    this.target = this.applyGetters(this.target, this.action.substring(0, var12));  
                    this.action = this.action.substring(var12 + 1);  
                }  
//--------------------------------------part3----------------------------------------  
//var13获取了method的名称, var13=public java.lang.Process java.lang.ProcessBuilder.start() throws java.io.IOException  
                Method var13 = Statement.getMethod(this.target.getClass(), this.action, var5);  
//--------------------------------------------------------------------------  
//判断var13是否为空,当然不为空啦  
                if (var13 == null) {  
                    var13 = Statement.getMethod(this.target.getClass(), "set" + NameGenerator.capitalize(this.action), var5);  
                }  
  
                if (var13 == null) {  
                    String var9 = var5.length == 0 ? " with no arguments" : " with argument " + var5[0];  
                    throw new RuntimeException("No method called " + this.action + " on " + this.target.getClass() + var9);  
                } else {  
//-------------------------------------part4----------------------------------  
//调用invoke,调用函数,执行命令  
                    return MethodUtil.invoke(var13, this.target, var6);  
                }  
//------------------------------------------------------------------------------  
            } catch (IllegalAccessException var10) {  
                throw new RuntimeException(var10);  
            } catch (InvocationTargetException var11) {  
                Throwable var8 = var11.getTargetException();  
                throw var8 instanceof RuntimeException ? (RuntimeException)var8 : new RuntimeException(var8);  
            }  
        }  
}
```  
  
有一说一看到这里的时候，就感觉 XStream 可能比较多的会通过动态代理作为 sink  
#### DynamicProxyConverter 动态代理转换器  
  
DynamicProxyConverter 即动态代理转换器，是 XStream 支持的一种转换器，其存在使得 XStream 能够把 XML 内容反序列化转换为动态代理类对象：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKw0ZcqffUTUynPVCXWpgcqhRkMQuWico23xamO21s8EByMyDANciaC5TgQ/640?wx_fmt=png "null")  
  
XStream 反序列化漏洞的 PoC 都是以 DynamicProxyConverter 这个转换器为基础来编写的。  
  
以官网给的例子为例：  
```
<dynamic-proxy>  
  <interface>com.foo.Blah</interface>  
  <interface>com.foo.Woo</interface>  
  <handler class="com.foo.MyHandler">  
    <something>blah</something>  
  </handler>  
</dynamic-proxy>
```  
  
dynamic-proxy 标签在 XStream 反序列化之后会得到一个动态代理类对象，当访问了该对象的com.foo.Blah 或 com.foo.Woo 这两个接口类中声明的方法时（即 interface 标签内指定的接口类），就会调用 handler 标签中的类方法 com.foo.MyHandler  
## 0x02 CVE-2013-7285  
  
**PoC**  
```
<sorted-set>  
  <dynamic-proxy>  
    <interface>java.lang.Comparable</interface>  
    <handler class="java.beans.EventHandler">  
      <target class="java.lang.ProcessBuilder">  
        <command>  
          <string>Calc</string>  
        </command>  
      </target>  
      <action>start</action>  
    </handler>  
  </dynamic-proxy>  
</sorted-set>
```  
  
看到 PoC 这里大致是明白了，在之前有一段代码是读取每一个 XML 的节点，读取这些节点之后应该是用动态代理触发 invoke() 了  
  
**触发代码**  
```
import com.thoughtworks.xstream.XStream;  
import com.thoughtworks.xstream.io.xml.DomDriver;  
  
import java.io.FileInputStream;  
  
// CVE_2013_7285 Exploit  
public class CVE_2013_7285 {  
    public static void main(String[] args) throws Exception{  
        FileInputStream fileInputStream = new FileInputStream("G:\\OneDrive - yapuu\\Java安全学习\\JavaSecurityLearning\\JavaSecurity\\XStream\\XStream\\XStream-Basic\\src\\main\\java\\person.xml");  
        XStream xStream = new XStream(new DomDriver());  
        xStream.fromXML(fileInputStream);  
    }  
}
```  
### 漏洞原理  
  
XStream 反序列化漏洞的存在是因为 XStream 支持一个名为 DynamicProxyConverter 的转换器，该转换器可以将 XML 中 dynamic-proxy 标签内容转换成动态代理类对象，而当程序调用了 dynamic-proxy 标签内的 interface 标签指向的接口类声明的方法时，就会通过动态代理机制代理访问 dynamic-proxy 标签内 handler 标签指定的类方法。  
  
利用这个机制，攻击者可以构造恶意的XML内容，即 dynamic-proxy 标签内的 handler 标签指向如 EventHandler 类这种可实现任意函数反射调用的恶意类、interface 标签指向目标程序必然会调用的接口类方法；最后当攻击者从外部输入该恶意 XML 内容后即可触发反序列化漏洞、达到任意代码执行的目的。  
### 漏洞分析  
  
下断点调试一下，这里前面的流程和分析 XStream 流程是类似的，会调用HierarchicalStreams.readClassType() 来获取到 PoC XML 中根标签的类类型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwrNPdicp4cAtZY8ibCicgBx6z6GJYwXW8N8IZry7jbEVhaMqQJztjKVpaA/640?wx_fmt=png "null")  
  
后面会跟进到 mapper.realClass() 进行循环遍历，用来查找 XML 中的根标签为何类型（前面也都分析过了），接着是调用 convertAnother() 函数对 java.util.SortedSet 类型进行转换，我们跟进去该函数，其中调用 mapper.defaultImplementationOf() 函数来寻找 java.util.SortedSet 类型的默认实现类型进行替换，这里转换为了 java.util.TreeSet 类型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwVeRsXPzeO13sLw8EG0iakzoVD0SB5HuCvSTlSODjzc6eHjHEXplicic1Q/640?wx_fmt=png "null")  
  
接着就是寻找 Convert 的过程，这里寻找到对应的转换器是 TreeMapConverter 转换器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKw2eLqlCGcxpLfs2O1UHSawdB3qVOOhR6ZrWJJUgR3doJPRwFGCiayOVw/640?wx_fmt=png "null")  
  
往下调试，在 AbstractReferenceUnmarshaller.convert() 函数中看到，会调用 getCurrentReferenceKey() 来获取当前的 Reference 键，并且会将当前的 Reference 键压到栈中，这个 Reference 键后续会和保存的类型 —— java.util.TreeSet 类一一对应起来。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwEjg1ZvPbkDZf3BMUlMtRBy5wPFyicncnQ3L4v08RbrvVztYJ5MicLB3g/640?wx_fmt=png "null")  
  
接着调用其父类即的 FastStack.convert() 方法，跟进去，显示将类型压入栈，然后调用转换器 TreeSetConverter 的 unmarshal() 方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwWOr4OpWpZk9GGeHbCLlf306M23ThP8NvOnRG4qX2653HYg4WPJiakag/640?wx_fmt=png "null")  
  
在它第 61 行调用了 treeMapConverter.unmarshalComparator() 方法，这个方法获取到了第二个 XML 节点元素，这个方法当时漏看了，这个方法还是比较重要的，它获取到了 xml 根元素的子元素。  
  
跟进之后就变得一目了然了，其中判断 reader 是否还有子元素  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwextbdV8DpoCakQ5pJCyxqH1DXqlwicYkEn2XGkYX84tcgpFXrB4YNPQ/640?wx_fmt=png "null")  
  
下面的 reader.movedown() 方法做了获取子元素，并把子元素添加到当前 context 的 pathTracker  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwlk3rBnPVNd9rDs5jYF3LYDKjTfhDHSzxQH1CCrXMiamUCCso2fOAVtQ/640?wx_fmt=png "null")  
  
往下调试，在 TreeSetConverter.unmarshal() 方法中调用了 this.treeMapConverter.populateTreeMap()，从这个方法开始，XStream 开始处理了 XML 里面其他的节点元素。跟进该函数，先判断是否是第一个元素，是的话就调用 putCurrentEntryIntoMap()函数，即将当前内容缓存到 Map 中：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKw25Y5bCEiaGjVsXfp30as3IQU5GIhNeswE2AdNpYcxIJhekrV5ItclCg/640?wx_fmt=png "null")  
  
跟进去，发现调用 readItem() 方法读取标签内的内容并缓存到当前 Map 中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwIyZcqe4B3zkV79icLUqicjkFdV0aUvelF6ddoq3CtrkACGA8Oc3fb9Aw/640?wx_fmt=png "null")  
  
这里再跟进 readItem() 方法，会发现比较有意思的一点是它又调用了 HierarchicalStreams.readClassType() 和 context.convertAnother() 方法，而这里的元素已经变成了第二个元素，也就是 <dynamic-proxy>，这里有点像是递归调用  
  
可以跟进去看一下，这里通过查看 mapper 可以知道目前拿去保存在 mapper 当中的还是两个元素，而 XStream 的处理，则会处理最新的一个（最里层的一个）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwL8miciaYGH0cEWpnl06SRPMEuuCcZ5BzMDvoPZhKtexkpgb5IFicTXtIw/640?wx_fmt=png "null")  
  
经过处理之后返回的 type 就为最新的一个子元素的类型，这里是 com.thoughtworks.xstream.mapper.DynamicProxyMapper$DynamicProxy，对应的转换器为 DynamicProxyConverter，跟进到其中来看具体处理。  
  
先判断当前元素是否还有子元素，并获取该子元素进行后续判断  
  
根据我们所编写的 xml，获取到的子元素为 <interface>，经过判断 if (elementName.equals("interface"))，如果为 true，则将目前 <interface> 节点的元素获取到，再获得转换类型。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKw86DbaKw7bYVPa03iaQS6HicrDFsF0MQ8xOoFnATuVuB30u8E87tom8IQ/640?wx_fmt=png "null")  
  
因为仍旧存在子元素，获取完 <interface> 后重新进入这个迭代，下一个获取到的子元素是 <handler>。这里程序会判断是否等于 handler，如果等于 handler，则获取它标签所对应的类，并跳出迭代。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwESgQe58jzfFjE03w0Xh9LibPpmM0Rz6wcbOqFLTvozJd59vwSfiaL8Jg/640?wx_fmt=png "null")  
  
往下走，第 125 行调用了 Proxy.newProxyInstance() 方法，这里是动态代理中的，实例化代理类的过程。第 127 行这里，调用 context.convertAnother() 方法，跟进一下。对应的转换器是 AbstractReflectionConverter，它会先调用 instantiateNewInstance() 方法实例化一个 EventHandler 类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwJL3DI6az8wHSbRPBTQ8cRzKCFL21rmibeaEAEydgD6Uhao3vTsI8bPw/640?wx_fmt=png "null")  
  
往下，跟进 doUnmarshal() 方法，这里又是一层内部递归，从 xml 中可以看到 <handler> 节点之下还有很多子节点（又看到了熟悉的 hasChildren()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwFYYhkan71MhWA40TvciaEeFlVIBwRyPvt2uibr6Couml2Q2VU7Bc6jaQ/640?wx_fmt=png "null")  
  
这时我们获取到的 type 为 class java.lang.ProcessBuilder，跟进 unmarshallField() 方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwMricGEjegicq7FBjoEZhsrk5xytttic7FCS0P8PDvu5icldUf8zG2uDtNA/640?wx_fmt=png "null")  
  
后面也都是类似的运行流程了，这里就不再废话，师傅们可以自行分析一下，是很容易看懂的；XSteam 虽然处理了 xml，且我们也基本明白了基础运行流程，但是最后漏洞触发这里还是要关注一下。  
  
将所有的节点过完一遍之后，最终还是会走到 treeMapConverter.populateTreeMap() 这个地方  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwmlr29ZiaTzHfAZudLRCbSU1Q1kwl6kCiaxxqIENCTbVvNc3PzEDJvkXw/640?wx_fmt=png "null")  
  
跟进，直到第 122 行，调用 put.All() 方法，里面的变量为 sortedMap，查看一下它的值可以发现这是一串链式存储的数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKw1aI6FXaHYhNLehjOPs4Uh4LMIC1WdwJ25IT98rmA878S2UfP8T0r8w/640?wx_fmt=png "null")  
  
最终是调用到 EventHandler.invoke() 方法调用栈如下，还是比较简单的  
```
invoke:428, EventHandler (java.beans)
compareTo:-1, $Proxy0 (com.sun.proxy)
compare:1294, TreeMap (java.util)
put:538, TreeMap (java.util)
putAll:281, AbstractMap (java.util)
putAll:327, TreeMap (java.util)
populateTreeMap:122, TreeMapConverter (com.thoughtworks.xstream.converters.collections)
```  
  
最后成功调用了 java.lang.ProcessBuilder#start 方法，命令执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LdhSssl9qquESbSepwdMJKwXPdIvTcQJvXmc1DVWOfBLEnnDvTibwDialRebDZLglMAsLRw6uWicOBug/640?wx_fmt=png "null")  
## 0x03 漏洞修复  
  
根据官方的修复手段，这里其实增加了黑名单  
  
Users can register an own converter for dynamic proxies, the   
java.beans.EventHandler type or for the   
java.lang.ProcessBuilder type, that also protects against an attack for this special case:  
```
xstream.registerConverter(new Converter() {
  public boolean canConvert(Class type) {
    return type != null && (type == java.beans.EventHandler || type == java.lang.ProcessBuilder || Proxy.isProxy(type));
  }

  public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
    throw new ConversionException("Unsupported type due to security reasons.");
  }

  public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
    throw new ConversionException("Unsupported type due to security reasons.");
  }
}, XStream.PRIORITY_LOW);
```  
## 0x04 小结  
  
XStream 最基础的漏洞是 CVE-2013-7285，通过这个漏洞可以很好的先认识 XStream 的基础运行流程，后续的漏洞挖掘和修复也算是一些《攻防史》，还是比较有意思的  
## 0x05 Ref  
  
https://x-stream.github.io/CVE-2013-7285.html  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6iavic0tIJIoZCwKvUYnFFiaibgSm6mrFp1ZjAg4ITRicicuLN88YodIuqtF4DcUs9sruBa0bFLtX59lQQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
学习  
网安实战技能课程  
，戳  
“阅读原文”  
  
