#  Android漏洞之战——整体加壳原理和脱壳技巧详解   
随风而行aa  看雪学苑   2022-07-09 17:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FrP0dufj0UvLSqPj6BWy5oIrr1bvP1q1awUvicOFLZKmAxvMxauA74Cw9998F5ibXjnlBycB3vqIzA/640?wx_fmt=jpeg "")  
  
本文为看雪论坛优秀文章看雪论坛作者ID：随风而行aa  
  
  
一  
  
  
**前言**  
  
  
为了帮助更加方便的进行漏洞挖掘工作，前面我们通过了几篇文章详解的给大家介绍了动态调试技术、过反调试技术、Hook技术、过反Hook技术、抓包技术等，掌握了这些可以很方便的开展App漏洞挖掘工作，而最后我们还需要掌握一定的脱壳技巧，进行进一步助力我们漏洞挖掘的效率。  
  
  
本文主要介绍Android App加壳中的整体dex加壳，帮助大家掌握加壳的原理和脱壳的各种技能。  
  
   
  
本文第二节主要讲述Android启动流程和加壳原理。  
  
   
  
本文第三节主要介绍整体加壳的实现。  
  
   
  
本文第四节主要讲当下脱壳点的概念。  
  
   
  
本文第五节讲述现有的脱壳技巧。  
  
  
  
二  
  
  
**相关介绍**  
###   
### 1.Android App启动流程  
####   
#### （1）Android系统启动流程  
  
  
我们要彻底的了解App加壳原理，首先我们从了解App的启动流程出发，先于App启动之前，Android系统是启动最早，下面我们来详细查看一下Android系统的启动过程：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7vd6qOiaFW40gYmdFXMKFWAkqajMyLL9fVs3Z8vLHx0VkoLXIJY5kTsw/640?wx_fmt=png "")  
  
   
  
我在Xposed源码定制（  
https://blog.csdn.net/hzwailll/article/details/85339714  
）  
一文中详细的讲解了Android的启动流程，简单来说就是：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7lLg6XnEYJc4roweULbibbDto5hHWDZyUOJ7ntanmHTHVqhRhEEYfFbw/640?wx_fmt=png "")  
  
```
加载BootLoader --> 初始化内核 --> 启动init进程 --> init进程fork出Zygote进程 --> Zygote进程fork出SystemServer进程
```  
  
  
我们就了解了最后Zygote进程fork出第一个进程：SystemServer进程，SystemServer主要完成了以下工作：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7FEKjMhgKQThgtWe9ZruNHBNibojLTPKSbBlqKjKBxQBs5lHLN34I3cA/640?wx_fmt=png "")  
  
   
  
android app安装  
  
   
  
首先这里我们先介绍一下PackageManagerService，其主要是完成Android中应用程序安装的服务，我们了解的Android应用程序安装的方式：  
```
· 系统启动时安装，没有安装界面
· 第三方应用安装，有安装界面，也是我们最熟悉的方式
· ADB命令安装，没有安装界面
· 通过各类应用市场安装，没有安装界面
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7mibQHXCoDFTt5oZBGib63R9icMZjDBE4UyLyIfJibNuEEPia4Ol8fw5aExw/640?wx_fmt=png "")  
  
   
  
虽然安装方式不同，但是最后四种方式都是通过PackageManagerService服务来完成应用程序的安装。而PackageManagerService服务则通过与Installd服务通信，发送具体的指令来执行应用程序的安装、卸载等工作。  
```
public static final IPackageManager main(Context context, Installer installer,
    boolean factoryTest, boolean onlyCore) {
        PackageManagerService m = new PackageManagerService(context, installer, factoryTest, onlyCore);
        ServiceManager.addService("package", m);
    return m;
}
```  
  
  
应用程序在安装时涉及到如下几个重要目录：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7g1Vj55eQQE6UAzJQEszghicHric5fa0AKv0hPdia1sJ7FIC9jeiaTm3TDA/640?wx_fmt=png "")  
  
   
  
我们了解完App的安装流程是由PackageManagerService，同理SystemServer启动了一个更加重要的服务ActivityManagerService, 而AMS其中很重要的一个作用就是启动Launcher进程，具体是怎么启动的，大家可以参考文章:Android系统启动流程（四）Launcher启动过程与系统启动流程（  
https://blog.csdn.net/itachi85/article/details/56669808  
），这里就不再详细讲解，而进入Launcher进程，我们就进入了App启动的流程。  
  
#### （2）App启动流程  
  
  
Android系统启动的最后一步是启动一个Home应用程序，这个应用程序用来显示系统中已经安装的应用程序，这个Home应用程序就叫做Launcher。应用程序Launcher在启动过程中会请求PackageManagerService返回系统中已经安装的应用程序的信息，并将这些信息封装成一个快捷图标列表显示在系统屏幕上，这样用户可以通过点击这些快捷图标来启动相应的应用程序。  
  
   
  
前面我们描述了AMS将Launcher启动，然后进入App启动流程，这里参考文章：ActivityThread的理解和APP的启动过程（  
https://blog.csdn.net/hzwailll/article/details/85339714  
）  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu77n6duExVoBNW5kWu7ILH7umb5DgF2zich366AG8Bjbs34UIs6gO6aqg/640?wx_fmt=png "")  
  
  
① 点击桌面APP图标时，Launcher的startActivity()方法，通过Binder通信，调用system_server进程中AMS服务的startActivity方法，发起启动请求。  
  
  
② system_server进程接收到请求后，向Zygote进程发送创建进程的请求。  
  
  
③ Zygote进程fork出App进程，并执行ActivityThread的main方法，创建ActivityThread线程，初始化MainLooper，主线程Handler，同时初始化ApplicationThread用于和AMS通信交互。  
  
  
④ App进程，通过Binder向sytem_server进程发起attachApplication请求，这里实际上就是APP进程通过Binder调用sytem_server进程中AMS的attachApplication方法,AMS的attachApplication方法的作用是将ApplicationThread对象与AMS绑定。  
  
  
⑤ system_server进程在收到attachApplication的请求，进行一些准备工作后，再通过binder IPC向App进程发送handleBindApplication请求（初始化Application并调用onCreate方法）和scheduleLaunchActivity请求（创建启动Activity）。  
  
  
⑥ App进程的binder线程（ApplicationThread）在收到请求后，通过handler向主线程发送BIND_APPLICATION和LAUNCH_ACTIVITY消息，这里注意的是AMS和主线程并不直接通信，而是AMS和主线程的内部类ApplicationThread通过Binder通信，ApplicationThread再和主线程通过Handler消息交互。  
  
  
⑦ 主线程在收到Message后，创建Application并调用onCreate方法，再通过反射机制创建目标Activity，并回调Activity.onCreate()等方法。  
  
  
⑧ 到此，App便正式启动，开始进入Activity生命周期，执行完onCreate/onStart/onResume方法，UI渲染后显示APP主界面。  
  
  
到这里，我们的大致弄清了APP的启动流程，而这里我们就进入了加壳中十分重要的地方ActivityTread。  
  
#### （3）ActivityThread启动流程  
  
  
寒冰大佬在FART：ART环境下基于主动调用的自动化脱壳方案（https://bbs.pediy.com/thread-252630.htm  
） 一文中讲述了ActivityThread.main()是进入App世界的大门，并由此展开了对加壳原理的讲述。  
  
   
  
同理接下来，我们开始进行源码分析，了解ActivityThread的具体操作：  
  
   
  
xref/frameworks/base/core/java/android/app/ActivityThread.java  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu70BQv36cvdfAkibGBXfvtFEcqbnTYdrYn0LSyic6d7UO2ibVPaYrEmTYBw/640?wx_fmt=png "")  
  
   
  
根据寒冰大佬描述，在ActivityThread完成实例化操作，调用thread.attach(false)完成一系列初始化准备工作，最后主线程进入消息循环，等待接收来自系统的消息。当收到系统发送来的bindapplication的进程间调用时，调用函数handlebindapplication来处理该请求。  
```
public void handleMessage(Message msg) {
****
    case BIND_APPLICATION:
        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "bindApplication");
        AppBindData data = (AppBindData)msg.obj;
        handleBindApplication(data);
        Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
        break;
****
}
```  
  
  
在处理消息过程，很很明显进入了handlebindapplication函数。  
  
   
  
这里我再用寒冰大佬文章的内容：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7khwVz9GzldiaTgn2XibJY9oMibYaf7HLuicTeDyPiaDnAIHtRicYaiavlFa2g/640?wx_fmt=png "")  
  
   
  
我们定位第四步，Application进行实例化，然后进入makeApplication。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7aTXqPudbWnSjCPYsUM35jU9QMHx62PzlqaicicDQNlP1NPhjxean4D7w/640?wx_fmt=png "")  
  
   
  
然后我们进入newApplication。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7no1YoG0SFNC7ChFCiaNH4Rs4ONH7FcVOtkprn4Enxr6cULP9ojHemQg/640?wx_fmt=png "")  
  
   
  
这里我们可以看见完成了两件事：  
  
① 完成了Application的实例化；  
  
② 并调用Application.attach()函数。  
  
  
然后我们继续进入Application.attach()函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7TkMiaeIN8lyy4Cx3LnOx9hx278a1ibdSHX5KSeqKWQwicf0Nwp6ctRJ9A/640?wx_fmt=png "")  
  
   
  
这里我们就进一步调用了attachBaseContext()方法。  
  
   
  
最后回到handlebindapplication中执行第6步，进入callApplicationOnCreate()函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7U4B4h1chEUdnxdCmpWicibNcGmLDDzkAP08vjRgG4YdRaT7RNlMm80Sw/640?wx_fmt=png "")  
  
   
  
就执行了Application.onCreate()方法。  
  
   
  
总结：  
  
  
从上可知, App的运行流程是  
  
初始化————>Application的构造函数————>Application.attachBaseContext()————>Application.onCreate()函数  
  
  
最后才会进入MainActivity中的attachBaseContext函数、onCreate函数  
  
所以加壳厂商要在程序正式执行前，也就是上面的流程中进行动态加载和类加载器的修正，这样才能对加密的dex进行释放，而一般的1厂商往往选择在Application中的attachBaseContext或onCreate函数进行。  
  
  
这里我附上网上一个大佬的详细执行流程图：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7vd6qOiaFW40gYmdFXMKFWAkqajMyLL9fVs3Z8vLHx0VkoLXIJY5kTsw/640?wx_fmt=png "")  
  
### 2.整体加壳原理详解  
####   
#### （1）整体加壳原理  
  
  
Dex整体加壳可以理解为在加密的源Apk程序外面有套上了一层外壳，简单过程为：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7nu5H8MQCUyPvh6S6gqiaIlCvabh3OdwIzwgszBDC02jTN0HLfQVmRtQ/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7kfr2R8l1ObXVkBicngaCmeC5mFI1tmKLMic3KIMQHF2iaiczvd2Hce7s8g/640?wx_fmt=png "")  
  
   
  
如何对App进行加一层外壳呢，这里就需要应用动态加载的原理，关于动态加载和类加载器，我在上篇文章中有详细讲解：Android加壳脱壳学习（1）——动态加载和类加载机制详解（  
https://bbs.pediy.com/thread-271538.htm  
）。  
  
   
  
这里我们可以用一个案例来进一步讲述，我们打开一个整体加壳的样本。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7AJeSibJOahkV3o0NB26Ym9bk9DyCSEsD7iaK19Op565sib1PFS2AatqcQ/640?wx_fmt=png "")  
  
   
  
我们很明显看见，除了一个代理类Application，其他相关的代码信息都无法发现。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7uyQS9OazibYxT1NVR7XenwxOzykwTcr9PUHLdVicrZjCv21BaNnoMdgA/640?wx_fmt=png "")  
  
   
  
在代理类中反射调用了一些方法，很显然我们解析出的结果都无法查找，很明显就说明在Application.attchBaseContext()和Application.onCreate()中必须要完成对源加密的dex的动态加载和解密。  
  
   
  
结合上面的描述，App加载应用解析时就是这个流程：  
  
① BootClassLoader加载系统核心库。  
  
② PathClassLoader加载APP自身dex。  
  
③ 进入APP自身组件，解析AndroidManifest.xml，然后查找Application代理。  
  
④ 调用声明Application的attachBaseContext()对源程序进行动态加载或解密。  
  
⑤ 调用声明Application的onCreate()对源程序进行动态加载或解密。  
  
⑥ 进入MainActivity中的attachBaseContext()，然后进入onCreate()函数，执行源程序代码。  
####   
#### （2）类加载器的修正  
  
  
上面我们已经很清晰的了解了壳加载的流程，我们很明显的意识到一个问题，我们从头到尾都是用PathClassLoader来加载dex，而上篇文章我在讲类加载器的过程中说过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7q0T4tDAobto5diaNdoQpUcnjOBdnkEicicm6an1gfvk3SFPP8enymWclQ/640?wx_fmt=png "")  
  
  
Android中的ClassLoader类型分为系统ClassLoader和自定义ClassLoader。其中系统ClassLoader包括3种是BootClassLoader、DexClassLoader、PathClassLoader。  
  
  
① BootClassLoader:Android平台上所有Android系统启动时会使用BootClassLoader来预加载常用的类。  
  
  
② BaseDexClassLoader:实际应用层类文件的加载，而真正的加载委托给pathList来完成。  
  
  
③ DexClassLoader:可以加载dex文件以及包含dex的压缩文件(apk,dex,jar,zip),可以安装一个未安装的apk文件，一般为自定义类加载器。  
  
  
④ PathClassLoader:可以加载系统类和应用程序的类，通常用来加载已安装的apk的dex文件。  
  
   
  
补充：  
  
Android 提供的原生加载器叫做基础类加载器，包括：BootClassLoader，PathClassLoader，DexClassLoader，InMemoryDexClassLoader（Android 8.0 引入），DelegateLastClassLoader（Android 8.1 引入）。  
  
  
我们要想动态加载dex文件必须使用自定义的DexClassLoader，那我们直接使用DexClassLoader进行加载就可以么，很显然不行，还是会报异常。  
  
  
DexClassLoader加载的类是没有组件生命周期的，即DexClassLoader即使通过对APK的动态加载完成了对组件类的加载，当系统启动该组件时，依然会出现加载类失败的异常。  
  
  
所以我们要想使用DexClassLoader进行动态加载dex，我们需要进行类加载器的修正。  
  
   
  
当前实现类加载器的修正，主要有两种方案：  
  
① 替换系统组件类加载器为我们的DexClassLoader，同时设置DexClassLoader的parent为系统组件加载器；  
  
② 打破原有的双亲委派关系，在系统组件类加载器PathClassLoader和BootClassLoader的中间插入我们自己的DexClassLoader。  
  
  
<1>类加载器替换  
  
  
怎么去替换系统的类加载器了，这就和我们上面分析的ActivityThread中LoadedApk有关了，LoadedApk主要负责加载一个Apk程序，我们进一步分析源码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7HpfPNIZDPq3nb7r0soF4peGEYIGiaWgxT8houp79AEPzuCCe0aDzalg/640?wx_fmt=png "")  
  
   
  
很明显，我们可以想到我们通过反射获取mclassLoader，然后使用我们的DexClassLoader进行替换，不就可以成功的让DexClassLoader拥有生命周期了么。  
  
   
  
**源码实现：**  
  
  
总结：  
  
① 获取ActivityThread实例；  
  
② 通过反射获取类加载器；  
  
③ 获取LoadedApk；  
  
④ 获取mClassLoader系统类加载器；  
  
⑤ 替换自定义类加载器为系统类加载器。  
  
```
public static void replaceClassLoader(Context context,ClassLoader dexClassLoader){
       ClassLoader pathClassLoader = MainActivity.class.getClassLoader();
       try {
           //1.获取ActivityThread实例
           Class ActivityThread = pathClassLoader.loadClass("android.app.ActivityThread");
           Method currentActivityThread = ActivityThread.getDeclaredMethod("currentActivityThread");
           Object activityThreadObj = currentActivityThread.invoke(null);
           //2.通过反射获得类加载器
           //final ArrayMap<String, WeakReference<LoadedApk>> mPackages = new ArrayMap<>();
           Field mPackagesField = ActivityThread.getDeclaredField("mPackages");
           mPackagesField.setAccessible(true);
           //3.拿到LoadedApk
           ArrayMap mPackagesObj = (ArrayMap) mPackagesField.get(activityThreadObj);
           String packagename = context.getPackageName();
           WeakReference wr = (WeakReference) mPackagesObj.get(packagename);
           Object LoadApkObj = wr.get();
           //4.拿到mclassLoader
           Class LoadedApkClass = pathClassLoader.loadClass("android.app.LoadedApk");
           Field mClassLoaderField = LoadedApkClass.getDeclaredField("mClassLoader");
           mClassLoaderField.setAccessible(true);
           Object mClassLoader =mClassLoaderField.get(LoadApkObj);
           Log.e("mClassLoader",mClassLoader.toString());
           //5.将系统组件ClassLoader给替换
           mClassLoaderField.set(LoadApkObj,dexClassLoader);
       }
       catch (ClassNotFoundException e) {
           e.printStackTrace();
       } catch (NoSuchMethodException e) {
           e.printStackTrace();
       } catch (IllegalAccessException e) {
           e.printStackTrace();
       } catch (InvocationTargetException e) {
           e.printStackTrace();
       } catch (NoSuchFieldException e) {
           e.printStackTrace();
       }
   }
```  
  
  
<2>类加载器插入  
  
  
还有一种方案，动态加载中我们讲述了类加载器的双亲委派机制，就是说我们的类加载器刚拿到类，并不会直接进行加载，而是先判断自己是否加载，如果没有加载则给自己的父类，父类再给父类，所以我们让DexClassLoader成为PathClassLoader的父类，这样就可以解决DexClassLoader生命周期的问题。  
  
  
总结：  
  
① 将DexClassloader父节点设置为BootClassLoader；  
  
② 将PathClassLoader父节点设置为DexClassloader。  
  
  
代码实现：  
```
public static void replaceClassLoader(Context context, ClassLoader dexClassLoader){
        //将pathClassLoader父节点设置为DexClassLoader
        ClassLoader pathClassLoaderobj = context.getClassLoader();
        Class<ClassLoader> ClassLoaderClass = ClassLoader.class;
        try {
            Field parent = ClassLoaderClass.getDeclaredField("parent");
            parent.setAccessible(true);
            parent.set(pathClassLoaderobj,dexClassLoader);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }

    }
```  
  
  
完成壳加载器的修正后，我们就可以正常的加载dex了。  
  
  
  
三  
  
  
**整体加壳案例实现**  
  
  
前面我们详细讲述了App运行机制和整体加壳的实现机制，下面我们就按照前面的讲述，来实现一个简单的整体加壳案例。  
  
   
  
实验准备：  
```
源程序
加壳程序
```  
  
  
**1.编写源程序**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu77GlUxgvSPFb11g6GZiatYYWQ15r65oGVlkIKV1iaYicorHj0VhMbhhYGw/640?wx_fmt=png "")  
  
   
  
这就是我们的源程序，源程序运行，我们会在日志中看见我们打印的信息，然后我们生成dex文件。  
  
### 2.编写壳程序  
####   
#### （1）准备工作  
  
  
将dex文件上传sdcard，并给应用设置存储权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7cibYLyKSnPhZHXe9RGFPIMqyniaib0icyowM2ohTQaLHgc3f8znKD35M4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7zpVpBvQSBX2ic3SWsoBs3pbbVzKJopNDbic1Fxndg9aYYJJtkTf0lOMw/640?wx_fmt=png "")  
####   
#### （2）编写代理类  
  
  
我们首先编写代理类，模仿上面的加壳应用。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7Yn7tc9fx3ibbunhe87OjcDq7QJVMOoSXXLcpKYETyibejYsY960XxKwA/640?wx_fmt=png "")  
  
   
  
然后我们设置AndroidManifest.xml中的代理类别。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7cvfibE89P2iaYN92tjI3x7Z5S6ubFetMUqRutVeVA9CYttut38aibEhcw/640?wx_fmt=png "")  
  
   
  
然后我们选择在attachBaseContext或onCreate中对我们的dex进行动态加载和类加载器修正即可，因为这里我们源dex并未进行加密，所以也无需解密的过程。  
  
   
  
然后加入导入类的Activity。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7x9iaNSw0Nf6ZX0NcC4F4jBr7wrMI5PliaTU5fS50SSQqMsd1FrMoVo1w/640?wx_fmt=png "")  
####   
#### （3）动态加载  
  
  
我们进行动态加载classes.dex。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7AENCO8LqbqDlu3zv7m5wfDA5JJlKBibdmu1e25ZpCibbM1FFR09dacYw/640?wx_fmt=png "")  
  
   
  
然后使用上面的一种方法进行类加载器修正。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7Icg498hiaZv34djGvTXjPXN0usJcZqcLWQnhF1NzJdZsu0En9BSebicQ/640?wx_fmt=png "")  
  
   
  
然后运行：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu77qbfyovVZjiaRXXVufedTUzwpIPSXK3gpE6Ghz86xkwd5tNZ2jqyM9A/640?wx_fmt=png "")  
  
   
  
运行成功，说明我们的整体加壳成功。  
##   
##   
  
四  
  
  
**脱壳点相关概念详解**  
  
  
上面我们已经理解了APP加壳的基本原理，下面我们进一步来学习如何进行脱壳，Android APP脱壳绕不开DexFile、ArtMethod两个概念，这两个在脱壳中扮演的至关重要的地位，无数的脱壳点都是从其演变而来。  
  
### 1.Dex加载流程  
  
  
我们在分析脱壳点过程中，首先就需要明白Dex加载的基本流程。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7Sg2nYuzjicw36NOPAicmfJ81By8JYxwEFLruibrt0jdJkAOPbPNaL9d0A/640?wx_fmt=png "")  
  
  
DexPathList:该类主要用来查找Dex、SO库的路径，并这些路径整体呈一个数组；  
  
Element:根据多路径的分隔符“;”将dexPath转换成File列表，记录所有的dexFile；  
  
DexFile:用来描述Dex文件，Dex的加载以及Class的查找都是由该类调用它的native方法完成的。  
  
  
我们依次来分析这个过程中的源码。  
  
   
  
DexPathList  
```
/libcore/dalvik/src/main/java/dalvik/system/DexPathList.java
public DexPathList(ClassLoader definingContext, String dexPath,
            String librarySearchPath, File optimizedDirectory) {
**********************     
   this.dexElements = makeDexElements(splitDexPath(dexPath), optimizedDirectory,
                                         suppressedExceptions, definingContext);   
********************** 
            }
```  
  
  
makeDexElements  
```
private static Element[] makeDexElements(List<File> files, File optimizedDirectory,
          List<IOException> suppressedExceptions, ClassLoader loader) {
**********************           
       DexFile dex = loadDexFile(file, optimizedDirectory, loader, elements);   
**********************        
          }
```  
  
  
loadDexFile  
```
private static DexFile loadDexFile(File file, File optimizedDirectory, ClassLoader loader,
                                       Element[] elements)
            throws IOException {
        if (optimizedDirectory == null) {
            return new DexFile(file, loader, elements);
        } else {
           String optimizedPath = optimizedPathFor(file, optimizedDirectory);
            return DexFile.loadDex(file.getPath(), optimizedPath, 0, loader, elements);
        }
    }
```  
  
  
loadDex  
```
static DexFile loadDex(String sourcePathName, String outputPathName,
      int flags, ClassLoader loader, DexPathList.Element[] elements) throws IOException {
      return new DexFile(sourcePathName, outputPathName, flags, loader, elements);
  }
```  
  
  
DexFile  
```
/libcore/dalvik/src/main/java/dalvik/system/DexFile.java
DexFile(String fileName, ClassLoader loader, DexPathList.Element[] elements) throws IOException {
        mCookie = openDexFile(fileName, null, 0, loader, elements);
        mInternalCookie = mCookie;
        mFileName = fileName;
        //System.out.println("DEX FILE cookie is " + mCookie + " fileName=" + fileName);
    }
```  
  
  
这里出现的mCookie，mCookie在C/C++层中是DexFile的指针，我们在下面详细讲解。  
  
   
  
openDexFile  
```
private static Object openDexFile(String sourceName, String outputName, int flags,
        ClassLoader loader, DexPathList.Element[] elements) throws IOException {
       // Use absolute paths to enable the use of relative paths when testing on host.
        return openDexFileNative(new File(sourceName).getAbsolutePath(),
                                 (outputName == null)
                                    ? null
                                   : new File(outputName).getAbsolutePath(),
                                      flags,
                                   loader,
                                   elements);
    }
```  
  
  
这里就进入了C/C++层。  
  
   
  
openDexFileNative  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7qR8IicyF0k0QrPicdNHV1okI7VPBibJ2wCP99yibe6SnEUyQYVWzDPDQhg/640?wx_fmt=png "")  
  
   
  
为了节约篇幅，我们快速分析，中间再经过一些函数。  
```
OpenDexFilesFromOat()
MakeUpToDate()
GenerateOatFileNoChecks()
Dex2Oat()
```  
  
  
最后进进入了Dex2Oat，这就进入了Dex2Oat的编译流程。  
  
   
  
反之如果我们在下面Dex2Oat的流程中通过Hook相关方法或execv或execve导致dex2oat失败，我们就会返回到OpenDexFilesFromOat。  
  
   
  
OpenDexFilesFromOat  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7NeBwnHuc7DrOiawwDEgsnCmLj01wM8r8jjCvASfVicSysOkTaYibZC9sQ/640?wx_fmt=png "")  
  
   
  
会先在HasOriginalDexFiles里尝试加载我们的Dex，也就是说，倘若我们的壳阻断了dex2oat的编译流程，然后又调用了DexFile的Open函数。  
  
   
  
DexFile::Open  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7PqbYyI7rspvHfoOaFWCOtbPhjmwibdTRa6FY6Pd4MiamD3vCRSUXmHoQ/640?wx_fmt=png "")  
  
   
  
校验dex的魔术字字段，然后调用DexFile::OpenFile。  
  
   
  
DexFile::OpenFile  
```
/art/runtime/dex_file.cc
std::unique_ptr<const DexFile> DexFile::OpenFile(int fd,
                                                const std::string& location,
                                                bool verify,
                                                bool verify_checksum,
                                                std::string* error_msg) {
 **************************************
 std::unique_ptr<DexFile> dex_file = OpenCommon(map->Begin(),
                                                map->Size(),
                                                location,
                                                dex_header->checksum_,
                                                kNoOatDexFile,
                                                verify,
                                                verify_checksum,
                                                error_msg);  
  **************************************

                                                }
```  
  
  
OpenCommon  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu746m8bZ0KS3NFnBPqicrkyFjoWibXpCpea0mNaQrbs5X7AF27Z616X7Dw/640?wx_fmt=png "")  
  
   
  
最后又再次回到DexFile类，这里我们的dex文件加载基本流程分析完毕。  
  
### 2.Dex2Oat编译流程  
  
  
Dex2oat是google公司为了提高编译效率的一种机制，从Android8.0开始实施，一些加壳厂商实现抽取壳往往会禁用Dex2oat，而针对整体加壳没有禁用的Dex2Oat也成为了脱壳点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu748Rrr6Y0ZWJJYbCn9MXjiav6yWVum8thnX4xibiaacBF0Ykiajoar42LxA/640?wx_fmt=png "")  
  
   
  
Exec  
```
/art/runtime/exec_utils.cc
bool Exec(std::vector<std::string>& arg_vector, std::string* error_msg) {
  int status = ExecAndReturnCode(arg_vector, error_msg);
  if (status != 0) {
    const std::string command_line(android::base::Join(arg_vector, ' '));
    *error_msg = StringPrintf("Failed execv(%s) because non-0 exit status",
                              command_line.c_str());
    return false;
  }
  return true;
}
```  
  
  
ExecAndReturnCode  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7B7SIv1bT8BCkxOTRDS2JuCcZqZQZIYwibJ6UBAO2Qkf2ibKSKPUicZShA/640?wx_fmt=png "")  
  
   
  
而我们就可以通过Hook execv或execve来禁用Dex2Oat，而如果我们不禁用dex2oat，execve函数是用来调用dex2oat的二进制程序实现对dex文件的加载，我们这时候找到dex2oat.cc这个文件，找到main函数。  
```
/art/dex2oat/dex2oat.cc
 int main(int argc, char** argv) {
  int result = static_cast<int>(art::Dex2oat(argc, argv));
  if (!art::kIsDebugBuild && (RUNNING_ON_MEMORY_TOOL == 0)) {
    _exit(result);
  }
  return result;
```  
  
  
这里我们调用了Dex2oat。  
  
   
  
Dex2Oat  
```
/art/dex2oat/dex2oat.cc
static dex2oat::ReturnCode Dex2oat(int argc, char** argv) {
   **************************************
   dex2oat::ReturnCode setup_code = dex2oat->Setup();
    dex2oat::ReturnCode result;
  if (dex2oat->IsImage()) {
    result = CompileImage(*dex2oat);
  } else {
    result = CompileApp(*dex2oat);
 }
   **************************************
}
```  
  
  
Dex2oat中会对dex文件进行逐个类逐个函数的编译，setup()函数完成对dex的加载。  
  
   
  
然后顺序执行，就会进入CompileApp。  
  
   
  
编译过程中会按照逐个函数进行编译，就会进入CompileMethod。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7AXOSsWqrQfZwDBiaByGiabHacSrhvbDTzWHc5PlwJQxqib4mwX2xlXwyg/640?wx_fmt=png "")  
  
   
  
到这里Dex2oat的基本流程就分析完毕。  
  
### 3.类加载流程  
  
  
要理解DexFile为什么如此重要，首先我们要清除Android APP的类加载流程。Android的类加载一般分为两类隐式加载和显式加载。  
```
1.隐式加载:
    (1)创建类的实例,也就是new一个对象
    (2)访问某个类或接口的静态变量,或者对该静态变量赋值
    (3)调用类的静态方法
    (4)反射Class.forName("android.app.ActivityThread")
    (5)初始化一个类的子类(会首先初始化子类的父类)
2.显示加载：
    (1)使用LoadClass()加载
    (2)使用forName()加载
```  
  
  
我们详细看一下显示加载：  
```
Class.forName 和 ClassLoader.loadClass加载有何不同：
（1）ClassLoader.loadClass也能加载一个类,但是不会触发类的初始化(也就是说不会对类的静态变量,静态代码块进行初始化操作)
（2）Class.forName这种方式,不但会加载一个类,还会触发类的初始化阶段,也能够为这个类的静态变量,静态代码块进行初始化操作
```  
  
  
我们在详细来看一下在类加载过程中的流程：  
  
   
  
java层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu76HmkkIEhqxEuaNpgr18foW3J6uIeCSAIUghO01iaRay68ve8Uupw19w/640?wx_fmt=png "")  
  
   
  
我们可以发现类加载中关键的DexFile，该类用来描述Dex文件，所以我们的脱壳对象就是DexFile。  
  
   
  
这里从DexFile进入Native层中，还有一个关键的字段就是mCookie。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7ezU8qxia80xbemQLK8Qic3jnjzO4SMRnYrLDficFZvUplN3e39icMicONEg/640?wx_fmt=png "")  
  
   
  
后面我们详细的介绍mCookie的作用。  
  
   
  
我们进一步分析，进入Native层。  
  
   
  
Native层  
  
   
  
/art/runtime/native/[dalvik_system_DexFile.cc  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu77ict9qvK59HX55nc6XntfnR64FN2m6PIa17utV117hrYsiaEibatc7hsA/640?wx_fmt=png "")  
```
ConvertJavaArrayToDexFiles对cookie进行了处理
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7Wd7XFr7rCO8pkHMKwLeKy6JgkgbNicpc2bbwefl3eWELVdfDOWJEkIg/640?wx_fmt=png "")  
  
   
  
通过这里的分析，我们可以知道mCooike转换为C/C++层指针后，就是dexfile的索引。  
  
   
  
我们继续分析DefineClass。  
```
art/runtime/class_linker.cc
mirror::Class* ClassLinker::DefineClass(Thread* self,
                                      const char* descriptor,
                                        size_t hash,
                                       Handle<mirror::ClassLoader> class_loader,
                                        const DexFile& dex_file,
                                        const DexFile::ClassDef& dex_class_def) {
***************
LoadClass(self, *new_dex_file, *new_class_def, klass);
***************
}
```  
  
  
LoadClass  
```
art/runtime/class_linker.cc
void ClassLinker::LoadClass(Thread* self,
3120                            const DexFile& dex_file,
3121                            const DexFile::ClassDef& dex_class_def,
3122                            Handle<mirror::Class> klass) {
3123  const uint8_t* class_data = dex_file.GetClassData(dex_class_def);
3124  if (class_data == nullptr) {
3125    return;  // no fields or methods - for example a marker interface
3126  }
3127  LoadClassMembers(self, dex_file, class_data, klass);
3128}
```  
  
  
LoadClassMembers  
```
art/runtime/class_linker.cc
void ClassLinker::LoadClassMembers(Thread* self,
                                   const DexFile& dex_file,
                                   const uint8_t* class_data,
                                   Handle<mirror::Class> klass) {
***************
      LoadMethod(dex_file, it, klass, method);
      LinkCode(this, method, oat_class_ptr, class_def_method_index);
***************
}
```  
  
  
LoadMethod  
```
art/runtime/class_linker.cc
void ClassLinker::LoadMethod(const DexFile& dex_file,
                           const ClassDataItemIterator& it,
                            Handle<mirror::Class> klass,
                             ArtMethod* dst) {
}
```  
  
  
LinkCode  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7CqnsCey2HFTdvrsgSJqNglgfDfMBnX8NQA62OxLW5gym4L9chEwH6g/640?wx_fmt=png "")  
  
   
  
我们可以发现这里就进入了从linkcode后就进入了解释器中，并对是否进行dex2oat进行了判断，我们直接进入解释器中继续分析。  
  
   
  
我们知道Art解释器分为两种：解释模式下和quick模式下，而我们又知道Android8.0开始进行dex2oat。  
  
  
如果壳没有禁用dex2oat，那类中的初始化函数运行在解释器模式下；  
  
  
如果壳禁用dex2oat，dex文件中的所有函数都运行在解释器模式下  
  
则类的初始化函数运行在解释器模式下。  
  
  
所以一般的加壳厂商会禁用掉dex2oat，这样可以是所有的函数都运行在解释模式下，所以一些脱壳点选在dex2oat流程中，可能针对禁用dex2oat的情况并不使用，我们这里主要针对整体加壳，就不展开讲述，最后我们得知解释器中会运行在Execute下。  
  
   
  
Execute  
```
art/runtime/interpreter/interpreter.cc
static inline JValue Execute(
    Thread* self,
    const DexFile::CodeItem* code_item,
    ShadowFrame& shadow_frame,
    JValue result_register,
    bool stay_in_interpreter = false) REQUIRES_SHARED(Locks::mutator_lock_){

***************
      ArtMethod *method = shadow_frame.GetMethod();
***************

    }
```  
  
  
这里我们大致分析完成了类加载的思路。  
  
### 4.DexFile详解  
  
  
前面我们分析了很多，对dex加载、类加载等都已经有了一个很详细的了解，而最终一切的核心就是DexFile，DexFile就是我们脱壳所关注的重点，寒冰大佬在拨云见日：安卓APP脱壳的本质以及如何快速发现ART下的脱壳点中提到，在ART下只要获得了DexFile对象，那么我们就可以得到该dex文件在内存中的起始地址和大小，进而完成脱壳。  
  
   
  
我们先查看一些DexFile的结构体。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7FWEicI9FHpR4Xhp3wGFc1gl04TYyDEAPT2ZmblWfMVBAiawI0kFarQGw/640?wx_fmt=png "")  
  
   
  
只要我们能获得起始地址begin和大小size，就可以成功的将dex文件脱取下来，这里我们记得DexFile含有虚函数表，所以根据C++布局，要偏移一个指针。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu78MTL99fTbHTpO4WsqiaFyUJD9qibQzw7Ho49x2nQgviaszibyRnXdkM3wQ/640?wx_fmt=png "")  
  
   
  
而DexFile类还给我们提供了方便的API。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7X6ciblUPI1eBvyS8MMh050icCuPm3L76XS0CNlk23Gf3GNWmI4HaPdEA/640?wx_fmt=png "")  
  
   
  
这样只要我们找到函数中有DexFile对象，就可以通过调用API来进一步dump dex文件，由此按照寒冰大佬的思想，大量的脱壳点由此产生。  
  
#### （1）直接查找法  
  
  
我们通过直接在Android源码中搜索DexFile，就可以获得海量的脱壳点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7yl8SCHlHiaoUJS7a1J0WUFhIH3ltRMWKuev8pdiblpF54pK0S6xOpgZw/640?wx_fmt=png "")  
  
   
  
我们通过在IDA中搜索libart.so导出的DexFile，同样可以获得大量的脱壳点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7h2KClHGvDMsdFqmK0waPs7atVQw4la3VpicJUwx7mfedQWUE9rCLIRA/640?wx_fmt=png "")  
####   
#### （2）间接查找法  
  
  
这里就是寒冰大佬在文章中提到的通过ArtMethod对象的getDexFile()获取到ArtMethod所属的DexFile对象的这种一级间接法，通过Thread的getCurrentMethod()函数首先获取到ArtMethod或者通过ShadowFrame的getMethod获取到ArtMethod对象，然后再通过getDexFile获取到ArtMethod对象所属的DexFile的二级间接法。  
```
getDexFile()
getMethod()
```  
  
### 5.ArtMethod详解  
  
  
上面我们已经详细分析了DexFile的文件结构，我们知道通过ArtMethod可以获得DexFile，那么为啥又要单独提ArtMethod呢，因为ArtMethod在抽取壳和VMP等壳中扮演了重要的角色。  
  
   
  
ArtMethod结构体  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7TjbH3624zDXRggHwXehdMpo7tSnBjuVGTnDBvTlMicPiawRgoSibRAlHA/640?wx_fmt=png "")  
  
   
  
我们通过ArtMethod可以获得codeitem的偏移和方法索引，熟悉dex结构的朋友知道codeitem就是代码实际的值，而codeitem则再后续加壳技术扮演了至关重要的地址，而且ArtMethod还有非常丰富的方法，可以帮助大家实现很多功能，所以在脱壳工作中也是十分重要的。  
  
  
  
五  
  
  
**脱壳技术归纳**  
  
  
前面分析了很多，最后无非整体加壳的脱壳方案落脚在DexFile的关键对象上，由此产生了一些常用的方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7E85YAyWsU8mmUueWicqemJjOr4H89h5ru56VqWibb9nLkx0AwZ41GiajA/640?wx_fmt=png "")  
###   
### 1.现有工具脱壳法  
  
  
工欲善其事必先利其器，整体加壳已经很多年，不少的大佬们都开发了很多非常好用的工具，我们在自己掌握原理过程时，平时工作中也可以使用很多大佬的开发工具，这里随便举几个自己经常用的工具，这里我对各个大佬的脱壳工具进行了一个梳理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7HpWBCeJicrP3qCm4KW4SlTs6nDHaDpRIiakiahjBiaZRXzULzlKL0Zl03A/640?wx_fmt=png "")  
####   
#### （1）FRIDA-DEXDump  
  
  
这是葫芦娃大佬开发的针对整体加壳的工具，主要通过frida技术，文章参考：深入 FRIDA-DEXDump 中的矛与盾（  
https://www.anquanke.com/post/id/221905  
），该工具的特点是一般的hook方案通过直接搜索DEX的头文件dex.035来定位dex的起始地址，但是后来不少公司对头文件的魔术字段进行了抹除，这样针对没有文件头的 DEX 文件，该工具通过map_off 找到 DEX 的 map_list， 通过解析它，并得到类型为 TYPE_MAP_LIST 的条目计算出文件的大小和起始地址，也很好的提供了一种解决思路。  
  
   
  
使用方法：  
  
   
  
FRIDA-DEXDump使用十分的简单，详细参考github：FRIDA-DEXDump  
  
（  
https://github.com/hluwa/frida-dexdump  
）  
  
   
  
这里引用一张大佬星球的使用流程图，非常详细，快速进行脱壳。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7HtTiaD9K9YiakpBWsX41iaiab4diaqz8wicFQZibexcW5WHYufFcXkBU7qeIw/640?wx_fmt=png "")  
  
   
  
我们简单演示一下，这里结合objection一起使用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu75eJUXYPSkHX4zMV5xqribW3TiaNVNtmwGI9aiaK1iaDicS12d6d7uHj9SIQ/640?wx_fmt=png "")  
  
然后再次打开脱下来的dex，即可。  
  
#### （2）FDex2  
  
  
Fdex2主要是利用Android7.0及版本以下的特殊API getDex()来进行脱壳，原本是基于Xposed的模块，不过掌握原理后，大家可以使用各种Hook框架去实现,参考链接：安卓xposed脱壳工具FDex2。  
  
#### （3）其他工具  
  
  
针对整体壳的脱壳工具有很多，无非是针对各种脱壳点再采用不同的方法，其原理是殊途同归，而基于源码定制的Fart、youpk等等针对整体加壳壳都可以基本实现完全的脱壳，而且抽取壳也有着很好的效果，下面我们就依次来讲述具体的脱壳方法原理，各种脱壳工具如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7hPXD9HlMWib7V6efaTAJZpcxVx5Q5y1ic2JyuahicE6pic2xgOgufoxGQA/640?wx_fmt=png "")  
### 2.Hook脱壳法  
  
  
我们前面知道了，只要函数中包含DexFile对象，我们就可以通过Hook技术拿到对象，然后取到begin和size，从而进行脱壳，市面上使用较多的无非是Xposed和frida，我平时使用frida较为方便，这里也用frida和大家演示：  
  
   
  
首先我们使用GDA识别加壳程序。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7QgxoxSmiaZ45COUCGc3IPd0QrMrXfXHXucY20G2ibGJDVEH5hggzb9Vw/640?wx_fmt=png "")  
  
很明显是进行了整体加壳，有没其他加壳暂时不知道，我们先进行脱壳。  
  
   
  
找到脱壳点  
  
   
  
通过IDA打开libart.so，搜索DexFile，我们可以找到海量的脱壳点。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7BGSaIrBdOAhVB7178xeib05Nc3a5pY2lp3wA79vpO0DEYcfqvV2UokA/640?wx_fmt=png "")  
  
   
  
我们就随便找一个包含DexFile的脱壳函数，然后记录符号值。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7yuIOEaXIEGbMErL4HYXjMjhm5GewUxZkicJ1j0LvkKdSgicCRHmBcPeg/640?wx_fmt=png "")  
  
   
  
然后我们编写hook脚本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu74Rc6KVCLInHiaicGJ0s5JuFPfYbQ5UqWoibYoicIjZYHn2XYtJdhweKE7A/640?wx_fmt=png "")  
  
这里之所以获取begin加上一个指针，是因为我们前面讲了dexfile含有一个虚函数地址，所以加上一个指针偏移。  
  
  
然后启动frida_server。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7OTuicavIib8ZQcyic4ls130xRdMYg4UPRFIUrWc40wRhLaCiclrkvaIqlw/640?wx_fmt=png "")  
  
   
  
附加进程进行dump，这里我们存在sdcard下面，所以需要提前赋予sdcard权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu78kib8J0DB2Ric3l67oPiboahZyayiacnIHNTHX3aZ6M1CeticIRpDO09Abw/640?wx_fmt=png "")  
  
   
  
这里就脱壳成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu75QNQqEajw4ic9AoCPaaia0quxrdUgA9veJwzzZ9VwlySdFicOibiceoUHUQ/640?wx_fmt=png "")  
  
   
  
然后我们打开相应的dex。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7uIGKcciaYib9SibBGRicCt6cKpMT5UmbOcUftbLqibIr1ZzBdibNeL3ervKg/640?wx_fmt=png "")  
  
   
  
此时说明我们整体脱壳成功，不过应用还有抽取壳，这个不是本文解决的内容。  
###   
### 3.插桩脱壳法  
  
  
插桩脱壳法，就是在Android源码里面定位到相应的脱壳点，然后插入相应的代码，重新编译源码生成系统镜像，最后就可以使用定制的系统进行脱壳。  
  
   
  
我们在源码编译（1）——Android6.0源码编译详解（https://bbs.pediy.com/thread-269575.htm  
）中已经讲述了如何编译源码，接下来我们进行插桩脱壳。  
  
   
  
同理、还是定位脱壳点，我们还是随便定位一个脱壳点LoadMethod 然后进行插桩。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7kSCSMLn3SJ6QoENiabe138MibHsBozZN48HT5c9AdZ0UAG5mLwguFia2A/640?wx_fmt=png "")  
```
//add
char dexfilepath[100]=0;
memset(dexfilepath,0,100);
sprintf(dexfilepath,"%d_%zu_LoadMethod.dex",getpid(),dex_file.Size());
int dexfd = open(dexfilepathm,O_CREAT|O_RDWR,666);
if(dexfd>0){
    int result = write(dexfd,dex_file.Begin(),dex_file.Size());
    if(result>0){
        close(dexfd);
        LOG(WARNING)<<"LoadMethod"<<dexfilepath;
    }

}
//add
```  
  
  
同理我们在execute同样插桩此段代码，最后进行编译，编译成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7hyHysFhHyHu0SPGJn43k6fiaQe5PKYH5PhptypLvehysGPSOxhhwGgg/640?wx_fmt=png "")  
  
   
  
然后给程序授权sdcard权限，再次启动应用，就可以看见脱取的dex文件就保存在sdcard目录下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7ic73omfc0XmxUtOicKeM6FIBb7paxNtMahkLFw8dTQdq7WDkSwrkOb9w/640?wx_fmt=png "")  
  
   
  
再次将sdcard下dex文件打开，这里我们已经看见了8732435这个文件，再次打开脱取成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7uIGKcciaYib9SibBGRicCt6cKpMT5UmbOcUftbLqibIr1ZzBdibNeL3ervKg/640?wx_fmt=png "")  
###   
### 4.反射脱壳法  
  
  
反射脱壳法的核心思想就是利用前面我们提到的mCooike值。  
```
核心思路：反射 + mCookie
步骤：
1、找到加固apk的任一class，一般选择主Application或Activity
2、通过该类找到对应的Classloader
3、通过该Classloader找到BaseDexClassLoader
4、通过BaseDexClassLoader找到其字段DexPathList
5、通过DexPathList找到其变量Element数组dexElements
6、迭代该数组，该数组内部包含DexFile结构
7、通过DexFile获取其变量mCookie和mFileName

至此我们已经获取了mCookie

对该mCookie的解释:
#1、4.4以下好像，mCookie对应的是一个int值，该值是指向native层内存中的dexfile的指针
#2、5.0是一个long值，该值指向native层std::vector<const DexFile*>* 指针，注意这里有多个dex，你需要找到你要的
#3、8.0，该值也是一个long型的值，指向底层vector，但是vector下标0是oat文件，从1开始是dex文件
// 至于你手机是那个版本，如果没有落入我上面描述的，你需要自己看看代码

8、根据mCookie对应的值做转换，最终你能找到dexfile内存指针
9、把该指针转换为dexfile结构，通过findClassDef来匹配你所寻找的dex是你要的dex
10、dump写文件
```  
  
  
综述mCookie是在native层就是dexfile的指针，我们利用反射原理来获取mCookie，从而就可以进行脱壳了，这里我们同样使用frida演示：  
  
   
  
编写hook代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu70duxD3ZlPsJnoZfRCgFvzAR240Zp6MS7Zlg97cFJuegbR7O3ZJvZiaQ/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7jwgaqkPK1HQtX3INae9smbIYJ03w7kibddJSbNz7EQk8QdhVumaoPSA/640?wx_fmt=png "")  
  
我们看见了和上面同样大小的8841876_mCookie.dex。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7icV9FEfibvicAmb0bdQ3qeQ2VH4Hh7Dnk8w0WH2mYrvEib3ibmUvJloibI1A/640?wx_fmt=png "")  
  
使用工具打开，发现同样脱壳成功。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7wJMNDA4biarzM5SellyWqTPKe54gOgulYJLxWDX28oe29ehMpniaPkWA/640?wx_fmt=png "")  
  
  
### 5.动态调试脱壳法  
  
  
所谓动态调试法，核心原理和上面一样，就是我们在动态调试的过程中找到DexFile的起始地址和大小，然后执行脚本进行dump。  
  
   
  
首先选取脱壳点，我们还是选择DexFile::DexFile。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7wQjE4HA9VL3YMSHMNSpYdibeTeUWcf4e7OLic21gsaRaIGq99hJPBeRw/640?wx_fmt=png "")  
  
   
  
动态调试的步骤我在前面的文章中已经做了详细的讲解，不会的朋友去看前面的文章。  
  
   
  
首先我们启动android_server。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7FkWWAUGYqmdgekOjPhCUwf7kGrAGRw8IMxJZE9Dv8rCmC0yqOEwFGw/640?wx_fmt=png "")  
  
   
  
然后我们附加上进程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7ERUzxz76SJM0Ij8Luvic3MwyEGcIusfQY9W9kQEQL0ibCErk9SqicNmcQ/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7W6qooqNRibXkwPOHcsapVXUmEQlwXevDIYs2YZs6rb8jF0IugjCPCgg/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu74jl7Ae7BAIibXPT1yL1a0Q59mctfyTbe39mxbv8o34UTG7CbGDYkvicw/640?wx_fmt=png "")  
  
   
  
然后我们打开libart.so，并定位到DexFile::DexFile。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7rMd1vuRLBymeUZeMfgicnsjz09eibTe91tgbsNkQS9De9f0UnkltDb7Q/640?wx_fmt=png "")  
  
   
  
然后在该函数下断点，然后F9过来。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7P3ly5VJD3Pcam4R2XRVsWN4tib5eRviaMn9BopEsl8PvYeGMdsWzgxRA/640?wx_fmt=png "")  
  
此处我们就可以很明显看到X1就是我们的起始地址，X4是我们的偏移值。  
  
   
  
编写脚本进行hook。  
```
static main(void){   
    auto fp, begin, end, dexbyte;     
    fp = fopen("d:\\dump.dex", "wb+");     
    begin =  0x76FCD93020;   
    end = begin + 0x7EEC5600;
    for ( dexbyte = begin; dexbyte<end;dexbyte++)
    {
    fputc(Byte(dexbyte), fp);       
    }  

}
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7vy4OSQaqmcIcWiarcX2Lyu8596zsxzcbicu0ibs61iakCfC1e3mYb6Nqdg/640?wx_fmt=png "")  
  
直接运行run。  
  
   
  
然后我们查看dump.dex文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu74EM4qSBsZhe3hdZnxgpnNibBFyqyBAYPriaYczsEA0ypw8hQ1cYIK5iaQ/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7UEcLUQ9M5MWUfJS2GjbwjGQq4YNmstZWUTe0mMHFkYIG3BUoCKwjZw/640?wx_fmt=png "")  
  
   
  
我们可以发现这里是代理类，还没有到我们想要的dex，我们再次F9，再次到这里，地址再次改变，再次结合长度来计算，我们每次计算可以取小点值，先试一下。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7atMuWkYHbEUhwiaYI9nClKISBHu9ibsE08jjmRzFkFmuyichiamUn4QYRw/640?wx_fmt=png "")  
  
发现还是不是，我们需要不停测试直到dump出dex为此。  
  
   
  
这里大家可以下去按照此方法尝试，或者换一个脱壳点来尝试。  
  
### 6.特殊API脱壳法  
  
  
所谓特殊的API脱壳法就是通过Android自身提供的API来获得Dex，这主要是参考Fdex2，前面我们讲了Fdex2主要是利用Android7.0及以下提供了getDex()和getBytes()两个API，我们可以直接可以获得class对象，然后直接调用这两个API。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7G49IBLvUKu1ibkKicuP0JR0oVNUITxdpuNcIXW0nemGW4de7ibJBfPAHw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7vHtaAhT6WG1IiarwVzz8ma0kH7Rxjzy73rEVOS0AqAGzTxmrzRACVgA/640?wx_fmt=png "")  
  
   
  
编写hook代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu74VcWa1QwsH9hdNWpHJvZo4XAmWrf4tbf3OKGlJdkuYO9qUdGy5VEAg/640?wx_fmt=png "")  
  
① 使用frida枚举所有Classloader。  
  
② 确定正确的ClassLoader并获取目标类的Class对象。  
  
③ 通过Class对象获取得到dex对象。  
  
④ 通过dex对象获取内存字节流并保存。  
  
  
然后我们查看程序的类对象，随便dump一个类对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7k7QY1hTDaI34jAKBm2CiarLaAwLdicTHS47lDqx5kaP1C7H9icXNwxCTg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7lVicOU2cmWz5ZsYuRXKwG5WtjPFuGa34n6rGIyfKpnUVAnq2iboAEomw/640?wx_fmt=png "")  
  
  
然后我们再次用工具打开。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu70WTTTBgUWqhQc1IBlDTicpDQOicODvX4SGNTm3O0YIdQymQ1M1PW26Wg/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7arzEHMItEdP05pOvkgibvHlK1DRHUFHTaVsWSgG2CYyXzGicIbeCMyYw/640?wx_fmt=png "")  
  
   
  
发现就可以成功的dump。  
  
   
  
通过这种方式，我们发现神奇的事我们还可以抽取壳的情况，比如我们之前为空类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7DLrqSWicz8uLoNgXQibiacbetY2rSeX7gxRTfV0QA9I8dxGoBCoyiabdUg/640?wx_fmt=png "")  
  
   
  
我们明显可以发现这里是采用了函数抽取的技术，一般的一代壳dump方案是无法解决抽取壳的，我们使用特殊API方法。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7P4r29iauBNr1yPqrD9uZ0bxSmOrcGUIhbZaRqVqW9pyD5SKxX6lCOfw/640?wx_fmt=png "")  
  
   
  
再次打开，成功dump。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7UVrY17vF0r4kA41v2fsTTXu1dHmT2Xq0bcw20q3ueFz9ZvNvuibdKQA/640?wx_fmt=png "")  
  
   
  
这其实主要是抽取壳的一个回填时机的问题，这个详细放在以后抽取壳中讲解。  
  
  
  
六  
  
  
**实验总结**  
  
  
本文总结了当下dex整体加壳的基本原理，和常用的一些脱壳方案，并一一进行复现，还有一些文件监控法等，由于我平时用的很少就没列举了，复现实验过程中由于涉及到不同的实验，所以我用了Android 6.0 Android 7.0 Android 8.0三台机器进行实验，所以大家可以注意下对应的方法和其Android版本，这里彻底解决了整体加壳的脱壳方案，到这里可以掌握脱壳、抓包、Hook、反Hook、反调、反签等基本手段，这样在进行Android App漏洞挖掘过程中将事半功倍。后面我将继续讲解Android App漏洞中的XSS漏洞、Sql注入漏洞、文件上传漏洞、端口扫描漏洞、WebView漏洞等。  
  
   
  
脱壳脚本相关样本会放在github，所有的脱壳脚本和工具和上传知识星球。  
  
   
  
github：  
https://github.com/WindXaa  
##   
##   
## 参考文献  
  
https://bbs.pediy.com/thread-252630.htm#msg_header_h2_4  
  
https://bbs.pediy.com/thread-254555.htm#msg_header_h2_4  
  
https://www.anquanke.com/post/id/221905?display=mobile  
  
https://www.qj301.com/news/317.html  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2RVaJQxkQ9MuVD6UmAvu7XpZdAcsSKMuTVWb6Ncr9JHW6hX7ArxibBic3VQFcm2RcPyOqs7zn9Vmg/640?wx_fmt=png "")  
  
  
**看雪ID：随风而行aa**  
  
https://bbs.pediy.com/user-home-905443.htm  
  
*本文由看雪论坛 随风而行aa 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458454449&idx=2&sn=c0122501b606c1ccb334113ddc47bf4a&chksm=b18e393b86f9b02d30b9f0be78fa5d2ea77eec354428754723c0065615643a66dd2bcfc6b04d&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1.[堆、UAF之PWN从实验到原理](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458457898&idx=1&sn=a3cb542d0aa67530d769da24a11cf1e7&chksm=b18e27a086f9aeb6a369c278c64790fe841d87f162a859a01cc2ce5989581be2fc53be4e3f79&scene=21#wechat_redirect)  
  
  
2.[Frida inlineHook原理分析及简单设计一款AArch64 inlineHook工具](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458457019&idx=1&sn=1b8dcdc9fbce79e5b202463fec3c77cc&chksm=b18e233186f9aa27180271881bde18b3a60fd0d84b8c1508815d3e4b0fe21202d36d80dc34ef&scene=21#wechat_redirect)  
  
  
3.[PWN学习笔记【格式化字符串漏洞练习】](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458456999&idx=1&sn=888c98e867eee43d5b93ec491482560f&chksm=b18e232d86f9aa3bb4eb50b749bf52b881006641abaeb2ef0598e8658d9a35a7ecf85392ddce&scene=21#wechat_redirect)  
  
  
4.[2022 CISCN初赛 Satool](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458456988&idx=1&sn=a3a8c08263efee84e985eb9af97ba71b&chksm=b18e231686f9aa007a6903e8fcf915418fd42c06f002a7a254297c78f4cae96bb11266471b45&scene=21#wechat_redirect)  
  
  
5.[练习1个Kimsuky样本](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458456686&idx=1&sn=f835232a748b16444cc1b00338767c19&chksm=b18e22e486f9abf2ca723ed74c4debaf933b88743e81a55aaa0fc5efc57eea819a0e1d4777d2&scene=21#wechat_redirect)  
  
  
6.[SVC的TraceHook沙箱的实现&无痕Hook实现思路](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458456411&idx=2&sn=1e77542d7681824e8d82763331a4f10d&chksm=b18e21d186f9a8c788edbd9f219a1b9e246bebcf73b481c5ba0c57b72ac6b15241938c997600&scene=21#wechat_redirect)  
****  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicd7icG69uHMQX9DaOnSPpTgamYf9cLw1XbJLEGr5Eic62BdV6TRKCjWVSQ/640?wx_fmt=gif "")  
  
点击“阅读原文”，了解更多！  
