#  漏洞分析｜Adobe ColdFusion WDDX 序列化漏洞利用   
M1sery  GobySec   2023-09-04 14:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjI5Q3x6bzsVk96G7I16yaichRTEbdC2L5YosL8jhIfnDib8mc8CZnEENJGdUmvWCGjKELG8J8CY2pfw/640?wx_fmt=png "")  
  
G  
o  
b  
y  
社  
区  
第  
   
3  
1  
   
篇  
技  
术  
分  
享  
文  
章  
  
全  
文  
共  
：  
2544  
字  
   
   
   
预  
计  
阅  
读  
时  
间  
：  
9  
   
分  
钟  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
  
   
**01**  
****  
**概述**  
  
在上一篇有关 Adobe ColdFusion 序列化漏洞（CVE-2023-29300）的文章中，我们对已公开的 JNDI 利用链（CVE-2023-38204）进行了复现。  
JNDI 利用链受目标出网的限制，在不出网的情况下无法很好地利用。**本文中我们将分享不出网的利用方式，提出 C3P0 和 JGroups 两条基于服务错误部署的新利用链。**  
  
经过测试，C3P0 存在被利用的可能，JGroups 利用成功率为 0.1%。  
尽管能被利用成功的概率较低，我们也已经在 Goby 中实现了 C3P0 和 JGroups 利用链的完整利用，完全支持命令执行以及结果回显功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png "")  
  
   
**02**  
****  
**Apache Felix**  
  
ColdFu  
sion 通过自身实现  
FelixClassloader  
来调用  
BundleClassLoader#loa  
dClass()  
方法，用于启动和禁用后台一个叫做 Package Manager 的服务下载的插件，动态加载 bundles 文件夹下的各种 Jar 包。  
我们  
可以看到这些 Jar 包的 MANIFEST 文件中多了不少字段：  
  
```
Manifest-Version: 1.0
Bnd-LastModified: 1490514990031
Build-Jdk: 1.8.0_111
Built-By: uriel
Bundle-Description: Java reflect give poor performance on getter sette
 r an constructor calls, accessors-smart use ASM to speed up those cal
 ls.
Bundle-DocURL: http://www.minidev.net/
Bundle-License: http://www.apache.org/licenses/LICENSE-2.0.txt
Bundle-ManifestVersion: 2
Bundle-Name: accessors-smart
Bundle-SymbolicName: net.minidev.accessors-smart
Bundle-Vendor: Chemouni Uriel
Bundle-Version: 1.2
Created-By: Apache Maven Bundle Plugin
Export-Package: net.minidev.asm;version="1.2.0";uses:="org.objectweb.a
 sm",net.minidev.asm.ex;version="1.2.0"
Import-Package: net.minidev.asm.ex;version="[1.2,2)",org.objectweb.asm
 ;version="[5.0,6)"
Tool: Bnd-3.3.0.201609221906
```  
  
搜索可知，Apache Felix 是 OSGi（Open Service Gateway Initiative，开放服务网关协议）的一种开源实现框架，通过为 Jar 包添加 metadata 来定义哪些类暴露，哪些类隐藏，来实现依赖的模块化，其控制单元就叫做 bundle。  
  
其中最重要的就是  
Export-Package  
和  
Im  
port-Package  
两个字段，分别用于告诉 OSGi 自己对外提供哪些类，引用了其它包的哪些类。如果没有这两个字段，OSGi 或者说它的实现 Felix 就无法正常工作。  
#  03 构造利用链  
### 3.1 Felix ClassLoader  
  
ColdFusion 在进行 WDDX 序列化的过程中，将调用  
BundleClassLoader  
来对目标类进行加载。  
实现  
的  
findClass()  
方法如下：  
```
protected Class findClass(String name) throws ClassNotFoundException {
    Class clazz = this.findLoadedClass(name);
    if (clazz == null) {
        // ...

        String actual = name.replace('.', '/') + ".class";
        byte[] bytes = null;
        List<Content> contentPath = this.m_wiring.m_revision.getContentPath();
        Content content = null;

        for(int i = 0; bytes == null && i < contentPath.size(); ++i) {
            bytes = ((Content)contentPath.get(i)).getEntryAsBytes(actual);
            content = (Content)contentPath.get(i);
        }

        if (bytes != null) {
            String pkgName = Util.getClassPackage(name);
            Felix felix = this.m_wiring.m_revision.getBundle().getFramework();
            Set<ServiceReference<WeavingHook>> hooks = felix.getHookRegistry().getHooks(WeavingHook.class);
            Set<ServiceReference<WovenClassListener>> wovenClassListeners = felix.getHookRegistry().getHooks(WovenClassListener.class);
            WovenClassImpl wci = null;
            // ...

            try {
                clazz = this.isParallel() ? this.defineClassParallel(name, felix, wovenClassListeners, wci, bytes, content, pkgName) : this.defineClassNotParallel(name, felix, wovenClassListeners, wci, bytes, content, pkgName);
            } catch (ClassFormatError var17) {
                // ...
            }

            // ...
        }
    }

    return clazz;
}
```  
  
此处会将全限类名转换为相对文件路径，如传入  
javax.sql.ConnectionPoolDataSource  
，则会尝试读取相对路径  
javax/sql/ConnectionPoolDataSource.class  
文件中的字节码，之后再去  
defineClassParallel()  
方法中调用  
defineClass()  
。由于这种特殊的类加载模式，即使  
ConnectionPoolDataSource  
存于  
rt.jar  
，也会因为无法定位 class 文件而抛出  
NoClassDefFoundError  
。  
```
java.lang.NoClassDefFoundError: javax/sql/ConnectionPoolDataSource
  at java.lang.ClassLoader.defineClass1(Native Method)
  at java.lang.ClassLoader.defineClass(ClassLoader.java:760)
  at org.apache.felix.framework.BundleWiringImpl$BundleClassLoader.defineClass(BundleWiringImpl.java:2338)
  at org.apache.felix.framework.BundleWiringImpl$BundleClassLoader.defineClassParallel(BundleWiringImpl.java:2156)
  at org.apache.felix.framework.BundleWiringImpl$BundleClassLoader.findClass(BundleWiringImpl.java:2090)
  at org.apache.felix.framework.BundleWiringImpl.findClassOrResourceByDelegation(BundleWiringImpl.java:1556)
  at org.apache.felix.framework.BundleWiringImpl.access$300(BundleWiringImpl.java:79)
  at org.apache.felix.framework.BundleWiringImpl$BundleClassLoader.loadClass(BundleWiringImpl.java:1976)
  at java.lang.ClassLoader.loadClass(ClassLoader.java:357)
...
```  
  
不过还有一种可能，如果目标类已提前被加载，  
ClassLoader#findLoadedClass()  
就会直接返回目标类，也不会进入抛出错误的分支。那么会不会有人部署服务时不走寻常路，将原本散落各处的依赖包全部集中到了自定义的 lib 中呢？  
  
本着遵循客观事实的原则，我们进行了利用测试，结果表明的确存在可以利用的目标：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjLdC6HyXD1S1R55z44S8ej1zeQGKM3KJT49S2JR01JYPnN9ZlKOCwPS9pMicwlLlRypicJE4eG4sbMA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjLdC6HyXD1S1R55z44S8ej1yUxLMQhB1wRz94ILwP9OicicFyHYJ3M4Vzm3vUpicicxicoiacT1FEUuUgvA/640?wx_fmt=png "")  
  
无一例外，这些目标都手动更改了服务的依赖包路径。相比使用 Package Manager 服务，他们更愿意自己手动管理依赖，这也将绕过  
BundleClassLoader  
的依赖加载机制，留给我们相当大的操作空间。  
### 3.2 C3P0  
  
以  
WrapperConnectionPoolDataSourceBase#setUserOverridesAsString()  
方法为入口，构造的调用链如下，最后将传入的字节解码并调用原生反序列化。  
```
WddxDeserializer
  -> deserialize()

...

WrapperConnectionPoolDataSourceBase
  -> setUserOverridesAsString()

VetoableChangeSupport
  -> fireVetoableChange()

VetoableChangeListener
  -> vetoableChange()

C3P0ImplUtils
  -> parseUserOverridesAsString()

SerializableUtils
  -> fromByteArray()
  -> deserializeFromByteArray()

ObjectInputStream
  -> readObject()
```  
  
parseUserOverridesAsString()  
方法将截取并 Hex 解码传入的字节流，因此我们构造原生序列化流时需要相应地填写占位和进行编码。  
```
java
    public static Map parseUserOverridesAsString(String userOverridesAsString) throws IOException, ClassNotFoundException {
        if (userOverridesAsString != null) {
            String hexAscii = userOverridesAsString.substring("HexAsciiSerializedMap".length() + 1, userOverridesAsString.length() - 1);
            byte[] serBytes = ByteUtils.fromHexAscii(hexAscii);
            return Collections.unmodifiableMap((Map)SerializableUtils.fromByteArray(serBytes));
        }
        // ...
    }
```  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/GGOWG0fficjLdC6HyXD1S1R55z44S8ej1u3VGM07KA02elLdaBkxTT5YlpBV14icvJAIyAq2jB8ZJWgYoYRUucZA/640?wx_fmt=gif "")  
### 3.3 JGroups  
  
和 C3P0 类似，JGroups 的  
ReplicatedTree#setState()  
方法接受字节数组参数，并调用原生反序列化，利用链如下。  
```
WddxDeserializer
  -> deserialize()

...

ReplicatedTree
  -> setState()

Util
  -> objectFromByteBuffer()
  -> oldObjectFromByteBuffer()

ObjectInputStream
  -> readObject()
```  
  
由于  
setState()  
方法接收的参数不是基本类型，我们需要利用  
<binary>  
标签触发  
BinaryHandler  
来传入字节数组，并进行 base64 编码。  
```
java
public void onEndElement() throws WddxDeserializationException {
  this.setValue(Base64Encoder.decode(this.m_buffer.toString()));
  this.setType(-3, "VARBINARY");
}
```  
  
objectFromByteBuffer()  
方法将根据传入的第一个字节，调用不同的  
readObject()  
，因此构造原生序列化流时还需要在首位添加一个  
0x2  
。  
```
java
public static Object objectFromByteBuffer(byte[] buffer, int offset, int length) throws Exception {
    // ...
    ByteArrayInputStream in_stream = new ByteArrayInputStream(buffer, offset, length);
    byte b = (byte)in_stream.read();
    // ...
    try {
        ObjectInputStream ois;
        switch (b) {
            // ...
            case 2:
                in = new ObjectInputStream(in_stream);
                retval = ((ObjectInputStream)in).readObject();
                break;
            // ...
        }
        // ...
    }
    // ...
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/GGOWG0fficjLdC6HyXD1S1R55z44S8ej1AEAatS8T8vf8SV8Z9DY5Aaiads2VQT2zNX8EicMiciabNoPIvBxJBHe57Q/640?wx_fmt=gif "")  
  
#  04 总结  
  
通过深入挖掘 CVE-2023-29300 的利用方式，我们摸清了产品更多的细节，如BundleClassLoader的类加载机制，并最终提出了两条不出网的利用链：  
C3P0 和 JGroups。  
虽然在默认部署环境中无法成功利用，我们最开始也不相信有人会手动破坏依赖管理机制，但事实是规则总有人打破，而这也让攻击者得以趁虚而入。  
  
希望在阅读本篇文章后，能为大家带来一些新思路的启发。  
  
#  05 参考链接  
  
https://helpx.adobe.com/security.html  
  
https://felix.apache.org/documentation/index.html  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**最新****Goby 使用技巧分享**  
**：******  
  
•  
   
1  
4  
m  
3  
t  
a  
7  
k  
   
|  
 [Weblogic CVE-2023-21931 漏洞挖掘技巧：后反序列化利用](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247527913&idx=1&sn=f3dce554430b75bc9bd5c1e76dde5587&chksm=eb848649dcf30f5f829b8e51a85390b2581f29b0a164d67fa164609f84c9ddd6f72de2231100&scene=21#wechat_redirect)  
  
  
•  
   
k  
v  
2  
   
|  
 [死磕RDP协议，从截图和爆破说起](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247528393&idx=1&sn=74961047a04f95115cb9eab084b1baef&chksm=eb848469dcf30d7fc97318feb7a4c1584dd9ed447d50e679a1a233914f245db1f943c2aa72c5&scene=21#wechat_redirect)  
  
  
•  
   
1  
4  
m  
3  
t  
a  
7  
k  
   
|  
 [死磕Jenkins漏洞回显与利用效果](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247528988&idx=1&sn=ce221e6ef302aa68a7a50b5946aab1ad&chksm=eb8499bcdcf310aac0dee3d4c1489b7eda0cb8f18ff91ba5f33608dec6e266c0f43fb53d8be4&scene=21#wechat_redirect)  
  
  
•  
   
路  
人  
甲  
 |   
[Metabase (CVE-2023-38646): H2 JDBC 深入利用](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247529429&idx=1&sn=823772f28e4bf9dc1f387eebad6e25e5&chksm=eb849875dcf31163432df4fd6959b52d7d01f5b9a7283c2e060f36a9d6975e354284d017a20b&scene=21#wechat_redirect)  
  
  
•  
   
M  
1sery |   
[Adobe ColdFusion 序列化漏洞（CVE-2023-29300）](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247529590&idx=1&sn=1c31354c67dd41b2a44e0b3205c01ab5&chksm=eb849fd6dcf316c01d09f9ba703dafa48132b0205be239fb78c38a9a76ca801f2a5b2a3738a6&scene=21#wechat_redirect)  
  
  
  
更  
多  
   
>  
>  
   
   
技  
术  
分  
享  
  
  
G  
o  
b  
y  
   
欢  
迎  
表  
哥  
/  
表  
姐  
们  
加  
入  
我  
们  
的  
社  
区  
大  
家  
庭  
，  
一  
起  
交  
流  
技  
术  
、  
生  
活  
趣  
事  
、  
奇  
闻  
八  
卦  
，  
结  
交  
无  
数  
白  
帽  
好  
友  
。  
  
也  
欢  
迎  
投  
稿  
到  
   
G  
o  
b  
y  
（  
G  
o  
b  
y  
   
介  
绍  
/  
扫  
描  
/  
口  
令  
爆  
破  
/  
漏  
洞  
利  
用  
/  
插  
件  
开  
发  
/  
   
P  
o  
C  
   
编  
写  
/  
   
I  
P  
   
库  
使  
用  
场  
景  
/  
   
W  
e  
b  
s  
h  
e  
l  
l  
   
/  
漏  
洞  
分  
析  
   
等  
文  
章  
均  
可  
）  
，  
审  
核  
通  
过  
后  
可  
奖  
励  
   
G  
o  
b  
y  
   
红  
队  
版  
，  
快  
来  
加  
入  
微  
信  
群  
体  
验  
吧  
~  
~  
~  
- 微  
信  
群  
：  
公  
众  
号  
发  
暗  
号  
“  
加  
群  
”  
，  
参  
与  
积  
分  
商  
城  
、  
抽  
奖  
等  
众  
多  
有  
趣  
的  
活  
动  
  
- 获  
取  
版  
本  
：  
h  
t  
t  
p  
s  
:  
/  
/  
g  
o  
b  
y  
s  
e  
c  
.  
n  
e  
t  
/  
s  
a  
l  
e  
  
-   
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjLVsnYdd0PiaCzAr1V8cElzgJlhod7oXgjMibCeSME8sw0ia2zSeZ7UugvjmyUr4wh9V9DJWoBZTjRYg/640?wx_fmt=png "")  
  
