#  CVE漏洞复现：Maglev中VisitFindNonDefaultConstructorOrConstruct的类型混淆   
XiaozaYa  看雪学苑   2024-05-02 17:59  
  
```
```  
  
  
  
最近在学习Maglev  
相关知识，然后看了一些与其相关的CVE  
，感觉该漏洞比较容易复现，所以先打算复现一下，本文还是主要分析漏洞产生的原因，基础知识笔者会简单说一说，更多的还是需要读者自己去学习。  
> 这里说一下为什么笔者不愿意在漏洞分析中写过多的前置知识，因为笔者认为读者都已经开始复现漏洞了，那么对基础知识应当是有一定的了解了，并且笔者的基础也比较差，所以不希望误人子弟，网上的资料很多，自己学学就 OK 啦。  
  
#   
  
  
```
```  
  
  
  
```
```  
  
#   
  
  
```
```  
  
  
  
**new关键字**：new func()  
效果为：  
  
◆创建一个默认对象this  
，然后进行初始化this.prop = val  
  
◆若func  
本身返回一个对象，则抛弃默认对象；否则返回默认对象  
  
  
这里给一个示例代码：  
  
  
```
```  
  
  
****  
**new.target**这里自行看  
资料（https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Operators/new.target）。  
**Reflect.construct(target, argument, new_target)**函数以target  
为构造函数创建对象，这里new_target  
提供原型，然后行为跟new func()  
类似。上面的知识都比较简单，所以也不想细说了，如果读者不是很清楚的话，请自行查阅下相关资料吧，这里主要关注JS  
引擎层面的实现。对于默认对象，其是通过FastNewObject  
函数创建的，其调用链如下：  
  
  
```
```  
  
  
  
先来看看TF_BUILTIN(FastNewObject, ConstructorBuiltinsAssembler)  
：  
  
  
```
```  
  
  
  
该函数比较简单，其主要就是调用了ConstructorBuiltinsAssembler::FastNewObject  
函数：  
  
  
```
```  
  
  
  
可以看到ConstructorBuiltinsAssembler::FastNewObject  
分为快速路径  
和慢速路径：  
  
  
◆快速路径：直接根据new_target的initial_map进行默认对象的创建  
- initial_map的构造函数与target相同  
  
- new_target的initial_map为一个有效map  
  
◆慢速路径：调用Runtime::kNewObject运行时函数  
  
  
这里的快速路径可能有点奇怪？因为这里target  
才是构造函数，所以默认对象的map  
再怎么说也不应该与new_target  
的initial_map  
相同，但这其实是一个优化，其会将target  
的initial_map  
和new_target  
的prototype  
缓存在new_target  
的initial_map  
域，这个后面再说。然后可以看到走快速路径是存在两个条件的，不满足则会走慢速路径Runtime::kNewObjec  
：  
  
  
```
```  
  
  
  
可以看到其直接调用了JSObject::New  
函数：  
  
  
```
```  
  
  
  
在【1】  
处会调用JSFunction::GetDerivedMap  
函数，这里的constructor  
传入的是target  
：  
  
  
```
```  
  
  
  
可以看到其会调用FastInitializeDerivedMap  
为new_target  
创建initial_map  
：  
  
  
```
```  
  
  
  
可以看到在【2】  
处设置了new_target  
的initial_map  
为map  
，但是修改了prototype  
为new_target  
的prototype  
，constructor  
为target  
。而该map  
在【1】  
处是通过复制constructor_initial_map  
来的，看到这里可能就明白了之前快速路径的逻辑。所以在快速路径中，当new_target.initial_map.constructor = target  
时，则说明new_target.initial_map  
与target.initial_map  
是相同的，所以这里就会直接使用new_target.initial_map。  
OK，以上就是后面漏洞分析需要的一些基础知识。  
  
  
  
```
```  
  
  
  
还是先从  
patch（https://chromium.googlesource.com/v8/v8/+/ed93bef7ab786d5367c2ae7882922c23aa0eda64%5E%21/#F0）  
入手：  
  
  
```
```  
  
  
  
从补丁打的位置可以知道该漏洞应该发生在Maglev  
的图构建阶段，并且其主要打在了MaglevGraphBuilder::VisitFindNonDefaultConstructorOrConstruct  
函数中，根据函数名大概知道其主要就是处理FindNonDefaultConstructorOrConstruct  
字节码的，而该操作的功能为“寻找非默认构造函数”，这里结合chatGPT  
食用：  
> 在 V8 引擎中，FindNonDefaultConstructorOrConstruct 字节码指令用于查找非默认构造函数或构造器函数。这个字节码指令在 JavaScript 代码中的类构造过程中使用。当在 JavaScript 中创建一个类并调用 new 关键字来实例化对象时，V8 引擎会执行相应的字节码指令序列。其中，FindNonDefaultConstructorOrConstruct 字节码指令用于查找适当的构造函数或构造器函数。具体而言，该指令会检查类的原型链以查找适合的构造函数。它首先尝试查找类自身的 constructor 属性，如果找到则使用该构造函数。否则，它会沿着原型链向上查找，直到找到一个非默认构造函数或构造器函数。这个过程是为了确保在类继承链中正确地选择构造函数，以便在实例化对象时执行相应的初始化逻辑。  
  
  
  
所以可以写出如下代码去生成目标字节码：  
  
  
```
```  
  
  
  
来看下B  
产生的字节码：  
  
  
```
```  
  
  
  
可以看到这里确实生成了FindNonDefaultConstructorOrConstruct  
字节码，其实可以把它看成一种优化，其会遍历B  
的原型链，尽量的忽略哪些默认构造函数，如果最后到达原型链顶层，则调用FastNewObject  
创建默认对象。  
  
现在我们回到主要的补丁代码：  
  
  
```
```  
  
  
  
可以看到这里的补丁仅仅对new_target  
的initial_map  
进行了检查，而之前的漏洞代码并没有对new_target  
的initial_map  
进行合法性检查，我们看下这个函数的关键逻辑：  
  
  
```
```  
  
  
  
可以看到如果最后到达顶层构造函数，并且new_target  
是一个JSFunction  
对象，则会调用BuildAllocateFastObject  
进行默认对象的创建，而不是调用之前分析的TF_BUILTIN(FastNewObject, ConstructorBuiltinsAssembler)  
函数进行创建，但是这里调用BuildAllocateFastObject  
时，没用对new_target  
的initial_map  
进行合法性检查，然后这里第一个参数是通过FastObject  
构造函数创建的，跟进看看：  
  
  
```
```  
  
  
  
注意我们传入的参数是new_target_function  
，所以可以看到这里的map  
就是new_target_function.initial_map。  
然后可以跟进BuildAllocateFastObject  
函数看看：  
> 该函数有多个实现，可以根据参数类型判断具体调用了那个函数  
  
  
```
```  
  
  
  
所以这里的关键点就是其把默认对象的map  
设置为了new_target.initial_map  
，这便是漏洞之处，通过之前的分析我们知道，调用BuildAllocateFastObject  
函数之前没有对new_target.initial_map  
进行合法性检查，所以最后可以导致的效果为：  
  
  
◆创建了一个new_target.initial_map  
类型的默认对象obj  
  
◆对默认对象obj  
的初始化由target  
完成  
  
  
那么这时如果new_target  
与target  
的initial_map  
不相同，则可能导致属性初始化错误，比如new_target  
的initial_map  
为JSArray  
，那么此时就会导致target  
忽略对默认对象length  
属性的初始化。  
  
  
  
```
```  
  
  
  
想要到达漏洞代码逻辑，得使以下关键判断成立：  
  
  
```
```  
  
  
  
先来看下TryGetConstant  
函数：  
> 注：这里TryGetConstant  
存在多个实现，但没办法用参数进行判断调用了哪一个，所以这里参考参考文章的分析  
  
  
```
```  
  
  
  
由于还没开始审计Maglev  
源码，所以这里笔者不是很懂，简单来说就是这里有两个路径可以进行判断node  
是否是constant  
：  
  
  
◆【1】  
：该路径直接检查node  
是否是一个global constant  
  
◆【2】  
：检查是否有其它nodes  
标记该node  
是一个constant  
  
  
这里【1】  
路径行不通，所以这里利用【2】  
路径进行绕过，其主要就是插入一个CheckValue  
节点，而该节点会标记该node  
为一个constant  
：  
  
  
```
```  
  
  
  
这里直接看poc  
：  
  
  
```
```  
  
  
  
看下Maglev IR  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Ey0Z2fLQtGQHrnic5NDLhqHmyj8MbItgOqlaCTRPAsfsibIKBYl5nmx5ADibyNiaU8OXZ9kgcF4lemdA/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到这里确实产生了CheckValue  
节点，并且这里可以看Map  
的值：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Ey0Z2fLQtGQHrnic5NDLhqHnPd22qQgeyJbx4LWHgOH761JTnFPDaUqqnqRqS6w4n2MgMdpywXrCA/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到其直接赋值的new_target.initial_map  
，而new_target.initial_map  
的类型为JSArray  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Ey0Z2fLQtGQHrnic5NDLhqHqmUXcJiaG8eEErmYE0vnDGTp0BVVicl9Gcjvzoia5c0ubAsqicV0M1nglg/640?wx_fmt=png&from=appmsg "")  
  
  
来看下初始化过程：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Ey0Z2fLQtGQHrnic5NDLhqH9Fh5icG9ibib4trroTc1eiaPYZtJVxtx32GakcMGwzgHzicGvLmRUibKuibOw/640?wx_fmt=png&from=appmsg "")  
  
  
这里的4/8  
明显是properties/element  
的偏移，但是其却没有对length  
进行赋值，可以看到print(arr instanceof Array)  
输出的是true  
，即arr  
是一个数组：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Ey0Z2fLQtGQHrnic5NDLhqH6aAbMmffyfMGvqBLgxpNcOyEWanpCm1Uia01uaRNZib6K5ZbYLsia469Q/640?wx_fmt=png&from=appmsg "")  
#   
  
  
```
```  
  
  
  
这里主要利用的是JSObject  
与JSArray  
的类型混淆，JSObject  
是不存在length  
属性的，而JSArray  
存在length  
属性，所以如果target  
为JSObject  
，而new_target  
为JSArray  
，那么触发漏洞后，target  
就不会初始化创建对象的length  
属性，所以这里的length  
就是一个未初始化的值，如果这个未初始化length  
值比较大，就可以实现越界读写。有了越界读写，后面写利用就比较简单了，很多利用手法都大同小异，所以就不细说了，主要说下关键点：  
  
  
◆虽然没有对length  
进行初始化，但是一般（没有gc  
）时，length  
就为 0，所以这里先提前触发gc  
去移动对象，这样有概率存在残留数据覆盖length  
，如果length  
比较大，就可以实现越界读写。  
  
  
◆由于JSObect  
对象不使用element  
属性，所以这里element  
指向FixedArray[0]  
，其值在笔者机器上固定为0x219  
，其属于的页权限为只读权限，但是这里问题不大，因为0x219  
基本就在堆的最低地址处了，只要被覆盖的length  
比较大，就可以实现越界读写。  
  
  
exploit  
如下：  
  
  
```
```  
  
  
  
效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Ey0Z2fLQtGQHrnic5NDLhqHooJgRiaSMGGQ48PXOmjuRQicHSobLSJnh2TovtibNGkH7Tib7icXZKltqDA/640?wx_fmt=png&from=appmsg "")  
#   
  
  
```
```  
  
  
  
通过对该CVE  
的分析利用，对Maglev  
有了基本的了解，但是还有一些细节上的东西没有搞清楚，这个只能后面对Mgalev  
逐渐熟悉后再看看了。然后看了下腾讯玄武去年的talk  
，发现Maglev  
是一个很不错的攻击面（玄武的大佬好像直接挖了7个洞），其与trubofan  
有部分相同的性质，而其又具有独特的攻击面，所以笔者感觉可以将turbofan  
的一些历史漏洞去套下Maglev  
。当然了，随着chrome  
对turbofan  
保护强度的逐步上升，目前想在trubofan  
中出一个洞可以说是非常难了，而Maglev  
应该是目前最能够出JIT  
洞的了，当然自己目前太菜了，也希望早日能够挖到自己的漏洞。说点别的，瞎扯一下：目前其实也复现了很多漏洞，但是对挖漏洞其实还是比较迷茫的，自己也花了一些时间总结了下，发现自己虽然在复现一些漏洞，但是很多漏洞都比较老，并且在复现漏洞的时候没有去总结可能的攻击面，看了很多大佬的talk  
，发现选取攻击面是非常重要的，就chrome  
而言，其有很多组件，每个组件又有不同的功能分支，如何针对性的进行fuzz  
是非常重要的。也希望后面可以跟踪一些比较前沿的攻击手法和比较新的攻击面。  
  
  
目前在笔者看来，复现漏洞就两个目的，第一就是熟悉某个知识点，就比如笔者之所以复现该漏洞其实就是为了巩固下Maglev  
中的一些东西；第二就是总结攻击面，这个目前笔者做的比较失败。然后单纯的为了写利用去复现漏洞是没有意义的，漏洞那么多，是不能全部复现的。所以后面笔者复现漏洞也会有针对性的复现，会尽量选取一些比较新的漏洞进行复现。人一定要学会反思，不然就如同行尸走肉一般。  
  
# 参考  
  
Getting RCE in Chrome with incomplete object initialization in the Maglev compiler  
  
（https://github.blog/2023-10-17-getting-rce-in-chrome-with-incomplete-object-initialization-in-the-maglev-compiler/）  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FQicadOCiboLpxXIRw7OaqYTicpRhTlicDQQt6dwQ6XRXT7xs1vibtGFpibgOCrupPymNyePqunL6C2EGw/640?wx_fmt=png&from=appmsg "")  
  
  
**看雪ID：XiaozaYa**  
  
https://bbs.kanxue.com/user-home-965217.htm  
  
*本文为看雪论坛精华文章，由 XiaozaYa 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550539&idx=1&sn=99d99a504e0b364140e6cfe6c561f0b1&chksm=b18db18186fa389736b29f09c357e9d8c3ecbc37c6411d7664c2876cb7d8d99311810e406a4c&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1、[自定义Linker实现分析之路](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550539&idx=2&sn=e3a883e6de9929783e4920b1ae75802d&chksm=b18db18186fa38971cf9a67439421e62a1c3e1dbeb2cdc974c70ab52186fe92738ed759cf003&scene=21#wechat_redirect)  
  
  
2、[逆向分析VT加持的无畏契约纯内核挂](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550427&idx=1&sn=399ad869e9f33b368de123b079ca1ff2&chksm=b18db01186fa390707f03c65e957277ed4eb7d250bbce02130ab2d6324c0c4cd9ab837e01802&scene=21#wechat_redirect)  
  
  
3、[阿里云CTF2024-暴力ENOTYOURWORLD题解](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550386&idx=1&sn=ef197d9dc41313d624d8e297d6cc5f9a&chksm=b18db0f886fa39eedca81d2ebee9e73e689d9db0bfdcb9831d8ebe4a759a5c55f98aff2a771b&scene=21#wechat_redirect)  
  
  
4、[Hypervisor From Scratch - 基本概念和配置测试环境、进入 VMX 操作](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550275&idx=1&sn=c1b54dc12abbcb627796db92d4f9c2fc&chksm=b18db08986fa399ff036a52bbbe579808ba65111151b31af848628a464efe064e4fbd7c6c1d9&scene=21#wechat_redirect)  
  
  
5、[V8漏洞利用之对象伪造漏洞利用模板](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550274&idx=1&sn=83844418c6e1fb22d4d8c2033abdea5e&chksm=b18db08886fa399ee2927fefc6f01c0213e126ef3248a8ecc439231526e9e56e69f937a29a3c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78txPhfvI9WpuGSCawCN8NJCgzD16Y0IwdUkaI33Qr3DpwRRuvibgRQOg/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
