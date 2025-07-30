#  Android Native内存型漏洞实例   
原创 OPPO安珀实验室  OPPO安珀实验室   2024-11-29 08:30  
  
##   
  
##   
  
**前言**  
  
  
  
##   
  
本文将结合5例Android安全公告公开的Native历史漏洞实例，分析C/C++内存型漏洞的产生场景，尤其是由C++面向对象特性导致的漏洞场景。  
  
  
**1．缺乏长度校验导致的堆溢出**  
  
  
  
  
**漏洞信息**  
  
  
编号：CVE-2023-21118  
  
来源：2023年5月安全公告披露  
  
漏洞类型：ID（信息泄露）  
  
影响版本：11, 12, 12L, 13  
  
危险等级：高危  
  
漏洞模块：libsensor  
  
  
**漏洞分析**  
  
### 本漏洞中，会涉及3个Android libutils.so的关键函数，先进行解释：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4yKYP8OdsKf9vZI9CbHrvrTZ982hQLCpSwtTJ4XJ2LVkpfx5nyYp14g/640?wx_fmt=png&from=appmsg "")  
  
第一，FlattenableUtils::advance()函数。它是FlattenableUtils类定义的静态成员函数，主要目的是将buffer指针向后移动offset长度，并将buffer长度size更新为移动指针后buffer的剩余长度。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4r9IhE71XGr2d97V9w9bCtpXsQyj0DHdgoGzhKj3dt1DS3QS5tnibkcw/640?wx_fmt=png&from=appmsg "")  
  
第二，FlattenableUtils::read()函数。主要是将buffer中的内容拷贝到目标value中，然后通过上述FlattenableUtils::advance()更新buffer指针位置及长度size。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4FSQZ49rgIsZRCibyicbdk1EFrj58enxFSb7AsrjO108Pp45oJIxYKPww/640?wx_fmt=png&from=appmsg "")  
  
第三，FlattenableUtils::align()函数。用来将输入的数字对齐到N的整数倍，N必须是2的幂。  
  
接下来让我们把目光投向漏洞代码本身。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4J5CRIejXGLr8iaV8bSFyJdg4G1lYLVXKJhFDiaiat9qUNHYIW5Up54v1Q/640?wx_fmt=png&from=appmsg "")  
  
libsensor库中使用unflatten()函数解析传感器参数数据，赋值给成员变量。unflatten()函数将调用unflattenString8()函数来解析传入buffer中的传感器名称和供应商等字符串。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4H8SAPMrSb7ibc9WF732YrEGzNURfjHtrPYdYN0bPaVlR6tQSw2nzOVQ/640?wx_fmt=png&from=appmsg "")  
  
unflattenString8()函数首会先调用一次FlattenableUtils::read()函数，读取一个4字节长度的uint32_t型变量len，也就是接下来要读取的整个字符串的长度。读取的同时也会右移buffer指针并减小size，使size变为buffer的剩余长度。通过和len比较可以判断buffer剩余长度是否满足后续拷贝需求。  
  
  
形参outputString8是mName/mVendor的引用，下一步用String8::setTo()函数从buffer截取len长度将字符串拷贝到mName/mVendor中。  
  
  
紧接着导致越界的步骤出现，读取完字符串后，会通过FlattenableUtils::advance()函数进行一次4字节对齐。比方说一开始读取的len是1，那align的结果就是4，advance就会将指针向后移动4字节。  
  
  
如果buffer本身长度不足，剩余长度小于4字节，在执行FlattenableUtils::align()时就会将指针移出buffer有效范围，造成堆溢出。  
  
  
**修复方法**  
  
  
   
谷歌给出的修复方案是在进行4字节对齐前，检查剩余长度是否足够。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4yDdxzJneAtdbcryjn9WRbdMDr9Oowg3f2hW05leHnPy4JPrAwVSGOw/640?wx_fmt=png&from=appmsg "")  
  
在使用如FlattenableUtils::advance()函数进行移动指针时，需要特别留意函数内部是否进行了越界检查。如果函数没有实现，一定要手动检查边界，防止发生溢出。  
  
  
**2. 无符号数回绕导致的堆溢出**  
  
  
  
  
**漏洞信息**  
  
  
编号：CVE-2024-0018  
  
来源：2024年1月安全公告  
  
漏洞类型：EoP（权限提升）  
  
影响版本：11, 12, 12L, 13, 14  
  
危险等级：高危  
  
漏洞模块：libstagefright  
  
  
**漏洞分析**  
  
  
libstagefright库实现的ColorConverter 类用于执行颜色格式之间的转换，在构造函数中指定源颜色格式和目标颜色格式，后续调用ColorConverter::convert()函数使进入不同格式转换分支。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4IBe2Wc1FaC9Bom23iatNiahfUdFBLOtB0ic0Um2LsO7GDalQkZbCCLCgg/640?wx_fmt=png&from=appmsg "")  
  
这例漏洞发生在YUV420格式转换到Y410格式的分支。YUV420的Y表示亮度，UV信息包含色彩及其饱和度，420采样中每4个Y为一组共用1个UV信息。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4oI5XdWSIIJ78JlCH2NLPOC2Zr7aSYutj6bYtbib0DxsVxvvhPqkyySQ/640?wx_fmt=png&from=appmsg "")  
  
由YUV420的采样模式可知，输入的正常图像buffer长度应该是4的整数倍。漏洞所在的循环中也确实进行了一次长度校验，因为指针每次要右移4个单位长度，所以每次比较src.cropWidth()-3来看图像的宽度够不够下次移动指针。  
  
  
但如果图片的宽度不足3呢？由于src.cropWidth()的返回值是一个无符号的size_t类型，src.cropWidth()-3将发生无符号数下溢，结果变为一个接近2^64的很大的数，使得for语句长度判断完全失效，后续移动指针时发生越界读、越界写。  
###   
  
**修复方法**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4GEVAOQHTKibp9tia9E0U13RY4GnNTURLh2l6nrP2k2SX1VZtMZ15chUg/640?wx_fmt=png&from=appmsg "")  
  
修复该漏洞的方法是将不等式移项，将容易引发无符号数下溢的减法操作转化为左式的加法操作，通过x+3与宽度进行比较。  
  
  
**3. 主线程销毁后子线程使用野指针导致UAF**  
  
  
  
  
**漏洞信息**  
  
  
编号：CVE-2023-40131  
  
来源：2023年11月安全公告  
  
漏洞类型：EoP（权限提升）  
  
影响版本：12, 12L, 13  
  
危险等级：高危  
  
漏洞模块：gpuservice  
  
  
**漏洞分析**  
  
  
多线程环境下，子线程可能需要使用到主线程的上下文，如果不进行线程管理就可能发生内存释放后访问的问题。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4KQFmQYt2PCjhxgq6Dtjc8hjTAoIZAicQB0q7bv6a5a1lXGZ6EpOicWpg/640?wx_fmt=png&from=appmsg "")  
  
在这个2023年公布的高危漏洞中，GpuService类构造函数将this指针传递给初始化函数。为了提升效率，这些初始化函数使用detach()函数创建子线程。  
  
  
使用detach()函数创建的子线程时，子线程会驻留后台运行，但是主线程不会自动监控其生命周期等待它执行完。所以当调用GpuService类的构造函数后立即析构，就会导致子线程接受的this指针丢失成为野指针，后续子线程中通过该指针调用成员变量、成员函数都属于UAF。  
###   
  
**修复方法**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA45CiciaqcYU5UhKuJjUMULn6iagVT7hcXVlRtet6u9bAbrfwf7ZphSictAA/640?wx_fmt=png&from=appmsg "")  
  
通过智能指针创建子线程，并在析构函数中等待所有子线程运行结束即可解决这个问题。  
  
  
从这个实例我们可以发现，由于C++很多指针、内存、线程的管理已经对开发者透明了，导致我们自己在实现类时会习惯性忽视这些因素。实践中如果涉及多线程、指针及内存生命周期管理等操作应该格外小心。  
  
  
**4. Vector未加锁产生条件竞争导致UAF**  
  
  
  
  
**漏洞信息**  
  
  
编号：CVE-2021-0437  
  
来源：2021年4月安全公告  
  
漏洞类型：EoP（权限提升）  
  
影响版本：8.1, 9, 10, 11  
  
危险等级：高危  
  
漏洞模块：drm  
  
  
**漏洞分析**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4lbmzXiaA47KTYiadbniaHSEbiahEd04Xwk8TRTlLnZRPLQibqCs6wqlKe9g/640?wx_fmt=png&from=appmsg "")  
  
这是一例由Vector类型内存管理模式引发的条件竞争漏洞。在DrmPlugin类的setPlayPolicy()函数中，会对KeyedVector型成员变量mPlayPolicy进行加项。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4ucAUpGBPkhiaia0Aavk5N0BmrXibSevEtNBBhaqVQvblQK0PZ4Fh8qJPg/640?wx_fmt=png&from=appmsg "")  
  
KeyedVector是Android封装的一个特殊Vector子类，和STL库的vector、map类型一样，它也是一种可以在原分配内存不够用时自动扩容的动态数组。当前的容量不满足添加数据后所需容量时，KeyedVector对象会创建一段新的((3*x + 1) / 2)长度内存，拷贝数据后释放掉原来的内存空间。  
  
  
这样的模式虽然使用起来非常方便，但会引发一个问题：在未加锁的情况下多线程访问Vector，如果一个线程的加项操作使Vector重新分配空间，刚好另一个线程已经获取了指向旧内存空间的指针，那它后续使用的将是一个野指针，这样就会产生UAF。  
  
  
这个实例中的KeyedVector、std::vector、std::map以及其它所有存在类似内存管理机制的对象，多线程访问时都会存在UAF风险。  
  
  
**修复方法**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4bQsEI4icjmicN3ZVPgvAgjeiaT0D4eS3ZjnSYHRuhCFXz2vpibaYvepbaw/640?wx_fmt=png&from=appmsg "")  
  
就像上文提到的，访问这类自动管理内存分配的对象时，一定要加锁，避免产生条件竞争。  
  
  
**5. 超出作用域形成野指针导致UAF**  
  
  
  
  
**漏洞信息**  
  
  
编号：CVE-2020-0008  
  
来源：2020年1月安全公告  
  
漏洞类型：ID（信息泄露）  
  
影响版本：8.0、8.1, 9, 10,  
  
危险等级：高危  
  
漏洞模块：bt  
  
  
**漏洞分析**  
  
  
这一类错误比较容易忽视，是由于作用域误判导致的UAF。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4bszxVroL3vp6YgTSB3qJBicmydlzSiaQBojR1TOAwV7KafZtEDmNydDg/640?wx_fmt=png&from=appmsg "")  
  
BtAddrString()是一个封装好的函数，用于将蓝牙地址转换为std::string对象返回。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4wxZOJ3UFve9ia3kvubhcFSxNLiaGQ3Gn6HpLvITtzHvr9WWVuAAPxwYg/640?wx_fmt=png&from=appmsg "")  
  
我们看这句字符串指针赋值的代码，由于BtAddrString()函数返回的string对象是在栈上的，而且在红框代码调用后没有专门声明变量储存该string对象，所以它的生命周期只在这一行分号就结束了，立刻被析构掉。addr指针指向的内存被释放，于是成了野指针，后续函数使用时就会产生UAF。  
  
  
**修复方法**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TzNt9KawKBEed9Xxp28Bh0xt12fkJLA4SJuCL8fcHzJSiarQsGuVeNrXubpVQZciaEnGiay4NiaZXfasDVvObybxgQ/640?wx_fmt=png&from=appmsg "")  
  
声明string对象存储返回值，存储后对象生命周期和所在函数生命周期一致，后续使用就不会出问题。  
  
  
**总结**  
  
  
  
  
本文分析了5个Android高危历史漏洞。  
  
前两例堆溢出漏洞主要成因是在进行指针移动前，未进行恰当的长度校验，导致指针移出buffer有效范围。在封装移动指针操作、使用封装的移动指针操作时，需要明确相关函数是否进行了长度校验、校验条件能否限制所有的非正规情况发生。  
  
  
后三例内存释放后访问漏洞的情况更为复杂。第一，多线程在提升程序运行效率的同时，也需要开发者更注重线程同步。无论是主线程销毁使子线程使用的对象指针失效，还是Vector类型自动分配内存导致旧数据指针失效，都会导致程序面临极大风险。第二，需要明确临时变量的作用域，避免指针在实际使用前变为野指针。编程时应当关注临时变量的生命周期，防止产生上文实例中的危险行为。  
  
  
**相关链接**  
  
  
  
  
Android安全公告：https://source.android.google.cn/docs/security/bulletin  
  
  
  
**➤**  
**往期推荐**  
  
[· Android Memory Tagging Extension (MTE) 的深度研究与应用](http://mp.weixin.qq.com/s?__biz=MjM5Njk1MDY5Ng==&mid=2247491068&idx=1&sn=8977a76609d570047bf692077995e2b0&chksm=a6e03a3b9197b32d5081403ee2575cf7570c1f834464fe4d13008251f8b5ebb6a7a3d5a3ad4c&scene=21#wechat_redirect)  
  
  
[· ODC24 安全生态分论坛：OPPO构建端云协同技术，守护AI时代隐私安全](http://mp.weixin.qq.com/s?__biz=MjM5Njk1MDY5Ng==&mid=2247491051&idx=1&sn=f9e1379a3175b39c7f82994e569a86d0&chksm=a6e03a2c9197b33a931a196c9483868a9e3d880d0a13fba09573e56bdd2e443f9b708b4eaef2&scene=21#wechat_redirect)  
  
  
[· Parcelable和Bundle的爱恨情仇（三）](http://mp.weixin.qq.com/s?__biz=MjM5Njk1MDY5Ng==&mid=2247490941&idx=1&sn=d8268f601cc9890c0a4ae04fdd6c9539&chksm=a6e03aba9197b3ac186500c85a1712db3364dba7ed02b0140c51c77703a62fde9730fb6f6b22&scene=21#wechat_redirect)  
  
  
[·](http://mp.weixin.qq.com/s?__biz=MjM5Njk1MDY5Ng==&mid=2247490098&idx=1&sn=c1b4f15470e9c8d316c0cf8bda60341e&chksm=a6e03df59197b4e3f62ec05e3df1096555a55423e59ac705f7a4b0a34bbc8ffa7357177574b5&scene=21#wechat_redirect)  
  
 [TensorFlow Lite文本分类在Android上的应用](http://mp.weixin.qq.com/s?__biz=MjM5Njk1MDY5Ng==&mid=2247490893&idx=1&sn=c7bf53c7d98f9522a43ca30a04bd5fdb&chksm=a6e03a8a9197b39ca9835c7993ba61b622cebb807e86b76f9461132bd1f67e9c7cea2f8d08ff&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5Njk1MDY5Ng==&mid=2247490575&idx=1&sn=d788813f6927a81394e0a892f8291a9c&chksm=a6e03bc89197b2def8960a422b2abd4541b849c1973c6a60d7de7caecdb248f74047095d88a3&scene=21#wechat_redirect)  
[·](http://mp.weixin.qq.com/s?__biz=MjM5Njk1MDY5Ng==&mid=2247490098&idx=1&sn=c1b4f15470e9c8d316c0cf8bda60341e&chksm=a6e03df59197b4e3f62ec05e3df1096555a55423e59ac705f7a4b0a34bbc8ffa7357177574b5&scene=21#wechat_redirect)  
[ 浅谈Android BLE蓝牙安全隐私问题](http://mp.weixin.qq.com/s?__biz=MjM5Njk1MDY5Ng==&mid=2247490575&idx=1&sn=d788813f6927a81394e0a892f8291a9c&chksm=a6e03bc89197b2def8960a422b2abd4541b849c1973c6a60d7de7caecdb248f74047095d88a3&scene=21#wechat_redirect)  
  
  
  
  
