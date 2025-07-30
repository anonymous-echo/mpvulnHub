> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5OTk2MTMxOQ==&mid=2727846792&idx=1&sn=622536f639aa4976d47ddfc18e65de3e

#  LazyValue下的Parcel漏洞  
原创 獬豸实验室  京东安全应急响应中心   2025-07-04 03:45  
  
**背景介绍**  
  
  
在安卓13以前，Parcel作为一个非常广泛的攻击面，曾出现过大量反序列化漏洞，详情可参考文章Android 反序列化漏洞攻防史话  
（  
https://evilpan.com/2023/02/18/parcel-bugs/  
）。  
其核心原理是，利用Parcelable对象在序列化和反序列化过程中的读写不匹配，在第一次反序列化过程中隐藏掉intent对应的key-value键值对，绕过system_server针对intent字段的检查。然后通过读写不匹配漏洞，实现序列化过程中bundle自修改，从而使得settings进程拿到恶意构造的intent，达到LaunchAnyWhere的攻击效果。  
  
此类漏洞曾被大规模利用实现提权，并进行不法行为，包括但不限于保活、防卸载、采集用户敏感信息等。  
  
**LazyValue介绍**  
  
  
由于这类漏洞非常容易在开发阶段引入，同时又能造成危害较为严重的提权效果，谷歌官方在安卓13引入了新的保护机制LazyValue  
(  
https://www.blackhat.com/eu-22/briefings/schedule/index.html#android-parcels-the-bad-the-good-and-the-better---introducing-androids-safer-parcel-28404  
)，限制这类漏洞造成的破坏效果，在很大程度上限制了漏洞利用。  
  
具体而言，Parcel会将那些不定长、由Parcelable对象自实现序列化/反序列化的对象定义为LazyValue类型，相比于普通类型，LazyValue对象会在头部添加type和length类型.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC56qrERnKFtFlZ0DH0EcIL938NFuIOQptZpdlDqBvJ6vRgWHKqd1kWew/640?wx_fmt=png&from=appmsg "")  
  
此外，相较于之前Parcel的反序列化，安卓13还对反序列化的步骤进行优化。在对某一对象进行操作需要反序列化的场景中，不会将整个bundle对象完整反序列化，而是仅反序列化该对象，从而避免其他键值对以及整个bundle被篡改。对于未被反序列化的LazyValue对象，在跨进程通信过程中会以序列化的形式被逐字节拷贝过去。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5mCNR3kdXPMQRG1cx5Qe6QTgMsRoHXiagqlz4aeI389roGe2p9Uwp56A/640?wx_fmt=png&from=appmsg "")  
  
**漏洞1**  
  
  
首先介绍一个安卓13下的提权漏洞，该漏洞能够实现往其他进程的堆栈加载activity。  
  
  
**补丁分析**  
  
  
  
该漏洞的补丁是针对intent对象，调用Intent的构造函数，将其再次构造成Intent对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5tmvLn8Me9QIFxCxqTWXsQWVLWnibRZYybKK1O5g3VD6SLmibicmCYteeA/640?wx_fmt=png&from=appmsg "")  
  
观察上下文，intent对象在声明和赋值的过程中都是Intent类型，为什么还需要再构造一次呢?  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5laqsMI94I3qY4AmiaHXW3HTpuURrYXj6TeBrP9IpUfIP7NPxU9iaVEyQ/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞原理**  
  
  
  
AIDL生成的代码，用readTypedObject(Type.Creator)进行读，但是，在bundle中，会用反射调用构造函数，进行反序列化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5LiaIny58zGgoS0aY967YuwfRUs0wd3tdNS6UiavhngHwwfMEPZ8hNskw/640?wx_fmt=png&from=appmsg "")  
  
这样就会造成序列化和反序列化不匹配的情况。  
  
写入：运行时类型的实例方法 writeToParcel，实际上是子类  
  
读取：声明类型的 Creator 字段的 readFromParcel，使用的是父类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5SX1UMvjicT9LV7VrGHlan18oX0mrZgoKHz7qXo10AjhN7OLMdqXLIrA/640?wx_fmt=png&from=appmsg "")  
  
  
**攻击思路**  
  
  
  
那么攻击思路就围绕读写不匹配展开。  
  
首先，需要找到Intent类型的子类，来实现Intent类型之外的额外写，aosp中Intent有两个子类LabeledIntent和ReferrerIntent，其中LabeledIntent类较好用，相比于Intent多写了4个字段。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC54LXdtc2qIzGW3C9wHaSbnRBohMB25lOykxyLQG7DSwB4CyO9s4WibKA/640?wx_fmt=png&from=appmsg "")  
  
观察intent对象后面的其他几个参数字段，其中options字段可以利用，修改该字段中launchTaskId，即可实现往目标进程堆栈中加载自己的activity。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5axFC7dBd4aZpNSibp52wN0LqubcCYIxntDhR9Fy7cFN34hY9xPYYicUQ/640?wx_fmt=png&from=appmsg "")  
  
  
**复现效果**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Z9MuUwaeeGK2U0OsSvZzst1DdT7UhHgYrN0ydbMut9k6xwPIlF2lq5oPkNoC5lfFp9lbokcZ1wUdw5ibhjibMiabQ/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞2**  
  
  
第二个漏洞的危害则更大，能够实现LaunchAnyWhere提权的攻击效果。  
  
  
**补丁分析**  
  
  
  
分析一下漏洞2的补丁，跟之前类似补丁也很短，看不出什么重要信息。  
  
其中bundle.getParcelable的返回值intent，在下一行已经有类型检查了，在安卓13中getParcelable函数新加了一个带有类型参数的版本，还需要在参数里加上类型吗？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5KNksibicltoXPjco36nvmnkDR2ZtwvC5N3qlD0G9DjibsgvQmZ4Nba1ng/640?wx_fmt=png&from=appmsg "")  
  
其实是有必要的，分析修复前的源码可以发现，只要通过构造，将intent和simulateIntent同时为null即可满足检查条件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC50fkI6871ZqFyHCx9IWLzzhFEfnWNibeUtWKFVAQ29GcQvY3CXPo9c5A/640?wx_fmt=png&from=appmsg "")  
  
  
**攻击思路**  
  
  
  
参考LazyValue引入之前的反序列化漏洞，Parcel对象的数据在以下进程进行传递：vulapp -> system_server -> settings，我们需要在第一次反序列化的过程中，修改LazyValue，从而让settings进程通过第二次序列化，读取到我们构造的恶意intent。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC58kIVoicYfmvd3iax0td8frJXRToiahICOBMCgicMOnGdnyk0SAAj0b2frw/640?wx_fmt=png&from=appmsg "")  
  
根据原作者michalbednarski的分析，他在aosp中找到两个非常强大的gadget片段，串联起来实现上述目标。  
  
首先是android.content.pm.PackageParser$Activity，在这个类反序列化的过程中，可以反射调用任意类的构造函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5OaMnRDib7GhS9aOj2ibEeVM61hQXBnAN1k6MkOS7DAMnODuyCL6wXqwQ/640?wx_fmt=png&from=appmsg "")  
  
第二个片段是android.os.PooledStringWriter构造函数接受一个Parcel对象，往对象写入一个int。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5VU3jH6pm61Zg1kRbyd7dIxwg5T2uWT7pCeJncPaViaw1GH2DZZN0icSg/640?wx_fmt=png&from=appmsg "")  
  
  
**问题**  
  
  
  
上述攻击思路非常巧妙，但是构造和利用过程中也遇到了一些问题。  
  
1. 由于android.content.pm.PackageParser$Activity反序列化过程中，会将类型转化为IntentInfo，因而抛出类型转换错误。解决方案就是找一个带异常处理的Parcelable类，通过try catch捕获这个异常。比较可惜的是aosp源码中没有合适的目标，作者转而找到一个三星oem中的一个类SemImageClipData。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5iaSKykk5oEYDiaaSEUjPBxVwJcKzldeo3ZwS8HjzCP4SQXUtT4ZmNluw/640?wx_fmt=png&from=appmsg "")  
  
利用这个类将反序列化的步骤用try catch模块捕获异常，就可以避免这个问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5zdjxDpFpGGUhgyfK7Eb1SXDMXgM2ToJMNp5zjy7wBOsQX61STWUX3g/640?wx_fmt=png&from=appmsg "")  
  
2. SemImageClipData类型反序列化后返回结果，转Intent对象又会抛出类型转换异常。对于这个问题，可以在Parcelable对象外再套一层，包装成ParcelableArray数组对象，这样就能捕获到异常并返回null。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC50cIT1rRSSNgvvH4LiaSxwWZCszWT6TRO2a5J3eN3sYIyG9Bh4mLhMCQ/640?wx_fmt=png&from=appmsg "")  
  
  
**数据对比**  
  
  
  
观察bundle数据，前后对比一下，可以发现触发反序列化前的数据都是正常的，第一个key对应LazyValue触发反序列化，然后调用两个gadget，第二个key也用Parcelable类型的LazyValue，保证不会被反序列化，并将恶意intent隐藏在数据部分，第三个key是随机数用以填位。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC57QBnZlwDjvnPMSYsnTvlP7rcYm1FlgzIypqR7QDhpNFBugU2wrj3Zg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5eDerts8Tlz88Km3cm2Mt2faTnNCYBBR5Yexe1kqOczg8jOAETFvDFw/640?wx_fmt=png&from=appmsg "")  
  
对比Parcel的前后数据会更明显，第二个key: android.os.PooledStringWrite在反序列化前对应的类型是Parcelable，反序列化后类型被覆盖为0，代表字符串类型。第三个key则是之前被隐藏在数据部分当中的intent对象，通过这种方式暴露出来。另外由于与第一个key:intent相同，会将第一个value覆盖掉，因此我们看到的map里面只有两个对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5pIjSC4FTrKzh9DzfDmsTfuPp358lBdhvPVaWVDP46NRxmETd7Y5gOg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5dDdke6ia7Sgia1fPT5rkjmNBiaRJWFBa18Lu28tQHkVS670n33tt2FIDg/640?wx_fmt=png&from=appmsg "")  
  
  
**复现效果**  
  
  
  
由于本人手上没有合适的三星手机，参考原作者的方法，往aosp中加入该类，然后自己编译刷机  
  
  
  
**另一条路径**  
  
  
  
深蓝研究团队  
(  
https://mp.weixin.qq.com/s/JMLWqGGsRcWyPjscle8i3Q  
)在他们的分享中提到了另外一条利用，他们在某国产手机厂的型号中找到另外一个合适的Parcelabl对象，也能够实现在反序列化过程中修改自身的LazyValue对象  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5JMomWc8rIYylwm3CyYkFOUIKUR30tSTrcwIciaz1JrMGeNUvAFpsNSw/640?wx_fmt=gif&from=appmsg "")  
  
**时间线**  
  
  
这两个漏洞共涉及以下四个CVE，原作者是 michalbednarski  
  
- CVE-2023-20944 2023-02 vul1-patch1  
  
- CVE-2023-21098 2023-04 vul2-patch1  
  
- CVE-2023-35669 2023-09 vul1-patch2  
  
- CVE-2023-45777 2023-12 vul2-patch2  
  
  
  
当第一个漏洞第一次完成修复后，有人发现修复少了一条利用链，因此再次向谷歌官方报告，并完成第二次修复。但是第二次修复过程中，使用的getParcelable是旧版的未指定类型的版本，导致了第二个漏洞的第二次出现。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5kriagiaaC4kcAO20s1Ckf2a1DpbS73ohj3U4ux2WzDCCRHG54NHDEhmg/640?wx_fmt=png&from=appmsg "")  
  
因此，第二个漏洞被再次引入和利用，需要第二次修复，换用新版本的getParcelable函数即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z9MuUwaeeGJ2RMU36h4HrJvkKGXc8dC5KNksibicltoXPjco36nvmnkDR2ZtwvC5N3qlD0G9DjibsgvQmZ4Nba1ng/640?wx_fmt=png&from=appmsg "")  
  
**参考链接**  
  
  
1. https://evilpan.com/2023/02/18/parcel-bugs/  
  
1. https://www.blackhat.com/eu-22/briefings/schedule/index.html#android-parcels-the-bad-the-good-and-the-better---introducing-androids-safer-parcel-28404  
  
1. https://github.com/michalbednarski/TheLastBundleMismatch  
  
1. https://konata.github.io/posts/creator-mismatch/  
  
1. https://mp.weixin.qq.com/s/JMLWqGGsRcWyPjscle8i3Q  
  
  
  
  
**獬豸实验室介绍**  
  
  
獬豸实验室 （Dawn Security Lab）是京东旗下专注前沿攻防技术研究和产品沉淀的安全研究实验室。重点关注移动端安全、系统安全、核心软件安全、机器人安全、IoT安全、广告流量反作弊等基础和业务技术研究。  
  
实验室成员曾多次获得Pwn2Own冠军，在BlackHat、DEFCON、MOSEC、CanSecWest、GeekCon等顶级安全会议上发表演讲，发现Google、Apple、Samsung、小米、华为、Oppo等数百个CVE并获得致谢。曾获得2022年黑客奥斯卡-Pwnie Awards“最佳提权漏洞奖” ；同时也是华为漏洞奖励计划优秀合作伙伴，CNNVD一级支撑单位，GeekCon优秀合作伙伴。  
  
  
**加入我们**  
  
  
獬豸实验室正在招募各路英雄，欢迎加入崇尚技术创新、用技术守护互联网安全的我们。  
  
**简历发送：jsrc@jd.com**  
  
**邮件主题和简历附件名称请备注**  
  
**“岗位编号-岗位名称-姓名”**  
  
  
**招聘岗位：**  
  
007-安全研究员  
  
008-后端开发工程师  
  
009-大数据开发/算法工程师  
  
010-数据挖掘工程师  
  
011-移动安全开发工程师  
  
012-移动安全工程师  
  
013-安全情报运营工程师  
  
014-安全情报研发分析工程师  
  
桌面端安全开发工程师  
  
  
**招聘详情请戳**  
👇  
[](https://mp.weixin.qq.com/s?__biz=MjM5OTk2MTMxOQ==&mid=2727844182&idx=1&sn=e20a71c9e1db4610ef4b27ddb4a1318c&scene=21#wechat_redirect)  
  
  
