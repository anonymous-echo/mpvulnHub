#  ZecOps 对 AliExpress 平台购买的 Android 手机取证分析   
luochicun  嘶吼专业版   2022-09-08 12:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
ZecOps 对 AliExpress 平台购买的 Android 手机取证分析，发现该手机将系统 Android 6 伪造欺骗成 Android 10。我们会在本文介绍攻击者如何“伪造”iOS 上的关机屏幕以实现持久性，以及设备伪造者如何将旧的 Android 设备作为新设备出售，伪造的规格包括伪造 CPU 速度、Android 版本、补丁级别、内存，甚至屏幕分辨率。  
  
我们能够在全球速卖通上找到下面的手机。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIZkClNhpWaOQfRDhxCs4wPL0IRsLMV1dF2OFyXRNpNbhleVsNpoibqfQ/640?wx_fmt=png "")  
  
这款手机看起来很棒，而且非常便宜。  
  
在使用ZecOps for Mobile检查了这款手机后这款设备声称的Android 10其实是Android 6。  
  
我们做的第一件事是转到设置→关于手机。如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIia9nPhmwGsvgqcB43sAO1G5dFmTFTF21euD6M6U9FDo2AZP9kqibXia9Q/640?wx_fmt=png "")  
  
如上所示，该设备显示它是具有 10 个处理器内核的 Android 10。然后我们使用了一个名为“CPU-Z”的已知软件。此应用程序用于检查硬件属性。  
  
我们检查了内核版本和设备属性：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIxpEmPpCxjeV31ibicaXx9Xou9uGH9GrrKnt6lgAticguE85qDbbNPmkSw/640?wx_fmt=png "")  
  
由输出可知内核版本为3.18.19,Android版本为6.0。设置应用程序，以及CPU-Z，试图欺骗终端用户。  
  
让我们检查一下处理器：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIDUTch1fJvLoWPb8TpNf8RCFDVtFxH38srenBiamoGWeeBrJ3MFcrZfg/640?wx_fmt=png "")  
  
我们看到了 MT6753。该处理器有 8 个内核，而不是“设置”应用程序中显示的 10 个内核。  
  
让我们检查一下API版本：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIaKAjibh9RI2DHvAhrh4hj8Niavrib5K3gbh64AhTxOmLAS56CDTSp8k9w/640?wx_fmt=png "")  
  
该API版本与Android 6一致。  
  
此外，我们对这款手机的用户界面做了一些观察，它与我们之前使用的Android 6版本类似。  
# Android 伪造过程  
  
设置应用程序和CPU-Z应用程序报告了相同的假硬件细节。为了了解Android 伪造过程，让我们应关注 各个Android 版本并检查所有其他应用程序是否确实看到与 CPU-Z 相同的设备属性，让我们以 CPU-Z 或设置应用程序的方式进行操作。  
  
首先，让我们检查一下这个 fake 是否是全局的，这将帮助我们猜测发生伪造的正确组件。我们已经知道，使用 ADB 可以获取正确的 OS 版本号，这与 SDK 版本和内核版本都是一致的。  
  
让我们从一个简单的检查开始，并建立一个起点：编写我们自己的程序来检查预编译框架加载的实际版本。  
  
代码（放置在基本项目模板的 onCreate 中）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIibsVlicwmYJQYdZUdeCeTIsDT36YIN5gHFgSicaztzZsAY8VnKY5VJbEg/640?wx_fmt=png "")  
  
输出：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIeE9nu92W11Utia9L40aspMiaeGWY4C7uAJNJAF8RKXvRQ0u2RxEmqSsw/640?wx_fmt=png "")  
  
因此，这里的所有内容都正确地显示出来，并且与adb输出一致。接下来我们需要检查设置应用程序。  
  
对应apk的提取和apktool'ing给了我们android版本字符串资源id的id，它是“firmware_version”，但是里面没有classes.dex。没关系，这是设置应用程序的常见情况。  
  
使用 baksmali 进行 deodexing /system/priv-app/Settings/oat/arm/Settings.odex并获取代码后，我们可以对其进行 grep 获取 firmware_version 常量，并查看它获取os.android.Build.VERSION的内容。  
  
在 DeviceInfoSettings.smali 中，我们会看到如下内容：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIFxDZVdUH1QuGdferlt0Zic84h8r37RY13eicTCjaqonwPoQR8l5rv0uw/640?wx_fmt=png "")  
  
这对应于https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-6.0.1_r55/src/com/android/settings/DeviceInfoSettings.java中的onCreate代码。  
  
但是调试信息中的行号与确切的行不对应，只在所需的代码周围。  
  
将代码反编译回java后，我们终于可以看到更有趣的内容了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIeiayVvR4sP68xFypw4nBoMf4LiaEOCnThiaWCiaNbmicIGoUDWxA2Yu9sQw/640?wx_fmt=png "")  
  
现在一切都清楚了，与原始实现类似的代码从未实际发生，因为“persyst.sys.hdf.androidsdk”在这款手机上的实际值为1。  
  
这里有一些有趣的细微差别，包括从 2018 年到 2019 年安全补丁级别的更换！  
  
现在我们知道了虚假的 Android 版本是怎么出现的了。它来自 HdfUtil.GetHrfAndroidString，以及许多其他虚假属性。  
  
让我们进一步研究一下虚假Android版本是如何配置的：  
  
正如我们在 onCreate 函数的开头看到的那样，调用了 SystemProperties.getInt(“persyst.sys.hdf.androidsdk”, 0)。  
  
我们可以使用 getprop 实用程序验证这个值，并看到返回值为 1，因此将显示为 android 版本的值来自 HdfUtil.getHrfAndroidString 。  
  
下面是这个函数的源代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIE7Wb0mRicQxe2TjeSM2y9NwiaAFGrtDhb2liavK0zqOBF7CfRjpu8QC5w/640?wx_fmt=png "")  
  
这个函数实际上是根据从 SystemProperties.getInt(“persist.sys.hdf.androidv”, 0) 返回的实际值返回值“10.0”，可以用 getprop 工具检查，等于 7。  
  
对于所有其他参数也会发生类似的操作。  
  
DeviceInfoSettings 类的几乎所有 onCreate 函数都引用了这个类，而不是像原来的 Android 源所说的那样（主要是指 os.android.Build.VERSION 类，见下文）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxID5zPv4FKib81tZJLxzugqfROjNHLHVYLIFlusZn6NQNAd6zolRXBjFg/640?wx_fmt=png "")  
  
所有的硬件伪造都发生在 HdfUtil.java 中。这个文件没有被混淆。  
  
当我们了解其中到底发生了什么时，我们就可以将这台设备的真实硬件属性与我们的设置应用程序所显示的进行比较。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIa73K8t25zI06YVr4dxntg3SA0f4H0X8tcbbTJYC3Eia45za6WicDcBZw/640?wx_fmt=png "")  
  
综上所述，伪造的原因如下：  
  
1.伪造者对现有 Android 6 环境的来源进行了更改。  
  
2.他们从 Java 源代码编译了它，我们看到它是因为 smali 代码中存在有效的调试信息。  
  
3.他们添加了一些我们可以在 /system/build.prop 中看到的构建参数和通过 adb 的输出，这些参数定义了自定义设置应用程序应该向用户显示的确切内容。原始参数保持不变，因此所有未触及的框架都可以正常工作。  
  
4.HdfUtil.java 中的硬件变体数量表明该框架也可能用于伪造其他手机。  
  
我们可以看到，这足以欺骗小白级的用户，或是贪小便宜的人。  
  
但还有三个谜团需要解决：  
  
1.他们究竟是如何欺骗 CPU-Z 应用程序的，该应用程序在出现时并未安装在手机上？  
  
2.还有其他类似的手机？谁负责伪造规格，我们可以自动找到这些手机吗？  
  
3.手机上是否还有其他恶意软件允许卖家远程访问设备？  
# 欺骗 CPU-Z 应用程序  
  
在花了一些时间调查 android.os.Build.VERSION 的工作原理、root 设备（mtk-su 完美运行）、反转框架及其本机部分之后，我们主要专注于他们如何显示虚假数据，而不是如何获取版本号和字符串。  
  
看起来他们只是简单地改变了类android.widget.TextView的代码，使其在特定的应用程序中显示所需的虚假值。有时候，事情比看上去要简单得多。  
  
为了验证我们应该从设备中提取的 boot.oat，使用 oat2dex 实用程序将其转换为 dex 文件，然后反编译生成的 dex 文件。  
  
看起来如下（以下代码来自 public final void setText(CharSequence var1) ）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxILRBR2ichIialdJqAcHhRU124CXYL9R5awbL8BkJmEj7gBFcTkQ7O3PdA/640?wx_fmt=png "")  
  
其背后的主要思想如下：如果包的名称是 com.cpuid.cpu_z （对应于 CPU-Z 包名称）并且之前用 function 设置的字符串是伪造的参数之一，则文本基于可以使用 getprop 检查的相同构建参数，神奇地更改为以类似于设置应用程序中使用的方式编码的值。  
  
与以下包相关的类似代码片段也可以在此代码中找到：  
  
com.antutu.ABenchMark  
  
com.mediatek.camera  
  
com.mediatek.filemanager  
  
com.qiku.android.filebrowser  
  
com.finalwire.aida64  
  
com.ludashi.benchmark  
  
ru.andr7e.deviceinfohw  
  
这不仅增加了CPU-Z被欺骗的嫌疑，也增加了检查设备规格/设备基准测试的其他常见应用程序的嫌疑。  
  
在进一步分析了各种有趣的代码片段之后，我们反编译了所有的框架，并且令人惊讶地发现了另一个有趣的发现，它分享了伪造者如何处理其他基准测试/规范应用程序的信息。在规范伪造框架的其他类中似乎存在一些可疑活动，特别是在包管理器中。  
  
在反转包管理器之后，似乎除了欺骗这些应用程序之外，规范伪造者还用一种有趣的方法欺骗了包管理器：他们没有安装从 Google Play 下载的 APK，而是使用预先存储和篡改的副本 /系统/数据。经过简要分析，我们得出结论，这些 APK 并不是恶意的。这一改变是为了确保他们正在处理的假冒应用程序版本经过了适当的测试，并显示了虚假值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxII96fFcRRqrWu1TTWgWqpt83RYUTxMiambMp6SIuibZQqu3C3pg4luP7g/640?wx_fmt=png "")  
  
最后，伪造人员在活动管理器中屏蔽了 Google Play 保护的崩溃报告，并根据 ro.hdf.shutdown.ani 参数修改了关机动画。  
  
至于预装的恶意软件及其作用我们将下一篇文章中介绍。  
  
参考及来源：https://blog.zecops.com/research/fake-droids-your-new-android-device-is-actually-an-old-android-6/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxINsmjdZUuL2CUZR0YNzfuJL5BU2HX6okuqHyJdxk6flFcjQcalLg3lQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CFlyrYxxribOicMv70k2FxIbu2A8hSOLbR4EDxkOwFKVnxPdu8iaaeRI82Y94X3iaIBTc2NicVobZwyg/640?wx_fmt=png "")  
  
