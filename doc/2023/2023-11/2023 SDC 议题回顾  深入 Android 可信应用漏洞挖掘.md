#  2023 SDC 议题回顾 | 深入 Android 可信应用漏洞挖掘   
原创 2023 SDC  看雪学苑   2023-11-17 18:02  
  
在过去的几年中，可信执行环境（TEE，Trusted Execution Environment）在Android生态系统（智能手机、智能汽车、智能电视等）中实现了普及。TEE 运行独立、隔离的 TrustZone 操作系统，与 Android 并行，保证在Android系统沦陷的情况下用户的核心敏感数据或者手机的核心安全策略仍然安全。  
  
  
与Android系统中预置的系统级App一样，TEE系统中也存在必要的应用（Trusted Application， 即TA）以承担数据加密等安全策略的实现。2022下半年演讲者对部分主流厂商的TA实现做了安全研究，目前已有60处漏洞被确认，包括但不限于指纹图片提取、指纹锁屏绕过、支付密钥提取、提取用户的明文密码等严重漏洞。  
  
  
在本次议题中，演讲者将会介绍主流厂商的TEE环境中的TA实现以及常见的攻击面并分享一些针对TA做安全研究的技巧与方法，比如如何尽可能快速的拥有一台具备Root权限的手机用于研究与测试。在研究过程中，演讲者构建了一套模拟系统对这些TA进行模拟和Fuzzing，在本次议题中演讲者也会介绍到如何实现这个模拟系统以及使用到的Fuzzing技术和部分调优策略。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcATnDP3vEpsZhbIk8e6VDNnncvNCN2nQWx00XHyWiaibOwboJYEAXHrYA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
下面就让我们来回顾看雪·第七届安全开发者峰会（2023 SDC）上**《深入 Android 可信应用漏洞挖掘》**  
的精彩内容。  
  
  
  
**0****1**  
  
**演讲嘉宾**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P2849Qh5lLJJJicsURhUpL5fTKeUJYrn9uGzaORY7EOicgPogEPpgrLN2NGg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcAjwUPgpViaULMuzTaeckFoLG7PxcYk0NapnRP5DkEJoicIt2iapEEMbCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**【李中权-启明星辰ADLab 移动安全专家】**  
  
专注于Android、Apple、loT方面的漏洞挖掘与Fuzzing。曾多次发现Apple、华为、荣耀、三星、小米、OPPO、vivo、联发科等主流厂商的高危漏洞，在天府杯上完成过产品破解。  
  
  
  
**0****2**  
  
**演讲内容**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P2849Qh5lLJJJicsURhUpL5fTKeUJYrn9uGzaORY7EOicgPogEPpgrLN2NGg/640?wx_fmt=png "")  
  
  
  
以下为速记全文：  
  
  
大家下午好，我是李中权。今天我带来的议题是深入Android可信应用的漏洞挖掘。我现在在启明星辰的ADlab做安全研究，目前专注于苹果、安卓、IoT的漏洞挖掘与Fuzzing，同时也做一些安全开发的工作。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcl9jQroTVPcSwnx0SVLEQKNaHn0RXb3iapTK8Z5UVsfbibWIvnibaCOwuA/640?wx_fmt=png&from=appmsg "")  
  
  
这里是本次演讲的主要内容，首先我们会简单的对TEE做一下基本的介绍。我们需要知道TEE它是属于主处理器当中的一个独立的安全区域，它提供了一个隔离的环境，那么即使设备的主操作系统被攻击，TEE当中保存的敏感数据和安全策略也不会受到影响。  
  
  
另外还有一些基本概念是我们需要了解的，在本次演讲当中Normal World和REE指的都是安卓操作系统，那在安卓操作系统中，那些会通过特定的API与TEE通信的应用程序，也被称为Client
Application，简称为CA。这是一个通用的架构图，当然不同的TEE实现它可能会有不同的架构实现，比如Kinibi在S-EL0级别还会存在可信驱动的概念。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcQ7OXWHjz6LDgREYZibPF8ibttLZDrUiblXlN9MicDCg4DKSqwHYusTtoQg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcWicEKynrrnRbIEcibP0wleE5tiaG3c2XHibGcAoEkOMsgrfJr0knKrGX0w/640?wx_fmt=png&from=appmsg "")  
  
  
在本次的演讲当中，我们主要关注S-EL0的漏洞挖掘，首先我们需要知道可信应用TA它到底是拿来干嘛的。对于TEE来说，它主要用于承载敏感数据的安全存储、安全通信、安全加密策略、DRM、可信UI的绘制等等。那么这些功能的承载者就是可信应用。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcpfmuic3lXjC3XwRjXiaM4DmWVgDTZoUSrV3deV6bptwnaGYN5UxToYUw/640?wx_fmt=png&from=appmsg "")  
  
  
在去年下半年的时候，其实我本来是想要对TEEOS以及ATF整体做一下漏洞挖掘，但是挖掘到TA的时候发现TA的漏洞多到超乎想象，所以就针对部分主流厂商的TA做了一下漏洞的挖掘，目前已经有60处漏洞被确认。  
  
  
不过出于厂商漏洞披露政策的原因以及赏金问题就没有再继续挖下去了，所以这一套模拟和Fuzzing的系统其实是能够产出更多的漏洞的。当然同样也因为厂商漏洞披露政策的限制，在本次的分享当中我会省略掉部分漏洞的细节。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcn9LXMLSrptRbbscYtgDUdluIYSDiagz3Bkiax7HaLfghmyiaNwQhbiaAUA/640?wx_fmt=png&from=appmsg "")  
  
  
那么接下来我们再谈一谈主流TA的一个架构实现和逆向分析。  
  
  
首先我们需要知道CA它到底是如何跟TA进行通信的，在最开始的时候CA会调用一个TEE的API去跟安卓侧的一个driver进行通信，安卓侧的driver会初始化请求，封装必要的参数，并通过Secure Monitor发送给TEE。  
  
  
那么TEE接收到请求之后，就会把TA镜像文件的内容从REE侧加载到TEE的共享内存当中，之后 TEE就可以校验贴的完整性、证书签名、版本等等，校验通过之后自然就可以进入到TA的生命周期了。  
  
  
在介绍TA的生命周期之前，我们需要了解一个规范，就叫Global Platform TEE
Client API 规范。这一套规范大家可以简单理解为一套标准化的开发流程。如果开发者遵循这一套规范，那么便可以在很短的时间内开发自己的可信应用和CA。  
  
  
这是GP规范当中TA的生命周期，主要是下面的这5个。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNctI3jicicRic1WUTFlXLY77841ZjnnpfEJDIJp066J9pIAu0vgbukP1W1g/640?wx_fmt=png&from=appmsg "")  
  
  
而作为一个安全研究员，我们的关注点通常是前面的三个，而这里的CreateEntryPoin和OpenSessionEntryPoint，大家简单理解就是用来做初始化的。而第三个函数InvokeCommandEntryPoint是我们分析的核心，因为开发者会在这个函数当中针对外部传入的数据做请求的分发。  
  
  
额外需要提到一点，OpenSessionEntryPoint同样也是我们需要关注的一点，因为这个函数它也是能够接受外部输入的，所以这里也是可能存在漏洞的。  
  
这是GP规范当中TA的一些基本的定义。其实我们能一眼看出来，TA依靠uuid的形式来做每个TA的区分。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcoF8CEkzQEe4g0Cma1Sy2VZvXR8rOf7ebnXxibLksaGmTCpWXa3nSUiaA/640?wx_fmt=png&from=appmsg "")  
  
  
当然在一些高通的手机或者是厂商自研的一些TA，我们能发现它TA的名字是类似于这张图的这种英文短字符的形式，但其实我们在它的安卓文件系统上做一下简单的搜索和逆向，其实能发现它只是简单的做了一下映射关系，它本质还是uuid的形式。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcQl73tP6V76ia21qhFd7EmbKiaJRicpzIq7DXBNY0PMYWf01fBjafAS73w/640?wx_fmt=png&from=appmsg "")  
  
  
在去年的研究过程中，存在很多不同类型的TA，为了方便模拟和Fuzzing，我根据TA处理外部数据的方式，把它们分为了两类。第一类就是遵循GP规范的TA了，它会使用TEE_Params这个数据结构去做数据交换，这个结构在最后的攻击面会有非常详细的介绍。第二类它会从外部传入的一个buffer当中去读取数据。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcmQvN4YcRbbXiciciaJhk19W5iaFRN1QmDIicNJ75qG0lq0Cw79A672suXhA/640?wx_fmt=png&from=appmsg "")  
  
  
接下来再谈一谈如何分析CA和TA的调用流程。其实不同的TEE实现会有不同的调用流程，只是出于厂商隐私披露的限制，所以这里没有办法展示具体的case，但是可以分享一套我自己的通用的分析思路，本质还是使用lsof去查看安卓侧的那些TA的CA它加载了哪些so。其实很多时候我们从so的名字就能很快定位哪些so是用于TEE
API的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcskZCKYrjVrNcd585WDZ9oB1ic9R8eRQ8WceuNBaCXqnwlha8fOeC9PA/640?wx_fmt=png&from=appmsg "")  
  
  
这是基于GP规范的一个TA的方法调用，我们能发现他直接从/vendor/lib64目录下面加载了一个libTEECommon.so，之后再加载了一些常用的TA的函数，那么之后再走TA的正常生命周期就可以发起函数的调用了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcUqwaviblc6vYzscEAUqDf4MCSnCllajJEAcQM6k9nelr4S4ECCCVtqQ/640?wx_fmt=png&from=appmsg "")  
  
  
这是高通TA的方法调用，其实我们能一眼发现高通TA的方法调用跟前面GP规范的方法调用是完全不一样的。但是高通CA调用TA的方法，其实是最容易分析的。因为高通的CA的代码在AOSP当中是完全开源的，所以我们可以直接把AOSP的源码拷下来，然后做一下简单的分析，就能知道在高通当中CA如何跟TA进行通信。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNceWq500HY7TYW6Be1E93NEoFZt0O61AQWc5OXgjia1dy9ibvV3eyrRtsQ/640?wx_fmt=png&from=appmsg "")  
  
  
谈到CA跟TA的通信，我们就一定需要注意一个情况，也就是TA的实例。因为TA存在独占式的实例，也就是单实例的情况。对于单实例的TA，如果我们想要测试，建议使用frida去Hook它原始的CA，然后再跟他的TA去进行通信，否则我们就需要kill掉原始的CA，并自行配置TA的初始化。这一套逻辑其实一般都非常复杂，耗费很多精力。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcqtay7WpfFQMaKSCEQqpyjHueC6DPIbhwxR0M8dib4OiabwVCurGqdiaGQ/640?wx_fmt=png&from=appmsg "")  
  
  
接下来再谈一谈TA的提取和逆向分析。TA其实分为两类，第一类就是常规类型的TA，这类型的TA保存的位置是在安卓的文件系统上，所以说只要我们具备root的权限，或者直接从手机的固件包当中是可以把这些TA提取出来的。  
  
而第二种类型就是嵌入式的TA，这类型的TA它会跟TEEOS的特定镜像打包混在一起，所以如果我们想要提取，那么就需要分析并按照TEEOS的特定镜像格式去进行解析了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNc8vbD6PS7Q00aEiczXgcGiaFtXjIMhHlicEmtmhI8EW2tleCx2cJDaSnCg/640?wx_fmt=png&from=appmsg "")  
  
  
接下来再谈谈逆向。不过从去年的研究内容来看，目前只有高通跟Kinibi采用了自定义格式的TA，也就是这里的mdt和mclf格式，而这两种格式目前在git上都有非常完善的开源解决方案，大家可以直接使用。  
  
  
而对于其它所有厂商的TA，目前都是基于OP-TEE格式的TA，这类型的TA其实非常好分析，我们只需要移除掉它原始的TA的 Header，就可以拖进Ida进行分析了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcmPLY6aqQyNLoMLvUqgoC1UoU7BQ1LtlrZfnIDcohHYPFujic0nHEtCQ/640?wx_fmt=png&from=appmsg "")  
  
  
这是一个二进制文件的内容，其实我们能直接发现它里面是包含一个.elf文件头的，所以我们只需要简单的把.elf文件头前面的数据删掉，Ida就能正常解析，但是这里只是谈的是TA的逆向分析，而不是TA的模拟。因为TA的header当中一般都会包含很多必要的信息，包括TA的uuid ,section等基本信息，所以如果我们想要对TA做模拟的话，是不能这么简单粗暴的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNc34r95xg2vlYIAChlZgb22mkiapNPnRGHmos6RQL2gvVcrI6AWnMXjuQ/640?wx_fmt=png&from=appmsg "")  
  
  
那么我们接下来再谈一谈如何对TA做安全研究。首先我们需要知道对TA做安全研究的三个难点，第一个就是我们很难或者是完全无法调试TA。  
  
  
第二个就是CA调用TA的执行log它被关闭或者是加密了。也就是说即使我获得了一个任意代码执行的权限，我把POC发过去了，但是我看不到任何的执行结果，所以我就没有办法确认我的poc或者exp是否编写成功，这是第二个难点。  
  
第三个就是大部分的TA其实都包含敏感的内容或功能，所以说从安全架构的设计上来说，我们需要先提权才能跟TA发送请求。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcDe27icTzlRsW9e7QiaEbJGFNZ7hHx7OpTw4HIo3JFgAZxkia18XKibzakA/640?wx_fmt=png&from=appmsg "")  
  
  
所以现在对于TA的安全研究，主要是从下面的两个维度，在真实的手机设备上和使用模拟工具。  
  
  
我们先简单谈一下在真实的安卓设备上针对TA做安全研究。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNccIoHEB75INHyISl5vGnJc6IUBJAng8aBric34SsjqwN0iakSOszpy1IQ/640?wx_fmt=png&from=appmsg "")  
  
  
这是两年前开发的一套半自动化静态漏洞扫描工具，只要我们现在的漏洞模板足够丰富，其实它是可以直接发现所有的潜在的System/Root提权的攻击点的，那么只需要在接下来做一下简单的人工审计，就能够快速的发现基本上所有的本地system或者root提权。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcvOZxkl5KjYs1J3icnWa3uyVb1Vycticl4x3X4libcKydoOIxzrQ3GraWA/640?wx_fmt=png&from=appmsg "")  
  
  
我把漏洞分为了两种类型，第一种类型是可以武器化的漏洞，第二种类型就是可以用于安全研究的漏洞。我们此时使用本地system或者root提权的根本目的，其实是为了构建我们自己的安全研究设备，而并不是为了数据取证或者是攻击。  
  
所以我们需要额外关注那些仅可用于安全研究的本地提权漏洞。  
  
  
非常典型的一个例子就是这里的三，需要授予其他敏感权限的漏洞，比如通知栏当中的PandingIntent劫持漏洞，如果一个应用想要劫持通知栏当中的PendingIntent，那么一定需要用户手动在设置当中为我们的应用授予NotifiCAtion Manager的权限。这一次的授予操作其实就是一次强交互，即使我们最后劫持成功，并且能够实现system级别的intent转发，那么厂商也只可能给予这个漏洞中危或者低危的等级。  
  
  
如果说一个漏洞需要5次10次甚至更多的用户交互，那么厂商不修都可以。但是这种漏洞在我们安全研究员的手中，就能变成构建我们自己研究设备的大杀器。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNc7eXKgtMvqSggfOQdGicWM4Yib8eLL2oTlibHdTnZ2QNfiaIiaiaRJUtPLicBA/640?wx_fmt=png&from=appmsg "")  
  
  
然后接下来再谈一谈去年的研究的主要内容，都是依靠解锁Bootloader获取持久化root的形式来做安全研究。那么首先还是考虑一个问题，解锁Bootloader难吗？在去年对Bootloader做安全研究之前，其实我认为这一块可能会花掉我特别多的时间，因为当时的研究目标是几个主流厂商的手机，也就意味着我需要都解锁他们的Bootloader，但是当我对Bootloader做了安全研究之后，我发现这里的难度其实并没有想象的那么高，最终解锁了5款手机的Bootloader，其中3款用到了Nday，2款用到了0day。  
  
  
这里面nday的占比其实是远超我想象的，因为在原本的预期当中可能会认为需要用到4个0day，结果现在nday的占比是要比0day还要多的。为什么会出现这种情况？  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcb0gXmxUzaIudWrqzsC6FNWSjEpP8Ndoibf2KKD0UcKDgRWnrZIvhSiaQ/640?wx_fmt=png&from=appmsg "")  
  
  
同样的还是发散一下我们自己的思维。如果我们现在想要使用Nday去解锁Bootloader用于构建我们自己的安全研究设备，那么我们的目标需要是那些最新的旗舰手机吗？其实不是的，我们的目标可以是那些子品牌发布了很久，但是具备最新OEM系统的手机，因为我们的目标很简单，拥有一台具备最新系统的手机就可以了。手机的版本配置以及这个漏洞是否能够武器化，我们一点都不关心。  
  
  
那么在解锁了这类手机的bootloader之后，我们就获得了在真机上测试TEE和TA的能力，在exp编写完成之后，就可以在最新版本的旗舰机上直接使用了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNc0RfFwN95YpctfGfjQqjibeUIVdEibaoeBhblOYeGYpTtF9atNSk3JgXw/640?wx_fmt=png&from=appmsg "")  
  
  
当然，如果说我们找寻了一个厂商所有的子品牌都没有发现一个合适的nday，怎么办呢？这个时候其实可以考虑0day加nday的形式。  
  
  
首先我们需要知道一个概念，修复解锁Bootloader的漏洞和修复普通应用漏洞的策略其实是有本质区别的。如果一个攻击者解锁了老版本系统的Bootloader，那么它是可以自行刷入最新版本的系统，从而保证在最新的系统上仍然获得root权限的。也就是说厂商他在修复解锁Bootloader的漏洞时，不仅需要提供这个漏洞的patch，还需要封禁用户降级到漏洞版本的能力。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcibib4wkBhPDkxnWOk8C2RXeOYZ2upVPib2BrQQfquYLFCBiawiacoC9GIPA/640?wx_fmt=png&from=appmsg "")  
  
  
现在的国内主流厂商其实都对手机的降级有非常严格的限制，但是厂商的防降级安全策略就真的是安全的吗？  
  
  
其实也不是，因为手机降级它是一个非常正常的用户需求，在安全性和用户体验的考量中，厂商很容易做出妥协，为用户开辟例外，那么我们只需要专注于找到这些例外就可以了。第二个就是单纯的手机的防降级安全策略的实现漏洞，只是同样的出于厂商隐私保护的需要，所以这部分的细节就不得不省略了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcro3Lr6PSiboSelxtTZBTIxctq5W51Bbhf8aN7KYiaKIrPibg6Ge7Nc6ow/640?wx_fmt=png&from=appmsg "")  
  
  
那么前面谈的是在真实的安卓设备上对TA做研究，那么接下来就谈一谈TA的模拟。要谈到TA的模拟的话， Unicorn和Qemu就是绕不开的话题，这里采用了Unicorn，因为它的颗粒度会更细。  
  
  
同时自己是选择了基于Unicorn去做二次开发，而没有直接选择Qiling框架。  
  
因为当时的研究目标是业内部分主流TEE的TA的实现，这些TA它的文件格式差别都非常大，同时每个TEE的syscall都不一样。  
  
  
为了避免在兼容性上耗费太多的时间，就采取了自己基于Unicorn去做二次开发。不过如果各位想要针对指定手机的TA或者是指定的TEE OS去做安全研究，我的建议是使直接使用Qiling框架，因为确实能够省很多事儿。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcQ1O0fH9NicczJAricxt1hEuhH4Pibn4Pf1dQTZHDxUkQx1fibT2hU54iayA/640?wx_fmt=png&from=appmsg "")  
  
  
那么这是去年的模拟和Fuzzing框架的一个主要的功能图。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNccKiak5ZiauqzcRxonq5icXVic86IAvVwtKwZiaNpAygTZlfic15vX7NeVNtw/640?wx_fmt=png&from=appmsg "")  
  
  
其实最需要给大家介绍的是Hook模块当中的Crash Patch handler，因为在最初的架构设计当中是并不存在这个模块的，但是当Fuzzing开始的时候，这个模块就必不可少。因为如果一个TA的漏洞过多，那么前序代码造成的crash会阻碍后续代码得到有效的测试。所以当时的解决方案也非常简单，就搞出了这样的一个Crash
Patch handler，也就是我手动地为TA打上一个补丁，比如它的memcpy会造成一个溢出或者是越界，当它执行到memcpy的时候，我就手动的把它的寄存器调整为正常值就可以了。  
  
  
在Fuzzing这一块选择的是 AFL-Unicorn。不过AFL-Unicorn它存在下面三个已知的问题，包括它是无状态的Fuzzing，基于Crash的漏洞检测，同时也是没有ASAN的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcPdRIQxMiadkZTqeYTWGlABdb9AvQFQ70QacjF7Rj8cCMqVqK0H7g2hg/640?wx_fmt=png&from=appmsg "")  
  
  
不过现在我们去看它官方的 git上面的库，其实是能发现它自己使用Python实现了一套类似ASAN的堆溢出的检测逻辑，它的检测的思路跟ASAN的逻辑是一模一样的，当我要执行一个内存分配，比如malloc(8)的时候，它会在分配的堆块的前方跟后方各自插入一个red zone，那么当TA触碰到这两个red zone的时候，就会自然地认为发生了越界访问，从而抛出异常。  
  
  
这一套逻辑其实跟ASAN是一模一样的，但是这个代码其实并不建议大家在自己的模拟中直接去使用，因为它在极端情况下可能会出现bug。这里大家可以明确看到，对于一个malloc(8)的操作，它本质会分配0x3000的大小，它首先会对 malloc(8)的大小做一个页对齐，同时两个red zone各占0x1000，这也造成malloc(8)的操作最后会导致一个0x3000的内存分配。  
  
  
之所以会出现这样的情况，是因为它的malloc的本质采用的是Unicorn实时mmap的形式，而Unicorn实时mmap的最小单位就是0x1000或者是0x1000的整数倍。  
  
  
那么这一套的解决方案其实也非常简单，我们只需要在初始化我们的Unicorn的时候，提前把我们的堆的地址mmap出来，比如0x10000000，那么后续malloc的时候从0x10000000当中抠出一个小堆块，那么自然就能够实现分配了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcZEWcJqXfWUprxmOqHdjf7tvpvXBTSegYMTYoGicgjoQQ8HEUuQ5tLAQ/640?wx_fmt=png&from=appmsg "")  
  
  
既然它存在malloc，它自然就会存在Free，不过当时它的Free的这一套代码其实是有一点小瑕疵的，因为当它Free一个对象失败的时候，它会很简单的返回一个false，但其实这里漏掉了double Free和invalid free这两种漏洞，当然补丁现在已经提上去了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcySC05nI3pQoPtsU231oD7mW1fuXOia64q9mjnRLc4PKCYf03frICVTQ/640?wx_fmt=png&from=appmsg "")  
  
  
然后下面的这个是自己实现的一个整数溢出检查的代码，其实就是针对指令集去做针对性的检查，这里给的代码是Arm64，没有给出Arm32 TA的一些整数溢出检查，是因为在Arm32的TA上，我们不仅需要关注Arm指令，还需要关注Thumb指令，代码量直接翻番，这里放不下。  
  
  
那么接下来再谈一谈AFL-Unicorn存在的一个最主要的问题，就是无状态Fuzzing的问题。  
  
  
首先需要先给大家简单介绍一下，为什么AFL-Unicorn它会出现无状态的Fuzzing？当他要去测试command 1的时候，首先它会保存当时的内存上下文以及所有计算器的值，当command
1执行完成之后，它会还原所有的状态值和寄存器为初始状态。接着再去测试command 2。如果说command2的漏洞触发依赖于command1的执行结果，那么这个时候就会出现漏报，因为此时command1的执行结果已经被清空了。所以当时采用了两种方案。  
  
  
最开始的时候针对TA做了一下基本的调研，发现很多TA它里面的command分支其实并不多，很多时候他都只有2个3个或者是4个5个，所以说第一种解决方案就自然而然的出来了。我们只需要枚举出一个TA当中所有的 command，然后对它们进行排列组合。那么当一条command执行完成之后，我再去还原它的上下文，那么这是一套非常暴力的解决方案，但它确实是有效的，不过这一套方案其实现在也并不建议大家继续去使用，因为它会有非常明显的问题，第一个它会把我们Fuzzing的效率直接显著的拉低。  
  
  
第二个就是我们的去重会很难做。第三个就是发生了crash之后，有的时候会很难定位到底是什么输入数据导致了crash，所以后面就采用了第二种方案，预先执行并保存上下文的形式，其实也就是基于快照，也是目前更推荐大家采用的方式。  
  
  
下面这个漏洞在最初的时候是手动挖掘到的，因为在第一次使用AFL-Unicorn的时候，并没有发现这个问题，在优化之后是已经能够发现这个情况了。  
  
这个漏洞的成因其实蛮简单的，就是攻击者需要首先调用command13，把攻击者完全可控的一个keyblock的结构体放进rpmb当中。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcjyhHce4omXfxIhNpwN6wnzjBNRwubBZb8LepXEuLKgPDFicVSlwEzbw/640?wx_fmt=png&from=appmsg "")  
  
  
然后攻击者再调用command12，此时TA会从rpmb当中去读取用户刚刚保存的 keyblock的结构体。根据这个结构体的一个成员变量的值，判断循环拷贝的下一次步长，而TA没有做好循环拷贝的步长的校验，就产生了循环拷贝导致的溢出。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNchgacPnfvhN0k46MlmQA7JtnxEcEyS9uHZRMwSicaRSZLkKQicdzak0zw/640?wx_fmt=png&from=appmsg "")  
  
  
这里其实就是很典型的command12的漏洞触发依赖于command13的执行结果。  
  
  
那么接下来再顺便介绍一下TA的攻击面分析。简单梳理了一下，大概是这10种类型。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcowXLbToHcuiapqZWc6BCC4Y8gDEFAaHaEFuJ898OMLYKL3ajsYFCIibQ/640?wx_fmt=png&from=appmsg "")  
  
  
第一种类型是一定需要给大家介绍到的，也就是TA的类型混淆。  
  
  
在前面介绍TA的分类的时候，我也介绍到了使用GP格式规范的TA，会使用TEE_Param结构去封装请求的数据，而它能够接收的数据的参数类型就是下面的这一张图，大家可以发现它里面既可以包含value，也可以包含buffer，这也意味着开发者在使用外部传入的数据的时候，一定需要自行校验外部输入的参数类型是否合法。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcY2cnqVxv7hNQq1zfHO3ZeZPMcRwXHbMoJG9zqiavmtnduqkbRTtibGdA/640?wx_fmt=png&from=appmsg "")  
  
  
一旦你不校验，把 value当成buffer来用，把buffer当成value来用，就一定会发生类型混淆的问题。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcXibHNPwk7naq2GniafxGD0x3la9LlywH8ckCxXceMXQW7u2B7ezo55Gg/640?wx_fmt=png&from=appmsg "")  
  
  
在去年的研究过程中，这个漏洞无一幸免，只要厂商的TA遵循了GP规范，它总有一个或多个TA存在这种漏洞，这种漏洞的发现和修复都非常简单，尤其是Fuzzing，一Fuzzing一个准，快的几十秒，慢的话十几分钟或者几十分钟也能够找到，但它的漏洞数量就是很多。  
  
  
我认为一个根本原因其实是TEE它授予了开发者过大的权限，把TA接收和处理外部参数类型的危险能力授予了开发者。  
  
  
不过站在OP-TEE的角度或者是制定一套公开的规范来讲，我认为这种策略其实没有任何的问题，因为它能够有效地提升开发效率和易用性，但是对于很多厂商自研的私有TEE来讲，这一套规范对开发者的要求就有一点过高了，因为如果开发者没有很好的理解TA参数请求当中的参数类型，或者就是单纯的疏忽，那么就会直接造成漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcCSDsBxe1CLEbSVHmRRKnb7DM6ibBzYGwVOOaVSkeiaAuZJkh7LSB0WBQ/640?wx_fmt=png&from=appmsg "")  
  
  
这是一个非常典型的例子。  
  
  
首先我们先看下面的两个箭头，能够发现开发者在这里非常有安全意识的调用了TEE_CheckMemoryAccess函数，用于校验外部的输入参数类型到底是不是buffer，你是buffer我才会执行后续的代码，但是我们现在再回到上面的两个箭头，就发现开发者在没有校验外部输入参数类型的情况下，就已经使用了它的值，那么这里就造成了一个类型混淆导致的任意位置读。  
  
  
当然这个洞其实我更倾向于是一个二次开发造成的问题，第一个开发者他是有安全意识的，但是第二个的开发者可能没有或者单纯的疏忽了，所以针对防护TA的类型混淆漏洞会有一个建议的开发方式，也就是需要校验paramTypes，以及调用TEE_CheckMemoryAccess函数去防止非法输入，不过我认为还会有一套更通用的办法，也就是可以把外部输入参数类型的校验功能封装为SDK，限制外部传入的参数类型只能为共享缓冲区。  
  
  
也就是说收回开发者对于TA参数校验的能力，限制开发者只能从共享缓冲区中去读取数据。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcdhmYwxk0Zf3nCD0YU3iaV6GI1oPejZTfJE9iaIlKOgqJVkfeVJq8GiaiaA/640?wx_fmt=png&from=appmsg "")  
  
  
那么介绍完了类型混淆，接下来还是回到经典的二进制的问题，这是指纹TA当中的一个经典的栈溢出，这个洞有多经典呢，它是没有ASLR，没有Stack cookie的，所以一个很经典的构建ROP就能够实现任意代码执行。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcNAFlbicxZY9ca1hq6BZk72u80CMAaQBQSluXUdMr71gcAmmFibPG99OQ/640?wx_fmt=png&from=appmsg "")  
  
  
不过后续我在它的内存当中漫游的时候，发现指纹TA存在一些特殊的攻击点。  
  
  
首先我们需要知道一个概念，当用户的手指按压到手机的指纹传感器，想要解锁屏幕的时候，指纹传感器会把用户手指的信息发送给指纹TA，指纹TA会把外部的输入和本地保存的指纹模板做一个相似度的匹配，一旦你的匹配达到一定的阈值，我就认为你是一个合法的指纹，从而解锁手机。  
  
  
但是大家可以看到下面的第二张图，这一个手机上面的指纹TA，它的匹配的阈值是37%，也就是说只要相似度达到37%，我就会认为你是一个合法的指纹，从而解锁手机。看起来好像它的策略做得非常的糙，但是当时的那一款手机其实它是一个侧边指纹，校验指纹的位置是在电源键，它本身校验的区域大小就是有限的，所以37是能够接受的。  
  
  
那站在我们攻击者的角度做一下考虑。如果我们现在获得了一个类型混淆导致的任意位置写0，任意位置写1的漏洞，是不是很多时候还需要花很多精力去构建我们自己的rop，有的时候甚至我们的exp都不能编写成功。  
  
  
但如果我们的攻击目标是这种指纹TA或者类似的TA，其实就可以尝试攻击这些状态变量，从而直接解锁手机。不过这里有一个很明显的前提，就是这些状态变量的保存的内存页需要是一个可写状态。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcagicINJbaJgqkLFjTWFQfib5o6CKK6ia6vU36JJ7o3WA9Mjq0ukGGbmRw/640?wx_fmt=png&from=appmsg "")  
  
  
接下来就是一个信息泄露的问题，当然这里额外谈的就是通过log去泄露了。不过同样的从去年的分析结果来看，目前并没有太多的厂商打开了TA的 log，基本上都对TA的log做了加密或者是关闭，也就是提高了安全研究员分析的成本。  
  
  
但是很多厂商的开发者为了方便自己的开发，其实都会给自己留后门，只是因为厂商隐私保护的需要，这里就不展示具体的case，但是各位可以在system，proc,
vendor, odm, products,oem这些目录下去找寻一下常见的二进制文件或者是现有脚本，很多时候是会有彩蛋的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcKOCFwDX8Av5NqPbYF57lr51IyTVYeLkPCYf0Xu5haXs70B4K2PD2bA/640?wx_fmt=png&from=appmsg "")  
  
  
接下来再介绍一个逻辑漏洞，提取手机当中用户保存的一个明文密码，这里需要介绍到一个东西叫Keystore安卓当中的密钥库系统。大家简单理解，Keystore就是安卓系统提供给上层APP一个加密的方式，上层的APP使用Keystore实现加密之后，安卓系统会把你加密的密钥材料放进TEE当中，从而提高你密钥的保存的级别，进而提高破解的难度。  
  
  
这是一个非常典型的例子，开发者只需要调用Keystore的API，然后去生成rsa的公私钥，那么接下来再做一下加解密就可以了。不过站在攻击者的角度，我们看一下这段代码，能够一眼发现问题，这一段代码其实它只用于保存非核心的数据的，因为一旦攻击者提权到漏洞应用的权限之后，能够以应用的身份请求Keystore解密这个应用的所有加密数据。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcVS4J2MyNSs0RS42qUibadnNTGRiaQYE4OEWCQkDM6SEG04kcgMIzp9jA/640?wx_fmt=png&from=appmsg "")  
  
  
所以其实Keystore它还支持安全级别防护更高的保存方式，也就是基于用户身份验证的方式，这个方式也就是说当用户想要触发密文的解密的时候，一定需要先进行PIN码或者指纹的校验，而这两套校验操作本身就是TEE里发生的，所以从而保证它的一个安全。  
  
  
那么从功能和使用的效果上，我把Keystore的用户身份认证策略分为了下面的两个，这两个策略的核心其实都发生在TEE，也就是说我的REE层无法hook或者干扰，从而保证在REE沦陷的情况下，用户的数据仍然安全，说人话也就是即使你拿到了安卓的root权限，你也不能解密我的数据。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcibV1ZRuoVToB08FPrpiaah8LdOWjsVVCceVLGrqsjJgLxGzTJRKxriaQw/640?wx_fmt=png&from=appmsg "")  
  
  
这是一个很好的demo，其实也就是使用了相关的API。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcWTMEGxNhkWNRCU7JagxdZHZTeCn3icdtoHMxPSlgqBAMVmN3HDAVNOA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcA5cbVZKryUr0ncicKvSib3EVbNOuRtun110XCO7ibKicjxIvr2A9E9adKg/640?wx_fmt=png&from=appmsg "")  
  
  
前面谈的是基本的概念，那么接下来就谈一谈它实际的应用场景了，在安卓的手机当中会存在一个自动填充服务，这个其实非常好理解，也就是当我要点击一个APP想要登录的时候，那么系统会弹个框，要你校验你自己的指纹，当你校验通过之后，系统会把你之前预留的账号的密码和你的账号自动输入到 APP当中，那么这个就叫做自动填充服务。  
  
  
实际上每个OEM厂商其实都可以实现自己的自动填充服务策略，那么在本次的分享当中会使用到Pixel5a去做演示，在pixel5a上面，这一套的自动填充服务策略的实现者是GMS。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcG0nicib0yJ6CR6h5mDTCmJhciaQqzHEiaHrhglaJ1gRBwqBXpNu2eQnRoQ/640?wx_fmt=png&from=appmsg "")  
  
  
从下面的第二张图我们能发现，当用户点击Discord的时候，系统会弹个框，要你校验指纹，你指纹校验通过之后，我才会给你展示第四张图，也就是显示Discord的用户明文密码。  
  
  
那看起来 GMS它好像使用了，需要用户身份认证才能获得用户密明文密码的安全策略，但实际其实并不是。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcOKcRCiaPD7diaVXtibZOicrEAzViaAmIyXrU0O1iaavysuzF15NfQRb75wTA/640?wx_fmt=png&from=appmsg "")  
  
  
因为从逆向的结果来看，GMS在初始化密钥阶段并未设置这一个API，这也意味着解密它本地的密文其实并不需要通过指纹校验，之所以UI流程上我们看起来有一个指纹校验的步骤，只是因为GMS在REE层独立调用了指纹校验的API，这个校验的结果其实并不会影响TEE的解密策略，所以说在REE沦陷的情况下，攻击者可以直接触发密文的解密策略。  
  
  
这就是一个最简单的攻击例子。也就是说一旦一个攻击者具备System权限，那么它就可以直接提取本应由TEE保护的用户密码，对于用户密码的防护等级其实是明显不足的，不过这个洞对于GMS来说可修可不修，因为GMS它只是一个三方产品，它如何保存用户的明文密码都可以，但是如果一个厂商或者是高级别的APP，在自己的安全白皮书中明确提到了，要使用手机的最高防护等级来保存用户的密码的话，这个洞就是必修的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcqN2V3T9hZJ6mT36EDzzbGykZ9occ7DOahb8mW81w0KphlkeUqNAZaw/640?wx_fmt=png&from=appmsg "")  
  
  
接下来再谈一谈我们在对TA做研究的时候，其实很多时候都会发现我们只是一个普通的adb shell的权限或者普通APP的权限。那么很多时候虽然我们能够调用TEE的API，但是TEE的API本质还是跟安卓侧的一个Driver去通信的，而这个Driver它是具备System权限，这也意味着我们很多的普通APP是没有办法直接调用我们想要的TA的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcz4IMfD84kbknicI6FuhBBCEWlEPtYNv558aj3UeOjqBtjk4mjM5BXDA/640?wx_fmt=png&from=appmsg "")  
  
  
但其实同样的还是发散一下我们自己的思维。TA它构建出来就是为了给业务用的，部分TA因为业务的需要其实没有任何权限的限制，也就是说任意的三方应用都可以通过安卓侧预制的CA暴露的接口与目标TA直接通信，并不需要与TEE driver去进行通信。  
  
  
非常典型的例子就是这里的IFAA了，IFAA大家简单理解就是一套跟支付相关的规范，当然他自己也有自己的一套通用的组件，每个OEM厂商都可以在通用的组件上编写自己的代码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcztZYachsqVnG4I3AgJ4adI0cNqrlkXibwR6HpD4UVvLsOALdQIkg9yw/640?wx_fmt=png&from=appmsg "")  
  
  
这个厂商他自己的实现代码出现了问题，就导致任意的一个普通应用都可以以IFAA
TA的权限向任意文件写入指定的内容。同时它也支持读取任意文件，比如说IFAA保存的支付密钥，而这个漏洞的攻击就是不需要任何权限的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcPVuVwKDsvqtRicfBmkBBwdIPTAKRZpwRk5vexuQEqmU7ITY9my3VoRg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNc4zFPMTzULpibKfr2omj4Qm2gG1ajacNKice6sc9fQJ4WCwGUB2YF6g4Q/640?wx_fmt=png&from=appmsg "")  
  
  
那么接下来谈最后一个文件操作，在TEE当中的数据存储分为两种方式，rpmb和SFS。rpmb大家简单理解就是一块数据它存储的数据量是非常有限的，所以对于指纹这种大数据，TEE保存的方案都是使用AES对它要保存的数据做加密，然后放在安卓的文件系统上，这套机制就叫SFS，所以它的攻击面其实也非常明显。  
  
  
安卓侧的攻击者，虽然没有AES的key，没有办法解密数据，但问题在于攻击者是可以直接把你删了的，因为这个数据是保存在安卓的文件系统上的。同样攻击者也可以创建一个同名的文件，这些都没有任何问题，攻击者往里面写入任意的数据也是可以的。如果说一个TA比如说找回手机， TA是否生效的依据是判断安卓的文件系统上是否存在某个文件，那么这一套策略就能够直接被绕过。  
  
  
第二个是路径穿越的问题，当然默认情况下，OP-TEE的文件操作的API其实并不会存在路径穿越漏洞，只是部分厂商自己实现的TA，构建了自己的文件交互的API，所以就有可能会导致路径穿越漏洞的重现了。  
  
  
第三个就是多实例TA，对于同一个文件的操作可能会存在条件竞争。  
  
  
那么接下来的这里其实本来是今年的研究目标。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcaVOOiaOxt0O0MYwRzJiad3HnaBORVKkI98VkG7U9zNXyPR1YZKPdtskQ/640?wx_fmt=png&from=appmsg "")  
  
  
但是大家从我今天的分享当中也能够发现，出于厂商隐私保护的需要，很多漏洞其实都没有办法  
完全的披露细节，所以从今年的  
7  
月开始已经转向了国外产品的漏洞挖掘。  
  
  
  
目前在 Mac上发现了一些漏洞，比如说通用沙箱逃逸，多个FDA权限的获取，本地提权等。这些漏洞苹果都正在修复，等到明年修复完成之后，会做全细节的漏洞披露，所以各位要是感兴趣的话，可以到时候关注一下。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8H2WErEEknSzXYXlbDXBeNcEy9fWxZje1ic6D8oU0XykZ6Qa1yzbo1XJ0paKzEdFfFuCOa9icpaKdPw/640?wx_fmt=png&from=appmsg "")  
  
  
我的演讲到此结束，谢谢。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P284Aa0ficGSC1CtOTRibyibuX3fkwqMa3jAezvXteqVLAcCrcUPHZUu93Mvw/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P284Aa0ficGSC1CtOTRibyibuX3fkwqMa3jAezvXteqVLAcCrcUPHZUu93Mvw/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P284Aa0ficGSC1CtOTRibyibuX3fkwqMa3jAezvXteqVLAcCrcUPHZUu93Mvw/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P284Aa0ficGSC1CtOTRibyibuX3fkwqMa3jAezvXteqVLAcCrcUPHZUu93Mvw/640?wx_fmt=gif "")  
  
  
*峰会议题PPT及回放视频已上传至【看雪课程】  
https://www.kanxue.com/book-leaflet-171.htm   
  
  
PPT及回放视频  
对  
【未购票者收费】；  
  
  
【已购票的参会人员免费】：我方已通过短信将“兑换码”发至手机，按提示兑换即可~  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P284wQLs8sYYQ3SPfjTU0yUCFEMI7GL1j6icj6WJdJjZRzhXEYwWPhJaC1w/640?wx_fmt=png "")  
  
《看雪2023 SDC》  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ELCV0YeODjPibEdocEbeulG8eibHMbMqd8wW0FtAiaQd5vUOojOYr9h0YLL4Bghyg6WDAa1BLOrwPpw/640?wx_fmt=png "")  
  
看雪安全开发者峰会（Security Development Conference，简称SDC）由拥有23年悠久历史的顶尖安全技术综合网站——看雪主办，面向开发者、安全人员及高端技术从业人员，是国内开发者与安全人才的年度盛事。自2017年七月份开始举办第一届峰会以来，SDC始终秉持“技术与干货”的原则，致力于建立一个多领域、多维度的高端安全交流平台，推动互联网安全行业的快速成长。  
  
  
  
**钻石合作伙伴**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ELCV0YeODjPibEdocEbeulGNQnicTfdFTMLZZrYiad6CepLfOmmSayZRAoTqY7lt6y3EvW0lgSAxBAg/640?wx_fmt=png "")  
  
  
  
**黄金合作伙伴**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8ELCV0YeODjPibEdocEbeulGC6w7uQ4dRWK870hpcDAqBp3iabcq2hfnk1rSzaDn9kDjcnVFxEeYbhg/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P284kfD9S9vsfbA7wPYNQ1wzFzTUw4rT7XEI8KOYUSEhfic4IVhiaQxGQ8zg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P284kfD9S9vsfbA7wPYNQ1wzFzTUw4rT7XEI8KOYUSEhfic4IVhiaQxGQ8zg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P284kfD9S9vsfbA7wPYNQ1wzFzTUw4rT7XEI8KOYUSEhfic4IVhiaQxGQ8zg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GxwN4MtQwbAbqh6Dr1P284ibrSyc6kEbCicjrkzh1Md8GPu0nrHAkP3sBOhSP2sEqpIYVjm0OSdNBA/640?wx_fmt=gif "")  
  
点击阅读原文查看更多  
  
