#  Android App半自动化静态漏洞挖掘技术分析   
ADLab  白帽子左一   2023-12-17 12:00  
  
扫码领资料  
  
获网安教程  
  
免费&进群  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFJNibV2baHRo8G34MZhFD1sjTz4LHLiaKG9208VTU6pdTIEpC9jlW6UVfhIb9rHorCvvMsdiaya4T6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
## 一、前言  
  
在Android应用层安全研究领域，研究人员大多采用人工审计加脚本的方式进行漏洞挖掘。针对某个新的攻击面，对手机厂商上千款的预置App开展批量的漏洞挖掘时，短时间内很难产出结果，漏洞挖掘效率低。  
  
在2021年7月上旬，启明星辰ADLab基于开源工具二次开发，编写了一套半自动化静态漏洞扫描工具以辅助漏洞挖掘。在2021年8月底，仅3天时间，用这套工具在小米手机上挖掘到10余处高危漏洞及若干中危漏洞，位列小米SRC 2021 TOP1。  
  
本文主要介绍半自动化漏洞挖掘关键技术以及一些研究经验总结。  
## 二、Android App漏洞扫描的难点  
  
由于Java的语言特性，扫描器在某些情况下存在漏报、误报。此外很多App漏洞都属于逻辑漏洞，和代码逻辑强相关。与栈溢出等安全漏洞不同，我们很难直接通过扫描逆向后的App代码得到准确的结果，基本都需要研究员介入做最后的漏洞确认。典型的场景就是Webview Jsbridge漏洞。扫描器确实可以扫描出从外部输入被解析到输入数据被Webview加载的代码执行路径，但Jsbridge漏洞最关键的域名校验策略有多种写法，代码实现完全取决于开发者。扫描器在处理这种漏洞时只能承担辅助作用，即帮助研究员定位哪些代码路径可触发Webview Jsbridge函数，而不能直接得到『存在Webview Jsbridge漏洞』的结果。  
  
同时Android系统诞生的时间足够长且代码开源，故市面上已经存在非常成熟且开源的漏洞扫描工具，内卷极其严重。很多时候比的不是扫描逻辑，而是比谁的漏洞模板和数据建模更优秀。  
## 三、个人扫描器和商业化扫描器的区别  
  
根据不同的扫描目的（如企业使用、个人使用），扫描器可分为个人扫描器和商业化扫描器。主要存在以下4个区别：  
- 漏洞扫描的颗粒度不同  
  
- 扫描结果的呈现方式不同  
  
- 对于漏洞漏报的容忍度不同  
  
- 对于漏洞误报的容忍度不同  
  
## 四、半自动化和自动化漏洞扫描的区别  
  
半自动化漏洞扫描指的是需要在扫描过程中或扫描结束后人工参与的漏洞扫描。大多数情况下是指扫描结束后需要研究员二次确认漏洞是否真实存在。Android应用层漏洞因其特性，存在很多逻辑漏洞，所以对于个人研究者而言，半自动化扫描器会是更好的选择。  
## 五、基于文本匹配的半自动化静态漏洞扫描器介绍及优化  
### （一）实现原理  
  
首先利用反编译工具（如jadx）将dex转换为Java源码并保存到本地，然后执行文本扫描，可简化为执行grep（正则匹配），最后按照扫描模板中定义的漏洞点识别文本，一旦匹配则保留结果。  
  
其中，扫描模板决定了该漏洞扫描器的漏洞发现率。只要漏洞模板定义得足够好，可以保证大部分的漏洞类型不出现漏报。但该扫描策略颗粒度太大，一定会存在误报，需要研究员人工确认。  
### （二）开源工具MobSF  
  
MobSF[1]是目前许多文本匹配扫描器的始祖。其核心实现（文本匹配）逻辑简单，大量类品只是基于该框架增删改UI、增加漏洞扫描模板等。为避免重复造轮子浪费时间，我们最终选择了MobSF，在此基础上进行拓展优化目标。  
  
MobSF基本界面如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGwlXppxEuwwmxgy19yibLUlKkW7mvGuDzdZkemK7KhwZZB30Uxv2tAeiaHdhb9gMicxjakicCJMVwJLg/640?wx_fmt=jpeg&from=appmsg "")  
图1  MobSF主界面  
  
下图展示的ISSUE仅为使用MobSF的『预置漏洞模板』得到的结果，并非实际可用漏洞，仅用作界面展示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGwlXppxEuwwmxgy19yibLUlt63JKEsRhvqSvJt0uWs0NS9rF8q9AaevDrEZtOA2s3BIcibKsib10Dhg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGwlXppxEuwwmxgy19yibLUlq0Wbyd45FlaGwonfO0OswmsmyTdibaRpkQHniciawSlX3nAAdkLghicGHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
图 2 MobSF扫描结果详情页  
  
当用户点击FILES标签下的代码文件，如`xx /xx/common/xx.java`后，程序会自动打开并加载目标源文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGwlXppxEuwwmxgy19yibLUlibHnaFlyfTJte3IibECxcSTx76KY4YL81qic0gApOGa7NmQYCdvH0Jx8A/640?wx_fmt=jpeg&from=appmsg "")  
  
图 3 MobSF漏洞详情页  
  
MobSF扫描器以yaml格式解析漏洞扫描模板[2]:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGwlXppxEuwwmxgy19yibLUlo1IzvAy32aicW46pIKzMOS9GgdBdOiaeHCibtmWJSSokPq9K7EnCPDg4w/640?wx_fmt=jpeg&from=appmsg "")  
  
图4 扫描模板定义  
  
MobSF的优点：  
- UI精美。对于大多数不会前端开发或者想节省开发时间的研究员来说，MobSF是一个绝佳的二次开发目标。研究员只需将精力聚焦于核心扫描逻辑的优化和扫描模板的构建上。扫描结果的展示及统计可直接采用MobSF的框架，避免重复造轮子，节省了大量不必要的时间。  
  
- 功能丰富。MobSF还支持恶意病毒扫描、敏感数据扫描等。研究员可根据自己的需要对这些模块增删改查。适合不同方向的研究员，如病毒分析、隐私合规、漏洞挖掘等。  
  
- 纠误成本低。MobSF支持在浏览器中直接查看反编译得到的源码。研究员只需要点击一次便可快速纠误。对于一些漏洞类型，经验丰富的研究员只需几秒就能确定扫描结果是否误报。  
  
- 只要漏洞模板足够完善，漏报概率极低。  
  
- 扫描器会将APK反编译并保存java源码到本地，适合研究员快速分析目标APP。也便于研究员反复测试及扫描结果的查询。  
  
MobSF的缺点：  
- 误报率高。扫描的核心逻辑为正则匹配。以查找包含hello关键词的漏洞举例，hello、helloWorld、aaahello、hellooooooooood均会被标记为漏洞。虽纠误成本低，但若误报的数量太大（100：1），同样会耗费研究员大量的精力。  
  
- 分析速度慢。扫描器会将APK反编译并保存Java源码到本地，该流程的执行速度取决于目标APK的代码复杂度且后续会对本地文件执行正则匹配以扫描漏洞。若漏洞模板丰富，漏洞扫描亦很耗时间。以小米手机为例，300个预装App总分析时间为4~6个小时（8核32G Macbook pro）。但多次分析同一APK时，速度较快，因为不再需要反编译APK。  
  
- 占用磁盘空间大。以小米手机为例，300个预装App分析后占用的磁盘大小为40G~60G  
  
## （三）拓展和优化  
  
本节主要介绍对该框架进行拓展以及优化时使用到的技术及思考。  
- 在2021年7月的1.0版本，除了核心的扫描逻辑没变，我们对其余的代码模块均做了二次开发。在2022年9月的2.0版本，又对其核心的扫描逻辑做了优化升级。至此，除了UI模块未变，其余模块均做了二次开发。  
  
- 移除动态调试、病毒查杀、iOS支持等无关模块，仅保留StaticAnalyzer模块  
  
- 删除自带的无用模板，根据需要编写特定的漏洞扫描模板（30+）  
  
- 优化多次扫描的逻辑  
  
- 优化部分代码逻辑，提升扫描速度  
  
- 针对误报率过高导致的即使纠误成本低也需耗费大量精力的问题，结合Android App漏洞的特性，优化其核心扫描逻辑。目前在大多数类型（如双无PendingIntent劫持、Intent转发、代码执行等基础漏洞）的漏洞扫描上误报率极低。误报率从（100：1）降低至（3~10）：1。部分漏洞无误报。  
  
## 六、基于静态污点分析的半自动化漏洞扫描器介绍及优化  
### （一）污点分析的基本介绍  
  
污点分析分为静态和动态，这里介绍静态的污点分析。污点分析的原则是：  
- 将当前用户的输入视作污点数据，所有基于该污点数据产生的新数据同样视作污点数据；  
  
- 所有污点数据的执行路径称为污点路径；  
  
- 跟踪和污点数据相关的信息的流向，根据特定的规则判断它们是否会影响某些代码逻辑，进而挖掘程序漏洞。  
  
### （二）逻辑梳理  
  
如果现在要编写基于静态污点分析的扫描器来分析App是否存在Webview jsbridge攻击点（Intent转发漏洞也一样），先梳理一下思维：  
- 找到一个导出的Activity（具备BROWSABLE属性并响应VIEW action）  
  
- 该activity会解析外部传入的intent并让注册了jsbridge接口的webview加载intent中的url  
  
因此核心在于：  
- 确定参数传递的入口。  
  
- 获得污点的传播路径：从这些Activity解析Intent的位置依次往后查看，构建一条调用链直到到达webview.loadUrl。亦可逆推。  
  
- 判断调用链是否到达最终的攻击入口。  
  
那如何知道这个Android App中哪些Activity是导出的？又该怎么获得方法和方法之间的调用关系呢？我们可以借助Androguard[3]。这款工具是现在很多Android静态分析工具的核心，它会分析dex并完全解析其中的类、方法，生成相关的Python类，在Androguard分析完后，某个类/方法调用了谁，谁调用了它，全都保留在内存里。而研究人员只需要进行正序或者逆序的溯源即可（即在Androguard上做二次开发，添加自己的逻辑）。  
  
这里以逆序的溯源为例：  
- 首先得到AndroidManifest的内容，判断哪些Activity的exported= true或者exported != false且具备Intent-filter，Intent-filter包含BROWABLE属性，同时响应VIEW这个action。  
  
- 拿到wloadUrl这个函数的被调用情况。附加条件如addJavascriptInterface，也是一样的判断逻辑。  
  
- 依次回退调用链，查看调用loadUrl的方法是否有被其他类的某个方法调用，如果有，持续回退，并构建调用链。  
  
- 一旦发现回退到的类名等同于导出的Activity或者其他颗粒度更细的函数，如四大生命周期函数，Intent的解析函数等（取决于扫描策略），匹配终止，打印出该调用链。  
  
- 至此，扫描器就找到了一条外部可控的攻击路径，接着研究员便可执行漏洞的可利用分析。  
  
### （三）开源工具Jandroid  
  
与『基于文本匹配的半自动化扫描器』一样，『基于静态污点分析』的半自动化漏洞扫描器也存在很好的开源实现。Jandroid[4]扫描器于2019年年底公开。  
  
Jandroid扫描模板[5]：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGwlXppxEuwwmxgy19yibLUlhpHYLAakxuzufOsjYbyxXbyTjue9C1XqzKpuGJ3SCJDUmPJw3ibEgjw/640?wx_fmt=jpeg&from=appmsg "")  
  
图 5 扫描模板  
  
Jandroid扫描结果为可视化的节点：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGwlXppxEuwwmxgy19yibLUlNK6rcsOJiahKqWibtTe4U9QCXicwv4n29FXSbWbKRDoXSic31vag5nQI2Q/640?wx_fmt=jpeg&from=appmsg "")  
  
图 6扫描结果  
  
『基于静态污点分析』的优点：较之于文本匹配，该扫描策略扫描速度更快。无需转换dex为java源码，速度是文本匹配扫描器的2~4倍。采用基于调用关系依赖的扫描策略，所以只要模板定义得好，误报率会很低，在扫描『ZIP包路径穿越』、『Intent转发』、『命令注入』等漏洞时有奇效。且不占用太多磁盘空间。  
  
『基于静态污点分析』的缺点：经研究发现，这种分析策略因Java的语言特性限制存在很大不足，导致漏报率较高，只能当做辅助审计的工具，故将其搁置。例如，作为一个浏览器App，基本都会有导出且具备Browable属性的Activity，同时该Activity会调用webview.loadUrl打开指定网页。但令人惊讶的是，我们使用该扫描策略扫描了3款主流浏览器应用，却只扫出1款浏览器存在少许符合条件的Activity。同时经人工确认，该款App也不止具备这几个符合条件的Activity，该扫描策略的漏报率极高。  
  
接下来我们会介绍『基于调用关系的静态分析』为何会存在漏报以及如何解决。  
### （四）漏报原因以及解决方案  
  
Java是一个面向对象的语言，拥有4大特性：封装、继承、多态、抽象。Java也存在反射机制。为了实现『一次编译，多平台共用』的目的，在程序语言和机器语言中间布置了一个中间层即JVM。JVM拥有自己的堆用于存放生成的对象，也有自己的堆管理策略。  
  
以Java的接口举例。在Java中，如果要创建一个接口的实例，就需要使用一个类来实现这个接口，并使用new关键词（或者其他实例化的方法）标记以便JVM将其实例化，而JVM在运行时才会为对象分配内存并调用其构造函数。故只有在运行时程序才能知道该对象具体的类型是什么，才能进一步去寻找需要调用的目标函数。  
  
前面我们已经提到，Androguard在静态分析时会梳理方法和方法之间的调用关系并构建调用链。但如果目标方法依赖的是一个接口，而接口的具体实现又只能在运行时才会实例化，这就会导致Androguard在静态分析时无法定位这个接口的真实实例，从而导致调用链的断开。  
  
同时，基于Java的语言特性，Android开发者们有很多花哨的代码写法，很典型的便是EventBus、Rxbus。以事件总线举例，可以将其简单地理解为一个队列Queue。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGwlXppxEuwwmxgy19yibLUlU9w7WdjD9BxB9edgLt3sVxJbRVbBl4pWSTlSQ2YSKpzxhabLPuUzGg/640?wx_fmt=jpeg&from=appmsg "")  
  
图7 事件流  
- 事件流拥有一个管理类Manager。  
  
- 在初始化阶段或动态注册阶段，各注册者（即各个类，基于同一接口）会调用Manager的subscribe函数告诉Manager自己要处理的eventID。  
  
- 当一个事件来临时，如用户触发某个操作，这个事件会从事件流的上游传递到下游（本质就是Manager遍历自己的注册者列表），如果注册者注册的eventID和这个事件的ID一致，那么Manager会终止遍历，并将这个事件抛给该注册者处理。  
  
前面介绍到了，『调用关系依赖』的漏洞扫描策略是利用方法和方法之间的显式调用关系来生成回溯链的。在这种情况下，事件的发出方只知道调用了事件管理类Manager的event_in函数，但在静态的情况下不知道到底被哪个注册者的event_handle函数处理了，所以也就没有办法继续维护该回溯链，从而导致漏报（即多态导致漏报）。  
  
在2019年底接触到这种扫描策略后，就考虑过如何解决这个问题。结论是，如果能加上一些语法分析以及机器学习，便能部分解决这个问题。当然，动态分析也能解决这个问题。  
  
但对个人安全研究者而言，这种解决方案成本太高，个人研究者并没有必要死磕。编写漏洞扫描工具的本意就是为了更高效地挖洞。如果编写漏洞挖掘工具的成本是人工审计加脚本挖掘的几倍甚至几十倍，那也就没有编写漏洞扫描器的意义了（如果是商业扫描器，或者企业内部的扫描器，自然有必要解决这个问题）。  
  
另外我们相信，不能过于依赖扫描器的准确率。作为扫描器而言，如果这个扫描器的扫描结果有效率是99.9%，那也仍有0.1%的概率漏报。以数学的概念理解，0.1%和99.9%相比太小，完全可以忽略。但如果这0.1%中恰好包含严重漏洞呢？出现『前99.9%的漏洞总价值100美元，这0.1%的漏洞价值20万美元』的情况也是可能的。        故我们认为个人研究员在编写扫描器时除了准确率外还需要有兜底策略，即防御漏报。因彼时（2019年底）的研究重心并不在移动安全，故未再深入研究。  
  
2021年7月在编写『基于文本匹配的半自动化漏洞扫描器』时，我们想到可以结合这两个扫描器，将他们的优势互补，便可很大程度弥补各自的缺陷。此时我们编写的并非商业化扫描器，而是个人扫描器，因此无需一个技术点上死磕。只要能解决问题，那就是好办法。  
  
『基于静态污点分析的扫描器』确实会存在漏报，但『基于文本匹配的扫描器』并不会。即使某些漏洞使用『基于文本匹配的扫描器』扫描也不能得到确切的结果，但至少可以抛出问题，避免出现『遗漏漏洞』的情况，此时只需结合人工审计即可覆盖所有的攻击点。  
  
同时『基于静态污点分析的扫描器』也会在一定程度上弥补『基于文本匹配的扫描器』容易误报的问题。只需编写一个Bridge合并它们扫描的数据和结果即可。  
  
这样，研究员便能以很小的代价得到一个相对好的结果。  
  
2021年7月我们在编写这款漏洞扫描器1.0时，只花了不到2周时间（大部分时间用于微调UI和优化输出），就得到了很好的结果。后续的2.0优化，也不过1周多的时间。  
## 七、研究经验总结  
1. 不建议使用挖掘App（如Facebook、淘宝）的思维挖掘AndroidOEM厂商的App漏洞（如三星、小米等）。构建漏洞扫描器亦是如此。前者只是App，后者是操作系统，很多时候都需要兼顾应用层、框架层、内核甚至是TEE的特性对预置App进行漏洞挖掘。  
  
1. 结合反编译软件的特性定制化静态扫描软件的扫描逻辑：如双无PendingIntent的漏洞扫描。  
  
1. 本文介绍了『基于文本匹配』和『基于静态污点分析』的Android半自动化静态扫描技术，中间也提到了两个很成熟的开源扫描工具MobSF和Jandroid。从这里我们也能了解到，因为Android已经发展了十多年，业内对它的研究已经非常成熟，各种扫描策略都有开源实现，所以很多时候研究者们能做的就是看能否对他们的策略进行优化或者能否先别人一步准备好漏洞扫描模板。现阶段的竞争已趋于『漏洞模板质量和数量』的竞争。谁能率先发现新的攻击面，谁就能掌握主动。所以研究员可将更多的精力放在新攻击面的挖掘上。  
  
## 八、未来优化方向  
  
将结合Android框架层的机制挖掘OEM App的一些独特攻击面，并考虑结合动态分析。因目前的扫描器已能完成大部分的任务，故未来再根据实际需求对其进行相应优化。  
# 九、参考链接  
  
[1]https://github.com/MobSF/Mobile-Security-Framework-MobSF  
  
[2]https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/StaticAnalyzer/views/android/rules/android_rules.yaml  
  
[3] https://github.com/androguard/androguard  
  
[4] https://github.com/WithSecureLabs/Jandroid  
  
[5]https://github.com/WithSecureLabs/Jandroid/blob/master/templates/android/sample_basic_browsable_jsbridge.template  
```
来源:https://www.freebuf.com/articles/network/385451.html
```  
  
声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。**所有渗透都需获取授权**  
！  
  
@  
**学习更多渗透技能！体验靶场实战练习**  
```
```  
  
  
