#  G.O.S.S.I.P 阅读推荐 2024-06-21 漏洞猖狂，硬件帮忙   
原创 G.O.S.S.I.P  安全研究GoSSIP   2024-06-21 20:20  
  
想要解决软件的安全漏洞问题，光从代码层面入手似乎已经不太可能了——现如今全世界每天产出软件代码的量越来越大，更不要说AI也加入到生产  
shit mountain高质量代码的行列中来。代码静态安全分析工具和动态测试工具再厉害，也受不了这么多需要分析的新代码，更不要说还需要人来确认各种缺陷是否真实存在。于是乎，作为防守方，安全研究人员只能且战且退  
范戴克，把新的安全防线构建在硬件层面上，从而试图“一劳永逸”地解决所有上层的软件安全问题。可现实真的如此美好吗？今天我们要介绍的这篇来自ACM Computing Survey的论文A Survey of Hardware Improvements to Secure Program Execution会回答你的各种疑问：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21Ep1wBfamiaE3AKRMgSicJ1hLiaPTyTezZrS6gzaiaRp9vhPxIRyEibuhLQYGgibvqqib5Oru8TECx6y48Cg/640?wx_fmt=png&from=appmsg "")  
  
当今搞安全研究，如果不了解安全的历史，你就不能说自己“懂安全”。作者当然也要先说明一下本文做到了博古通今，于是就拿牙膏厂做例子，展示了一下从20年前开始Intel是如何把各种乱七八糟的（安全）特性加入到处理器中（如下图所示）。你对这些特性熟悉也好，不熟悉也好，反正首先可以直观地看出来，通过硬件新特性来增强整个系统的安全，并不是最近才开始的趋势。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21Ep1wBfamiaE3AKRMgSicJ1hLk6Qb0ERLicFLxJZSg27Uvx3hbrFQWEvlW3khtob51OUiaHibAalUsjMlQ/640?wx_fmt=png&from=appmsg "")  
  
实际上，基于硬件特性实现特定的安全防护，这方面的研究论文可以说是汗牛充栋，肯定不能流水账一样介绍给大家，那这篇survey的作者是怎么对这些研究成果进行分类的呢？我们首先从一张大表看起。在下面这张表格中，作者首先把硬件安全特性分为了三大类：  
1. Execution Mode：这一类硬件安全特性是为代码执行构建了一个特定的（权限）模式，从而让特定的代码能够相对独立地运行，提高安全性，这里面典型的例子就是Intel的SGX和ARM的TrustZone技术；  
  
1. Extension：这一类硬件安全特性是在现有的运行环境中增加了一些安全扩展，一方面为了增加安全性，另一方面也是出于对软件实现的效率开销的考量，这方面的典型例子就是Intel的MPK技术——尽管用软件方法（mprotect）也能实现类似的内存页隔离效果，但是硬件实现能够做到非常小的运行时开销；  
  
1. Co-processor：这一类安全特性完全把代码执行放进一个独立的隔离环境里面去保护（还记得我们前几天介绍的【G.O.S.S.I.P 阅读推荐 2024-06-11 乱拳打死加密师傅】中介绍的StrongBox技术吗），这种设计一般只能把一些不太需要频繁交互、相对比较简单的操作（例如加密和签名）放在特定的协处理器（也可以叫做安全芯片）中去执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21Ep1wBfamiaE3AKRMgSicJ1hLZXcOvlDWujV5cq8JxAGeb32fvgmgK5lgGs1icE8Gn9eAExwFaysTHJw/640?wx_fmt=png&from=appmsg "")  
  
但你也许会说，这种对硬件安全特性的分类方法科学吗？实际上本文并不是一上来就直接提出这种分类方法的，作者为了讨论硬件安全防护，首先需要聚焦一个需要保护的对象。在本文中，这个对象被抽象为program execution，而硬件安全防护的目标就是去保证所谓的secure program execution，听到这里，你是不是觉得有点太抽象了？到底什么样的程序执行算是安全的程序执行，这个也太难定义了吧？确实，什么叫安全，这个甚至涉及到自由主义和保守主义的价值观了，我们必须要有更为具体的讨论点才行，因此本文作者从如下三个方面属性来讨论了程序执行的安全性：  
1. State correctness：这个属性主要是要求程序执行满足两点：第一，初始化状态要正确，也就是说加载待执行的代码必须是可信的，现在很多设备在启动阶段要求检查bootloader签名就是个很好的例子；第二，执行状态的连续性（突然想到了著名的“可微必连续，连续不一定可微”）需要保证，也就是说从一个可信的状态开始，需要保证所有的执行状态都能正确的保存下来（例如固件升级以后就不能降级，需要确保状态信息的完整性，这里又提醒大家去读一下我们前几天的文章【G.O.S.S.I.P 阅读推荐 2024-06-13 大破eMMC写入限制】，看看执行状态是怎么被修改的）；  
  
1. Runtime protection：这个就是经典的内存安全性要求啦，也就是需要保证不能非法（不过这个地方的非法又是一个很难严格定义的概念）访问或内存——特别是低权限代码不能访问高权限数据；同时还需要保证CPU的执行（PC指针）不能被外部输入控制，否则会造成code reuse attack；  
  
1. Input/output protection：要求输入的数据（特别是代码）需要有密码学签名的保护，否则不能信任；另一方面，对于一些特定的需求（例如指纹验证），最好通过硬件保护的输入信道来进行数据交互，防止中间人进行数据篡改。  
  
作者用下图来展示了在整个程序执行的生命周期中，这三方面属性的影响：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21Ep1wBfamiaE3AKRMgSicJ1hLAfwicicS7mShcUcV3GgGMnSgicO2A4doIGULCg1giccpOkt8uVStuW6SEw/640?wx_fmt=png&from=appmsg "")  
  
在进行完分类并且讨论了一些典型的技术（论文3.3章）后，作者用了两个具体的应用场景来作为实例，以上述三方面属性作为审查的切入点，逐一讨论究竟硬件特性应该如何帮助实现软件安全，又或者说，在实践中，有哪些实现错误，让基于硬件安全特性建立的所谓“安全”运行环境出现了问题。那究竟是什么应用场景呢？让我们往下看。  
  
作者讨论的第一个场景，是基于Firmware建立起来的可执行环境（EE），这个听起来好像有点陌生，因为我们作为用户很少会去和这类EE交互。但其实各种设备上基本上都会有这类EE：想象一下，各种设备在最初始上电阶段，都是要依赖firmware来引导和建立一个甚至没有操作系统的环境，而且这个步骤非常重要，一旦被攻击，甚至连后面的操作系统的安全性都没法保证。当然，基于Firmware建立的EE，不仅仅是像Bootloader这类和后续的操作系统运行在不同阶段的EE，有的EE会和基于操作系统的EE共存（例如后面会介绍到的“臭名昭著”的Intel System Management Mode 也就是那个SMM系统管理模式），还有的EE不和主系统共享硬件资源（比如内存），单独占用一个协处理器来完成它的任务。那作者讨论的第二个场景就是我们大家非常熟悉的TEE，这里面既包括了像ARM家的TrustZone也包括了Intel家的SGX和AMD家的SEV。TEE的特点是基本上都和主系统共同运行，硬件资源也基本共享（当然使用了各类隔离手段），而且还提供了许多接口方便TEE和外部环境交互。  
  
读到这里（论文的4.1和4.2章），其实感觉稍微有点脱节——硬件安全防护机制究竟是怎么和各类EE结合起来的，并没有很有机的融合到Firmware EE和TEE的介绍中去。而接下来的4.3章和第5章，又回到了对各类硬件安全防护机制的讨论上，如果读者阅读这些部分，建议就只管当前语境不管上下文就好。  
  
论文的最后部分（第6章）提到了安全攻击，也是我们读者会比较感兴趣的内容。特别地，作者用了前面提到过的SMM作为例子，讲述了它的发展史上出现的各类安全攻击（如下图所示），并把这些安全攻击分为三类——通过绕过内存隔离机制的攻击、通过侧信道手段的攻击以及通过固件更新开展的攻击。这部分还蛮有意思的，喜欢的读者可以去延伸阅读里面提到的各类安全问题的细节：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicdfzKrO21Ep1wBfamiaE3AKRMgSicJ1hL5ZrSEiaCPMSrdvibdE3iaNpibhn0cnTHF85qhg19Oor13soHOuicb8gUpXA/640?wx_fmt=png&from=appmsg "")  
> 论文：https://people.scs.carleton.ca/~lianyingzhao/CSUR_survey_hardware_security_authors.pdf  
>   
  
  
  
