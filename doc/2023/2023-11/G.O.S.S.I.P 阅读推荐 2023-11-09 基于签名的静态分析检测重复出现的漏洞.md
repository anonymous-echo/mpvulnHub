#  G.O.S.S.I.P 阅读推荐 2023-11-09 基于签名的静态分析检测重复出现的漏洞   
 安全研究GoSSIP   2023-11-09 21:16  
  
> Wooseok Kang, Byoungho Son, and Kihong Heo. 2022. TRACER: Signature-based Static Analysis for Detecting Recurring Vulnerabilities. In Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security (CCS '22). Association for Computing Machinery, New York, NY, USA, 1695–1708. https://doi.org/10.1145/3548606.3560664  
  
  
今天分享一篇来自 CCS' 2022 的论文 "Signature-based Static Analysis for Detecting Recurring Vulnerabilities"  
# Intro  
  
由于开发者很容易在同样的地方踩坑（数学运算，协议等），或者人们对复杂的低级语意的误解（C 语言中的未定义行为等），加之代码重用，致使相似的漏洞重复出现。  
  
代码相似性有一些相关论文，这里记录一下  
- Yaniv David et al. Firmup: Precise static detection of common vulnerabilities in firmware.  
  
- Steven H. et al. Asm2vec: Boosting static representation robustness for binary clone search against code obfuscation and compiler optimization  
  
- Jiyong Jang et al. Redebug: Finding unpatched code clones in entire os distributions  
  
- Seulbae Kim et al. VUDDY: A scalable approach for vulnerable code clone discovery  
  
- Jingyue Li et al. Cbcd: Cloned buggy code detector. In 34th International Conference on Software Engineering (ICSE 2012). IEEE Computer Society, 2012  
  
- Damien Octeau et al. Combining static analysis with probabilistic models to enable market-scale android inter-component analysis  
  
- Nam H Pham et al. Detection of recurring software vulnerabilities  
  
- Yang Xiao et al. MVP: Detecting vulnerabilities using patch-enhanced vulnerability signatures  
  
作者认为这些工具检测是基于语法匹配的，不能应对语法结构完全不一样却有着相似的漏洞。  
  
作者提出5个要素以评价分析器  
- Accuracy：是否正确报告潜在的漏洞，误报率低  
  
- Robustness：能否发现同样漏洞的变种  
  
- Generality：能否发现很多不同种类的漏洞  
  
- Scalability：能否适用于大型程序  
  
- Usability：是否有直观可解释的报告  
  
# Content  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5oDah9ZBo0bbTrhIR5JaYKYaOCxhksbea3VyZJIu3KYwN9ibLsQicABjA/640?wx_fmt=png "")  
  
2009 年，在图像处理软件 gimp 中出现了这么一个整数溢出的漏洞（图1a，第12，13，14行）。8 年后，相似的漏洞又一次出现在了图像处理软件 sam2p 中（如图1b）。因为对 BMP 处理有着相似的逻辑，这两段代码片段有着相似的逻辑，相似的漏洞  
（人类总是在同一个地方重蹈覆辙）。  
  
为了发现这样的漏洞，作者提出 Signature-based Static Analysis。经典的方法是直接比较程序的语法（比如函数或者程序块），启发式的方法（VUDDY 和 MVP）选择包含 patches 的函数作为特征。然而这些方法都对付不了规模较大的、语法差别较大的函数（如图1c），尽管漏洞的本质是一样的。  
  
作者还提到，基于克隆的方法不能高效的通过图1a 的 signature 检出图1b 图1c 的漏洞，通用的整数溢出检测又有很多误报，通过特定的匹配工作量也非常大。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5btg9sYNviajowrK1ibM2fMm6H4SSktabGLQdV8CRwqBguL7bmyzL5icMw/640?wx_fmt=png "")  
  
图2 是作者介绍的工具，可以用图1a 中的 signature 精确检测图1b 和图1c 的漏洞。  
## Taint Analysis  
  
作者用简单的污点值抽象域 T = {⊥𝑡 , ⊤𝑡 } 表示是否可能被污染，⊥𝑡 表示没被污染 , ⊤𝑡 表示可能污点数据。抽象域 I = {⊥𝑜, ⊤o} 表示是否可能溢出 ⊤o 可能溢出，⊥𝑜 没溢出。只有同时 ⊤𝑡 和 ⊤o 时才可能存在漏洞。  
## Traces on Data Dependency Graphs.  
  
这部分是关于需要比较的 signatures 也就是所谓的 Traces 。值得注意的是，作者认为使用数据流依赖图而非控制流依赖图能够避免不相关的表达式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5tlMlSBL6D5J4rOl5tj0AtUpV0zQyuxONBwhqwibMDannozQn6lBLvKg/640?wx_fmt=png "")  
  
作者使用如图3 所示的，从数据流图中提取出的 source 到 sink point 的痕迹。这样的痕迹（Trace）会被作为漏洞的 signature。  
  
然后会尽可能地提取出所有 source 到 sink point 的痕迹。  
值得注意的是这里他们只展开一次循环。  
## Feature Representation  
  
这里讲的主要是对语意语法的表达。最终  
  
作者以向量的形式来表示 Trace。  
- Low-Level feature：如图3a 所展示的被 <> 包裹的向量，只表达使用了几次 primitive operator 和 APIs。  
  
- High-Level feature：需要手动实现的比如 **IfSmallerThanConst** ，表达 x < const 这种语意。另外，作者✍️手动实现了 5 种语意。  
  
假如从程序中检出了目标的痕迹，但是没检出 signature 痕迹（这里我认为是指 High-Level feature），那么就认为没有漏洞。  
## Similarity Checking  
  
作者使用余弦函数来表示相似度。以图3 为例。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5Yqt9wAbU4qc4V6TQicKv3fgw2Prq5XyObqGrrgqK2MwuSlSVlqlzAJg/640?wx_fmt=png "")  
  
图3a 和图3b 有着 0.96 的相似度。Tracer 由此检测相似度比较高重复漏洞。  
  
接着作者紧随其后描述了上述整个过程的形式化方法，对 ALARM，TAINED TRACE，SCORE OF ALARM 的形式化定义。如果感兴趣可以看一下原文，这里只简描述一下一下形式化的算法和几个定义。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5gM3CicoN5a1SPIIeP7hOVQuQ9rLHLPOblZqbqPgGAGSPw8tHHNBicQ9w/640?wx_fmt=png "")  
  
从程序中取出 alarm 的集合 （line1）  
  
根据程序构建 DFG （line2）  
  
对程序的每一个 alram，从中提取出 traces 的集合 （line5）  
  
然后把这些 traces 表达成 feature vectors （line6）  
  
与 signature traces 的 feature vectors 对比，取相似度最高的 （line7）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5gVhr1Jwr81XnHIxCX7RHPUyJZ3wvbU7fiaANU8VXMTMFtfwCOYWEkjg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5dic2ficOun1cGKsZOCWqICzQMfic91Ow0iccmRhOJG0OVwTs69qhwmeh4A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5bgGLN5ZZSELT6FDSeWia4BiblsqxPJEOia4fvORicK4oq2Eyf34WI2Supw/640?wx_fmt=png "")  
  
除此之外，作者还定义了抽象内存，以及一系列在抽象内存上的形式化方法。  
  
作者的动机是在看漏洞报告时发现开发者通常根据一系列操作来描述一个漏洞，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5jt5RHZGCxIYQHZxh10sLichDXzFyNkaG5dOvPEOpCDPtNSImWswTjUg/640?wx_fmt=png "")  
  
作者把 low-level feature 和 high-level feature 分离是为了提高效率和精度。  
  
在 Low-Level feature 中，由于每个 Trace 只是由一系列操作组成，为了提高精度  
- 只有当分析器报告 alarm（source and sink points ）才会从程序中提取 trace（那一段向量）  
  
- 使用数据流依赖  
  
在 High-Level feature 中，作者设计了如下的特性，进一步提高程序分析的精度。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5kneLILVyicjibbYF1vZlg1iaW1oB2HlHJ3R7SdGXy7xQ8KlJiaq2eSGoMw/640?wx_fmt=png "")  
  
以 EqualToPercentage 为例，这个设计也在 MVP 中使用过，在通常的条件表达式中可以避免格式化字符串的错误。尽管作者说在只有 Low-Level feature 的情况下，Trace 的精度已经很高了，使用了 High-Level feature 可以让精度更高。  
# Evaluate  
## Experimental Setup  
  
**Implementation**：Tracer 基于 Facebook’s Infer analyzer，使用污点追踪能分析整数上溢，整数下溢，格式化字符串，命令注入，缓冲区溢出，另外用 Pulse engine 能分析UAF，double free。  
  
**Signature Program**：Signature Trace 取自 （1）16 个能被污点追踪复现的漏洞以及以前的一些工作。（2）Juliet test suite：包含了很多常见漏洞的小程序，作者使取了 5383 个 Tracer 能分析的漏洞程序。（3）OWASP 中取了 5 个安全编程的例子。  
  
**Benchmark**：选取了 273 个 Debian package（C/C++） 作为基准测试。  
  
**Baseline**：与先进的三类检测工具进行对比（1）clone-based approach（2）learning-based approach（3）pattern-based static analyzer。其中选择了 VUDDY，CCAligner，Devign 和 Github's CodeQL。  
  
**Metrics**：由于不同分析器之间的表现不太一致，比如 CodeQL 只报告 sink point。为了公平比较做了一些考虑。展示 **Root Cases**，以及 **Sink Point**，对于 Tracer 和 CodeQL 比较 true alarm 和 flase alarm，而其他的（VUDDY，CCAligner，Devign）则只记录报告的函数。  
## RQ1：Effectiveness  
  
对于 Debian package 中尚未被发现的漏洞，作者选取了相似度大于 0.85 的 alarm，在 0.85 以下又随机选取了 100 个报告进行分析，最终产生了 424 份报告。作者写这篇论文时，Tracer 找到了 112 个新漏洞，30个漏洞已经被确认，且收获了 6 个 CVEs。而在这 112 个漏洞中，只有 10 个能被 baseline tools （VUDDY 和 Devign）发现。  
（杀人诛心）  
  
表2 是 Tracer 发现的漏洞的一部分。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5SpBeXKN9U8x0wqmNWu2ibIARREmkzYHAwZPp1QAylSJ4z1KpZkfnxUQ/640?wx_fmt=png "")  
  
false alarm 与 true alarm 的曲线，图中的 0.95 0.90 0.85 表示 Tracer 的相似度。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP55M696bFYicrX4bX4kvlNkf3bGDBGujqGgHvSOqvPrt5dDKKhxRjDriag/640?wx_fmt=png "")  
## RQ2：Comparison  
  
基于以下事实进行比较，对于所有工具（Tracer85, VUDDY, CCAligner, and CodeQL）作者都会手动分析 Tracer85 产生的 alarm 数量；收集所有工具的真实报警，包括 Tracer 中相似度小于 0.85 随机采样的真实报警。  
  
最终作者收集到 453 个基本事实与其他 baseline 比较。另外，由于 Devign 不提供合适的报告，作者只判断它能否找到 453 其中的事实。  
  
比较的结果如表3 所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5tmd68njrbOd1SDCCQ8neBEpjFd4FoxuhxwlDnyNGpwNLqCWicgNKpjQ/640?wx_fmt=png "")  
  
与 VUDDY 和 CCAligner 相比（与 clone-based 方法相比）。VUDDYO 使用了原来的数据库，VUDDYS 使用了与 Tracer 相同的数据库。在 VUDDYO 12 个报告中有 7 个误报，其中只有 3 个漏洞，3 个漏洞中有 1 个 Tracer 没有发现（作者解释说是因为没有相对应的 signature），而其他 2 个如图12 所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5HTaKiahOR8ZnaJoiaDe379pFicTszSF3uOJwEzyz6jAzK8IB8VrRVibRWA/640?wx_fmt=png "")  
  
对于这两个相似的漏洞，VUDDYO 根据 LibRaw-demosaic-pack-GPL2, CVE-2017-6889 而 Tracer 根据与发现图1b 中的漏洞的 signature 相似度达到 0.92。更说明了尽管图12 与图1b 中展示的漏洞有着完全不同的语法结构，Tracer 仍能高效发现这样的漏洞。  
  
VUDDYS 只有 10 个误报。以图13 为例，作者认为到 vfprintf 的格式化字符串输入都是合法的。(单看这个图应该看不出来)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5k5cK42r69JhgoSgRvVUL5vsdia47JVFL9h9SqOYGTBRXmLOH1t7szKQ/640?wx_fmt=png "")  
  
CCAligner 发现了 150 个报告但是没有发现漏洞（因为它本来就不是拿来挖洞的），但是对于漏洞挖掘来说，它也存在大量与 VUDDYO 相似的的出现在图13b 中的误报（合法输入）。  
  
与 CodeQL 相比（human-written bug patterns），CodeQL 报告了 3488 个，作者分析了其中 324 个。其中 CodeQL 报告了 453 个事实（前面收集的）中的 161 个真实的报告，而 Tracer85 能发现 253 个。事实上 CodeQL 与 Tracer 相比并不能说明 Tracer 在 signature 匹配上更加好，因为 CodeQL 并没有匹配 signature 而且有着完全不同的架构。这样只说明了 Tracer 与当前比较好的静态分析器相比也能发现比较重要的漏洞。  
  
对比 Devign（learning-based），作者也使用了两种不同的数据集（与 VUDDY 相似）。Devign𝑂 发现的 10 个漏洞中有 8 个能被 Tracer 发现，而 Devign𝑆 同样一无所获。  
## RQ3：Impact of High-level Features  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5AsEicr7vVIWezXtoGzsdqxBM0cuPOts9YI0oxodo6FHSc5JgOzFT12g/640?wx_fmt=png "")  
  
从表4 中可以看出有无 High-Level Features 对精度的影响不大，但是还是有一些提升的。  
## RQ4：Scalability  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tBics1PdpEkeZeVjcA7CniafoYhVMlDdP5YrElpN6ZykjhWlGhKLsg672r2gAXzJeJO9GcvgcpibEqD86nYd1QajQ/640?wx_fmt=png "")  
  
作者主要从程序的规模和运行的时间来描述。静态分析框架分析平均只要 140.42”，相似度计算平均要 2.71“，对于大部分的包都在 20‘ 内完成。一个花了 53‘ 的例外，作者认为是因为函数指针分析不精准导致分析了太多函数。另一个例子是对 gettext 他们只花了 91“ 就能分析完成 982K 行代码。  
# Results  
  
作者开发的 Signature-based Static Analysis 在 273 个 Debian 上发现了 112 个先前未发现的漏洞，其中有 6 个被确认为 CVE。  
# 碎碎念  
  
这是我(RT)读的第三篇论文，文章的内容，可能有地方我的理解不太对，或者部分内容详略不够得当，恳请🙇读者批评指正。  
  
难以置信，“只是” 把运算的操作和 APIs 作为一个向量计算相似度，就能发现如此多的漏洞；另一方面只是计算运用了多少次某种运算（基本操作符与APIs）为什么已经能够表示这一段操作了呢，这不应该有一个时序的关系嘛；现在已经过了一段时间了（相比于那次会议，或者说这篇论文录用的时间），上面的漏洞确认怎么样了还不太清楚；另外这篇文章使用了非常多形式化方法来描述污点追踪等操作，看的太吃力了😭我太菜了。  
  
  
  
