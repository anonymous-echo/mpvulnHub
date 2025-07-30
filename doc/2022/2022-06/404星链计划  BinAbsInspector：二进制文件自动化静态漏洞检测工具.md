#  404星链计划 | BinAbsInspector：二进制文件自动化静态漏洞检测工具   
 知道创宇404实验室   2022-06-22 17:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT09IJjs3wGQbICd50va8zMqfnXZfD5LGdibcuOrtia3P4DpMAVfibZ8J4MsbHt0JW20QL8Wh0SO8zpyA/640?wx_fmt=gif "")  
  
前几天404星链计划发布了新收录的项目：**404星链计划新项目发布，速来升级装备，一秒回血**  
。今天介绍的是项目  
**BinAbsInspector，一款开源的二进制文件静态漏洞分析工具**。  
  
  
另外欢迎加入404星链计划社群，请在文末识别运营同学二维码，添加时备注“星链计划”。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3k9IT3oQhT0eKmyEA37bX2TnKs3dVJ7fmhvKEEAriccW2gf2qGibibBEnib0bruYaOSqcOftOmbIz1olianiazIKycWg/640?wx_fmt=png "")  
  
  
**项目名称：BinAbsInspector**  
  
**项目作者：KeenSecurityLab**  
  
**项目地址：**  
  
**https://github.com/KeenSecurityLab/BinAbsInspector**  
  
  
  
  
  
**背景**  
  
**软件漏洞检测“两板斧****”**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/zZKnUibvoer89jLgDZTenc5rADESgLYaia6ycDicHIEqzzdyFSFypdYH0FrteXRoevKvJI3EbHZXPMfGpsZOccONQ/640?wx_fmt=gif "")  
  
  
  
随着信息产业的发展，网络安全问题日益严峻，软件漏洞对于互联网威胁极大，是网络安全中的核心问题。为了缓解漏洞所造成的危害，需要对软件进行安全检测，尽可能地发现并消除潜在漏洞。目前常见的自动化漏洞检测手段可以分为两类：  
动态分析测试  
和  
静态分析  
。  
  
  
动态分析测试方法（如fuzzing等）在过去五年里吸引了研究者的广泛关注，相关系统在工业界中已经得到了大规模的部署和应用。相比于动态方法，静态分析通常能够得到更为全面可靠的程序状态，可以从根源上有效地克服动态分析的覆盖率问题；然而在现实中静态分析如何兼顾平衡精度和复杂度在学术界和工业界仍是一大难题，在产品中也多依赖人工经验规则进行补充，这导致其在现实场景中的落地不尽如人意。  
  
  
**静态分析工具现状**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/zZKnUibvoer89jLgDZTenc5rADESgLYaia6ycDicHIEqzzdyFSFypdYH0FrteXRoevKvJI3EbHZXPMfGpsZOccONQ/640?wx_fmt=gif "")  
  
  
  
目前国际上较为成功的商业化分析工具有Coverity[1]、CodeSonar[2]、VeraCode[3]等，它们在代码质量保障上发挥了重要作用，相关产品也在Google等公司的DevOps流程中得到了广泛部署和使用。  
  
  
包括开源及商业化产品在内，现有的静态分析方案多为源码级分析。面向源代码进行扫描，尽管可以在一定程度上满足软件安全需要，然而在真实安全场景中，待分析对象多为二进制文件，如嵌入式系统固件，商业软件等，研究人员难以获得相应的源代码，此时源码级静态分析方案不再适用。  
  
  
值得一提的是，部分商业化产品（如CodeSonar等）也提供了对于二进制文件的分析能力，然而商业化路线所带来的封闭性，在很大程度上限制了普通研究者的使用和二次开发。与此同时，在开源社区中也涌现出一批知名的二进制分析工具，如angr[4]、BAP[5]、cwe_checker[6]。其中，angr和BAP逐渐往通用分析框架发展，并非专注于二进制漏洞扫描，因此其内部的分析算法较为庞杂，不利于进一步扩展和优化；cwe_checker的定位相对清晰，专注于安全漏洞扫描，但其精度和效率却不甚理想。目前业界亟需一种更为先进的二进制漏洞扫描工具，在开源的大前提下，其性能和可扩展性也要满足真实场景的需要。为此，科恩实验室基于自身在二进制领域丰富的研究与实践经验，同时结合业内相关优秀工具的设计理念，最终孵化出性能出色且自主可控的二进制漏洞静态扫描工具——BinAbsInspector。  
  
  
**原理与实现**  
  
BinAbsInspector的设计思想来源于上世纪70年代诞生的经典程序分析理论“抽象解释”；在具体实现上，BinAbsInspector的分析基于Ghidra[7]所提供的中间表示Pcode上。通过设计合适的抽象域，实现其上的多种运算，完成相关Pcode的操作语义，执行流敏感（flow-sensitive）和上下文敏感（context-sensitive）的过程间分析，同时加入静态污点分析的能力，完成对程序运行时状态的抽象估计，最后基于上述分析所得的抽象数据流信息对多种漏洞类型进行建模检查，实现对二进制漏洞的静态扫描。  
  
  
关于如何对程序运行时状态进行抽象这一关键问题，我们主要参考了经典论文《WYSINWYX: What you see is not what you eXecute》[8]中的做法并加以改良、简化和提升。  
  
  
具体来说，在BinAbsInspector中整个运行时环境被分为Local （抽象栈）、Heap（抽象堆）、Global（全局变量和数值）、Unique（对应Ghidra中产生的临时变量区）和Register（寄存器区）五种region。在这些不同的抽象区域上加上偏移数值offset，便可以组成一个抽象变量ALoc（Abstract Location/Variable）。因为在二进制程序中，变量并非全部显式表示，ALoc便是对实际程序中变量的一种估算和识别。  
对应不同的程序点，需要记录此处可能存活的抽象变量和其对应的抽象值，称之为AbsEnv（Abstract Environment）。  
  
  
因为是静态的抽象，那么对于一个程序点的一个抽象变量，它可能会包含多个抽象值，这些抽象值组成了一个集合。虽然这个集合可能会包含无穷多个元素，但是为了保证整个计算过程实践上可收敛，令此集合取一个上限K，这种集合称之为KSet。一旦其中包含的元素超过K，便将其变为一个Top，即包含所有抽象值。此方法与前人重要相关工作Jakstab[9]中的KSet较为相似。KSet支持多种算数和逻辑运算。此外每一个KSet对象也会包含一个污点的位图，用来跟踪多个污点的同时传播，从而实现静态污点分析。这样AbsEnv便可以认为是一个从ALoc到KSet的map。  
  
  
由于BinAbsInspector的分析是上下文敏感的，对于被调用者的上下文 （Context），我们使用最近的call string（call site）来进行唯一标识。即对于同一个被调用者，不同的调用者会生成不同的Context，一般只记录最近的几个调用者。这样我们便把程序点处的AbsEnv记录在不同的Context中。  
  
  
除此，对于过程内的不动点计算BinAbsInspector里使用了worklist算法，即把待处理的程序点不断地放入worklist中，直到其空为止。过程间分析主要在于不同的Context之间的转变，这是通过call/return指令的语义实现的。这样通过对整个程序指令的迭代计算值并加以Context的转换，Context及其附属的worklist得到逐一处理，直到所有的worklist计算结束，最后达到不动点。  
  
  
通过这整个的计算过程，便会得到所有可能的Context以及对应的每个程序点的AbsEnv。这样相当于得到了一个对程序行为可靠的估算，有了这些抽象数据流的信息，我们便可以进行内存破坏漏洞、命令注入漏洞等多种漏洞的检测了。  
  
  
**实例演示**  
  
下面我们通过一个包含  
Use-After-Free漏洞  
的简单样例来演示BinAbsInepector的运行情况和基本原理。  
  
**漏洞原理**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/zZKnUibvoer89jLgDZTenc5rADESgLYaia6ycDicHIEqzzdyFSFypdYH0FrteXRoevKvJI3EbHZXPMfGpsZOccONQ/640?wx_fmt=gif "")  
  
  
  
“CWE416_Use_After_Free__malloc_free_struct_01_bad”函数中首先调用“malloc”函数分配内存用于存放100个“twoIntsStruct”对象—>依次对这部分对象进行初始化操作—>直接释放内存—>释放内存过后再次调用了“printStructLine”函数访问已释放内存中的地址—>造成Use-After-Free漏洞。  
```
void CWE416_Use_After_Free__malloc_free_struct_01_bad()
{
    twoIntsStruct * data;
/* Initialize data */
    data = NULL;
    data = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
if (data == NULL) {exit(-1);}
    {
size_t i;
for(i = 0; i < 100; i++)
        {
            data[i].intOne = 1;
            data[i].intTwo = 2;
        }
    }
/* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
free(data);
/* POTENTIAL FLAW: Use of data that may have been freed */
    printStructLine(&data[0]);
/* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

int main(int argc, char * argv[])
{
/* seed randomness */
    srand( (unsigned)time(NULL) );
    printLine("Calling bad()...");
    CWE416_Use_After_Free__malloc_free_struct_01_bad();
    printLine("Finished bad()");
return 0;
}
```  
  
  
**安装及导入**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/zZKnUibvoer89jLgDZTenc5rADESgLYaia6ycDicHIEqzzdyFSFypdYH0FrteXRoevKvJI3EbHZXPMfGpsZOccONQ/640?wx_fmt=gif "")  
  
  
  
BinAbsInspector作为Ghidra Extension的形式进行开发，构建后安装在Ghidra中，支持GUI和Headless模式运行，用户也可以通过项目中提供的Dockerfile构建docker镜像体验功能，具体使用方法见【仓库README】：https://github.com/KeenSecurityLab/BinAbsInspector。在此我们以  
GUI模式  
为例介绍使用步骤。  
  
  
首先将BinAbsInspector安装在Ghidra，我们将编译好的样本程序（armv7）导入Ghidra，待Ghidra的分析完成，便可以运行我们的分析了。这时会弹出工具的分析选项框，将分析过程的配置参数暂时保持默认即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoericaePKHOqEd6jSkoIlbgkRfmVRYubn0jIUj4FxTPPPxn27XLiaIs9JXm5ibQImsZXlt6rYsVRohCZ0Q/640?wx_fmt=png "")  
  
    
     图1-工具分析选项框  
  
  
**结果展示**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/zZKnUibvoer89jLgDZTenc5rADESgLYaia6ycDicHIEqzzdyFSFypdYH0FrteXRoevKvJI3EbHZXPMfGpsZOccONQ/640?wx_fmt=gif "")  
  
  
  
分析显示找到2处CWE告警，在下方命令行中会显示具体告警的地址。  
  
**标记1**  
：触发告警的地址，即产生Use-After-Free访问的指令地址；  
  
**标记2**  
：上下文调用记录，可以理解为函数的调用栈；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoericaePKHOqEd6jSkoIlbgkRfz9xBdmkt8qGxx61gRkjStzgAVIFapoBbzrUKDz2YLyJ98T22sMH6Nw/640?wx_fmt=png "")  
  
图2-1 分析结果展现  
  
                                                   
                                                                   
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoericaePKHOqEd6jSkoIlbgkRfGI2rV7YZ7KyZjIWTwibGFZTQzyUXMZZ2b6RIictPQeIetvGdJK7NortA/640?wx_fmt=png "")  
  
图2-2 分析结果展现细节图  
  
  
  
**分析溯源**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/zZKnUibvoer89jLgDZTenc5rADESgLYaia6ycDicHIEqzzdyFSFypdYH0FrteXRoevKvJI3EbHZXPMfGpsZOccONQ/640?wx_fmt=gif "")  
  
  
  
双击命令行中的告警地址可以在汇编窗口跳转到对应的指令，另外右边的反编译窗口也将同步展示对应的伪代码，可以看到两条告警的指令都位于“printStructLine” 函数的内部，都是访问已释放内存的LDR指令，结果符合预期。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoericaePKHOqEd6jSkoIlbgkRfjqJfkTOb3S5CyNe0cDl4Tfq0NRYvC2CJNl1q5MVzMmktslXhP7qJoQ/640?wx_fmt=png "")  
  
 图3-1 分析溯源反汇编框  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoericaePKHOqEd6jSkoIlbgkRfuHCpzBeqrzPOmkE70iborppqkO4e61LAOr26zEu5ZAXh5nRZmTeCU0Q/640?wx_fmt=png "")  
  
 图3-2 分析溯源反编译框  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoericaePKHOqEd6jSkoIlbgkRfOeNgIiaesHFYTjO4JibUerjn8T6oEPrtpqquFMSiaXNHV5hmGlHDeeZjg/640?wx_fmt=png "")  
  
 图3-3 分析溯源报告框  
  
  
原理上简而言之，在第6行“malloc”处创建了一个Heap region，data的抽象值为此Heap及偏移值0，这一信息被加入当前的AbsEnv中并继续向后传播，经过第17行的“free”，data的抽象值数值保持不变，其中的Heap region变成了一个相同数值但是为无效状态的新region，当前的AbsEnv也会同步更新这一变化并将这一改动向后传播，最后在19行“printStructLine”内部的LDR指令时，通过查询传播到此的AbsEnv，检测到data指向的是一个无效的Heap region，这样便可以查找出这个Use-After-Free的问题。  
  
  
**性能评估**  
  
我们选取Juliet[10]这一较为权威的测试集，在x86、x64、armv7三个架构上进行测试，并与cwe_checker测试结果进行对照比较。另外，BinAbsInspector也支持对aarch64架构样本的检测，这是cwe_checker目前不支持的。  
  
  
下面表格展示的是在CWE415 (Double-Free)， CWE416 (Use-After-Free)，CWE476 (Null Poionter Deference), CWE78 (Command Injection) 4种核心漏洞检测能力与cwe_checker的对比结果。  
  
结果表明，BinAbsInspector的测试结果在所支持的CWE类型上均取得较大幅度优势。  
  
  
(BAI: BinAbsInspector, CC: cwe_checker, TP: True Positive正阳性, FP: False Positive假阳性, TN: True Negative正阴性, FN: False Negative假阴性)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoer89jLgDZTenc5rADESgLYaiaq28R5xuM2FA1jbQYOL1ibw5GiadYEJrEZhPXT3wBnxpBEypL7dkibFEZw/640?wx_fmt=png "")  
  
     
     图4-x86下-核心检测能力数据对比  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoer89jLgDZTenc5rADESgLYaiayRdsmyIDSMM84PEJa49LepeMuZFNoqia56BFCibh4DZ56XDW6AgW5vjQ/640?wx_fmt=png "")  
  
图5-x64下-核心检测能力数据对比  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoer89jLgDZTenc5rADESgLYaiaDQjg6DiaQHuylFEPwCZDDHru2ecBTUdwCLBYAjicKapSeQMPRsXZpPicw/640?wx_fmt=png "")  
  
图6-armv7下-核心检测能力数据对比  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoericaePKHOqEd6jSkoIlbgkRfUaallGaDt5Qh3cHE7z50ZNMlekE74mfCIAiauibgKAee6JKCwDt0XhQQ/640?wx_fmt=png "")  
  
图7-三种架构下核心漏洞检测误报率对比  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zZKnUibvoer89jLgDZTenc5rADESgLYaiaYUyy4LS3y1iaSqmibOhoHEVHOiaFkKZibBu2sDogKP4zkibIwVB3qSrqS9Q/640?wx_fmt=png "")  
  
图8- 三种架构下核心漏洞检测漏报率对比  
  
  
**总结**  
  
****  
**迄今成果**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/zZKnUibvoer89jLgDZTenc5rADESgLYaia6ycDicHIEqzzdyFSFypdYH0FrteXRoevKvJI3EbHZXPMfGpsZOccONQ/640?wx_fmt=gif "")  
  
  
  
科恩在二进制安全研究领域有着深厚积累，其中二进制软件成分分析平台[BinaryAI[11]](http://mp.weixin.qq.com/s?__biz=MzU1MjgwNzc4Ng==&mid=2247496102&idx=1&sn=7835a7682a921a324d1a1e65a23a9c2d&chksm=fbfecda3cc8944b5a620e57ab9b32272f629bd31c3ecdf56ecbdc66e52ae39eb537dd49182c1&scene=21#wechat_redirect)  
已免费开放，推动软件成分分析在DevSecOps、安全研究等场景的应用与发展。在二进制静态分析方向，科恩孵化高效、准确的自动化二进制文件静态漏洞分析工具BinAbsInspector。经过内部应用实践及优化，BinAbsInspector已达到了较好的完成度。  
  
  
**步履不停**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/zZKnUibvoer89jLgDZTenc5rADESgLYaia6ycDicHIEqzzdyFSFypdYH0FrteXRoevKvJI3EbHZXPMfGpsZOccONQ/640?wx_fmt=gif "")  
  
  
  
BinAbsInspector未来将持续打磨算法及工程上的可提高之处，结合科恩二进制分析、算法等能力输出，赋能更多软件相关从业者，助力提升整体代码安全防治效率。关于更多的技术细节和代码实现，请移步我们的开源仓库及wiki文档，点击文末  
“阅读原文”即可跳转。欢迎所有感兴趣的小伙伴一起参与协同开发，在实践中迭代优化，打造更优秀的二进制漏洞静态分析利器。  
  
  
**文献参考**  
  
[1]  
https://www.synopsys.com/software-integrity/security-testing/static-analysis-sast.html  
  
[2]  
https://www.grammatech.com/products/source-code-analysis  
  
[3]  
https://www.veracode.com/  
  
[4]  
https://angr.io/  
  
[5]  
https://github.com/BinaryAnalysisPlatform/bap/  
  
[6]  
https://github.com/fkie-cad/cwe_checker/  
  
[7]  
 https://ghidra-sre.org/  
  
[8]  
https://dl.acm.org/doi/pdf/10.1145/1749608.1749612  
  
[9]  
http://www.jakstab.org/  
  
[10]  
https://samate.nist.gov/SRD/testsuite.php  
  
[11]  
https://www.binaryai.net/  
  
**欢迎加入星链计划社群，入群请添加下方运营同学微信，添加时请备注“星链计划”。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT2NAZUwSWczFcDkibjIKD9udCavb6GxNkaRbxCpdxRglHic78lZq1HhqdhJQ0UfW1W1wVTDJWY2dQsQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT0Z79Hq9GCticVica4ufkjk5xiarRicG97E3oEcibNSrgdGSsdicWibkc8ycazhQiaA81j3o0cvzR5x4kRIcQ/640?wx_fmt=gif "")  
  
**往 期 热 门**  
  
(点击图片跳转）  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650961752&idx=1&sn=13c769c2073ed4f3897d561d77ef59ae&chksm=8079356ab70ebc7c02a0c1614ea6a2774faf9494020d344313f29dace24bb765a8607440fde2&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650955351&idx=1&sn=9c681e4ce970772e7d62e749ddad3a7b&chksm=80791c65b70e9573af8d78902010c3d50b3b01daa808a6f0cc715027abc0dcbf6de1f7a33aa0&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650955304&idx=1&sn=4c5675e9f90f1030c38b1fc251e4ec65&chksm=80791c1ab70e950c677c84ea5b2b47e5fb59d1c54880cebe14609b60d553498c8c37ae45128f&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3k9IT3oQhT2lPCugsWDQaQ4y4TicQ2PYkP1ic0pfWibibFsiavzULenib1K6qzR4URa5P0nAI4AQ8tLKZVmtibYvjWpIg/640?wx_fmt=jpeg "")  
  
