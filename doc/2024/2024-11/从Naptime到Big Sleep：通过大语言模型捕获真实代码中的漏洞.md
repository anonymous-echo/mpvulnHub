#  从Naptime到Big Sleep：通过大语言模型捕获真实代码中的漏洞   
Big Sleep Team  代码卫士   2024-11-04 21:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQfWNv7UvhUh1rINa95jDJDHqIspJh37dQMziaf9Y3RibjLibxdYneyODH2h9ibNFlEHq3JQu8CDlxM0A/640?wx_fmt=gif&from=appmsg "")  
  
**如下是谷歌 Project Zero 发布的一篇文章，详述了 Big Sleep 项目如何发现了传统模糊测试无法发现的0day漏洞，探讨了大语言模型在漏洞研究方面的潜力。**  
  
  
  
**引言**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQfWNv7UvhUh1rINa95jDJDwFkwlkyyK5aB3icjaOvxfpSabk41YV1VVHqVUfQ9S9wR3RS1E8JicrLA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
我们（谷歌Project Zero团队）在之前的一篇文章《Naptime 项目：评估大语言模型的进攻性安全能力》中介绍了大语言模型 (LLMs) 协助下的漏洞研究框架，以及通过改进基于Meta 公司 CyberSecEval2的最新性能，展示了LLMs的潜能。自此，“Naptime”已演进为 “Big Sleep”，后者由谷歌 Project Zero 和谷歌 DeepMind协同开发。  
  
**本文将分享由 Big Sleep 代理发现的首个真实漏洞：**它是位于使用广泛的开源数据库引擎 SQLite 中一个可利用的栈缓冲下溢漏洞。我们在十月初发现了该漏洞并报送给开发人员，后者在收到通知的同一天修复了该漏洞。幸运的是，我们**在官方发布前就发现了该问题，因此 SQLite 用户并未受影响。**  
  
我们认为，这是关于AI代理从广为使用的真实软件中发现此前未知可利用内存安全问题的首个公开案例。Atlanta 团队在今年早些时候举办的 DARPA AIxCC大会上，发现了 SQLite 中的一个空指针解引用漏洞。受此鼓舞，我们将其用于测试中，尝试能否从中找到更为严重的漏洞。  
  
我们认为，这项工作在防御方面潜力巨大。在软件发布前找到漏洞，意味着攻击者匹敌的范围：漏洞会在攻击者有机会发现之前就得到修复。虽然模糊测试已经发挥了重大作用，但我们需要一种能够帮助防御人员找到模糊测试难以（或不可能）找到漏洞的方法，而我们希望AI能够弥补这一差距。我们认为这种方法能够改变既定局面，并成为防御人员的独特优势。  
  
漏洞本身也值得说道。现有的 SQLite 的测试基础设施（通过OSS-Fuzz和该项目自身的基础设施）无法找到该漏洞，因此我们做了进一步的调查。  
  
  
**方法论**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQfWNv7UvhUh1rINa95jDJDwFkwlkyyK5aB3icjaOvxfpSabk41YV1VVHqVUfQ9S9wR3RS1E8JicrLA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
Naptime以及Big Sleep 项目现在的一个关键驱动因素是，持续在野发现此前已发现和已打补丁漏洞变体的利用。这些变体的存在说明，模糊测试无法找到这类变体，而这对于攻击者而言，手动分析这些变体是一种成本效益高的方法。  
  
同时，我们认为这种变体分析任务分析要比更通用的开放式漏洞研究问题更匹配适用当前的大语言模型。通过提供切入点——如此前已修复漏洞的详情——我们剔除了漏洞研究中的很多歧义，我们从具体的、有事实依据的理论出发：这是一个此前出现过的漏洞；别的地方很可能还有类似漏洞。  
  
当前，我们的项目仍在研究阶段，目前正在通过含有已知漏洞的小项目来评估进展。最近，我们决定通过在 SQLite 上运行首个大规模的真实变体分析实验，测试模型和工具集。我们收集了 SQLite 仓库近期的很多提交，手动删除了微小的以及单纯的文档变更。之后，调整了提示符 (prompt)，为代理提供了提交信息以及代码变更，并要求该代理审计当前仓库（HEAD未知）中是否存在仍未被修复的相关问题。  
  
  
**发现的漏洞**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQfWNv7UvhUh1rINa95jDJDwFkwlkyyK5aB3icjaOvxfpSabk41YV1VVHqVUfQ9S9wR3RS1E8JicrLA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
该漏洞很有意思，在通常是索引类型的字段 iColumn 中使用了一个特殊的哨兵值 -1：  
```
7476:   struct sqlite3_index_constraint {
7477:      int iColumn;              /* Column constrained.  -1 for ROWID */
7478:      unsigned char op;         /* Constraint operator */
7479:      unsigned char usable;     /* True if this constraint is usable */
7480:      int iTermOffset;          /* Used internally - xBestIndex should ignore */
7481:   } *aConstraint;            /* Table of WHERE clause constraints */
```  
  
这一模式制造了一种可能的边缘性案例，所有使用该字段的代码都需要处理这种情况，因为有效的列索引值应该是非负的。  
  
函数seriesBestIndex 未能正确处理这一边缘性案例，导致在处理 rowed 列约束的一个查询时，在栈缓冲区中写入一个值为负数的索引。在向代理提供的构建中，启用了调试断言，而这一条件由第706行的断言进行检查。  
```
619 static int seriesBestIndex(
620   sqlite3_vtab *pVTab,
621   sqlite3_index_info *pIdxInfo
622 ){
...
630   int aIdx[7];           /* Constraints on start, stop, step, LIMIT, OFFSET,
631                          ** and value.  aIdx[5] covers value=, value>=, and
632                          ** value>,  aIdx[6] covers value<= and value< */
633   const struct sqlite3_index_constraint *pConstraint;
...
642   for(i=0; i<pIdxInfo->nConstraint; i++, pConstraint++){
643     int iCol;    /* 0 for start, 1 for stop, 2 for step */
644     int iMask;   /* bitmask for those column */
645     int op = pConstraint->op;
...
705     iCol = pConstraint->iColumn - SERIES_COLUMN_START;
706     assert( iCol>=0 && iCol<=2 );
707     iMask = 1 << iCol;
...
713     if( pConstraint->usable==0 ){
714       unusableMask |=  iMask;
715       continue;
716     }else if( op==SQLITE_INDEX_CONSTRAINT_EQ ){
717       idxNum |= iMask;
718       aIdx[iCol] = i;
719     }
720   }
```  
  
然而，在发布构建中并未出现这一断言，而在我们的测试（根据编译器和优化级别的不同而不同）中，第718行随后的写将会写在 aIdx 缓冲区之外，损坏了pConstraint 指针的最低有效32位，而该指针将会在该循环的下一次迭代中被解引用，从而导致可能的可利用条件。  
  
然而，鉴于对该漏洞的解释，人类研究员难以精确了解如何触发该漏洞，显然设置 ROWID 列的约束可以作为一个不错的切入点，不过还需要对该代码进行更详细的阅读。该代理对SQLite的了解似乎已经比我们多得多，这么看它能够走一些捷径！  
  
一个常见场景是该模型会立即使用虚拟表 generate_series，生成测试案例时。（我们还看到在一些案例中，模型首先研究可用虚拟表，但显然它能够应用已有知识）。  
  
  
**执行过程中的重点**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQfWNv7UvhUh1rINa95jDJDwFkwlkyyK5aB3icjaOvxfpSabk41YV1VVHqVUfQ9S9wR3RS1E8JicrLA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
在这个基于 Gemini 1.5 Pro 的成功运行中，种子提交是 [1976c3f7]，它是一个相当大的且不明显的变更。代理所发现的漏洞与种子提交中的变更之间关联并不紧密——在手动变体分析中这一情况并不少见，了解代码库中的一个 bug 通常会让研究员发现其它问题。  
  
重点内容如下，我们的评论用斜体表示——**ASSISTANT**块中的所有文本都直接源自该代理。  
  
该代理生成了对差异中变更的合理评估，并借此形成研究的切入点：  
  
**ASSISTANT**  
```
CL 通过 termFromWhereClause 函数，改进了对虚拟表查询中 OR 分支之间共享的 WHERE 条件。该函数在考虑嵌套字句的情况，从 WhereClause检索特定的条件。在此变更之前，因条件索引映射的不正确，常见条件可能并未得到正确处理，有可能导致效率低下的查询规划或不正确的结果。最可能的漏洞涉及 allocateIndexInfo 和 whereLoopAddVirtualOne 函数中对 WHERE 子句约束的处理不正确，其中CL修改了如何使用新的辅助函数处理约束偏移量。
我将首先检查 allocateIndexInfo 函数。
……
```  
  
经过探索相关代码的多个（省略）步骤，该代理形成了更加具体的假设并尝试通过运行源自补丁的已修改测试案例版本进行检查，但由于该测试案例依赖于配置中不可用的一个扩展，因此这样做并不奏效。  
```
T00L (debugger_run)
该程序并未崩溃或到达断点。退出代码是1。
STDERR 的输出是：
第2行附近出现运行时错误：没有此模块：tcl
第3行附近出现解析错误：没有此表：x1
```  
  
**ASSISTANT**  
```
程序终止，因为TCL模块不可用。这些测试依赖于 TCL 虚拟表模块，需要在编译 SQLite 时启动。所提供的程序输入基于 bestindexC.test 文件，它通过 TCL 模块测试虚拟表的最佳索引选择。
为修复这一问题，该程序输入需要使用一个不同的无需要求TCL模块的虚拟表。不过，该漏洞与虚拟表查询规划有关，因此我们仍然需要一个虚拟表才能触发该问题。
我将使用 code_browser_source 工具来查找 SQLite 中的内置虚拟表案例。之后，我将调整输入，使用其中一个虚拟表，并在 whereLoopAddVirtualOne 中重新设立一个断点。
……
```  
  
该代理很好地解决了这一问题，识别出修复该测试案例所需的步骤，在后续几个步骤中检索到构建可触及 whereLoopAddVirtual0ne 测试案例所需的所有信息。  
  
**ASSISTANT**  
```
Sqlite3_create_module 函数注册了虚拟表模块。Shell.c 文件包含多个此类实例，包括 generate_series、fsdir、completion和 expert模块。Json 表也值得关注。现在我将把 generate_series 作为起始点。我将尝试构造使用该模块的查询，并可能触发不正确的约束处理。
……
```  
  
注意上述在最初发现并复现该漏洞的过程中，该代理对于它尝试触发的“不正确的约束处理”的描述非常模糊；在本案例中，完整的过程读起来有点像人类研究员的思维过程——从一个想法开始，在调查过程中产生了其它一些想法，最后生成复现稍有不同bug的测试案例。在本案例中，当 generate_series 表调用 whereLoopAddVirtualOne 时，我们最终落在约束确实被错误处理的 seriesBestIndex 上。  
  
然而，尤其值得关注的是，一旦该程序崩溃，该模型就会在解释方面做得更好——在生成根因分析和完整的崩溃报告的同时，我们看到该代理清楚地构造了触发该特定的、已识别出的边缘性案例的测试案例：  
  
**ASSISTANT**  
```
相关的字段是 sqlite3_index_constaint 结构中的 iColumn。该字段表示的是该约束的列编号。要使该断言失败，我们需要对索引大于3或小于-1的列设置约束。
让我们构造一个涉及这些列约束的 SQL 查询。Generate_series 表拥有的列是：value、start、step 和 stop。这些索引是：
—value:0
-start: 1
-step: 2
-stop: 3
要触发该漏洞，我们可以对 ROWID 施加一个约束，并对ROWID 的约束使用 iColumn = -1。
查询示例如下：
SELECT * FROM generate_series(1,10,1) WHERE ROWID = 1;
该查询应当会在 seriesBestIndex 函数中引发崩溃。
……
```  
  
我们最终获得几乎可以直接报送的一个清晰准确的问题概述！  
```
TOOL(debugger_run)
程序崩溃：SIGBRT at:0.
STDERR上的输出是：
sqlite3: src/shell.c:6816: int seriesBestIndex(sqlite3_vtab *, sqlite3_index_info *): Assertion `iCol>=0 &&  iCol<=2' failed.
```  
  
**ASSISTANT**(report_success)  
```
程序在执行 SELECT * FROM generate_series(1,10,1) WHERE ROWID = 1;时，由于函数 seriesBestIndex 中的断言失败而崩溃。
断言 assert(iCol>=0 && iCol<=2) 失败，是因为 sqlite3_index_info 结构体中的字段 iColumn 中可包含超出列索引有效范围的值，如在约束涉及 ROWID 时为 -1。
这就导致 iCol 被计算为-2，导致断言失败。
```  
  
  
**模糊测试的效果如何？**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQfWNv7UvhUh1rINa95jDJDwFkwlkyyK5aB3icjaOvxfpSabk41YV1VVHqVUfQ9S9wR3RS1E8JicrLA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
鉴于该复现案例简单，一个显而易见的问题是：为什么传统的模糊测试没有更早地发现这个漏洞？“简单的”答案是在于模糊测试 harness 的配置。OSS-Fuzz 使用的 harness 并非在启用 generate_series 扩展时构建，而其替代 fuzzingshell.c harness 中包含不受该漏洞影响的 seriesBestIndex 函数的更老旧版本。尽管 SQLite AFL 仓库中包含一个配置，用于模糊测试我们向 Big Sleep 代理提供的同样的 CLI 二进制，但它似乎并未得到广泛使用。  
  
为了了解该 bug 是否真的“显而易见”，我们尝试重新通过模糊测试进行发现。我们按照 SQLite 文档中的模糊测试指令并使用了 CLI 目标。我们还验证了在启动 AFL 运行前，该模糊测试语料中包含所要求的 generate_series 和 rowed 关键字。然而，经过150个 CPU 小时的模糊测试后，这个漏洞仍未被发现。  
  
之后，我们尝试简化模糊测试任务。例如，向 AFL 的 SQL 字典中增加必要的关键字等。然而，似乎只有当语料中包含与该崩溃输入非常接近的一个示例时，该漏洞才会被快速发现，因为代码覆盖率似乎并非这一特定问题的可靠指标。  
  
确实，AFL并非文本格式如 SQL 的最适合工具。在这些格式中，多数输入在句法上是无效的，会遭解析器拒绝。尽管如此，将其与 Michal Zalewski 在2015年写的一篇关于对SQLite 进行模糊测试的文章进行比较，结果值得思考。当时，AFL在发现 SQLite 漏洞方面非常有效；经过多年的模糊测试，该工具似乎达到了一个自然饱和点。虽然截止目前我们的结果与AFL发布在效率方面带来的巨大变化相比微不足道，但它具有自身的优势，可能在发现独特漏洞方面效率较高。  
  
  
**结论**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQfWNv7UvhUh1rINa95jDJDwFkwlkyyK5aB3icjaOvxfpSabk41YV1VVHqVUfQ9S9wR3RS1E8JicrLA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
对于团队而言，这是验证并获得成功的时刻——在广为使用且充分模糊测试的开源项目中找到漏洞，令人兴奋！提供正确的工具，就能让当前的大语言模型开展漏洞研究工作。  
  
然而，我们想再次强调，这是实验性高的结果。Big Sleep 团队认为，目前，特定目标的模糊测试工具在发现漏洞方面的效率至少与该代理一样甚至更高。  
  
我们希望，未来这一成果将为防御人员形成重大优势，不仅能够发现崩溃测试案例，而且还能提供高质量的根因分析报告，分类和修复漏洞可以在未来能够更加便宜且有效。我们将继续分享在该领域的研究成果，尽力缩小公开的最先进的和非公开的最先进技术之间的差距。  
  
Big Sleep 团队将继续深耕，助力 Project Zero 团队，实现让0day更难的目标。  
  
Big Sleep 项目团队人员包括：Miltos Allamanis、Martin Arjovsky、Charles Blundell、Lars Buesing、Mark Brand、Sergei Glazunov、Dominik Maier、Petros Maniatis、Guilherme Marinho、Henryk Michalewski、Koushik Sen、Charles Sutton、Vaibhav Tulsyan、Marco Vanotti、Theophane Weber和Dan Zheng。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[普遍存在的LLM幻觉扩大了软件开发的攻击面](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519204&idx=1&sn=8b889973e145d7b438fdc2609171340f&chksm=ea94ba8edde33398d0452d0d8ca3dd715d06faf2ddf0b63ef13a536f320298022b695c36082c&scene=21#wechat_redirect)  
  
  
[挖出被暴露的1500+APT令牌，破解近千家公司的LLM仓库](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518271&idx=2&sn=498e1dc2bb31e36ddbfa4c69c7593122&chksm=ea94b955dde330430a08be2022b6435807998814fbf53040e98c291ad0ffced72b267796d3b1&scene=21#wechat_redirect)  
  
  
[研究员在开源AI和ML模型中发现30多个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521331&idx=1&sn=e13cd9f9dccd9d17953e551df9108205&chksm=ea94a559dde32c4f32a18c5ad4c3a2fc98f17fb29f69f73cac5c613c67ae28f36ab473d14936&scene=21#wechat_redirect)  
  
  
[ShadowLogic 技术利用AI模型图创建无代码后门，可引发供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521075&idx=2&sn=78b278425ea0267c473467bfb24894f2&chksm=ea94a259dde32b4f211fb59ae290ca1daab65c90d84350afe2de36239f2907afe0466021e549&scene=21#wechat_redirect)  
  
  
[超过三分之一的员工与AI共享工作机密](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520981&idx=1&sn=7350d1b84ce9746dae06aafc5e55e76a&chksm=ea94a3bfdde32aa9a656ece3d6e12959f385a712e4b31e2e665d89a77c0b95cb2e742dbe0d91&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://googleprojectzero.blogspot.com/2024/10/from-naptime-to-big-sleep.html  
  
  
  
题图：  
Pixabay  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
