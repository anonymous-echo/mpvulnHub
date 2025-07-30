#  韩国科学技术院 | 探索基于LLM的Bug复现   
zhanS  拨开云雾   2023-09-22 17:23  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1rCBKs5fu1myCIC2xmpAtzaA5RWaH63ZGmrreur8o5BCcuyb1RJpibfw/640?wx_fmt=png "")  
  
转载一篇我发表在安全学术圈的论文阅读笔记。  
  
再续一篇基于LLM的程序bug分析论文，来自**IEEE/ACM ICSE' 23**，题目为"  
Large Language Models are Few-shot Testers: Exploring LLM-based General Bug Reproduction"。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1lbKE8DFCetGCicHMwBKBician7WNfFZSLxyIKXjB9cZNsFcW4VLJIaq6A/640?wx_fmt=png "")  
  
**一、 引言**  
  
为了促进完全自动化，大多数现有的测试生成技术旨在增加覆盖率，或者生成探索性输入。然而，这些技术在很大程度上无法实现更多的语义目标，例如：生成测试来复现给定的错误报告。尽管如此，复现bug仍然很重要。作者的实证研究表明，由于提交的issues而在开源存储库中添加的测试数量大约是相应项目测试套件大小的28%。同时，由于将错误报告中的预期程序语义转换成测试预言是困难的，现有的bug复现技术倾向于专门处理程序崩溃，这是所有错误报告的一个小子集。为了从一般的bug报告中自动生成测试，本文提出了LIBRO，一个基于大型语言模型的框架。  
  
软件测试是通过对被测软件执行测试来确认软件满足规范标准的实践（software under test，SUT），关乎软件项目的重要性和安全性，软件测试是软件开发过程中最重要的实践之一。尽管如此，人们普遍认为软件测试是乏味的，因为需要大量的人力资源[1]。为了填补这一空白，自动化测试生成技术被提出，相应地衍生出一些列基于隐式预言（回归或崩溃检测）来指导自动化过程的工具。当添加新特性时，它们是有用的，因为它们可以为一个焦点类（focal class）生成高覆盖率的新测试。然而，并不是所有的测试都和它们的焦点类一起被立即添加。事实上，大量的测试源于bug报告。也就是说，创建这些测试是为了防止将来对所报告的错误的回归（这个回归是啥意思？）。这表明从bug报告中生成bug复现测试是一种被低估但有效的为开发人员自动编写测试的方式。  
  
一般的report-to-test问题对于软件工程社区来说是非常重要的，因为解决这个问题将允许开发人员使用大量的自动化调试技术，配备复现所报告的错误的测试用例。Koyuncu等人[2]注意到，在广泛使用的Defects4J bug基准测试中，在96%的情况下，bug揭示（bug-revealing）测试在bug报告提交之前并不存在。因此，当第一次报告错误时，可能很难利用最先进的自动化调试技术，因为它们依赖于bug复现测试。  
  
在本文中，作者尝试使用大型语言模型来生成测试，提出一个名为LIBRO的框架，基于OpenAI LLM。  
  
**二、 动机**  
  
report-to-test问题的重要性取决于两个观察结果：  
- **观测一：当缺陷报告归档时，暴露缺陷的测试很少可用**，并不像自动化调试技术经常假设的那样。根据Koyuncu等人[2]的论文，在他们分析的95%的情况下，基于频谱的bug定位技术并不能在报告时定位缺陷，因此他们提出了一种完全静态的自动调试技术。然而，正如Le等人[5]所证明的，使用动态信息通常会导致更精确的定位结果。因此，report-to-test技术可以增强大部分自动化调试模型的实用性和性能。  
  
- **观测二：report-to-test问题可能没有得到充分的重视，但仍然是测试中重要的和反复出现的部分**。现有的开发人员调查显示，**开发人员认为从bug报告中生成测试是改进自动化测试的一种方式**。Daka和Fraser[6]调查了225名软件开发人员，并指出自动化测试生成可以帮助开发人员的方式，其中三个（决定测试什么，现实性，决定检查什么）可以通过使用bug报告来解决，因为bug报告复现是一个相对定义良好的活动。Kochhar等人[7]明确询问数百名开发人员是否同意“在维护期间，当一个bug被修复时，添加一个覆盖它的测试用例是好的”这一说法，结果是：在李克特量表（Likert scale）5分的基础上，平均得分为4.4分。  
  
为了进一步验证开发人员定期处理report-to-test问题，作者通过挖掘数百个开源Java存储库，分析了可归因于错误报告的测试增加的数量。他们从Alon等人[8]的Java-med数据集（它由GitHub的1000个顶级Java项目组成）开始。从每个存储库的提交列表中，检查（1）提交是否添加了一个测试，以及（2）提交是否链接到一个issue。为了确定一个提交是否添加了一个测试，作者检查它的diff是否添加了@Test装饰符和一个测试体。此外，如果（1）提交消息提到了"(fixes/resolves/closes) #NUM"，或者（2）提交消息提到了一个pull请求，这又提到了一个issue，就将提交链接到一个bug报告（或者GitHub中的一个issue）。将此类报告相关提交所增加的测试数量与当前（2022年8月）测试套件的规模进行比较，以估计此类测试的流行程度。由于不同的存储库有不同的issue处理实践，因此过滤掉没有添加测试的问题相关提交的存储库，因为这表明不同的issue处理实践（例如google/guava）。作者分析了300个存储库，如表1所示。作者发现，相对于当前的测试套件大小，这300个存储库中通过发布引用提交添加的测试的中值比率为28.4%，这表明**大量测试是由于错误报告而添加的**。但这并不意味着测试套件中28.4%的测试来自错误报告，因为作者没有跟踪添加测试后测试的情况。尽管如此，它表明**测试活动报告在测试套件的发展中发挥着重要作用**。基于这一结果，作者得出结论：报告report-to-test的生成问题是由开源开发人员定期处理的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1tdQPwhuwA3PJ28XkrfjWjUcS5AibLsI3Sklylcvbenkhfe0JAIfia7sA/640?wx_fmt=png "")  
  
现有的工作试图通过关注不同的方面来解决问题的特殊情况：一些研究者将报告的句子分为观察到的或预期的行为等类别[9]，而另一些研究者只复现崩溃(崩溃再现)[10]，[11]。**解决这个问题需要对自然语言和编程语言都有很好的理解**，还需要执行推理的能力。例如，表2中的bug报告没有明确指定任何代码，但是精通英语和Java的开发者能够推断出当两个参数都是NaN时,“MathUtils”中的“equals”方法应该返回false。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1w9kSfFNJHPib8auEv0C3AV9FhEH9mh9lKaDGEOFTznlMFI3Q7BXnNIQ/640?wx_fmt=png "")  
  
一个有希望的解决方案是利用预先训练的大型语言模型的能力。LLM通常是基于Transformer神经网络，以语言建模为目标进行训练，即：基于前面的上下文预测下一个token。LLM的主要创新之一是它们可以在没有训练的情况下执行任务：简单地通过文本提示“要求”LLM执行任务。那么，**给定一个bug报告，LLM可以复现多少个bug**。另一方面，实际上重要的是能够知道**什么时候开发者应该相信和使用LLM结果**。  
  
**三、 方法**  
  
LIBRO模型的框架如图1所示。给定一个bug报告，LIBRO首先构建一个提示（prompt）来查询一个LLM（  
**图1：(A)**）。使用这个提示，通过多次查询LLM来生成初始的候选测试集（  
**图1：(B)**）。然后，LIBRO处理测试，使它们在目标程序中可执行（  
**图1：(C)**）。LIBRO随后识别和管理可能是bug复现的测试，并对它们进行排序，以最小化开发人员的检查工作（  
**图1：(D)**）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1bLSsHErQ4nYFbwS0Ryic3ufheEr5eHtRb9SqNCJYcXfajVhXTX827uA/640?wx_fmt=png "")  
  
**A. Prompt引擎**  
  
先前的工作已经发现，“要求”（asking）LLM解决问题方式的不同将导致显著不同的性能水平[12]。找到完成给定任务的最佳查询被称为提示工程[13]。  
  
为了让LLM从一个给定的错误报告中生成一个测试方法，我们从错误报告中构造了一个Markdown文档，它将在提示中使用：考虑Listing 1中的例子，这是一个从表2所示的bug报告中构造的Markdown文档。LIBRO在Markdown文档中添加了几个独特的部分：（1）命令“提供一个重现该问题的自包含示例”；（2）Markdown中代码块的开始，(即```)：（3）部分代码片段  
public void test，其作用是引导LLM编写一个测试方法。由于对提示格式没有实际的限制，崩溃bug提供的堆栈跟踪（模拟提供堆栈跟踪的情况），或者bug所在类的构造函数都可以作为提示（模拟报告错误位置的情况）。  
  
【由于LIBRO特定的模板格式使得生成的提示不太可能逐字存在于LLM训练数据中。此外，实践中的大多数报告仅仅通过一个参考链与暴露缺陷的测试相联系。因此，LIBRO提示模板的格式在一定程度上减轻了数据泄露的担忧。】  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1H5JrLcNz2NBpeBEwYpWOnDdeSFoL3DfyibOz2PXeYP6m35aiaciavNQ5g/640?wx_fmt=png "")  
  
**B. 查询LLM**  
  
使用生成的提示，LIBRO**查询LLM来预测提示后面的token（相对于在提示的引导下，完成后续任务）**。由于提示的性质，它可能会生成一个测试方法，特别是当提示以序列public void test结束时。通过  
接收token直到第一次出现```确保结果只跨越测试方法，这表明Markdown中代码块的结束。  
  
当执行完全贪婪解码（即：严格基于最可能的下一个令牌进行解码）时，LLM会产生较差的结果[14]，而当执行加权随机采样时，性能会更好，这是一种受temperature参数调制的行为。根据之前的工作[14]，作者将temperature设置为0.7，这允许LLM基于完全相同的提示生成多个不同的测试。本文采用生成多个候选复现测试的方法，使用它们的特性来确定bug实际复现的可能性。  
  
对于Listing 1中的提示，LLM的输出示例如Listing 2所示。此时，**LLM输出通常无法单独编译，需要其他构造，如：导入语句**。因此，需要将生成的测试集成到现有的测试套件中，使其可执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG13xjKhAJOxGq9HY5ZgYnKwWxAru4OGFR40ibcLWXOM0IXurCtrJfpL2Q/640?wx_fmt=png "")  
  
**C. 测试后处理**  
  
**（1）将测试注入到合适的测试类**  
  
如果开发人员在bug报告中发现了一个测试方法，他们可能会将其插入到一个测试类中，该测试类将为该测试方法提供所需的上下文（如：所需的依赖）。例如，对于上面示例中的bug，开发人员向MathUtilsTest类添加了一个复现测试，其中大部分必需的依赖项都已经导入，包括焦点类MathUtils。因此，将LLM生成的测试注入到现有的测试类中是很自然的，因为这符合开发人员的工作流程，同时解决了大量最初未满足的依赖关系。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1lPuM048PjwIUWsc0ibDuoibBEmibVJp21xdfvCsFN6miaYxQHJRzQjibjibQ/640?wx_fmt=png "")  
  
为了找到将测试方法注入其中的最佳测试类，需要找到在词汇上与生成的测试最相似的测试类（算法1，第1行）。**直觉上，如果一个测试方法属于一个测试类，那么这个测试方法很可能使用相似的方法和类，因此在词汇上与这个测试类中的其他测试相关**。因此，作者基于等式（1）为每个测试类分配匹配分数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1ib7iajV9BJS3wZhJQD6QC9icyFbYCrWrgu8LVYKjaDjUza4ZN2u94vGdA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1VTcQ2gxwrtYeLWoDOyoglwZUGicuV4iakdibKxTLvsJicORPoibpOmnJhicg/640?wx_fmt=png "")  
  
其中，  
是生成的测试的token集合，  
是第  
个测试类的token集合。例如在Listing 3中，测试包含与Listing 2中LLM生成的测试所使用的类似的方法调用和常量，特别是在第4和第6行。  
  
**（2）解决依赖问题**  
  
尽管通过将测试放在正确的类中可以解决许多依赖问题，但是**测试可能会引入需要导入的新构造**。为了处理这些情况，LIBRO启发式地推断要导入的包。  
  
算法1中的第2行到第10行描述了LIBRO的依赖关系解析过程。首先，LIBRO解析生成的测试方法，识别变量类型和引用的类名/构造函数/异常，然后过滤“已经导入”的类名，方法是将名称与测试类中现有的导入语句进行词汇匹配（第3行）。  
  
上述过程结束后，在测试类中并没有发现被解析的类型。为此，LIBRO首先尝试查找具有该类型的已识别名称的公共类；如果正好有一个这样的文件，那么将导出所标识类的类路径（第7行），并添加一个import语句（第11行）。但是，可能不存在或存在多个匹配的类。在这两种情况下，LIBRO都会在项目中查找以目标类名结尾的import语句（例如，在搜索MathUtils时，LIBRO会查找import .*MathUtils;）。LIBRO在所有项目源代码文件中选择最常见的导入语句。此外，作者添加了一些规则，允许正确地导入断言语句，即使在项目本身中没有适当的导入。  
  
**D. 选择与排名**  
  
当且仅当测试是由报告中指定的错误而失败时，该测试才是错误复现测试（BRT，Bug Reproducing Test）。LIBRO生成的测试成为BRT的一个必要条件是测试在有缺陷的程序中编译并失败：我们称这样的测试为FIB（Fail In the Buggy program）测试。然而，并不是所有的FIB测试都是BRT，因此很难判断bug复现是否成功。这是将我们与crash复现工作[15]分开的一个因素，因为crash复现技术可以通过比较crash时的堆栈跟踪来确认错误是否已经被复现。另一方面，向开发人员展示所有生成的FIB测试是不明智的，因为要求开发人员迭代多个解决方案通常是不可取的[16，17]。因此，LIBRO试图使用观察到的**与成功的bug复现相关的几种模式来决定何时建议测试**。  
  
算法2概述了LIBRO如何决定是否呈现结果，以及如何对生成的测试进行排序。在第1-10行，LIBRO首先决定是否向开发者显示任何结果。将显示相同失败输出（相同错误类型和错误消息）的FIB测试分组，并查看同一组中的测试数量（第8行中的max_output_clus_size）。这是基于直觉：**如果多个测试显示类似的失败行为，那么很可能LLM对其预测“有信心”，因为其独立预测彼此“一致”，bug复现很有可能成功**。LIBRO可配置为仅在输出中存在显著一致时显示结果（将一致阈值设置为高）或显示更多探索性结果（设置为低）。  
  
一旦LIBRO决定展示它的结果，它就依靠三种试探法来对生成的测试进行排序，按照区分力度递增的顺序。首先，如果失败消息和/或测试代码显示了在错误报告中观察到和提到的行为（异常或输出值），那么测试很可能是bug复现。虽然这种试探是精确的，但是它的决定不是很有区别，因为测试只能被分成“包含”和“不包含”的组。接下来，通过查看输出集群大小（output_clus_size）来查看生成的测试之间的“一致性”，这代表了LLM生成结果的“一致性”。最后，LIBRO基于测试长度区分优先级（因为较短的测试更容易理解），这是最细粒度的信号。首先只留下语法上唯一的测试（第11行），然后使用上面的试探法对输出集群和这些集群中的测试进行排序（第16和18行）。  
  
由于具有相同失败输出的测试彼此相似，所以作者认为：**如果来自一个集群的一个测试不是BRT，来自同一个集群的其余测试很可能也不是BRT**。因此，LIBRO展示了来自不同集群的测试。对于第19-22行的每个第  
次迭代，从每个聚类中选择第  
个排序的测试并将其添加到列表中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1tjqFRTE7LEPFmVM3s9TibwsFjzzTCCiabiaBLcCZVNNepZ0RDvszU02JQ/640?wx_fmt=png "")  
  
**其他**  
  
本文的评估数据集为Defect4J 2.0。作者设计了3个RQ以验证LIBRO的效果，效率和实用性，如下（PS：这个格式值得借鉴）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1LVeZ6PdkmOssHJ7tkucC2Pg3xDE3TArwVDeBkGRHUhuwcBAYeqOuSw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1osnhBQdxr1nCbCICKqwr8GMdTrKicvCS7kxtycWfibib5D1rVBCLaZ0mw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG12yYu4Jg8d4uw26JMu8eSKltWSGdKjkqLsnMdT3zvX0icBnR1bibXlw8g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG199Xgjp0lHia7ibIVBT7maWA3Kp9PjFDtCmkzIU2n9ptj8BwL7XDic7UmA/640?wx_fmt=png "")  
  
此外，作者对RQ的回答这部分的排版也值得参考哦。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEdsLemmcGvze7etX6ZsGG1ROeXpLAEmTuSvtde8kAHA5UyVKJcZmHhaibpcFDxc6EanfUWegfxQIA/640?wx_fmt=png "")  
  
**参考文献**  
  
[1] Haas R, Elsner D, Juergens E, et al. How can manual testing processes be optimized? developer survey, optimization guidelines, and case studies[C] //Proceedings of the 29th ACM Joint Meeting on European Software Engineering Conference and Symposium on the Foundations of Software Engineering. 2021: 1281-1291.  
  
[2] Koyuncu A, Liu K, Bissyandé T F, et al. iFixR: Bug report driven program repair[C]//Proceedings of the 2019 27th ACM joint meeting on european software engineering conference and symposium on the foundations of software engineering. 2019: 314-325.  
  
[3] Xiong Y, Wang J, Yan R, et al. Precise condition synthesis for program repair[C]//2017 IEEE/ACM 39th International Conference on Software Engineering (ICSE). IEEE, 2017: 416-426.  
  
[4] Li X, Li W, Zhang Y, et al. Deepfl: Integrating multiple fault diagnosis dimensions for deep fault localization[C]//Proceedings of the 28th ACM SIGSOFT international symposium on software testing and analysis. 2019: 169-180.  
  
[5] Le T D B, Oentaryo R J, Lo D. Information retrieval and spectrum based bug localization: Better together[C]//Proceedings of the 2015 10th Joint Meeting on Foundations of Software Engineering. 2015: 579-590.  
  
[6] Daka E, Fraser G. A survey on unit testing practices and problems[C]// 2014 IEEE 25th International Symposium on Software Reliability Engineering. IEEE, 2014: 201-211.  
  
[7] Kochhar P S, Xia X, Lo D. Practitioners' views on good software testing practices[C]//2019 IEEE/ACM 41st International Conference on Software Engineering: Software Engineering in Practice (ICSE-SEIP). IEEE, 2019: 61-70.  
  
[8] Alon U, Brody S, Levy O, et al. code2seq: Generating sequences from structured representations of code[J]. arXiv preprint arXiv:1808.01400, 2018.  
  
[9] Song Y, Chaparro O. Bee: A tool for structuring and analyzing bug reports[C]//Proceedings of the 28th ACM Joint Meeting on European Software Engineering Conference and Symposium on the Foundations of Software Engineering. 2020: 1551-1555.  
  
[10] Nayrolles M, Hamou-Lhadj A, Tahar S, et al. JCHARMING: A bug reproduction approach using crash traces and directed model checking[C]//2015 IEEE 22nd International Conference on Software Analysis, Evolution, and Reengineering (SANER). IEEE, 2015: 101-110.  
  
[11] Kojima T, Gu S S, Reid M, et al. Large language models are zero-shot reasoners[J]. Advances in neural information processing systems, 2022, 35: 22199-22213.  
  
[12] Kojima T, Gu S S, Reid M, et al. Large language models are zero-shot reasoners[J]. Advances in neural information processing systems, 2022, 35: 22199-22213.  
  
[13] Reynolds L, McDonell K. Prompt programming for large language models: Beyond the few-shot paradigm[C]//Extended Abstracts of the 2021 CHI Conference on Human Factors in Computing Systems. 2021: 1-7.  
  
[14] Brown T, Mann B, Ryder N, et al. Language models are few-shot learners[J]. Advances in neural information processing systems, 2020, 33: 1877-1901.  
  
[15] Soltani M, Derakhshanfar P, Devroey X, et al. A benchmark-based evaluation of search-based crash reproduction[J]. Empirical Software Engineering, 2020, 25: 96-138.  
  
[16] Kochhar P S, Xia X, Lo D, et al. Practitioners' expectations on automated fault localization[C]//Proceedings of the 25th international symposium on software testing and analysis. 2016: 165-176.  
  
[17] Noller Y, Shariffdeen R, Gao X, et al. Trust enhancement issues in program repair[C]//Proceedings of the 44th International Conference on Software Engineering. 2022: 2228-2240.  
  
### 作者团队  
- Sungmin Kang，Juyeon Yoon，韩国科学技术院计算机学院博士生，对自动化调试技术感兴趣，主要是自动化程序修复，也做了测试生成方面的工作。  
  
- Shin Yoo，韩国科学技术院计算机学院副教授，带领的COINSE实验室，主要研究将计算智能应用于软件工程问题。https://coinse.github.io/  
  
  
  
> [安全学术圈招募队友-ing](http://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247484475&idx=1&sn=2c91c6a161d1c5bc3b424de3bccaaee0&chksm=fe2efbb0c95972a67513c3340c98e20c752ca06d8575838c1af65fc2d6ddebd7f486aa75f6c3&scene=21#wechat_redirect)  
 有兴趣加入学术圈的请联系   
**secdr#qq.com**  
  
  
  
