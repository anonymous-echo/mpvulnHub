> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU1NTEzODc3MQ==&mid=2247487193&idx=1&sn=c8a311487502fac2a3ce23003a19ecb1

#  BAZZAFL：通过面向漏洞的种子分组将模糊测试活动导向漏洞  
原创 FuzzWiki  FuzzWiki   2025-06-23 03:44  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/JchE46RGRlr92CPaC2cSiaTUCEWwOd0OucLNLlY09jGCso4gTL4BmXsBNsvOlSMv9qPopLaecg7r21KD4gBERqA/640?wx_fmt=gif "")  
  
  
**基本信息**  
  
**原文名称：**  
BAZZAFL: Moving Fuzzing Campaigns Towards Bugs via Grouping Bug-Oriented Seeds  
  
**原文作者：**  
Kai Ye；Xiaogang Zhu；Xi Xiao   
  
**原文链接：**  
https://ieeexplore.ieee.org/abstract/document/10506549  
  
**发表期刊：**  
IEEE Transactions on Dependable and Secure Computing，2025  
  
**开源代码：**  
https://github.com/BazzAFL/BazzAFL  
  
   
  
  
  
  
**一、概述**  
  
BAZZAFL的核心思想是  
维护多个种子组  
，  
每个种子都在某一目标上表现最好  
。在这些种子组中，BAZZAFL通过多  
目标优化  
的方式，优先测试最有可能包含漏洞的代码区域，并根据  
香农熵自适应地分配能量  
给种子组中的不同种子。  
  
在变异过程中，BAZZAFL倾向于变异那些  
可能改变执行状态  
的字节。通过这些创新，BAZZAFL逐步推动模糊测试朝着更接近漏洞触发点的方向发展。  
  
**二、介绍**  
  
覆盖引导灰盒模糊测试作为最有效的漏洞检测方法之一，其核心假设是通过提升代码覆盖率增加漏洞暴露概率。  
  
现有研究主要通过优化调度策略、路径约束处理等方式提升覆盖率，但代码覆盖率本身存在效率瓶颈——理想的漏洞检测需同时满足两个条件：  
  
1）  
到达含漏洞的代码区域  
；  
  
2）  
满足触发漏洞的特定执行状态（如内存值/寄存器值等运行时信息）  
。然而多数CGF方案仅关注代码覆盖，忽略执行状态分析。  
  
检测多种类型的漏洞是一个多目标优化问题。  
  
一方面，  
不同类型的漏洞在模糊测试过程中可能会相互冲突  
。例如，某个代码区域可能是基于漏洞类型A的最可疑位置，但基于漏洞类型B却是最不可能的位置。  
  
另一方面，一  
个输入可能同时影响多种类型的漏洞  
。例如，由于类型A和B的漏洞位于同一个代码区域，某个输入可以同时影响这两个漏洞。然而，尽管它们位于同一代码区域，但相同的输入不太可能同时触发这两种漏洞，因为它们需要不同的执行状态。  
  
本文提出了BAZZAFL。为了应对一个种子无法同时表示多种漏洞类型的问题，BAZZAFL将具有相同执行路径但不同漏洞度量的种子组织成种子组。组中的所有种子执行相同的代码区域，每个种子仅负责其自身类型的漏洞。  
  
**三、动机**  
  
图3-1展示了常见程序中可能存在的两个漏洞。一个可能的内存消耗错误可能出现在D块，当请求的内存过多时。另一个错误是算法复杂度错误，可能出现在G块，因为函数process_input()的执行次数与输入相关。  
  
代码覆盖率作为唯一指标，模糊测试倾向于优先选择覆盖范围最大的种子（g1）。  
  
但关键错误存在于ACDFG（g2）和ACEFG（g3）路径，导致错误检测效率低。  
  
现有方法使用单一种子，无法优化不同错误类型的触发。因此，一个更好的解决方案是使用多个指标来评估种子。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDiawnDg8wMUeAzOiaV3HzxBic5Ac79I5KjflZgQVcees5HbM0dD8j73C2A/640?wx_fmt=png&from=appmsg "")  
  
**图3-1 动机例子**  
  
**四、方法**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDicKOexke6oB2UXUib3TJ67g8PomJ6ZAAbHF1wyeHibXBaRDiaibGHLqVKBQ/640?wx_fmt=png&from=appmsg "")  
  
**图4-1 BAZZAFL的工作流程**  
  
基于种子组优化种子选择和变异。种子组的组织标准是所有种子都执行相同的执行路径。  
  
主要包括三个组件：种子组优先级排序、能量分配调度和字节推断。  
  
种子组优先级排序旨在选择那些其种子更有可能在错误检测上取得更好表现的获胜组。  
  
选定种子组后，能量分配调度用于确定每个种子在组中分配的能量。  
  
在种子变异过程中，字节推断用于推断与每个目标错误相关的字节。字节推断旨在进一步探索可疑的执行状态。  
  
**1．Seed Group**  
  
在检测多种类型错误的多目标问题中，每个目标都需要被量化，以便不同目标之间可以进行比较。  
  
包含五个种子的种子组可以执行所有类型错误的最可疑执行状态。该组中的种子具有相同的执行路径，但组中的以某个错误为导向的种子在该错误度量上表现得比其他种子更好。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDInpZKjPfgkHQvzckfZj2uicDgejKQEPnl9wXNUJnaHzqqP05ibXW6MpQ/640?wx_fmt=png&from=appmsg "")  
  
**图4-2 种子分组的过程**  
  
边覆盖  
：发现错误的第一步是探索可疑的代码区域。为了衡量种子在边覆盖方面的质量，设置了两个度量，分别是执行速度（m1）和种子所覆盖的边数量（m2）。  
  
内存违规错误  
（MV）：当内存被指针错误地访问时，就会发生内存违规错误。因此，如果模糊测试关注内存访问操作，即为更多内存访问的代码区域分配更多能量，它可能会发现更多的内存违规错误。为了衡量种子在MV错误方面的质量，作者使用内存访问操作的次数作为度量（m3）。  
  
越界错误  
（OOB）：OOB是内存违规错误的一种特定类型，它发生在读取或写入越界的字节时。直观地说，访问更接近内存边界的输入比访问远离边界的输入更可能触发越界错误。为了衡量种子在OOB错误方面的质量，使用一个比率来衡量内存访问距离边界的远近（m4）。该比率定义为r = cur/max，其中cur是内存块中的当前索引，max是最大大小。  
  
内存消耗错误  
（MC）：MC是一个空间复杂度问题，当程序执行时消耗了过多或无法控制的内存时，就会发生这种错误。由于该错误消耗了过多的内存，它使得攻击者可以发起拒绝服务（DoS）攻击。为了衡量种子在MC错误方面的质量，使用已分配内存的大小作为度量（m5）。  
  
算法复杂度错误  
（AC）：AC是一个时间复杂度问题，它发生在触发最坏情况的算法行为时。如果一个输入触发了算法复杂度错误，该输入将需要很长时间来完成执行，因为有太多的基本块需要执行。因此，它也可以被攻击者利用来发起DoS攻击。为了衡量种子在AC错误方面的质量，使用已执行的基本块数量（m6）。  
  
**2．Seed Group Prioritization**  
  
将种子组的优先级排序视为一个多目标优化问题。在多目标问题中，可以获得一组最优解，或者称为帕累托最优解，这有助于在模糊测试中优先选择一组种子组。  
  
采用非支配排序方法来为不同轮次找到帕累托最优解。该问题可以定义为：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDzUgI9oEiaibhoibNX0cfueUopuJxF1mHiciaQahWTEpib3qKK41u2hicUJxlg/640?wx_fmt=png&from=appmsg "")  
  
F(g)是一个包含k个目标函数的目标向量，即选择种子组的k个度量。BAZZAFL为每个种子组设置了六个度量（即k=6）。理想情况下，这六个度量有助于模糊测试优先选择种子组。  
  
1.  
非支配排序方法  
：一种常用的多目标优化解决方案是计算帕累托前沿。帕累托前沿是一个非支配的解，定义为：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDNE64oKvK57cRyMC48yfUSF1MKicLsJJDve9tRV8ZFNkvJCjpA1dml0Q/640?wx_fmt=png&from=appmsg "")  
  
其中，g’支配g当且仅当对于目标向量[m1, m2, …, m6]：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJD6iadiaBuNVWDiaD1GdVrpXEAgbeB7EfrLoZUbIF8ibHw2h3dR34UuoBHIA/640?wx_fmt=png&from=appmsg "")  
  
在模糊测试的背景下，帕累托前沿是动态变化的，因为每个种子组中的度量值在模糊测试过程中发生变化。  
  
因此，使用非支配排序进化方法来计算动态的帕累托前沿。基本上，每个种子组都分配一个等级，初始值为0。在计算帕累托前沿的过程中，如果g’支配g，那么g的排名就增加1。  
  
对于每个模糊测试活动，BAZZAFL优先选择具有最小排名的组。  
  
新添加的种子组在下次计算帕累托前沿时进行排名。这可以节省计算帕累托前沿的时间，因为每次添加新种子时，无需更新所有种子的排名。  
  
2.  
放松的多目标问题  
：然而，在某些情况下，这六个度量同时满足的条件过于严格，导致没有优先排序的种子组。具体来说，所有的排名相同，因为没有种子能够支配其他种子。根据图4-3的结果，只有少数种子位于0级，表示如果不放宽约束，几乎无法得到更好的种子在帕累托前沿中。  
  
因此，如果当前的优先级排序无法选择具有最小排名的获胜组，BAZZAFL通过逐渐去除目标向量F(g)中的一个度量来放宽约束。优先删除那些不太可能触发错误的度量。  
  
首先删除度量m1（执行速度），因为最终目标是发现错误。如果去除m1仍然不能选择获胜组，作者将删除m2（覆盖的边数量）。如果仍然无法选择获胜组，m6（执行的基本块数量）将是第三个被删除的度量，因为AC比其他错误类型的发生概率低。最后，将删除m3（内存访问操作数量），因为OOB比其他类型的内存违规错误更可能发生。  
  
保留至少两个度量m4（衡量内存访问距离边界的远近的比率）和m5（已分配内存的大小），以确保问题仍然是一个多目标问题。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDOU9Tibiahj7Yrl0VQGmzPoA3YypLE22yfWDibfA1Is8Mgb7lNX1NsWuIA/640?wx_fmt=png&from=appmsg "")  
  
**图4-3 不同级别的支配约束的总支配成功百分比**  
  
**3．Power Schedule for Individual Seeds**  
  
  
当选定一个种子组后，受到ENTROPIC的启发，BAZZAFL将模糊测试理解为一种学习过程，并基于香农熵来计算能量，从而优化能量分配。具体而言，如果一个种子能够揭示程序的更多信息，则该种子将获得更多的能量。  
  
1.   
香农熵  
：ENTROPIC是一个专注于更大代码覆盖的模糊测试工具。它将程序中的每个边视为一个物种，边的发现类似于物种发现。如果输入覆盖了边Di，则该输入被认为属于物种Di。由于一个输入可以覆盖多个边（即一个输入属于多个物种），根据香农熵公式   
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDLYBwTV3p6WtBic9mc5a63bwdRxmr7waQ7ITY2ZwLicQpCeECUJJdCInw/640?wx_fmt=png&from=appmsg "")  
  
ENTROPIC计算种子t的熵为：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDeRoDFiaFzM7ZKCpvPOdIjicvd21B2bbIicbNjjRc8RKc4BQoAjkFVGpWQ/640?wx_fmt=png&from=appmsg "")  
  
其中，S是区分物种（边）的数量，是由种子t生成的输入属于物种Di的概率，是生成的输入属于物种D1到DS的概率总和。公式表示了种子t观察到的信息量。熵值越大，种子t揭示的信息就越多。揭示更多边信息的种子将在模糊测试中分配更多能量，因为该种子能学习更多的程序信息。  
  
  
2.  
五个物种  
：BAZZAFL借用了ENTROPIC在物种发现中的思想，并引入了五个物种来进行能量分配。一个物种用于边覆盖，其余四个物种分别用于四种错误。例如：COVG 是用于边覆盖的物种，程序中的不同边是不同的边物种。MVG 是用于内存违规错误的物种，每个输入的度量m3是一个物种… …（m4，m5，m6）。  
  
  
在实践中，作者观察到，频繁的物种会降低能量分配的效果。因为发现的稀有物种几乎可以解释未发现物种的特性，所以熵是基于稀有物种计算的。对于COVG物种，稀有物种是由少数输入覆盖的边。对于四个错误物种，稀有物种是由输入增加的错误度量的值。例如，如果输入增加了种子的度量m5的值，则该物种是稀有的，输入属于该稀有物种。  
  
因此，对于MVG、OOBG、MCG和ACG物种，种子t的熵被计算为：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDIkMeaGS9HC3gCBBLSBJznxvfhXeD2iaTEdWTbQr0z9CxDXwuolcyQtQ/640?wx_fmt=png&from=appmsg "")  
  
  
BUG可以是物种MVG、OOBG、MCG或ACG。  
  
  
3.  
能量分配  
：每个种子属于所有五个物种。具体来说，每个种子包含边覆盖、内存违规错误、越界错误、内存消耗错误和算法复杂度错误的特征。因此，每个种子包含五个熵值。种子t的总熵计算为：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDqnf0l9WAVVBp1dfNJc3pXuEJLb43luNr7ZgEiaOC8njI89RGXRAaSXw/640?wx_fmt=png&from=appmsg "")  
  
  
其中，gi是种子组g中的第i个种子，Rgi是种子组g中第i个种子的比例。有了比例Rgi，每个种子的能量可以简单地计算为：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDIZtqWPCGyUnYm79IYeYSjkwiaQkNXgcVAouWib1aPWcH6jOSl06SPfyw/640?wx_fmt=png&from=appmsg "")  
  
  
其中，Eg是种子组g的总能量。基于边覆盖的种子，种子组的能量Eg按照AFL的策略计算。因此，BAZZAFL自适应地为种子组中的每个种子分配能量，揭示更多信息的种子将获得更多的能量。  
  
**4．Byte Inference for Mutation**  
  
使用与AFL++相同的变异操作符来进行变异。  
  
BAZZAFL推断出可以改变与漏洞相关的度量值的字节。字节推断基于这样一个观察结果：种子中的只有一部分字节与漏洞度量相关，这表明变异所有字节是浪费时间。  
  
作者考虑在确定性阶段对字节推断的变异操作，包括位级、字节级和字级的变异操作。具体来说，选择那些已知变异字节位置的变异器，如FLIP_BIT和SWAP32。  
  
对于每个面向漏洞的种子，字节推断更有可能变异与其目标漏洞相关的字节。  
  
请注意，由于确定性变异器的低效，仅对一个种子（即边覆盖种子）进行字节推断，然后将结果用于变异种子组中的其他面向漏洞的种子。  
  
至于模糊测试的其他阶段，大多使用非确定性变异器进行测试。  
  
BAZZAFL首先记录变异字节的位置，然后根据漏洞度量的变化确定变异位置是否与相应的度量相关。  
  
如果一个字节的变化导致MC度量值发生变化，BAZZAFL将记录该字节为种子s的相关字节。在变异针对MC设计的种子s时，BAZZAFL更可能变异与MC漏洞相关的字节。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDII8wDqASS3PP8c9kYdPhYfaf6ceZ0miboarUjsrUvM1EuphyptlpeyA/640?wx_fmt=png&from=appmsg "")  
  
**图4-4 字节推断**  
  
**五、评估**  
  
  
  
基于AFL++ 4.01a 实现了BAZZAFL，利用LLVM 13 对目标程序进行插桩，获取边覆盖和漏洞度量的反馈。  
  
使用与AFL++相同的插桩方式来获得边覆盖。  
  
对于内存违规漏洞，对操作内存的指令进行插桩，并计数这些指令。具体而言，在操作内存的函数调用处进行插桩，如malloc、free和memcpy。此外，作者还在可能操作内存的指令处进行插桩，利用LLVM中的mayReadFromMemory()和mayWriteToMemory()。  
  
对于越界错误，作者在数组和结构体等聚合数据类型处进行插桩，以获取偏移量（即内存访问的当前地址）和大小（聚合数据的总大小）。作者使用偏移量/大小的比值来量化越界的可能性。  
  
对于内存消耗漏洞，作者在分配和释放内存的指令处进行插桩，以获取已分配内存的总大小。  
  
对于算法复杂度漏洞，作者计算输入覆盖的基本块数。  
  
**1．Experiment Setup**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDMaZcHYNyIN3lAI3H1To5GQAfFXfZ9nv3u5At9v0DGbZ8U78vbxU9TA/640?wx_fmt=png&from=appmsg "")  
  
**表5-1 用于评估的程序**  
  
在Ubuntu 18.04上，使用Intel(R) Xeon(R) Gold Silver 6230R CPU进行实验。  
  
如表5-1所示，在24个程序上运行模糊测试，这些程序来自UniFuzz。  
  
对每个目标程序运行每个模糊测试器10次，每次运行24小时。所有模糊测试器都使用提供的相同初始种子。  
  
基准模糊测试器包括AFL、AFL++、MOPT、MemLock、FuzzFactory和SLIME。  
  
**2．RQ1: Effectiveness of BAZZAFL**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDgHgUQ1tBKI41v1up6moRXLCxvBP02JkwmIQykn9YeHLUjfRXic5y5AQ/640?wx_fmt=png&from=appmsg "")  
  
**表5-2 10次实验中模糊器暴露的独特崩溃和错误数量**  
  
如表5-2所示，BAZZAFL发现了最多的唯一崩溃和漏洞。BAZZAFL共发现了179个漏洞，覆盖了21个程序，发现的漏洞比第二名SLIME多62个（即多发现了53%的漏洞）。  
  
尽管BAZZAFL更多地关注漏洞，但它仍然保持了代码发现的能力。如表5-3所示，BAZZAFL比第二好的模糊测试器AFL++多发现1.75%的边。  
  
至于执行速度，BAZZAFL比其他模糊测试器平均快37.15%，仅比最好的模糊测试器AFL慢0.6%。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDsZT2XnO4iceoyg5G0qtUwic8RsuKVAFZRIb7SliaqFdxoiaxg7LScvDw1g/640?wx_fmt=png&from=appmsg "")  
  
表5-3 10次实验中模糊器的平均边覆盖数和执行速度  
  
表5-4展示了作者实验中发现的漏洞信息，包括CVE ID、漏洞原因以及漏洞所属的类别。  
  
BAZZAFL暴露了九种类型的漏洞，包括使用后释放、内存访问违规、（栈、堆或全局）缓冲区溢出、缓冲区过读、内存泄漏、错误分配、作用域外使用、栈溢出、内存不足和浮点异常。  
  
在这九种漏洞中，使用后释放和内存访问违规可以通过内存违规种子进行攻击；  
  
栈溢出可以通过算法复杂度种子进行攻击；  
  
内存不足、内存泄漏和错误分配可以通过内存消耗种子进行攻击；  
  
缓冲区溢出可以通过越界种子进行攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDWaIxvSZ7EVTzlGZBmzIoAw5eZpBIiau7EV3GTkDYNXDFNPlicj480OlQ/640?wx_fmt=png&from=appmsg "")  
  
表5-4  BAZZAFL发现的典型错误类型  
  
**3．RQ2：Significance of Seed Groups**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDgTVm9Hy61aWvHdRUHMdYJzWCn9uKibasrciadbic9AxyjZ5tKZAUIUkFg/640?wx_fmt=png&from=appmsg "")  
  
**图5-1 当一个面向bug的种子被禁用时，边覆盖、唯一崩溃和bug数量的比较**  
  
在本节中，通过消融实验探索种子组中每个单独种子的影响。禁用种子组中的一个面向漏洞的种子，并与原始种子组进行对比实验。将禁用面向漏洞的种子的方案表示为BAZZAFL-，其中可以是MV、AC、MC和OOB之一。  
  
总体而言，当种子组中的所有种子都启用时，漏洞发现的效率更高。在50%的程序中，BAZZAFL比BAZZAFL-*发现了更多的唯一崩溃和漏洞。  
  
**4．RQ3：Effectiveness of Seed Group Prioritization**  
  
在本节中，通过消融实验展示了放宽方法在种子组优先级中的重要性。对每个程序运行24小时，并计算每个级别上的成功支配次数。  
  
结果如图5-2所示，其中级别0表示满足所有6个约束。从级别1到级别4，按顺序每个级别放宽一个约束。在几乎所有程序中，级别0的支配成功率都低于3%。当级别增加（即约束减少）时，更多的支配成功发生。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDQR6icia9EYhNZ8nzFqDXkB76gT55QMIMlhIINjT9m9vKIJeR2r64icfag/640?wx_fmt=png&from=appmsg "")  
  
图5-2 不同级别的支配约束的总支配成功百分比  
  
**5．RQ4：Efficiency of Information Discovery**  
  
在本节中，通过最大时间段来衡量模糊测试器的效率，这段时间是模糊测试器未能发现新信息的时间，称为“空闲时间”。当模糊测试发现新的边覆盖或在漏洞度量上达到更大的值时，就会发现新信息。  
  
如果一个模糊测试器长时间无法发现新信息，则认为该模糊测试器效率低下。图5-3是一个小提琴图，显示了在10次实验中的平均空闲时间的概率密度。  
  
在图中列出的10个程序中，BAZZAFL在所有程序上都比其他模糊测试器更高效地发现新信息，即BAZZAFL具有最小的空闲时间中位数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDc54mCLFPFSqOdxUTOzaibxLPNIXTrDBLicdaxdITPE8ofwJ5l82KibsYw/640?wx_fmt=png&from=appmsg "")  
  
**图**5-3 空闲时间的Violin图  
  
此外，作者进行了字节推断的消融实验，结果如表5-5所示。度量更新计数指的是每个种子组中漏洞度量的更新次数，表示是否有任何漏洞度量得到更新。最大度量更新计数代表全局范围内最大漏洞度量的更新次数。  
  
表格中的前面值表示没有任何字节推断的结果，而后面的值表示在相应度量下进行字节推断的结果。ALL表示对所有4种漏洞度量进行字节推断。  
  
根据表格，对于大多数程序和漏洞度量，字节推断的度量更新计数比基线更高。这证明了字节推断在提高信息发现效率方面的有效性，并且与BAZZAFL的能量调度配合使用，使漏洞度量能够得到全面的利用和开发，并高效地最大化漏洞度量值。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRloBsGtk3D6ibiaoYMZM3gKGJDibdhicr2icKKmIxOmr1HicUWiady5QNMdUx468bhPGjHEVd7FKFEL8qQic0Q/640?wx_fmt=png&from=appmsg "")  
  
表5-5 不带字节推理和带字节推理的不同路径BUG度量和全局最大BUG度量的平均更新次数  
  
****  
**六、结论**  
  
  
在本文中，作者提出了BAZZAFL，旨在  
优化多目标模糊测试的调度  
，包括边覆盖和多种类型的漏洞。BAZZAFL基于种子组开发了三个组件，分别是  
种子组优先级  
、  
能量调度  
和  
字  
节推断  
。评估结果表明，BAZZAFL  
成功地优化了种子选择和能量调度  
，能够在多个目标之间进行有效调度，并且识别出了最多的独特漏洞。  
  
**—END—**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRlrFxo5eqwR0gsfAItibNmfykKRSz1SvNIKndIPoSB9dQk8u1iaH2IcWlV4vR3Ov4uXgMibO6uPGRA2dQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRlqicsiaxDHZjSsKx6Eoahhic8tm1AUvF5TI33T7kuQmpqnP5HoOUicFhuIhrcXcyaZJzHJrYaLibPCZSRQ/640?wx_fmt=png "")  
  
  
[通过命令行反馈利用大语言模型提高编译器选项黑盒模糊测试](https://mp.weixin.qq.com/s?__biz=MzU1NTEzODc3MQ==&mid=2247487166&idx=1&sn=f5e0bb1a8a8749524e4d5707e1332fde&scene=21#wechat_redirect)  
  
  
[Beyond REST：一种用于全面API漏洞模糊测试的工具APIF](https://mp.weixin.qq.com/s?__biz=MzU1NTEzODc3MQ==&mid=2247487150&idx=1&sn=3337e826144d84e123f6d83c4cffb942&scene=21#wechat_redirect)  
  
  
[SELECTFUZZ:采用选择性路径探索的高效定向模糊测试](https://mp.weixin.qq.com/s?__biz=MzU1NTEzODc3MQ==&mid=2247487127&idx=1&sn=7bded765fbc0019e4e001fefee6b7a04&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JchE46RGRlrFxo5eqwR0gsfAItibNmfyk5wLcpKFBfhV2gLHUvrA15ticyqNAUM2Nvak36LBpQmxVQdliabzKmaSg/640?wx_fmt=png "")  
  
  
  
