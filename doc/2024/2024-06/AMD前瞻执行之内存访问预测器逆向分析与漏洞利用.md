#  AMD前瞻执行之内存访问预测器逆向分析与漏洞利用   
 网络安全应急技术国家工程中心   2024-06-05 14:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5c7dYibD2jpuDOb5KsdnapPW3icYNI7gs4zaaQByAiboz1A8HKBoWu0YwEZOvBmeuc2nzG02hcFhYCBWXv7QDibaRA/640?wx_fmt=gif "")  
  
前瞻执行（又称推测执行）是一种有效降低由流水线停滞引起的性能损失的重要方法。骑士战队对AMD前瞻执行技术中的内存访问预测器进行了逆向工程，揭示了两个关键预测器的内部结构和状态机设计。通过进一步的实验分析，我们发现这些预测器可以在瞬态执行期间被故意操作和更改，从而导致跨安全域的信息泄露。基此，我们提出了新的攻击方式，包括Spectre-STL的一种变体和一种名为Spectre-CTL的全新Spectre攻击形式。启用推测性存储旁路禁用功能可以缓解这些漏洞。然而，这是以显著的性能下降为代价的。  
  
以骑士战队刘畅博士为第一作者发表的论文《Uncovering and Exploiting AMD Speculative Memory Access Predictors for Fun and Profit》发表在2024年国际体系结构顶会HPCA（High-Performance Computer Architecture）上。论文链接：  
https://ieeexplore.ieee.org/document/10476467  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5c7dYibD2jpuDOb5KsdnapPW3icYNI7gs4zaaQByAiboz1A8HKBoWu0YwEZOvBmeuc2nzG02hcFhYCBWXv7QDibaRA/640?wx_fmt=gif "")  
  
**4攻**  
  
**01 研究背景：Spectre-V4攻击01 研究背景：Spectre-V4攻击**  
  
  
**01 研究背景：Spectre-V4攻击**  
  
  
  
**（1）基本原理**  
  
Spectre-V4攻击利用加载存储单元（Load Store Unit，LSU）中的错误预测实现瞬态执行攻击。具体而言，通过LSU的错误预测，攻击者能够通过存储队列（Store Buffer）或缓存（Cache），给一条加载指令注入一个恶意数据，并可以用这个恶意数据作为地址，进一步访问受害者进程中的任意地址，从而窃取受害者进程任意地址的任意数据。攻击者巧妙利用CPU预测器预测错误后的回滚机制，避免注入的恶意数据导致受害者进程崩溃，或者被受害者识别。目前已知的LSU预测器包括预测性存储转发预测器（Predictive Store
Forwarding Predictor, PSFP）和推测性存储绕过（Speculative Store
Bypass Predictor, SSBP），这两个预测器的错误预测，均能导致加载指令在瞬态执行期间得到一个受控的错误数据，从而被用于实现Spectre-V4攻击。  
  
**（2）预测性存储转发******  
  
PSFP用于优化从存储缓冲区（或称为存储队列）到加载队列的转发机制。存储队列用于暂存已发出但尚未完成的存储指令的地址和数据。基于存储队列到加载队列的转发机制是加速写后读（Read-After-Write, RAW）场景中内存访问的公认技术。当加载队列中的某条加载指令的地址与先前的存储指令地址相同时，加载指令可以在存储地址生成之后、存储指令完成之前，直接从存储队列中获取数据。为了进一步提高存储至加载转发的性能，PSFP在存储地址生成之前，提前预测存储指令所携带的数据能否直接转发给加载指令。  
  
**（3）预测性存储绕过**  
  
SSBP用于优化数据相关性未知的访存场景。在某些情况下，访存指令的地址生成较慢，CPU无法在短时间内确定一条存储指令和一条加载指令是否会发生RAW。为了确保正确执行，CPU必须暂停加载指令，直到前面的存储指令的数据地址生成，但这会导致性能损失。为了避免这种停顿并加速加载指令，Intel和ARM的CPU引入了SSBP，用于预测加载指令是否与存储指令是否发生RAW。AMD声称其处理器上实现了类似技术。然而，除了简短的专利描述外，AMD并未公开披露是否存在与Intel和ARM类似的预测器。  
  
**（4）攻击过程******  
  
如图1所示，以利用 PSFP 的攻击为例，攻击过程如下：(1) 攻击者首先通过延迟存储指令的访存地址，激活预测器；(2a) 如果利用PSFP，那么攻击者构造使用一个访存地址与存储指令不同的加载指令；(3a) PSFP错误地预测加载指令和存储指令地址相同；(4a) 存储指令所携带的数据 0xdd 被错误地传递给加载指令；(5) 加载指令使用错误数据 0xdd 进行后续操作，例如访问受害者数据内存；(6) CPU 检查到 PSFP 预测错误并触发回滚，加载指令使用错误数据执行的影响在指令层面被消除，但对缓存等部件的影响未被消除。  
  
利用SSBP的攻击类似，但攻击者需要对访存指令的数据相关性和恶意注入数据的位置进行调整。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5c7dYibD2jpux9v3LaIKOu8B8nTVadjbSk5qgONZO98FqnVQEGxWfju3jFw1KnrFR7LN33ATRo2rJkkyTgNOskQ/640?wx_fmt=png&from=appmsg "")  
  
图1   
利用PSFP（1, 2a, 3a, 4a, 5, 6）和SSBP（1, 2b, 3b, 4b, 5, 6）的瞬态执行实现  
Spectre-V4攻击  
  
  
  
**02 研究动机**  
  
  
  
在本研究之前，  
AMD  
处理器已知的  
Spectre-V4  
攻击，仅包括利用  
PSFP  
实现的同进程同地址攻击。同进程，指攻击者需要和受害者在同一进程，或使用共享指令页，从而能够执行相同地址上的相同指令；同地址，指攻击者用于训练存储单元预测器的存储和加载指令，与后续触发攻击的存储和加载指令相同，但在训练阶段和利用阶段具有不同的数据相关性。同进程和同地址极大地增加了  
AMD  
处理器  
Spectre-V4  
攻击的复杂程度，限制了攻击的可行性和可利用性。  
  
因此，我们希望通过这一研究，回答以下问题：  
  
（  
1）能否利用  
AMD处理器的  
SSBP预测器实现同进程同地址的  
Spectre-V4攻击？  
  
（  
2）能否利用  
AMD处理器的  
PSFP和  
SSBP实现同进程跨地址攻击？  
  
（  
3）能否利用  
AMD处理器的  
PSFP和  
SSBP实现跨进程跨地址攻击？  
  
其中，如果（  
2）或（  
3）可行，能使得  
Spectre-V4攻击非常轻易地在  
AMD处理器上实现，将大大增加  
AMD处理器上  
Spectre-V4攻击的可行性和可利用性。  
  
为了解决上述问题，本研究对  
AMD处理器的  
PSFP和  
SSBP预测器进行了第一个详细的逆向分析，在得到这两个预测器的设计细节后，成功实现了基于  
PSFP的跨地址攻击，以及基于  
SSBP的跨进程跨地址攻击。  
  
  
  
  
  
**03 研究方法**  
  
  
  
  
  
通过精心构造测试代码，我们对  
4款  
AMD处理器（  
AMD Ryzen 9 5900X、  
AMD EPYC 7543、  
AMD Ryzen 5 5600G和  
AMD Ryzen 7 7735HS）的推测内存访问预测器（包括  
PSFP和  
SSBP）进行了详细逆向分析，分析内容包括这两个预测器的架构设计、表项数量、索引方式、状态机和状态转移方式等。  
  
在分析状态机和状态转移方式时，我们观察测试代码的执行时间，对不同的时间类型进行区分，并使用性能监控单元（  
Performance Monitor Unit, PMU)中的一些事件分析了不同执行时间的原因。在分析架构设计、表项数量和索引方式时，我们使用代码滑动方法，通过频繁地修改指令页的内容，来收集发生预测器表项碰撞地址，并对这些地址的数学特征进行分析。****  
  
  
  
**04 研究结果**  
  
  
**（1）PSFP和SSBP设计**  
  
我们在图2中总结了PSFP和SSBP的组织。存储和加载的48位指令地址（IPA）作为哈希函数的输入，产生12位的压缩输出。PSFP是12路全相联的，由3个计数器组成，存储和加载的哈希指令地址作为标签。SSBP由2个计数器组成，并具有更复杂的选择函数。根据我们的实验，我们研究中使用的所有4个AMD Zen 3 CPU都采用了相同的PSFP和SSBP设计。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5c7dYibD2jpux9v3LaIKOu8B8nTVadjbSfvHIzWpjsyNg8Nz5UKiaE3p0alLgFicKl3rVP8MJE4KjV8gQibEybbkCw/640?wx_fmt=png&from=appmsg "")  
  
图2 PSFP和SSBP的组织结构概览  
  
对于一对存储和加载指令，根据图2所述架构，会同时访问PSFP和SSBP，分别在PSFP读取3个计数器的值，以及在SSBP读取2个计数器的值。  
这5个计数器的结果可以视为一个状态机，决定了加载指令的执行方式，如是否推测性地绕过存储指令并直接访问缓存，是否推测性地从存储指令得到数据，或者是否阻塞不执行。  
通过分析，状态机设计如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5c7dYibD2jpux9v3LaIKOu8B8nTVadjbSSDdCUelEHfGuXW1sBrq6HSN5OqDQDg5LOam0swyWMtSphTqpqOxnyg/640?wx_fmt=png&from=appmsg "")  
  
图3   
预测器的状态机设计  
  
**（2）安全性分析**  
  
我们的实验证实PSFP被很好地隔离了，然而，SSBP在两个安全域（包括主机操作系统中的一个用户进程、虚拟机中的一个进程以及一个内核线程）之间并未被隔离，允许一个域从另一个域泄漏数据。此外，我们发现SSBP不受上下文切换的影响，并会保留前一个进程中的旧数据，由此可能导致信息泄露，并且能被用于构造跨地址（PSFP和SSBP）或跨进程（SSBP）的Spectre-V4攻击。  
  
  
  
  
**05 漏洞利用**  
  
  
  
基于对AMD的SSBP和PSFP的逆向工程及安全分析，我们提出了两种新的Spectre攻击变体，即Spectre-STL和Spectre-CTL。此外，我们还验证了SSBP可以被滥用来进行应用程序指纹识别。  
  
**（1）Spectre-STL******  
  
Spectre-STL，也被称为Spectre V4，已在AMD CPU上被发现。然而，由于预测器在上下文切换期间会被清空，因此利用范围仅限于单个进程。除了作为进程内攻击外，目前的研究还表明，Spectre-STL只能在原地被利用。虽然AMD声称可以进行非原地的利用，但由于相关的PSFP不是公开可用的，因此尚未有研究发现一种方法，在攻击者的地址空间内，并在攻击者的完全控制下，使用不同的存储加载对来实现Spectre-STL。我们提出了一种非原地的方法来利用PSFP，并在AMD Zen 3 CPU上进行了实现，这扩大了攻击面。我们通过在一个用户进程中泄露10000个随机生成的字节来测试非原地SpectreSTL的准确性和带宽，实现的准确率为99.95%，攻击平均每秒泄露416字节（B/s）。  
  
**（2）Spectre-CTL******  
  
我们提出了一种名为Sepctre-CTL的新型Spectre攻击，利用SSBP克服了Spectre-STL的局限性。Spectre-CTL的关键代码片段如图4所示，其代码段中不需要秘密地址，秘密也不需要乘以一个大数，这使得在受害者的代码中更容易找到可被利用的代码段。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5c7dYibD2jpux9v3LaIKOu8B8nTVadjbS6TnlfjibxQicyG5vBYMCkjjxhbkXCE1G2oGQqbXRIdBejkCXxI3L2x5w/640?wx_fmt=png&from=appmsg "")  
  
  
  图4
Spectre-CTL关键代码片段  
  
①本地攻击  
  
Spectre-CTL的本地攻击过程如图5所示。在训练阶段，攻击者试图通过代码滑动发现与受害者的第一次和第三次加载的两个碰撞。在找到这些碰撞后，攻击者通过清除来训练相关的SSBP条目，以便发生误预测为非混叠。训练后，攻击者执行受害者函数。SSBP给出了一个误预测，即第一次加载可以绕过存储并从缓存或内存中获取数据。当CPU检测到误预测并触发回滚时，泄漏阶段就完成了。然后，攻击者在恢复阶段探测第二个SSBP条目。我们通过泄露10,000个随机生成的字节来测试Spectre-CTL的准确性和带宽。实现的准确性为99.97%，攻击平均每秒泄露384字节（B/s）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5c7dYibD2jpux9v3LaIKOu8B8nTVadjbSCuiaJQ3uYF69hZq9GAArvD4bTlKKWVqyTbncSpbypL1Jbw7J3ckzxgQ/640?wx_fmt=png&from=appmsg "")  
  
图5
Spectre-CTL攻击概览  
  
②通过网页浏览器攻击  
  
我们在AMD Zen 3 CPU上的Chrome 86版中实现Spectre-CTL攻击，证明了Spectre-CTL在网络环境中是一种实用而强大的攻击手段。首先，我们验证了在网络浏览器中可以检测到SSBP状态。为了实现这一点，我们直接在浏览器中实现了一个高分辨率计时器，该计时器能够达到大约10纳秒的时间级别。我们的实验证明，在网络浏览器的环境中，SSBP侧信道攻击是可行的，并且可以替代浏览器中常用的Evict+Reload隐蔽信道。我们在网络浏览器中的Spectre-CTL攻击能够实现大约170 B/s的数据泄露率，准确率为81.1％。  
  
**(3) 进程指纹攻击******  
  
除了瞬时攻击外，SSBP还可以以两种方式被利用来实施侧信道攻击。首先，由于SSBP在上下文切换期间不会被刷新，因此一个进程中有可能泄露某些机密的加载指令的控制流可以通过SSBP披露给另一个进程。其次，哈希函数包含有关物理地址的信息，并可能无意中泄露从虚拟地址到物理地址的映射，而这对于用户空间中的常规用户进程是不可访问的。  
  
我们收集了不同机器学习模型的指纹。用于测试的卷积神经网络（CNN）模型在受害进程中运行，而攻击者将探测进程绑定到同一CPU上。为了量化这些差异并区分不同的模型，我们使用了sklearn模块提供的支持向量机（SVM）来根据它们的相对频率向量对模型进行分类。这种分类方法的准确率超过95.5%，表明我们的指纹技术在成功区分各种CNN模型方面是有效的。  
  
  
  
  
**06 防御措施**  
  
  
  
**（1）通过SSBD和PSFD禁用预测******  
  
我们通过实验发现SSBD修复了屏蔽状态上的所有SSBP和PSFP条目。由于SSBP条目处于屏蔽状态，因此攻击者无法检测到序列之间的时间差异，从而防止了不同进程之间的侧信道。此外，存储和加载是序列化的，因此不可能触发可利用的瞬态窗口，这可以防止SpectreSTL和Spectre-CTL攻击。不过，启用SSBD会对CPU性能产生相当大的影响，因为它会为非混叠加载引入停滞。因此，在Linux内核中，SSBD默认是禁用的。  
  
**（2）其它潜在缓解措施******  
  
尽管禁用推测是一种直接的缓解方法，但显著的性能损失将阻碍其在生产系统中的采用。我们提出了一些潜在的缓解策略，包括：开发一个安全的计时器、在上下文切换期间清空SSBP、随机选择条目。  
  
  
  
**07 总结**  
  
  
  
本文介绍了我们在AMD处理器上推测内存访问安全性方面的逆向和安全分析工作，以及我们在AMD处理器上实现的非原地Spectre-STL攻击、Spectre-CTL攻击以及程序指纹识别侧信道攻击。该研究可使我们更好地理解PSFP和SSBP这两个预测器的内部组织和安全属性。  
  
  
  
