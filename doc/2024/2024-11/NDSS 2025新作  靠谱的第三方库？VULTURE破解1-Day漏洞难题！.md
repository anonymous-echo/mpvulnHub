#  NDSS 2025新作 | 靠谱的第三方库？VULTURE破解1-Day漏洞难题！   
原创 Shangzhi Xu  SecNotes   2024-11-25 19:19  
  
**“**  
 软件开发的时候，使用第三方库（Thrid Party Library, TPL）早已成为开发者的标配，既省时又省力。但方便的背后，往往藏着 1-Day 漏洞的风险。  
  
我们新开发的工具VULTURE@NDSS 25'，通过  
静态  
补  
丁语义分析，能够精确地锁定软件中存在的  
1-Day  
 漏洞并提供详细的修复建议。**”**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELicaicj3FtibnUsXu6oEOOJt1Kd8geayOic8D49p71ySFQCJ5XLibV84AO0pSxndiaXy2VL4xDygwYIYv0C6v8e1OEw/640?wx_fmt=png&from=appmsg "")  
  
## 1. 什么是1-Day漏洞  
  
1-Day 漏洞是指那些**已经公开**的漏洞，虽厂商已经提供了**修复补丁**，但因为软件开发者**没有及时更新**，导致漏洞依然存在于下游软件。这给攻击者创造了机会，用现成的漏洞信息发起攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELicaicj3FtibnTuicicMGCK8icXDY4mpYdde3UvEMFAwic19gG4Ee06mCft2SdGGlKe5lOwPd0ibDdCbKfqSjdlXUU1xA/640?wx_fmt=png&from=appmsg "")  
1. 某个第三方库有漏洞（“Library With Vulnerability”），而软件复用了这个有问题的库（“Software Reused Library”）。  
  
1. 攻击者通过现成的漏洞利用代码（Exploit），修改后直接对这些复用库的应用发起攻击（ATTACK）。  
  
1. 最终，攻击者可能导致系统瘫痪、数据泄露，甚至牟取经济利益。  
  
我们的工具，VULTURE，就是为了解决上述问题，精确找到目标软件中可能存在的1-Day vulnerability。流程图如下：  
  
VULTURE先收集一个包含已知漏洞&漏洞patch的数据库，随后检测目标软件是否包含已知漏洞影响的TPLs版本，如果包含收影响版本，进一步检测是否漏洞已经被patch，从而定位1-Day 漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELicaicj3FtibnTuicicMGCK8icXDY4mpYdde3VBuRnBoicHTvsMdpurf33fMvNrHGR3R5k6EhHuJqaDcWqibvI6OoIxDw/640?wx_fmt=png&from=appmsg "")  
  
## 2. 第三方库复用检测技术  
  
  
要检测出目标软件中是否包含1-Day漏洞，第一步肯定是先确认目标软件究竟复用了哪些第三方库（TPLs），以及它们的具体版本。这是整个检测流程的基础，有了这些信息，我们就可以进一步判断漏洞是否存在以及是否得到了修复。  
### 2.1 数据库构建  
  
要追踪第三方库，首先得有一份“情报库”——包含常见库的版本、函数、以及可能的漏洞信息。  
这个数据库不能随意构建，而应该将同一平台常见的TPLs放在一起，不同平台的TPLs相互分离。  
例如Centris[1]等工具的做法就是尽可能多地把所有常见的数据库都爬下来，构建成一个庞大的数据库。  
这会导致数据库难以维护。  
  
  
并且  
存在一种情况：  
同一个项目针对不同平台，可能发布了不同的第三方库，例如CocoaMQTT，Paho MQTT C/C++ client都是MQTT在不同平台的实现。  
如果构建数据库的时候不区分平台，将会产生大量误报，无法判断目标软件究竟使用了哪个平台的TPL。  
  
  
我们认为，1-Day漏洞检测数据库应该满足以下三个条件：  
- Comprehensive：数据库需要包含目标平台上常用的第三方库。  
  
- Specific：针对特定平台定制数据库，排除其他平台的无关库或非第三方库，避免误报。  
  
- Maintainable：数据库需要易于扩展和更新。  
  
      
  
数据库中的另一个组成部分是patch信息，有了patch信息，我们才能判断目标软件是否已经完成patch。然而patch的收集非常费时费力，NVD[2]等网站上的信息维护并不完美，相当大量的CVE是没有对应的patch信息的。  
  
  
为解决这个问题，VULTURE借助LLMs对Github上的Commit进行自然语言分析，判断当前commit是否和NVD上的漏洞描述相符，如果相符，则认为当前commit就是此CVE对应的patch。  
这一步至关重要，减少了构建数据库所需的大量手动工作。  
### 2.2 复用检测  
  
在构建了高质量的数据库后，下一步就是确认目标软件究竟复用了哪些TPLs以及它们的具体版本。  
  
  
开发者在复用第三方库时，可能会选择直接使用原始代码，但也可能根据项目需求对代码进行修改。这些因素会导致复用检测难度增加。  
- **自定义修改**：开发者对 TPL 的部分代码进行自定义修改，导致直接匹配失败。  
  
- **代码重叠**：不同的 TPL 可能会共享相同或相似的代码片段，容易导致误报。  
  
- **多级依赖**：某些 TPL 本身依赖于其他库（如嵌套依赖），需要区分直接依赖和间接依赖。  
  
  
  
VULTURE的解决方法分为三步骤  
- **找候选库：**通过函数哈希值对比代码，算出每个库的相似度，挑出可能复用的第三方库。  
  
- **确认版本：**分析TPL在目标软件中路径（比如 /libs/mqtt/），结合时间戳，确认具体使用的库和版本**。**  
  
- **优化结果：**通过时间戳先后，排除公共代码，区分直接复用和间接依赖，避免误报**。**  
  
## 3. 1-Day 漏洞检测  
  
当我们知道了目标软件使用的TPLs以及版本后，我们就可以去看究竟目标软件使用的版本是否包含已知漏洞，如果包含的话，目标软件有没有使用合适的patch。  
### 3.1 传统方法  
  
很多工具，甚至是**商用工具**例如SNYK[3]，会通过目标软件里声明的 license 或 copyright 来判断用了哪些第三方库，再去漏洞数据库查这些库的版本是否有问题。然而这会导致很多的问题  
1. **信息不完整：**很多开发者没在代码里明确标注用的是什么库，license 文件可能没写或者写得很随意。  
  
1. **改动难追踪：**即使有库名和版本，代码可能已经被修改过，传统方法也无从判断。  
  
靠这些静态信息去找漏洞，效果不太理想。  
  
  
于是，就有了代码层级上的分析，例如V1SCAN[4]使用的方法是判断patch里出现的代码行是否也在目标软件中出现。这些方法依然存在很多误报，这是因为传统方法忽视了patch的语义信息以及上下文信息，导致了大量的误报。  
### 3.2 Chunk-based Analysis  
  
语义信息，上下文信息，我们第一个想到的是静态分析。但是patch并非可运行代码，只是代码片段。同时静态分析需要编译，需要环境配置，非常复杂。有没有可能找到一个方法，保证足够用的语义和上下文信息被抽取，同时又能快速且方便的使用呢？  
  
  
VULTURE 用了一种叫 **Chunk-based Analysis** 的方法，从代码逻辑入手，包含如下步骤  
- **标准化代码：**把目标软件的代码和补丁代码都格式化，去掉无关信息，比如注释、空行，这样能更好地对比。  
  
- **切分代码块：**按逻辑把代码分成一个个小块（Chunk），比如 if-else、loop这些单元，每个块只关注一个功能和上下文。  
  
- **逐块对比：**拿补丁里的chunk和目标软件的chunk对比，判断需要patch的关键的变量和逻辑有没有被修改到。  
  
- 修改一致，说明漏洞修好了。  
  
- 修改不完整，说明漏洞还在。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELicaicj3FtibnTuicicMGCK8icXDY4mpYdde3TvNicXBZAoTWwQLE6gKGM9zhTczibpKmpqw9aNAkjIu4bficWvm3mrcvw/640?wx_fmt=png&from=appmsg "")  
  
  
## 4. 实验结果  
  
我们对于数据库能力，和1-Day漏洞挖掘能力进行了详细的实验。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELicaicj3FtibnTuicicMGCK8icXDY4mpYdde3R1rQrFBuicVm5ddgRMWfd1gcyzptiav8I07ASJOQ1HMemKXpNppHBibfg/640?wx_fmt=png&from=appmsg "")  
  
数据库构建上，VULTURE成功找到了62%CVE的patch commit，明显强于其他工具。并且VULTURE数据库更新需要的时间比Centris少上千倍。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELicaicj3FtibnTuicicMGCK8icXDY4mpYdde3u7xeVUb7UlibhPY996l09kzojncISiaRhiaBTLg10qNBJVXkiadX6NbdRA/640?wx_fmt=png&from=appmsg "")  
  
同时，分平台数据库的思路（上表DB_iot）明显提升了TPLs 复用检测的检测成功率和准确度。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELicaicj3FtibnTuicicMGCK8icXDY4mpYdde36C3pFCtPKiaNnZiaESLqcSgRn5jaIg7ZmkZHdyad7UW2SiaRMMdZZKkFQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞挖掘上，VULTURE总共找到了175个1-Day漏洞，明显强于传统工具V1SCAN以及商用工具SNYK。  
  
  
[1]   
Centris: A Precise and Scalable Approach for Identifying Modified Open-Source Software Reuse： https://dl.acm.org/doi/10.1109/ICSE43902.2021.00083  
  
[2]NVD: https://nvd.nist.gov/  
  
[3] SNYK https://snyk.io  
  
[4]V1SCAN: Discovering 1-day Vulnerabilities in Reused C/C++ Open-source Software Components Using Code Classification Techniques  
#  https://www.usenix.org/conference/usenixsecurity23/presentation/woo  
  
[5]   
Source code & database: https://anonymous.4open.science/r/Vulture-17BC  
  
  
  
