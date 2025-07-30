#  SinkFinder - 闭源系统半自动漏洞挖掘的尝试   
原创 medi0cr1ty  Medi0cr1ty   2024-06-24 00:25  
  
SinkFinder，一个用于实战场景中快速找到 sink 点及上层代码逻辑链路的半自动化漏洞挖掘工具。  
  
本文主要分享初版的实现思路，后台回复“sinkfinder”即可获取 jar 包，  
**欢迎反馈及交流**。  
  
  
  
**01**  
  
**工具定位**  
  
  
SinkFinder 专注于根据 Sink 规则找上层调用关系，相较于其他工具明显的优势在于短平快，适合时间紧张场景。  
  
SinkFiner 工具实现思路概括即：  
  
首先递归读取 jar / war / zip 中所有 class 节点数据，通过 ASM API 以深度优先遍历的方式找到 sink 点在项目中所有可能触达的路径，sink 点路径存储在本地文件。  
  
在实现过程中考虑到效率等因素，可自定义配置文件路径、jar 包、class 黑白名单，以及 sink 规则。  
  
**02**  
  
**工具实现**  
  
  
**自定义规则 rules.json 中配置**  
：  
- 递归深度  
  
- 黑白名单：目录路径、jar 名、class 类名  
  
- sink 规则配置："类名:方法名[(参数;)]"  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMDSfTsDWqPnh9I3LuKdICByQvKApIVTWKCeibX95jJwA3YicGc252KTStA/640?wx_fmt=png&from=appmsg "")  
  
  
同时为了灵活使用，在工具运行时支持参数配置：  
- -ci、-ji ：class 、jar 的白名单配置  
  
- -s ：sink 规则自定义，同时为了更精准的匹配，支持添加方法参数，如：  
  
- org.test.SerializationUtils:deserialize(Ljava/io/InputStream;)  
  
- -scb ：禁用某类别的规则，如：Fastjson  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMDgniaaNzSlzI5FZEFNcb6sGRTHksKUklIQfXasjc4dnPD9QbXiccjfwpg/640?wx_fmt=png&from=appmsg "")  
  
**03**  
  
**代码实现**  
  
  
大体实现思路为两步：第一步录入class，第二步通过 sink 找路径。  
  
**3.1**  
  
**录入**  
  
  
  
  
  
首先将项目中所有 java class 文件读入并转为 ClassNode 。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMDXKSRvFP2xOR850iaE9SFtib6ibtKgXumNickibDibZdaNARC6QcH0ZAhn1kA/640?wx_fmt=png&from=appmsg "")  
  
这里以 ClassName 为键、ClassInfo 为值存入 ClassRepo 静态属性 classes 中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMDEiaukSCyMx3xvNVYaToVPHoMa7BGSicvc81rViaUEbsbFr0y2duSfjcyQ/640?wx_fmt=png&from=appmsg "")  
  
ClassInfo 中属性包括类节点 ClassNode 、方便找类出处的 jar 包名、以及该类所有子类，方便后期直接查找。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMD25sWa9a9ReOwibKkod82xNlP0z92uJpAXmuub8GAWvhicArmX5mNVQAQ/640?wx_fmt=png&from=appmsg "")  
  
  
录入有个点需要考虑，一个 jar 中嵌套多个 jar ，即 fatjar ，由于所有的 class 文件都要读入，所以需递归读。  
  
**3.2**  
  
**查找**  
  
  
基于第一步中读入的 ClassRepo ，第二步在 ClassRepo 中找到所有可能触达 Sink 点的路径。  
  
第一层遍历 ClassRepo 中的 classes 。为了减少不必要路径查找增加效率，通过配置加载的 class 黑白名单可限制查找范围（读入的时候也可通过 jar 、文件名来限制）。  
  
第二层遍历 ClassNode 中所有的方法调用指令节点。  
  
这里遍历通过数据结构 WrapperNode 实现：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMDJhPj8iaX9L5CUZjFqBd3cFMNGbZNic1MhJicwQZuhfib2QwMqvv5V4FKIw/640?wx_fmt=png&from=appmsg "")  
  
由于递归查找下一层时需要当前方法调用节点的类节点及方法节点组成下一层查找的规则。所以 WrapperNode 中包括类节点、方法节点，以及方法调用指令节点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMD6ODRklQHn5br03wn3LMiaNkh0ib9rLvTHef4aoqyH1mCKcV2Jia3CicIAQ/640?wx_fmt=png&from=appmsg "")  
  
第二层遍历时，通过 sink 规则对应 MethodInsnNode 中 owner 、name、desc 进行匹配。  
  
如果匹配上，则将该节点的类名及方法名存入 ArrayList 中，并代入递归调用第一层的类节点循环。  
  
如果没有匹配上或者判断为**自循环**调用（防死锁），则跳过该方法调用节点，到下一个方法调用节点的循环中。  
  
结束递归两种方式：  
1. 到达指定的最大递归层数；  
  
1. 没有上层调用点。  
  
两层遍历简单示意图 😈  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMDib1mZ7icn17O76LwQ8uicN7Hs4A8N0saib7zNicGcqiauYkTIKVZtzNjeDnw/640?wx_fmt=png&from=appmsg "")  
  
具体代码实现：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMDVaD7sdibPMF4ic7BtssJtIIraCrwFqzicrOExHReic2dQq5xA4oSwE4VDg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
在实现过程的小坑点：  
  
在查找的过程中，因为 java 继承、接口实现等，项目中的方法调用可能不是直接调用，而是通过动态调用，如调用某个子类的方法，而该方法的实现在其父类中。  
  
这种方式需要在查找时考虑当前方法调用节点 MethodInsnNode 的 owner 是否为当前层 sink 的子类/接口类，如果是，则判断存在调用关系。  
  
如下图， A 继承自 B ，C 中某个方法调用了 A 的 test 方法，此时若 sink 为 B 的 test 方法，应将 C.METHOD 记录下来，并进入下一层查找。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZiaGB6iaicqkWjx4qOnicaYLoZsmZZaYKFMDRkOXzzUZoMqneQPG4mrn8Tzr7Adh8DEmnl8PyNGEqgvOpnI241CY7g/640?wx_fmt=png&from=appmsg "")  
  
  
  
接口类亦是如此，只是反过来，若 A 实现 B 接口，C 中某方法调用 B.test ，此时若 Sink 点为 A.test ，同样应将 C.METHOD 记录下来，进入下一层。  
  
**04**  
  
**第2版优化**  
  
  
这种方法实现的 SinkFinder 有天然劣势即不确定参数是否由上层传递而来，仅判断调用路径。第二版支持了通过正向数据流污染与 H  
ook 验证，  
来保证参数  
触及到的路径为最终漏洞路径，但  
有利也有弊，sink  
链路确定性大幅提升的同时牺牲了效率  
，逐步偏向于   
SDL 流程化的非实战场  
景。  
  
  
目前分享第一版，回复“sinkfinder”即可获取，喜欢的话点个赞，谢谢～🌸  
  
  
