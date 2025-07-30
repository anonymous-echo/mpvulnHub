#  成果分享｜Java反序列化漏洞自动化挖掘和可利用性验证   
原创 陈波妃、张磊  复旦白泽战队   2023-12-31 16:23  
  
**元**  
  
**喜迎2024**  
  
**旦**  
  
      
复旦大学系统软件与安全实验室在开源代码治理方面取得新进展。本团队为  
Java  
反序列化漏洞的挖掘和利用上提供了一套高效的端到端的新方案和工具，在各云平台常用的  
Apache Dubbo  
，  
Motan  
，  
Solon  
等流行  
Java  
开源云组件上挖掘出  
127  
个零天的可利用链。研究成果整理成文后发表在网络与信息安全领域四大顶级学术会议中的  
IEEE S&P 2024  
上，第一次投稿就获得评审专家一致好评。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RyyHWbbqW86bQJu9V1CvfZhqWmUE4Pf7xzO4nfzl1ia7D3cwckWHm65RZYiarC6gqP6uT1JZfzzgBg2UN34RKo8Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
01  
  
**背景介绍**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RyyHWbbqW86bQJu9V1CvfZhqWmUE4Pf75xnr0zbD2VGicaYKXInPXeUmG7deSlOc25gvO0hZb7PrpJNy9HDdcqw/640?wx_fmt=png&from=appmsg "")  
  
  
    Java反序列化漏洞是云组件安全中最重要最危险的安全漏洞之一。该类漏洞将广泛应用的Java云组件、微服务架构以及分布式系统暴露于远程代码执行（Remote Code Execution）等高级别安全风险的威胁之下，使得攻击者能远程无接触式操控受影响的云系统或服务。鉴于其广泛的影响范围和严重的潜在后果，这类漏洞通常被赋予极高的风险评级和治理优先级。  
  
  
02  
  
**突破挑战**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RyyHWbbqW86bQJu9V1CvfZhqWmUE4Pf75xnr0zbD2VGicaYKXInPXeUmG7deSlOc25gvO0hZb7PrpJNy9HDdcqw/640?wx_fmt=png&from=appmsg "")  
  
      
  
    为了实现对这类高危漏洞的自动化挖掘与利用，我们突破了两个关键的技术挑战：（1）**Java动态特性**极大地扩增了反序列化程序的潜在执行路径，要充分探索调用链（Gadget Chain）的构造空间需要解决指数级**路径爆炸**问题；（2）为了触发攻击者预期的方法调用序列，注入对象通常具有  
**复杂的类层次结构和字段相关的条件约束**，随机变异难以为调用链生成有效的payload，以验证其可利用性。  
  
  
03  
  
**创新方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RyyHWbbqW86bQJu9V1CvfZhqWmUE4Pf75xnr0zbD2VGicaYKXInPXeUmG7deSlOc25gvO0hZb7PrpJNy9HDdcqw/640?wx_fmt=png&from=appmsg "")  
  
  
    首先，我们设计了一套  
**Gadget片段摘要技术和自底向上的检测方案**，并通过分析和建模，使静态分析引擎具备  
**模拟Java语言动态特性的能力**。其次，我们设计了一种新型数据结构来表征程序执行时的条件约束，以利用  
**定向模糊测试技术进行高效的Payload生成和输入变异**，实现端到端的调用链检测和可利用性验证。下图为我们方案的整体流程：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RyyHWbbqW86bQJu9V1CvfZhqWmUE4Pf7pcZdwZibIxLeusKzNibian4RJ4NAiaePVvibxbNypxhDzWJ8yH48wKg55Sg/640?wx_fmt=png&from=appmsg "")  
  
检测工具架构图  
  
04  
  
**实验评估**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RyyHWbbqW86bQJu9V1CvfZhqWmUE4Pf75xnr0zbD2VGicaYKXInPXeUmG7deSlOc25gvO0hZb7PrpJNy9HDdcqw/640?wx_fmt=png&from=appmsg "")  
  
  
    我们在领域内知名数据集Ysoserial上评估了该方法的有效性，结果显示，相比目前国内外最好的工具，我们的方法能额外检测出近百个之前未公开的利用链。此外，对Apache Dubbo, Sofa-RPC, Solon等多个流行的Java开源组件最新版进行检测，我们  
**检测出127个零天的可利用链**，并获得相关厂商的认可和致谢。  
  
  
  
欢迎大家阅读论文原文（点击“阅读原文”即可查看）：  
  
https://secsys.fudan.edu.cn/ce/78/c26976a642680/page.htm  
  
  
  
  
素材：陈波妃、张磊  
  
供稿：  
陈波妃、张磊  
  
排  
版：孙福特  
  
审核：张琬琪、洪赓、邬梦莹  
  
  
  
  
复旦白泽战队  
  
一个有情怀的安全团队  
  
  
还没有关注复旦白泽战队？  
  
公众号、知乎、微博搜索：复旦白泽战队也能找到我们哦~  
  
