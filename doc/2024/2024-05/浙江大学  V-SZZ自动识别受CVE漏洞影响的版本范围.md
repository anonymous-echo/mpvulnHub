#  浙江大学 | V-SZZ:自动识别受CVE漏洞影响的版本范围   
原创 octopus  安全学术圈   2024-05-17 15:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WG8ZAibok7AlDEg9wTiaLibq1rHsz5Y1q8QLGYqhXRicwFNqeF6In5gTNFuhazfb2iaXBMu4lU7b05ST8A/640?wx_fmt=png&from=appmsg "")  
> 原文标题：V-SZZ: Automatic Identification of Version Ranges Affected by CVE Vulnerabilities原作者：Lingfeng Bao，Xin Xia*，Ahmed E. Hassan，Xiaohu Yang发表会议：2022 IEEE/ACM 44th International Conference on Software Engineering (ICSE)原文链接：https://ieeexplore.ieee.org/document/9794006主题类型：漏洞版本影响、SZZ、V-SZZ笔记作者：octopus  
  
# 概述  
  
过去对漏洞的研究主要为漏洞管理，漏洞补丁，漏洞识别等，很少有研究漏洞所影响的版本问题。但是，漏洞影响版本是很值得探讨的问题，因为许多政府、企业等所用的软件严重依赖NVD、CVE等漏洞数据库所揭露的漏洞来制定软件安全策略，若当前使用的版本存在脆弱版本，则需要执行打补丁更新等操作。但是，NVD等数据库所揭露的版本不一定正确，这就导致了企业和软件供应链可能错误的更新补丁，造成人力资源等浪费。  
  
基于上述问题，作者评估了SZZ算法以及出现的许多变体的SZZ(AG-SZZ, MA-SZZ, 和 RA-SZZ)算法是否能够准确的识别漏洞诱导提交，并对原始的SZZ算法改进，提出了V-SZZ算法，以之前的算法为基线，得出了改进的V-SZZ算法准确度，并基于诱导提交有效地细化脆弱版本，再手工验证了受这些漏洞影响的软件版本，得出最后结果。  
# 论文工作  
- 构建链接CVE漏洞的数据集，涵盖c/c++项目和Java项目，并手工验证了受这些漏洞影响的软件版本  
  
- 验证传统的SZZ算法是否能正确找出诱导提交以及判断出正确的脆弱版本  
  
- 基于SZZ算法提出改进算法，使得该方法能够更有效识别漏洞诱导提交并据此细化脆弱版本  
  
# 数据集  
  
包含以下语言的各项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WG8ZAibok7AlDEg9wTiaLibq1r64AL98gozhTibrJ7iabT1zvHZKIicGHg4uicZBL6Fbogaup5oPAlewF0Yw/640?wx_fmt=png&from=appmsg "")  
- Vul：漏洞数  
  
- VFC：漏洞Fixing commits数  
  
- ZERO：没有删除行的漏洞修复提交  
  
- SMALL：多于0少于等于5的删除行提交  
  
- LARGE：多于5行的删除代码提交  
  
作者排除了四类样本：  
1. 没有在CVE、NVD数据库中的漏洞  
  
1. ZERO类漏洞，因为这种情况可认为所有代码都为漏洞代码，即为Inducing commits  
  
1. LARGE类漏洞，删除行太多，不易识别此类代码行  
  
1. 项目版本标签与NVD发布的版本没有任何对应的漏洞  
  
因此，最后实验数据集从剩下的C/C++每个项目中随机挑选20个漏洞共计100个，41个Java项目中剩余的72个漏洞，共计**172**个漏洞总数和**188**个提交  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WG8ZAibok7AlDEg9wTiaLibq1rIdpFiaau8YWPacDTibtnut4RnIYAmQhs8tBj2AibGQ8XE4Jxsol4cA4Ug/640?wx_fmt=png&from=appmsg "")  
# 实验方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WG8ZAibok7AlDEg9wTiaLibq1rD6rrtqVmxtibrJGGU0kKAdyQewqvLLLw7ANLjOyQH48xCXgmCltShWw/640?wx_fmt=png&from=appmsg "")  
- Inducing commits：第一个诱导漏洞的提交  
  
- Fixing commits：解决漏洞的提交  
  
- Duplicated fixing commits：将Fixing commits合并到另一分支上的提交  
  
- Previous commits：Fixing commits的前一个提交  
  
- descendants commits：在改变Fixing commits修改的行之前的所有提交  
  
## 实验步骤  
### R1. Identify inducing commits  
  
原始的VSS算法认为previous commits即为inducing commits，这是不精确的。因为在previous commits之前的提交很有可能存在引发漏洞的某几行代码的更改，意味着previous commits不是第一个修改Fixing commits修改的行的提交，在之前的存在称为descendants commits，找到第一个修改那些行的提交才能认为是inducing commits  
#### 寻找方法  
  
对于修复提交的每一个修改行，使用**git blame**命令去识别之前的提交(忽略非语义行代码)，然后应用行映射算法，去将修改的行映射到识别到的之前的提交的那一行，接着使用**git blame**迭代上述步骤，直到找到映射出的行被作为新行，第一次被加在代码里，那此时的提交即为Inducing commit  
#### 行映射算法  
- Java项目：使用语法树(AST)来映射修改行  
  
- C/C++项目：使用行间的字符串相似性与本地化映射  
  
### R2. Duplicated change detection  
  
在一个项目中，把一个分支的某个提交提交到另一个分支上是很常见的，通常使用命令**git cherry-pick**实现。如果仅仅对某一个分支执行**git blame**指令，可能会忽略掉其他的分支，导致结果不准确。  
#### 寻找方法  
  
如果使用命令**git cherry-pick**实现，通常会存在git消息中生成“herry picked from commit xxx”，据此可以轻易的判断出这个提交是从哪个分支上提交过来，但若没有此消息，作者将所有的提交块进行哈希，当给定一个提交时，可以将其哈希并且与所有哈希进行匹配，匹配成功的那些提交块则认为是复制过去的提交  
### R3. 寻找脆弱版本  
  
根据上面找的Inducing commits，再找到可抵达其的提交(可抵达意味着他们两个提交属于相同的祖先或父母)的版本号作为  
，然后在找到可抵达Fixing commits的提交的版本号作为  
，两者的差值即为脆弱版本集合  
# 实验结果  
  
对于C/C++和Java项目，其召回率和精确度和F1分数基本都领先其余SZZ算法，其在检测诱导提交和正确的版本号都具有更显著的效果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WG8ZAibok7AlDEg9wTiaLibq1rJL0BKAian05SibB0PSOaQeQgVvfARTLXicOooAn6fUDUqfZqPucwtXAicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WG8ZAibok7AlDEg9wTiaLibq1raDWgUMFLjfwlyzib2n2OKIvZIC8yM2eGv27zl3jU6KH68uqjqYNOY4A/640?wx_fmt=png&from=appmsg "")  
# 个人思考  
## 实验不足  
- 选择的数据集太少，导致应用型较弱  
  
- 在进行行映射时准确度不高，有误报  
  
- 无法应对较多行代码修改的情形  
  
- 只针对两种编程语言  
  
- 手工标注提交效率低，容易出错，在大数据集下难以实行  
  
## 改进点  
1. 增加编程语言  
  
1. 利用nlp技术进行代码匹配  
  
1. 改进标注方法  
  
1. 尝试新的办法而不是只专注对漏洞代码行更改的地方  
  
  
  
> [安全学术圈招募队友-ing](http://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247484475&idx=1&sn=2c91c6a161d1c5bc3b424de3bccaaee0&chksm=fe2efbb0c95972a67513c3340c98e20c752ca06d8575838c1af65fc2d6ddebd7f486aa75f6c3&scene=21#wechat_redirect)  
 有兴趣加入学术圈的请联系   
**secdr#qq.com**  
  
  
  
