#  美国国家标准局 | 对最危险软件安全漏洞的评估（ACSAC 2020）   
原创 JSY2019  安全学术圈   2023-05-18 11:10  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/6Dibw6L070WEAJAno6d7Aw3WN9SboX15DJiaYRJz4SPQXel6CQJ3AlPpFy6LicWepXgzBW5FClkCsZs6IibxdVa3Qw/640?wx_fmt=jpeg "")  
  
> 原文标题：Measurements of the Most Significant Software Security Weaknesses原文作者：CC Galhardo, P Mell, I Bojanova, A Gueye原文链接：Measurements of the Most Significant Software Security Weaknesses发表会议：ACSAC '20: Annual Computer Security Applications Conference笔记作者：JSY2019@安全学术圈笔记小编：黄诚@安全学术圈  
  
## 背景  
  
截至2019年，有超过17000个软件漏洞被记录。这些大量的漏洞可被映射到很少几种漏洞种类。  
  
CWE于2019年推出了  “前25个最危险的软件错误”（Top 25 Most Dangerous Software Errors， MDSE）。作者提出，由于MDSE的计算公式将存在分布几乎截然不同的两个值：频率和严重度，放在一起计算，导致该计算公式高度偏向于频率，而几乎忽略了严重度的影响。频率的分布存在一个类似于幂函数的曲线，而严重度分布则更加平均。  
  
本文提出了一个评价标准，用于计算“最显著的安全脆弱点”（Most Significant Security Weaknesses， MSSW）。该标准主要基于CWE。同样的，本文通过开源的CVE代码仓库来权衡传播广泛性（publicly announced）；通过CVSS来权衡漏洞的严重度；通过NVD仓库完成CVE-CWE-CVSS的映射。  
## 已有方法的局限性  
  
MDSE基于两个参数：严重性和频率。某个CWE的严重性参数由属于某个CWE条目下所有CVE的CVSS分数的均值决定。某个CWE的频率参数由属于某个CWE条目下的CVE个数和决定。  
  
某个CWE的MDSE的计算步骤是这样的：首先将归一化后的频率参数和归一化后的严重性参数相乘，之后再乘以100。这里的归一化方法采用max-min归一化。  
  
作者提出，MDSE存在着如下的局限性：  
1. 数据分布的不同之处  
  
因频率和严重性的数据分布不同，导致就算MDSE将这两个参数同等处理，也会造成对频率的偏重过高。部分CWE有着非常少的频率，部分CWE有着非常大的频率。下图中，20个红色三角为被MDSE Top 20选中的CWE；其余的为102个黄色点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WEAJAno6d7Aw3WN9SboX15DnibzRiavxRmTNfB2fXKXKd4Xe2bRp64z11jL4YGGCbLeLtkRDrDP2hrA/640?wx_fmt=png "")  
  
对于严重性，相关性便没有那么强了。入选的CWE分布于很广泛的CVSS归一化后的范围。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WEAJAno6d7Aw3WN9SboX15DghAZ4ehELR74gwa1tt0qM6U0LNJcqXcdibFyPpx0vT9voia4yOkg7hxA/640?wx_fmt=png "")  
1. 归一化时的错误  
  
MDSE在归一化时使用了min-max方式。对于CVSS（严重性参数）来说，这种归一化不会形成正态分布。这是因为每个CWE存在的CVE都是不同的，平均后的结果也不同。  
## 作者提出的方法  
  
作者将MDSE的归一化方法和严重度计算方法用以下五个公式进行了替换。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WEAJAno6d7Aw3WN9SboX15DZpjiaHZpgopBlBCbpdQR504HhrNuMe8UmJ6bF4RgHgOpUg2FiaRA4ZQw/640?wx_fmt=png "")  
  
公式（7-9）替换了频率参数的归一化方法。将CVE总数目Ni先经过两次loge后（公式8-9）乘以一个来源于公式（7）的系数k。这三个公式的目的是将CWE频率分布的幂函数趋势转化为接近线性的趋势，解决了局限性1。（下图蓝色为原始分布，黄色和红色分别是loge一次和两次的分布）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WEAJAno6d7Aw3WN9SboX15DaYCSIPbIof5Nhw0BUmR1T5YP01EjSNuqKWD4ebecrhzzB5d3rxicwLw/640?wx_fmt=png "")  
  
对于严重度分布，公式（10）做了一个类似“全局min-max”的归一化。将当前CWE的CVSS分数最大、最小值换为了所有的CWE的CVSS均值的最大、最小值来进行min-max归一化。这样解决了局限性2。  
  
最后，公式（11）将这两个归一化的参数相乘后乘以100。因为是将两个趋势形状较相同的值进行相乘，故得到的结果会更加平均，而非更倾向于哪一个参数的趋势。  
## 实验效果  
  
文章分别把使用MDSE和MSSW的风险分布图做了对比，可见MSSW分布更健康，而MDSE更多偏向于频率趋势。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WEAJAno6d7Aw3WN9SboX15DvL5sOlOB40XvEiaXZbc9x3T8gxHhDDNc3Xuib5Kicgegr8Nz4xOHuDXtA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WEAJAno6d7Aw3WN9SboX15DQqCicsbUR3IVbz2qBqvLVXdugiaVI8wAECaKcQNoic6X6lEg7iaaWmqk6A/640?wx_fmt=png "")  
  
MSSW的参数和CWE预测趋势图。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WEAJAno6d7Aw3WN9SboX15DQ1qEO89YZR8axFXNEGHnrePdneUQehBqJ4nSd4QbfNJ4NovqJYLdew/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WEAJAno6d7Aw3WN9SboX15D6ibKBuNaIISyT0tticksIgZRgF9BLZ0JjhxWbC2qGPjic0Y9bz1P32zYw/640?wx_fmt=png "")  
  
分别以MDSE和MSSW来计算2019 CWE top 20，以及得分与两个参数的相关度：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WEAJAno6d7Aw3WN9SboX15DGf6CZUeOI7LGyicXhGHtRAaKP8jSks7QttzIwkr52S6Fm2FThT3k1rQ/640?wx_fmt=png "")  
## 结论  
  
本文的创新点可简述为通过**修改归一化方法**来做到修改数据分布，从而做到改进CWE重要度排序公式。**通过修改两个归一化公式**，做到了将分布趋势拟合为线性，得到了较好的结果。  
  
> [安全学术圈招募队友-ing](http://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247484475&idx=1&sn=2c91c6a161d1c5bc3b424de3bccaaee0&chksm=fe2efbb0c95972a67513c3340c98e20c752ca06d8575838c1af65fc2d6ddebd7f486aa75f6c3&scene=21#wechat_redirect)  
 有兴趣加入学术圈的请联系   
**secdr#qq.com**  
  
  
  
