#  CNNVD发布《2022年度网络安全漏洞态势报告》   
 中国信息安全   2023-07-21 18:53  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wMI6t5fciagatLNlHF6LEk914JTeI81ZSWUTxtS79Ng8bJ4ZDt1ob87cJ7iaIVYiaXWkxibThHxlAJtQ/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wMI6t5fciagatLNlHF6LEk914JTeI81ZSWUTxtS79Ng8bJ4ZDt1ob87cJ7iaIVYiaXWkxibThHxlAJtQ/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1brjUjbpg5wMI6t5fciagatLNlHF6LEk9QaI4K2XP9aI86eaoCO6Y5ibnp5xtXcgvnbqrC0J95ibf9B7ic7dGwo4icg/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wMI6t5fciagatLNlHF6LEk914JTeI81ZSWUTxtS79Ng8bJ4ZDt1ob87cJ7iaIVYiaXWkxibThHxlAJtQ/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wMI6t5fciagatLNlHF6LEk914JTeI81ZSWUTxtS79Ng8bJ4ZDt1ob87cJ7iaIVYiaXWkxibThHxlAJtQ/640?wx_fmt=gif "")  
  
**扫码订阅《中国信息安全》**  
  
邮发代号 2-786  
  
征订热线：010-82341063  
  
  
**报告摘要：**  
  
本报告基于2022年国家信息安全漏洞库（CNNVD）发布的漏洞数据，统计数量增长、类型、严重等级、修复和攻击危害等情况，分析研判漏洞发展趋势和特点，并研究提出漏洞防范和缓解的工作思路。  
  
2022年度新增漏洞近2万5千个，达到历史新高，保持连年增长态势。超高危级漏洞占比呈持续上升趋势，漏洞修复率大幅提升，面临漏洞威胁形势依然严峻。整体形势出现新变化，呈现高风险漏洞数量突破新高、零日争夺凸显攻防新较量、单边漏洞管控扰乱国际秩序、网络霸权主义冲击网空权益等特点，网络安全整体形势更加复杂严峻。  
  
漏洞风险关乎国家安全，治理漏洞风险是维护国家安全和保障网络安全的必然要求，要着力促进漏洞治理国际合作机制，推动漏洞治理国家机制顺畅，营造良好的漏洞生态环境，加强漏洞感知机制和手段建设，加快漏洞标准制定和体系建设，以实现高水平漏洞风险治理自立自强。  
  
# 一、公开漏洞情况  
  
2022年新增漏洞近2万5千个，达到历史新高，保持连年增长态势。超高危级漏洞占比呈持续上升趋势，漏洞修复率大幅提升，面临漏洞威胁形势依然严峻。截至2022年，CNNVD合计发布漏洞信息199465条，2022年新增漏洞信息24801条。从漏洞危害及修复情况来看，2022年新增漏洞中，超危漏洞4200个，高危漏洞9968个，中危漏洞10146个，低危漏洞487个，相应修复率分别为54.86%、79.65%、76.13%和91.38%，整体修复率为77.76%。从厂商分布来看，Google是2022年产品漏洞数量最多的厂商，共新增漏洞1411个，排名第二的是Microsoft漏洞数量是963个。从漏洞类型来看，跨站脚本类漏洞3217个，占总量12.97%，占比最高。  
## （一）漏洞增长情况  
  
2022年新增漏洞24801个，较2021年相比涨幅19.28%，增速显著。2018至2022年漏洞新增数量统计如图1所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn240UsyRuPZU6ouQjxicFsCUxOsWjN287VjwvN7UK78vxD46GiatBaETTg/640?wx_fmt=png "")  
  
**图1  2018至2022年漏洞新增数量对比统计图**  
  
近年来，漏洞数量逐年递增，2018至2022年漏洞数量涨幅趋势如图2所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2HyEWJTqW5HadFPB3CZnPXp6ol8a6pVGbQgrkcx9U3emEjzibEuqibPmg/640?wx_fmt=png "")  
  
**图2  2018至2022年漏洞数量涨幅趋势图**  
  
2022年1至12月新增漏洞数量分布如图3所示，2022年每月新增漏洞约2067个，较上年月增334个。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2uMeQEmZ2Iic3kENMoL7Cd82iaChoITlRSpbgVTZG9oYXqTrC9zaBjiaxw/640?wx_fmt=png "")  
  
**图3  2022年1至12月漏洞数量分布情况**  
##   
## （二）漏洞分布情况  
### 1、漏洞厂商分布  
  
2022年国外厂商漏洞数量22087个，占比89.06%；国内厂商漏洞数量2714个，占比10.94%，较上年增长3个百分点。总体情况仍呈现国外厂商漏洞数量比重较大的态势，2018至2022年国内外厂商漏洞数量结构对比如图4所示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2lHLDj1DpO0fkXW6QiaapGlME3GU20MUBmyLOvD1PkybicUQ3F9GicFoMw/640?wx_fmt=png "")  
  
**图4  2018至2022年国内外厂商漏洞数量结构对比图**  
  
**（1）国外厂商漏洞分布**  
  
2022年漏洞数量排名前十的国外厂商分布见表1所示，前五名厂商是Google、Microsoft、Oracle、IBM、Adobe。Google产品漏洞数量为1411个，名列第一。  
  
**表1  2022年新增漏洞数量排名前十国外厂商统计表**  
<table><tbody><tr><td style="word-break: break-all;"><p><strong><span style="font-size: 16px;">序号</span></strong></p></td><td width="193"><p><strong><span style="font-size: 16px;">厂商名称 （国别）</span></strong></p></td><td width="175"><p><strong><span style="font-size: 16px;">漏洞数量</span></strong></p></td><td width="139" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">所占比例</span></strong></p></td></tr><tr><td><p><span style="font-size: 16px;">1</span></p></td><td width="46"><p><span style="font-size: 16px;">Google（美）</span></p></td><td width="161"><p><span style="font-size: 16px;">1411</span></p></td><td width="139"><p><span style="font-size: 16px;">5.69%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">2</span></p></td><td width="46"><p><span style="font-size: 16px;">Microsoft（美）</span></p></td><td width="161"><p><span style="font-size: 16px;">963</span></p></td><td width="139"><p><span style="font-size: 16px;">3.88%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">3</span></p></td><td width="46"><p><span style="font-size: 16px;">Oracle（美）</span></p></td><td width="161"><p><span style="font-size: 16px;">417</span></p></td><td width="139"><p><span style="font-size: 16px;">1.68%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">4</span></p></td><td width="46"><p><span style="font-size: 16px;">IBM（美）</span></p></td><td width="161"><p><span style="font-size: 16px;">417</span></p></td><td width="139"><p><span style="font-size: 16px;">1.68%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">5</span></p></td><td width="46"><p><span style="font-size: 16px;">Adobe（美）</span></p></td><td width="161"><p><span style="font-size: 16px;">417</span></p></td><td width="139"><p><span style="font-size: 16px;">1.68%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">6</span></p></td><td width="46"><p><span style="font-size: 16px;">Apple（美）</span></p></td><td width="161"><p><span style="font-size: 16px;">389</span></p></td><td width="139"><p><span style="font-size: 16px;">1.57%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">7</span></p></td><td width="46"><p><span style="font-size: 16px;">Samsung（韩）</span></p></td><td width="161"><p><span style="font-size: 16px;">359</span></p></td><td width="139"><p><span style="font-size: 16px;">1.45%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">8</span></p></td><td width="46"><p><span style="font-size: 16px;">Cisco（美）</span></p></td><td width="161"><p><span style="font-size: 16px;">344</span></p></td><td width="139"><p><span style="font-size: 16px;">1.39%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">9</span></p></td><td width="46"><p><span style="font-size: 16px;">Siemens（德）</span></p></td><td width="161"><p><span style="font-size: 16px;">300</span></p></td><td width="139"><p><span style="font-size: 16px;">1.21%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">10</span></p></td><td width="46"><p><span style="font-size: 16px;">Intel（美）</span></p></td><td width="161"><p><span style="font-size: 16px;">239</span></p></td><td width="139"><p><span style="font-size: 16px;">0.96%</span></p></td></tr><tr><td colspan="2" width="46" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">合计</span></strong><span style="font-size: 16px;"></span></p></td><td width="161"><p><span style="font-size: 16px;">5256</span></p></td><td width="139"><p><span style="font-size: 16px;">21.19%</span></p></td></tr></tbody></table>  
**（2）国内厂商漏洞分布**  
  
2022年漏洞数量排名前十的厂商分布如表2所示，前三名厂商是腾达、华为和吉翁电子，腾达产品漏洞数量达450个，占2022年国内厂商新增漏洞总数的16.58%。  
  
**表2  2022年新增漏洞数量排名前十国内厂商统计表**  
<table><tbody><tr><td width="69" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">序号</span></strong></p></td><td width="162"><p><strong><span style="font-size: 16px;">厂商名称（地区）</span></strong></p></td><td width="133"><p><strong><span style="font-size: 16px;">漏洞数量</span></strong></p></td><td width="146"><p><strong><span style="font-size: 16px;">所占比例</span></strong></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">1</span></p></td><td width="182"><p><span style="font-size: 16px;">腾达</span></p></td><td width="153"><p><span style="font-size: 16px;">450</span></p></td><td width="146"><p><span style="font-size: 16px;">16.58%</span></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">2</span></p></td><td width="182"><p><span style="font-size: 16px;">华为</span></p></td><td width="153"><p><span style="font-size: 16px;">262</span></p></td><td width="146"><p><span style="font-size: 16px;">9.65%</span></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">3</span></p></td><td width="182"><p><span style="font-size: 16px;">吉翁电子</span></p></td><td width="153"><p><span style="font-size: 16px;">219</span></p></td><td width="146"><p><span style="font-size: 16px;">8.07%</span></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">4</span></p></td><td width="182"><p><span style="font-size: 16px;">联发科（台）</span></p></td><td width="153"><p><span style="font-size: 16px;">209</span></p></td><td width="146"><p><span style="font-size: 16px;">7.70%</span></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">5</span></p></td><td width="182"><p><span style="font-size: 16px;">友讯（台）</span></p></td><td width="153"><p><span style="font-size: 16px;">146</span></p></td><td width="146"><p><span style="font-size: 16px;">5.38%</span></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">6</span></p></td><td width="182"><p><span style="font-size: 16px;">新华三</span></p></td><td width="153"><p><span style="font-size: 16px;">100</span></p></td><td width="146"><p><span style="font-size: 16px;">3.68%</span></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">7</span></p></td><td width="182"><p><span style="font-size: 16px;">睿联</span></p></td><td width="153"><p><span style="font-size: 16px;">89</span></p></td><td width="146"><p><span style="font-size: 16px;">3.28%</span></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">8</span></p></td><td width="182"><p><span style="font-size: 16px;">紫光展锐</span></p></td><td width="153"><p><span style="font-size: 16px;">76</span></p></td><td width="146"><p><span style="font-size: 16px;">2.80%</span></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">9</span></p></td><td width="182"><p><span style="font-size: 16px;">普联</span></p></td><td width="153"><p><span style="font-size: 16px;">63</span></p></td><td width="146"><p><span style="font-size: 16px;">2.32%</span></p></td></tr><tr><td width="33"><p><span style="font-size: 16px;">10</span></p></td><td width="182"><p><span style="font-size: 16px;">福昕</span></p></td><td width="153"><p><span style="font-size: 16px;">55</span></p></td><td width="146"><p><span style="font-size: 16px;">2.03%</span></p></td></tr><tr><td colspan="2" width="113" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">合计</span></strong></p></td><td width="153"><p><strong><span style="font-size: 16px;">1669</span></strong></p></td><td width="146"><p><strong><span style="font-size: 16px;">61.5%</span></strong></p></td></tr></tbody></table>### 2、漏洞影响产品分布  
  
**（1）操作系统漏洞分布**  
  
2022年影响操作系统新增漏洞为6392个，2018年至2022年操作系统漏洞数量统计如图5所示，较上年下降18.1%。2022年主流操作系统漏洞数量及操作系统漏洞总量占比统计如表3所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2ia5UmM7ph0hO9fkrnClrNkkuWpHR3HZ2OCl6XA7tWX1xUFW7Ckow7lg/640?wx_fmt=png "")  
  
**图5  2018至2021年操作系统漏洞数量对比统计图**  
  
**表3  2022年主流操作系统漏洞数量统计表**  
<table><tbody><tr><td style="word-break: break-all;"><p><strong><span style="font-size: 16px;">序号</span></strong></p></td><td width="261"><p><strong><span style="font-size: 16px;">操作系统名称</span></strong></p></td><td width="83"><p><strong><span style="font-size: 16px;">漏洞数量</span></strong></p></td><td width="113"><p><strong><span style="font-size: 16px;">所占比例</span></strong></p></td></tr><tr><td><p><span style="font-size: 16px;">1</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows Server 2022</span></p></td><td width="103"><p><span style="font-size: 16px;">583</span></p></td><td width="113"><p><span style="font-size: 16px;">9.12%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">2</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows Server 2019</span></p></td><td width="103"><p><span style="font-size: 16px;">569</span></p></td><td width="113"><p><span style="font-size: 16px;">8.90%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">3</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows 10</span></p></td><td width="103"><p><span style="font-size: 16px;">543</span></p></td><td width="113"><p><span style="font-size: 16px;">8.49%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">4</span></p></td><td width="44"><p><span style="font-size: 16px;">Android</span></p></td><td width="103"><p><span style="font-size: 16px;">524</span></p></td><td width="113"><p><span style="font-size: 16px;">8.20%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">5</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows 11</span></p></td><td width="103"><p><span style="font-size: 16px;">517</span></p></td><td width="113"><p><span style="font-size: 16px;">8.09%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">6</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows Server 2016</span></p></td><td width="103"><p><span style="font-size: 16px;">512</span></p></td><td width="113"><p><span style="font-size: 16px;">8.01%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">7</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows Server 2012</span></p></td><td width="103"><p><span style="font-size: 16px;">431</span></p></td><td width="113"><p><span style="font-size: 16px;">6.74%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">8</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows Server 2012 R2</span></p></td><td width="103"><p><span style="font-size: 16px;">430</span></p></td><td width="113"><p><span style="font-size: 16px;">6.73%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">9</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows 8.1</span></p></td><td width="103"><p><span style="font-size: 16px;">391</span></p></td><td width="113"><p><span style="font-size: 16px;">6.12%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">10</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows Rt 8.1</span></p></td><td width="103"><p><span style="font-size: 16px;">378</span></p></td><td width="113"><p><span style="font-size: 16px;">5.91%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">11</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows Server 2008</span></p></td><td width="103"><p><span style="font-size: 16px;">344</span></p></td><td width="113"><p><span style="font-size: 16px;">5.38%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">12</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows Server 2008 R2</span></p></td><td width="103"><p><span style="font-size: 16px;">343</span></p></td><td width="113"><p><span style="font-size: 16px;">5.37%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">13</span></p></td><td width="44"><p><span style="font-size: 16px;">Windows 7</span></p></td><td width="103"><p><span style="font-size: 16px;">323</span></p></td><td width="113"><p><span style="font-size: 16px;">5.05%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">14</span></p></td><td width="44"><p><span style="font-size: 16px;">Linux Kernel</span></p></td><td width="103"><p><span style="font-size: 16px;">200</span></p></td><td width="113"><p><span style="font-size: 16px;">3.13%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">15</span></p></td><td width="44"><p><span style="font-size: 16px;">Apple macOS</span></p></td><td width="103"><p><span style="font-size: 16px;">154</span></p></td><td width="113"><p><span style="font-size: 16px;">2.41%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">16</span></p></td><td width="44"><p><span style="font-size: 16px;">Apple iOS</span></p></td><td width="103"><p><span style="font-size: 16px;">150</span></p></td><td width="113"><p><span style="font-size: 16px;">2.35%</span></p></td></tr></tbody></table>  
**（2）应用产品漏洞分布**  
  
2022年新增应用产品漏洞总量为18889个，较上年增长23.14%；超高危级漏洞数量为10266个，占应用产品漏洞总量54.35%，较上年上浮九个百分点。2022年前十应用产品漏洞数量统计如表4所示，2018至2022年应用产品漏洞数量统计如图6所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2HoR3GuQo6WazE8Y1LvgZkV6IXawzMvJBiceJ4E4NpQO5Qam6r9dibItA/640?wx_fmt=png "")  
  
**图6  2018至2022年应用产品漏洞数量对比统计图**  
  
**表4  2022年应用产品漏洞数量前十统计表**  
<table><tbody><tr><td style="word-break: break-all;"><p><strong><span style="font-size: 16px;">序号</span></strong></p></td><td><p><strong><span style="font-size: 16px;">应用产品名称（厂商名称）</span></strong></p></td><td><p><strong><span style="font-size: 16px;">漏洞数量</span></strong></p></td><td><p><strong><span style="font-size: 16px;">所占比例</span></strong></p></td></tr><tr><td><p><span style="font-size: 16px;">1</span></p></td><td><p><span style="font-size: 16px;">Chrome (Google)</span></p></td><td><p><span style="font-size: 16px;">360</span></p></td><td><p><span style="font-size: 16px;">1.91%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">2</span></p></td><td><p><span style="font-size: 16px;">On Command Insight (NetApp)</span></p></td><td><p><span style="font-size: 16px;">214</span></p></td><td><p><span style="font-size: 16px;">1.13%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">3</span></p></td><td><p><span style="font-size: 16px;">MicroStation/Bentley View (Bentley)</span></p></td><td><p><span style="font-size: 16px;">181</span></p></td><td><p><span style="font-size: 16px;">0.96%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">4</span></p></td><td><p><span style="font-size: 16px;">On Workflow Automatin (NetApp)</span></p></td><td><p><span style="font-size: 16px;">177</span></p></td><td><p><span style="font-size: 16px;">0.94%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">5</span></p></td><td><p><span style="font-size: 16px;">TensorFlow (Google)</span></p></td><td><p><span style="font-size: 16px;">164</span></p></td><td><p><span style="font-size: 16px;">0.87%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">6</span></p></td><td><p><span style="font-size: 16px;">GitLab (GitLab)</span></p></td><td><p><span style="font-size: 16px;">163</span></p></td><td><p><span style="font-size: 16px;">0.86%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">7</span></p></td><td><p><span style="font-size: 16px;">FireFox (Mozilla)</span></p></td><td><p><span style="font-size: 16px;">157</span></p></td><td><p><span style="font-size: 16px;">0.83%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">8</span></p></td><td><p><span style="font-size: 16px;">Active Iq Unified Manager (Netapp)</span></p></td><td><p><span style="font-size: 16px;">154</span></p></td><td><p><span style="font-size: 16px;">0.82%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">9</span></p></td><td><p><span style="font-size: 16px;">Acrobat Reader DC (Adobe)</span></p></td><td><p><span style="font-size: 16px;">126</span></p></td><td><p><span style="font-size: 16px;">0.67%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">10</span></p></td><td><p><span style="font-size: 16px;">Acrobat Reader (Adobe)</span></p></td><td><p><span style="font-size: 16px;">126</span></p></td><td><p><span style="font-size: 16px;">0.67%</span></p></td></tr><tr><td colspan="2" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">合计</span></strong><span style="font-size: 16px;"></span></p></td><td><p><span style="font-size: 16px;">1822</span></p></td><td><p><span style="font-size: 16px;">9.65%</span></p></td></tr></tbody></table>  
**表5  2022年应用产品超高危漏洞数量前十统计表**  
<table><tbody><tr><td width="65" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">序号</span></strong></p></td><td width="255"><p><strong><span style="font-size: 16px;">应用产品名称（厂商名称）</span></strong></p></td><td width="91"><p><strong><span style="font-size: 16px;">漏洞数量</span></strong></p></td><td width="108"><p><strong><span style="font-size: 16px;">所占比例</span></strong></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">1</span></p></td><td width="255"><p><span style="font-size: 16px;">Chrome (Google)</span></p></td><td width="111"><p><span style="font-size: 16px;">258</span></p></td><td width="108"><p><span style="font-size: 16px;">2.51%</span></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">2</span></p></td><td width="255"><p><span style="font-size: 16px;">MicroStation (Bentley)</span></p></td><td width="111"><p><span style="font-size: 16px;">131</span></p></td><td width="108"><p><span style="font-size: 16px;">1.28%</span></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">3</span></p></td><td width="255"><p><span style="font-size: 16px;">TensorFlow (Google)</span></p></td><td width="111"><p><span style="font-size: 16px;">104</span></p></td><td width="108"><p><span style="font-size: 16px;">1.01%</span></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">4</span></p></td><td width="255"><p><span style="font-size: 16px;">Vim (Vim)</span></p></td><td width="111"><p><span style="font-size: 16px;">95</span></p></td><td width="108"><p><span style="font-size: 16px;">0.93%</span></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">5</span></p></td><td width="255"><p><span style="font-size: 16px;">FireFox (Mozilla)</span></p></td><td width="111"><p><span style="font-size: 16px;">82</span></p></td><td width="108"><p><span style="font-size: 16px;">0.80%</span></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">6</span></p></td><td width="255"><p><span style="font-size: 16px;">Acrobat Reader DC/Acrobat DC (Adobe)</span></p></td><td width="111"><p><span style="font-size: 16px;">73</span></p></td><td width="108"><p><span style="font-size: 16px;">0.71%</span></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">7</span></p></td><td width="255"><p><span style="font-size: 16px;">View (Bentley)</span></p></td><td width="111"><p><span style="font-size: 16px;">70</span></p></td><td width="108"><p><span style="font-size: 16px;">0.68%</span></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">8</span></p></td><td width="255"><p><span style="font-size: 16px;">Thunderbird (Mozilla)</span></p></td><td width="111"><p><span style="font-size: 16px;">62</span></p></td><td width="108"><p><span style="font-size: 16px;">0.60%</span></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">9</span></p></td><td width="255"><p><span style="font-size: 16px;">Bentley View (Bentley)</span></p></td><td width="111"><p><span style="font-size: 16px;">61</span></p></td><td width="108"><p><span style="font-size: 16px;">0.59%</span></p></td></tr><tr><td width="70"><p><span style="font-size: 16px;">10</span></p></td><td width="255"><p><span style="font-size: 16px;">Microstation Connect (Bentley)</span></p></td><td width="111"><p><span style="font-size: 16px;">58</span></p></td><td width="108"><p><span style="font-size: 16px;">0.56%</span></p></td></tr><tr><td colspan="2" width="46" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">合计</span></strong><span style="font-size: 16px;"></span></p></td><td width="111"><p><span style="font-size: 16px;">994</span></p></td><td width="108"><p><span style="font-size: 16px;">9.68%</span></p></td></tr></tbody></table>  
**3、漏洞类型分布**  
  
2022年漏洞数量排名前十的漏洞类型统计如表5所示，其中排名前五的漏洞类型为跨站脚本、缓冲区错误、SQL注入、代码问题及输入验证错误，累计11246个漏洞，占比达45.34%，接近漏洞总量一半。  
  
**表5  2022年漏洞数量排名前十的漏洞类型统计表**  
<table><tbody><tr><td style="word-break: break-all;"><p><strong><span style="font-size: 16px;">序号</span></strong></p></td><td><p><strong><span style="font-size: 16px;">漏洞类型</span></strong></p></td><td><p><strong><span style="font-size: 16px;">漏洞数量</span></strong></p></td><td><p><strong><span style="font-size: 16px;">所占比例</span></strong></p></td></tr><tr><td><p><span style="font-size: 16px;">1</span></p></td><td><p><span style="font-size: 16px;">跨站脚本</span></p></td><td><p><span style="font-size: 16px;">3217</span></p></td><td><p><span style="font-size: 16px;">12.97%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">2</span></p></td><td><p><span style="font-size: 16px;">缓冲区错误</span></p></td><td><p><span style="font-size: 16px;">3155</span></p></td><td><p><span style="font-size: 16px;">12.72%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">3</span></p></td><td><p><span style="font-size: 16px;">SQL注入</span></p></td><td><p><span style="font-size: 16px;">1747</span></p></td><td><p><span style="font-size: 16px;">7.04%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">4</span></p></td><td><p><span style="font-size: 16px;">代码问题</span></p></td><td><p><span style="font-size: 16px;">1653</span></p></td><td><p><span style="font-size: 16px;">6.67%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">5</span></p></td><td><p><span style="font-size: 16px;">输入验证错误</span></p></td><td><p><span style="font-size: 16px;">1474</span></p></td><td><p><span style="font-size: 16px;">5.94%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">6</span></p></td><td><p><span style="font-size: 16px;">资源管理错误</span></p></td><td><p><span style="font-size: 16px;">1138</span></p></td><td><p><span style="font-size: 16px;">4.59%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">7</span></p></td><td><p><span style="font-size: 16px;">路径遍历</span></p></td><td><p><span style="font-size: 16px;">666</span></p></td><td><p><span style="font-size: 16px;">2.69%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">8</span></p></td><td><p><span style="font-size: 16px;">跨站请求伪造</span></p></td><td><p><span style="font-size: 16px;">632</span></p></td><td><p><span style="font-size: 16px;">2.55%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">9</span></p></td><td><p><span style="font-size: 16px;">授权问题</span></p></td><td><p><span style="font-size: 16px;">569</span></p></td><td><p><span style="font-size: 16px;">2.29%</span></p></td></tr><tr><td><p><span style="font-size: 16px;">10</span></p></td><td><p><span style="font-size: 16px;">信息泄露</span></p></td><td><p><span style="font-size: 16px;">502</span></p></td><td><p><span style="font-size: 16px;">2.02%</span></p></td></tr></tbody></table>  
依据2022年漏洞数量排名前十的漏洞类型，即跨站脚本、缓冲区错误、输入验证错误、代码问题、资源管理错误、信息泄露、SQL注入、授权问题、访问控制错误、路径遍历，对2018至2022年前十漏洞类型做对比统计如图7所示，跨站脚本与缓冲区错误持续增长较快并保持前两名的地位。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2XlJot3gWtEBiajTlQLKvon07d9nk4HpY9KKgJELFroKCrvhC1dO7CVA/640?wx_fmt=png "")  
  
**图7  2018年至2022年前十漏洞类型对比统计图**  
### 4、漏洞严重等级分布  
  
根据漏洞的影响范围、利用难度、攻击效果等综合因素，漏洞严重等级分为超危、高危、中危和低危等四个级别。2022年漏洞严重等级分布统计如图8所示，超危4200个、高危9968个、中危10146个、低危487个，超高危漏洞占比57.12%，较上年增长三个百分点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2h7noOVzeQKXruyph6yqd8Fcavx516CGL4tQb7VamxHLBBhePJ2JCWA/640?wx_fmt=png "")  
  
**图8  2022年漏洞严重等级分布统计图**  
  
2018至2022年漏洞危害等级分布如图9所示，高风险漏洞呈持续上升趋势。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2FEeEniaqdTbxWwMTq0epoW4icPXagt2LBc7bgjMzt3R119uNEibC0eu8g/640?wx_fmt=png "")  
  
**图9  2018至2022年漏洞严重等级对比统计图**  
## （三）漏洞修复情况  
### 1、整体修复情况  
  
2022年漏洞修复情况统计如图10所示，漏洞整体修复率为77.76%，较上年下浮十个百分点，其中超高危漏洞修复率为72.3%，低于上年15个百分点。2018至2022年漏洞修复率对比统计如图11所示，整体和超高危修复率均有明显降低。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2K5G4YZnlZ3icXQibn8B9ibg6KVibpEHMnZmSOJZKq4Npj3jU0yEejLPpKw/640?wx_fmt=png "")  
  
**图10  2022年漏洞修复情况统计图**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2YgibyUoiaLIZH0FFg7xOc7XPhLRIhECxGphvbBsrvpqqc1MsytP4Sy3w/640?wx_fmt=png "")  
  
**图11  2018至2022年漏洞修复率对比统计图**  
### 2、厂商修复情况  
  
2022年漏洞数量排名前十的国外厂商修复情况统计如表6所示，Microsoft、Oracle修复率达100.00%。总体来看，前十名国外厂商平均修复率达94.86%，较上年下降四个百分点。  
  
**表6  2022年漏洞数量前十国外厂商修复情况统计表**  
<table><tbody><tr><td width="61" style="word-break: break-all;"><p><span style="font-size: 16px;"><strong>序号</strong></span></p></td><td width="138"><p><strong><span style="font-size: 16px;">厂商名称</span></strong></p></td><td width="86"><p><strong><span style="font-size: 16px;">漏洞数量</span></strong></p></td><td width="100"><p><strong><span style="font-size: 16px;">修复数量</span></strong></p></td><td width="110"><p><strong><span style="font-size: 16px;">修复率</span></strong></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">1</span></p></td><td width="138"><p><span style="font-size: 16px;">Google（美）</span></p></td><td width="106"><p><span style="font-size: 16px;">1411</span></p></td><td width="97"><p><span style="font-size: 16px;">1277</span></p></td><td width="110"><p><span style="font-size: 16px;">90.50%</span></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">2</span></p></td><td width="138"><p><span style="font-size: 16px;">Microsoft（美）</span></p></td><td width="106"><p><span style="font-size: 16px;">963</span></p></td><td width="97"><p><span style="font-size: 16px;">963</span></p></td><td width="110"><p><span style="font-size: 16px;">100.00%</span></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">3</span></p></td><td width="138"><p><span style="font-size: 16px;">Oracle（美）</span></p></td><td width="106"><p><span style="font-size: 16px;">417</span></p></td><td width="97"><p><span style="font-size: 16px;">417</span></p></td><td width="110"><p><span style="font-size: 16px;">100.00%</span></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">4</span></p></td><td width="138"><p><span style="font-size: 16px;">IBM（美）</span></p></td><td width="106"><p><span style="font-size: 16px;">417</span></p></td><td width="97"><p><span style="font-size: 16px;">393</span></p></td><td width="110"><p><span style="font-size: 16px;">94.24%</span></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">5</span></p></td><td width="138"><p><span style="font-size: 16px;">Adobe（美）</span></p></td><td width="106"><p><span style="font-size: 16px;">417</span></p></td><td width="97"><p><span style="font-size: 16px;">409</span></p></td><td width="110"><p><span style="font-size: 16px;">98.08%</span></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">6</span></p></td><td width="138"><p><span style="font-size: 16px;">Apple（美）</span></p></td><td width="106"><p><span style="font-size: 16px;">389</span></p></td><td width="97"><p><span style="font-size: 16px;">344</span></p></td><td width="110"><p><span style="font-size: 16px;">88.43%</span></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">7</span></p></td><td width="138"><p><span style="font-size: 16px;">Samsung(韩)</span></p></td><td width="106"><p><span style="font-size: 16px;">359</span></p></td><td width="97"><p><span style="font-size: 16px;">350</span></p></td><td width="110"><p><span style="font-size: 16px;">97.49%</span></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">8</span></p></td><td width="138"><p><span style="font-size: 16px;">Cisco（美）</span></p></td><td width="106"><p><span style="font-size: 16px;">344</span></p></td><td width="97"><p><span style="font-size: 16px;">311</span></p></td><td width="110"><p><span style="font-size: 16px;">90.41%</span></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">9</span></p></td><td width="138"><p><span style="font-size: 16px;">Siemens（德）</span></p></td><td width="106"><p><span style="font-size: 16px;">300</span></p></td><td width="97"><p><span style="font-size: 16px;">297</span></p></td><td width="110"><p><span style="font-size: 16px;">99.00%</span></p></td></tr><tr><td width="25"><p><span style="font-size: 16px;">10</span></p></td><td width="138"><p><span style="font-size: 16px;">Intel（美）</span></p></td><td width="106"><p><span style="font-size: 16px;">239</span></p></td><td width="97"><p><span style="font-size: 16px;">225</span></p></td><td width="110"><p><span style="font-size: 16px;">94.14%</span></p></td></tr><tr><td colspan="2" width="46" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">合计</span></strong><span style="font-size: 16px;"></span></p></td><td width="106"><p><span style="font-size: 16px;">5256</span></p></td><td width="97"><p><span style="font-size: 16px;">4986</span></p></td><td width="110"><p><span style="font-size: 16px;">94.86%</span></p></td></tr></tbody></table>  
2022年漏洞数量排名前十的国内厂商修复情况统计如表7所示，仅联发科修复率达100.00%。总体来看，前十国内厂商平均修复率为58.72%，无线设备厂商修复率较低。  
  
**表7  2022年国内漏洞数量前十厂商漏洞修复情况统计表**  
<table><tbody><tr><td width="70" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">序号</span></strong></p></td><td width="98"><p><strong><span style="font-size: 16px;">厂商名称</span></strong></p></td><td width="91"><p><strong><span style="font-size: 16px;">漏洞数量</span></strong></p></td><td width="80"><p><strong><span style="font-size: 16px;">修复数量</span></strong></p></td><td width="142"><p><strong><span style="font-size: 16px;">修复率</span></strong></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">1</span></p></td><td width="98"><p><span style="font-size: 16px;">腾达</span></p></td><td width="97"><p><span style="font-size: 16px;">450</span></p></td><td width="100"><p><span style="font-size: 16px;">110</span></p></td><td width="142"><p><span style="font-size: 16px;">24.44%</span></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">2</span></p></td><td width="98"><p><span style="font-size: 16px;">华为</span></p></td><td width="97"><p><span style="font-size: 16px;">262</span></p></td><td width="100"><p><span style="font-size: 16px;">259</span></p></td><td width="142"><p><span style="font-size: 16px;">98.85%</span></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">3</span></p></td><td width="98"><p><span style="font-size: 16px;">吉翁电子</span></p></td><td width="97"><p><span style="font-size: 16px;">219</span></p></td><td width="100"><p><span style="font-size: 16px;">70</span></p></td><td width="142"><p><span style="font-size: 16px;">31.96%</span></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">4</span></p></td><td width="98"><p><span style="font-size: 16px;">联发科（台）</span></p></td><td width="97"><p><span style="font-size: 16px;">209</span></p></td><td width="100"><p><span style="font-size: 16px;">209</span></p></td><td width="142"><p><span style="font-size: 16px;">100.00%</span></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">5</span></p></td><td width="98"><p><span style="font-size: 16px;">友讯（台）</span></p></td><td width="97"><p><span style="font-size: 16px;">146</span></p></td><td width="100"><p><span style="font-size: 16px;">62</span></p></td><td width="142"><p><span style="font-size: 16px;">42.47%</span></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">6</span></p></td><td width="98"><p><span style="font-size: 16px;">新华三</span></p></td><td width="97"><p><span style="font-size: 16px;">100</span></p></td><td width="100"><p><span style="font-size: 16px;">87</span></p></td><td width="142"><p><span style="font-size: 16px;">87.00%</span></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">7</span></p></td><td width="98"><p><span style="font-size: 16px;">睿联</span></p></td><td width="97"><p><span style="font-size: 16px;">89</span></p></td><td width="100"><p><span style="font-size: 16px;">20</span></p></td><td width="142"><p><span style="font-size: 16px;">22.47%</span></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">8</span></p></td><td width="98"><p><span style="font-size: 16px;">紫光展锐</span></p></td><td width="97"><p><span style="font-size: 16px;">76</span></p></td><td width="100"><p><span style="font-size: 16px;">72</span></p></td><td width="142"><p><span style="font-size: 16px;">94.74%</span></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">9</span></p></td><td width="98"><p><span style="font-size: 16px;">普联</span></p></td><td width="97"><p><span style="font-size: 16px;">63</span></p></td><td width="100"><p><span style="font-size: 16px;">37</span></p></td><td width="142"><p><span style="font-size: 16px;">58.73%</span></p></td></tr><tr><td width="34"><p><span style="font-size: 16px;">10</span></p></td><td width="98"><p><span style="font-size: 16px;">福昕</span></p></td><td width="97"><p><span style="font-size: 16px;">55</span></p></td><td width="100"><p><span style="font-size: 16px;">54</span></p></td><td width="142"><p><span style="font-size: 16px;">98.18%</span></p></td></tr><tr><td colspan="2" width="46" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">合计</span></strong><span style="font-size: 16px;"></span></p></td><td width="97"><p><span style="font-size: 16px;">1669</span></p></td><td width="100"><p><span style="font-size: 16px;">980</span></p></td><td width="142"><p><span style="font-size: 16px;">58.72%</span></p></td></tr></tbody></table>  
**（四）漏洞攻击情况**  
### 1、漏洞攻击向量分布  
  
2022年新增漏洞攻击向量统计如图12所示，其中可远程攻击占比约为72.3%，本地攻击约占24.95%，邻接网络占1.78%，物理攻击仅占0.97%。远程攻击漏洞数量占比最高，且较上年上浮四个百分点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn26e5TPSPhrFSbeb92DWLOVpUyo0z6838ORJ46ic1Jkt5SIpw3Ae9a1lQ/640?wx_fmt=png "")  
  
**图12  2022年新增漏洞攻击向量分布图**  
### 2、漏洞利用情况  
  
2022年披露了较多高风险漏洞，这些漏洞广泛影响网络服务、办公软件、网络设备等关基设施，安全更新可得到修复，但依然存在未修复情况并处于被利用高风险状态，具体见表8。  
  
**表8  2022年漏洞利用排名**  
<table><tbody><tr><td width="61" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">序号</span></strong></p></td><td width="251" style="word-break: break-all;"><p><strong><span style="font-size: 16px;">漏洞名称</span></strong></p></td><td width="125"><p><strong><span style="font-size: 16px;">漏洞编号</span></strong></p></td><td width="113"><p><strong><span style="font-size: 16px;">严重等级</span></strong></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">1</span></p></td><td width="231"><p><span style="font-size: 16px;">Google Chrome <br/>资源管理错误漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202202-1153<br/>CVE-2022-0609</span></p></td><td width="110"><p><span style="font-size: 16px;">高危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">2</span></p></td><td width="231"><p><span style="font-size: 16px;">Spring Framework <br/>代码注入漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202203-2514<br/>CVE-2022-22965</span></p></td><td width="110"><p><span style="font-size: 16px;">超危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">3</span></p></td><td width="231"><p><span style="font-size: 16px;">Zimbra Collaboration Suite <br/>代码问题漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202204-3909<br/>CVE-2022-27925</span></p></td><td width="110"><p><span style="font-size: 16px;">高危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">4</span></p></td><td width="231"><p><span style="font-size: 16px;">Zimbra Collaboration Suite <br/>授权问题漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202208-2850<br/>CVE-2022-37042</span></p></td><td width="110"><p><span style="font-size: 16px;">超危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">5</span></p></td><td width="231"><p><span style="font-size: 16px;">Zimbra Collaboration Suite <br/>代码问题漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202209-2715<br/>CVE-2022-41352</span></p></td><td width="110"><p><span style="font-size: 16px;">超危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">6</span></p></td><td width="231"><p><span style="font-size: 16px;">F5 BIG-IP 访问控制错误漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202205-2141<br/>CVE-2022-1388</span></p></td><td width="110"><p><span style="font-size: 16px;">超危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">7</span></p></td><td width="231"><p><span style="font-size: 16px;">Zyxel（合勤科技）USG FLEX<br/>操作系统命令注入漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202205-3104<br/>CVE-2022-30525</span></p></td><td width="110"><p><span style="font-size: 16px;">超危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">8</span></p></td><td width="231"><p><span style="font-size: 16px;">Microsoft Windows Support Diagnostic Tool<br/>操作系统命令注入漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202205-4277<br/>CVE-2022-30190</span></p></td><td width="110"><p><span style="font-size: 16px;">高危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">9</span></p></td><td width="231"><p><span style="font-size: 16px;">Atlassian Confluence Server <br/>注入漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202206-442<br/>CVE-2022-26134</span></p></td><td width="110"><p><span style="font-size: 16px;">超危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">10</span></p></td><td width="231"><p><span style="font-size: 16px;">Microsoft Exchange Server <br/>安全漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202210-001<br/>CVE-2022-41040</span></p></td><td width="110"><p><span style="font-size: 16px;">高危</span></p></td></tr><tr><td width="30"><p><span style="font-size: 16px;">11</span></p></td><td width="231"><p><span style="font-size: 16px;">Microsoft Exchange Server <br/>安全漏洞</span></p></td><td width="105"><p><span style="font-size: 16px;">CNNVD-202210-002<br/>CVE-2022-41082</span></p></td><td width="110"><p><span style="font-size: 16px;">高危</span></p></td></tr></tbody></table>  
**（1）Google Chrome 资源管理错误漏洞**  
  
2022年2月中旬，美谷歌官方披露检测Chrome零日漏洞（CNNVD-202202-1153/CVE-2022-0609）攻击并发布安全更新。该漏洞漏洞源于动画组件中的释放后使用，可被用来执行任意代码或在浏览器的沙箱中逃逸。该漏洞系谷歌威胁分析团队发现漏洞攻击，追溯到一个月前已被朝鲜黑客利用零日远程代码执行对美媒体、IT公司、加密货币和金融机构发起攻击。  
#### （2）Spring Framework 代码注入漏洞  
  
2022年3月底，美虚拟产品商VMware运营的开源框架Spring Framework零日漏洞（CNNVD-202203-2514/CVE-2022-22965）一经发现即被疯传并暴发大规模恶意利用，Spring官方立即发布漏洞公告及安全更新。该漏洞系国内研究者发现，其影响在JDK 9+上运行的Spring MVC和Spring WebFlux 应用程序，攻击者需将WAR包部署在Servlet容器上，可对目标主机的后门文件写入和配置修改，继而通过后门文件访问，获得目标主机权限，进而突破所在网络。  
#### （3）Zimbra Collaboration Suite两个利用链漏洞  
  
2022年4月和8月，美电子邮件产品商Zimbra官方发布安全公告并修复Zimbra协同套件两个高风险漏洞（CNNVD-202204-3909/CVE-2022-27925、CNNVD-202208-2850/CVE-2022-37042），利用前者可上传任意文件导致目录遍历或远程代码执行，利用后者可绕过身份验证，结合利用两者可未经身份验证而远程代码执行。6月底发现，利用上述组合漏洞对全球上千个Zimbra协作平台发起攻击，8月有报道称上述漏洞被武器化并大规模传播。美CISA要求联邦机构9月1日前完成漏洞修补。  
#### （4）Zimbra Collaboration Suite 代码问题漏洞  
  
2022年10月中旬，美电子邮件产品商Zimbra官方发布安全公告并修复Zimbra协同套件零日漏洞（CNNVD-202209-2715/CVE-2022-41352），此前已检测到APT组织在中亚地区发起攻击利用。利用该漏洞可上传任意文件，并结合基于Linux系统的文件提取程序cpio早期漏洞（CNNVD-201501-244/CVE-2015-1197）提取文件到文件系统任意位置，进而导致任意代码执行。  
#### （5）F5 BIG-IP 访问控制错误漏洞  
  
2022年5月初，美网络设备商F5官方发布安全公告并修复高风险漏洞（CNNVD-202205-2141/CVE-2022-1388），此后验证代码被披露，使不太成熟的参与者能够利用该漏洞。BIG-IP是美国F5公司应用程序交付和集中设备管理软硬件解决方案。攻击者利用该漏洞可绕过身份验证执行任意系统命令导致目标系统被控。BIG-IP及相关产品组件版本都受该漏洞影响，全球众多用户受影响。  
#### （6）Zyxel（合勤科技）USG FLEX操作系统命令注入漏洞  
  
2022年5月12日，中国台湾网络设备商Zyxel（合勤科技）官方发布公告并修复漏洞（CNNVD-202205-3104/CVE-2022-30525），在此之前漏洞细节被披露且已在野利用，据悉官方早在4月即修复。未经身份验证的攻击者利用该漏洞以nobody用户身份执行任意命令，USG FLIX系列、ATP系列及VPN系列等防火墙产品固件受此影响，欧美多国用户设备受到攻击。  
#### （7）Microsoft Windows Support Diagnostic Tool 操作系统命令注入漏洞  
  
2022年5月底，Microsoft Windows Support Diagnostic Tool零日漏洞（CNNVD-202205-4277/CVE-2022-30190）被研究者披露并检测到在野利用，微软官方随即发布漏洞公告并提供临时缓解措施，6月中旬发布安全更新。该漏洞源于应用程序（例如 Word）使用URL协议调用微软Windows支持诊断工具（MSDT）时可被远程利用，使用调用应用程序的权限下可执行任意代码，并可安装程序、查看更改或删除数据，以及创建新帐户。该漏洞影响Windows及Windows Server系列版本。截至2023年3月，依然可检测到该漏洞利用情况。  
#### （8）Atlassian Confluence Server 注入漏洞  
  
2022年6月初，澳大利亚项目协同软件开发商Atlassian发布安全公告并修复高风险漏洞（CNNVD-202206-442/CVE-2022-26134），同期漏洞细节被披露且已在野利用。未经身份验证的远程攻击者构造OGNL表达式，可在Confluence Server或Data Center上执行任意代码。据悉，5月下旬发现黑客联合利用 Spring4Shell漏洞（CNNVD-202203-2514/CVE-2022-22965)获得Confluence Web应用初始访问权限，利用漏洞开展间谍活动或部署矿机。因该漏洞风险极高，美CISA要求联邦结构4天内完成修复。  
#### （9）Microsoft Exchange Server两个利用链漏洞  
  
2022年9月底，微软官方紧急披露Exchange Server两个零日漏洞，即SSRF（服务器端请求伪造）漏洞（CNNVD-202210-001/CVE-2022-41040）和RCE（远程代码执行）漏洞（CNNVD-202210-002/CVE-2022-41082），联合利用上述漏洞经身份验证的攻击者可远程访问PowerShell并执行代码。Exchange Server是微软开发的邮件服务组件，上述漏洞影响Microsoft Exchange Server 2013、Microsoft Exchange Server 2016、Microsoft Exchange Server 2019等版本，网络探测系统监测到数百万服务器分布在美中德等国家地区，可导致大规模的信息资产被非法控制或敏感数据泄露。  
  
# 二、漏洞趋势分析  
  
随着全球数字化、网络化和智能化进程的推进，网络安全漏洞数量、严重程度以及受关注度都在急剧飙升，数字经济发展面临网络安全领域的挑战不断升级。  
## （一）高风险漏洞数量突破新高  
  
2018至2022年连续五年漏洞数量呈持续增长走势，2022年新增漏洞数量达历年最高，较2018年增长52%，超高危数量较2018年翻一倍。2018至2022年漏洞新增数量和超高危漏洞数量统计如图13。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn282rPv0kIlkJLnkaeiayznAg3KvkficBrt1yBnNAVqicyYlP2icy6ed1I6w/640?wx_fmt=png "")  
  
**图13  2018至2022年漏洞新增数量和超高危数量对比统计图**  
  
2022年较上年增速明显加快，超高危漏洞数量增速同步提升，2022年超高危漏洞占比57%，较往年占比增幅较大。2018至2022年漏洞新增和超高危漏洞增长率统计如图14。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2icz87HPepibpfbKtaiaTC2KDDdBUIPKfWL1KYs0BujVf5M6sfcicRXrZsg/640?wx_fmt=png "")  
  
**图14  2018至2022年漏洞数量增长率和超高危增长率对比统计图**  
  
整体统计近五年月度数据，各年新增漏洞数量普遍在4月、10月和12月居当年较高水平，2月、5月和11月相对偏低。2018至2022年新增漏洞数量按月分布统计如图15所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2sLRe6JWtkGhlWQqJJ92Bhedtvark9pEezDs1ia5IOd76YgbOFyANowA/640?wx_fmt=png "")  
  
**图15  2018至2022年漏洞数量增按月分布对比统计图**  
## （二）零日争夺升级攻防新较量  
  
美企一边占据零日漏洞榜单，一边不断加价赏金数额。零日漏洞是补丁公开前被在野外利用的漏洞，因其隐蔽性和易于利用而成为网络攻击的利器，主要用在有限范围或有针对性的间谍活动中，勒索软件等大规模攻击更多利用的是N日漏洞。据统计，2022年被跟踪的55个零日漏洞中，有37个是美微软谷歌苹果产品漏洞，其余漏洞分布在飞塔等美主流厂商产品。一直以来，受零日漏洞影响的目标类型主要是操作系统、浏览器、网络管理产品以及移动操作系统，并正在向物联网设备和云解决方案不断发展。零日漏洞发现是资源密集型工作，市场价格大幅飙升，微软为单个漏洞最高支付20万美元赏金，谷歌为Android利用链漏洞奖励60.5万美元，是上年同类奖金的四倍，打破单笔奖金记录。2022年零日漏洞厂商分布图16所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2rQyJbiajoxRiboTUINGcSBpW49xq04vk0YJY7Vmcd1Yx0Dd27hna10UQ/640?wx_fmt=png "")  
  
**图16  2022年零日漏洞厂商分布图**  
## （三）单边漏洞管控扰乱国际秩序  
  
美政府一边针对我封锁漏洞技术出口，一边升级漏洞监测机制。近两年，美频繁动作针对我国高新技术脱钩断链，特别在2022年5月，美商务部产业与安全局发布针对网络安全领域新的出口管制规定《信息安全控制：网络安全物项》，以国家安全和反恐为由，要求美企与我国政府相关组织网络安全产业合作需经审核，并限制漏洞检测分析等技术产品出口我国，由此Cobalt Strike等商业网络安全工具对我停更。同时，美持续提升漏洞态势感知能力，基于漏洞监测情况，CISA持续更新在野利用漏洞清单（Known Exploited Vulnerabilities Catalog），并敦促政企用户限期完成漏洞修复工作，该清单已纳近千条漏洞信息。  
## （四）网络霸权主义冲击网空权益  
  
美一边指责我国利用漏洞对其攻击，一边疯狂对我使用网络武器。五年间美发布14份官方报告斥责我国政府支持的网络入侵或间谍活动，2022年美CISA联合FBI、NSA发布两份报告，列举了由我政府支持的瞄准美国和盟国网络攻击所利用的软硬件设备高危漏洞清单（见表9和表10），由此联合数字产业加大政府与关基单位风险防御和态势感知能力。与此同时，美频繁发起对我高级持续攻击，包括NSA攻击组织APT-C-40自2010年针对中国系列行业龙头公司的攻击；NSA使用多达41种网络武器针对西北工业大学攻击，其中有“影子经纪人”泄露过的NOPEN。  
  
**表9  被利用漏洞的组件目录**  
<table><tbody><tr><td><p>序号</p></td><td><p>软件或组件</p></td><td><p>漏洞编号</p></td><td style="word-break: break-all;"><p>攻击效果</p></td></tr><tr><td style="word-break: break-all;"><p>1</p></td><td style="word-break: break-all;"><p>Apache Log4j</p></td><td><p>CVE-2021-44228</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>2</p></td><td><p>Pulse Connect Secure</p></td><td><p>CVE-2019-11510</p></td><td><p>任意文件读取</p></td></tr><tr><td style="word-break: break-all;"><p>3</p></td><td><p>GitLab CE/EE</p></td><td><p>CVE-2021-22205</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>4</p></td><td><p>Atlassian</p></td><td><p>CVE-2022-26134</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>5</p></td><td><p>Microsoft Exchange</p></td><td><p>CVE-2021-26855</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>6</p></td><td><p>F5 Big-IP</p></td><td><p>CVE-2020-5902</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>7</p></td><td><p>VMware vCenter Server</p></td><td><p>CVE-2021-22005</p></td><td><p>任意文件读取</p></td></tr><tr><td style="word-break: break-all;"><p>8</p></td><td><p>Citrix ADC</p></td><td><p>CVE-2019-19781</p></td><td><p>路径遍历</p></td></tr><tr><td style="word-break: break-all;"><p>9</p></td><td><p>Cisco Hyperflex</p></td><td><p>CVE-2021-1497</p></td><td><p>命令执行</p></td></tr><tr><td style="word-break: break-all;"><p>10</p></td><td><p>Buffalo WSR</p></td><td><p>CVE-2021-20090</p></td><td><p>路径遍历</p></td></tr><tr><td style="word-break: break-all;"><p>11</p></td><td><p>Atlassian Confluence Server and Data Center</p></td><td><p>CVE-2021-26084</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>12</p></td><td><p>Hikvision Webserver</p></td><td><p>CVE-2021-36260</p></td><td><p>命令注入</p></td></tr><tr><td style="word-break: break-all;"><p>13</p></td><td><p>Sitecore XP</p></td><td><p>CVE-2021-42237</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>14</p></td><td><p>F5 Big-IP</p></td><td><p>CVE-2022-1388</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>15</p></td><td><p>Apache</p></td><td><p>CVE-2022-24112</p></td><td><p>身份验证绕过</p></td></tr><tr><td style="word-break: break-all;"><p>16</p></td><td><p>ZOHO</p></td><td><p>CVE-2021-40539</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>17</p></td><td><p>Microsoft</p></td><td><p>CVE-2021-26857</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>18</p></td><td><p>Microsoft</p></td><td><p>CVE-2021-26858</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>19</p></td><td><p>Microsoft</p></td><td><p>CVE-2021-27065</p></td><td><p>远程代码执行</p></td></tr><tr><td style="word-break: break-all;"><p>20</p></td><td><p>Apache HTTP Server</p></td><td><p>CVE-2021-41773</p></td><td><p>路径遍历</p></td></tr></tbody></table>  
  
**表10  被利用漏洞的设备目录**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1thw9GooccUVBfqbu8FsZmV1icO3KUn2UNV8SJ4pQ13ae94VrSt9YtvRs9Fs1aQIH4aJkot7kIWvnNKiaR3qWRA/640?wx_fmt=png "")  
# 三、下步措施建议  
  
**一是促进漏洞治理国际合作机制，对冲网络霸权，构建网络空间命运共同体。**  
数字化转型是全球经济发展趋势，全球数字供应链相互交织，单方面断供禁售不符合协作共赢的发展理念，提供高质量数字技术、以负责任的态度持续保障产品安全性能才是拓展国际市场的长远之计。特别要与核心基础数字产品供应方建立漏洞信息及时共享的保障机制，共同创建国际通用的漏洞规范标准，引领国际漏洞治理体系新规则，实现安全权益最大化。  
  
**二是推动漏洞治理国家机制顺畅，统筹漏洞治理体制建立健全。**  
漏洞治理是解决非传统安全风险向传统安全风险传导问题的关键环节，是提升国家安全治理能力的基础，更是维护国家安全的重要战略任务，狠抓漏洞治理就是筑牢网络安全根基。漏洞治理的关键和根本，是要依赖国家安全层面统一部署的工作机制，明确漏洞治理职能，构建基础研究、发现检测、风险评估及人才管理等治理能力，统筹推进漏洞风险治理体系建设，实现漏洞风险有效管控。  
  
**三是营造良好的漏洞生态环境，推动漏洞技术攻关和应用创新。**  
漏洞产业是漏洞风险治理的重要支柱力量，在严厉打击黑产链条基础上，合理引导上游产出，加大中游参与主体准入和监督力度，运用政策支持鼓励下游企业积极应用创新，规划布局产业整体发展方向，有力提升产业效能，充分发挥产业漏洞治理的重要作用。  
  
**四是加强漏洞感知机制和手段建设，提升网络安全防御能力。**  
漏洞利用是网络攻击的主要手段，一旦重大风险漏洞被披露，大型机构难以立即完成全网脆弱资产的修复，能否应对漏洞攻击的根本取决于对漏洞的识别能力及针对性的响应速度，是保障关基等重要网络资产安全的根本所在。关基领域要做好关键基础设施网络资产管理工作，做到“底数清”。有关部门应协调组织技术力量开展漏洞攻击特征资源汇聚，加强漏洞攻击识别能力建设，有效支撑国家关键基础设施网络安全防护，以及有关执法部门防范和打击境内外利用漏洞进行的破坏、窃密、间谍等各类违法犯罪活动。  
  
**五是加快漏洞标准制定和体系建设，夯实漏洞基础研究能力。**  
漏洞虽不可避免，但采取有效的管理和技术手段可以减少漏洞产生的数量、降低漏洞风险的等级，改善数字产品安全性能。建立健全漏洞管理标准体系，编制漏洞风险等级、分类、安全检测等系列标准，为漏洞风险评估机制建设执行提供技术依据。  
  
（来源：CNNVD）  
  
  
  
  
  
  
**《中国安全信息》杂志倾力推荐**  
  
**“企业成长计划”**  
  
  
**点击下图 了解详情**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzE5MDAzOA==&mid=2664162643&idx=1&sn=fcc4f3a6047a0c2f4e4cc0181243ee18&chksm=8b5ee7aabc296ebc7c8c9b145f16e6a5cf8316143db3edce69f2a312214d50a00f65d775198d&scene=21#wechat_redirect)  
  
  
