#  Catcher外网打点指纹识别+Nday漏洞验证工具|指纹识别   
island  深白网安   2025-02-18 02:29  
  
# 免责声明：文章中内容来源于互联网，涉及的所有内容仅供安全研究与教学之用，读者将其信息做其他用途而造成的任何直接或者间接的后果及损失由用户承担全部法律及连带责任。文章作者不承担任何法律及连带责任！如有侵权烦请告知，我们会立即删除整改并向您致以歉意。  
  
## 0x01: 简介  
  
Catcher是一款专为网络安全专业人士设计的高效工具，专注于外网资产梳理、漏洞检查和系统指纹识别。它特别适用于处理大量子域名的情况，能够快速准确地进行指纹识别，并对已识别的系统执行对应的漏洞验证。此外，Catcher还具备CDN判断功能，可以区分是否使用了CDN的域名，并对未使用CDN的域名进行端口扫描。  
  
![1](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud84Hh8diaoy4gsicLgstTpoY37p3iaTFQKmUpjo60b1XqBm17Mj8ia3EmM8yPt1Xx2icqnN3EHT3GtYqkw/640?wx_fmt=png&from=appmsg "")  
## 0x01: 使用  
  
工具目录如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud9TzeagBAvImTPNdNr0GPBA4pu0662dx7OkO0Ds6xdm2BKzWOjZqG4vBFWAhvZJSMY2t8JpajEPKg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
domain.txt: 需要进行测试的域名（可直接写入ip和端口的形式如1.1.1.1:80，也可写url: https://www.xxx.com的形式，也可直接写域名www.xxx.com）  
  
finger.json: 指纹文件  
  
poc : poc文件  
## 0x02: 流程  
  
1.Catcher首先会对域名通过finger.json文件进行指纹识别  
  
![3](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud84Hh8diaoy4gsicLgstTpoY3dg2CzPBNVhTAtaiaBew5z7SNgmeO4AU7nljtE2IJITs3EoEfiauVs1SA/640?wx_fmt=png&from=appmsg "")  
  
2.识别成功后会进入poc文件下去找具体对应的poc进行测试  
  
比如识别到的指纹为Atlassian Confluence，那么就会进入到 poc文件下的Atlassian Confluence文件下，去运行该文件中所有的poc文件  
  
![4](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud84Hh8diaoy4gsicLgstTpoY3Sibn2IP61amow34mcQ4roWoE6YhHBmibKsZyJib4WwiaKwIr13J0JVYic5Q/640?wx_fmt=png&from=appmsg "")  
  
Catcher中内置了许多用于漏洞验证的poc  
  
![5](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud84Hh8diaoy4gsicLgstTpoY3PbCIyskcia7dFV91KZL5c69OMSYsyyQYgMzej5ULX793bmfRFWz1icOw/640?wx_fmt=png&from=appmsg "")  
  
![6](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud84Hh8diaoy4gsicLgstTpoY3cGbVjqReOIgO3VynvJpEibiaUy3UCeh3JrrvxJttRZ23KPlqTvSicZlcg/640?wx_fmt=png&from=appmsg "")  
  
后续会继续更新指纹以及poc  
  
3.进行完漏洞测试后会将所有域名进行cdn判断（不可能做到绝对准确）  
  
4.判断完cdn后会去获取域名对应的ip，并进行端口扫描  
  
5.运行结束后会将结果保存到results文件下  
  
![7](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud84Hh8diaoy4gsicLgstTpoY30h5icW1NPrHxxlJKkibab8CyJkRouoCuTXWPXxiaqWh24JZn5cMNfajfA/640?wx_fmt=png&from=appmsg "")  
  
该文件下有7个文件  
  
Cdn.txt: 使用了cdn的域名  
  
NoCdn.txt: 没有使用cdn的域名  
  
ErrorCdn.txt: 未判断出是否使用cdn的域名  
  
Finger.xlsx: 指纹识别到的域名  
  
NoFinger.xlsx: 未指纹识别到的域名  
  
PocResults.txt: 漏洞测试的结果  
  
Ports.txt: 端口扫描结果  
  
生成的Finger.xlsx和NoFinger.xlsx为表格的形式方便查看  
  
![8](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud84Hh8diaoy4gsicLgstTpoY32Agr4JxicYlkerZolRKDqUJR3phy2fXvFKCnTaQ4LQicEEiaibBgPHYQyw/640?wx_fmt=png&from=appmsg "")  
  
除了对多个域名进行指纹识别漏洞验证  
  
因为domain.txt中也可写入ip端口的形式，并且Catcher中有很多poc。  
  
对多个资产、单个资产进行批量的泛微OA、用友OA等漏洞验证也是不错的选择  
  
![10](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud84Hh8diaoy4gsicLgstTpoY3UxbzByBNibZD1QsWW10PibNzPfK8GiaxE1kBiarBLe1TF5Pujy4cQ6gszQ/640?wx_fmt=png&from=appmsg "")  
  
![9](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFud84Hh8diaoy4gsicLgstTpoY3T7PBibYyWfHWXeFmHla0GR4z22dhFTDhyz3ngj2ogyiaTHYLpiacrMGNA/640?wx_fmt=png&from=appmsg "")  
## 0x03: 更新  
  
2024-5-23 新增几十条poc以及部分指纹，优化输出结果的显示使其更加友好  
  
2025-2-15 采用命令行形式供用户自行选择是否进行poc测试，将生成的结果文件改为表格，新增指纹和poc  
  
## 0x04: 工具获取  
  
**回复公众号10012**  
  
# 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
**遵守网络安全法，请勿用于非法入侵，仅供学习**  
  
