> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NzgzMjUzOA==&mid=2247485836&idx=1&sn=f56323b1b517dc6f96997e64d68eba92

#  【翻译】SRC挖掘中如何大规模搜寻泄露的敏感文件  
otterly  安全视安   2025-06-19 13:27  
  
# 免费网络安全资料PDF大合集  
  
**链接：https://pan.quark.cn/s/41b02efa09e6**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF5xOsytm8HnicSzbLxpd8ftiayzOUDHO0ThH4c5u1nj0xL95BmAMgOfsc1d426a81FwEcpMYiazDBNRQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
如今，纸质文件越来越少见，大量关键数据和文档都存储在线上。每天都有各种案例，披露敏感公司文件泄露的详细信息。这些文件原本供员工、投资者内部使用，或用于管理内部业务，如果不采取足够的预防措施，就有可能被未经授权披露。错误很容易发生，尤其是在拥有数千名员工的大公司，庞大的员工队伍使得确保不发生任何错误变得极具挑战性。对于我们这些赏金猎人来说，这可能是一座真正的金矿，因为这些文件可能包含一些个人身份信息 (PII) 或其他敏感数据！在本文中，我将介绍我自己的方法，即如何大规模搜寻泄露的敏感文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF6BQiaia7eE4VHrjThznIGSrouFKejVqpUYstbvcnl5wkEKNuLRVHGxDMcx9JibVwPicPWVWl2ILadicbQ/640?wx_fmt=png&from=appmsg "")  
  
## 获取目标域  
  
据我们所知，黑客攻击没有固定的套路。为了找到敏感文档的泄露，你也可以一次只锁定一个或几个程序。这实际上取决于具体情况和你的黑客风格。在这个例子中，我将展示我是如何通过一次性追踪所有程序的泄露文档，获得相当可观的赏金的！为了获得一个目标域名列表，我通常会结合多种技术。这确实需要一些手动操作，但最终这些努力应该会有所回报。  
### 1#项目发现的公共漏洞赏金计划  
  
正如我在  

```
Mass Hunting S3 Buckets
```

  
 (  
https://ott3rly.com/misconfigured-s3-buckets-axiom-part-5/  
)文章中提到的那样，我有一个单行代码（针对这种情况稍作修改）用于从项目发现的公共漏洞赏金计划存储库 (  
https://github.com/projectdiscovery/public-bugbounty-programs  
)中收集目标域：  

```
curl-s https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json | jq &#34;.[][] | select(.bounty==true) | .domains[]&#34;-r > targets.txt
```

  
这行 Bash 单行代码会 curl 一个公开的漏洞赏金计划列表，过滤包含赏金的计划，从参数中仅选择域名，并将输出保存到  
**target.txt**  
文件中。我们稍后会在漏洞追踪中使用这个文件。  
### 2# sw33tLie 的 BBSCOPE 工具  
  
如果您想节省大量时间，可以单独使用此工具 (  
https://github.com/sw33tLie/bbscope  
)。但请记住，您可能需要手动检查收集的数据。它确实涵盖了许多主要漏洞赏金平台的域名目标：  
  
**Hackerone**  

```
bbscope h1 -a -u <username> -t <token> -b > bbscope-h1.txt
```

  
**Bugcrowd**  

```
bbscope bc -t <token> -b > bbscope-bc.txt
```

  
**Intigriti**  

```
bbscope it -t <token> -b > bbscope-it.txt
```

  
**注意：**  
手动检查所有发现，并将其添加到没有通配符的域的  
**targets.txt和带有通配符的域的**  
  
**targets-wildcards.txt**  
中。  
### 可选：Arkadiyt 的赏金目标数据  
  
GitHub 上还有另一个存储库，可用于构建所有程序的目标列表。Arkadaiyt 的漏洞赏金目标数据存储库(  
https://github.com/arkadiyt/bounty-targets-data  
)每 30 分钟持续更新一次！遗憾的是，此存储库无法过滤来自 VDP 或 BBP 的域名（至少对于  
**domains.txt**  
和  
**wildcards.txt**  
而言）。如果您想做好事，并且不太在意报酬，您可以按照此步骤操作，但请记住，您的目标列表中将充满 VDP 目标！  

```
curl -s &#34;https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt&#34; | anew targets.txt
curl -s &#34;https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt&#34; | anew target-wildcards.txt
```

## 准备 VPS 以进行大规模 PDF 文件搜索  
  
如果你关注我的故事，你可能会知道我是Axiom(  
https://github.com/pry0cc/axiom  
)的忠实粉丝。我已经介绍过如何备份 VPS 实例(  
https://ott3rly.com/axiom-part-3/  
)，以便复制和扩展漏洞赏金计划。为了大规模搜索敏感的 PDF 文件，我希望在每个 Axiom 实例上都安装  
**pdftotext**  
 CLI 实用程序。使用此实用程序，我可以将 PDF 转换为文本，然后在 grep 中查找敏感词汇（潜在泄漏或 PII）。在这个特殊情况下，ChatGPT 帮助我准备了一个 Axiom 实例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Pf9NC3AaQF6BQiaia7eE4VHrjThznIGSro06HV56DW8pMJ1llvEh3icTTC8lyyfOdFXmV6qVic2TDibFQodqcoaB1Cg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
如我们所见，为了在每个实例上都安装  
**pdftotext**  
，我需要使用  

```
sudo apt-get install poppler-utils
```

  
命令在目标机器上安装。安装并备份后，它几乎就可以使用了。  
## 扫描目标，赢取巨额利润  
  
我还创建了自定义模块，其中包括一行代码，可以从包含通配符的 PDF 中收集敏感数据：  

```
[{
&#34;command&#34;:&#34;for i in `cat input | gau --subs --threads 16 | grep -Ea '\\.pdf' | httpx -silent -mc 200`; do if curl -s \&#34;$i\&#34; | pdftotext -q - - | grep -Eaiq 'internal use only|confidential'; then echo $i | tee output; fi; done&#34;,
&#34;ext&#34;:&#34;txt&#34;
}]
```

  
**~/.axiom/modules/gau-pdfs.json**  
  
让我们分析一下这一行代码的作用：  
- 使用gau(  
https://github.com/lc/gau  
)收集端点，包括来自 wayback、urlscan 等的子域。  
  
- **通过.pdf**  
扩展名过滤端点。  
  
- 通过匹配 200 状态代码检查httpx(  
https://github.com/projectdiscovery/httpx  
)是否处于活动状态。  
  
- 对于每个活动端点：  
  
- 卷曲端点。  
  
- 从 PDF 转换为文本。  
  
- 查找一些敏感词，例如  
**仅限内部使用**  
或  
**机密**  
。  
  
您可以发挥您的创造力，尝试根据自己的需求修改此脚本。例如，使用 katana 代替 gau，或者检查其他敏感词，使用其他扩展程序等等。运用自己的创意方法可以获得最高的赏金！  
  
最后，使用  
**axiom-scan 扫描**  
具有子域的目标：  

```
axiom-scan targets-wildcards.txt -m gau-pdfs -anew pdf-leak-findings.txt
```

  
如果您想在没有包含子域的目标上使用它，则需要通过删除 –subs 标志来修改模块：  

```
[{
&#34;command&#34;:&#34;for i in `cat input | gau --threads 16 | grep -Ea '\\.pdf' | httpx -silent -mc 200`; do if curl -s \&#34;$i\&#34; | pdftotext -q - - | grep -Eaiq 'internal use only|confidential'; then echo $i | tee output; fi; done&#34;,
&#34;ext&#34;:&#34;txt&#34;
}]
```

  
**~/.axiom/modules/gau-pdfs.json**  
  
并对没有通配符子域的目标运行命令：  

```
axiom-scan targets.txt -m gau-pdfs -anew pdf-leak-findings.txt
```

## 最后  
  
我已经介绍了如何通过一种颇具创意的方法大规模地开展漏洞赏金活动。您可以尝试对其他文档类型（例如 doc、docx、xlsx 等）执行此操作，因为许多其他文档类型也可能会出错。  
  
  
