#  利用AI辅助测试WEB漏洞   
原创 红色火焰  联想全球安全实验室   2024-12-27 10:07  
  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7MweeEm1wpM2aRktYhFKP351tnlia2xp9Uq3XJ9HgDYHMdecrrPXHPrA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7wSeVzZwjRLEbcI7zlxmsmDAmQBFzwkjplgqhJBCRJLm63WdSwjOxow/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A75g9DnNCN6QiaCAbYkBr41F3gfSM7tFgtU6EM7klq0jC5ENj3bh7pvFQ/640?wx_fmt=png&from=appmsg "")  
  
**利用AI辅助**  
  
**测试WEB漏洞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7a3n5D3StwzUfHuibkQ34MibuYloIJZG1wNbFvHg56Q4Q4WiaevHT0PYuQ/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7wjDE5VQngzIxafbtwc7IhQZfkibVVELUzTOJ3gwty1Yt6o4tDYlCc4A/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A75g9DnNCN6QiaCAbYkBr41F3gfSM7tFgtU6EM7klq0jC5ENj3bh7pvFQ/640?wx_fmt=png&from=appmsg "")  
  
  
近年来，人工智能（AI）的飞速发展引发了各领域的广泛关注。AI不仅在内容创作和自动化任务中展现出了巨大的潜力，也在网络安全领域带来了新的机遇和挑战。作为一名白帽子，利用AI来辅助WEB漏洞测试是一种创新的尝试，这种方法可以有效地解放人力资源，让我们有更多的时间专注于研究其他复杂的安全问题。  
  
AI的强大之处在于其数据处理和模式识别能力。在WEB漏洞测试中，AI可以通过分析大量的网页源码，快速识别潜在的漏洞区域。大模型能够自动生成测试脚本，模拟攻击行为，并在此过程中帮助识别和验证漏洞的存在。这种自动化过程不仅提高了测试效率，还减少了人为错误的可能性。  
  
通过将简单的、重复性的任务交给AI，我们可以专注于更具挑战性的任务，例如高级攻击模式的研究和安全策略的优化。此外，AI还能提供智能化的修复建议，帮助开发者快速修补漏洞，从而提升系统的整体安全性。  
  
总之，AI在漏洞测试中的应用不仅是技术上的进步，更是思维方式的革新。它为安全工程师提供了一种全新的工具和方法，让我们能够更高效地保护数字世界的安全。  
  
我们做了个简单测试，最终发现大模型是可以发现一些简单的web漏洞的。先上一张成果的截图，可以看到通过大模型的引导，最终发现存在漏洞，并且给出了修复建议。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7QgXhWHlKKL3pAaiagDvoibRCIX8cdmS20O4HUiceHk9ibjUKp7dTCkPkhQ/640?wx_fmt=png&from=appmsg "")  
  
本文只是抛砖引玉的作用，仁者见仁智者见智。  
  
  
  
  
**01**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7a3n5D3StwzUfHuibkQ34MibuYloIJZG1wNbFvHg56Q4Q4WiaevHT0PYuQ/640?wx_fmt=gif&from=appmsg "")  
  
**必备工具**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7wjDE5VQngzIxafbtwc7IhQZfkibVVELUzTOJ3gwty1Yt6o4tDYlCc4A/640?wx_fmt=png&from=appmsg "")  
  
  
  
在进行AI辅助的WEB漏洞测试中，需要准备以下工具：  
  
1.**BurpSuite**：这是一款功能强大的渗透测试工具，广泛用于WEB应用程序的安全测试。它提供了多种功能，包括抓包、扫描、测试漏洞等。  
  
**下载地址**：https://portswigger.net/burp  
  
2. **Python3**：作为主流的编程语言，Python在测试过程中的应用非常广泛。其丰富的库和模块可以帮助快速开发测试脚本。  
  
3. **大模型**：大语言模型（如ChatGPT、Claude 3.5等）近年来发展迅速，在自然语言处理任务中表现出色。我们可以选择适合自己的模型来辅助我们的渗透测试工作。  
  
4. **DVWA靶机**：Web应用程序（DVWA）是一个很容易受到攻击的PHP / MySQL Web应用程序。其主要目标是帮助安全专业人员在法律环境中测试他们的技能和工具，帮助Web开发人员更好地了解保护Web应用程序的过程，并帮助学生和教师了解受控类中的Web应用程序安全性房间环境。DVWA的目标是通过简单直接的界面练习一些最常见的Web漏洞，具有各种难度。  
  
**下载地址**：https://github.com/digininja/DVWA  
  
  
  
**02**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7a3n5D3StwzUfHuibkQ34MibuYloIJZG1wNbFvHg56Q4Q4WiaevHT0PYuQ/640?wx_fmt=gif&from=appmsg "")  
  
**原理**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7wjDE5VQngzIxafbtwc7IhQZfkibVVELUzTOJ3gwty1Yt6o4tDYlCc4A/640?wx_fmt=png&from=appmsg "")  
  
  
  
使用AI进行WEB漏洞测试的基本原理如下：  
  
1. **传送网页源码**：首先，将目标网页的HTML源码发送给大模型。大模型通过分析源码，识别潜在的漏洞区域。  
  
2.**自动分析与生成测试代码**：大模型利用其强大的分析能力，自动生成测试方法，并生成相应的测试脚本。  
  
3. **执行与反馈**：用户执行大模型生成的测试脚本，并将测试结果反馈给大模型。大模型会进一步分析结果，判断是否存在漏洞。  
  
4. **漏洞修复建议**：如果检测到漏洞，大模型还会提供针对性的修复建议，帮助开发者快速修补漏洞。  
  
  
  
**03**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7a3n5D3StwzUfHuibkQ34MibuYloIJZG1wNbFvHg56Q4Q4WiaevHT0PYuQ/640?wx_fmt=gif&from=appmsg "")  
  
**最佳实践**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7wjDE5VQngzIxafbtwc7IhQZfkibVVELUzTOJ3gwty1Yt6o4tDYlCc4A/640?wx_fmt=png&from=appmsg "")  
  
  
  
1. **漏洞发现**：通过将靶机的网页源码输入到大模型中，大模型成功识别了潜在的命令执行漏洞。  
  
2. **生成测试脚本**：大模型生成了一段Python3脚本，用于验证该漏洞的存在。用户执行该脚本后，确认了漏洞。  
  
3. **修复建议**：在确认漏洞的同时，大模型也提供了修复建议，如输入验证和使用安全API等。这些建议迅速帮助我们修复了漏洞，提升了系统的安全性。  
  
下面是笔者自己使用的一个案例，供大家参考。  
  
为了验证AI在渗透测试中的实际效果，我们准备了一个WEB靶机进行测试。该靶机具有命令执行漏洞。  
  
(1)准备prompt，我这里的prompt是这样，大家可以按自己的需求进行改进。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A74eBJDNJz7OsMuRjF6WA1poJdFZTr8SIvR5jwlCyP2dwwU5DMAKwErw/640?wx_fmt=png&from=appmsg "")  
  
图 3‑1 prompt提示词  
  
(2)安装DVWA（上面有下载地址），漏洞测试系统。进入页面，打开含有命令注入的页面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7uadlsS2b4NeqiaK08zs8sYk0w9jJtelVK6QgW8mv1UrHf5LQPkAquDg/640?wx_fmt=png&from=appmsg "")  
  
图 3‑2 进入DVWA靶机  
  
(3)通过浏览器提供的查看源码功能，右键查看页面源码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A76eXq2YM4WaXRsWFGTaKccWysr5uBbeTPdnAib2libNJ4MoTMv1icPhiaAw/640?wx_fmt=png&from=appmsg "")  
  
图 3‑3 靶机页面源码  
  
(4)把源码复制粘贴发送给大模型，等待大模型分析结果。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7teOtptjcYRiaM26h4bLB974WOVpFuWsHAsEmUick8MlKia11T90Hjzhnw/640?wx_fmt=png&from=appmsg "")  
  
图 3‑4 源码发送给大模型  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7OoDEiag0G5EDebaNicYlGkhccSckN9QyrbcqjbpzRvB6LtBZX3alooicg/640?wx_fmt=png&from=appmsg "")  
  
图 3‑5 大模型的返回结果  
  
(5)大模型给出了一段，python的测试代码。我们会发现测试代码没有给页面地址，这时可以给大模型一段测试代码（直接从brupsuit中抓取），让大模型对python脚本进行修正。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7vXF8tfA3g0NPEvDuAHf7GBPPGCpTBlib1bpMAict9Ax2opJqiaoQIeMGA/640?wx_fmt=png&from=appmsg "")  
  
图 3‑6 测试代码  
  
(6)大模型修正后的python代码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7icbiaoMkQCwesNNAQWn3avIMISYWvkU22O8pTeegiaoxVOpGzE92zGpSg/640?wx_fmt=png&from=appmsg "")  
  
图 3‑7 大模型修正后的python代码  
  
(7)复制大模型提供的代码，在本地进行运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A73DnNK79y24P4fbSI0Llm0IcOiaKBT8PXEDdjtozcfYda2hxyeaIoc7w/640?wx_fmt=png&from=appmsg "")  
  
图 3‑8 python脚本在本地执行结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7ibAQOKialQquP1OWQbPJWVmvxCg8IOoNmC6M6piadLKEMBmN3afmyIROQ/640?wx_fmt=png&from=appmsg "")  
  
图 3‑9 可以看到有执行结果  
  
  
(8) 把执行结果，发送给大模型，大模型发现了存在命令注入漏洞，而且给出了相应的修复建议。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A79Q3cib24ic3GuXCibAJj8q2uQrU9tZOEibogeNADVYiaTfE4AhibdeoRRUjg/640?wx_fmt=png&from=appmsg "")  
  
图 4‑10 大模型的分析结果  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A75g9DnNCN6QiaCAbYkBr41F3gfSM7tFgtU6EM7klq0jC5ENj3bh7pvFQ/640?wx_fmt=png&from=appmsg "")  
  
  
随着AI技术的不断进步，大模型在渗透测试领域的应用前景十分广阔。AI不仅可以帮助我们自动化简单的测试任务，还可以在漏洞识别、攻击模拟和安全策略优化等方面发挥重要作用。通过不断的学习和优化，AI有潜力成为渗透测试中的重要助手，帮助安全工程师提升工作效率，发现和修复更多的安全漏洞。大模型的加入，标志着渗透测试领域进入了一个智能化的新阶段。我们期待着A I技术在未来能够帮助我们解决更多复杂的安全问题，为网络安全保驾护航。  
  
本文只是抛砖引玉的作用，仁者见仁智者见智。  
  
  
  
  
**往期精彩合集**  
  
  
  
● [堆以及堆利用技巧之UAF](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491351&idx=1&sn=edb9465e222ea0866332db61c7de3ebe&scene=21#wechat_redirect)  
  
  
● [深入了解SAML协议及常见安全问题](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491313&idx=1&sn=49b15be28a571d1e470af12fd721adb8&scene=21#wechat_redirect)  
  
  
● [AIGC时代，个人信息面临的挑战和应对策略](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491208&idx=1&sn=4d67e7380ae001573f229aa43046dcc4&scene=21#wechat_redirect)  
  
  
● [NPU安全研究报告](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491155&idx=1&sn=5f3071551c328162afe78bb5b766f76e&scene=21#wechat_redirect)  
  
  
● [Windows防火墙你了解吗](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491153&idx=1&sn=04a1bb8ab85fe7b384487b1feb0923df&scene=21#wechat_redirect)  
  
  
● [CVE-2019-13288漏洞分析](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491100&idx=1&sn=82084a0c0fef11259adf5b2c5862d69c&scene=21#wechat_redirect)  
  
  
● [Windows中压缩包可能出现的安全问题及相关缓解方案参考](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247490974&idx=1&sn=1104bfd16b690e811cfd43b75a591467&scene=21#wechat_redirect)  
  
  
● [移动操作系统的底层安全机制](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247490928&idx=1&sn=7815e58cc79937cfec94f81dba7815e0&scene=21#wechat_redirect)  
  
  
● [pixel5内核build、pixel6 LineageOS编译、motorola救砖](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247490898&idx=1&sn=a34fa8274af579695334537cf14d89ac&scene=21#wechat_redirect)  
  
  
● [前后端分离架构下 利用SpringBoot确保接口安全性](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247490811&idx=1&sn=54d09b319084c319ce0ff8ac8dca29b3&scene=21#wechat_redirect)  
  
  
  
**长**  
  
**按**  
  
**关**  
  
**注**  
  
联想GIC全球安全实验室（中国）  
  
chinaseclab@lenovo.com  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PicDhHpwdziaibb1ib6ez7pM1A362kq2k8A7xHnicmpKXRWgGgnPMzHbOMNn8BEnF9TRw6Tj7vhkZ1JpWnsAxy7HVag/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
