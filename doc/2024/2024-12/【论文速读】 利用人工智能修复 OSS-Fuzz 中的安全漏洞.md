#  【论文速读】| 利用人工智能修复 OSS-Fuzz 中的安全漏洞   
原创 知识分享者  安全极客   2024-12-18 09:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8QmTLhv0jB8GS6Wtic69pG44V8Gib7ccD3FZolnOVkdOPafA3YULibw9S5AEkdO8sstRLGNFVDj7SgRg/640?wx_fmt=jpeg&from=appmsg "")  
  
**基本信息**  
  
  
**原文标题：**Fixing Security Vulnerabilities with AI in OSS-Fuzz  
  
**原文作者：**Yun Tong Zhang, Jiawei Wang, Dominic Berzin, Martin Mirchev, Dongge Liu, Abhishek Arya, Oliver Chang, Abhik Roychowdhury  
  
**作者单位：**National University of Singapore, Google  
  
**关键词：**AI, OSS-Fuzz, 安全漏洞修复, 开源软件, 模糊测试  
  
**原文链接：**https://arxiv.org/pdf/2411.03346  
  
**开源代码：**暂无  
  
**论文要点**  
  
  
**论文简介：**  
本文探讨了如何利用人工智能（AI）来修复开源软件系统中安全漏洞，特别是通过 OSS-Fuzz 平台进行的模糊测试。OSS-Fuzz 是一个用于连续验证开源软件系统的基础设施，其核心目标是通过随机化输入数据来发现和修复安全漏洞，特别是那些可能导致程序崩溃的漏洞。尽管 OSS-Fuzz 已经成为开源软件安全验证的最重要工具，但仍然存在一定的挑战和局限性。本文提出了一种基于 AI 的解决方案，以提高 OSS-Fuzz 在识别和修复漏洞方面的效率，并且提出了新的方法来优化模糊测试过程。  
  
**研究目的：**  
当前，开源软件系统在安全性上的验证仍依赖于大量的模糊测试，这虽然有效，但也有其局限性，特别是在发现复杂漏洞和修复漏洞的速度上。OSS-Fuzz 已经取得了显著的成果，但其依然面临如何提高漏洞修复效率、扩大漏洞种类和减少误报等问题。为此，本文的研究目标是通过引入人工智能技术来改善 OSS-Fuzz 在这些方面的表现。具体来说，作者旨在提出一种新的基于 AI 的漏洞检测和修复方法，通过智能分析和学习，提升系统漏洞检测的全面性与准确性。  
  
**研究贡献：**  
  
1. 提出了一个结合 AI 技术的 OSS-Fuzz 模糊测试优化框架，旨在提升漏洞检测的速度与准确度。  
  
2. 设计了一种新的 AI 驱动的漏洞修复机制，能够自动识别并修复 OSS-Fuzz 检测到的安全漏洞。  
  
3. 提供了一个全面的实验评估，展示了该方法在实际操作中的效果和优势，包括减少误报和提高漏洞修复的效率。  
  
**引言**  
  
  
在当前的开源软件开发过程中，安全性是一个亟待解决的问题。由于开源软件的广泛应用，任何安全漏洞都可能对全球大量用户造成影响。为了提升软件的安全性，开源社区普遍采用模糊测试技术（Fuzzing），该技术通过输入大量随机化的测试数据，寻找可能导致程序崩溃或出现未定义行为的漏洞。OSS-Fuzz 是一种持续的开源系统安全验证工具，它通过长时间运行的模糊测试来确保软件的安全性。然而，尽管 OSS-Fuzz 在过去几年中取得了显著进展，它依然面临诸多挑战，尤其是在漏洞检测和修复的速度、准确性、以及如何减少误报和漏报方面。  
  
目前的模糊测试方法大多依赖于随机输入的生成，这使得测试的覆盖面和效率无法得到充分保证。更重要的是，OSS-Fuzz 的漏洞检测系统仍然无法完全解决复杂漏洞的发现问题，这些漏洞常常需要更高效的方式来识别和修复。此外，如何确保漏洞修复后的软件依然保持稳定性和功能完整性，也是当前技术体系中的一个难题。  
  
为了克服这些问题，本文提出了一种基于 AI 的优化方案。该方案利用机器学习和深度学习技术，通过对模糊测试的结果进行智能分析，不仅能提高漏洞检测的全面性，还能自动化漏洞修复过程，进一步提升 OSS-Fuzz 系统的效能。本文的目标是通过引入 AI 驱动的优化方法，解决 OSS-Fuzz 在漏洞检测中的局限性，提高系统的安全性和可靠性。  
  
**OSS-Fuzz案例研究**  
  
  
OSS-Fuzz 是 Google 提供的一个开源项目，旨在通过长时间运行的模糊测试，帮助开源社区发现并修复安全漏洞。其核心思想是通过自动化测试，使用随机输入数据对程序进行长时间的压力测试，从而发现潜在的漏洞。OSS-Fuzz 目前已经为数百个开源项目提供支持，包括 Chromium、OpenSSL 等知名项目。通过这些项目的验证，OSS-Fuzz 已经发现了大量的安全漏洞，并及时通知开发者进行修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8S5snFmt07icyGhbwVRDMfh7MuFibIOr8rfVCk19L6EETOsjhTez9u24bfAoHeze1cxK31Yz5K4StFA/640?wx_fmt=png&from=appmsg "")  
  
然而，尽管 OSS-Fuzz 在漏洞检测方面取得了显著成效，它仍然面临着效率和准确性方面的挑战。例如，模糊测试的随机化输入生成方法可能无法覆盖到软件中的某些关键路径，导致一些复杂漏洞未能被及时发现。针对这一问题，本文通过引入人工智能技术，提出了一种基于机器学习的自动优化机制，来增强 OSS-Fuzz 的漏洞检测能力。  
  
**CodeRover-S**  
  
  
CodeRover-S 是本文提出的一种新型漏洞修复工具，旨在通过人工智能技术自动修复 OSS-Fuzz 检测到的漏洞。该工具结合了深度学习和程序分析技术，能够快速定位漏洞并提供有效的修复建议。与传统的手工修复方法相比，CodeRover-S 在效率和准确性上有显著提升。通过大量的实验数据表明，CodeRover-S 能够在更短的时间内修复更多类型的漏洞，且修复后的代码仍能保持高质量和稳定性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8S5snFmt07icyGhbwVRDMfh7Y5sQsxW9XkVwa1o7kiaowt3biaYJvotcJ7PTD98Im5t0I0Vvmu6rSJNQ/640?wx_fmt=png&from=appmsg "")  
  
**研究评估**  
  
  
本文通过一系列实验验证了所提出的 AI 驱动漏洞检测和修复方法的有效性。实验设置主要包括对多个开源项目的测试，评估了不同优化策略下漏洞检测的覆盖率和修复速度。实验结果表明，基于 AI 的方法相较传统方法具有更高的漏洞修复率和更低的误报率。尤其是在复杂漏洞的检测和修复上，AI 驱动的优化方法表现出了显著的优势。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8S5snFmt07icyGhbwVRDMfh7NQWD29wOCOzwyquXcQAIialBGSxZJmSnlW2EI1fYAOh9024J4RvuIfA/640?wx_fmt=png&from=appmsg "")  
  
**论文结论**  
  
  
本文的研究展示了一种基于人工智能的漏洞检测和修复方法，显著提升了 OSS-Fuzz 在开源软件安全验证中的效率和准确性。通过引入 AI 技术，作者解决了当前模糊测试方法中的几个核心问题，包括漏洞检测的覆盖面、修复速度、以及误报和漏报的控制。这项研究为开源社区提供了一个有效的工具，可以大幅提升软件系统的安全性，同时也为未来的智能化漏洞修复技术开辟了新的研究方向。  
  
**活动预告：******[“AI+Security”社区第4期活动，12.21线下沙龙报名开启了](https://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247495405&idx=1&sn=67249648d5c312b5c178b23b077d28f3&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247495405&idx=1&sn=67249648d5c312b5c178b23b077d28f3&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SbEa20DfsSwTdtZvGHcMdnaeeCU3zmv6KREjeTkJ8NPf8CUpib4ejMVtx8KlQvDPiav7IxVTl6Qe4w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493750&idx=1&sn=27bd578179e5abbdc8907b669519bb8f&chksm=c2b95d82f5ced4945cf8844013563398cb3a885ea96a2ee2b60bfcc26d77ebffe78a35285646&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493759&idx=1&sn=0aed37ae210bde25a6b16a745301b71d&chksm=c2b95d8bf5ced49d12eb8cc6192c4e091bf11b6ffe99d4025467ea98b9d04cad89ba0ea91710&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493770&idx=1&sn=2c6d24403cda8f0ef45cadb10e1bfebd&chksm=c2b95d7ef5ced4686e39951e21153c81f0a1e57cabf0937e0d996e6621385745d3ee30d98c11&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8Q8ZzB8H1iavVTGLzQKrmiaV9ZINGu1cbRLSnUrgib5SPL2ibfOu7IicnWewfFoticsJsNECqJXia5mV8tWw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
