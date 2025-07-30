#  复盘｜Balancer 漏洞分析   
原创 慢雾安全团队  慢雾科技   2023-10-09 18:13  
  
**背景**  
##   
  
  
8 月 22 号，Balancer 官方发布公告表示收到影响多个 V2 Boost 池的严重漏洞报告，只有 1.4% 的 TVL 受影响，多个池子已暂停，并通知用户尽快提取流动性 LP。  
[1] [2]  
  
  
8 月 27 号，慢雾 MistEye 系统发现疑似 Balancer 漏洞被利用的攻击交易。  
[3]  
  
  
由于池子无法暂停，一部分资金仍然受到攻击的影响，Balancer 官方再次提醒用户将受影响池子中的 LP 取回。  
[4]   
随后，Balancer 官方于 Medium 发布了 8 月披露的漏洞细节   
[5]  
，慢雾安全团队对其进行复盘，详情如下：  
  
## 引入  
  
  
Balancer 官方在其披露中简单指出此次的问题在于，线性池的向下舍入以及可组合池的虚拟供应量导致 bptSupply 为 0。首先让我们来简单了解一下与这次漏洞相关的 Balancer 协议中的内容。  
  
### Balancer V2 Vault  
  
  
Balancer V2   
[6]  
 协议是一种基于以太坊的去中心化自动做市商（AMM）协议，它代表了可编程流动性的灵活构建块。其核心组件是 Vault 合约，该合约维护着所有池子的记录，并管理代币的记账和转移，甚至包括原生 ETH 的包装和解包。也就是说，Vault 的实现是将代币记账和管理与池子逻辑分开。  
  
  
Vault 中有四个接口，分别是 joinPool, exitPool, swap 和 batchSwap（加入、退出和交换是分开的调用，不存在单次调用时的组合）。其中一个突出的特点是 batchSwap，它能实现多个池子之间多次原子交换，将一个池子交换的输出与另一个池子的输入相连（GiveIn 和 GiveOut）。该系统还引入了闪电交换   
[7]  
，类似于一个内部的闪电贷。  
  
### Linear Pools 线性池  
  
  
Balancer 为了提高 LP 的资本效率及 warp 和 unwarp 高额开销的问题，在 V2 中推出线性池作为解决方案，由此引入了 BPT (ERC20 Balancer Pool Token) 代币。  
  
  
线性池   
[8]   
包含 main token（底层资产），warpped token（包装代币）和 BPT 代币，通过已知汇率交换资产及其包装的、具有收益的对应物。包装代币的比例越高，收益率和资金池的资本效率就越高。在 warp 的过程中，通常都会通过缩放因子来确保不同代币以相同的精度进行计算。  
### Composable Pools 可组合池  
###   
  
  
所有的 Balancer 池都是可组合池，池子包含其他代币，池子本身也有自己的代币。其中 BPT 币指的是 ERC20 平衡池代币，是所有池的基础。用户可以在其他池内使用 BPT 代币自由组合进行兑换。兑换总是涉及一个池和两个代币：GiveIn 和 GiveOut。In 代表送入成分代币并接收 BPT，而 Out 意味着送入 BPT 并接收成分代币。如果 BPT 本身就是成分代币，它就可以像其他代币一样进行交换。这样的实现构成了外部池中的基础资产和代币之间的一个简单 batchSwap 路径，用户可以用 BPT 交换到线性池的底层资产，这也是 Balancer Boosted Pool   
[9]   
的基础。  
  
  
通过以上的组合，Balancer 的可组合池就形成了。一个 bb-a-USD 可组合稳定池由三个线性池组成，同时向外部协议（Aave）发送闲置流动性。例如，bb-a-DAI 是一个包含 DAI 和 waDAI（包装的 aDAI）的线性池。当用户需要进行 batchSwap 时（如要将 USDT 换成 DAI），交换路径举例如下：  
  
  
1. 在 USDT 线性池中，将 USDT 兑换 bb-a-USDT（进入 USDT 线性池）；  
  
2. 在 bb-a-USD 中，bb-a-USDT 兑换 bb-a-DAI（线性 BPT 之间的交换）；  
  
3. 在 DAI 线性池中，bb-a-DAI 兑换为 DAI（退出 DAI 线性池）。  
  
  
简单了解过以上前置知识后，我们进入漏洞分析环节。  
##   
## 分析  
  
  
在 8 月 27 号时，慢雾安全团队收到 MistEye 系统识别，一笔疑似 Balancer 漏洞的在野利用发生。交易  
 [3]   
如下：  
  
  
攻击者首先从 AAVE 通过闪电贷借出 300,000 枚 USDC。接着调用 Vault 的 batchSwap 操作，通过可组合稳定池 bb-a-USD 池进行 BPT 代币的兑换计算，最终将 94,508 枚 USDC 兑换为 59,964 枚 bb-a-USDC，68,201 枚 bb-a-DAI 和 74,280 枚 bb-a-USDT。最后将获得的 BPT 代币通过 Vault 合约的 exitPool 退出池子换取底层资产，偿还闪电贷，并获利约 108,843.7 美元离场。  
  
  
由此可见，这次攻击的关键在 batchSwap 里，而 batchSwap 中具体发生了什么呢？我们深入了解一下。  
  
  
攻击者在整个 batchSwap 过程中，先在 bb-a-USDC 池中兑换出 USDC ，接着进行 BPT 代币间的兑换，将 bb-a-USDC 兑换为 bb-a-DAI，bb-a-USDT 和 USDC。最后再将底层的 main 代币 USDC 兑换为 bb-a-USDT。也就是说，bb-a-USDC 作为关键的 BPT 代币充当 GiveOut 和 GiveIn 的成分代币。  
  
  
攻击者在第一步以固定的缩放因子在 bb-a-USDC 线性池中用 BPT 代币兑换出 USDC main代币，其增加的数量记录在池子中的 bptBalance 中。但是在第二次 onSwap 的兑换后，我们发现，同样的兑换过程，兑换出 USDC 的 amountOut 值却是 0。这是为什么呢？  
  
  
深入 onSwap 函数，我们发现在这个过程中会先做一次精度处理 nominal 化并计算出对应代币的缩放因子。而在接下来调用 _downscaleDown 函数时，amountOut 存在向下舍入的情况。如果 amountOut 和 scalingFactors[index  
Out] 之间的值相差很大，计算出的 _downscaleDown 值就为零。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZAQmjEQibibiauEHdWlaLVXD3SLSpfL6EriaCibFC65iccgmrzMsEN9jZbmwLovG81Fx9pAJAhnFY13UOA/640?wx_fmt=png "")  
  
  
  
也就是说当我们使用 BPT 代币来兑换 main 代币时，如果 amountOut 过小，返回值将向下舍入为零，且这个值就是小于由 scalingFactors 所计算来的 1e12。  
但 amountIn 进来的 bb-a-USDC 数量仍然会加入到 bptBalance 虚拟数量当中，而此操作会增加 bb-a-USDC 池子中的余额，可以将其看作为单边添加 bb-a-USDC 流动性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZAQmjEQibibiauEHdWlaLVXD3ibwtRnQLv9cPHqKeRibeI8vQNRRn26gOlLuKuhuXS00F76WaUGrPnY7Q/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZAQmjEQibibiauEHdWlaLVXD3GBzk77Vlf9j2dhTAVibxpp1Ie24xYn8IM2hblh17GTvUa7bmV6mBpyw/640?wx_fmt=png "")  
  
  
接着利用可组合稳定池的特性，通过 BPT 代币之间的相互转换，首先将 bb-a-USDC 兑换为其他 BPT 代币。跟进这个兑换过程，可组合稳定池的以下调用路  
径 bb-a-DAI onSwap -> _swapGivenIn -> _onSwapGivenIn 先将 bb-a-USDC 依次换成 bb-a-DAI 和 bb-a-USDT。与在线性池中不同的是，可组合稳定池在进行 onSwap 操作之前需要进行汇率的缓存更新。从代码中我们可以看到，在  
组合池中，onSwap 会先判断是否需要更新缓存的 token 兑换率。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZAQmjEQibibiauEHdWlaLVXD3R0HmicnZTiblSgTVgF7Td9sLvJlRRHXl7BSeZu4Dw2enJfZ50hhAAhqA/640?wx_fmt=png "")  
  
  
经过之前的兑换，bb-a-USDC 的数量发生了改变，并通过 _toNominal 名义化后的真实总量为 totalBalance 994,010,000,000，虚拟供应的 BPT 代币为 20,000,000,000 。可以计算出，更新后的汇率几乎是之前线性池原始缓存兑换率 1,100,443,876,587,504,549 的 45 倍，即 49,700,500,000,000,000,000。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZAQmjEQibibiauEHdWlaLVXD3TvuAyFL4TqFdutnXllfibho8UJGpOahsN8upGWGAJk1Sib2uMflIuNTA/640?wx_fmt=png "")  
  
  
随后，在线性池中将 bb-a-USDC 兑换为 USDC。然而这一次的兑换同第二次的兑换一样，再一次造成 amountOut 向下舍入为 0 的情况，兑换路径和之前相同。  
  
  
而接下来的这一次兑换则是反向将 USDC 兑换成 bb-a-USDC，兑换路径为 onSwap -> onSwapGivenIn -> _swapGivenMainIn。在这个过程中，我们发现，在计算需要兑换的 amountOut 的时候，其中对于虚拟供应量的计算，是基于兑换后的 BPT 代币 totalsupply 与池中剩余量之间的差值，该差值为0。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZAQmjEQibibiauEHdWlaLVXD3Ibc5O9S2fXlCVK218WLMD20wrDfpic1eXJdGSUSB7XXgkJKStXiclVSw/640?wx_fmt=png "")  
  
  
这是因为 bptSupply 为 0，在计算 BPT Out 时直接通过调用 _toNominal 函数，而此路径的调用使得 USDC 兑 bb-a-USDC 的兑换比例接近 1:1。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZAQmjEQibibiauEHdWlaLVXD3KlZ9Q2Npt7hTgV6sCXMtg7iaIK04WUD0STScruFFRyyjwvlrMVT7Icg/640?wx_fmt=png "")  
  
 ![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZAQmjEQibibiauEHdWlaLVXD38DhVmWXb5AKakTgN3SfKI8PmeKJNMQIbicab5eUEpp6H4ibPofj0rcsg/640?wx_fmt=png "")  
  
  
## 总结  
  
  
batchSwap 通过多个池子之间多次原子交换，将一个池子交换的输出与另一个池子的输入相连（tokenIn 和 tokenOut），将 USDC 兑换为 BPT 代币。在这个 batchSwap 中并不会发生实际代币转移，而是通过记录转入和转出的数量来确认最后的兑换数量。又因为线性池是通过底层资产代币进行兑换的，兑换方式是通过一个虚拟供应量且是固定的算法计算出 Rate 。因此，batchSwap 中存在两个安全漏洞：  
  
  
一是线性池的向下舍入问题，攻击者通过舍入为池子单边添加 main 代币提高缓存代币的比率，从而操纵相应可组合池中的代币兑换率；  
  
  
二是由于可组合池的虚拟供应量特性，虚拟供应量通过 BPT 代币减去池子中的余额来计算，在兑换的时候如果 GiveIn 是 BPT 代币，那么之后的供应量就会扣掉这部分，攻击者只需要将 BPT 作为 GiveIn 来进行兑换，并将其供应量先操纵为 0 ，之后进行反向 swap，即 BPT 再作为 GiveOut 一方，这时候由于供应量是 0，算法会按照接近 1:1 的比例低于线性池的兑换比例来进行实际兑换，使得 GiveOut 的 BPT 代币数量间接被操控。  
  
  
我们可以发现，漏洞一为兑换增加了兑换率，而反向兑换时漏洞二再反向降低兑换率，攻击者利用了双重 buff 获利离场。  
  
  
**参考链接：**  
  
[1]https://twitter.com/Balancer/status/1694014645378724280  
  
[2]https://forum.balancer.fi/t/vulnerability-found-in-some-pools/5102?u=endymionjkb  
  
[3]https://etherscan.io/tx/0x7020e0ccafff2c86db3df5a2af0cccb4e931fe948f69bf20ea517b0cc99c1f15  
  
[4]https://twitter.com/Balancer/status/1695777503699435751  
  
[5]https://medium.com/balancer-protocol/rate-manipulation-in-balancer-boosted-pools-technical-postmortem-53db4b642492  
  
[6]https://docs.balancer.fi/concepts/overview/basics.html  
  
[7]https://docs.balancer.fi/reference/swaps/flash-swaps.html#flash-swaps  
  
[8]https://docs.balancer.fi/concepts/pools/linear.html  
  
[9]https://docs.balancer.fi/concepts/pools/boosted.html  
  
  
**往期回顾**  
  
[慢雾出品｜重磅推出 HKSFC 合规安全审计服务](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498598&idx=1&sn=42aa2e3d3097cba8d9786e0b260b4b6d&chksm=fdde85e1caa90cf79f0961ffc2e8a38a01b28039bb8262d8a453ca173249ae950d14a0784a3e&scene=21#wechat_redirect)  
  
  
[慢雾(SlowMist) 与新加坡管理大学(SMU) 举行签约仪式](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498584&idx=1&sn=54b536af3b44211808efc7f992a52d64&chksm=fdde85dfcaa90cc97372ed1a795b69085d5a64703a31cdacfcee7317d32b8459409a5456e074&scene=21#wechat_redirect)  
  
  
[慢雾中秋献礼 | 黑暗森林主题版礼盒已上线](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498556&idx=1&sn=300c5cbec65b3140d64429a9ea94263e&chksm=fdde85bbcaa90cad48a6270f64cb19b2c075410a4085f45a21f3b7c776561f701fc31f8ecf69&scene=21#wechat_redirect)  
  
  
[华为云与慢雾(SlowMist) 联合发布 “分布式验证解决方案”](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498529&idx=1&sn=cbb53d34adf3c796e29eeb9cc211f082&chksm=fdde85a6caa90cb0735f8816916df8053cae5795e9c5c3a2aaa674a7b4455faa41d315cce072&scene=21#wechat_redirect)  
  
  
[活动 | 解读香港的 Web3 监管格局](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247498506&idx=1&sn=9fada4a66c10e16b82f8cd10f08de7fb&chksm=fdde858dcaa90c9b9cdb6d11e3969885f198bc0ad9d9ef858bed77010e5f1adc6b98fc423e5b&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLazKt6yZQQvqiccDeUu8Togv4VUdq4r7iak19Hta2pfbzPrGohPNR71WxPKrBoK9nyibPVL7ssCuW3yA/640?wx_fmt=png "")  
  
**慢雾导航**  
  
  
**慢雾科技官网**  
  
https://www.slowmist.com/  
  
  
**慢雾区官网**  
  
https://slowmist.io/  
  
  
**慢雾 GitHub**  
  
https://github.com/slowmist  
  
  
**Telegram**  
  
https://t.me/slowmistteam  
  
  
**Twitter**  
  
https://twitter.com/@slowmist_team  
  
  
**Medium**  
  
https://medium.com/@slowmist  
  
  
**知识星球**  
  
https://t.zsxq.com/Q3zNvvF  
  
