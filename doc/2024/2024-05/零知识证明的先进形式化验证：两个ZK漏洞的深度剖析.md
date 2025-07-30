#  零知识证明的先进形式化验证：两个ZK漏洞的深度剖析   
原创 CertiK  CertiK   2024-05-28 22:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE5yZQ2M0Vib7iaia7DsNibt2TjxO40aCWZlKePcIhDojrvDuQsMYEa1TK37Q/640?wx_fmt=png&from=appmsg "")  
  
  
在之前的文章中，我们讨论了[零知识证明的先进形式化验证：如何验证一条ZK指令](http://mp.weixin.qq.com/s?__biz=MzU5OTg4MTIxMw==&mid=2247502807&idx=1&sn=e5a6deabb78220190c027570b58943f0&chksm=feacaf45c9db26539e50d6973bcc0c85d2bd22d518e23d1de5ef3e344431725396a74b6dddec&scene=21#wechat_redirect)  
。通过形式化验证每条zkWasm指令，我们能够完全验证整个zkWasm电路的技术安全性和正确性。在本文中，我们将关注  
发现漏洞的视角  
，**分析在审计和验证过程中发现的具体漏洞，以及从中得到的经验和教训**  
。如要了解有关零知识证明（ZKP）区块链的先进形式化验证的一般讨论，请参见[零知识证明区块链的先进形式化验证](http://mp.weixin.qq.com/s?__biz=MzU5OTg4MTIxMw==&mid=2247502807&idx=2&sn=78500f419cac74bcaed529ac7f739c9b&chksm=feacaf45c9db26538b0c019504d7cf23e51c99b915e1f02353420c8be66a765081c9c36ab8c9&scene=21#wechat_redirect)  
一文。  
  
在讨论ZK漏洞之前，让我们先来了解CertiK是如何进行ZK形式化验证的。对于像ZK虚拟机（zkVM）这样的复杂系统，形式化验证（FV）的第一步是明确需要验证的内容及其性质。这需要对ZK系统的设计、代码实现和测试设置进行全面的审查。这个过程与常规的审计有所重合，但不同之处在于，审查后需要确立验证的目标和性质。在CertiK，我们称其为面向验证的审计。审计和验证工作通常是一个整体。对于zkWasm，我们对其同时进行了审计和形式化验证。  
  
  
# 什么是ZK漏洞？  
  
  
  
零知识证明系统的核心特征在于允许将离线或私密执行的计算（例如区块链交易）的简短加密证明传递给零知识证明验证器，并由其检查和确认，以确信该计算确已按声明的情况发生过。就此而言，ZK漏洞将使得黑客可以提交用于证明虚假交易的伪造ZK证明，并让ZK证明检查器接受。  
  
对于zkVM的证明器而言，ZK证明过程涉及运行程序、生成每一步的执行记录，并把执行记录的数据转换成一组数字表格（该过程称为“算术化”）。这些数字之间必须满足一组约束（即“电路”），其中包括了具体表单元格之间的联系方程、固定的常数、表间的数据库查找约束，以及每对相邻表行间所需要满足的多项式方程（亦即“门”）。链上验证可以由此确认的确存在某张能满足所有约束的表，同时又保证不会看到表中的具体数字。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE55RfEWQL6ia0oDo9qfYn7vLic4LxF88J3kJJtY2KmcWrhHricJFsTphnicw/640?wx_fmt=png&from=appmsg "")  
  
zkWasm算术化表  
  
每一个约束的准确性都至关重要。任何约束中的一个错误，无论是偏弱或是缺失，都可能使得黑客能够提交一个误导性的证明，这些表格看似代表了智能合约的一次有效运行，但实际并非如此。与传统VM相比，zkVM交易的不透明性放大了这些漏洞。在非ZK链中，交易的计算细节是公开记录在区块之上的；而zkVM则不将这些细节存储于链上。透明度的缺失使得攻击的具体情况很难被确定，甚至连攻击是否已发生都很难确定。  
  
执行zkVM指令规则的ZK电路极其复杂。对于zkWasm来说，其ZK电路的实现涉及超过6,000行的Rust代码和数百个约束。这种复杂性通常意味着可能存在多个漏洞正等待着被发现。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE5dsj6vWJib9gPOOkeYukKmA83rG7chnu7CiajWCHZvxnAwKGicMYEXfZibg/640?wx_fmt=png&from=appmsg "")  
  
zkWasm电路架构  
  
的确，我们通过对于zkWasm审计和形式化验证发现了多个这样的漏洞。下面，我们将讨论两个具有代表性的例子，并讨论它们之间的差异。  
  
  
# 代码漏洞：Load8数据注入攻击  
  
  
第一个漏洞涉及**zkWasm的Load8指令**  
。在zkWasm中，堆内存的读取是通过一组LoadN指令来完成的，其中N是要加载的数据的大小。例如，Load64应该从zkWasm内存地址读出64位的数据。Load8应该从内存中读出8位的数据（即一个字节），并用0前缀填充以创建一个64位的值。zkWasm内部将内存表示为64位字节的数组，因此其需要“选取”内存数组的一部分。为此使用了四个中间变量（u16_cells），这些变量合起来构成了完整的64位加载值。  
  
这些LoadN指令的约束定义如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE514hZPcv6ibtQa20fo56y93y7HbSQ2kkSBJvrdoCEgAxibjx4vhqBhUOQ/640?wx_fmt=png&from=appmsg "")  
  
这个约束分为Load32、Load16和Load8这三种情况。Load64没有任何约束，因为内存单元正好就是64位的。对于Load32的情况，代码确保了内存单元中的高4个字节（32位）必须为零。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE54FArBmia9xwDg2cOj6WjtDm845l8a3iazLScAkys6qRf9oV7ZOHO8UVg/640?wx_fmt=png&from=appmsg "")  
  
对于Load16的情况，内存单元中的高6个字节（48位）必须为零。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE51JibhabhvaCK2iasiaAiaCxLUapzeUKRbOB82MtNmbVZnmDDUibrHFxKrbA/640?wx_fmt=png&from=appmsg "")  
  
对于Load8的情况，应该要求内存单元中的高7个字节（56位）为零。遗憾的是，在代码中并非如此。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE5Sq4aHLRohWblusY877fssz7DoIDukfv3nFRBzNl58jjkyeaLyJWnPA/640?wx_fmt=png&from=appmsg "")  
  
正如你所见，**只有高9至16位被限制为零**  
。其他的高48位可以是任意值，却仍然可以伪装成“从内存中读取的”。  
  
通过利用这个漏洞，黑客可以篡改一个合法执行序列的ZK证明，使得Load8指令的运行加载这些意外的字节，从而导致数据损坏。并且，通过精心安排周边的代码和数据，可能会触发虚假的运行和转账，从而窃取数据和资产。这种伪造的交易可以通过zkWasm检查器的检查，并被区块链错误地认定为真实交易。  
  
修复这个漏洞实际上相当简单。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE5Toaeq6Xp8vvjZ5KcKSSqJpj5MhIFEyYCWVAQicsH9IrfEfHB6zISeUg/640?wx_fmt=png&from=appmsg "")  
  
该漏洞代表了一类被称为“代码漏洞”的ZK漏洞，因为**它们源于代码的编写，并可以通过较小的局部代码修改来轻松修复**  
。正如你可能会同意的那样，这些漏洞也相对更容易被人看出来。  
  
  
# 设计漏洞：伪造返回攻击  
  
  
让我们来看看另一个漏洞，这次是关于zkWasm的调用和返回。调用和返回是基本的VM指令，它们允许一个运行的上下文（例如函数）去调用另一个，并在被调用者完成其执行后，恢复调用者上下文的执行。每次调用都预期稍后会返回一次。zkWasm在调用和返回的生命周期中所追踪的动态数据被称为“调用帧（call frame）”。由于zkWasm按顺序执行指令，所有调用帧可以根据其在运行过程中的发生时间进行排序。下面是一个在zkWasm上运行的调用/返回代码示例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE5Vxr4kX3ibc6Szib0icHttX8kCvlpxINe4DHECL32gjAFcf6ibYaiaWyN9TQ/640?wx_fmt=png&from=appmsg "")  
  
用户可以调用buy_token()函数来购买代币（可能是通过支付或转移其他有价值的东西）。它的核心步骤之一是通过调用add_token()函数，实际将代币账户余额增加1。由于ZK证明器本身并不支持调用帧数据结构，因此需要使用执行表（E-Table）和跳转表（J-Table）来记录和追踪这些调用帧的完整历史记录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE5kRicUzRakfq2iawgd1N4RJ6Y2xgl4WKdTSib5qFptIBgzIWvTu3beicJEw/640?wx_fmt=png&from=appmsg "")  
  
上图说明了buy_token()调用add_token()的运行过程，以及从add_token()返回到buy_token()的过程。可以看到，代币账户余额增加了1。在执行表中，每个运行步骤占一行，其中包括当前执行中的调用帧编号、当前上下文函数名称（仅用于此处的说明）、该函数内当前运行指令的编号，以及表中所存的当前指令（仅用于此处的说明）。在跳转表中，每个调用帧占一行，表中存有其调用者帧的编号、调用者函数上下文名称（仅用于此处的说明）、调用者帧的下一条指令位置（以便该帧可以返回）。在这两个表中，都有一个jops列，它追踪当前指令是否为调用/返回（在执行表）以及该帧（在跳转表）发生的调用/返回指令总数。  
  
正如人们所预期的，每次调用都应该有一次相应的返回，并且每一帧应该只有一次调用和一次返回。如上图所示，跳转表中第1帧的jops值为2，与执行表中的第1行和第3行相对应，那里的jops值为1。目前看起来一切正常。  
  
但实际上这里有一个问题：**尽管一次调用和一次返回将使帧的jops计数为2，但两次调用或者两次返回也会使计数为2**  
。每帧有两次调用或两次返回听起来可能很荒谬，但要牢记的是，这正是黑客试图通过打破预期要做的事情。  
  
你现在可能有点兴奋了，但我们真的找到问题了吗？  
  
结果表明，两次调用并不是问题，因为执行表和调用表的约束使得两个调用无法被编码到同一帧的行中，因为每次调用都会产生一个新的帧编号，即当前调用帧编号加1。  
  
而两次返回的情况就没那么幸运了：**由于在返回时不会创建新的帧，黑客确实有可能获取合法运行序列的执行表和调用表，并注入伪造的返回（以及相应的帧）**  
。例如，先前执行表和调用表中buy_token()调用add_token()的例子可以被黑客篡改为以下情况：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE5sSWkQQ2XVEibakC7h2oOuFGaHMvOkczXoMGMYb6Wsxk3YMibMciaEwxZg/640?wx_fmt=png&from=appmsg "")  
  
黑客在执行表中原来的调用和返回之间注入了两次伪造的返回，并在调用表中增加了一个新的伪造的帧行（原来的返回和后续指令的运行步骤编号在执行表中则需要加4）。  
**由于调用表中每一行的jops计数均为2，因此满足了约束条件，zkWasm证明检查器将接受这个伪造的执行序列的“证明”**  
。从图中可以看出，代币账户余额增加了3次而不是1次。因此，黑客能够以支付1个代币的价格获得3个代币。  
  
解决这个问题有多种方法。一个明显的方法就是分别单独追踪调用和返回，并确保每一帧恰好有一次调用和一次返回。  
  
你可能已经注意到，到目前为止我们尚未展示这个漏洞的哪怕一行代码。主流的原因是没有任何一行代码是有问题的，代码实现完全符合表格和约束设计。问题在于设计本身，而修复方法也是如此。  
  
你可能认为，这个漏洞应该是显而易见的，但实际上并非如此。  
这是因为“两次调用或两次返回也会导致jops计数为2”与“实际上两次返回是可能的”之间存在空白。  
后者需要对执行表和调用表中相关的各种约束进行详细、完整地分析，很难进行完整的非形式化推理。  
  
  
# 两个漏洞的比较  
  
  
对于“Load8数据注入漏洞”和“伪造返回漏洞”，它们都可能导致黑客能够操纵ZK证明、创建虚假交易、骗过证明检查器，并进行窃取或劫持。但他们的性质和被发现的方式却截然不同。  
  
**“Load8数据注入漏洞”是在对zkWasm进行审计时发现的**  
。这绝非易事，因为我们必须审查超过6,000行的Rust代码和上百条zkWasm指令的数百个约束。尽管如此，这个漏洞还是相对容易发现和确认的。由于这个漏洞在形式化验证开始之前就已被修复，所以在验证过程中并未遇到它。如果在审计过程中未发现该漏洞，我们可以预期在对Load8指令的验证中会发现它。  
  
**“伪造返回漏洞”是在审计之后的形式化验证中发现的**  
。我们在审计中未能发现它的部分原因在于，zkWasm中有一个同jops非常相似的机制叫做“mops”，其在zkWasm运行期间追踪每个内存单元历史数据对应的内存访问指令。mops的计数约束确实是正确的，因为其只追踪了一种类型的内存指令，即内存写入；而且每个内存单元的历史数据都是不可变的，并只会写入一次（mops计数为1）。但即使我们在审计期间注意到了这个潜在的漏洞，如果不对所有的相关约束进行严格的形式化推理，我们将仍然无法轻易地确认或排除每一种可能情况，因为实际上没有任何一行代码是错误的。  
  
总结来说，这两种漏洞分别属于“代码漏洞”和“设计漏洞”。代码漏洞相对较为浅显，更容易被发现（错误代码），并且更容易推理和确认；设计漏洞可能非常隐蔽，更难以发现（没有“错误”代码），更难以推理和确认。  
  
  
# 发现ZK漏洞的最佳实践  
  
  
根据我们在审计和形式化验证zkVM以及其他ZK及非ZK链的经验，下面是关于如何最好地保护ZK系统的一些建议：  
  
 **检查代码以及设计**  
  
如前所述，ZK的代码和设计中都可能存在漏洞。这两种类型的漏洞都可能导致ZK系统受到破坏，因此必须在系统投入运行之前消除它们。与非ZK系统相比，ZK系统的一个问题是，任何攻击都更难揭露和分析，因为其计算细节没有公开或保留在链上。因此人们可能知道发生了黑客攻击，但却无法知道技术层面上是如何发生的。这使得任何ZK漏洞的成本都非常高。相应地，**预先确保ZK系统安全性的价值也非常高**  
。  
  
 **进行审计以及形式化验证**  
  
我们在这里介绍的两个漏洞分别是通过审计和形式化验证发现的。  
有人可能会认为，使用了形式化验证就不需要审计了，因为所有的漏洞都会被形式化验证发现。  
实际上我们的建议是两者都要进行。  
正如本文开头所解释的，一个高质量的形式化验证工作始于对代码和设计的彻底审查、检查和非正式推理；  
而这项工作本身就与审计重叠。  
此外，在审计期间发现并排除更简单的漏洞，将使形式化验证变得更加简单和高效。  
  
如果要对一个ZK系统既进行审计又进行形式化验证，那么最佳时机是同时进行这两项工作，以便审计师和形式化验证工程师能够高效地协作（有可能会发现更多的漏洞，因为形式化验证的对象和目标需要高质量的审计输入）。  
  
如果你的ZK项目已经进行了审计（赞）或多次审计（大赞），我们的建议是在此前审计结果的基础上对电路进行形式化验证。我们在zkVM以及其他ZK和非ZK项目的审计和形式化验证的经验一再表明，  
**验证常常能捕捉到审计中遗漏而不易发现的漏洞**  
。由于ZKP的特性，虽然ZK系统应该提供比非ZK解决方案更好的区块链安全性和可扩展性，但其自身的安全性和正确性的关键程度要远高于传统的非ZK系统。因此，对ZK系统进行高质量形式化验证的价值也远高于非ZK系统。  
  
  
 **确保电路以及智能合约的安全******  
  
ZK应用通常包含电路和智能合约两个部分。  
对于基于zkVM的应用，有通用的zkVM电路和智能合  
约应用。  
对于非基于zkVM的应用，有应用特定的ZK电路及相应部署在L1链或桥的另一端的智能合约。  
<table><tbody><tr><td width="166" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 16px;"><strong><span style="color: rgb(34, 34, 34);font-family: PingFangSC-Light;letter-spacing: 2px;text-align: left;caret-color: rgb(7, 193, 96);text-wrap: wrap;background-color: rgb(255, 255, 255);">ZK应用</span></strong></span></td><td width="166" valign="top" style="word-break: break-all;text-align: center;"><span style="color: rgb(34, 34, 34);font-family: PingFangSC-Light;letter-spacing: 2px;text-align: left;caret-color: rgb(7, 193, 96);text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 16px;"><strong>电路</strong></span></td><td width="166" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 16px;"><strong><span style="font-size: 16px;color: rgb(34, 34, 34);font-family: PingFangSC-Light;letter-spacing: 2px;text-align: left;caret-color: rgb(7, 193, 96);text-wrap: wrap;background-color: rgb(255, 255, 255);">智能合约</span></strong></span></td></tr><tr><td width="166" valign="top" style="word-break: break-all;text-align: center;"><span style="color: rgb(34, 34, 34);font-family: PingFangSC-Light;letter-spacing: 2px;text-align: left;caret-color: rgb(7, 193, 96);text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">基于zkVM</span></td><td width="166" valign="top" style="word-break: break-all;text-align: center;"><span style="color: rgb(34, 34, 34);font-family: PingFangSC-Light;letter-spacing: 2px;text-align: left;caret-color: rgb(7, 193, 96);text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">zkVM</span></td><td width="166" valign="top" style="word-break: break-all;text-align: center;"><span style="color: rgb(34, 34, 34);font-family: PingFangSC-Light;letter-spacing: 2px;text-align: left;caret-color: rgb(7, 193, 96);text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">应用</span></td></tr><tr><td width="166" valign="top" style="word-break: break-all;text-align: center;"><span style="color: rgb(34, 34, 34);font-family: PingFangSC-Light;letter-spacing: 2px;text-align: left;caret-color: rgb(7, 193, 96);text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">非基于zkVM</span></td><td width="166" valign="top" style="word-break: break-all;text-align: center;"><span style="color: rgb(34, 34, 34);font-family: PingFangSC-Light;letter-spacing: 2px;text-align: left;caret-color: rgb(7, 193, 96);text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">应用特定</span></td><td width="166" valign="top" style="word-break: break-all;text-align: center;"><span style="color: rgb(34, 34, 34);font-family: PingFangSC-Light;letter-spacing: 2px;text-align: left;caret-color: rgb(7, 193, 96);text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">L1链/桥</span></td></tr></tbody></table>  
我们对zkWasm的审计和形式验证工作只涉及了zkWasm电路。  
从ZK应用的整体安全性角度来看，对其智能合约进行审计和形式化验证也非常重要。  
毕竟，在为了确保电路安全方面投入了大量精力之后，如果在智能合约方面放松警惕，导致应用最终受到损害，那将是非常遗憾的。  
  
有两种类型的智能合约值得特别关注。第一种是直接处理ZK证明的智能合约。尽管它们的规模可能不是很大，但它们的风险非常高。第二种是运行在zkVM之上的大中型智能合约。我们知道，它们有时会非常复杂，而其中最有价值的应该进行审计和验证，特别是因为人们无法在链上看到它们的执行细节。幸运的是，经过多年的发展，智能合约的形式化验证现在已经可以实用，并且为合适的高价值目标做好了准备。  
  
让我们通过以下的说明来总结形式化验证（FV）对ZK系统及其组件的影响。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKnDCSFw7hYHSic12LI6TBRE53kZ2nNby1qhLsEd4yP4zp2uBguSS6KkNmfKFeqc4lxauibyApJmxsOw/640?wx_fmt=png&from=appmsg "")  
****  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/mHUbQLu9aKnfsDKgiabELk0iaomE1wDWHGhyKicaAMAic6AUsMD7ZjlibSBnIzDSV7OsxDhUoFOzEUK9l3iavIpOibQNQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
