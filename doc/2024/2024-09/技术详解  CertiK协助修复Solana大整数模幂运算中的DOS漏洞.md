#  技术详解 | CertiK协助修复Solana大整数模幂运算中的DOS漏洞   
原创 CertiK  CertiK   2024-09-14 19:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TT3hhZibx4vW4bAlT4gEsmJZS4I9sibNcbfGaNZChUwxKPbelw3aibAxysw/640?wx_fmt=png&from=appmsg "")  
  
**导读：**  
本文深入探讨了区块链交易费⽤模型的重要性及其在确保网络安全和有效运行中的关键作用。通过对以太坊和Solana区块链网络的交易费⽤模型进行比较分析，揭示了不安全的交易计费可能引发的网络安全风险。特别关注了  
**CertiK团队发现并协助修复的Solana网络中大整数模幂运算的CU计算错误，这一错误可能导致潜在的DOS攻击**  
。文章详细分析了Solana的智能合约计价模型、POH共识机制、并行事务处理方式，并通过在Solana私有集群上的实验，复现了远程DOS攻击的过程和成本。  
  
  
##   
## 1. 摘要与背景  
  
区块链的计费模式是确保网络安全和有效运行的关键机制，通过收取用户执行操作所需的费用（如Gas费用），防止恶意行为和资源滥用，保护用户利益，并推动整个区块链生态系统的发展和创新。一个有效的计费系统不仅是财务基础，也是促进技术进步和社区信任的重要因素。  
  
本文将深入分析以太坊（ETH）和Solana区块链网络的交易费用模型，以及不安全的交易计费可能引发的网络安全风险。重点讨论CertiK团队发现并修复的Solana网络中大整数模幂运算CU（计算单元）计算错误所引发的潜在远程DOS攻击漏洞，并通过此案例探讨区块链计费模型中的安全隐患。  
## 2. 交易费用模型的重要性  
  
在Web3.0领域中，底层基础设施运行在去中心化的区块链网络上。这些网络由全球验证者共同维护和运营。用户通过交易和智能合约进行互动，所有的交易都被记录在分布式账本上，并且这些记录是永久不可篡改的。  
  
验证者们凭借有限的资源共同维护着这庞大的区块链网络，而交易费用在确保网络稳定性和安全性方面起到关键作用。这些费用不仅激励着网络参与者，还是推动区块链成功发展的动力。有效的交易费用模型能够确保网络资源的合理分配，防止恶意行为和资源滥用，同时保护用户利益，促进技术的持续创新和社区的健康发展。  
  
交易费用模型的安全性对于区块链的长期健康和稳定至关重要。这种模型不仅仅是对网络资源的有效管理，还直接影响用户的信任和参与度。一个健全的交易费用模型能够有效地防止网络遭受恶意行为，如拒绝服务攻击（DDoS），通过设定适当的费用门槛使攻击者难以滥用网络资源。  
  
合理的费用结构能够激励验证者和矿工投入足够的资源来维护区块链的安全性和稳定性，因为他们通过收取交易费用来获取奖励和补偿。此外，透明和公平的计费机制还可以保护用户免受不当收费和资源耗费，增强他们对区块链生态系统的信任感。因此，一个经过良好设计的交易费用模型不仅是经济上的基础，更是确保区块链网络安全和用户权益的重要保障。  
## 3. ETH与Solana网络的交易费用模式设计  
  
在BTC网络中，所有交易的复杂度相对一致，并采用单一的交易计费模型。相比之下，ETH和Solana网络采用图灵完备的脚本语言，其交易计费模型设计更为复杂，涵盖带宽消耗、存储消耗和计算消耗等多个方面。智能合约可以消耗任意数量的带宽、存储和计算资源，而Gas费用则是衡量合约执行所需计算工作量的单位。通过限制Gas费用的消耗，可以有效控制智能合约对资源的过度利用。  
### 3.1：ETH网络的交易计费模型设计  
  
在以太坊（ETH）网络中，交易计费模型设计如下  
：  
  
3.1.1：**单位和概念解释**  
  
•**Wei和Gwei单位：**  
Wei是以太币（ether）的最小单位，1 ether = 1 x 10^18 wei。Gwei是Gas的计量单位，1 gwei = 1 x 10^9 wei。  
  
3.1.2：**Gas费用计算系统**  
  
•**Gas Limit：**用户愿意为确认交易或执行操作支付的最大Gas量。在  
伦敦升级[1]后，Gas Limit可以根据网络需求在15M至30M之间动态调整。  
  
•**Gas Used：**实际消耗的Gas数量，不超过Gas Limit。对于未使用的Gas部分，将会自动退回到用户的钱包余额。  
  
•**Gas Price：**用户愿意为每单位Gas支付的价格。Gas Price随着以太坊网络上交易拥堵情况而变化，通常是动态调整的，  
当前查询[2]Gas Price约为10gwei左右。伦敦升级引入了改进的  
EIP-1559[3] 新增两个参数（基础费用BaseFee和优先级费用PriorityFee），改进后的Gas Price计算为BaseFee + PriorityFee。  
  
3.1.3：**ETH网络交易费用计算示例**  
  
•  
例如，如果Gas Price为35 gwei/Gas，交易手续费计算如下：  
  
交易手续费 = Gas Price (10 gwei) * Gas Limit (21000) / 10^9 = 0.00021 ETH如果以每ETH单价3500美元计算，这笔交易手续费大约为0.735美元。在网络极度拥堵时，Gas Price可能会上升至100 gwei/Gas以上，导致单笔交易费用超过10美元。  
  
3.1.4：**ETH网络的TPS**  
  
•  
在区块链领域中，每秒事务数（TPS）是指网络每秒处理或执行的事务数量。  
当前查询[4]  
显示以太坊网络的TPS约为12.7。  
  
这些特性和参数使得以太坊网络能够根据需求动态调整交易费用，并有效管理网络资源，从而支持其广泛的智能合约和分布式应用生态系统的运行和发展。  
### 3.2：Solana网络的交易计费模型设计  
  
3.2.1：**Gas费计算系统**  
  
•**本地代币SOL和Lamport：**Lamports是Solana网络中的本地代币，相当于SOL的最小单位。一个SOL等于1,000,000,000 Lamports。MicroLamport是Lamports的最小单位，等于0.000001 Lamports，用于计算优先级费用。  
  
•**签名费用：**每笔交易必须包含一个签名，每个签名的基本费用固定为5000 Lamports（0.000005 SOL）。  
  
•**计算单元（CU）：**用于衡量Solana区块链智能合约执行资源消耗的最小单位。在Solana 1.9.2中引入了类似ETH的Gas Limit的功能，每笔交易默认具有200,000 CU预算，并且可以设置最大的1,400,000 CU。  
  
3.2.2：**Solana经济学设计**  
  
•**基础费用：**在2020年推出后的前两年，Solana的交易基础费用固定为0.000005 SOL每笔（每笔交易一个签名）。  
  
•**优先费用：**  
 自2022年起，Solana引入了额外的优先费用机制，允许在交易时支付额外费用以优先处理。计算优先费用的方法是将请求的最大计算单元(CU)乘以每个计算单元0.000001 Lamports的价格，四舍五入到最接近的Lamports。  
  
•**租金费用：**  
每个Solana账户在区块链上存储数据的费用称为“租金”。验证者根据账户在内存中维护的数据收取基于时间和空间的租金费用。账户需要足够的Lamports余额以免除租金并保留在Solana区块链上。账户若无法支付租金，则可能会通过垃圾收集过程从网络中删除。  
  
•**例如：**  
如果一个账户持有至少 2 年的租金，则该账户被视为免租。每次账户余额减少时都会检查此项，将余额 减少到最低金额以下的交易将会失败，目前的免租费用为每 MB 6.96 SOL。创建新账户时，费用会分配给该账户；删除账户时，可重新收取免租费用，假如一个大小为15,000字节的可执行程序需要105,290,880个lamports (=~ 0.105 SOL) 的余额才能免租。  
  
3.2.3：**Solana交易费用计算示例**  
  
•**交易总费用计算：** 假设一笔交易请求1,000,000 CU，并设置每个CU的优先费用为10,000 MicroLamports。则交易总费用为5000 Lamports（签名费用） + 1,000,000 CU * 10,000 MicroLamports * 0.000001 Lamports = 0.000015 SOL。当前Solana平均费用  
查询[5]显示，平均费用约为0.000021 SOL，额外费用约为0.000025 SOL。以每SOL 100美元的价格计算，单笔交易费用大约为0.0021美元。  
  
•**计算单元时间限制：** 计算单元CU也可以取决于在Solana SVM中执行时间的定价，每33 ns的计算时间等价于1 CU。假设默认上限为200,000 CU，那么在Solana SVM中执行200,000 CU的智能合约时间约为6.6毫秒。最大1,400,000 CU的执行时间约为46.2毫秒。  
  
•**交易费用分配：** Solana网络将所有交易费用的50%烧毁，其余50%分配给处理交易的验证者。  
  
3.2.4：**Solana网络的TPS**  
  
•根据Solana的白皮书，理论上Solana每秒可以处理多达710,000笔交易。在实际场景中，Solana已经表现出超过5,000 TPS的能力，并且在测试期间达到了65,000 TPS。当前  
查询[6]显示Solana的TPS约为3300。  
  
这些设计和参数使得Solana网络能够高效处理大量交易，并提供灵活的费用和资源管理机制，以支持其快速发展和广泛应用的智能合约和分布式应用生态系统。  
## 4. ETH和Solana网络交易费用对比  
  
**4.1：Gas费用对比：**  
  
根据平均费用查询，Solana的单笔交易费用为0.0021美元，远低于ETH的0.7美元交易费。ETH的交易费用随着网络拥堵而上升，而Solana相对于ETH网络，其单笔交易费用非常低，大约500笔交易的总费用才相当于1美元。  
  
**4.2：TPS对比：**  
  
目前，Solana的TPS约为ETH网络的250倍至500倍（ETH的tps为3000至5000的12分之一）。  
  
**4.3：总结：**  
  
总体而言，Solana相对于ETH网络在极低的Gas费用下能够处理大量交易。然而，Solana网络面临垃圾交易的风险高于ETH网络，这对其稳定性和冗余性构成了相当大的考验。  
## 5. ETH和Solana网络交易计费设计缺陷带来的风险  
  
前面了解并对比了ETH网络和Solana网络计费系统设计的细节和差异性，计费系统设计有缺陷会带来严重的网络安全风险，拒绝服务攻击是图灵完备的区块链网络备受困扰的网络安全风险之一，后续将会详细讨论ETH网络和Solana网络面临计费系统缺陷带来的网络安全风险。  
### 5.1：ETH网络历史上的计费系统风险  
  
ETH网络在历史上遭遇了两次拒绝服务攻击，并导致网络性能下降或者崩溃，解决方案分别是2016年10月18日的  
橘子哨（Tangerine Whistle）分叉[7]和2016年11月22日的  
伪龙（Spurious Dragon）分叉[8]。  
  
**5.1.1：EXTCODESIZE操作码攻击的原因：**   
  
造成这次拒绝服务攻击的罪魁祸首是EXTCODESIZE操作码，由于EXTCODESIZE操作码的Gas Price相当低，并且需要节点从磁盘读取状态信息，只要这些操作的Gas加起来不超过区块的Gas Limit，每个区块的攻击交易可调用此操作码大约50,000次。这一个区块内的交易所占用的计算时间就被大大延长，从而导致了整个以太坊网络的瘫痪。  
  
修复方案  
EIP-150[9]：通过增加EXTCODESIZE操作码的Gas成本，从20增加到700，以此防止类似的攻击再次发生。  
  
**5.1.2：SELFDESTRUCT 操作码攻击的原因：**  
  
攻击者利用SELFDESTRUCT操作码生成了大量空账户。每次SELFDESTRUCT操作会花费90 Gas生成一个空账户，这些账户需要存储在以太坊的状态树中。攻击者总共创建了约1900万个空账户，导致状态树的存储空间大幅膨胀，超过了实际创建账户所需的存储空间，最终导致节点存储压力爆炸。  
  
修复方案  
EIP-161[10]：EIP-161通过清除空账户和优化状态树的存储机制，减少了存储空间的浪费。现在创建新账户时需要额外支付25,000 Gas，空账户功能上等同于不存在的账户，可以通过交易与空账户交互来删除它们。  
  
**5.1.3：总结：**  
  
ETH 网络这两次拒绝服务攻击都利用了某些操作码的低Gas成本，从而放大了攻击的效果。攻击者可以用很少的资源对网络造成极大的负担，暴露了区块链网络在低Gas机制下的潜在脆弱性。  
### 5.2：Solana网络面临过的计费系统风险  
  
ETH网络在2016年经历了重大的拒绝服务攻击，成为当时的重要挑战之一。而彼时Solana还处于创始阶段，被视为潜在的“以太坊杀手”。Solana在2022年经历了严峻的网络中断考验（总计中断5次），但在2023年仅有一次中断。作为超高性能的区块链网络，Solana引入了  
8项关键创新[11]，虽然带来了技术进步，也引发了许多未知的风险。  
  
在数次中断事件中，2022年1月和2022年4月，Solana网络分别因大量垃圾交易遭遇拒绝服务攻击。  
  
**5.2.1： 2022年1月 – 严重的网络拥塞[12]**：  
  
由于重复交易过多导致缓存耗尽，网络性能严重下降，部分节点的处理能力受限，持续了较长时间。  
  
**5.2.2：2022年4月和5月 – 短暂的中断[13]**：  
  
2022年4月，Solana网络中断了2小时42分钟，主要原因是NFT机器人大量发送垃圾邮件，导致网络过载。同年5月，Solana再度因垃圾邮件攻击中断了5小时31分钟，每秒600万次的垃圾邮件交易使验证器内存不足，网络流量超出100 Gbps，最终导致主网Beta集群的共识停滞。投票不足以清理旧区块，进一步加剧了内存使用问题，导致验证器崩溃。  
  
与2016年ETH网络拒绝服务攻击类似，Solana在几次中断后也通过提高Gas费用来缓解攻击问题。特别是引入了优先级费用，允许用户为交易支付额外费用，以确保其交易优先处理。这种机制有效增加了攻击成本，降低了垃圾邮件攻击的可行性。  
  
**5.2.3：总结**：  
  
无论是ETH还是Solana网络，正确设计计费系统对于防范拒绝服务攻击至关重要。攻击者往往会利用Gas费用机制中的漏洞发起攻击。虽然Solana引入了优先级费用来提高攻击成本，但其交易成本仍然非常低，这可能意味着未来仍存在未知的攻击面。  
## 6. Solana智能合约的计价模型  
  
**6.1：Solana合约精确计算模型**  
  
Solana虚拟机（SVM）在Solana区块链上运行合约至关重要，因其高效的计算单元（CU）模型和快速执行速度。SVM通过精确的计费结构和优化的执行引擎，支持高吞吐量和低延迟的应用程序需求，同时保障了合约的安全性和稳定性。  
  
Solana的合约计费模式采用精确计算单元（CU）模型。每33纳秒的计算时间对应消耗1 CU，CU是衡量Solana虚拟机中资源消耗的标准单位。合约的执行成本是基于SVM中运行的字节码所消耗的CU来计算的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TTLOxL7vQc4opLM1nia5dLsWKfx28H9p99DyFqumIrlxFUXWAicsM7TbNQ/640?wx_fmt=png&from=appmsg "")  
  
SVM的CU计算模型对于Solana生态系统至关重要。根据CertiK团队于5月24日发布的一篇关于[SVM的CU计算漏洞的研究文章](https://mp.weixin.qq.com/s?__biz=MzU5OTg4MTIxMw==&mid=2247502980&idx=1&sn=7ba7670d5f9b63dfeb6a09ea12e7105f&scene=21#wechat_redirect)  
  
，SVM的CU计算指令在某些情况下可能会出现错误翻译，导致智能合约在SVM中出现无限计算消耗，严重时可能会导致整个Solana区块链网络的崩溃。  
  
**6.2：Solana引入syscall功能采用预估计算模型**  
  
随着Solana的发展，可能会引入新的功能或补丁来改变集群的行为和程序的运行方式。这些更改可以通过增加或减少syscall功能来实现。  
  
Solana支持一种称为运行时功能的机制，类似于热补丁，用于在集群发生行为更改时调整程序的行为。这些更改通过syscall功能门实现，默认情况下这些功能是禁用的，除非开启了相应的syscall功能。  
  
syscall的计费通过为每个特定的系统调用功能分配固定的CU值来实现，这些值被定义在计算预算中。  
  
在Solana的CU计费研究中，syscall功能的执行并不完全依赖于SVM标准模型，而是采用预估计算模型，某些情况下可能涉及第三方库的支持。syscall的这一特性使其在功能引入时更灵活，但同时也带来了一定的复杂性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TT2Lo4K2TC7Yc9f4ZicSmB9DeL1njWKesmBiay4ia7ENNS1q56SBwhzphOw/640?wx_fmt=png&from=appmsg "")  
  
    
     
## 7. syscall功能预估模型的CU计算错误  
  
Solana的Gas成本限制通过CU资源限制来实现的，CU计算的错误会导致合约在Solana链上执行消耗的资源(cpu、time)严重超出了限制，进一步导致潜在的Solana区块链上远程DOS攻击。  
  
在对Solana的syscall功能研究中，结合ETH网络和Solana历史漏洞同时，CertiK团队针对syscall功能的Gas成本做了深入研究，研究发现big_mod_exp syscall功能在CU成本计算存在漏洞，bits和bytes的混用，导致CU计算出问题，严重偏移了资源限制消耗，最终会导致Solana区块链远程DOS攻击。  
### 7.1：syscall功能big_mod_exp模块的作用与其CU计算模型  
  
**7.1.1：引入的pull提案**  
  
Solana的syscall中引入了大整数模幂运算功能，详细见提案：  
add big_mod_exp syscall #28503[14]。该功能类似于  
EIP-198[15]中的实现。big_mod_exp的CU计算模型如下：  
  
```
[1u8; len] for the base and exponent
 Use a prime or an RSA modulus for each bit-sizes.
```  
  
  
**7.1.2：CU计算与消耗时间预期测试结果**  
  
由于该系统调用适用于使用RSA算法的程序，输入数据最大支持2048位（支持的位数包括32、64、128、256、512、1024、2048）。CU的计算公式如下：  
  
```
计算时间（ns） = bits^2
CU = 计算时间 / 33 ns
```  
  
  
以2048位为例，预期输入的执行时间为4,194,304纳秒，其CU计算结果为：  
  
```
CU = 4,194,304 / 33 ≈ 127,100
```  
  
  
注：Solana这里最高引入了4096位的计算，对于4096位的输入，计算时间为52毫秒，对应的CU为：  
  
```
CU = 52,000,000 / 33 ≈ 1,575,757
```  
  
  
由此可以看出，big_mod_exp的CU消耗基于输入的位长度进行计算，位数越高，CU的消耗也越大。  
### 7.2：syscall功能big_mod_exp代码深入分析  
  
Solana引入#28503时，big_mod_exp功能4096 bits 的CU预算是1,575,757，而测试发现CU预算只有8043，**big_mod_exp**功能的CU计算出现了问题。  
  
big_mod_exp的关键代码位于SyscallBigModExp  
中，三个主要输入参数为base、exponent和modulus，分别对应的长度为params.base_len  
、params.exponent_len  
和params.modulus_len  
。需要注意的是，这些参数的单位是bytes：  
  
```
let params = &translate_slice::<BigModExpParams>(
            memory_mapping,
            params,
            1,
            invoke_context.get_check_aligned(),
            invoke_context.get_check_size(),
        )?
        .get(0)
        .ok_or(SyscallError::InvalidLength)?;
        if params.base_len > 512 || params.exponent_len > 512 ||
params.modulus_len > 512 {
            return Err(Box::new(SyscallError::InvalidLength));
        }
let input_len: u64 = std::cmp::max(params.base_len, params.exponent_len);
let input_len: u64 = std::cmp::max(input_len, params.modulus_len);
```  
  
  
big_mod_exp功能关键 CU计算：  
  
```
let budget = invoke_context.get_compute_budget();
        consume_compute_meter(
            invoke_context,
            budget.syscall_base_cost.saturating_add(
                input_len
                    .saturating_mul(input_len)
                    .checked_div(budget.big_modular_exponentiation_cost)
                    .unwrap_or(u64::MAX),
            ),
        )?;
```  
  
  
从代码中可以推导出CU的计算公式为：  
  
```
CU = bytes^2 / big_modular_exponentiation_cost (33)
```  
  
  
对比Solana在引入  
#28503[16]时的原始计算公式：  
  
```
CU = bits^2 / 33
```  
  
  
这揭示了漏洞的核心问题：输入的单位为bytes，但应转换为bits。正确的CU计算方式应为：  
  
```
CU = (bytes * 8) ^2 / big_modular_exponentiation_cost
```  
  
  
以4096位输入为例，正确的CU计算为：  
  
```
CU = 4096 ^ 2 / 33 ~= 508,400
```  
  
  
在当前存在漏洞的情况下，CU预算为200,000时，调用4096位的big_mod_exp功能合约的执行时间为：  
  
```
200_000 / 8043 ≈ 24
24 * 37 ms ≈ 890 ms
```  
  
  
而在最大CU上限为1,400,000的情况下，单个合约的执行时间约为6.23秒。  
  
Solana的平均出块时间约为400ms~600ms，具体出块时间可在  
Solana Explorer[17]中查看，目前约为400ms。考虑到Solana通过Proof of History（PoH）实现的共识机制及其并行事务处理能力，单个最高6.23s的合约能造成Solana集群的远程DOS攻击吗？或者并行执行多个合约呢?后续将会对Solana共识机制和事务处理展开讨论，结合有问题的big_mod_exp合约实现对本地Solana集群的远程DOS攻击。  
## 8. 深入分析Solana区块链与智能合约交互  
### 8.1：POH共识  
  
Slot和Epoch是Solana网络中的时间单位。Slot是最小的单位，432,000个Slot组成一个Epoch。PoH（Proof of History）通过可验证延迟函数（VDF）生成一系列不可预测的时间序列，用于给每个Slot中生成的区块打上时间戳。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TTB8icibuXhV3vNdM0RadgfXKHXXjzWU51JqAnq9wL8oX3maK45rqibKpAA/640?wx_fmt=png&from=appmsg "")  
  
  
Solana每笔交易都有时间作为  
交易生命周期[18]：每笔交易都包含一个“最近的区块哈希”，用作PoH时钟时间戳，并在该区块哈希不再足够“最新”时过期，在150个Slot周期内。  
  
Solana验证器会查找他们希望在区块中处理的每笔交易的区块链相应时隙编号。如果验证器找不到区块哈希的插槽号，或者查找到的插槽号比正在处理的区块的插槽号高150个以上，交易就会被拒绝：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TT40KRmhHd10cyWgxRpttJoJiaiaoOiayiaecoIjkqKRrIjIicFZ0CrHqNj5Q/640?wx_fmt=png&from=appmsg "")  
  
**Solana区块链的工作原理涉及以下6个基本步骤：**  
  
（1）**领导者选举与时隙分配**  
  
Solana网络通过基于PoS的选举机制轮流选出一个领导者（Leader）。每个领导者被分配四个连续的时间槽（Slot）来处理数据，总共持续约1.6秒（4个区块，每个区块400毫秒）。领导者的选举是随机的，概率与验证者的权益权重成正比，选举周期约为2-3天（即432,000个时隙）。  
  
（2）**领导者消息排序与数据流最大化**   
  
领导者使用Proof of History（PoH）生成一条可验证的时间序列，确保了全网的读一致性和时间的可验证性。领导者对用户提交的交易进行排序，确保验证者能够以一致的顺序处理交易，从而最大化数据流的效率并保持网络高效运行。  
  
（3）**领导者执行交易**   
  
领导者将用户提交的交易存储在RAM中，并在当前状态上执行这些交易，处理诸如代币转移、智能合约执行等操作。交易数据在RAM中的临时存储提高了处理速度和吞吐量。  
  
（4）**领导者发布交易结果**   
  
领导者在执行完交易并更新状态后，对交易集的哈希和最终状态进行签名，然后将这些信息发布给验证者（也称为复制节点），确保交易结果的不可篡改性和可验证性。  
  
（5）**验证者验证交易与最终状态**   
  
验证者接收到领导者发布的交易和状态签名后，在其本地状态副本上重复执行相同的交易，以确认最终状态的正确性。验证者通过应用分叉选择规则（Fork Choice Rule）评估领导者提出的区块，并确保其与网络的整体一致性。  
  
（6）**共识确认**   
  
验证者通过Gossip网络发布其状态签名，作为共识算法的一部分，确保网络达成一致。这些签名作为投票，用于确认区块的有效性，最终形成全网共识。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TTLBzGj0wwFMic8MV40R8sO7stic8UmrhyfpSLITLRsq7GEal7t01cSq5g/640?wx_fmt=png&from=appmsg "")  
### 8.2：并行事务处理  
  
Solana验证器中通过多线程来执行多队列的，单个线程执行单笔队列，其中参数NUM_THREADS和MIN_TOTAL_THREADS用于控制线程数量：  
  
```
 pub const NUM_THREADS: u32 = 6;
    const NUM_VOTE_PROCESSING_THREADS: u32 = 2;
    const MIN_THREADS_BANKING: u32 = 1;
    const MIN_TOTAL_THREADS: u32 = NUM_VOTE_PROCESSING_THREADS +
MIN_THREADS_BANKING;
    ...
    pub fn num_threads() -> u32 {
            cmp::max(
                env::var("Solana_BANKING_THREADS")
                    .map(|x| x.parse().unwrap_or(NUM_THREADS))
                    .unwrap_or(NUM_THREADS),
                MIN_TOTAL_THREADS,
            )
         }
```  
  
### 8.3：深入事务处理代码  
  
Solana事务处理是在一个多线程中进行的，通过调用  
process_loop[19]函数来循环处理交易事务。  
  
```
 Builder::new()
            .name(format!("solBanknStgTx{id:02}"))
            .spawn(move || {
                Self::process_loop(
                    &mut packet_receiver,
                    &decision_maker,
                    &mut forwarder,
                    &consumer,
                    id,
                    unprocessed_transaction_storage,
                )
            })
            .unwrap()
```  
  
  
在  
process_loop里面[20]通过unprocessed_transaction_storage: UnprocessedTransactionStorage循环获取待处理的交易hash，函数process_buffered_packets将带出来的交易hash传递到下层函数，最终到Solana的SVM虚拟机进行处理，receive_and_buffer_packets则循环接收待处理交易hash。  
  
```
 loop {
            if !unprocessed_transaction_storage.is_empty()
                || last_metrics_update.elapsed() >= SLOT_BOUNDARY_CHECK_PERIOD
            {
                let (_, process_buffered_packets_time) = measure!(
                    Self::process_buffered_packets(
                        decision_maker,
                        forwarder,
                        consumer,
                        &mut unprocessed_transaction_storage,
                        &banking_stage_stats,
                        &mut slot_metrics_tracker,
                        &mut tracer_packet_stats,
                    ),
                    "process_buffered_packets",
                );
                slot_metrics_tracker
                    .increment_process_buffered_packets_us(process_buffered_packets_time.as_us());
                last_metrics_update = Instant::now();
            }

            tracer_packet_stats.report(1000);

            match packet_receiver.receive_and_buffer_packets(
                &mut unprocessed_transaction_storage,
                &mut banking_stage_stats,
                &mut tracer_packet_stats,
                &mut slot_metrics_tracker,
            ) {
                Ok(()) | Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => break,
            }
            banking_stage_stats.report(1000);
        }
```  
  
  
Solana处理交易的关键在  
execute_and_commit_transactions_locked[21]，通过在SVM虚拟机执行指令，并检查错误后，将完整的交易commit提交，返回被正确记录的交易到上层process，调用了record_transactions记录交易，committer.commit_transactions提交完整的事务：  
  
```
let (load_and_execute_transactions_output, load_execute_us) = measure_us!(bank
            .load_and_execute_transactions(
                batch,
                MAX_PROCESSING_AGE,
                &mut execute_and_commit_timings.execute_timings,
                TransactionProcessingConfig {
                    account_overrides: None,
                    log_messages_bytes_limit: self.log_messages_bytes_limit,
                    limit_to_load_programs: true,
                    recording_config: ExecutionRecordingConfig::new_single_setting(
                        transaction_status_sender_enabled
                    ),
                }
            ));
        execute_and_commit_timings.load_execute_us = load_execute_us;
        .......
        .......
        let (record_transactions_summary, record_us) = measure_us!(self
            .transaction_recorder
            .record_transactions(bank.slot(), executed_transactions));
        execute_and_commit_timings.record_us = record_us;
        .......
        ......
        let (commit_time_us, commit_transaction_statuses) = if executed_transactions_count != 0 {
            self.committer.commit_transactions(
                batch,
                &mut loaded_transactions,
                execution_results,
                last_blockhash,
                lamports_per_signature,
                starting_transaction_index,
                bank,
                &mut pre_balance_info,
                &mut execute_and_commit_timings,
                signature_count,
                executed_transactions_count,
                executed_non_vote_transactions_count,
                executed_with_successful_result_count,
            )
        } else {
            (
                0,

                vec![CommitTransactionDetails::NotCommitted; execution_results.len()],
            )
        };
```  
  
  
正常合约完整执行过程为（SVM虚拟机执行->记录交易->提交交易）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TTl7FDqUpN1sxluKHUyibiaLhAErufnGbMCxicPCQJ8GHPiboZ6NtLeH9few/640?wx_fmt=png&from=appmsg "")  
  
    
### 8.4：存在CU漏洞的合约会跨Slot导致事务处理混乱  
  
分析完Solana的POH共识机制和并行事务处理方式，这里引入带有CU计算漏洞的big_mod_exp合约，结合漏洞探究其对Solana链上执行合约造成的影响和原理。  
  
当执行一次带有4096位big_mod_exp功能的合约，在默认200,000CU上限中，执行时间890ms的可以跨越1-2个Slot，当跨越Slot将会导致  
record[22]失败，是因为交易后传入的原始Slot比当前slot慢1-2个Slot，返回PohRecorderError::MaxHeightReached错误：  
  
```
if bank_slot != working_bank.bank.slot() {
                return Err(PohRecorderError::MaxHeightReached);
            }
```  
  
  
上文我们分析了Solana的交易是存在  
生命周期[23]的，而其生命周期的控制是通过参数 MAX_PROCESSING_AGE，MAX_PROCESSING_AGE的值为150也就是对比是否小于150 Slot，带有big_mod_exp漏洞的合约因为跨了Slot导致事务失败，失败后Solana会比较当前Slot和 MAX_PROCESSING_AGE，只要小于150 Slot,Solana会设置retryable_transaction_indexes为0，并且返 回到process_packets填充retryable_packets，重新retry当前交易：  
  
```
fn process_packets<F>(
        &mut self,
        bank: &Bank,
        banking_stage_stats: &BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        mut processing_function: F,
    ) -> bool
    where
        F: FnMut(
            &Vec<Arc<ImmutableDeserializedPacket>>,
            &mut ConsumeScannerPayload,
        ) -> Option<Vec<usize>>,
    {
        let mut retryable_packets = self.take_priority_queue();
        let original_capacity = retryable_packets.capacity();
        let mut new_retryable_packets = MinMaxHeap::with_capacity(original_capacity);
        let all_packets_to_process = retryable_packets.drain_desc().collect_vec();
        ..............
                ..........
                while let Some((packets_to_process, payload)) = scanner.iterate() {
            let packets_to_process = packets_to_process
                .iter()
                .map(|p| (*p).clone())
                .collect_vec();
            let retryable_packets = if let Some(retryable_transaction_indexes) =
                processing_function(&packets_to_process, payload)
            {
                Self::collect_retained_packets(
                    payload.message_hash_to_transaction,
                    &packets_to_process,
                    &retryable_transaction_indexes,
                )
            } else {
                packets_to_process
            };

            new_retryable_packets.extend(retryable_packets);
        }
        .......
      }
```  
  
  
所以最后带有CU计算漏洞的bid_mod_exp合约将会重复执行150次后，最后导致交易过期失败，而 MAX_PROCESSING_AGE的检查在  
chek_transaction_age[24]调用4096位的big_mod_exp功能合约：200_000 / 8043 ~= 24, time : 24 * 37 ms ~= 890 ms，而retry 150次后，整个交易将会在133,500ms，约130s后结束，长期占用资源将会导致队列堵塞。将会是以下过程：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TTbbza86UPz5c4T4EbaHPvgWGPA3SF20tBXm8CtVlDn1B5tfhx1sXESA/640?wx_fmt=png&from=appmsg "")  
## 9. 在搭建的Solana私有集群上复现远程DOS攻击  
  
本地测试准备了10-20个独立账户，每个独立账户调用一次带有4096位的big_mod_exp功能的合约，都是默认200,000CU上限，同时运行多个独立账户的正常合约进行对比：  
  
**私有集群测试**  
  
私有集群总计4个节点，包括Leader Node、User RPC Node、Attacker RPC Node、Node4 , User界面通过10个独立账户调用正常合约执行，正常合约调用从rpc客户端请求到返回结束平均花费740ms左右，Attacker是模拟攻击者的界面，通过20个独立账户，每个账户调用20次带有4096位的big_mod_exp功能合约，以下截图是模拟攻击攻击发送了20次恶意合约的场景，可以观察到Leader Node的cpu已经是满负荷运行， 并且User界面已没有正常合约调用的rpc返回：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TTicKMqcDib9nv1APWPdEjlwvsyfe0mvjk19a5eKbiagwKsDaDMKCmmdPYg/640?wx_fmt=png&from=appmsg "")  
  
测试结果显示私有集群和本地集群在一次性处理多个(20)独立账户带有4096位的big_mod_exp功能的合约时，总计调用20次，出现了长时间高达(133s)的堵塞，反复攻击将会造成严重的DOS攻击！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TTicAVesxxicsPDOXBeUibQhhQkJp58dlqNic7lWCpBMdiaeQRFnaVy6BPk1Q/640?wx_fmt=png&from=appmsg "")  
## 10. 远程DOS攻击成本  
  
一次攻击成本预估：带有4096位的big_mod_exp功能的合约在本地集群运行时，由于交易过期被drop掉,Gas费后续都为0，Solana的CU计算成本类似ETH的Gas计算，通过限制合约消耗的网络资源来防止远程DOS攻击，Solana 引入的预估费用计算模型存在的缺陷带来了CU计算漏洞，导致了严重的资源消耗偏移，最终导致潜在的远程DOS攻击。  
  
幸运的是Solana在引入syscall新功能前会经过大量测试和验证并且包括了和外部安全研究员漏洞赏金合作的模式，确保了上线后的稳定性，这次提前发现了Solana的syscall的big_mod_exp功能存在严重的漏洞，维护了Solana网络的稳定性和安全性!  
## 11. 漏洞确认与修复  
  
Solana确认了CertiK团队提交的大整数模幂运算(big_mod_exp)中CU计算错误将会导致潜在的远程DOS攻击，并分类为DOS攻击漏洞，Solana开发者  
修复方案[25]重新计算了big_mod_exp的CU成本，通过重新基准测试模幂运算的性能，调整计算单位（CU）为 N^2/2 + 190,虽然修复不是把bytes置换成bits，但是重新计算了大整数模幂运算的CU成本最终修复了安全漏洞，根据安全公告未来可能还会优化算法以提高性能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TTOricav0okJCQqF8iaoVam0myZgqLswUZr5Nsk2KOhZxDjaaVeiaDicbecA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TTHNxNmA3sdliabvp4HMy2u72xPla1SWbHQibk7mqO9IWbvWzJOUBorQqQ/640?wx_fmt=png&from=appmsg "")  
  
### 参考：  
  
[1]  
 伦敦升级: https://ethereum.org/zh/history/#london[2]  
 当前查询: https://cn.etherscan.com/Gastracker[3]  
 EIP-1559: https://eips.ethereum.org/EIPS/eip-1559[4]  
 当前查询: https://etherscan.io/[5]  
 查询: https://beta-analysis.solscan.io/public/dashboard/06d689e1-dcd7-4175-a16a-efc074ad5ce2[6]  
 查询: https://solscan.io/analytics[7]  
 橘子哨（Tangerine Whistle）分叉: https://ethereum.org/zh/history/#tangerine-whistle[8]  
 伪龙（Spurious Dragon）分叉: https://ethereum.org/zh/history/#spurious-dragon[9]  
 EIP-150: https://eips.ethereum.org/EIPS/eip-150[10]  
 EIP-161: https://eips.ethereum.org/EIPS/eip-161[11]  
 8项关键创新: https://medium.com/Solana-labs/proof-of-history-a-clock-for-blockchain-cf47a61a9274[12]  
 2022年1月 – 严重的网络拥塞: https://twitter.com/SolanaStatus/status/1484947431796219906?s=20&t=x6Itu5Yn_8-HtapAyLBrfA[13]  
 2022年4月和5月 – 短暂的中断: https://solana.com/news/04-30-22-Solana-mainnet-beta-outage-report-mitigation[14]  
 add big_mod_exp syscall #28503: https://github.com/Solana-labs/Solana/pull/28503[15]  
 EIP-198: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-198.md[16]  
 #28503: https://github.com/Solana-labs/Solana/pull/28503[17]  
 Solana Explorer: https://explorer.solana.com/[18]  
 交易生命周期: https://docs.solana.com/developing/transaction_confirmation[19]  
 process_loop: https://github.com/anza-xyz/agave/blob/5263c9d61f3af060ac995956120bef11c1bbf182/core/src/banking_stage.rs#L644C8-L656C22[20]  
 process_loop里面: https://github.com/anza-xyz/agave/blob/5263c9d61f3af060ac995956120bef11c1bbf182/core/src/banking_stage.rs#L742[21]  
 execute_and_commit_transactions_locked: https://github.com/anza-xyz/agave/blob/5263c9d61f3af060ac995956120bef11c1bbf182/core/src/banking_stage/consumer.rs#L569[22]  
 record: https://github.com/anza-xyz/agave/blob/master/poh/src/poh_recorder.rs#L942[23]  
 生命周期: https://solana.com/docs/advanced/confirmation[24]  
 chek_transaction_age: https://github.com/anza-xyz/agave/blob/5263c9d61f3af060ac995956120bef11c1bbf182/runtime/src/bank.rs#L3513[25]  
 修复方案: https://github.com/anza-xyz/agave/commit/eb37b21d4d5ed29d1bf40c9ca7c64509681a2a09  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKkH4zQB26zY7BpBXc0nM6TThxy5lY7a5BUkRyCOKibIckKf3hTLIibrsFty6CD6tFmJtlLL9Zr5EuYA/640?wx_fmt=png&from=appmsg "")  
  
