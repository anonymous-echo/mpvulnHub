#  探索 NASA CryptoLib 的 SDLS 实现中的漏洞   
 Ots安全   2024-12-25 10:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudB7XwrnvjlwzfyP0WibY5F4EnBkJM3IvkfOJbPxk0NgCC0ibmlDXHyF0g/640?wx_fmt=jpeg&from=appmsg "")  
  
介绍  
  
作为 ESTEC 系统安全工程团队的一名青年实习生，我被分配了一项任务，即分析地面和太空部分之间空间通信中使用的协议的安全性。范围很广，包括许多协议、标准（CCSDS 和 ECSS）和不同的实现，但这是一个具有挑战性的学习机会。这些活动导致了一些工具的开发，提供了一个名为 SPACE-SAT（空间协议分析、CCSDS 和 ECSS 安全评估工具集）的工具集。本文是这些活动的成果，描述了NASA Crytolib软件 v1.3.[0,1] 中发现的多个漏洞，该软件是一种纯软件解决方案，实现了空间数据链路安全协议 (SDLS)，用于保护地面部分和航天器之间的空间通信。  
  
已发现的漏洞使攻击者能够向航天器的机载计算机 (OBC) 发送任意遥控命令，从而可能导致不良行为。更严重的是，攻击者可以获得对航天器的独占控制权。换句话说，攻击者可以执行任何操作，完全绕过 SDLS 实现，甚至利用 SDLS 实现阻止合法操作员的访问。  
  
在本文中，我首先描述越界漏洞，并解释如何利用它来绕过 SDLS。接下来，我将介绍一种新的漏洞，该漏洞还允许攻击者绕过 SDLS 向航天器发送命令。然后，我将讨论 SDLS 扩展程序实施中的另一个漏洞，该漏洞使攻击者能够劫持卫星。随后，我将解释如何在不知道密钥的情况下解密合法的远程命令。最后，我将概述 CryptoLib 在安全性方面的 V&V（验证和确认）策略，并介绍漏洞补丁。  
  
**空间数据链路安全协议的背景**  
  
空间数据链路安全协议 (SDLS) 是由空间数据系统咨询委员会 (CCSDS) 标准化的第 2 层协议。它旨在通过提供的三种安全服务来保护任务控制系统 (MCS) 和卫星之间的帧数据有效载荷：  
- 身份验证（包括完整性保护）  
  
- 加密  
  
- 经过身份验证的加密。  
  
第四种服务也是标准化的，但不太为人所知，因为不推荐使用：Clear Mode 或透明模式。使用此服务时，SDLS 协议标头存在，但不执行加密操作。因此，此解决方案不提供任何形式的安全性。  
  
对于 SDLS 提供的所有安全服务，都会在帧中添加一个安全标头和（可选）尾部，以提供接收端执行安全验证所需的必要上下文信息，如图 1 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudetFL0O1GqIZyVG2qVu4rxHbcR14TUEiaakQD4qiaNHSGZYVRle1HibSeQ/640?wx_fmt=png&from=appmsg "")  
  
图 1：带有 SDLS 头和尾的 TC 帧  
  
SDLS 是一种状态协议，它依赖于发送端和接收端（任务控制系统和航天器）存储的安全关联 (SA)，定义加密通信参数来执行上述四种服务之一。接收方使用安全标头中的安全参数索引 (SPI) 来引用相应的 SA。利用帧安全字段和 SA，接收端可以执行安全验证。  
  
为了管理 SDLS 协议的实施，一组辅助服务已标准化，称为 SDLS 扩展程序。这些命令允许航天器操作员管理 SDLS 的安全参数（密钥管理、SA 管理、监控和控制）。例如，操作员可以将新密钥上传到航天器内存中，或将 SA 状态从“操作”更改为“过期”。  
  
为了进一步了解 SDLS，我建议看一下空间数据链路协议安全蓝皮书  
  
**崩溃的 CryptoLib**  
  
为了完成 SPACE-SAT 的开发，需要其他符合 CCSDS 的实现来交叉检查我的实现。NASA CrytoLib就是其中之一，它为TC、TM和AOS数据链路协议提供了两种主要安全功能：  
- Crypto_[TC,TM,AOS]_ApplySecurity：从有效帧生成符合 SDLS 的帧  
  
- Crypto_[TC,TM,AOS]_ProcessSecurity：解析并执行 SDLS 帧的安全验证。  
  
Crypto_TC_ProcessSecurity 函数无疑是航天器安全评估中最有趣的函数。它是与陆地世界交互的第一个保护措施（有时是唯一的保护措施）（类似于网络上的 https 服务器，但访问起来更具挑战性）。因此，潜在的恶意行为者也可能尝试向此接口发送帧。  
  
SPACE-SAT 的功能之一是基本的模糊测试功能，它能够通过用随机数替换已实施协议的选定字段的值来模糊这些字段。这允许对空间协议解析器进行首次稳健性测试。我对照CryptoLib 进程安全程序（用于测试功能的小型接口）交叉检查了该工具，测试成功，而且很快就证明了它成功了。通过模糊测试 SPI，许多值导致分段错误，如图 2 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudPEic3C2bSLia2c3hcibmg2jVPVibOOiaaB01h6ptSUfFNdlBSL3ibQMl5Z0A/640?wx_fmt=png&from=appmsg "")  
  
图 2：CryptoLib 因 SPI=16705 崩溃  
  
由于 CryptoLib 是开源的，因此很容易确定崩溃的原因。CryptoLib 使用C 结构来表示存储在静态数组中的每个 SA（这是嵌入式系统中更好地管理内存的常见做法），并使用 SPI 作为数组索引（例如，SA 1 由 sa[1] 访问）。使用这种内存管理，实现可能需要大量内存，因为根据标准有 65536 个 SPI 可用，并且当前实现中每个 SA 结构约为 200MB。为了限制内存消耗，CryptoLib 开发人员定义了一个预处理器指令NUM_SA，它缩小了可用 SA 的数量（默认为 64）。但是，他们没有在程序中引入对标准允许的最大值和其实现支持的最大值之间的 SPI 值的检查。因此，如果提供的 SPI 不在 [0, NUM_SA] 范围内，程序仍将使用 SPI 读取位于 sa[SPI] 的内存。这会导致越界读取漏洞。VisionSpace 于 2024 年夏天通过CVE-2024-44911披露了此漏洞，并通过检查解析的 SPI 是否在 [0, NUM_SA] 范围内进行了修复。CVE 正在影响航天器的可用性，但正如我们将在下一节中看到的那样，遥控命令的真实性也会受到影响。  
  
**CryptoLib 的崩溃影响**  
  
SDLS 是一个提供依赖于状态（有状态实现）的加密服务的库。在 SDLS 的上下文中，必须跟踪两个主要值以确保安全通信：  
1. 防重放序列号 (ARSN)  
  
1. 初始化向量（IV）  
  
ARSN 保护系统免受重放攻击，而 IV 确保即使使用相同的密钥，两个明文块也不会具有相同的密文。在 AES-GCM 中，初始化向量保存着 ARSN，该向量每增加一帧就会增加一。此计数器在请求中发送，其值由 MCS 和航天器仔细跟踪。在 CryptoLib 的情况下，计数器保存在航天器的易失性存储器中。因此，当越界漏洞被利用时，它不仅会使服务暂时不可用，而且还会重置加密计数器（在VisionSpace 的视频文章中，核心飞行系统 (cFS) 在段错误后重新启动并启动一个新实例）。如果没有定义程序以安全的方式处理这种情况，航天器将容易受到 TC 重放攻击，其 TM 帧将在重启后使用相同的 IV（IV 重用）。有能力嗅探合法命令的攻击者可以随心所欲地重放这些命令，因为他只需重新启动存在越界读取漏洞的系统即可使命令再次有效。因此，导致系统崩溃的越界读取漏洞也可能导致 SDLS 实现的完整性问题。  
  
**利用越界读取漏洞绕过 SDLS**  
  
利用越界读取漏洞，我们能够读取任意内存，但不能读取整个内存空间。在关注典型的 C 漏洞利用（例如远程代码执行）时，我找不到任何路径，因此我决定退后一步，考虑 SDLS 的特殊性，尤其是上面介绍的清除模式。我认为，如果我能找到指向内存空间并返回清除模式 SA 的 SPI，那么就有可能绕过 SDLS 保护（即向机载计算机发送远程命令）。要执行漏洞利用，必须回答两个问题：解析器中触发清除模式 SA 的条件是什么，有效载荷数据单元 (PDU) 在 SDLS 解析后有效的条件是什么（因为如果我可以绕过安全检查，但 OBC 始终会拒绝远程命令并将其视为无效，那么漏洞利用就没那么有用了）。  
  
**触发清除模式 SA 的条件**  
  
CryptoLib 库实现了清除模式（也称为 SA_PLAINTEXT），当 SA 结构属性加密服务类型（est）和身份验证服务类型（ast） 都等于零时触发，如从源代码中提取的下面代码片段所示。  
  
```
int32_t Crypto_TC_Get_SA_Service_Type(uint8_t* sa_service_type, SecurityAssociation_t* sa_ptr)
{
    int32_t status = CRYPTO_LIB_SUCCESS;
    if ((sa_ptr->est == 0) && (sa_ptr->ast == 0))
    { *sa_service_type = SA_PLAINTEXT; }
    else if ((sa_ptr->est == 0) && (sa_ptr->ast == 1))
    { *sa_service_type = SA_AUTHENTICATION;}
    else if ((sa_ptr->est == 1) && (sa_ptr->ast == 0))
    { *sa_service_type = SA_ENCRYPTION; }
    else if ((sa_ptr->est == 1) && (sa_ptr->ast == 1))
    { *sa_service_type = SA_AUTHENTICATED_ENCRYPTION;}
    else
    {[...]
    }
    return status;
}
```  
  
  
为了使 SA 可用，它还必须通过健全性检查，即测试配置的一致性（例如，确保 SDLS 标头 IV 长度小于或等于 IV 长度）。因此，如果我们提供一个可以读取内存的 SPI，其中est和ast字段为零（2 个字节），并且所有其他属性都通过一致性测试，则解析的帧将使用清除模式 SA。  
  
**SDLS 解析后有效载荷数据单元 (PDU) 有效的条件**  
  
在检查确定 PDU 的所有 SA 结构属性（主要是诸如次级报头 iv长度 shivf_len、次级报头长度shsnf_len、次级 pad 长度shplf_len和次级尾部 mac 长度stmacf_len等字段）时，我得出结论：最好让所有这些属性都等于零。幸运的是，所有这些属性都等于零的 SA 是有效的 SA，即通过了健全性检查。  
  
因此，我使用 SPACE-SAT 生成带有 SPI 字段的帧，同时使用 cryptolib 的包装器。在模糊测试的背景下，我只需等待 cryptolib 崩溃即可捕获被利用的漏洞，但这次，我需要知道处理何时成功。由于我的帧生成器设置为不执行任何加密操作，因此处理成功的唯一方法（即不崩溃且错误代码 == CRYPTO_LIB_SUCCESS）是触发清除模式 SA。开发了一个自定义包装器来返回处理状态：CRYPTO_LIB_SUCCESS、其他 cryptolib 错误代码或段错误。  
  
经过几次尝试，我们发现一个 SA（值为 8327）不在 [0,NUM_SA] 范围内（图 3）。我们可以看到，返回代码为 0（表示 CRYPTO_LIB_SUCCESS）；所有 SA 属性均为零（通过健全性检查）。因此，我们成功绕过了 SDLS 保护！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudhxP3MpcWXjq2Ye5oPKSOjVjbV2dMW1oexQFDAYTnAlnxaibhaOKWqWA/640?wx_fmt=png&from=appmsg "")  
  
图3：使用SPI=8327绕过CryptoLib  
  
攻击可能不是确定性的，因为满足 SDLS 旁路条件的任意读取数据的位置在程序的不同执行之间并不总是相同的。此外，这些数据可能会在操作期间发生变化，这意味着先前识别的程序内存可能不再触发有效的清除模式 SA。对程序内存进行更高级的分析可以使这种攻击更具确定性。但是，由于我发现了更有效的利用方法，所以我没有在这次攻击上花费更多时间。  
  
**绕过 SDLS 的简单方法**  
  
在分析成功绕过的输出时，我意识到我已经确定了一个特定的 SA 状态，其中几乎所有结构属性都设置为零（包括est和ast）。因此，SA 通过了健全性检查并返回了清除模式 SA。此行为是 sa_init() 函数的结果。该函数循环遍历所有 SA 属性并将其设置为零，但三个特定属性除外。为了理解这一点的含义，让我们分三个阶段检查 SA 内存管理：  
1. SA_CREATED：包含 SA 的数组是根据 NUM_SA 变量静态创建的。  
  
1. SA_INITALISED：sa_init() 函数将所有属性设置为零。  
  
1. SA_CONFIGURED：然后，sa_configure() 函数将使用提供的配置覆盖 SA，如默认配置中所定义 。  
  
如果 sa_configure() 函数没有覆盖 SA，SA 将保持其初始化状态。在默认配置中，初始化了 64 个 SA，但仅配置了 17 个。因此，43 个 SA 保持初始化但未配置，并且这些 SA 是有效的清除模式 SA，如前所示。此外，没有检查安全关联状态，默认情况下设置为SA_NONE 。这会导致一种称为动态管理代码资源控制不当的漏洞。  
  
使用 SPACE-SAT，我生成了一个帧，其 TC 标头为002C00C000，SPI 等于002C（仅初始化 SA 44 ），有效载荷为414243444546。我稍微修改了CryptoLib 进程安全程序，以显示解析后的返回代码和数据有效载荷。如图 4 所示，SA 44 被解析为 TC Clear SA。返回代码为 0（即 CRYPTO_LIB_SUCCESS），TC PDU 是我们的有效载荷。这样，我成功绕过了 NASA CryptoLib 的 SDLS 保护！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudTia4orVISpcnKRB6gxaHIcCW0iaRTnmDZA5RjibgldS5XTx0V7u4FlsWA/640?wx_fmt=png&from=appmsg "")  
  
图4：使用SPI=44绕过CryptoLib  
  
**使用 SDLS 扩展程序劫持航天器**  
  
根据标准，应使用具有特定 SPI 的专用通道向航天器发送 EP 命令（特别是 SPI 1 和 65535）。但是，CryptoLib 并未根据标准实现这一点。为了检测 SDLS-EP PDU，CryptoLib 会在太空数据包协议中查找特定的 VCID 或特定的 APID。如果满足其中一个条件，则将 PDU 解析为 SDLS-EP PDU。因此，可以利用先前发现的漏洞发送 SDLS-EP 命令。CryptoLib 并未根据标准实现这一点。为了检测 SDLS-EP PDU，CryptoLib 会在太空数据包协议中查找特定的 VCID 或特定的 APID。如果两个条件之一匹配，则将 PDU 解析为 SDLS-EP PDU。因此，可以利用先前发现的漏洞发送 SDLS-EP 命令。能够发送 EP 命令是一种巨大的能力。我们可以想象这样一种场景：我们设法删除所有现有的安全关联 (SA)，然后上传我们自己的 SA，从而独占控制航天器并拒绝航天器操作员的访问。要执行此场景，需要以下 SDLS-EP 命令：  
- sa_stop() 停止 SA 运行  
  
- sa_expire() 解除 SA 密钥  
  
- sa_delete() 删除现有 SA  
  
- Crypto_Key_OTAR() 上传我们的密钥  
  
- sa_create() 创建我们的 SA  
  
- sa_rekey() 将 SA 与我们的密钥链接起来  
  
- sa_start() 将 SA 设置为运行状态  
  
所有这些命令均由 CryptoLib 实现。但是，有一个限制：OTAR 程序在通道安全性之上增加了一层额外的安全性。专用于此 SDLS-EP 命令的主密钥用于加密和验证 OTAR PDU。因此，要上传密钥，我们需要知道一个主密钥。  
  
OTAR 程序 PDU 如图 4 所示。操作员上传加密密钥 ID 和加密密钥，这两者都经过加密并使用 MAC 进行完整性保护。主密钥 ID（表示使用的密钥）和初始化向量 (IV) 是航天器用于验证真实性和解密 PDU 的加密参数。对于此加密操作，不使用安全关联（这也意味着没有 ARSN 并且没有 IV 重用的跟踪）。因此，我们不能直接使用我们新的 SA 绕过漏洞；但是，我们仍然可以应用相同的基本思想。我们需要确定一个我们知道其值的主密钥 ID。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudiaGib9aIfNSJnB0V3HbTE1NTtm44FEU4sjHul2j1KSiamvlrkKcrJ9LicQ/640?wx_fmt=png&from=appmsg "")  
  
图 4：基线实施 OTAR 程序  
  
密钥内存管理类似于 SA 内存管理。使用静态数组来存储由密钥值、密钥长度及其状态组成的结构。内存初始化为全零，然后应用配置，覆盖初始配置。与 SA 解析器相比，密钥解析器不易受到越界读取攻击，因为在检索密钥时会执行检查。但是，与 SA 解析器一样，密钥的状态在使用前不会得到验证，因此初始化密钥被视为有效密钥。在这种情况下，这意味着可以使用全零密钥。唯一需要满足的条件是主密钥 ID 必须低于 128，这很容易实现。  
  
使用 SPACE-SAT，我使用 SPI 44 生成一个帧以绕过安全通道，并使用 VCID 4 向航天器通知 SDLS-EP 命令。在有效载荷内，有一个带有我自己的密钥（密钥 ID 129）的 OTAR 命令。我使用已初始化但未配置的密钥（即主密钥 ID 64）。密钥 ID 和密钥值使用值为零的 256 位密钥和值为零的 96 位 IV 进行加密。如图 5 所示，OTAR 程序有效，返回代码为 0（即 CRYPTO_LIB_SUCCESS）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudGzGHEmZE1icN4XXxkf66DXQBMJibE155DZ6UPXndHzKWUTED4LcrMuVw/640?wx_fmt=png&from=appmsg "")  
  
图 5：使用主密钥 64 上传新密钥  
  
对于其他程序，无需进行任何黑客攻击，只需遵守数据格式即可。版本 1.3.1 中引入的新功能允许在实例之间保存和加载 sa 数组，用于见证状态的变化。下图显示了 SA 1 的示例，已使用我们的新密钥进行了全面更新。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudF8U0fhkT632ESRIF1788UpmR5oic23v7dIzRgy1ic5P5r0XwQ1MJZibPw/640?wx_fmt=png&from=appmsg "")  
  
图 6：停止和过期 SA 1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHuddM0Y5GG0QhRdibseIbT4JhB9edibVpoAkvIgDXqT0goALTZ8ZGwjgCLA/640?wx_fmt=png&from=appmsg "")  
  
图 7：删除和创建 SA 1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudmT6zoYM09a1SoBd8Loouw0WprDCz6Ku9Tc35R7wuBMLhXzUp1ZzxWQ/640?wx_fmt=png&from=appmsg "")  
  
  
图 8：重新密钥并激活 SA 1  
  
然后，攻击者对其他 63 个 SA 重复相同的程序，并且操作员将被拒绝与航天器通信（直到它重新启动，因为 SA/密钥存储在易失性存储器中）。  
  
我们已经证明劫持航天器的所有必要功能都已实现，使攻击变得可行。与之前的漏洞类似，我们可以将此漏洞归类为对动态管理代码资源的不当控制。  
  
**无需密钥即可解密航天器操作员的遥控指令**  
  
尽管对卫星拥有独家控制权，但仍有几个关键细节未知，例如上层使用的协议（例如 SPP/PUS）及其配置（例如如何触发轨迹修改）。收集更多信息的一种方法是嗅探来自 MCS 的合法流量。如果流量未加密，我们可以对协议及其配置进行逆向工程。但是，如果流量是加密的，我们首先需要解密帧，但由于我们不知道密钥，并且没有 EP 命令可以返回它，因此这是一个挑战。尽管如此，如果我们设法触发 IV 重用，当使用 AES GCM 时，我们可以在不知道密钥的情况下解密加密的有效载荷。当两个消息使用相同的 IV 时，它们的关系是 M1 xor E1 = M2 xor E2，其中 Mx 是明文消息，Ex 是相应的加密消息。  
  
因此，如果 4 个变量中有 3 个已知，就可以恢复第四个变量。例如：M2 = M1 xor E1 xor E2  
  
密钥验证程序允许验证一组活动密钥。这向航天器操作员确认密钥没有被破坏或修改并且完全可操作。为了验证密钥，操作员向航天器发送一个带有 key_id 的质询（随机数）进行测试。然后，航天器对质询执行经过身份验证的加密，并通过回复 pdu 返回使用所用 IV 加密的质询。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudpJI7Dwicsb7EuEIaMeJvtYmVStloZlpWgVIia6Jlr8Bk5uNEUwhKPIiaQ/640?wx_fmt=png&from=appmsg "")  
  
图 9：密钥验证 PDU  
  
关于此过程（和 OTAR 过程）的一个重要概念是它们不通过安全关联使用密钥。因此，不会执行 SA 提供的所有功能，包括 ARSN 检查和 IV 管理。实施者必须选择另一种方法来管理这一点。正如 sdls-ep 绿皮书中提到的那样，“防止密钥/IV 冲突是特定于实现的”。在 CryptoLib 的情况下，他们选择使用发送密钥验证命令的 TC 帧的 IV 并加 1（即 TC IV+1）来加密质询。由于我们有能力发送具有任何 IV 的 TC 帧并发送密钥验证过程，因此可以触发操作员用于发送遥控命令的密钥上的 IV 重用。此设置称为密钥流oracle，使我们能够恢复用于加密特定 IV 的操作员遥控命令的伪随机流。  
  
为了模拟来自操作员的合法帧，我使用 SPACE-SAT 生成一个使用 AES-GCM 加密和验证的帧，使用 key_id 0 和一个容易识别的有效载荷000102030405060708090A0B0C0D0E0F，IV=1，如图 10 所示。返回的加密有效载荷是CEOBB48BD837463A1B373F553E00D523。目标是恢复此帧的明文有效载荷。目前，我们有 4 个变量中的 1 个（E1）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHud17Ks0PTyNBwdRzmDR7dtYEPp9KEx922R4cM5rWv02IQ1ySHq7ndoNg/640?wx_fmt=png&from=appmsg "")  
  
图 10：SPACE-SAT 的输出  
  
作为攻击者，我生成一个密钥验证命令，嵌入在 IV=0 的 TC 帧中。我们现在知道 4 个变量中的 2 个（E1、M2）。此 SDLS-EP 命令被发送到航天器。图 11 显示了我们挑战的处理输出（通常，我们会从 TM 通道收到此回复）。加密前的帧数据代表我们的挑战，而加密后的帧数据是加密的挑战（E2）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudqwia45HEpXXI6AiclIFKK8RhLIQzo4fibiawU2ZMKuKe7j9eK3bVfYMe2g/640?wx_fmt=png&from=appmsg "")  
  
图11：输出处理密钥验证命令  
  
现在我们手上有 3 个变量，可以恢复第四个变量（M1）。XOR 运算足以恢复明文消息，如图 12 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudSYwlMKRa2GbHZoTLbI2s2pF4ibRKCyPH48XJUd2aFib5NE71yTqLCpMw/640?wx_fmt=png&from=appmsg "")  
  
图 12：解密 tc 框架  
  
我们成功恢复了初始有效载荷！然而，由于挑战的大小是固定的（16 字节），因此这种攻击受到限制。我们无法完全解密 PDU 大于 16 字节的 TC 帧，但我们仍然可以了解密钥信息。有了 16 个字节，我们可以确定使用了哪些协议和配置（例如，SPP 的 APID），甚至可以在 PUS（服务和子服务）的情况下识别应用层命令头。此外，密钥验证程序函数被硬编码为仅验证密钥 0，因此从今天起，它对其他密钥不起作用。重要的是要注意，虽然实现现在还没有完全受到攻击，但明天可能会变得如此。  
  
**验证和确认策略的安全性**  
  
CryptoLib wiki 页面通过 6 个步骤提供了有关其验证和确认策略的更多信息：  
1. 兼容性测试，  
  
1. 单元测试，  
  
1. 验证测试，  
  
1. 系统测试，  
  
1. 回归测试，以及  
  
1. 静态代码分析。  
  
尽管 V&V（验证和确认）策略定义明确且结构合理，但我在此处描述的漏洞并未被发现。我认为缺少开箱即用的测试，即检查它是否执行了实施不期望执行的操作。例如，在策略中添加模糊器可以检测到越界漏洞，并且通常可以检测到任何会导致崩溃的输入。这就是我所做的，我相信 VisionSpace 安全团队根据他们的发现也做了同样的事情。然而，即使实施了这一点，也不会发现新的漏洞。其他方法/工具（如污点分析、符号执行、使用负面测试完成单元测试或在策略中使用 SPACE-SAT）可能有助于检测漏洞。NIST 提供了一些指南，其中包括软件安全验证策略和工具。  
  
**负责任的披露、缓解和修补**  
  
我负责任地向 CryptoLib 开发人员披露了这些漏洞，并提出了缓解措施。在收到他们的确认后，我才公开了这篇博文，我可以自由发布  
  
下表总结了所提出的漏洞以及建议的缓解措施及其实施方案，包括对相应拉取请求的引用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadhkzMbpPpSw6NfJHUgsHudc3LHiaQFyk98a35zwwOpnj7EQJuibjZUMJafsibLAyf8xOKGOacsZS51A/640?wx_fmt=png&from=appmsg "")  
  
VisionSpace 披露的越界读取漏洞已在PR269中得到解决。  
  
**结论**  
  
本文展示了一种利用 NASA CryptoLib 越界读取漏洞的方法，从而绕过 SDLS 实现，同时也帮助发现了一种新的漏洞，即对动态管理的代码资源的不当控制，从而导致同样的结果。此外，我们还展示了攻击者可以利用缺乏状态验证来独占控制航天器。此外，我们还展示了如何将密钥验证程序用作密钥流预言机。这些发现突出了 SDLS 实现的复杂性，旨在提高太空界的认识。  
  
**致谢**  
  
我要感谢 NASA 将这个库开源，这对任何使用太空通信协议的人来说都是非常有益的。我想如果没有 Antonios Atlasis 的鼓励，我就不会写这篇文章。我要感谢 Antonios 和 Yohann Roiron 的审阅。  
  
**词汇表**  
  
AOS-- 先进轨道系统  
  
CCSDS-空间数据系统委员会  
  
ECSS——欧洲空间标准化合作  
  
ESTEC-欧洲空间研究与技术中心  
  
OBC——车载计算机  
  
MCS——任务控制系统  
  
PDU——分组数据单元  
  
PUS – 数据包利用服务  
  
SA——安全协会  
  
SDLS——空间数据链路安全  
  
SPACE-SAT - 空间协议分析、CCSDS 和 ECSS 安全评估工具集  
  
SPI——安全参数索引  
  
TC——遥控  
  
TM——遥测  
  
V&V——验证与确认  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
