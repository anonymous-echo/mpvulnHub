#  网络安全知识：漏洞管理五大原则（英国NCSC）   
何威风  河南等级保护测评   2024-03-07 00:00  
  
英国的  
NCSC给出了一个关于漏洞管理的指导性文件，在面对系统漏洞时，全世界都存在着共同的问题，而方法论或许有些许不同，不过总体来说都是客观的处理方式。  
我们译介过来，权当我们的他山之石，为我所用。  
而其中国情不一致的地方，则采取拿来主义，取其精华去其糟粕即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rTibWNx9ARWn0Dg8JicgSiaTx8IZEQhPKib1lFTtN4PcJsPk0mJrQzDt7ibwC8EcmTW00Y9nk6bKXegKGMxlAT9ogbw/640?wx_fmt=png&from=appmsg "")  
  
所有系统都存在漏洞。它们可能表现为需要系统管理员解决的配置问题、需要供应商更新的软件缺陷，甚至是供应商尚不知道存在且无法采取缓解措施的漏洞。  
  
这使得漏洞管理成为组织的关键控制措施。  
  
有效的漏洞管理流程使您的组织能够了解并定期验证您的技术资产中存在哪些漏洞以及更新失败的地方，并积极减少两者的影响。它还可以帮助您了解组织面临的严重漏洞，从而使您能够在披露关键漏洞时快速做出反应。  
## 验证过程  
  
对于组织来说，管理漏洞并不总是那么简单，部分原因是有些人可能认为它会分散人们对构建新系统或解决紧迫用户需求等活动的注意力。但漏洞管理应被视为验证（并在必要时进行修复）组织的软件更新过程和安全配置控制运行情况的过程。  
  
这假设系统和软件更新是“一切照旧”控制，而不是例外或按需更新，我们认识到，对于许多组织来说，目前情况可能并非如此。我们知道，并非所有组织都会默认进行更新，因为担心更新可能会“破坏”系统，或者需要进行额外的测试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rTibWNx9ARWn0Dg8JicgSiaTx8IZEQhPKib1SrnbndPib5gKhSta6XGfJRNrWvC05rkFBxWvomlstbrrGJ19CbcHwHg/640?wx_fmt=png&from=appmsg "")  
  
帮助组织建立有效的漏洞管理流程的原则。  
## 实施本指南  
  
本指南旨在帮助组织在漏洞管理方面指导他们的工作，并提供目标。  
  
当您第一次开始实施漏洞管理流程时，很容易被您发现的问题的数量和性质所淹没，因此确定操作和活动的优先级非常重要。通常最好从小规模或集中的方式开始，然后扩大流程规模，例如仅关注关键系统中的漏洞。  
## 更广泛的组织相关性  
  
漏洞管理流程不应孤立存在。这是一项跨领域的工作，不仅涉及 IT 运营人员，还涉及安全和风险团队。时间、预算和风险都应添加到组织的风险登记册中，并且您可能需要让高级领导参与其中，特别是当不同的团队向不同的董事会成员报告时。  
  
NCSC 的董事会网络安全工具包提供资源，帮助董事会更有效地管理网络风险。  
## 漏洞管理原则  
  
本指南列出了五项原则，旨在帮助组织建立有效的漏洞管理流程：  
- ## 1. 制定默认更新策略  
  
尽快应用更新，最好是自动应用更新，符合我们的最佳实践时间表。  
  
- ## 2. 确定资产  
  
了解您的技术领域拥有哪些系统和软件、谁负责什么以及存在哪些漏洞。  
  
- ## 3. 通过分类和优先顺序进行评估  
  
如果更新到受影响软件的最新版本无法修复报告的漏洞或错误配置，或者尚未有更新来解决该问题，则您将需要一个流程来进行分类和确定优先级。  
  
- ## 4. 组织必须承担不更新的风险  
  
有时可能有正当理由不更新。  
不这样做的决定是高层风险决策，应在组织风险管理政策和实践的更广泛背景下考虑。  
  
- ## 5.验证并定期审查您的漏洞管理流程  
  
您的漏洞管理流程应该始终不断发展，以跟上组织资产、新威胁或新漏洞的变化。  
  
# 1. 制定默认更新策略  
  
尽快应用更新，最好是自动应用更新，符合我们的最佳实践时间表。  
## 这一原则背后的思考  
  
安装最新更新对于确保您的财产安全至关重要。您应该制定默认更新策略，始终尽快应用软件更新，最好是自动应用。这应该是更新管理流程的核心，作为系统所需的标准，但它可能不适用于某些情况，例如安全关键系统或操作技术。  
## 不同类型的更新  
  
不同的供应商发布不同类型的软件更新，这些更新可能会令人困惑，并且会带来各自的复杂性。问题包括：  
- 有些将安全更新与功能更新分开，而另一些则将它们结合起来。  
  
- 有时，如果您已经安装了以前的更新，则只能安装最新的更新。  
多版本升级比单一更新更有可能产生意想不到的副作用。  
  
- 供应商可能会发布针对某些漏洞的建议，例如当已知攻击者正在积极利用这些漏洞时，但也会“默默地”更新其他漏洞，而无需公开承认。  
错过更新可能意味着您也错过了这些静默更新，从而增加了组织的风险。  
  
出于这些原因，NCSC 建议您尽快安装所有更新。您可以通过给自己时间执行受控更新来保持领先，而不是等到被迫并且迫切需要更新到最新版本以缓解新漏洞时。  
  
您还应该确保更新来自可信来源，通常是供应商支持网站。您可以在安装前确认哈希值或校验和。  
## 推出  
## 测试  
  
供应商对这些更新进行自己的质量保证测试，一旦他们发布更新，您也应该在自己的系统上进行测试。这不必减慢部署速度，因为您可以逐步执行，例如在整个资产中分阶段/分阶段部署，或者对一部分用户使用金丝雀部署模型。  
  
分阶段推出还允许您针对安全更新对资产进行“实时测试”。在实际系统（而不是测试或预生产系统）中进行测试将发现现实世界的问题。在实时测试中，如果发现问题，可以暂停或回滚部署。  
## 需要考虑的事项  
  
为了使更新管理和部署更容易，您应该考虑以下事项：  
- 作为系统所有者，请设置您的通信首选项，以便您在最新更新可用时立即收到它们。  
您还应该确保您拥有所需的许可证。  
  
- 最好遵守平台的应用程序开发规则——不要尝试“重新发明轮子”。  
例如，专门打包的应用程序比来自平台应用程序商店的程序包或使用平台本机安装程序的程序包更有可能遇到问题。  
  
- 一些支持基础设施即服务 (IaaS) 的云服务包括帮助进行漏洞管理和实施更新的工具。  
这通常包括在受支持的操作系统 (OS) 变体上构建部署的 IaaS，因此您应该使用具有带自动更新服务的云平台的受支持操作系统。  
  
- 采用基础设施即代码 (IaC)。  
最可靠的自动化方法是用更新的版本替换正在运行的映像或代码，而不是必须更新它。  
您的组织可以通过确保新开发的系统以允许轻松测试、更新和回滚的方式开发来减少遇到问题的机会。  
  
- 自动化是减轻负担的关键。  
例如，当扫描发现有任何丢失时，您可以自动部署更新。  
  
如果您使用可移动介质（例如 USB 记忆棒）将更新从 Internet 传输到另一个系统，则应在安装前检查可移动介质是否有病毒。  
## 最佳实践时间表  
  
为了帮助您规划部署流程，我们在下面列出了最佳实践的定义。  
这些时间表还可以帮助您的组织制定合同以实现最佳实践。  
我们的时间框架与供应商最佳实践建议和我们自己的  
Cyber Essentials 认证  
一致。  
它们适用于所有更新，无论漏洞的严重程度如何。  
  
您的目标应该是将时间范围缩短到尽可能小的窗口。  
当漏洞被修复后，攻击者通常会研究该漏洞并尝试为其编写漏洞利用程序。  
这可能会导致正在更新的网络防御者和想要接触尚未安装更新的网络攻击者之间的竞争。  
  
为了帮助满足时间要求，您可以利用一系列供应商工具和服务来实现自动更新并帮助管理部署。  
如果您确实遇到问题，这还可以让您轻松暂停或回滚更新。  
请注意，如果您使用应用程序或操作系统的默认配置，则可能不需要分阶段推出。  
  
对于业务关键型系统，您应该平衡以下时间范围与系统可用性。  
<table><thead style="border-width: 0px 0px 4px;border-top-style: initial;border-right-style: initial;border-bottom-style: solid;border-left-style: initial;border-top-color: initial;border-right-color: initial;border-bottom-color: rgb(5, 28, 72);border-left-color: initial;vertical-align: baseline;"><tr style="border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><th style="text-align: inherit;margin: auto;padding: 0px 8px 16px;border-right: 0px;border-bottom-width: 3px;border-bottom-color: rgb(5, 28, 72);border-left: 0px;font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;border-top: 0px !important;"><span style="vertical-align: inherit;">遗产类型</span></th><th style="text-align: inherit;margin: auto;padding: 0px 8px 16px;border-right: 0px;border-bottom-width: 3px;border-bottom-color: rgb(5, 28, 72);border-left: 0px;font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;border-top: 0px !important;"><span style="vertical-align: inherit;">推出</span></th><th style="text-align: inherit;margin: auto;padding: 0px 8px 16px;border-right: 0px;border-bottom-width: 3px;border-bottom-color: rgb(5, 28, 72);border-left: 0px;font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;border-top: 0px !important;"><span style="vertical-align: inherit;">更新完成内</span></th></tr></thead><tbody style="border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><tr style="border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><td style="margin: auto;padding: 16px 8px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(170, 170, 170);font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;"><span style="vertical-align: inherit;">面向互联网的服务和软件</span></td><td style="margin: auto;padding: 16px 8px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(170, 170, 170);font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;"><p style="margin: auto auto 1.25em;border-width: 0px;border-style: initial;border-color: initial;font-size: inherit;vertical-align: baseline;line-height: normal;color: rgb(0, 0, 0);font-stretch: normal;"><span style="vertical-align: inherit;"><span style="vertical-align: inherit;">首先安装在测试环境或备份。</span><span style="vertical-align: inherit;">测试和推出（如果适用，可以分阶段推出）。</span></span></p></td><td style="margin: auto;padding: 16px 8px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(170, 170, 170);font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;"><span style="vertical-align: inherit;">5天</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><td style="margin: auto;padding: 16px 8px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(170, 170, 170);font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;"><p style="margin: auto auto 1.25em;border-width: 0px;border-style: initial;border-color: initial;font-size: inherit;vertical-align: baseline;line-height: normal;color: rgb(0, 0, 0);font-stretch: normal;"><span style="vertical-align: inherit;">操作系统和应用程序</span></p></td><td style="margin: auto;padding: 16px 8px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(170, 170, 170);font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;"><p style="margin: auto auto 1.25em;border-width: 0px;border-style: initial;border-color: initial;font-size: inherit;vertical-align: baseline;line-height: normal;color: rgb(0, 0, 0);font-stretch: normal;"><span style="vertical-align: inherit;">一旦发布更新，这些更新就会自动应用。</span></p><p style="margin: auto auto 1.25em;border-width: 0px;border-style: initial;border-color: initial;font-size: inherit;vertical-align: baseline;line-height: normal;color: rgb(0, 0, 0);font-stretch: normal;"><span style="vertical-align: inherit;">分阶段推出，例如每天更新 10% 的资产。</span></p><p style="margin: auto auto 1.25em;border-width: 0px;border-style: initial;border-color: initial;font-size: inherit;vertical-align: baseline;line-height: normal;color: rgb(0, 0, 0);font-stretch: normal;"><span style="vertical-align: inherit;">如果遇到问题则暂停/回滚。</span></p></td><td style="margin: auto;padding: 16px 8px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(170, 170, 170);font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;"><span style="vertical-align: inherit;">7天</span></td></tr><tr style="border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><td style="margin: auto;padding: 16px 8px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(170, 170, 170);font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;"><span style="vertical-align: inherit;">内部/气隙服务和软件</span></td><td style="margin: auto;padding: 16px 8px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(170, 170, 170);font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;"><span style="vertical-align: inherit;"><span style="vertical-align: inherit;">首先安装在测试环境或备份。</span><span style="vertical-align: inherit;">测试和推出。</span></span></td><td style="margin: auto;padding: 16px 8px;border-top: 0px;border-right: 0px;border-left: 0px;border-bottom-color: rgb(170, 170, 170);font-size: 14px;vertical-align: baseline;line-height: normal;color: rgb(51, 51, 51);word-break: normal;"><span style="vertical-align: inherit;">14天</span></td></tr></tbody></table>## 当利用率很高时进行更新  
  
上述时间表适用于正常更新，但有时会发现漏洞，攻击者会在更新之前大规模扫描或攻击互联网以找到受害者。  
在这些情况下，上述时间线太长，必须加快更新过程。  
  
通常最好使用现有的内部流程来管理内部 IT 事件（例如中断）。  
这是因为必要的治理流程（例如待命员工轮班）应该已经到位。  
提出 IT 事件不应掉以轻心，安全团队应在适当的时候以及如何激活该流程与 IT 员工达成一致。  
  
如果发生这种情况，您还应该准备好在发现新漏洞后的几天内部署其他供应商更新。  
这不应该阻止您推出第一个更新。  
  
请注意，如果影响面向互联网的服务的漏洞在野外被积极利用，您应该在应用任何更新之前调查您的暴露情况并检查是否有受到损害的迹象，即使暴露时间很短。  
如果在暴露窗口期间成功利用漏洞，即使在应用更新后，仍然有可能受到损害。  
  
信息来源包括：  
- 供应商公告将包括有关漏洞和任何缓解措施的信息。  
它还可能包括妥协指标、脚本和其他支持。  
  
- CISA 的已知被利用的漏洞目录  
。  
  
# 2. 确定资产  
  
了解您的技术领域拥有哪些系统和软件、谁负责什么以及存在哪些漏洞。  
## 这一原则背后的思考  
  
了解您的技术领域拥有哪些系统和软件是有效漏洞管理的基础。了解谁  
负责您确定的每个系统或服务  
也同样重要。  
  
一旦确定了这一点，就安全和 IT 系统维护人员执行的任务达成一致非常重要。  
这应包括报告检测到的漏洞的节奏和性质、系统维护人员应分配用于纠正问题的时间和精力，以及就 IT 事件的适当优先级达成一致，例如关键漏洞是否在野外被利用。  
## 资产发现  
  
NCSC  
为组织提供了有关资产管理的单独指南  
，但您的基本目标是识别和监控您资产中的系统、服务、云基础设施、移动设备、硬件和软件。  
每个类别可能需要不同的方法，重要的是要通过不遗漏某个类别或合并具有截然不同要求和挑战的类别来最大程度地减少差距。  
  
资产发现以及随着时间的推移而变化的资产的编目和管理是一个持续的过程（有关定期审查的更多信息，请参阅原则 5）。  
自动化这些流程意味着您可以专注于结果。  
它还将有助于其他网络安全功能，例如  
事件响应  
。  
## 过时和延长支持的产品  
  
在资产发现过程中，您可能会发现已过时或处于扩展支持状态的产品。  
确保将它们分类并采取适当的操作非常重要。  
  
过时产品是指不再开发且未收到任何更新的产品。  
最好的补救措施是在产品寿命结束之前迁移到受支持的产品。  
如果无法做到这一点，您将需要管理与过时产品相关的风险。  
NCSC  
关于过时产品的指南  
可以在这方面为您提供帮助。  
  
对于扩展支持产品，您可以付费在主流支持结束后获得额外一段时间的软件支持。  
但是，他们可能无法收到所有已知漏洞的修复，并且可能必须手动安装更新。  
因此，NCSC 建议一旦产品不再受到主流支持，您就应迁移到受支持的版本  
。  
## 配置管理  
  
确保整个系统的配置安全一致对于安全和有效运行至关重要，因为攻击者可以利用任何弱点来访问您的网络。  
NCSC 提供  
设备安全指南，  
帮助组织安全地选择和配置设备，最有效的安全控制之一是  
应用程序允许列表  
。  
  
我们建议您自动进行配置审核，并覆盖您的整个资产。  
在可能的情况下，任何新系统都应使用基础设施即代码和配置即代码来部署，以减少错误配置的风险并使大规模修复变得容易。  
有效的配置管理流程以及资产发现和更新管理（请参阅  
原则 1  
）应该提供对所有资产上安装的当前软件和固件版本的态势感知。  
# 3. 通过分类和优先顺序进行评估  
  
如果更新到受影响软件的最新版本无法修复报告的漏洞或错误配置，或者尚未有更新来解决该问题，则您将需要一个流程来进行分类和确定优先级。  
## 这一原则背后的思考  
  
漏洞评估将突出显示需要注意的任何安全、配置或更新管理问题。  
为了管理您的攻击面，您应该至少每月对整个资产进行漏洞评估  
。  
如果您的组织从未运行过组织范围的漏洞扫描，第一份报告可能会包含数百甚至数千个漏洞。  
了解您的攻击面（外部  
暴露与内部  
暴露）也很重要。  
  
更成熟的组织应该考虑更定期的评估，特别是对于外部可访问的服务。  
如果您使用云环境中内置的等效工具，则应遵循提供商建议的节奏。  
  
尽管供应商通常有发布更新的节奏，但它们可以随时发布（称为带外更新）。  
如果发现严重漏洞，则可能会发生这种情况。  
如果这可能会影响您的组织，那么重要的是要有一个适当的流程，使您可以随时对关注的漏洞进行评估。  
  
区分旨在识别漏洞的漏洞评估系统和用于确定软件版本的软件资产管理非常重要。  
在某些情况下，一个工具可以执行这两种功能，但情况并非总是如此。  
有关更多信息，请参阅我们  
有关漏洞扫描工具和服务  
的指南。  
## 扫描  
  
定期扫描制度对于让您了解您的组织可能面临的风险至关重要。  
它不需要由外部合作伙伴运营，员工也不需要任何特殊培训。  
NCSC  
对如何选择、实施和使用自动化漏洞扫描工具提供了指导  
。  
  
漏洞和配置扫描还可能会突出显示无法通过软件更新解决的问题，或者自动更新机制无法正常工作的问题，这意味着需要手动修复。  
应使用原则 4  
中概述的流程对这些漏洞进行分类  
。  
漏洞扫描对于突出显示未  
安装更新的情况也特别有用。  
## 漏洞披露  
  
如果您开发软件或运行系统，您还应该考虑建立一个流程，允许安全研究人员向您报告他们发现的任何漏洞。  
NCSC   
漏洞披露工具包  
 旨在简化披露流程的设置。  
## 对无法或不会立即缓解的漏洞进行分类  
  
有时，安装受影响软件的最新版本可能无法修复报告的漏洞或错误配置，或者甚至可能没有更新来解决该问题。  
在某些情况下，不  
进行更新可能是合适的   
 ：例如，如果系统即将退役，并且漏洞难以发现且难以利用。  
通过合理的控制，例如确保退役继续进行，不更新是完全合理的。  
  
但更常见的是，由于员工时间等限制或对更新软件兼容性的担忧，组织感觉无法解决问题。  
充分了解这对您的组织的潜在影响非常重要。  
  
虽然漏洞评估软件或供应商咨询可能会为发现的问题提供严重性评级（例如   
通用漏洞评分系统或 CVSS  
），但您必须考虑组织的业务影响和风险。  
## 选择不更新  
  
有时，组织可能会评估自动更新的风险太高。  
在这种情况下，系统应添加到“例外列表”中，更新将通过您的组织所需的任何安全测试。  
由于额外的测试可能需要大量时间，因此应仅限于可用性至关重要且没有安全恢复到已知良好状态的机制的系统。  
## 分诊流程  
  
如果无论出于何种原因都没有可用的更新，您将需要一个流程来对修复进行分类和确定优先级。  
  
您应该整合所有问题并应用相同的分类和优先级流程，以便系统所有者具有充分的可见性来相应地管理问题。  
  
您的分类过程应首先将所有类似的发现结果或需要相同缓解措施的发现结果分组在一起：例如，所有 SSL 问题都成为一个问题。  
或者，您可以按类别对它们进行分组，例如外部暴露的漏洞。  
  
分组后，应将它们分为三类：要  
解决的  
问题、要  
确认的  
问题或  
要调查的问题  
。  
- “修复”  
适用于您将确保系统默认更新的问题，或者您将实施重新配置或缓解措施的问题。  
您应该优先考虑漏洞：  
  
• 面向互联网的服务或应用程序  
  
• 如果成功利用，将产生最大的负面影响（例如关键共享基础设施中存在的影响）  
  
在确定优先级和编写列表时，您应该记录问题得到解决的日期。  
这可能是供应商表示将发布修复的日期，也可能是对何时可以实施配置更改的估计。  
如果修复是临时供应商解决方法或缓解措施，则应有时间限制并积极跟踪，以便在完整的供应商修复可用并应用后可以将其删除。  
- “承认”  
无论出于何种原因您决定目前  
不解决的问题。  
不立即解决漏洞是有正当理由的，应记录这些原因以及计划的审查日期。  
如果它们带来的风险级别足够高，请将问题记录在风险登记册中。  
如果将来漏洞被利用，承认问题（而不是  
解决问题）的理由应该足以证明所做出的决定是合理的。  
您还应该考虑实施额外的监控，以便在已知漏洞被利用时发出警报。  
  
- “调查”  
分类无法将其归类为“修复”或“确认”的问题。  
调查只能用作临时状态  
。  
这可能是因为解决问题的成本未知，或者有多种可能的解决方案，需要做更多的工作来确定哪一种最有效。  
漏洞评估软件并非绝对可靠，并且可能会发生误报。  
如果怀疑存在此问题，您应该在将其作为问题删除之前进行调查。  
此类问题的时间表将取决于问题的严重性。  
  
# 4. 组织必须承担不更新的风险  
  
有时可能有正当理由不更新。  
不这样做的决定是高层风险决策，应在组织风险管理政策和实践的更广泛背景下考虑。  
## 这一原则背后的思考  
  
您可能会发现比您可用于解决这些问题的资源更多的问题。  
不  
解决问题的决定  
从根本上来说是高层业务风险决策，而不是 IT 问题，每个组织都有自己的风险偏好。  
这里需要考虑许多合理的因素，包括成本、资源、复杂性和其他运营风险。  
目标仍然应该是默认更新并最大程度地减少根据具体情况做出决策的需要。  
组织的风险管理结构和员工需要了解组织目前选择承受的风险。  
## 需要考虑的事项  
- 基于风险的优先级取决于您组织的  
风险评估  
，并参考  
CISA 已知被利用的漏洞目录  
或  
威胁情报源  
。  
您不应纯粹根据单一严重性评分（例如  
CVSS ）  
做出决策。  
  
- 对系统或服务的潜在影响 - 例如，您是否有有效的备份以及足够的系统知识来恢复它？  
  
- 系统、服务或您的组织的声誉可能受到损害。  
  
- 直接成本，例如更换过时的系统。  
  
- 短期修复的可用性和成本。  
  
- 开展工作所需的熟练资源的可用性和成本。  
  
- 事件响应和恢复的成本，包括在最坏情况下施加的任何罚款。  
  
做出决定后，记录其背后的原因，并确保在组织的整体风险管理框架中考虑任何剩余风险。  
这可能是一个风险登记册，您可以在其中对所有相同的风险进行分组，例如“高：未修补的外部暴露的漏洞允许初始危害”。  
重要的是，风险由企业而不是安全团队承担，并且高层领导可以看到风险。  
# 5.验证并定期审查漏洞管理流程  
  
您的漏洞管理流程应该始终不断发展，以跟上组织资产、新威胁或新漏洞的变化。  
## 这一原则背后的思考  
  
您的漏洞管理流程应该积极验证并不断发展。  
您应该建立一个反馈循环来帮助解决这个问题。  
改进可能包括缩短更新时间，或确保更频繁地完成和审核资产发现和管理扫描。   
## 确认  
  
您应该包括一个验证过程，以确保在使用重新配置或缓解措施修复漏洞的情况下，您已验证该漏洞不再存在。  
如果缓解措施只是临时解决方法，您将需要继续监控它。  
这可能是因为出现了另一个危及解决方法的漏洞，缺陷意味着解决方法不再有效，或者供应商发布了应安装的更新来代替临时解决方法。  
所有这些情况都应取代任何临时措施。  
  
使用第三方渗透测试是验证漏洞管理流程是否正常运行的好方法。  
NCSC  
对渗透测试有指导  
。  
## 定期回顾  
  
您应该定期检查漏洞管理流程，以跟上组织资产的任何变化，例如，使更多服务面向互联网的架构变化。  
新威胁或新发现的漏洞是继续审查的额外原因。  
订阅来自您使用的供应商、供应商和服务的安全警报将提醒您注意开发情况，然后您可以将其反映在漏洞管理流程中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rTibWNx9ARWn0Dg8JicgSiaTx8IZEQhPKib14icHCAmibibRvG5vnnNWrtSibBwBKBycQSWKBsZwadkibfvCicq8mt3II7jA/640?wx_fmt=png&from=appmsg "")  
# 了解漏洞  
  
什么是漏洞，它们是如何被利用的？  
  
漏洞是 IT 系统中的一个弱点，攻击者可以利用它来发起成功的攻击。  
它们可能是由于缺陷、功能或用户错误而发生的，攻击者会寻求利用其中的任何一个，通常结合一个或多个来实现他们的最终目标。  
## 缺陷  
  
缺陷是非预期的功能。  
这可能是由于设计不当或实施过程中犯下的错误造成的。  
缺陷可能在很长一段时间内未被发现。  
我们今天看到的大多数常见攻击都是利用这些类型的漏洞。  
2014年至2015年间，美国国家漏洞数据库（NVD）  
披露了近8000个独特且经过验证的软件漏洞  
。  
  
各种攻击者都在积极寻找和利用漏洞。  
因此，软件缺陷市场不断增长，“零日”漏洞（最近发现的尚未公开的漏洞）价值数十万英镑  
## 零日漏洞  
  
能力更强、资源更丰富的攻击者经常在定制攻击中使用零日漏洞。  
一旦零日漏洞变得众所周知，可重复使用的攻击就会被开发出来，并很快成为一种商品功能。  
这会给任何未应用相关补丁或未更新防病毒软件的计算机或系统带来风险。  
攻击者发现并攻击软件缺陷或破坏功能的能力取决于软件的性质及其技术能力。  
某些目标平台的访问相对简单，例如 Web 应用程序在设计上可能能够与互联网交互，并可能为攻击者提供机会。  
## 特征  
  
功能是指可能被攻击者滥用来破坏系统的预期功能。  
功能可以改善用户体验、帮助诊断问题或改进管理，但它们也可能被攻击者利用。  
  
当 Microsoft 在 20 世纪 90 年代末将宏引入其 Office 套件时，宏很快就成为首选漏洞，1999 年的 Melissa 蠕虫病毒就是一个典型的例子。  
宏至今仍被利用；  
2014 年底传播的 Dridex 银行木马依靠垃圾邮件传递包含恶意宏代码的 Microsoft Word 文档，然后将 Dridex 下载到受影响的系统上。  
  
JavaScript 广泛用于动态 Web 内容，并继续被攻击者使用。  
这包括将用户的浏览器转移到恶意网站并静默下载恶意软件，以及隐藏恶意代码以通过基本的网络过滤。  
## 用户错误  
  
经过精心设计和实施的计算机或系统可以最大限度地减少暴露在互联网上的漏洞。  
不幸的是，这样的努力很容易被撤销（例如，由缺乏经验的系统管理员启用易受攻击的功能、无法修复已知缺陷或保持默认密码不变）。  
  
更一般而言，用户可能是漏洞的重要来源。  
他们会犯错误，例如选择常见或容易猜到的密码，或者无人看管笔记本电脑或手机。  
即使是最具网络意识的用户也可能被欺骗而泄露密码、安装恶意软件或泄露可能对攻击者有用的官方信息（例如谁在组织中担任特定角色及其日程安排）。  
这些详细信息将允许攻击者适当地瞄准攻击目标并确定攻击时间。  
  
**—END—**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWhJou9CCpqmibD6ldgHL2ONAnycCV5yOcv7NiccibzQb5oMWLVmYhwK6jQaSapdQNKVoTAePYIKqmmicA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**精彩回顾：祺印说信安2024之前**  
  
[90个网络和数据安全相关法律法规打包下载](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652099357&idx=1&sn=5c38f6917d6b84e84632bb47344d3714&chksm=8bbcf924bccb7032f6ff66449cc927e65c853c9fc88b03c8569061bcd8048ef8fcefb48eb778&scene=21#wechat_redirect)  
  
  
[2023年收集标准合集下载](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104571&idx=1&sn=b2b0a1465e8d4856f593fa7a3b7fcd6c&chksm=8bbccd42bccb44540a72239af3de30db90adafde6d5c4217aa1b15600ba47feb550f5fa659bd&scene=21#wechat_redirect)  
  
  
[收集信通院白皮书系列合集（618个）下载](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104887&idx=1&sn=dde6bdba86b2b89bb59011ce58baf7cc&chksm=8bbcc28ebccb4b98219438b9dbf546bbfc1dce48f461858213104eb2790c1f92b54bc1400073&scene=21#wechat_redirect)  
  
  
**>>>网络安全等级保护<<<**  
  
[网络安全等级保护：等级保护工作、分级保护工作、密码管理工作三者之间的关系](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652098579&idx=1&sn=56da5aedb263c64196a74c5f148af682&chksm=8bbcfa2abccb733ca8dd898d7c0b06d98244ca76bd7be343482369fa80546554cced706fa74c&scene=21#wechat_redirect)  
  
  
[等级保护网络架构安全要求与网络分段的7个安全优点](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103736&idx=1&sn=9862de51a047cfde70c4575815ecb5c5&chksm=8bbcce01bccb4717a7bb7941cfd80fb25e9d0da8139c184e4ad245bf53fc91b1d6944bc85916&scene=21#wechat_redirect)  
  
  
[网络安全等级保护相关知识汇总](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652102246&idx=1&sn=6da86a0ad9a923edca47618aedac0ac9&chksm=8bbcf45fbccb7d49635a50913000dde2fc38b1beadf4172d7877b8093c721f727c1819cf1e0f&scene=21#wechat_redirect)  
  
  
**>>>数据安全系列<<<**  
  
[数据安全管理从哪里开始](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103384&idx=1&sn=391073e6109ff105f02be9029e01c697&chksm=8bbcc8e1bccb41f7fe478a3d22757d61f10dcf42548c1c02c0579b8f161277e527ba98ccb542&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据安全策略规划](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104021&idx=1&sn=7f80bb27ce6ad7c9debe83c172ff9f73&chksm=8bbccf6cbccb467a0971b9de4a8b14851c2666ad6934a88b8324a1ffc4b5cf5109cbc3976697&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据库安全重要性](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104183&idx=2&sn=f2a98256b0497ce3a99c0ad30223bf40&chksm=8bbccfcebccb46d8aac9f8a5c8d1f46061ca61ad69b3a61d52d3dc614e1e18ae65d982a5574b&scene=21#wechat_redirect)  
  
  
******>>>错与罚<<<**  
  
[北京多家公司因不履行网络安全保护义务被处罚！“两高一弱”仍然是安全隐患重点](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104010&idx=1&sn=0ddfdc41a52d235c99269b784b7858fa&chksm=8bbccf73bccb4665d0c29f8067b90e0e9b48894d2d4bbb9da98e64218efa47e36c32034a4775&scene=21#wechat_redirect)  
  
****  
  
[严厉打击网络谣言！商丘警方公布4起典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104388&idx=1&sn=9da4f7c6e055ff4e5bae9c0b10420538&chksm=8bbcccfdbccb45eb58a4322c3845b7ea5c743fe746a09e103f88aaaac84a2e997ab3b4658fa2&scene=21#wechat_redirect)  
  
  
[侮辱南阳火灾遇难学生的“谯城芳芳姐”获十日行政拘留](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104388&idx=2&sn=4824c66acd50a0701a117d12408ddf80&chksm=8bbcccfdbccb45ebfe3a03f67e98ddc5239ed0490efa326da41dc6abcdef432c12a6124eef12&scene=21#wechat_redirect)  
  
  
[宁夏网警公布5起打击谣言典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104388&idx=3&sn=3ab286ac8ead9305cbc8db6fcd1d25a6&chksm=8bbcccfdbccb45ebe9a7431baddbcf8aaf4f3e77545b0bcac0da033e84aed8fb7c9b76efb691&scene=21#wechat_redirect)  
  
  
[吉林警方公布3起、湖北公安公布5起打击谣言典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104256&idx=3&sn=1cec040494e2fe846ae1f4d19e9de390&chksm=8bbccc79bccb456f95523f31460e34fd5627344f26adb4fed2358b2d5a0178c5ef9fbb4d1439&scene=21#wechat_redirect)  
  
  
[安徽警方依法打击整治网络谣言10起典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104242&idx=3&sn=90a9f1e57b9e0ad43206eea3da80842c&chksm=8bbccc0bbccb451da48561fc6b3e6bee505be0f5a3e67ec5ac01bfa0dae2fd0d9a8bc23515a2&scene=21#wechat_redirect)  
  
  
[2023年度国家网络与信息安全信息通报工作总结会议在京召开](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104222&idx=2&sn=949bca98b6427c7d443ded04c6779a4d&chksm=8bbccc27bccb45313a34056bc7480bc14c0dc502250491a8a566f6b651f604b3f5b1b5753108&scene=21#wechat_redirect)  
  
  
[焦点访谈丨拒绝“按键”伤人 避免网络戾气变成伤人利器](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=6&sn=554d342874f552e8107d81ac664ae2e5&chksm=8bbccc2fbccb45392b7d1bb952aae7ac6a2fe4d1fdfa05512660a35645318afe0fc36f4414a4&scene=21#wechat_redirect)  
  
  
[全国公安厅局长会议召开 忠实履行神圣职责 为扎实稳健推进中国式现代化贡献公安力量](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=2&sn=125e830221fe7b1f3522bbf0205814fd&chksm=8bbccc2fbccb45398c2cc7393a957d5609feff89aae0f14b2e1c895a52642fe3940c9f145a89&scene=21#wechat_redirect)  
  
  
[公安部：纵深推进全面从严管党治警 着力锻造忠诚干净担当的新时代公安铁军](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=3&sn=878a4f16e8c21e2bf7903cba054e135f&chksm=8bbccc2fbccb4539551b2f6c98a75f3b6dfddc9cc7322a23123d6a71450efc0a8bde58d2c5eb&scene=21#wechat_redirect)  
  
  
[山西公布10、辽宁网警公布6起打击谣言典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=4&sn=4a425e447b3f74e37a3e029ea26fb2c7&chksm=8bbccc2fbccb4539286ea4900236dd52dee37cbc74347ab5e9147426a2e73c5df808f428ad8c&scene=21#wechat_redirect)  
  
  
[重庆璧山出现比缅甸还恐怖的新型背债人？警方：系某房产中介为博眼球造谣](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=5&sn=d743fe9c40fb4217584fb2ba5561c0df&chksm=8bbccc2fbccb4539c25341414c8ad6b4c6eb3aefc6b0e3b7a69c2f2b647ba46567af3d53ed46&scene=21#wechat_redirect)  
  
  
[上海、四川、浙江、福建警方宣传和打击整治网络谣言](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104159&idx=3&sn=cf504c3cfe1a938ce188f1f1d2e84921&chksm=8bbccfe6bccb46f01e547155be9b9b2af86c54c95659c9be99e1e247c4e60cbbc354946d27b2&scene=21#wechat_redirect)  
  
  
[四川德阳网警开展打击整治网络谣言宣传活动](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104077&idx=3&sn=66b3ec60984cdf4ea12f5a65cd7dfc9d&chksm=8bbccfb4bccb46a24b07a39022d717e962a18b389c135392dba1813f91dccee84bc8d12610a9&scene=21#wechat_redirect)  
  
  
[广安警方公布4起打击整治网络谣言典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104077&idx=4&sn=ba2c2112d68839753ef1a4880f3db435&chksm=8bbccfb4bccb46a22f39036676fe59cbdb5c1013ac120d6ce40a71130859ffc031a8b5084f07&scene=21#wechat_redirect)  
  
  
[四川查处两起利用AI编造、传播网络谣言案件](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104077&idx=5&sn=a5b11dc662e274df84fc7ccfd920877e&chksm=8bbccfb4bccb46a2e0daa6ff57acdf6ef282285bc2fdaba7cf2adcfa49d22765dfae1cdfe59f&scene=21#wechat_redirect)  
  
  
[西安网警依法处置一起网络暴力案件](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104021&idx=3&sn=0115bec6c696677cbfbfd227563417d4&chksm=8bbccf6cbccb467abebd9562fdbe58ff13f73130b95e6b4049c19ece0113d7b08e50c5359820&scene=21#wechat_redirect)  
  
  
[中信银行被罚400万，涉信息安全风险隐患未得到整改、虚假演练等](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103991&idx=1&sn=0cab9d0e32c9f69cab628b843bf73d4e&chksm=8bbccf0ebccb46187f7efe2016109ced6bdaef4ff8f6fd9d90790e36e3e623fe4483398992e0&scene=21#wechat_redirect)  
  
  
[中行被罚430万，涉迟报重要信息系统重大突发事件等](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103970&idx=2&sn=76254b9a3981e3fa57e4957aaaeb16c6&chksm=8bbccf1bbccb460d7d23b6b7b165005d22a33c21443632cbcca4e162d6aeaa06d9025783f638&scene=21#wechat_redirect)  
  
  
[新疆警方公布5起打击整治网络谣言典型案件](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103970&idx=4&sn=76410ed268999f04052b88352fa2be7e&chksm=8bbccf1bbccb460de37e1ef991c384e7e793b4f26fc97e419bcf13a0fae86b1ea874e57be351&scene=21#wechat_redirect)  
  
  
[山西忻州一网民因编造地震谣言被依法查处](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103970&idx=3&sn=de03afd0974ff1740044c29da6016604&chksm=8bbccf1bbccb460d5b5b70f919342b50efb5bb9ba9700f7fe606cfc6c74c827dcc2402e17e9d&scene=21#wechat_redirect)  
  
  
[公安部召开新闻发布会通报打击黑客类违法犯罪举措成效并答记者问](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103951&idx=2&sn=d4b7d5aebc16a942fb695bca3d414f4e&chksm=8bbccf36bccb46204f3274379ffd3c8903c4acb2469447c5b6515f7172e6b1a187e790c0ed42&scene=21#wechat_redirect)  
  
  
[有坏人！快藏好您的个人信息](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103951&idx=3&sn=a79b0b73813585d91ac550bd47b4455f&chksm=8bbccf36bccb462041e356e29f05d20c12736039871290414a0369a8ade194f635e8eeafa3ca&scene=21#wechat_redirect)  
  
  
[在西藏架设“GOIP”设备给骗子提供帮助，10人落网！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103951&idx=4&sn=5a29a6513ef65004fa9a52cc48a649ac&chksm=8bbccf36bccb4620e2c4151522f80dce5c8305587e9da66eebdfb26938a174c9d53b7a4469ed&scene=21#wechat_redirect)  
  
  
[网上买卖传播淫秽物品，触犯法律！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103940&idx=4&sn=b52f4c08d55e271ef299a174ab357f49&chksm=8bbccf3dbccb462b21ed00751ed278683c0927e2c2974adce3d24fff7a8771519f5480417e03&scene=21#wechat_redirect)  
  
  
[“温州帮”竟然是缅北电诈后台？警方通报来了](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103940&idx=5&sn=22173da928f67880a4a37a586dc7683c&chksm=8bbccf3dbccb462b5717c1fe4350d89b671183cba8d5278c294e063f1856fec41a0b9ace54f3&scene=21#wechat_redirect)  
  
  
[借甘肃积石山地震造谣博流量，行拘！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=3&sn=11ff4bcc6cc789554db01ea422185861&chksm=8bbccecdbccb47dbb07650da1243c57eb754e90ca8cff97384af1a691ef6a10f198634b93654&scene=21#wechat_redirect)  
  
  
[陕西警方公布6起打谣典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=4&sn=9ade7706756da02f2445d7bacc97d5ca&chksm=8bbccecdbccb47dba6b27b9b7d5f2f650dac3419e2fa55bdd47be8d81041f39a1af416fd5815&scene=21#wechat_redirect)  
  
  
[“再来一次12级地震”，行拘！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=5&sn=1bc2675b734a42942654184e8763b10e&chksm=8bbccecdbccb47db54e8cc53eb43b9401a318f5c11060aa0c807eb53ce27590e668ee94e32ab&scene=21#wechat_redirect)  
  
  
[江西警方公布7起“打谣”典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=6&sn=20e55dcdc18a802bf2079e3706050546&chksm=8bbccecdbccb47dbeea304bcbf81f23fb6c8ac7eb970893321f0b825277e5e1998e099cd9d47&scene=21#wechat_redirect)  
  
  
[江苏警方公布8起打谣典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=7&sn=b4692b982f6ad99a087ccb5f1d5f3a04&chksm=8bbccecdbccb47dbb96efae0b284dd655ef7e526ce811ad0ff6c2a92e04e0e1eac94110f4aa3&scene=21#wechat_redirect)  
  
  
[越想越生气，酒后干出糊涂事……](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=8&sn=5e96bbf3eb7076304c0193e1b21bdb81&chksm=8bbccecdbccb47dbd4ec4e1a6539eb19791b6e2120e4dbcf7cf91f49b94e601eec1897517029&scene=21#wechat_redirect)  
  
  
[邯郸刘某某因编造网络谣言被依法查处！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103925&idx=3&sn=a602191fd3828335576572dd1455d167&chksm=8bbcceccbccb47da5fac006e6d897247911225b784ec1de5b7c34a6ca7ba31944c243d9137eb&scene=21#wechat_redirect)  
  
  
**>>>其他<<<**  
  
[2023年10佳免费网络威胁情报来源和工具](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103402&idx=1&sn=80a1ee98453d96a6f2304272d2a6b33e&chksm=8bbcc8d3bccb41c5fe204b9933fbded47cd14612e3101111b2f806d8a136a61ff27577dfd765&scene=21#wechat_redirect)  
  
  
[2023年网络安全资金下降40%](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104036&idx=3&sn=797c6ac97c1c280791cbcf44737eae0c&chksm=8bbccf5dbccb464bc612673aa47f43a0affceaaa6827381f54333baf7da6994882bcff4cdbd9&scene=21#wechat_redirect)  
  
  
[为什么攻击模拟是避免 KO 的关键](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104101&idx=1&sn=4f52a7b75387d67862021b8f0d647d26&chksm=8bbccf9cbccb468ad8e85019c4978ff5f374845082160f75b52d9fd226b635e3f4815fb1edf9&scene=21#wechat_redirect)  
  
  
[持续安全监控对于稳健的网络安全策略的重要性](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103729&idx=3&sn=688da0c1e70c3975b24d7036e6f90c3d&chksm=8bbcce08bccb471e89426f5a0089aa335689403215ab6b4d0cea9fa159c2d2c7bfac94fd59f2&scene=21#wechat_redirect)  
  
  
[网络安全策略：远程访问策略](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104095&idx=2&sn=e8b2c6e7b9ec9c7a5e2da7f0df549ce8&chksm=8bbccfa6bccb46b0f847137b32cc0426dd05cf8a4b6d8b1ceeaee8e57482c70873a42041f771&scene=21#wechat_redirect)  
  
  
[网络安全策略：账户管理策略](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104021&idx=2&sn=c796ce34bf877501045259cda0097256&chksm=8bbccf6cbccb467ac55aa14b1a35004cb8f40dbab7a8760cb5ad2f06d15b3a15c85e38011087&scene=21#wechat_redirect)  
  
  
[保护企业的19项网络安全最佳实践](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104183&idx=1&sn=8f8693bdb34a0bba9975cade5b43b13d&chksm=8bbccfcebccb46d8e12d90e65018f0ee875ae2915ca5fc2e23eb86747361ddffcfec27561933&scene=21#wechat_redirect)  
  
  
**网络安全**[团队友情如何增强安全性](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104160&idx=1&sn=f23b88c17ca45309cb2d363490f72b84&chksm=8bbccfd9bccb46cf3d873a6d81b7873d31ba6357bfd87246b6790f1c0c54ced1b12526c65c13&scene=21#wechat_redirect)  
  
  
[实现混合网络时代的“无摩擦防御”](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104222&idx=1&sn=f15fd89240d1c5cb8bb83ccefaf9349a&chksm=8bbccc27bccb453100a3c15379d8e0f666c061c93ff25913e91de947a9d119f47b8d53045f25&scene=21#wechat_redirect)  
  
  
[物联网不是一份持续接受的礼物](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104222&idx=3&sn=ba74d7b9bb872a4da2572cb5ebbdad0f&chksm=8bbccc27bccb453114fc7ce6e43699a17a777a9f398981098df51574501c636efed381125342&scene=21#wechat_redirect)  
  
  
[确保完整的 IT 资产可见性及安全](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104844&idx=1&sn=bd54fd2cf9eb3eae1f084b751d4760bc&chksm=8bbcc2b5bccb4ba34125c429f2df73860919bc90cbabfe00a166c9dd90f1b82d19b3dd801f9a&scene=21#wechat_redirect)  
  
   
  
