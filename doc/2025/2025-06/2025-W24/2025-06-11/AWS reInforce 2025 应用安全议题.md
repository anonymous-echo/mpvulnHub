#  AWS re:Inforce 2025 应用安全议题  
原创 tonghuaroot  RedTeam   2025-06-10 13:50  
  
AWS re:Inforce 2025 将于6月16-18日在费城举办，主要聚焦云安全、合规性、身份管理和隐私保护。从技术议程来看，今年的应用安全(AppSec) track 内容相当丰富，涵盖了从组织层面的安全策略到具体的技术实现。  
## 会议结构概览  
  
本次大会包含多种形式的技术分享：  
- Breakout sessions  
  
- Chalk talks  
  
- Lightning talks  
  
- Code talks  
  
- Workshops  
  
- Builders sessions  
  
## AppSec 技术主题  
  
今年的应用安全 track 围绕四个核心技术领域展开：  
### 1. 组织层面的安全工程  
- **安全责任分配**  
：如何在开发团队中有效分配安全职责  
  
- **DevSecOps 实践**  
：开发、安全、运维团队的协作模式  
  
- **安全专业知识扩展**  
：将安全能力嵌入到各个工作负载团队  
  
- **快速交付与安全平衡**  
：在保证安全的前提下不降低开发速度  
  
### 2. Secure by Design  
- **架构阶段的安全考虑**  
：在软件设计早期就嵌入安全原则  
  
- **漏洞早期缓解**  
：通过设计减少后期的安全修复成本  
  
- **安全作为业务需求**  
：将安全视为功能需求而非可选项  
  
### 3. Pipeline Security  
- **SLSA (Supply chain Levels for Software Artifacts**  
)：软件供应链安全框架  
  
- SCITT (Supply Chain Integrity, Transparency, and Trust)：供应链完整性标准  
  
- **代码签名**  
：确保代码来源可信  
  
- **构建环境安全**  
：保护 CI/CD 基础设施  
  
### 4. Security in Pipeline  
- **SAST/DAST**  
：静态和动态应用安全测试  
  
- **SCA**  
：软件组成分析，识别开源组件漏洞  
  
- **自动推理**  
：使用形式化方法验证代码正确性  
  
- **AI 安全测试**  
：针对 Gen AI 应用的测试方法  
  
## 核心技术议题分析  
### Breakout Sessions  
  
**APS204 - Scaling security with Sportsbet's Security Guardians program**  
扩展安全：Sportsbet的安全守护者计划  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=aps204  
  
- 技术点：Security Champions 模式的实际实施  
  
- 适合人群：安全团队负责人、DevSecOps 工程师  
  
- 可学到：如何在开发团队中建立安全文化，安全责任的有效分配  
  
**APS301 - Improve code quality with Amazon Q Developer**  
使用 Amazon Q Developer 改善代码质量  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS301  
  
- 技术点：AI 驱动的代码质量检查、SCA、SAST 集成  
  
- 适合人群：开发人员、DevOps 工程师  
  
- 可学到：将 AI 工具集成到开发流程中进行安全检查  
  
**APS401 - Build verifiable apps using automated reasoning and generative AI**  
使用自动推理和生成式AI构建可验证应用  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS401  
  
- 技术点：形式化验证、LLM 与符号推理结合  
  
- 适合人群：高级开发人员、研究人员  
  
- 可学到：如何结合概率性和符号性方法构建可信 AI 系统  
  
### Code Talks  
  
**APS341 - Move fast and stay secure: Lessons learned from the AWS prototyping team**  
快速且安全：AWS原型团队的经验教训  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS341  
  
- 技术点：威胁建模、AWS CDK 安全实践、基础设施安全加固  
  
- 适合人群：云架构师、全栈开发人员  
  
- 可学到：原型开发中的安全最佳实践、CDK 安全构造  
  
**APS441 - Supercharge IaC security with AI: From commit to auto-remediation**  
AI增强的IaC安全：从提交到自动修复  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS441  
  
- 技术点：Git 提交签名、静态分析、AI 自动修复  
  
- 适合人群：DevOps 工程师、基础设施工程师  
  
- 可学到：完整的 IaC 安全反馈循环构建  
  
**APS442 - Create memory safe applications using open source verification tools**  
使用开源验证工具创建内存安全应用  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS442  
  
- 技术点：Rust 标准库验证、C 代码模型检查  
  
- 适合人群：系统级开发人员、安全研究人员  
  
- 可学到：大规模内存安全验证工具的实际应用  
  
### Workshops  
  
**APS351 - Securing generative AI agents using AWS Well-Architected Framework**  
使用AWS Well-Architected框架保护生成式AI代理  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS351  
  
- 技术栈：Amazon Bedrock、CloudWatch、IAM  
  
- 实践内容：端点安全、提示工程防护、监控系统  
  
- 产出：生产就绪的安全 AI 代理  
  
**APS353 - Red-teaming your LLM security at scale**  
大规模LLM安全红队演练  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS353  
  
- 技术栈：AI 安全代理、自动化攻击链  
  
- 实践内容：提示注入、边界测试、漏洞发现  
  
- 产出：自动化安全测试技能  
  
**APS354 - Secure your application using AWS services and open source tooling**  
使用AWS服务和开源工具保护应用  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS354  
  
- 技术栈：Automated Security Helper (ASH)、Amazon Q Developer  
  
- 实践内容：本地安全测试、CI/CD 集成、生成式 AI 应用安全  
  
- 产出：完整的安全测试流程  
  
**APS271 - Threat modeling for builders**  
面向构建者的威胁建模  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS271  
  
- 技术框架：STRIDE 方法论、威胁语法规则  
  
- 实践内容：数据流图、威胁识别、风险响应策略  
  
- 产出：实用的威胁建模技能  
  
**APS371 - Securing your generative AI applications on AWS**  
在AWS上保护生成式AI应用  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS371  
  
- 技术栈：多种 AWS 安全服务  
  
- 实践内容：部署漏洞应用、分层安全控制、检测和响应  
  
- 产出：生成式 AI 应用安全架构  
  
**APS471 - Boost developer productivity with Amazon Q Developer and Amazon Bedrock**  
使用Amazon Q Developer和Bedrock提升开发者生产力  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS471&search.sessiontracks=option_1614614703921  
  
- 技术栈：Amazon Q Developer、Amazon Bedrock  
  
- 实践内容：AI 代码审查、自动化测试、智能文档生成  
  
- 产出：AI 增强的开发工作流  
  
### Lightning Talks  
  
**APS221 - Building secure development into Amazon stores**  
Amazon.com的安全开发实践  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS221  
  
- 技术点：大规模电商平台的安全开发生命周期  
  
- 适合人群：大型系统架构师、安全工程师  
  
- 可学到：成熟企业的 SDL 实施策略  
  
**APS222 - Transform threat modeling using generative AI**  
使用生成式AI变革威胁建模  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS222  
  
- 技术点：AI 自动化威胁建模、Amazon Bedrock 集成  
  
- 适合人群：安全架构师、威胁建模专家  
  
- 可学到：CRED 公司的 AI 威胁建模架构实践  
  
**SEC221 - Raising the tide: How AWS is shaping the future of secure AI for all**  
AWS如何塑造安全AI的未来  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=SEC221  
  
- 技术点：CoSAI 标准、行业安全协作  
  
- 适合人群：AI 安全研究人员、政策制定者  
  
- 可学到：AI 安全的行业标准和最佳实践  
  
### Chalk Talks  
  
**APS431 - DevSecOps in action with Visual Studio Code & AWS IAM Access Analyzer**  
DevSecOps实战：VS Code与AWS IAM Access Analyzer  
- 议题链接：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog?search=APS431  
  
- 技术栈：Visual Studio Code、IAM Access Analyzer  
  
- 技术点：IDE 集成的实时安全检查、IAM 策略验证  
  
- 适合人群：DevOps 工程师、IAM 管理员  
  
- 可学到：开发阶段的权限管理和自动化策略检查  
  
## AI 安全的技术重点  
  
今年会议特别关注生成式 AI 的安全问题：  
  
**技术挑战**  
：  
- **提示注入攻击**  
：如何防范恶意输入绕过 AI 安全控制  
  
- **模型边界测试**  
：识别 LLM 的能力边界和潜在风险  
  
- **输出可控性**  
：确保 AI 生成内容的安全性和合规性  
  
- **Agent 安全**  
：多 AI Agent 系统的协调和权限控制  
  
**技术方案**  
：  
- **Bedrock Guardrails**  
：AWS 的 AI 安全防护框架  
  
- **自动推理结合**  
：概率性和符号性方法的混合使用  
  
- **实时监控**  
：AI 应用的运行时安全监控  
  
- **分层防御**  
：端点安全、提示工程、监控系统的组合  
  
## 从技术人员角度的收益分析  
  
**代码层面收益**  
：  
- 学习 ASH 工具集成 SAST/DAST/SCA 到 CI/CD  
  
- 掌握 Amazon Q Developer 的安全代码审查能力  
  
- 了解自动推理工具在 Rust/C 代码验证中的应用  
  
**架构层面收益**  
：  
- Well-Architected 框架在 AI 应用中的安全设计模式  
  
- 基础设施即代码的安全最佳实践  
  
- 威胁建模方法论的实际应用  
  
**运维层面收益**  
：  
- 供应链安全的 SLSA/SCITT 标准实施  
  
- 代码签名和构建环境的安全加固  
  
- AI 增强的安全运维自动化  
  
**组织层面收益**  
：  
- Security Champions 计划的建立和推广  
  
- DevSecOps 文化在团队中的落地实践  
  
- 安全技能在开发团队中的扩散策略  
  
## 值得关注的开源项目  
  
会议中提到的开源工具：  
- Automated Security Helper (ASH)：AWS 开源的应用安全工具集成平台  
  
- 项目地址：https://github.com/awslabs/automated-security-helper  
  
- **Rust 标准库验证工具**  
：AWS 正在开发的 Rust 内存安全验证工具  
  
- **C 模型检查器**  
：用于大规模 C 代码安全验证  
  
这些工具代表了当前应用安全工具化的最新趋势，值得技术团队关注和试用。  
## 相关资源  
- 会议完整目录：https://registration.awsevents.com/flow/awsevents/reinforce2025/sessioncatalog/page/sessionCatalog  
  
- AWS 安全博客：https://aws.amazon.com/blogs/security/  
  
- AWS Well-Architected：https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html  
  
  
  
