#  清源SCA社区版每日漏洞情报、新增CVE及投毒情报推送  
清源社区  安势信息   2025-06-13 04:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ibSWU7ian1thvJpbKXyJVyQ2vRt08HVKaXPaHV41WepeiaRMSGeQjolNavSyuzCuMhxnZiaz3AcjLicY7zt63GDPvicQ/640?wx_fmt=gif "")  
  
**扫码进群：****获取每日最新漏洞和投毒情报推送**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ibSWU7ian1thv0t8s4gJ7hF4WicJfORlicGxafKVXkGuZgvduauND4SbxoRFWlib9XbJic1XZ8G549Xn5VOcynlkMp6w/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MVPvEL7Qg0HJalXIBXGXSBFLMk2TZAqh23iaHwLpprUov8bNQ95dWDVMTq4qGicM3G6cmsZcCF6RsKyn9p8eQA3Q/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
清源SCA开源版交流群  
  
  
  
  
  
  
  
  
  
  
2025年6月12日新增漏洞情报  
  
  
CVE暂未收录高危以上漏洞：3  
  
CVE热点漏洞精选：3  
  
投毒情报：2  
  
  
  
  
  
漏洞感知情报（CVE暂未收录）  
  
  
1.   
MinIO未授权访问漏洞致多部分上传元数据泄露  
  
  
  
漏洞描述  
  
该漏洞源于S3 API接口list-multipart-uploads缺失资源级权限校验机制，攻击者可构造恶意GET请求遍历检索全实例范围内所有活跃分片上传会话记录。由于无需身份凭证即可直接访问受保护资源，成功利用后能够非法获取包含上传者标识、文件路径等关键元数据信息，进一步形成基于业务上下文的关系推断攻击面。CVSS评分依据显示攻击代价极低且作用域维持不变，仅需单次网络请求即可同步造成机密性与完整性双重破坏。  
  
  
组件描述  
  
MinIO是兼容Amazon S3协议的分布式对象存储系统，专为云原生环境优化设计其高可用架构提供大规模非结构化数据管理能力。组件通过实现标准RESTful API完成数据生命周期治理，采用分布式存储引擎保障跨节点数据一致性与弹性扩展特性。  
  
  
漏洞详情  
  
漏洞威胁性评级: 9.1 (超危)   
  
漏洞类型: Broken Access Control (CWE-285)   
  
受影响组件仓库地址: https://github.com/minio/minio   
  
Star数: 53072   
  
漏洞详情链接: https://github.com/minio/minio/issues/21375  
  
  
2.   
PostgREST API Server因JWT身份验证缺陷引发横向移动及数据泄露风险  
  
  
漏洞描述  
  
该漏洞源于JWT校验逻辑违背RFC 7519规范要求，默认配置完全忽略aud（受众）声明字段的存在性判断。攻击者可利用此缺陷在跨服务调用场景中劫持合法JWT，通过调整iss（签发方）或sub（主题）字段值实施身份伪装，进而突破同源策略限制完成横向渗透。由于无需用户交互即可经网络路径触发，且直接影响保密性（HIGH）和完整性（HIGH），可能造成整个数据平面的越权访问与篡改风险。  
  
  
组件描述  
  
PostgREST是一款将PostgreSQL数据库直接暴露为RESTful API的服务框架，采用零配置模式实现SQL到JSON的数据交互，其核心特性包括自动表结构映射、行级安全策略与OAuth 2.0身份验证支持。组件通过中间件层抽象数据库操作，适用于微服务架构中快速构建数据接口场景，默认启用JWT身份验证但依赖第三方库解析声明字段。  
  
  
漏洞详情  
  
漏洞威胁性评级: 9.1 (超危)   
  
漏洞类型: Improper Authorization (CWE-285)   
  
受影响组件仓库地址: https://github.com/PostgREST/postgrest   
  
Star数: 25385   
  
漏洞详情链接: https://github.com/PostgREST/postgrest/issues/4134  
  
  
3.   
Zizmor组件符号引用时间竞争漏洞允许攻击者远程执行任意代码  
  
  
漏洞描述  
  
该漏洞源于时间竞争检查缺陷（TOCTOU），攻击者可构造包含双阶段载荷的分支。首阶段以无风险提交诱导维护人员发起`workflow_dispatch`事件，随后立即更新符号引用指向嵌有隐蔽payload的新提交。由于工作流引擎在接收事件指令时尚未完成分支快照冻结，攻击者可在代码拉取与脚本解析间隙注入恶意文件（如植入shell命令或第三方库）。CVSS 9.6评分映射出漏洞具备远程代码执行（RCE）、完全破坏机密性、完整性和可用性的潜力，且攻击链涉及用户交互环节增加社会工程维度威胁。  
  
  
组件描述  
  
zizmor作为一个基于GitHub Actions的持续集成组件，其核心功能是通过工作流定义实现自动化构建与部署。组件采用符号引用（symbolic reference）绑定分支/拉取请求上下文的方式触发执行，设计目标在于简化多源代码协同开发场景下的流程编排。然而这种动态执行机制依赖于事件驱动模型与维护人员手动触发逻辑，导致执行前后的上下文一致性难以保障。  
  
  
漏洞详情  
  
漏洞威胁性评级: 9.6 (超危)   
  
漏洞类型: TOCTOU (CWE-362)   
  
受影响组件仓库地址: https://github.com/zizmorcore/zizmor   
  
Star数: 2684   
  
漏洞详情链接: https://github.com/zizmorcore/zizmor/issues/935  
  
  
  
新增CVE 情报  
  
  
  
1.   
Firefox Canvas渲染恶意绘图指令越界内存写漏洞导致远程代码执行  
  
  
漏洞描述  
  
漏洞编号：CVE-2025-49709  
  
发布日期：2025年06月11日  
  
CVSS v3.1 评分为 9.8（超危）  
  
参考链接：https://nvd.nist.gov/vuln/detail/CVE-2025-49709  
  
  
在 139.0.4 版本前，其 HTML Canvas 渲染模块因边界校验不足，存在 越界内存写（CWE-787） 安全缺陷。特定序列化绘图指令（如位图合成、像素缓冲区操作）可能引发堆内存覆盖，威胁进程稳定性与安全性。Firefox 浏览器在特定画布操作场景下存在内存损坏漏洞，攻击者可通过构造恶意页面触发，导致远程代码执行或服务中断。该漏洞已被证实存在公开利用证据。漏洞影响所有未更新至 139.0.4 的 Firefox 用户，包括桌面版与移动设备部署场景。攻击者仅需诱导目标访问特制网页即可完成漏洞利用，无须用户交互且可远程操控。  
  
  
组件描述  
  
Firefox 是一款跨平台开源网络浏览器，支持复杂图形渲染与 Web 技术交互。  
  
  
潜在风险    
  
攻击复杂度低：非专业攻击者亦可构造 PoC     
  
已检测到实际利用尝试：攻防对抗窗口紧缩  
  
  
修复建议     
  
1. 紧急升级至 Firefox 139.0.4 或更高版本   
  
2. 对运行环境启用沙箱隔离机制     
  
3. 阻断不可信来源的 Canvas 脚本加载  
  
4. 监控异常内存访问行为日志  
  
  
2.   
Firefox JS引擎OrderedHashTable构造数据处理整数溢出漏洞致任意代码执行  
  
  
漏洞描述  
  
漏洞编号：CVE-2025-49710     
  
发布时间：2025年06月11日    
  
CVSS v3.1 评分为 9.8（超危）  
  
参考链接：https://nvd.nist.gov/vuln/detail/CVE-2025-49710  
  
  
在 Firefox < 139.0.4 版本中，JavaScript 引擎使用的 `OrderedHashTable` 组件存在整数溢出漏洞。当处理特定构造的表数据时，整数运算结果超出变量表示范围可能导致内存越界行为，攻击者可通过远程恶意网站触发该漏洞，进而造成任意代码执行或服务中断风险。     
  
  
组件描述  
  
Mozilla Firefox 是由 Mozilla 基金会开发的开源网页浏览器，其内置 JavaScript 引擎负责解析和执行 Web 页面中的脚本逻辑。  
  
  
潜在风险  
  
该漏洞攻击门槛极低，无需用户交互即可实现远程利用，泄露内容可能涵盖敏感内存状态并破坏系统稳定性。  
  
  
修复建议  
  
建议受影响用户立即升级至 Firefox 139.0.4 及以上版本，开发者需优先审查动态数组大小计算逻辑，采用边界检查机制防范类似问题。  
  
  
3.   
Microsoft 365 Copilot AI命令解析恶意指令注入漏洞致系统命令执行  
  
  
漏洞描述  
  
漏洞编号：CVE-2025-32711   
  
发布时间：2025年06月11日     
  
CVSS v3.1 评分为 9.3（超危）  
  
参考链接：https://nvd.nist.gov/vuln/detail/CVE-2025-32711  
  
  
其 AI 命令解析组件 存在严重安全缺陷：攻击者可通过构造恶意输入向系统注入未经验证的命令参数，绕过默认的安全校验逻辑，在目标服务器上执行任意操作系统指令。具体而言，当用户提交特定格式的查询请求时，系统未能有效区分合法的自然语言指令与潜在危险的操作符组合（如分号 `;`、管道符 `|` 等），导致攻击者能够触发底层脚本引擎执行非预期操作。该漏洞无需用户交互即可远程利用，成功入侵后可读取本地文件、劫持内部服务通信或横向渗透企业内网资源。  
  
  
组件描述  
  
Microsoft 365 Copilot 是微软推出的集成式人工智能协作平台，旨在通过自然语言交互协助企业管理文档、数据分析、会议记录等核心业务流程。该系统基于云端部署，提供跨设备的实时协同能力，广泛应用于企业知识库构建与智能决策场景。  
  
  
潜在风险  
  
此漏洞攻击成本极低（CVSS 可利用性得分3.9），且因涉及敏感数据泄露（CVSS 机密性影响 HIGH），已被证实具备实战化利用价值。  
  
  
修复建议  
  
建议受影响用户立即关注微软官方公告，部署紧急修复方案，并通过最小权限原则限制 Copilot 的 API 调用范围。  
  
**投毒情报**  
  
  
1. npm投毒事件  
  
  
事件描述  
  
npm中frontend-tests组件的1.0.0版本被标记为存在恶意性。该组件被发现与一个与恶意活动相关的域名进行通信并且执行了一个或多个与恶意行为相关的命令。该组件版本的md5值为f4bbbbff85459bdfe65848726d941a6f  
  
  
发布日期  
  
2025年06月12日  
  
  
2.  
npm投毒事件  
  
  
事件描述  
  
  
npm中os-apps-ui-curvelibrary组件的11.1.9版本被标记为存在恶意性。该组件被发现与一个与恶意活动相关的域名进行通信并且执行了一个或多个与恶意行为相关的命令。该组件版本的md5值为f66ee3328243970488d7bf8c995a4cdc   
  
  
发布日期  
  
2025年06月12日  
  
  
**扫码进群：****获取每日最新漏洞和投毒情报推送**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ibSWU7ian1thv0t8s4gJ7hF4WicJfORlicGxafKVXkGuZgvduauND4SbxoRFWlib9XbJic1XZ8G549Xn5VOcynlkMp6w/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/MVPvEL7Qg0HJalXIBXGXSBFLMk2TZAqh23iaHwLpprUov8bNQ95dWDVMTq4qGicM3G6cmsZcCF6RsKyn9p8eQA3Q/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
清源SCA开源版交流群  
  
****  
  
  
开源安全，始于清源。让我们共同守护代码基石，释放开源生态的真正潜力！  
  
  
**关于安势信息**  
  
  
上海安势信息技术有限公司是国内先进的软件供应链安全治理解决方案提供商，核心团队来自Synopsys、华为、阿里巴巴、腾讯、中兴等国内外企业。安势信息始终坚持DevSecOps的理念和实践，以AI、多维探测和底层引擎开发等技术为核心，提供包括清源CleanSource SCA（软件成分分析）、清源SCA开源版、清正CleanBinary (二进制代码扫描)、清流PureStream（AI风险治理平台）、清本CleanCode SAST（企业级白盒静态代码扫描）、可信开源软件服务平台、开源治理服务等产品和解决方案，覆盖央企、高科技、互联网、ICT、汽车、高端制造、半导体&软件、金融等多元化场景的软件供应链安全治理最佳实践。  
  
  
欢迎访问安势信息官网www.sectrend.com.cn或发送邮件至 info@sectrend.com.cn垂询。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ibSWU7ian1thvJpbKXyJVyQ2vRt08HVKaXxHczG4WsCrOtWTeECrIBfiacYYzN8uWv0p1JiayvmhDqOnLBEt4HnZow/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ibSWU7ian1thsJfhqflSV8MgJqD32s60b2PF5zeRQ6zmpTCOKG5oa2118EA63XoLxem1ldHCgibnsH3aL0aKFOW9Q/640?wx_fmt=gif "")  
  
**点击蓝字 关注我们**  
  
  
  
  
