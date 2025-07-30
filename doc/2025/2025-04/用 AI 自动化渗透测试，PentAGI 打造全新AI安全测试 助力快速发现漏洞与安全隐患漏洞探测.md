#  用 AI 自动化渗透测试，PentAGI 打造全新AI安全测试 助力快速发现漏洞与安全隐患|漏洞探测   
原创 CeBain  渗透安全HackTwo   2025-04-21 16:03  
  
0x01 工具介绍 网络安全攻防战已进入白热化阶段，传统手动测试效率低下。PentAGI的横空出世，正在用AGI技术重构安全测试的底层逻辑。VXControl 团队打造的开源工具，凭借自动化、智能化的设计，为安全测试注入全新活力，通过智能 AI 代理进行渗透测试，打破了传统测试方式的局限。基于AI的攻击路径规划与漏洞利用这个文章里面提到的AI 渗透测试工具。已经实现了完全自主的 AI 代理，使用终端、浏览器、编辑器和外部搜索系统执行复杂的渗透测试任务等功能。注意：现在只对常读和星标的公众号才展示大图推送，建议大家把渗透安全HackTwo"设为星标⭐️"否则可能就看不到了啦！  
**下载地址在末尾**  
  
0x02 功能简介  
### ✨ 核心亮点：PentAGI 核心特征详解  
###   
- **安全隔离**  
：所有操作在沙盒化Docker环境中运行，确保系统安全。  
  
- **自主决策**  
：AI自动规划渗透测试步骤，无需人工干预。  
  
- **浏览器集成**  
：内置爬虫引擎，实时获取网络情报。  
  
- **内置编辑器**  
：Web界面直接查看和修改目标文件。  
  
- **完整历史记录**  
：所有操作和结果存储在PostgreSQL数据库。  
  
- **智能镜像选择**  
：根据任务自动匹配最佳Docker工具镜像。  
  
- **自托管部署**  
：支持私有化安装，数据完全自主掌控。  
  
- **现代化UI**  
：直观的Web仪表盘，实时可视化测试进度。  
  
- **AI行为监控**  
：集成Langfuse，全程记录AI决策过程。  
  
- **版本控制**  
：自动同步GitHub项目状态和工具版本。  
  
- **开放API**  
：提供REST和GraphQL接口，支持深度定制。****  
  
- **智能搜索**  
：整合Google/Tavily等引擎，快速获取漏洞情报。  
  
- **一句话总结**  
：PentAGI是集AI自动化、专业工具链和安全隔离于一体的智能渗透测试平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6yeR5BEFzE2ib8wl7blV2IxiafU6J6qia2BQnH89TWxShicons1ibBvvIUIPZ6dkrJdGcc6V9GwhJWlrw/640?wx_fmt=png&from=appmsg "")  
### PentAGI 工作原理  
###   
- **任务定义**  
：用户指定目标系统及测试范围（如Web应用、内网渗透等）。  
  
- **AI分析**  
：系统智能评估目标，自动选择最佳工具和攻击路径。  
  
- **自动化测试**  
：AI代理调用Nmap/Metasploit等工具执行扫描和漏洞利用。  
  
- **实时监控**  
：仪表盘动态显示当前攻击进度、发现漏洞和风险等级。****  
  
- **报告生成**  
：自动输出含漏洞详情、复现步骤和修复建议的专业报告。  
  
- **核心优势**  
：从任务下发到报告生成全流程自动化，大幅提升渗透测试效率。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6yeR5BEFzE2ib8wl7blV2IxYOGhXOro0BBfhCeUHGgJcCyFmdliaibY1zR3icvsibaQOtosZxibwaNqBow/640?wx_fmt=png&from=appmsg "")  
## 人工智能服务提供商  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6yeR5BEFzE2ib8wl7blV2IxFthCc6lcAn4XyRz7jsRPLdtse1IP6RyRgvEqHsZ5B2BaMB5KwWV8hQ/640?wx_fmt=png&from=appmsg "")  
## 可观察性堆栈  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6yeR5BEFzE2ib8wl7blV2IxPKZV1lFN5cUWTfh7siaP9g0qbRI9Vg6mQ2c5zsd8OIA3WH0ZbetOWhA/640?wx_fmt=png&from=appmsg "")  
  
自动化渗透效果图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6yeR5BEFzE2ib8wl7blV2IxvFDpr4vgHFgIibic98bLYj9aaG4JFWicq11uHkZs8deMY1GribKMVmMCGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6yeR5BEFzE2ib8wl7blV2IxPxQLNiaXbzlACtbjDORC7GnxRjd2ScrgqmGSDmdfBVYZ3bZ5MRsL16Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6yeR5BEFzE2ib8wl7blV2IxztzoKjtn2jtfTy2Dqe2F8UdZRs0oftNZ0bzuNZNqDFZyuEEIMcM2Ag/640?wx_fmt=png&from=appmsg "")  
## 0x03更新说明✨ 完全自主的 AI 代理系统，能够执行复杂的渗透测试任务0x04 使用介绍🚀 快速入门系统要求：Docker 和 Docker Compose最低 4GB RAM10GB 可用磁盘空间访问互联网 以下载 Docker 镜像和更新基本安装步骤：创建工作目录或克隆存储库：mkdir pentagi && cd pentagi  
  
**下载并配置 .env 文件：复制或下载**.env.example  
 文件：  
```
curl -o .env https://raw.githubusercontent.com/vxcontrol/pentagi/master/.env.example
```  
  
**在 .env 文件中填写所需的 API 密钥：**  
打开 .env  
 文件并填写以下 API 密钥：  
- **必填：**  
 至少选择一个 LLM 提供商（如 OpenAI 或 Anthropic）  
  
```
# Required: At least one of these LLM providers
OPEN_AI_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key

# Optional: Additional search capabilities
GOOGLE_API_KEY=your_google_key
GOOGLE_CX_KEY=your_google_cx
TAVILY_API_KEY=your_tavily_key
TRAVERSAAL_API_KEY=your_traversaal_key
PERPLEXITY_API_KEY=your_perplexity_key
PERPLEXITY_MODEL=sonar-pro
PERPLEXITY_CONTEXT_SIZE=medium
```  
  
**清除 .env 文件中的注释（如果需要）：**  
  
如果在 VSCode 或其他 IDE 中使用 .env  
 文件，可以通过以下命令清除所有内联注释：  
## perl -i -pe 's/\s+#.*$//' .env运行 PentAGI 堆栈：下载并运行 docker-compose.yml 文件curl -O https://raw.githubusercontent.com/vxcontrol/pentagi/master/docker-compose.ymldocker compose up -d访问 Web UI：在浏览器中访问 PentAGI Web UI，默认地址为 localhost:8443，默认登录用户名和密码为：用户名：admin@pentagi.com密码：admin注意事项：如果遇到有关 pentagi-network 或 observability-network 的错误，需要首先运行以下命令以创建网络，然后运行带有 Langfuse 和 Observability 服务的堆栈：docker-compose -f docker-compose.yml -f docker-compose-langfuse.yml -f docker-compose-observability.yml up -d您必须设置至少一个语言模型提供商（如 OpenAI 或 Anthropic）才能使用 PentAGI。其他搜索引擎 API 密钥是可选的，但建议使用它们以获得更好的效果。如果使用 TCP/IP 连接 Docker，而不是使用套接字文件，可以移除 root 权限并使用默认的 pentagi 用户，以提高安全性。🔧 高级设置Langfuse 集成：Langfuse 提供了监控和分析 AI 代理操作的高级功能。您可以在 .env 文件中配置 Langfuse 环境变量：在 .env 文件中启用与 Langfuse 的集成：LANGFUSE_BASE_URL=http://langfuse-web:3000LANGFUSE_PROJECT_ID= # 默认值：${LANGFUSE_INIT_PROJECT_ID}LANGFUSE_PUBLIC_KEY= # 默认值：${LANGFUSE_INIT_PROJECT_PUBLIC_KEY}LANGFUSE_SECRET_KEY= # 默认值：${LANGFUSE_INIT_PROJECT_SECRET_KEY}运行 Langfuse 堆栈：curl -O https://raw.githubusercontent.com/vxcontrol/pentagi/master/docker-compose-langfuse.ymldocker compose -f docker-compose.yml -f docker-compose-langfuse.yml up -d访问 Langfuse Web UI：在浏览器中访问 localhost:4000，使用 .env 文件中的凭据登录。监控和可观察性：要详细跟踪系统运行情况，您可以与监控工具集成。启用与 OpenTelemetry 和 PentAGI 的可观察性服务集成：在 .env 文件中启用集成：OTEL_HOST=otelcol:8148运行可观察性堆栈：curl -O https://raw.githubusercontent.com/vxcontrol/pentagi/master/docker-compose-observability.ymldocker compose -f docker-compose.yml -f docker-compose-observability.yml up -d访问 Grafana Web UI：在浏览器中访问 localhost:3000。笔记如果您想将 Observability 堆栈与 Langfuse 一起使用，则需要在.env文件中启用集成以设置LANGFUSE_OTEL_EXPORTER_OTLP_ENDPOINT为http://otelcol:4318。并且您需要运行这两个堆栈docker compose -f docker-compose.yml -f docker-compose-langfuse.yml -f docker-compose-observability.yml up -d才能运行所有服务。您还可以在 shell 中为这些命令注册别名，以便更快地运行它：alias pentagi="docker compose -f docker-compose.yml -f docker-compose-langfuse.yml -f docker-compose-observability.yml"alias pentagi-up="docker compose -f docker-compose.yml -f docker-compose-langfuse.yml -f docker-compose-observability.yml up -d"alias pentagi-down="docker compose -f docker-compose.yml -f docker-compose-langfuse.yml -f docker-compose-observability.yml down"集成 GitHub 和 Google OAuth：PentAGI 支持 GitHub 和 Google 的 OAuth 集成，允许用户使用现有帐户进行身份验证。使用 GitHub OAuth： 在 GitHub 中创建新的 OAuth 应用程序并在 .env 文件中配置：GITHUB_CLIENT_ID=your_github_client_idGITHUB_CLIENT_SECRET=your_github_client_secret使用 Google OAuth： 在 Google 中创建新的 OAuth 应用程序并在 .env 文件中配置：GOOGLE_CLIENT_ID=your_google_client_idGOOGLE_CLIENT_SECRET=your_google_client_secret  
0x05 内部VIP星球介绍-V1.4（福利）        如果你想学习更多渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点欢迎加入我们内部星球可获得内部工具字典和享受内部资源和内部交流群，每1-2天更新1day/0day漏洞刷分上分(2025POC更新至3700+)，包含网上一些付费工具及BurpSuite自动化漏洞探测插件，AI代审工具等等。shadon\Quake\Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！全网资源最新最丰富！（🤙截止目前已有1700多位师傅选择加入❗️早加入早享受）  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250422获取下载**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP星球福利介绍V1.4星球介绍(0day推送)**  
  
**2. 最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**3. 最新Nessus2025.02.10版下载**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard 10.2.128273破解版下载**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
