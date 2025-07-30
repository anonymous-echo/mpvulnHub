#  Safety：Python 依赖漏洞检测与安全保障工具   
原创 Urkc安全  Urkc安全   2024-09-06 18:03  
  
Safety 项目是一个用于检测 Python 依赖包已知安全漏洞的工具，通过维护一个不断更新的漏洞数据库来保障项目的安全性。它支持扫描 requirements.txt 等依赖文件，并且可以集成到 CI/CD 流程中。Safety 提供详细的报告选项，支持离线扫描，还允许用户使用自定义数据库。该项目以 MIT 许可证开源，欢迎社区贡献，并提供详细的文档和支持。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FL9Xqxpicm6qwYL7eibIjxDiaCaqqWzvELwu06jjMWibsPt1Cdk7PBsia2YAQZvibLLLyyHeuuicqITKHjZdVUaaqMLeA/640?wx_fmt=png&from=appmsg "")  
#### 1. 项目概述  
  
- **项目名称**: Safety  
  
- **仓库地址**: pyupio/safety  
  
- **目标**: 一个用于检查 Python 依赖包已知安全漏洞的工具。  
  
- **编程语言**: Python  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/FL9Xqxpicm6qwYL7eibIjxDiaCaqqWzvELwMrxwZCepeH2Fk0ohC5l9b2SS9luj9FMG8xibAia73IIPGNdeqjiaRib6Kw/640?wx_fmt=gif&from=appmsg "")  
#### 2. 主要功能  
  
- **漏洞扫描**: 检测 Python 依赖包中的已知安全漏洞。  
  
- **漏洞数据库**: 拥有一个持续更新的 Python 包漏洞数据库。  
  
- **依赖文件支持**: 支持扫描 requirements.txt 等依赖文件。  
  
- **自定义数据库**: 允许使用自定义漏洞数据库进行扫描。  
  
- **CI/CD 集成**: 可以集成到持续集成和持续交付（CI/CD）管道中。  
  
- **离线扫描**: 支持离线模式下的漏洞扫描。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FL9Xqxpicm6qwYL7eibIjxDiaCaqqWzvELwH0jhnuOI5h8vOVbIicuoT9qWcic3db3yzqAqgfDdm4gbOjq8NwMrpP7g/640?wx_fmt=png&from=appmsg "")  
#### 3. 安装  
  
- **包安装**: 可以通过 pip 安装 ( pip install safety)。  
  
- **Docker 支持**: 可以通过 Docker 容器运行。  
  
- **依赖要求**: Python 3.6 或更高版本。  
  
  
#### 4. 使用方法  
  
- **基本命令**:  
  
- safety check: 扫描依赖项中的漏洞。  
  
- safety report: 生成漏洞报告。  
  
- **命令选项**:  
  
- --full-report: 输出详细的扫描结果。  
  
- --ignore: 通过漏洞 ID 排除指定的漏洞。  
  
- --file: 指定自定义文件进行扫描。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/FL9Xqxpicm6qwYL7eibIjxDiaCaqqWzvELw1wnkp4cKfMRGIZyVEIOtQSqxMU3AOFxia8vrNa8QzIRYvPP2dHlA3og/640?wx_fmt=gif&from=appmsg "")  
#### 5. 贡献指南  
  
- **问题跟踪和讨论**: 提供问题跟踪器，用于报告错误和提出功能请求。  
  
- **贡献方法**: 提供贡献指南，涵盖如何运行测试和提交合并请求。  
  
- **行为准则**: 为贡献者提供社区行为守则。  
  
  
#### 6. 文档  
  
- **用户指南**: 详细的安装和使用说明。  
  
- **API 参考**: 公共 API 的文档说明。  
  
- **示例**: 提供使用场景的代码示例。  
  
- **官方文档**: https://docs.safetycli.com/  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FL9Xqxpicm6qwYL7eibIjxDiaCaqqWzvELwKZFvich8dFmBdeljnibzY2WJSFxMw0o3HV2OEQ8OTVJ9Hy47jvR3XBag/640?wx_fmt=png&from=appmsg "")  
#### 7. 许可  
  
- **许可证**: MIT 许可证  
  
  
#### 8. 社区与支持  
  
- **讨论**: GitHub Discussions 提供社区支持。  
  
- **安全问题**: 提供报告安全漏洞的指南。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FL9Xqxpicm6qwYL7eibIjxDiaCaqqWzvELwu06jjMWibsPt1Cdk7PBsia2YAQZvibLLLyyHeuuicqITKHjZdVUaaqMLeA/640?wx_fmt=png&from=appmsg "")  
  
  
  
