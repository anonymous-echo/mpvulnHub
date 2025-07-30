#  Nuclei，一键发现99%的漏洞，白帽子都在私藏的扫描神器| |基于YAML模板的新一代漏洞扫描工具，让渗透测试效率提升10倍   
原创 VlangCN  HW安全之路   2025-01-13 13:50  
  
Nuclei 是一款高效的漏洞扫描工具，用于检查现代应用程序、基础设施、云平台和网络，以帮助识别和修复可被利用的漏洞。  
  
Nuclei 的核心是基于 **YAML 模板**  
 的设计。这些模板以简单明了的 YAML 文件形式定义了检测、评估和处理特定安全漏洞的方法。  
  
每个模板详细描述了一种可能的攻击路径，包括漏洞的描述、严重程度、优先级评分，有时还会附带相关的漏洞利用方式。这种以模板为中心的方法不仅能帮助 Nuclei 识别潜在威胁，还能精准定位具有实际威胁的可利用漏洞，从而具备显著的现实应用价值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Bvow4Cv9oZ3QfHWHOmdyYdgicTQsTKLg0dDFkwSH3WbaWMjzudunNK6JBZWqh7yJyEs3ibF1flgO1srazAglxCuw/640?wx_fmt=jpeg&from=appmsg "")  
  
### Nuclei 概述  
  
Nuclei 是一款高效且可定制的漏洞扫描器，具备以下特点：  
- **模板驱动**  
：基于简单的 YAML 格式创建和自定义漏洞检测模板。  
  
- **社区支持**  
：由全球安全社区贡献模板，用以应对最新的漏洞。  
  
- **精准检测**  
：通过模拟真实场景的步骤，减少误报。  
  
- **高性能**  
：支持超快速的并行扫描和请求聚合。  
  
- **集成能力**  
：可嵌入 CI/CD 流水线，用于漏洞检测和回归测试。  
  
- **多协议支持**  
：涵盖 TCP、DNS、HTTP、SSL、JavaScript 等多种协议。  
  
- **灵活扩展**  
：可与 Jira、Splunk、GitHub、Elastic 等工具集成。  
  
### 安装 Nuclei  
#### 安装方式一：使用 go  
  
通过 go  
 编译和安装最新版本：  
```
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -version

```  
#### 安装方式二：从源码构建  
```
git clone https://github.com/projectdiscovery/nuclei.git
cd nuclei/cmd/nuclei
go build
sudo mv nuclei /usr/local/bin/
nuclei -version

```  
#### 安装方式三：直接下载已构建的包  
  
以 Linux 为例：  
```
wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_linux_amd64.zip
unzip nuclei_3.3.2_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
nuclei -version
nuclei -update-templates

```  
#### 查看使用帮助  
```
nuclei -h

```  
### 使用 Nuclei 进行漏洞扫描  
#### 本地测试  
  
如果您不希望测试外部目标，可以在本地运行一些漏洞环境（如 DVWA 或 OWASP Juice Shop）。这些环境可以通过 Docker 容器快速部署。例如：  
```
docker --version
# 确保 Docker 已安装
sudo docker pull bkimminich/juice-shop
sudo docker run -d -p 3000:3000 bkimminich/juice-shop

```  
  
运行后，通过以下地址访问 Juice Shop：  
```
http://<本地实验室IP>:3000

```  
#### 开始扫描  
  
运行以下命令对 Juice Shop 进行扫描：  
```
nuclei -u http://localhost:3000 -o results_test.txt

```  
- **-u  
**：指定目标 URL。  
  
- **-o  
**：将扫描结果输出到指定的文本文件。  
  
#### 查看扫描结果  
  
扫描结果保存在 results_test.txt  
 文件中，示例如下：  
```
[dns-rebinding:IPv4] [dns] [unknown] localhost ["127.0.0.1"]
[swagger-api] [http] [info] http://localhost:3000/api-docs/swagger.json [paths="/api-docs/swagger.json"]
[missing-sri] [http] [info] http://localhost:3000 ["//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js","//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"]
[http-missing-security-headers:content-security-policy] [http] [info] http://localhost:3000
[http-missing-security-headers:referrer-policy] [http] [info] http://localhost:3000
...

```  
#### 分析发现的漏洞  
  
以下是部分扫描结果的解析：  
1. **DNS 重绑定**  
：检测到本地环境中 localhost 解析到 127.0.0.1  
。在生产环境中，需确保正确配置 DNS，以防止 DNS 重绑定攻击。  
  
1. **Swagger API**  
：API 文档暴露在 /api-docs/swagger.json  
 路径下。在生产环境中，应对其进行保护或移除，避免泄露敏感 API 信息。  
  
1. **缺少子资源完整性（SRI）**  
：外部 JavaScript 库（如 jQuery）未启用 SRI 校验，可能导致脚本在传输过程中被篡改。  
  
1. **缺失安全头**  
：未设置多种重要的安全头，例如内容安全策略（CSP）和跨域资源策略（CORP），可能增加 XSS 或点击劫持等攻击的风险。  
  
1. **暴露的 Metrics**  
：检测到 /metrics  
 路径暴露了 Kubelet 和 Prometheus 的监控数据，可能泄露敏感的操作信息。  
  
1. **robots.txt 文件**  
：检测到 robots.txt  
 文件，需确保其中未暴露敏感路径。  
  
### 按需运行模板  
  
Nuclei 支持通过指定模板运行特定的扫描。例如，如果只想运行与 Cisco 相关的模板，可以使用以下命令：  
```
nuclei -t cisco -u http://localhost:3000 -o results_test.txt

```  
#### 批量目标扫描  
  
如果需要扫描多个目标，可以将目标列表保存在一个 .txt  
 文件中，并使用以下命令：  
```
nuclei -list targets.txt

```  
### 总结  
  
Nuclei 是一款强大的漏洞扫描工具，其模板驱动的架构、社区支持以及高性能使其成为现代安全测试的首选工具。在本文中，我们展示了 Nuclei 的核心概念、安装方法以及如何使用其扫描本地漏洞环境（如 OWASP Juice Shop）。Nuclei 的功能远不止于此，您还可以通过自定义模板、集成 CI/CD 流水线等方式，进一步发挥其潜力，帮助您快速识别和修复安全漏洞。  
  
  
