#  faraday好用的开源漏洞管理平台   
原创 infobyte  知树安全团队   2025-04-22 01:30  
  
## 1、工具介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/4APcPS50PEibEZTlATwIC0RsibfJvtd3jOkJDUeJYLhUMpbhaCxWHhnqmhPLyqiaA5LEvkgQBfzVBFf5z80iaDnNVQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/4APcPS50PEibEZTlATwIC0RsibfJvtd3jOmbrJbE5dSwNJMV3IgnUDC6PPymlCJLlwSd4d2HVGdrfsBmZEhXlSNA/640?wx_fmt=png&from=appmsg "")  
>   
> 安全性有两项艰巨的任务：设计获取新信息的智能方法，以及跟踪结果以改进修复工作。使用 Faraday，您可以专注于发现漏洞，而我们可以帮助您解决其余问题。只需在您的终端中使用它，即可在运行时组织您的工作。 Faraday 旨在让您以真正的多用户方式利用社区中的可用工具。  
  
## 2、主要功能介绍  
- 多用户协作  
 ：支持团队成员在同一个平台上共享信息，协同工作于同一项目，适合团队的安全审计和管理。   
  
- 工具集成 ：集成了多种主流安全扫描工具，如 Nmap、Nessus、Burp Suite 等，还支持通过插件扩展与其他工具的集成，可作为中央控制台管理不同来源的漏洞数据。   
  
- 数据聚合与标准化 ：能自动收集并统一不同来源的漏洞数据，提供一致的视图，便于分析和决策，还允许手动输入发现的漏洞。   
  
- 可视化界面 ：提供直观的界面，不仅适合技术人员，也便于管理层快速了解安全状况，还支持生成自定义报告和仪表盘，以满足不同用户的特定需求。  
  
- 自动化与 CI/CD 集成 ：通过其 API 和命令行接口（CLI），能够与 CI/CD 流程集成，实现自动化扫描和漏洞管理，进一步提高工作效率。   
  
- 支持离线工作 ：在没有互联网连接的情况下，用户依然可以正常使用 Faraday 的所有功能，无需联网，本地即可运行，适合在各种网络环境下使用。   
  
- 免费开源 ：用户可以根据自身需求自由下载、使用和修改代码，降低了使用成本，同时也可以充分利用社区的力量，借鉴他人的经验和技术，共同推动漏洞管理技术的发展。  
  
  
## 3、用法  
- Docker Compose ：这是启动并运行 Faraday 最简单的方法，只需使用   
```
wget https://raw.githubusercontent.com/infobyte/faraday/master/docker-compose.yml
```  
  
 命令获取   
```
docker-compose.yml
```  
  
 文件，然后执行   
```
docker-compose up
```  
  
 命令即可。   
  
  
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
- PyPi ：使用 pip3 安装 faradaysec，然后运行   
```
faraday-manage initdb
```  
  
-   
-   
-   
-   
```
faraday-server
```  
  
命令进行初始化和启动。   
- Binary Packages ：Debian 或 RPM 系统的 Linux 用户可以直接使用二进制包进行安装，安装后将用户添加到 faraday 组，再运行   
```
faraday-manage initdb
```  
  
-   
-   
-   
-   
```
sudo systemctl start faraday-server
```  
- Source ：推荐在虚拟环境中运行，先安装 virtualenv，创建并激活虚拟环境后，克隆远端仓库，安装依赖并运行服务器。  
  
## 4、工具获取  
  
点击下方名片进入公众号 回复关键字【  
250422  
】获取下载链接  
  
## 5、技术交流群和免费圈子  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/4APcPS50PEibEZTlATwIC0RsibfJvtd3jOCODJ5WBwrNaUKkasficUp5RDCibLHmehDaBFw0HBvLjKVy1gdZPMV9Vw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/4APcPS50PEibEZTlATwIC0RsibfJvtd3jOic9ZNEFs36v8v1eJm51zoAUDcNnV9ia7cKlEyRJQYb135q0MxHaRVGVQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
