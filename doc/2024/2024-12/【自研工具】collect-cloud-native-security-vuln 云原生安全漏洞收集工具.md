#  【自研工具】collect-cloud-native-security-vuln: 云原生安全漏洞收集工具   
原创 Y4ney  喵苗安全   2024-12-21 02:27  
  
## 0x00 概述  
  
collect-cloud-native-security-vuln[1]  
 是一款用于收集云原生生态系统中各个组件安全漏洞的工具。   
  
![](https://mmbiz.qpic.cn/mmbiz_png/wjnOkgIccsXwTRic1iaQia4qpa7IwibpWYKlV0X5bzUMreUp1jsWaQ6S8ueDOENTsaDAlJqE93KzeGk2TYsADSTGQQ/640?wx_fmt=png&from=appmsg "")  
  
通过自动化方式，它能帮助你及时获取到相关项目的最新安全信息，以便采取相应的防护措施。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wjnOkgIccsXwTRic1iaQia4qpa7IwibpWYKlick0bkFAfrLr05TXED0WafHal3lhUm4McZwYmW1dGhu72opuxBIXia0w/640?wx_fmt=png&from=appmsg "")  
  
所有收集的 JSON 数据通过 Github Action ， 每 6 小时更新在仓库  
cloud-native-sec-vuln[2]  
 中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wjnOkgIccsXwTRic1iaQia4qpa7IwibpWYKllqPuBoFBBNU2fw1LwgEwMXxkD6ic4SuvlD0N5IeleRMOQFn5ibSEeA7g/640?wx_fmt=png&from=appmsg "")  
  
## 0x01 快速开始  
### 1.1 安装  
1. 确保你的系统已安装 Go 环境，并克隆本项目到本地：```
git clone https://github.com/miao2sec/cloud-native-security-vuln.git
```  
  
  
1. 编译并生成可执行文件```
cd cloud-native-security-vulngo build -o collect
```  
  
  
### 1.2 使用  
1. (使用默认配置)进行漏洞收集  
```
./collect
```  
  
  
1. 生成默认的配置文件  
```
./collect -g
```  
  
  
1. 自定义漏洞数据的缓存路径  
```
./collect -r -c path/to/cacheDir
```  
  
  
1. 使用自定义的配置文件进行漏洞收集  
```
./collect -r -f <config>.yaml
```  
  
  
## 0x02 功能特性  
- 自动收集云原生生态系统中各个组件的安全漏洞信息。  
  
- 支持自定义配置文件，灵活调整收集策略。  
  
- 缓存漏洞数据，避免重复查询。  
  
- 支持多种命令行参数，方便用户操作。  
  
## 0x03 配置说明  
  
配置文件采用 YAML 格式，以下是一个示例配置：  
```
# token：GitHub API Token，用于访问 GitHub APItoken:write-your-github-token# cache_dir：漏洞数据存储目录cache_dir:cloud-native-sec-vuln# components：需要收集漏洞信息的组件列表，包括组件的 owner 和 repo。components:    -owner:moby      repo:buildkit    -owner:opencontainers      repo:runc
```  
## 0x04 组件支持  
### 4.1 运行时组件  
1. Docker (Moby)  
  
1. runc  
  
1. containerd  
  
1. CRI-O  
  
1. gVisor  
  
1. inclavare-containers  
  
1. iSulad  
  
1. Kata Containers  
  
1. Krustlet  
  
1. Kuasar  
  
1. Lima  
  
1. LXC  
  
1. rkt  
  
1. Singularity  
  
1. SmartOS  
  
1. Stratovirt  
  
1. Sysbox  
  
1. Virtual Kubelet  
  
1. WasmEdge  
  
1. Youki  
  
1. Podman  
  
### 4.2 网络组件  
1. Cilium  
  
### 4.3 容器镜像构建  
1. Kaniko  
  
1. BuildKit  
  
1. Buildah  
  
1. Bazel  
  
1. img  
  
1. orca-build  
  
### 4.4 服务网格  
1. Istio  
  
## 0x05 贡献指南  
  
欢迎各位同学参与本项目，共同完善云原生安全漏洞收集工具。以下是贡献指南：  
1. Fork 本项目。  
  
1. 创建您的特性分支。```
git checkout -b new-feature
```  
  
  
1. 提交您的修改。```
git commit -am 'Add some feature'
```  
  
  
1. 将您的修改推送到分支。```
git push origin new-feature
```  
  
  
1. 提交 Pull Request。  
  
## 0x06 许可证  
  
本项目采用 MIT 许可证，详情请参阅  
LICENSE[3]  
 文件。  
  
👇【点击阅读原文，直接跳转到项目地址】👇  
  
参考资料  
  
[1]  
collect-cloud-native-security-vuln:https://github.com/miao2sec/collect-cloud-native-sec-vuln  
  
[2]  
cloud-native-sec-vuln:https://github.com/miao2sec/cloud-native-sec-vuln  
  
[3]  
LICENSE:https://github.com/miao2sec/collect-cloud-native-sec-vuln/blob/main/LICENSE  
  
  
