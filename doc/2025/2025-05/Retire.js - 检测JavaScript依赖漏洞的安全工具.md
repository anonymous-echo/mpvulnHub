#  Retire.js - 检测JavaScript依赖漏洞的安全工具   
原创 qife  网络安全技术点滴分享   2025-05-28 00:35  
  
# 项目概述  
  
Retire.js是一个用于检测JavaScript项目中存在已知漏洞依赖的安全扫描工具。它能够识别网页应用和Node.js应用中使用的具有已知安全漏洞的JavaScript库和模块。  
## 主要特性  
- **多平台支持**  
：提供命令行工具、浏览器扩展和构建工具插件  
  
- **全面检测**  
：通过多种方式检测漏洞依赖：  
  
- 文件名/URL匹配  
  
- 文件内容扫描  
  
- 哈希值比对  
  
- 沙箱执行检测(浏览器扩展)  
  
- **丰富的输出格式**  
：支持文本、JSON、CycloneDX等多种报告格式  
  
- **持续更新**  
：漏洞数据库定期更新  
  
- **轻量级**  
：无复杂依赖，易于集成到开发流程中  
  
## 安装指南  
### 命令行工具安装  
```
npm install -g retire //前提要安装node.js
```  
### 如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209BHHfDzuWr39Q5s316LSu55IKicicU7gbiaMicKjg5YP6iaaDBa4JLvk6yLNibkqC9Ze5JzGTt8PVVlPicA/640?wx_fmt=png&from=appmsg "")  
### Chrome扩展安装  
1. 克隆仓库：git clone https://github.com/RetireJS/retire.js  
  
1. 运行构建脚本：./build_chrome.sh  
  
1. 在Chrome中加载解压的扩展：chrome://extensions/  
 → "开发者模式" → "加载已解压的扩展程序" → 选择chrome/extension  
目录  
  
如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209BHHfDzuWr39Q5s316LSu58GuP0RC2sxZmvAhGHo1ZHpiavoD0J6OAuMqB7CniaLxFQ3alyzamagZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209BHHfDzuWr39Q5s316LSu5nkY40dxskaJzfb0qLZ05JVfHuRsdb0FPq0TyMp0I8FGGTNSovaHMLQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209BHHfDzuWr39Q5s316LSu5RkQG3ggxJnm2wHLILTCxicnW14HxlKlbLCx4Zu5LPTC4nCfXaXGSGwg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209BHHfDzuWr39Q5s316LSu5RhOPTJfu0QIibEnCrhgibV1l4le7ll10RPfv3YMeWDtrKqUk1eWEmibuQ/640?wx_fmt=png&from=appmsg "")  
### Firefox扩展安装  
### firefox在管理扩展中搜索retire.js安装即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209BHHfDzuWr39Q5s316LSu5ibHHELwiaYV6icd0Wia7zwCiamwUzXWUc6bdCmBSjuu9yq0qHY5spWguEMQ/640?wx_fmt=png&from=appmsg "")  
## 使用说明  
### 基本扫描  
```
//npm install -g retire 安装完以后 在命令行执行
retire --path /path/to/scan --proxy http://127.0.0.1:21882 //在国内的话可能要用魔法
```  
### 如下所示，--path 后面添加要检查的web项目（须包含前端源代码的）  
### 比如我这个前后端分离的项目中，前端项目用了axios依赖，它即检测到了该项目使用了axios依赖，并识别出了当前axios使用的版本以及可能存在的漏洞风险  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209BHHfDzuWr39Q5s316LSu5FwIduKWmBvru79gBIux9b5bBx6YeScSK6ImDCUmAEya44U4HbqkS5Q/640?wx_fmt=png&from=appmsg "")  
### 常用选项  
```
# 指定扫描路径
retire --path /path/to/scan

# 输出JSON格式报告
retire --path /path/to/scan --outputformat json

# 忽略特定路径
retire --path /path/to/scan --ignore "node_modules,bower_components"

# 指定漏洞严重级别阈值
retire --path /path/to/scan --severity high
```  
### Chrome扩展使用  
  
安装后，扩展会自动扫描访问的网页，并在开发者控制台显示发现的漏洞。如下所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209BHHfDzuWr39Q5s316LSu5RhOPTJfu0QIibEnCrhgibV1l4le7ll10RPfv3YMeWDtrKqUk1eWEmibuQ/640?wx_fmt=png&from=appmsg "")  
  
FireFox扩展使用  
  
与Chrome扩展使用一样  
  
