#  Nuclei POC 管理工具（附POC地址）   
原创 perlh  蓝猫Sec   2025-01-18 02:46  
  
## wavely  
- 一款功能强大且操作简便的 POC 工具。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicYicLMVlzlVG9UenQs6m2yuwLNbRUjyg1fbpr5QjZAxSBkPWa0RmcvbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdic9KqRG6WYdWt06mktxjficeFibgiaVo7p8vwlaeY17VwRfibSLibORFm7EKA/640?wx_fmt=png&from=appmsg "")  
### ✨ 功能  
```
一款强大的桌面端 Nuclei POC 管理工具，功能涵盖 Nuclei 模板的增删查改操作，全面支持 MacOS、Windows 和 Linux 三大操作系统。
核心功能：多POC、多任务、多目标并行扫描：高效管理并行扫描任务，提升工作效率。
自定义选项：支持配置自定义 DNSLOG 服务器、扫描速率及多种 HTTP 代理（HTTP、HTTPS、SOCKS5）。
请求和响应查看：便捷查看匹配 POC 的请求包和响应包，确保检测透明化。
全新检测引擎：基于 Nuclei v3，全面兼容 YAMLv2 和 YAMLv3 模板格式。
增强扩展：POC 编辑器：支持主题切换，优化用户操作体验。
多模板导入方式：灵活导入 Nuclei 模板，同时支持模板去重处理，确保规范化管理。
国际化支持：提供 简体中文 和 英文 界面，满足多语言需求。
持久化配置：扫描任务、配置信息一键保存，方便后续使用。
API 扫描支持：包含目录扫描功能（如 http://target.com/api）。
操作便捷：一键 手动停止扫描任务，轻松掌控扫描进度。
```  
## 安装  
```
MacOS 安装说明
下载对应的压缩包并解压，解压后的文件夹内包含 Wavely.app 和 Applications 文件夹。
将 Wavely.app 拖动到 Applications 文件夹中完成应用复制。
打开终端，执行以下命令以解除应用限制：
sudo xattr -d com.apple.quarantine /Applications/Wavely.app
Windows 安装说明
使用 Wavely-amd64-installer.exe.zip 安装包进行解压。
双击解压后的安装程序，按照提示完成安装。
```  
### POC导入  
##### 在App中导入POC（带POC去重）  
- 点击  
从文件夹中导入  
按钮，选择  
nuclei poc文件目录  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicF6j8uV9X5G3dMs89ibQdy1wemLy1ichXw4NZIyFLX76E0wZHUblZlXaA/640?wx_fmt=png&from=appmsg "")  
### 快速使用  
  
以下是以扫描 **ThinkPHP 漏洞**  
 为例的具体使用说明  
##### 1、搜索 POC 并扫描  
- 不选择poc，则对搜索结果进行全扫描  
  
- 选择poc后，则对选择的poc进行扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicfCzftyibEZTZd4Bvcfa1fdOB8ACg90xkb2bp1KY8Ed8IY3R0zfJJHVw/640?wx_fmt=png&from=appmsg "")  
##### 2、添加目标  
- 按行添加目标  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicK4v9bbyL2NfQtebUcpgWo0L6a2qRKnnYCxGLV4YROqGdBlzkDLAibPw/640?wx_fmt=png&from=appmsg "")  
##### 3、扫描结果  
- 点击POC ID可跳转到POC编辑界面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicygs1zd3hcq13ohfZ19J5U6Wwx88OgjUlW71EWOfl60jJq1Y9xPTnSg/640?wx_fmt=png&from=appmsg "")  
##### 4、POC测试  
- 对于测试匹配到的POC，可显示请求响应包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdic4CerVfDMjkRMBoENksmeYR7Sa8AxHU2mKBvIuf5G3Ro1EcWbPvoIvg/640?wx_fmt=png&from=appmsg "")  
##### 5、添加Nuclei模版  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicuvVC8ibsHBFVF6oy9q1KJSLoIcuxOrPQdAyIMB2vPNH6neUp0kEtlDw/640?wx_fmt=png&from=appmsg "")  
##### 6、App设置  
###### 通用设置  
1. 可切换POC编辑器主题  
  
1. 选择语言  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicQFicPGqfrFMAvBEVbpAElFUGY7n1AbYHd6FEzrqVHSdJe4egdE1XQiaA/640?wx_fmt=png&from=appmsg "")  
###### 网络设置  
- 添加HTTP代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicQ6PCmbHpYiarFictpD7ENL5ibbg0dppOZm5G8oicKuIfhMtMOzB1qNGKWw/640?wx_fmt=png&from=appmsg "")  
###### 扫描设置  
- POC扫描参数设置  
  
- 设置扫描并发数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicsQc9weialEdf5vVq1m3SxFAx41zUtHJXPJCkX12zqSZF0Wf9PV9VQRQ/640?wx_fmt=png&from=appmsg "")  
###### 模版设置  
- 更新数据库  
  
- 导入模版  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdicyALSI5mZCC5A2OoYIdv7N7eQzgAG5sH9VERHXy6EgVbAziaavldNicPg/640?wx_fmt=png&from=appmsg "")  
#### 模版编辑  
- 编辑POC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdic9KqRG6WYdWt06mktxjficeFibgiaVo7p8vwlaeY17VwRfibSLibORFm7EKA/640?wx_fmt=png&from=appmsg "")  
- 编辑POC（请求）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdice5a4iciaL1UgZZUf4OG4EsucUPxVUjziblJq4fr6uFHnePQnZb8xTaMLw/640?wx_fmt=png&from=appmsg "")  
- 编辑POC （响应）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZXHK19fFGk5ZgEQh0I1PUZ3nribMtZBdic0bhaeveKiche7oecZMicnBNveKOzmBMWpaFeTPVLGo6xSNVENGWWurGw/640?wx_fmt=png&from=appmsg "")  
### 常见问题  
##### Windows启动时闪现弹出命令框  
  
为正常现象，不影响App的功能  
##### Macos 无法打开App  
  
由于没有使用apple证书签名app，可能会提示解除安全验证：  
软件显示禁止符号  
 或   
无法验证软件身份  
 或   
提示已损坏故不能正常打开  
，请参考：  
##### 方案1  
  
执行如下命令即可：  
```
```  
##### 方案2  
```
```  
#   
  
项目地址:  
  
https://github.com/perlh/Wavely  
  
https://github.com/projectdiscovery/nuclei-templates  
  
https://github.com/adysec/nuclei_poc  
  
  
