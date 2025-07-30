#  【工具分享】Nuclei GUI 管理工具(附12W+poc)   
原创 红岸基地赵小龙  暗影网安实验室   2024-12-11 09:20  
  
## 工具简介  
  
  
由于找不到好用的 POC 管理器，便自行开发，目前仅提供安装包下载。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7ll1KibZ9XolDewyyNicBy7gUJu8oYSXF58xa10HkLojPQZZX11pJyob6LQ/640?wx_fmt=png&from=appmsg "")  
  
## 功能介绍  
  
- **实现功能：**  
    - Nuclei POC 管理桌面应用，支持模版的增删查改操作  
  
    - 支持 Nuclei 扫描、多任务并行扫描  
  
    - 查看 Nuclei 模版请求和响应包  
  
    - 自定义 Nuclei DNSLOG 服务器  
  
    - 自定义扫描速率  
  
    - 支持 HTTP 代理（HTTP、HTTPS、SOCKS5）  
  
    - 兼容 MacOS、Windows 和 Linux 操作系统  
  
    - 使用全新 Nuclei v3 检测引擎  
  
    - 兼容 YAMLv2 和 YAMLv3 Nuclei 模版  
  
    - 支持主题切换  
  
    - 提供多种 Nuclei 模版导入方式  
  
    - 支持模版去重导入  
  
    - 基本支持简体中文和英文  
  
**后期计划：**  
    - 配置持久化生效  
  
    - 显示扫描进度  
  
    - POC 导出功能  
  
    - 扫描任务暂停功能  
  
  
- Nuclei POC 管理桌面应用，支持模版的增删查改操作  
  
- 支持 Nuclei 扫描、多任务并行扫描  
  
- 查看 Nuclei 模版请求和响应包  
  
- 自定义 Nuclei DNSLOG 服务器  
  
- 自定义扫描速率  
  
- 支持 HTTP 代理（HTTP、HTTPS、SOCKS5）  
  
- 兼容 MacOS、Windows 和 Linux 操作系统  
  
- 使用全新 Nuclei v3 检测引擎  
  
- 兼容 YAMLv2 和 YAMLv3 Nuclei 模版  
  
- 支持主题切换  
  
- 提供多种 Nuclei 模版导入方式  
  
- 支持模版去重导入  
  
- 基本支持简体中文和英文  
  
- 配置持久化生效  
  
- 显示扫描进度  
  
- POC 导出功能  
  
- 扫描任务暂停功能  
  
####   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**快速使用**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
### POC模版保存路径  
### 1. macos  
#### 对于MacOS和Linux，首次打开App会在家目录生成模版文件夹  
```
ls /Users/$USER/.wavely/templates# macos
ls /home/$USER/.wavely/templates# linux
```  
  
**2. Windows**  
  
Wavely.exe 会在同级目录下创建.wavely/templates  
 文件夹，请将 POC 文件放入此文件夹中（需开启隐藏文件/文件夹显示）。  
  
**POC 导入**  
1. 在 App 中导入 POC（支持去重）。  
  
1. 点击“从文件夹导入”按钮，选择 Nuclei POC 文件目录。  
  
####   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llBzWjOaxEz5vmOFF3zcjPGmOrI2JFiblKq05Nf631cxBNoD4YIQkDuYQ/640?wx_fmt=png&from=appmsg "")  
#### 2. 手动导入POC（不带POC去重）  
####   
1. 打开 Wavely，初始化数据库和 POC 配置目录，并将 Nuclei POC 文件复制到以下文件夹中。  
  
1. **MacOS**  
：/Users/$USER/.wavely/templates  
  
1. **Windows**  
：.wavely/templates  
  
1. 打开Wavely  
，进入**设置**  
->**模版**  
->点击**更新按钮图标**  
。  
  
> 注意：首次打开App将初始化数据库和POC保存路径  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llMaaUAp9RChpFPmG741p8LibBWiav2wexdW69h9ibSbnXl9nKkgnH9Gp2g/640?wx_fmt=png&from=appmsg "")  
  
## 功能展示  
  
模版管理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llcr43LWA41zDQC8UAXMSdstqHDxEg1hTKE1YbhhoPbDhELPjORfRXvg/640?wx_fmt=png&from=appmsg "")  
  
扫描任务  
  
选择thinkphp的poc进行扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7ll4GZBcZsdYlK7VnqJu5muMZ7UWicabJIRibubePeI5y8QZdMLSTP5RCCA/640?wx_fmt=png&from=appmsg "")  
  
扫描结果  
  
可复制扫描结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llO4sSPKKCg4ibiaQZicnnqTUexNm5SspSrlvQPaejNbzkklPlpJuj5rpmA/640?wx_fmt=png&from=appmsg "")  
  
编辑nuclie模版  
#### 编辑模版  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llE3Y47BUkRwSneHJR9tpKNEzG7T7ES4aWDOEuETF8hQMDnQHfbHAiceA/640?wx_fmt=png&from=appmsg "")  
  
- 匹配请求包（需扫描匹配POC成功时才可看到请求响应包）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llzdAa6SibBcJbgyhaz6nZ1gictBTIPxtQYeQOByibeiaobqoPy3yyjeqCibA/640?wx_fmt=png&from=appmsg "")  
- 匹配响应包（需扫描匹配POC成功时才可看到请求响应包）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llxc3lXkpiadMb2AriboRics9hZ8Ciabicylm4ACj0zKMqFuejibDB6LdicZ8Zw/640?wx_fmt=png&from=appmsg "")  
#### 添加Nuclei模版  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llJAdAZt4Oob6jsgDhlJjS8AkiagXZjmvdzLCibAu3vFCREdNhYW4wtgcA/640?wx_fmt=png&from=appmsg "")  
####   
### App设置  
### 切换POC编辑器主题  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llI1n9sQFmwmnjns1Z7RbgPGzRc9PicUE0k9TIjD0HHbnQ6VkuwoeIpRA/640?wx_fmt=png&from=appmsg "")  
  
添加HTTP代理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llQUlefudmPoXrrQm4ibKFKuRyvPwOicubyGuibDfN2WzOSOLofRvPtBcHw/640?wx_fmt=png&from=appmsg "")  
  
POC扫描参数设置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7llibsGupiceGY4NS3bibob88cfnyKhBaYtnV7kibKqaibXZhyibDUqFVlG70dg/640?wx_fmt=png&from=appmsg "")  
  
模版导入功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7ll6rn0ekxC4Il508fbsiacvvYz4bEKo30AVWZVSALkI7HdjhT0oNTE9Ow/640?wx_fmt=png&from=appmsg "")  
  
## 常见问题  
#### Windows启动时闪现弹出命令框为正常现象，不影响App的功能Macos 无法打开App由于没有使用apple证书签名app，可能会提示解除安全验证：软件显示禁止符号 或 无法验证软件身份 或 提示已损坏故不能正常打开，请参考：方案1执行如下命令即可：chmod 755 /Users/$USER/Desktop/Wavely_darwin_arm64_1.5.2.app/Contents/MacOS/Wavely方案2sudo xattr -d com.apple.quarantine Applications/Wavely.app  
## POC  
####   
#### 回复:NucleiPOC ，分享Nuclei GUI工具 + 12W+POC  
  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XvnzjMsl2upORiamZRoD7FiaHma0GSO7lluLAoH9RX50feVdovpgMibPJFP3LwarHmrdrXNhdTsqzWEF3Cd2WoJlQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
  
大家对于网络安全感兴趣的话，不妨来加一下我们的老师，我们会定期在给大家分享  
**渗透****工具**  
和  
**实战****文****章**  
，还会有  
**渗透公开课**  
可以试听！  
  
**扫码添加，提升自己，可以关注我，晚上10点进行直播间展示！**  
  
**👇👇👇**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/XvnzjMsl2uqSvZE6x25icBxYJVFOCI9lDasEWqq2rXaaHicvykJsBK94cBdfxibU6fOQ2iaTJ0IKoVMmiaFbIAjJz4A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
后续一些打击犯罪文章会在下方公众号发布  
  
  
  
