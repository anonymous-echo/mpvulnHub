#  Linux应急响应工具集【Html可视化报告】  
Rabb1tQ  夜组安全   2025-06-13 00:01  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WrOMH4AFgkSfEFMOvvFuVKmDYdQjwJ9ekMm4jiasmWhBicHJngFY1USGOZfd3Xg4k3iamUOT5DcodvA/640?wx_fmt=png&from=appmsg "")  
  
## 工具介绍  
  
Linux应急响应工具集，这是一个用于Linux系统安全应急响应的工具集，包含一键式信息收集脚本和可视化报告查看器。该工具集能够快速收集系统安全相关信息，并通过基于规则的分析引擎对收集到的信息进行安全风险评估。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2XEhDYic02PsU3ibvkSIgMx2jlNeY1Vje7nQhfkAJOZDSQRX4DVN8BvlSAgpW3Ds2RCbiaXZ3nO4iclkw/640?wx_fmt=png&from=appmsg "")  
## 功能特性  
### 1. 信息收集脚本 (emergency_response.sh)  
- **系统后门排查**  
  
- UID为0的非root用户检测  
  
- 可疑系统配置检查  
  
- 异常系统文件检测  
  
- **用户与登录检查**  
  
- 当前用户信息  
  
- 所有用户列表  
  
- 最近登录记录  
  
- 登录失败记录  
  
- **日志分析**  
  
- 系统日志错误  
  
- 安全日志错误  
  
- **网络检查**  
  
- 监听端口  
  
- 活动连接  
  
- 网络配置  
  
- 路由表  
  
- 可疑连接  
  
- **进程检查**  
  
- 高CPU占用进程  
  
- 可疑脚本进程  
  
- **文件系统检查**  
  
- SUID文件  
  
- 最近修改的文件  
  
- **软件包检查**  
  
- 已安装软件包列表  
  
- **持久化检查**  
  
- 自启动服务  
  
- 计划任务  
  
- SSH公钥  
  
- 启动项配置  
  
- **系统完整性**  
  
- 关键二进制文件校验  
  
- 系统文件完整性  
  
- **恶意进程与提权点**  
  
- 可疑进程  
  
- 可疑提权点  
  
- 隐藏文件  
  
### 2. 报告查看器 (emergency_report_viewer.html)  
- 分类展示收集的信息  
  
- 实时搜索功能  
  
- 告警信息分级展示（高、中、低）  
  
- 告警定位与跳转  
  
- 支持文本和JSON格式报告  
  
### 3. 规则引擎  
  
基于YAML的规则配置系统，包含多个规则集：  
- 后门检测规则  
  
- 网络异常规则  
  
- 持久化检测规则  
  
- 进程异常规则  
  
- 系统异常规则  
  
- 日志分析规则  
  
- 文件系统规则  
  
## 使用方法  
### 1. 信息收集  
```
# 以root权限运行脚本sudo bash emergency_response.sh
```  
  
脚本会在当前目录生成格式如 emergency_report_YYYYMMDD_HHMMSS.txt  
 的报告文件。  
### 2. 查看报告  
1. 打开 emergency_report_viewer.html  
  
1. 点击"选择文件"按钮，选择生成的报告文件  
  
1. 点击"分析报告"按钮开始分析  
  
1. 使用界面功能查看详细信息：  
  
1. 使用搜索功能查找特定内容  
  
1. 查看右侧告警面板的分析结果  
  
1. 点击告警可跳转到对应位置  
  
### 系统要求  
- 操作系统：支持主流Linux发行版（Ubuntu、Debian、CentOS等）  
  
- 权限要求：需要root权限  
  
- 浏览器要求：支持现代浏览器（Chrome、Firefox、Edge等）  
  
### 注意事项  
1. 脚本需要root权限才能收集完整信息  
  
1. 部分命令在不同发行版中可能不可用，脚本会自动跳过  
  
1. 报告查看器需要现代浏览器支持  
  
1. 建议定期更新规则库以适应新的安全威胁  
  
  
  
## 工具获取  
  
  
  
点击关注下方名片  
进入公众号  
  
回复关键字【  
250613  
】获取  
下载链接  
  
  
## 往期精彩  
  
  
往期推荐  
  
[DNSLog 平台克隆版（自定义域名支持）便于内网渗透测试与痕迹收集，同时绕过部分安全设备对 dnslog.cn 的拦截。](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494508&idx=1&sn=6a4f330108bb15eb8f7902427b22ad03&chksm=c36baf94f41c26828c153652e1c02234c53233c697a0b6b5b73dba6fc76474a152ffc73c027d&scene=21#wechat_redirect)  
  
  
[社会工程学密码生成器APP，利用个人信息生成密码的工具](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494507&idx=1&sn=d31a49fbc2febe095fb78304a35dbc6d&chksm=c36baf93f41c2685aafd12b6b2ff239b1b8ba5b43b8af5e98a3e2bd7280d7edc825c59d68203&scene=21#wechat_redirect)  
  
  
[后渗透信息/密码/凭证收集工具](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494483&idx=1&sn=8d58bd631fc216aa23299dc03216381f&chksm=c36bafabf41c26bdcb7b7048a5a8144105cc2290c459d0329273221b74eb76d444fa87347f50&scene=21#wechat_redirect)  
  
  
[Mitmproxy GUI用于解决渗透测试加解密难题，让你的burp像测试明文这么简单 更新v1.0.2](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494478&idx=1&sn=77dff746a51379718bcb3bf80e9219e2&chksm=c36bafb6f41c26a0fab3c14abdd7ca202823a23d0ed0ef7e198f70893b183d9dc85959ec6588&scene=21#wechat_redirect)  
  
  
[phpmyadmin 弱口令探测工具](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494477&idx=1&sn=acecaa45e35b79c1ae31bcbb181a3eba&chksm=c36bafb5f41c26a345a4417ee5cfa9f87f419205ab400654f8826d22552e99729ae7c085f10f&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557&tp=webp "")  
  
