> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NzUyNTI1Nw==&mid=2247497408&idx=1&sn=209bb5f44c48b649457172d487e57354

#  Linux应急响应工具集【Html可视化报告】  
Rabb1tQ  无影安全实验室   2025-06-18 13:03  
  
免责声明：  
本篇文章仅用于技术交流，  
请勿利用文章内的相关技术从事非法测试  
，  
由于传播、利用本公众号无影安全  
实验室所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号无影安全实验室及作者不为此承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把"**无影安全实验室**  
"设为星标，这样更新文章也能第一时间推送！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3GHDOauYyUGbiaHXGx1ib5UxkKzSNtpMzY5tbbGdibG7icBSxlH783x1YTF0icAv8MWrmanB4u5qjyKfmYo1dDf7YbA/640?&wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
安全工具  
  
  
  
## 0x01 工具介绍  
  
Linux应急响应工具集，这是一个用于Linux系统安全应急响应的工具集，包含一键式信息收集脚本和可视化报告查看器。该工具集能够快速收集系统安全相关信息，并通过基于规则的分析引擎对收集到的信息进行安全风险评估。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2XEhDYic02PsU3ibvkSIgMx2jDk1DOt8QzBsBia5AXRmqicmrxBdpgVDCrSXDenIg06WDDYNkyzjY8JnQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
## 0x02 功能特性  
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
  
## 0x03 使用方法  
### 1. 信息收集  

```
# 以root权限运行脚本
sudo bash emergency_response.sh

```

  
脚本会在当前目录生成格式如 
```
emergency_report_YYYYMMDD_HHMMSS.txt
```

  
 的报告文件。  
### 2. 查看报告  
1. 打开 
```
emergency_report_viewer.html
```

  
  
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
  
  
## 0x04 工具下载  
  
**点****击关注**  
**下方名片****进入公众号**  
  
**回复关键字【250618****】获取**  
**下载链接**  
  
  
  
最后推荐一下内部  
小  
密圈，干货满满，物超所值，**内部圈子每增加100人，价格将上涨20元，越早进越优惠！！！**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/awCdqJkJFETPiaqyHHBiaBXpf6mgUgP9xyic4Rox2duP5iaYRhTfMBDS0ibhUE1Hy7vW0icmpzictRicAUhYxRxIk6kTUw/640?wx_fmt=jpeg&from=appmsg "")  
  
