#  一个高性能的目录扫描工具，专门检测和验证 Web 中的路径遍历漏洞。通过异步并发扫描和智能 WAF 绕过技术，快速发现漏洞，   
kingjly  夜组安全   2025-05-20 00:00  
  
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
  
Directory Traversal Scanner 是一个高性能的目录遍历漏洞扫描工具，专门用于检测和验证 Web 应用程序中的路径遍历漏洞。通过异步并发扫描和智能 WAF 绕过技术，帮助安全研究人员快速发现潜在的安全隐患。  
## ✨ 特点  
- 🚄 异步并发扫描，支持大规模目标检测  
  
- 🛡️ 内置 WAF 绕过技术  
  
- 🎯 智能参数识别和目标提取  
  
- 📊 实时扫描进度展示  
  
- 📝 自动生成详细扫描报告  
  
- 🔄 支持自定义 payload  
  
- 🌈 美观的命令行界面  
  
## 🚀 快速开始  
### 先决条件  
- Python 3.8 或更高版本  
  
- pip 包管理器  
  
### 📦 安装  
```
# 克隆仓库git clone https://github.com/yourusername/directory-traversal-scanner.git# 进入项目目录cd directory-traversal-scanner# 安装依赖pip install -r requirements.txt
```  
### 🎮 基本使用  
```
# 扫描单个 URLpython scanner.py -u "http://example.com/page.php?file=test.txt"# 扫描多个 URL，启用 WAF 绕过python scanner.py -u "http://example1.com" "http://example2.com" --waf# 自定义并发数和超时时间python scanner.py -u "http://example.com" -c 200 -t 10
```  
## 📋 命令行参数  
```
-u, --urls        目标 URL（必需，支持多个）-d, --depth       最大遍历深度（默认：4）--waf            启用 WAF 绕过技术-c, --concurrency 最大并发请求数（默认：20）-t, --timeout     请求超时时间（默认：5秒）-o, --output      输出报告文件名（默认：scan_report.json）
```  
## 📊 扫描报告  
  
扫描完成后会在 results  
 目录下生成详细的扫描报告，包含：  
- 扫描配置信息  
  
- 目标 URL 列表  
  
- 扫描统计数据  
  
- 发现的漏洞详情  
  
- 完整的扫描命令  
  
  
  
## 工具获取  
  
  
  
点击关注下方名片  
进入公众号  
  
回复关键字【  
250520  
】获取  
下载链接  
  
  
  
## 往期精彩  
  
  
往期推荐  
  
[一个用于快速启动和管理各类工具的图形化工具箱，支持多种类型工具的统一管理和快速启动。](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494309&idx=1&sn=339af57de54f23f795531f8e1238e984&chksm=c36bae5df41c274b3f91f3bb1020c34b484e72bea4ef29c720dc484fd359ed2b3210264bb86a&scene=21#wechat_redirect)  
  
  
[水滴工具箱，各类开源的渗透工具，web扫描,抓包,免杀等等](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494308&idx=1&sn=497298181e4ff3e47bb0112d7bdcf878&chksm=c36bae5cf41c274a59a72b76935bd8e35ee570a5ae8bb513aea16956d1f69e37d3683c3a0e39&scene=21#wechat_redirect)  
  
  
[基于大语言模型的网络安全智能助手，通过自然语言交互，帮助用户执行渗透测试任务、查询安全信息、分析流量包等。](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494292&idx=1&sn=0c257b536c5fa421f536136ae335e4af&chksm=c36bae6cf41c277ae7f47ae0b0b1a63af0d996124365b350804d9735059f4a1d5529b087734c&scene=21#wechat_redirect)  
  
  
[渗透攻防各方位资源库](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494291&idx=1&sn=cbb08aa685dbf279249f10c99949e9e9&chksm=c36bae6bf41c277da9a425cc971ea8d0b0f382f074a54d5ef2d4716fbadba9f1a034601e7307&scene=21#wechat_redirect)  
  
  
[年轻人的第一款应急响应工具](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494276&idx=1&sn=ad0d2b0ea7b12d60ac7120b0d1b7163f&chksm=c36bae7cf41c276ad8f825652b07420b28069155ad00d1886d8de31350fec943f787f3de1533&scene=21#wechat_redirect)  
  
  
