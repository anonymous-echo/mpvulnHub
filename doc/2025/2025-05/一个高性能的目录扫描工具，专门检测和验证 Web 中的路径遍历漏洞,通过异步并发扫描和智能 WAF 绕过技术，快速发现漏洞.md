#  一个高性能的目录扫描工具，专门检测和验证 Web 中的路径遍历漏洞,通过异步并发扫描和智能 WAF 绕过技术，快速发现漏洞   
kingjly  无影安全实验室   2025-05-21 10:03  
  
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
  
Directory Traversal Scanner 是一个高性能的目录遍历漏洞扫描工具，专门用于检测和验证 Web 应用程序中的路径遍历漏洞。通过异步并发扫描和智能 WAF 绕过技术，帮助安全研究人员快速发现潜在的安全隐患。## 0x02 工具特点  
- 🚄 异步并发扫描，支持大规模目标检测  
  
- 🛡️ 内置 WAF 绕过技术  
  
- 🎯 智能参数识别和目标提取  
  
- 📊 实时扫描进度展示  
  
- 📝 自动生成详细扫描报告  
  
- 🔄 支持自定义 payload  
  
- 🌈 美观的命令行界面  
  
## 0x03 工具使用  
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
  
  
## 0x04 命令行参数  
```
-u, --urls        目标 URL（必需，支持多个）-d, --depth       最大遍历深度（默认：4）--waf            启用 WAF 绕过技术-c, --concurrency 最大并发请求数（默认：20）-t, --timeout     请求超时时间（默认：5秒）-o, --output      输出报告文件名（默认：scan_report.json）
```  
## 0x05 扫描报告  
  
  
扫描完成后会在 results  
 目录下生成详细的扫描报告，包含：  
- 扫描配置信息  
  
- 目标 URL 列表  
  
- 扫描统计数据  
  
- 发现的漏洞详情  
  
- 完整的扫描命令  
  
  
## 0x06 工具下载  
  
**点****击关注**  
**下方名片****进入公众号**  
  
**回复关键字【250521****】获取**  
**下载链接**  
  
  
  
最后推荐一下内部  
小  
密圈，干货满满，物超所值，**内部圈子每增加100人，价格将上涨20元，越早进越优惠！！！**  
  
****  
