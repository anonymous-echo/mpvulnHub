#  一款基于deepseek智能化代码审计工具，支持多语言代码安全分析，帮助开发者快速定位潜在漏洞。   
 黑白之道   2025-04-05 21:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
## 工具介绍  
  
DeepAudit 是一款基于 Python 和 Tkinter 开发的代码审计工具，旨在帮助开发者自动分析项目代码，检测潜在的安全漏洞。该工具通过调用 DeepSeek API，对代码进行深入分析，并将结果以直观的界面展示给用户。同时，支持将漏洞结果导出为 Excel 文档，方便用户进行后续处理。  
## 核心功能  
### 代码审计  
- **多语言支持**  
：PHP、Java、JavaScript、HTML/XML 文件分析  
  
- **智能分块处理**  
：自动拆分大文件进行分段分析  
  
- **漏洞类型检测**  
：SQL注入、XSS、代码执行等常见高危漏洞  
  
- **风险等级评估**  
：高危/中危/低危三级分类  
  
### 可视化界面  
- 项目文件树形浏览  
  
- 代码实时预览与语法高亮  
  
- 漏洞详情展示（风险点/Payload/修复建议）  
  
- 交互式搜索与跳转功能  
  
## 🚀 快速使用  
  
配置API密钥 首次运行会自动生成 config.ini，填入获取的API密钥  
```
python DeepAudit代码审计工具.py
```  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WNwMC4neOqKfA5fg5TQaglmBClV330eG1EOwx6iaHAxh4evlv17JpuWYqvUafmWWRW3lfW4LtBm7g/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 工具获取  
  
  
  
https://github.com/lizhianyuguangming/DeepAudit  
  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
