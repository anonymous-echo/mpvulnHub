> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxOTUyNTg2MA==&mid=2247483982&idx=1&sn=a506515361c892f7d439c4fe16467aa6

#  【淮橘AI代码审计工具v2.0】规则+AI双引擎，让漏洞无处遁形  
原创 淮橘安全  淮橘安全   2025-06-25 04:33  
  
# 声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，淮橘安全及文章作者不为此承担任何责任。  
  
  
现在只对常读和星标的公众号才展示大图推送，建议大家能把  
“  
**设为星标**  
”，  
否则可能就看不到了啦  
！公众号会经常分享一些0day，1day，工具供大家学习  
  
  
**0x01 简介**  
  
  
在代码安全审计领域，开发者和安全工程师长期面临两大痛点：**规则扫描漏报率高**  
，而**人工审计效率低下**  
。今天正式开源的淮橘AI代码审计工具v2.0，创新性地融合规则引擎与AI大模型能力，彻底颠覆传统审计模式！  
  
淮橘AI代码审计工具，是一款本身内置强大审计规则，并且可以使用本地ollama模型或者使用deepseek，openai等ai大模型的api去调用辅助审计的工具，旨在帮助开发者自动分析项目代码，检测潜在的安全漏洞。  
  
工具下载链接在文末  
  
  
**0x02 工具详情**  
### 核心功能亮点  
#### 1. 双引擎智能扫描  
- **规则审计引擎**  
：内置11大类漏洞规则库，覆盖SQL注入、命令执行等常见漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WZPkMIkCagQ7YVzJc40opXqnMxsvvC4oicJOgvygQDZkHb4oT8ekYszs5XibRBja4fAyxEqQhEZoG7aA6QcECasw/640?wx_fmt=png&from=appmsg "")  
- **AI智能引擎**  
：  
  
- 本地模型：支持Ollama本地大模型  
  
- 云端API：集成OpenAI/DeepSeek/Gemini/Claude  
  
- 智能代码摘要生成技术  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WZPkMIkCagQ7YVzJc40opXqnMxsvvC4oCFmPnKQO38gXZa8ztgM3p0Cfc6pqzorwCVMP8cIouHbI1BfJxhQZHg/640?wx_fmt=png&from=appmsg "")  
  
#### 2. 智能文件识别系统  
- 三重识别机制确保文件类型判断准确率超99%  
  
- 扩展名识别（.jsp/.php等）  
  
- MIME类型识别（magic库）  
  
- 内容启发式识别（PHP/JSP特征匹配）  
  
#### 3. 漏洞闭环管理  
- **漏洞验证**  
：右键菜单一键启动AI复查  
  
- **漏洞细节**  
：自动生成漏洞验证方案  
  
- **结果导出**  
：支持JSON/CSV/TXT格式  
  
- **书签导航**  
：快速定位漏洞代码位置  
  
#### 4. 可视化作战大屏  
- 实时漏洞统计仪表盘  
  
- 多主题切换（深色/浅蓝/绿色）  
  
- 四窗格专业布局：  
  
### 工具使用演示  
  
**双击打开即可**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WZPkMIkCagQ7YVzJc40opXqnMxsvvC4o8J3icKHTfOXy4tDCu9XKVl3GGGhsB6uxGluh0lDichDLhXjCTwxl9Pqg/640?wx_fmt=png&from=appmsg "")  
  
**结果处置**  
：  
1. 双击漏洞跳转代码  
  
1. 右键生成POC方案  
  
1. 导出审计报告  
  
### 技术栈揭秘  
- **前端框架**  
：PyQt5 + QTreeWidget + QSplitter  
  
- **AI集成**  
：Ollama API + OpenAI/ChatGPT  
  
- **规则引擎**  
：Re正则匹配+漏洞特征库  
  
- **智能调度**  
：concurrent.futures线程池  
  
**0x03 项目下载链接**  
  
关注公众号回复  
250625获取  
  
  
  
****  
  
  
