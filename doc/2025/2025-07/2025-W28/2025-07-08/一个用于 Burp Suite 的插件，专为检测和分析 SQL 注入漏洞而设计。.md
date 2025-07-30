> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMzMyNzMyMA==&mid=2247573910&idx=2&sn=ca0beb1967b43d9d39bca8eeb7715732

#  一个用于 Burp Suite 的插件，专为检测和分析 SQL 注入漏洞而设计。  
点击关注👉  马哥网络安全   2025-07-08 09:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAk1nlByTOFiahZKGHekfZGC1V0p6QaXc4CnbPBMZQuFGAnW00CX43Xk9JXONUTxeqYxActf31UiajMg/640?wx_fmt=png&from=appmsg "")  
  
## 工具介绍  
  
SQL Injection Scout 是一个用于 Burp Suite 的扩展，专为帮助安全研究人员和开发人员检测和分析 SQL 注入漏洞而设计。该扩展提供了丰富的配置选项和直观的用户界面，便于用户自定义扫描和分析过程。  
## 💯 功能特性  
- **被动检测SQL**  
：支持对除
```
OPTIONS
```

  
外的所有请求的参数进行 
```
FUZZ
```

  
 测试，支持 
```
XML
```

  
、
```
JSON
```

  
、
```
FORM
```

  
等表单数据格式。  
  
- **最小化探测**  
：通过最小化的 
```
payload
```

  
 探测，减少对目标的影响。  
  
- **响应差异分析**  
：对响应进行 
```
diff
```

  
 分析，自动标记无趣（灰色）和有趣（绿色）的响应。  
  
- ....  
  
- **判断原理**  
：假设页面参数为反射类型，通过比较 
```
payload
```

  
 和 
```
diff
```

  
 的长度，相同则认为无趣。  
  
- **重复内容过滤**  
：对绿色标记的分组进行进一步分析，出现
```
6
```

  
次以上重复的 
```
diff
```

  
 被标记为无趣。  
  
- **结果排序**  
：根据颜色对最终结果进行排序展示。  
  
- **✅：标记为值得进一步分析的响应。**  
  
- **🔥：标记为存在Sql注入**  
  
- **Error：标记为检测到SQL Error信息存在Response中**  
  
- **Max Params：标记为请求参数大于配置数**  
  
- **Skip URL：匹配配置中需绕过的URL**  
  
-   
- **自动匹配**  
：在扫描页面的响应中自动匹配 
```
diff
```

  
 结果，默认取第一处的差异。  
  
- **正则匹配**  
：正则匹配无需扫描的
```
URL
```

  
  
- **内置范围**  
：支持内置的 
```
scope
```

  
 范围设置。  
  
- **延时扫描**  
：支持固定抖动+随机抖动发包检测，更精准规避 
```
WAF
```

  
。  
  
- **自定义扫描参数数量**  
：防止参数过多导致的性能问题或误报，默认
```
50
```

  
  
- **🔥 Fuzz隐藏参数SQL注入**  
: 支持用户在原始请求中追加隐藏参数列表，进行
```
FUZZ
```

  
测试  
  
- 在
```
Site map
```

  
/
```
HTTP history
```

  
/
```
Logger
```

  
面板添加右键菜单，支持检测站点**单个**  
与**所有**  
请求  
  
- （搭配CaA使用本插件的
```
Fuzz Params List
```

  
功能）  
  
## ✅️ 安装  
1. 确保已安装 Burp Suite。  
  
1. 下载或克隆此项目到本地:  
  

```
   git clone  https://github.com/JaveleyQAQ/SQL-Injection-Scout.git

```

1. 使用 Gradle 构建项目：  
  

```
   cd SQL-Injection-Scout
   ./gradlew shadowJar

```

1. 在 
```
Burp Suite
```

  
 中加载生成的 
```
JAR
```

  
 文件：  
  
1. 打开 
```
Burp Suite
```

  
，导航到 
```
Extender
```

  
 -> 
```
Extensions
```

  
。  
  
1. 点击 
```
Add
```

  
 按钮，选择生成的 
```
JAR
```

  
 文件（位于 
```
build/libs
```

  
 目录下）。  
  
## 🥰  使用指南  
1. 启动 Burp Suite 并确保 SQL Injection Scout 扩展已加载。  
  
1. 在 
```
Extender
```

  
 选项卡中，找到 SQL Injection Scout 并打开其配置面板。  
  
1. 根据需要调整参数和模式设置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UoMfH0BInAJyGYB6oXJvzPFFEemicNOax6rVtaxezdMcDuD49BZgJhnluX2yfv30JZSibxp0vdMe0A/640?wx_fmt=png&from=appmsg&watermark=1 "")  
1. 使用 Burp Suite 的代理、扫描器等功能进行测试，SQL Injection Scout 将自动应用配置并提供结果。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UoMfH0BInAJyGYB6oXJvzP0zLBpEIINtqN9jDUYHibb04cPYkpTZFib5qd7uZV1jicMG5vTyRhAoIicg/640?wx_fmt=png&from=appmsg&watermark=1 "")  
  
  
文章转自夜组安全，侵删  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/c8mTq8UGcvM0O1nf88S0kYk2Ew2rJkORTISWF6KWULcibXibwcAOoY07QP57wXgaLoU6olFZlC3abMNP6uxRlYgA/640?wx_fmt=gif&from=appmsg "")  
  
  
今日阅读福利  
  
为了更多师傅们能学好网络安全，我会不定时的寻找各类学习资源，免费分享给大家。  
  
今天分享一份 渗透测试 笔记，一共355页。这次的**图文并茂，也很实用**  
。不需要转发，只需文末扫码即可直接免费领到。  
  
下面是 部分的PDF截屏，**内容详实，真的不错：**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAlC3wUCbBr0e6WeOZxy5XvcrpvDbRsMvVRRtTUpicRwVgYSOmwDNLU9YNEpgfKsSc1HTUQaykxTDnw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAlC3wUCbBr0e6WeOZxy5XvcD8RLCly0HzDkqW7A6PrBDibz4ias8kIh4blQ50HYibYjicNS54eScdUD6g/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
笔记源自网络，仅用于免费交流分享，版权归原作者所有，如有侵权请联系删除  
  
需要的朋友扫描下方二维码，备注：【355页渗透测试笔记】，免费领取  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkwcjtOtVXODCkPibWO4Py9FP1ESE26vHHMLwfyYA6zWj96VL7AsPYcyvHL43536JMIDNWibIdicAjRw/640?wx_fmt=png&from=appmsg "")  
  
  
