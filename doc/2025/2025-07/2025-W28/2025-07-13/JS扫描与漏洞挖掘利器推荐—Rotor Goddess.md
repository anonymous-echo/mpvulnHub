> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2NTk4MTE1MQ==&mid=2247487565&idx=1&sn=1f8f19fa59f52f8098ffe19d836e1b57

#  JS扫描与漏洞挖掘利器推荐—Rotor Goddess  
雪山乘客  TtTeam   2025-07-13 14:24  
  
## 工具介绍  
  
**在网络安全领域，信息收集与漏洞挖掘如同在黑暗中寻找潜藏的危险，传统工具常因速度迟缓、路径挖掘局限、分析过程繁琐，令安全从业者举步维艰。而一款名为 “转子女神” 的创新工具，正凭借其独特优势，为该领域带来新的曙光。**  
  
**Github地址 ：**  
  
https://github.com/Snow-Mountain-Passengers/Rotor-Goddess  
## 功能简介  
- **智能路径勘探**  
：通过精准的正则匹配，快速扫描并提取网页中的敏感路径和接口，自动拼接动态变量（如“/” + x + “/user/admin”），确保数据全面且准确。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd5E2KQszX9yRiajsLUh6dGibDerbZLicuVSZ4fFl31NDKMYkPjZfIqR12fA/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
- **JS深度分析**  
：自动扫描JS文件，提取隐藏的API接口和参数，结合AI风险评估，挖掘潜在漏洞，如SQL注入、未授权访问等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd5TCpYFffq7JcpreUsvv7QPJsrOssnHUEHXgjIF1IKJ8ic62L7VF8BicZg/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
- **高效爬虫与响应分析**  
：支持批量URL扫描，自动抓取响应状态、页面长度及ico hash值，并生成黑暗引擎查询语法，提升效率。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd5LD2Sa7FUdE5VKCzYVmNX8gxoRprOwIiaeiaDnstuk93EVyRb6pYIAOlw/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
- **灵活配置与扩展**  
：提供自定义拼接规则（--url）、证书绕过（--cer）、超时设置（--time）及请求头配置，适配复杂场景。  
  
- **AI驱动的漏洞提示**  
：通过AI对话机制，分析JS代码中的潜在风险，智能推荐漏洞测试方向，如ID fuzzing或鉴权问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd5ve3PibeuIqicoda6IElaFGicUkYcuClKjukVZ6u5pBJckpmZW3QVy8zyQ/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
- **日志与结果管理**  
：自动记录扫描URL及参数，生成详细日志，方便后续分析与复查，输出结果直观清晰。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd5sfWibx2mCYk7BKwNiaN58guJbXZlUwg5m9rB07ibhaSUe9DU6sLG12RMQ/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd50qv8zC8E0LeYOyNBQwlEqzwlMHwRw47hjHQgHEkCK7nKHJ1ibTvZwxw/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd5lJTkFib1twZS1LV1AX4bad4VsTuxmNpy0DpQ8SRfBsBaWdiaR0utf25g/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
- **批量处理与自动化**  
：支持批量URL文件扫描，结合AI自动化问话机制，减少手动操作，提升大规模测试效率。  
  
- **用户友好体验**  
：工具操作简单，扫描结果一目了然，几分钟即可完成复杂信息收集，适合挂后台运行，效率极高。  
  
## 使用介绍  
  
📦用法  
  
**绕过证书验证（--cer）**  
 在URL后添加
```
--cer
```

  
参数，即可绕过SSL证书验证，适用于目标站点证书不信任的场景。**示例**  
：  

```
roorgoddess --url https://example.com --cer

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd5J9ygu5kD0pnibCU552HqDEnoSVWicwt2VeiakSjJXJB8QKGSoPicFBZe4w/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
  
**自定义URL拼接（--url）**  
 对于需要特定拼接规则的站点（如
```
/#/
```

  
路径），使用
```
--url
```

  
参数自定义拼接逻辑，确保路径请求准确无误。**示例**  
：  

```
roorgoddess --url https://example.com/#/

```

  
工具将根据指定规则拼接路径并返回正确响应。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd5FekLXtln9YibiaGD702CAz0JwUEC1aU7W5FvWWnsMRxCQ3gMibKgVI6Iw/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
  
**设置请求超时（--time）**  
 通过
```
--time=x
```

  
设置请求超时时间（单位：秒），避免因目标站点响应过慢导致扫描卡顿。**示例**  
：  

```
roorgoddess --url https://example.com --time=5

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RUC00e0HO0icib8r6tnpAdpd55mrC09HNJbMLPSY8TjeWT8ZMCLEC0PjuB2l0gbGNprLd8FUjmCGXCQ/640?wx_fmt=png&from=appmsg "")  
  
AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
  
**批量URL扫描（url_batch）**  
 支持批量扫描多个URL，只需将目标URL列表保存为
```
.txt
```

  
文件，每行一个URL，然后运行工具即可自动扫描，无需逐个手动输入。**示例**  
：  
  
创建
```
urls.txt
```

  
，内容如下：  

```
https://example1.com
https://example2.com

```

  
运行命令：  

```
roorgoddess --url_batch urls.txt

```

  
**自定义请求头（headers）**  
 支持自定义HTTP请求头，修改User-Agent、Cookie等信息，适配复杂场景。格式保持标准，仅需更新对应字段数据。**示例**  
：  

```
roorgoddess --url https://example.com --headers &#34;User-Agent: Mozilla/5.0&#34;

```

  
**AI问话设置**  
 工具支持自定义AI问话机制，用于优化JS代码分析和漏洞提示。用户可修改AI问话模板，但需注意避免破坏路径提取功能。若删除问话配置，工具会自动生成默认问话机制。**示例**  
：修改AI问话模板后，运行  

```
roorgoddess --url https://example.com

```

  
以应用新设置。  
  
