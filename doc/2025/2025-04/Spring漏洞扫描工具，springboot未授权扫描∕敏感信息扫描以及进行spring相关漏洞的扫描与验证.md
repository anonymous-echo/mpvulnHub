#  Spring漏洞扫描工具，springboot未授权扫描/敏感信息扫描以及进行spring相关漏洞的扫描与验证   
 黑白之道   2025-04-24 01:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
## 一、工具概述  
  
**SBSCAN是一款专注于spring框架的渗透测试工具，可以对指定站点进行springboot未授权扫描/敏感信息扫描以及进行spring相关漏洞的扫描与验证。**  
- **最全的敏感路径字典**  
：最全的springboot站点敏感路径字典，帮你全面检测站点是否存在敏感信息泄漏  
  
- **支持指纹检测**  
：  
  
- 支持spring站点指纹匹配：支持启用指纹识别，只有存在spring指纹的站点才进行下一步扫描，节约资源与时间 (无特征的站点会漏报，客官自行决策是否启用)  
  
- 支持敏感路径页面关键词指纹匹配：通过维护敏感路径包含的关键词特征，对检出的页面进行指纹匹配，大大提升了工具检出的准确率，减少了人工去确认敏感页面真实性投入的时间  
  
- **支持指定模块发起检测：**  
 不想跑漏洞，只想检测敏感路径？ 或者只想检测漏洞？ 都可以，通过 -m  
 参数指定即可  
  
- **最全的spring漏洞检测POC：**  
 spring相关cve漏洞的检测poc全部给你集成到这款工具里，同类型最全  
  
- **无回显漏洞解决：**  
 无回显漏洞检测扫描器光看响应状态码不太靠谱？支持--dnslog参数指定dnslog域名，看到dnslog记录才是真的成功验证漏洞存在  
  
- **降噪输出结果：**  
 可通过指定-q  
参数只显示成功的检测结果  
  
- **友好的可扩展性：**  
 项目设计初期就考虑了用户的自定义扩展需求，整个项目尽量采用高内聚低耦合模块化的编程方式， 你可轻松的加上自己的poc、日常积累的敏感路径、绕过语句，轻松优化检测逻辑，具体见下文的“自定义扩展”  
  
- **其他一些常规支持**  
：单个url扫描/ url文件扫描 / 扫描模块选择 / 支持指定代理 / 支持多线程 / 扫描报告生成  
  
## 工具使用  
>   
> 检测效果图, 使用彩色表格打印更直观显示检测结果，**检测报告**  
保存位置将会在扫描结束后控制台显示  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2VB2vpRwsDLT60uDYG4ibL8iaiczHVF1zKah8QH6xwodOdaq1ialu28VcJFQWf713Kh8OkPloic5qIiaqyg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
>   
> **检测时**  
可使用 tail -f logs/sbscan.log  
 实时查看详细的检测情况  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2VB2vpRwsDLT60uDYG4ibL8iaB4PcIukia3yRlIhpur2Sq9GjH28DqyfvyncVC4ptXvOPA70JleguRVQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
```
## 🧾 已支持检测CVE列表- CVE-2018-1273- CVE-2019-3799- CVE-2020-5410- CVE-2022-22947- CVE-2022-22963- CVE-2022-22965- JeeSpringCloud_2023_uploadfile
```  
  
  
## 工具获取  
  
  
  
https://github.com/WuliRuler/SBSCAN/tree/master  
  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
