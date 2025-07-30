> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650611086&idx=4&sn=4dc6be3b6793503ac045fc0d6f0219ac

#  Wavely | 高效便捷的图形化Nuclei GUI POC管理工具  
 黑白之道   2025-06-17 01:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
安全工具  
  
  
  
## 0x01 工具介绍  
  
Wavely 是一款专为 Nuclei POC 管理设计的图形化工具，可以方便快捷地对  
Nuclei POC进行增删改查和精准漏洞扫描  
。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGgPn0qrpqWKicDeYcqRSicDrNRs8OEOYUby1lChmsm017OiaZoicybJibKJicA/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic&watermark=1 "")  
## 0x02 主要功能  
  

```
实现对nuclei模板的添加、删除、查询以及修改操作。
兼容MacOS、Windows和Linux操作系统。
实现选择多个POC、多个扫描任务以及多目标的并行扫描功能。
支持自定义DNSLOG服务器，自定义扫描速率，同时支持http代理（http、https、socks5）。
支持查看 POC 匹配到的请求包与响应包。
支持 POC 编辑器的主题切换。
支持nuclei模板一键导入(选择POC文件夹即可导入，可实现nuclei模版去重导入，基于template id)。
支持国际化，已广泛覆盖大部分区域。
支持手动停止扫描任务，便于灵活控制扫描进程。
支持配置持久化，确保用户配置信息持久化保存。
支持 API 扫描，包括带目录扫描（如：http://target.com/api）。
支持图形化生成简单poc，降低 poc 生成门槛。
```

  
## 0x03 工具使用  
  
3.1 注册  
  
依次点击设置 -> 注册，在注册页面按提示获取设备 ID，完成证书申请后上传证书，即可注册成功。  
  
3.2 导入方法  
  
在 App 中导入 POC（具备去重功能）  
- 点击
```
从文件夹中导入POC
```

  
按钮，选择存放
```
nuclei poc
```

  
文件的目录。  
  
- 系统将自动识别并导入所选目录内的所有 POC 文件，导入过程实时显示进度与文件数量，若存在基于 template id 的重复 POC，系统将自动去重，完成后弹窗告知导入结果。  
  
![alt text](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGgz1BFCNtQNG6IfnexQybbFj80GzfSZPYuckgmBB7L2RbJicW1WesevQw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
3.3 创建扫描任务流程  
  
任务发起操作  
- 选择指定POC后，点击顶部扫描按钮即可启动扫描。  
  
- 若未选择 POC，系统将对搜索结果执行全扫描；  
  
- 若已选择 POC，则仅针对所选 POC 进行扫描。  
  
-   
- 此外，点击扫描按钮前，可在任务设置区域自定义扫描速率等参数。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGglgMjjaWxjHQeiasmzuEQyYiag1nvBXmoTebgQHvicT1BOOIIVL4pGOASQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
扫描结果查看  
- 扫描完成后，点击
```
POC ID
```

  
可直接跳转到` POC 编辑界面，方便进一步分析与调整。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGgSPptkw78anZxnRC3xsfIYH9sGhBIicVrc52GNeN5ibKy47rjGIOhQr2g/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
2.4 Nuclei 模版编辑 / 添加操作  
  
编辑poc  
  
##### 查看请求 / 响应包（需检测匹配成功）  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGghGb8nwNe1BcRTMqxE0Le3p3upqibW8Hqico6wicicp0pW1wfUzZjiaNKMgA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
##### 图形化生成 POC  
- **表单形式请求包**  
：通过直观的表单填写方式。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGg1HJsq25dKFGNDCejxVu58UkkDVqpIueRsvgSOibxYzDMiczrTtZEfeUg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
- **raw 格式请求包**  
：支持以 raw 格式编辑和生成请求包。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFER1ldWvdqudtuAyFAibScqGgQHJa024Eh2u5GyXNWatFiasGm1FxF2BNPaoz8C7HHRrF3rIfOyWGicNg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
- **测试功能**  
：生成 POC 后，可点击测试按钮快速验证其有效性。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0fllln5icf8pDd2horQvfT3YzKlkvwy8CU4aprY4Q4nHJlMfZUaDrpM9FO0Z4yFXbbbiaYicp6rX8NIic6ZHQ/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
## 0x04 工具下载  
  
https://github.com/perlh/Wavely  
  
  
> **文章来源：无影安全实验室**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
