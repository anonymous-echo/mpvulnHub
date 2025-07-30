#  Nuclei|图形化|轻量化刷漏洞神器|11000+poc   
海底天上月  海底生残月   2024-12-11 06:29  
  
# 声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，海底生残月及文章作者不为此承担任何责任。  
  
现在只对常读和星标的公众号才展示大图推送，建议大家能把  
**海底生残月**  
“  
**设为星标**  
”，  
否则可能就看不到了啦  
！  
  
**0x01 简介**  
  
Nuclei用于根据模板在目标之间发送请求，从而实现零误报并在大量主机上提供快速扫描。Nuclei提供对各种协议的扫描，包括Tcp、DNS、HTTP、SSL、File、Whois、Websocket、Headless等。凭借强大且灵活的模板，Nuclei可用于对各种安全检查进行建模。  
  
支撑系统托盘  
  
支助项目管理  
  
支持配置管理  
  
支持模板管理  
  
支持模板编辑  
  
支持国际化，默认zh_CN  
  
支持多网络空间引擎接口搜索(fofa,Hunter)  
  
**0x02 软件及工具介绍**  
## 菜单栏¶  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaJHT0gSaggya6Hib2b9iaiaf14tj9ibuASmUicnm8kcZuvWWycMcEabFTNnjJXJOKQfqhmKuqhCCG6KZ4g/640?wx_fmt=png&from=appmsg "")  
## 工具栏¶  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaJHT0gSaggya6Hib2b9iaiaf14VmUfw26WhIr9hiaOUUia7J0Wu5XyIDcreNrdBfJJFKIIPWfZVb6ravjA/640?wx_fmt=png&from=appmsg "")  
  
从左往右依次为：  
- 新建终端或者右键选择终端，执行当前活动配置  
  
- run only new templates added in latest nuclei-templates release  
  
- automatic web scan using wappalyzer technology detection to tags mapping  
  
- 右键选择自定义分组的模板，执行当前活动配置  
  
- 保存当前项目的所有执行配置  
  
- 右键选择配置当前活动配置（本工具支持多配置管理，活动配置为当前默认执行的配置）  
  
## 模板管理¶  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaJHT0gSaggya6Hib2b9iaiaf14bg0wZmVoKUiaYDlUcbSR7G0jDyicybY8afqN26bYu1XZxSyoK7TfXcOw/640?wx_fmt=png&from=appmsg "")  
  
模板管理面板主要有三块：  
- 工具栏，实现了模板危险等级的过滤筛选以及关键字搜索功能  
  
- 模板表格，列出了模板的基本信息  
  
- 右键菜单，实现模板的各种应用、配置和管理  
  
## 目标管理¶  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaJHT0gSaggya6Hib2b9iaiaf14IibibeqVgLY6GqRbmxtHgfYD9uwIJOC4WGgVF6DNAWOJdiaNv8OWoEWjQ/640?wx_fmt=png&from=appmsg "")  
  
这里实现了目标从文件中的加载和保存。  
## 配置管理¶  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaJHT0gSaggya6Hib2b9iaiaf14SoDKUAGaBl3kMVYg0ic0Q1DDnj7HENzEmonEM1nXfptoGNWQ6AK1EUw/640?wx_fmt=png&from=appmsg "")  
  
配置管理提供了多配置管理的能力，点击  
 加号  
   
图标可以新增配置，每个配置主要有三块内容：  
- template  
   
配置，可在模板管理面板中右键追加配置  
  
- workflow  
   
配置，可在模板管理面板中右键追加配置  
  
- 还有除此之外的  
 nuclei  
   
配置，这里不再配置  
 template  
   
和  
 workflow  
  
## 运行终端¶  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaJHT0gSaggya6Hib2b9iaiaf141CajcBkicicUe0xcj9uVibNhuYdqFtu7EXjKv1sYiav8W2pP2G019AOqZA/640?wx_fmt=png&from=appmsg "")  
  
工具内置了终端，用于执行验证和其他命令（在  
 bin  
   
目录下的二进制命令工具）  
- 点击  
 加号  
   
新增终端  
  
- 可以刷新终端  
  
- 终端自动加载  
 bin  
   
目录到  
 PATH  
   
环境变量中  
  
## 网络空间搜索引擎¶  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaJHT0gSaggya6Hib2b9iaiaf14cSW16pIJHpqBvyG8S1sQpQgpxYPZJ1KTakcuNsaDfyiaaCkmnTTibZ1g/640?wx_fmt=png&from=appmsg "")  
  
目前内置了两款网络空间搜索引擎：Fofa  
   
和  
 Hunter  
  
右键菜单功能：  
- 浏览器打开目标  
  
- 追加到待测试的全局目标面板  
  
- 直接使用自定义分组的模板对选中的目标进行测试  
  
## 模板编辑¶  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaJHT0gSaggya6Hib2b9iaiaf14o3uN4B5NpF79Vbkickn4Ejxvc3sorHK7mJWWm2AsoWPW4kibxQ9M85ww/640?wx_fmt=png&from=appmsg "")  
  
具有新增、编辑、保存、另存以及测试调试功能。  
  
POC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fYSUHibFMoaJHT0gSaggya6Hib2b9iaiaf14ABwjs7VUMPHPIianpI2N4PekJxzbttYC173wQr6lGy9FricOFwuqeJIA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【nuclei-gui**  
**】获取工具****下载链接**  
  
**回复关键字【**  
nuclei-templates  
**】获取工具****下载链接**  
  
  
  
  
