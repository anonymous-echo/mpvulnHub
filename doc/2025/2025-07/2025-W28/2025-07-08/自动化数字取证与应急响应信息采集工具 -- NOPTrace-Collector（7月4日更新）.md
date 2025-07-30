> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4MDQ5MjY1Mg==&mid=2247516956&idx=1&sn=acf928132fa0a1f41f1ebd1882938baa

#  自动化数字取证与应急响应信息采集工具 -- NOPTrace-Collector（7月4日更新）  
Hack-For-Fun  Web安全工具库   2025-07-08 01:56  
  
哎呦 资料合集  
  
链接：https://pan.quark.cn/s/770d9387db5f  
  
===================================  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，  
安全性自测  
，  
大家都要把工具当做病毒对待，在虚拟机运行。  
如有侵权请联系删除。个人微信：  
ivu123ivu  
  
  
**0x01 工具介绍**  
  
NOPTrace-Collector 是基于 OpenForensicRules 标准化数字取证与应急响应信息采集规则格式规范开发的采集器。该项目采用 Go 语言开发，具有跨平台兼容性，支持 Windows、Linux 和 macOS 系统。  
  
**0x02 安装与使用**  
  
1. 默认配置加载  
  
直接执行二进制程序会自动加载执行目录同级的 configs 目录下的所有配置文件，包括子目录中的配置文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xqg6XmMxibmbsMz8z0kkB6mzb0sQB9hyCLRIJNhPMahyvMdibng0N8f7w/640?wx_fmt=png&from=appmsg "")  
  
注意： 是执行目录同级的 configs 目录，而不是二进制程序所在目录的同级 configs 目录。  
  
2. 指定配置文件夹  
  
使用 -C 参数指定要加载的配置文件夹：  

```
./noptrace-collector -C /path/to/configs
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xgibmyv2XTyOyMBdbHiaYVzvqLFWqdSq7VAMEOqRrkECO9u5d7aCBDm8A/640?wx_fmt=png&from=appmsg "")  
  
3. 指定单个配置文件  
  
使用 -c 参数指定要加载的单一配置文件：  

```
./noptrace-collector -c config.yaml
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xAM0yQgcYNTwD6T3cS88pGvp6Bqz4Pq7haGQ5sro029gN8HyJibvicEIQ/640?wx_fmt=png&from=appmsg "")  
  
4. 配置文件校验  
  
校验配置文件夹  
  
使用 -V 参数校验某个文件夹中所有配置文件的合法性：  

```
./noptrace-collector -V /path/to/configs
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xFM7OMdW4qbiaCgSWEGCBxnCticzeDPFgnj1zeLQeBdABicb6uSp06pruw/640?wx_fmt=png&from=appmsg "")  
  
校验单个配置文件  
  
使用 -v 参数校验单一配置文件的合法性：  

```
./noptrace-collector -v config.yaml
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xjbtzqe2yVvIJxrdhYicrthS6m8DOvNMTtUAOBFtsicTr5EHlDPh1GdIA/640?wx_fmt=png&from=appmsg "")  
  
5. 输出目录配置  
  
使用 -o 参数指定收集输出的结果目录。如果未指定，默认会在执行目录同级的 ./ForensicCollections 中输出结果。  
  
./noptrace-collector -o /path/to/output  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xmfWjAic3lXxgicE7P8E4qQNW7MzIEIxAicrY8UwPJwL6svoFbCnibqvm1w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xP7KUZGGdt6XLpiacMLER7xw7xwvNxia5CpG05K05AqAiaP4wq1vAIg1sA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xBDn0VhfyCcbqYiatVWU4faJc1TgAb3RL0ot3ficqnjicEPTcdw4tvHe5Q/640?wx_fmt=png&from=appmsg "")  
  
6. 结果解析  
  
收集结果保存为单一的 SQLite 数据库文件 ForensicResults.db，便于传输和分析。使用 -p 参数解析收集到的文件：  

```
./noptrace-collector -p ForensicResults.db
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xtdeaasCBSr8M9jLtFJKThTW3kEosWFNCRDJKsrPicW8QokicbSW7CclA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8H1dCzib3Uibu7uX2oYjbbibndft14nzUMIoRia7UqCAgMXSZAu1iaBDWSWLLuFnyibwfOiaCLO7YXaC6qib8icgHXwoe3Q/640?wx_fmt=jpeg "")  
  
****  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xNOxvbGwNAFyoH3acVUZWPOuuiauOGOvHrjk8DOWUCGOgfHxJGzaxiaeQ/640?wx_fmt=jpeg&from=appmsg "")  
  
京东购买链接：  
https://item.jd.com/10162873035829.htm  
  
详情扫描二维码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibusVfJXmzIeLa5EtNLA6I8xpshyDRX1FUDrJZH1TMZUDILFuQUke2GsHnW1fykkrGfgPBrlGvHECA/640?wx_fmt=png&from=appmsg "")  
> 本书在查阅一系列经典“离散数学与组合数学”素材的基础上，使用Python语言实现相关理论、算法及应用，内容包含组合计数原理、逻辑基础、一阶逻辑、集合、离散概率、数论、归纳与递归、关系、容斥原理、生成函数、递推关系、图论、树、布尔代数与开关函数、文法、有限状态机与图灵机等。本书内容翔实，不乏应用实例，力求以朴素易懂的方式描述相关数学理论。  
  
  
  
  
