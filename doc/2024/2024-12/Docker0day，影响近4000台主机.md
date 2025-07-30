#  Docker0day，影响近4000台主机   
hongzh0  Hacking Group 0434   2024-12-07 07:06  
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任  
  
  
- 系统描述  
  
  
  
DockerUI 是一个基于 Docker API 的开源 web 应用程序，它提供了大部分等同于 Docker 命令行的功能，主要用于容器和镜像的管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jZReoHLb66xdJS5I9NnsIOvmwdib6Et9Oib74GomGSAQibibtsjzq2xW6WicV7qAwOFibfYqiauibCMKysuRia3AuVvrQJg/640?wx_fmt=png&from=appmsg "")  
  
- 搜索语法：  
  
  
  
- zoomeye:  
  
  
```
iconhash="484370044e6b696ce8ea89122c3f8974"
```  
  
- quake:  
  
  
```
favicon: "484370044e6b696ce8ea89122c3f8974"
```  
  
- 漏洞描述  
  
弱口令一打一个准(  
  
ginghan/123456  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jZReoHLb66xdJS5I9NnsIOvmwdib6Et9OKUvF5M8niahMBzhpg15pAfeBGnTOBibz4GKnS8icricV2VeAtKtGPn4m5Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jZReoHLb66xdJS5I9NnsIOvmwdib6Et9Ot6l11qmgCe2EaRD6Y5oicJkEXSsnKy9RN5S9icrqDpIxyAn7eIiaibQAsg/640?wx_fmt=png&from=appmsg "")  
  
  
  
