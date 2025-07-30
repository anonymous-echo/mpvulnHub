> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4MDQ5MjY1Mg==&mid=2247516816&idx=1&sn=5d6d77197ef3850efacbaeceddfe1b44

#  内网漏洞自动化扫描工具 -- P1soda（6月7日更新）  
P001water  Web安全工具库   2025-06-15 16:01  
  
暗月渗透测试34 项目实战渗透合集项目项目五 linux内网完整渗透测试  
  
链接：https://pan.quark.cn/s/3435aff15758  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibv78jJ58JWXqClLOicQP5DKM5LtHeibU4266KRK3KYLIYBl6N6l2CatQRMFVQIESBLskINeMPb7JB8w/640?wx_fmt=png&from=appmsg "")  
  
===================================  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，  
安全性自测  
，  
大家都要把工具当做病毒对待，在虚拟机运行。  
如有侵权请联系删除。个人微信：  
ivu123ivu  
  
  
**0x01 工具介绍**  
  
P1soda （苏打水）是一款常规内网渗透场景下的全方位漏洞扫描工具。  
  
**0x02 安装与使用**  
  
工具参数如下图，默认情况下不开启服务爆破功能  
  
![image-20250115172430938](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibv78jJ58JWXqClLOicQP5DKMWQJicxMbn34PGNtd32PwwHROKb8Oyibq2clDAJaLMq2ibIQQ1ROuX2FMA/640?wx_fmt=png&from=appmsg "")  
- 入门使用  
  
单个、多个目标探测，支持CIDR网段输入  

```
P1soda.exe -t 192.168.110.235 	// 单个目标
P1soda.exe -t 192.168.110.2-235 // 多个目标
P1soda.exe -t 192.168.110.143,192.168.110.251 // 多个目标
P1soda.exe -t 192.168.110.235/24 // 扫描110 C段
```


```

```

- 内网网段探测  
  

```
.\P1soda.exe -plg netspy -cidr 192.168.0.0/16
```


```

```

- 指定用户名密码爆破  
  

```
.\P1soda.exe -t 127.0.0.1 -br -user root,admin -pwd 123456 // -br 开启爆破模式，默认情况不开启
```


```

```

- 输出保存文件  
  

```
.\P1soda.exe -t 127.0.0.1 -br -nc -o // -br开启爆破模式, -o输出重定向到p1.txt, -nc取消颜色输出
```


```

```

- 针对url的检测  
  
单个url目标  

```
.\P1soda.exe -u http://192.168.110.251
```


```

```

  
多个目标  

```
.\P1soda.exe -uf .\targets.txt
```


```

```

- Debug 测试信息  
  

```
.\P1soda.exe -u http://192.168.110.143:8888 -dbgdebug显示一些poc信息，http请求信息
```

  
![image-20240909005651301](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibv78jJ58JWXqClLOicQP5DKMLITnPMEGG1wYDSsByhhjoAPQbZkyoNfGUyEozAGQKv5sicRnACTmjicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8H1dCzib3Uibu7uX2oYjbbibndft14nzUMIoRia7UqCAgMXSZAu1iaBDWSWLLuFnyibwfOiaCLO7YXaC6qib8icgHXwoe3Q/640?wx_fmt=jpeg "")  
  
****  
  
  
**·****今 日 推 荐**  
**·**  
  
> 《  
C语言王者归来》详细讲解了C语言的相关知识，从基本概念开始，逐步讲解程序流程控制、循环、字符串、指针、函数、结构、文件输入与输出，以及完整的大型项目设计。同时本书还进一步讲解了数据结构的基础知识，如串行、堆栈、队列与二叉树，奠定读者未来学习算法的基础。  
  
  
  
