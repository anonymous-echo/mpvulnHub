> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMTUwOTY1MA==&mid=2247491130&idx=1&sn=bce87c351315abd069bb98e99f37ac10

#  大洞，速修，Redis远程命令执行漏洞。  
原创 ChinaRan404  知攻善防实验室   2025-07-10 09:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4nXTKcMNvDAEXiceibEJfeibc5vYVq6g6SOyj19zpUQM9Jxa2bByQjXPXiaNsmx8zYhYTJvartCEVATXYXibwbKwiaJw/640?from=appmsg "")  
  
.  
  
.  
  
.  
  
.  
  
.  
  
前言  
  
.  
  
.  
  
.  
  
.  
  
.  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/mFOgxUsUkK6icf3ibrBMuZZq63JMOC01a9fmliam6Cn8ahdibjl5p0nicS5wGMic1lQxjO1K5ibaQByhNdW2DjulfhdIg/640?from=appmsg "")  
  
  
经过身份验证的攻击者可通过构造特定的恶意字符串，在 HyperLogLog 操作中触发堆栈或堆内存的越界写入。由于内存破坏可能被进一步利用，此漏洞最终可能导致远程代码执行（RCE）。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4nXTKcMNvDAEXiceibEJfeibc5vYVq6g6SOyj19zpUQM9Jxa2bByQjXPXiaNsmx8zYhYTJvartCEVATXYXibwbKwiaJw/640?from=appmsg "")  
  
.  
  
.  
  
.  
  
.  
  
.  
  
漏洞复现  
  
.  
  
.  
  
.  
  
.  
  
.  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/mFOgxUsUkK6icf3ibrBMuZZq63JMOC01a9fmliam6Cn8ahdibjl5p0nicS5wGMic1lQxjO1K5ibaQByhNdW2DjulfhdIg/640?from=appmsg "")  
  
  
Docker运行漏洞环境  
  

```
docker run --name redis-container -p 6379:6379 -it redis:7.4.2-alpine3.21@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vqEM9QjdTgLuChE78M9LwqlqOQLJY5gAw76Szj57UQGqPWrR0J86HdLds9EfQvtBYGZPDzwMDc9hQ/640?wx_fmt=png&from=appmsg "")  
  
下载POC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vqEM9QjdTgLuChE78M9LwqlX6Zs5n80QZIG3rI8KzTOvG7KYuXK1xibZc7Z3X87Vxs6NRyoQqGv9fg/640?wx_fmt=png&from=appmsg "")  
  
https://github.com/leesh3288/CVE-2025-32023  
  
然后把容器的redis-server复制出来  

```
docker cp 2b536bc70f59:/usr/local/bin/redis-server .
```

  
编辑文件  

```
vim solver-f0b22e429fa6c984f39a409744ff954d3a45d843edd29428ef3a68085d696a7d.py
```

  
然后直接执行poc就可以了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vqEM9QjdTgLuChE78M9LwqlLYd6A9U3MIiaicRSWHq68oKGpTfRNwo6ts5QiaYvA2cfticf3ySJPyrAvg/640?wx_fmt=png&from=appmsg "")  
  
  
总体评价  
  
需要有redis-server编译后的文件，非docker，正常跑的redis，我测试过好几个版本，都会直接宕掉。  
  
个人感觉，目前市面上流出来的poc，非常鸡肋。  
  
修复建议，更新最新版本  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4nXTKcMNvDAEXiceibEJfeibc5vYVq6g6SOyj19zpUQM9Jxa2bByQjXPXiaNsmx8zYhYTJvartCEVATXYXibwbKwiaJw/640?from=appmsg "")  
  
.  
  
.  
  
.  
  
.  
  
.  
  
广告时间  
  
.  
  
.  
  
.  
  
.  
  
.  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/mFOgxUsUkK6icf3ibrBMuZZq63JMOC01a9fmliam6Cn8ahdibjl5p0nicS5wGMic1lQxjO1K5ibaQByhNdW2DjulfhdIg/640?from=appmsg "")  
  
  
CISP、CISSP、NISP、PTE等安全考证+Admin_Ran  
  
  
  
  
  
  
  
  
  
  
  
  
  
