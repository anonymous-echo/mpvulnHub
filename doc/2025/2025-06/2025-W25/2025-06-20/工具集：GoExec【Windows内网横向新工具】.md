> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0MjY1ODE5Mg==&mid=2247486247&idx=1&sn=baa2652154b28f0369eb43fb6b5cd34a

#  工具集：GoExec【Windows内网横向新工具】  
 风铃Sec   2025-06-20 16:06  
  
##### 声明：仅用于授权测试，用户滥用造成的一切后果和作者无关 请遵守法律法规！【文末获取工具】  
  
**0x01 工具介绍**  
  
GoExec是一款针对Windows的内网横向工具，它是获取 Windows 设备远程执行权限的全新工具。GoExec 实现了许多尚未实现的执行方法，并提供了显著的 OPSEC 改进。GoExec 由多个远程服务使用的模块组成对业界常用的现有解决方案（如 Impacket 远程执行脚本）进行了大量的补充和改进。Goexec 提供了一些与其他工具截然不同的横向方法：诸如  

```
tsch  scmr change
```

  
这些方法它会编辑现有资源，而不是创建新资源，从而规避防御。此外GoExec还支持本机代理，无需使用像  

```
Proxychains
```

  
这样的外部软件。  
Goexec 默认启用数据包桩加密，与   

```
dcomexec.py
```

  
 发送和接收的明文数据包相比，这显著降低了被网络监控检测到的可能性。  
以下是两种横向方法产生的流量对比：  
  
dcomexec.py  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HmtJdLjMFJbREfWeqjvGCQ3kdwsljlvYUTyjnnLL3z0iapfx3dSk8d6W90wgNlnRYianlnpm4jOsVoQ/640?wx_fmt=png&from=appmsg "")  
###### GoExec DCOM Module GoExec DCOM 模块  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HmtJdLjMFJbREfWeqjvGCQ3lk0RWzicuBxm5FiblR3O0CGaXoVmXDmiaUO7TxswEdgHfFIWdYCsCibWfQ/640?wx_fmt=png&from=appmsg "")  
  
**0x02 工具使用**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HmtJdLjMFJbREfWeqjvGCQ381mfZDKeGHib7nv313iaAFEz3HmaPcNeb2sxdgAI8MuySWTfMbtKpn3w/640?wx_fmt=png&from=appmsg "")  
  
**0x03 工具下载（已打包）**  
  
夸克网盘「GoExec」  
  
链接：  
https://pan.quark.cn/s/66cc0dbc22b7  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HmtJdLjMFJbREfWeqjvGCQ3DygO3C6dxdSCHpHaV0371HUUReS9iaj62gicWfSaglCQNtLq4osmATibQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x04 每日资源分享【 Nuclei Poc 20w+  
】  
  
夸克网盘「Nuclei Poc【20w+】」  
  
链接：  
https://pan.quark.cn/s/02110b52f458  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HmtJdLjMFJbREfWeqjvGCQ3NJc03mMYnVfeQCIj6oJA7N4I9WTqmOJicMicAG0m2Qo9P4egDo0lLbrQ/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
