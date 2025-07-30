> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyNTUyNTA5OQ==&mid=2247485553&idx=1&sn=88dd4856bbad8ec5449b1805bc0d8c64

#  DLL 注入术（三）：基于导入表修改的“白加黑”加载策略  
原创 仇辉攻防  仇辉攻防   2025-06-19 04:01  
  
📌   
**免责声明**  
：本系列文章仅供网络安全研究人员在合法授权下学习与研究使用，严禁用于任何非法目的。违者后果自负。  
  
一、术语解释：“白加黑”是什么？  
  
“白”：指合法的、可信的、经过签名的程序（白程序），如系统自带程序、正规厂商软件等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJwDDe53peXmJdiat7da5Cb093JjQ6PI4lYNX3eDGhWg8BIibgQIicBPvyJ7xYXZibHjOQoibnENallpYA/640?wx_fmt=png&from=appmsg "")  
  
“黑”：指自定义测试代码（黑程序、自定义DLL、shellcode等）。   
  
红队成员利用“白程序”去加载、执行“黑代码”，达到绕过安全检测、提升隐蔽性、逃避杀软查杀的目的。    
  
二、导入表（Import Table）机制解析  
  
导入表在Windows可执行文件（PE文件，包括exe和dll）中，是一个非常核心的概念，英文叫Import Table。   
- 是PE文件（exe、dll等）中的一个数据结构。  
  
- 用来记录当前程序运行时需要用到哪些外部的DLL和函数。  
  
- 当程序启动时，操作系统根据导入表自动加载这些DLL，并把对应的函数地址填好，供程序使用。  
  
  
这一机制被用于“白加黑”注入：  
在合法 DLL 的导入表中添加自定义 DLL，使其在程序加载时隐式执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJwDDe53peXmJdiat7da5Cb0rN4iaf4DKCUz4icOVq3uYfOSIErtZicLVcotLSCHibxRMTavRia1Lm2mnPw/640?wx_fmt=png&from=appmsg "")  
  
三、实战流程  
  
1、找一个白程序目标，查看其加载的dll，确定环境位数  
  
