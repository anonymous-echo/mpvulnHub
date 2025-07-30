> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2NzY5MzI5Ng==&mid=2247506817&idx=1&sn=d7d0e6841bf9b0829344d2b361ec9245

#  fxray（fscan+xray）内网大保健  
闲客  菜鸟学信安   2025-07-14 00:30  
  
工作原因定期开展多轮内网渗透，面对海量资产，fscan 只能照顾到一些服务弱口令，nday 等，xray 又只能在 web 上大展拳脚，所以缝了个小工具直接二者结合  
  
工作流程![](https://mmbiz.qpic.cn/mmbiz_png/oy4sM7gQoibBjHNsG1s1JNBuhO9clRtGt1HO29N4TYyGXTRqiaQkwg7ms1WpeRNXLiaYVMQLV3mP0S4UgZbr7JAfw/640?wx_fmt=png&from=appmsg&watermark=1 "")  
  
  
使用方法  

```
python3 fxray.py -f xxx.txt

```

  
config.ini文件可自定义端口，xray 需要配置绝对路径，结束后会生成当前时间戳文件夹包含各种结果等  
  
工具地址：  
https://github.com/Axianke/fxray  
  
另外里面的 fscan 为本人二开版本（不放心可替换原版），增加了爆破规则例如 admin@2025 admin123@2025 等，之前 fscan 源码里的密码爆破规则年份太久远，按照内网运维准则每年更改的情况下，今年大概率是 xxxx@2025，增加了若干个 poc，改了强特征等。  
  
  
