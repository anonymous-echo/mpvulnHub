> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0ODMwNjQzMA==&mid=2247485878&idx=1&sn=b0b216f75e14e34a1b3231553840a09d

#  fxray（fscan+xray）内网大保健  
xianke  XK Team   2025-06-19 09:58  
  
工作原因定期开展多轮内网渗透，面对海量资产，fscan 只能照顾到一些服务弱口令，nday 等，xray 又只能在 web 上大展拳脚，所以缝了个小工具直接二者结合  
  
工作流程![](https://mmbiz.qpic.cn/mmbiz_png/oy4sM7gQoibBjHNsG1s1JNBuhO9clRtGt4b2u0LnwqWIo7xtwrPOrtXKo95rxQ6wrfibKvNpR74OJFIKlscMOfNA/640?wx_fmt=png&from=appmsg "")  
  
  
使用方法  

```
python3 fxray.py -f xxx.txt

```

  
config.ini文件可自定义端口，xray 需要配置绝对路径，结束后会生成当前时间戳文件夹包含各种结果等  
  
工具地址 公众号回复**20250619**  
  
另外里面的 fscan 为本人二开版本（不放心可替换原版），增加了爆破规则例如 admin@2025 admin123@2025 等，之前 fscan 源码里的密码爆破规则年份太久远，按照内网运维准则每年更改的情况下，今年大概率是 xxxx@2025，增加了若干个 poc，改了强特征等。  
  
