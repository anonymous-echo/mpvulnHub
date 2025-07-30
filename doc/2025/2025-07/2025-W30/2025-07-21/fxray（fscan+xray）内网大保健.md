> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyMDM4NDM5Ng==&mid=2247493377&idx=1&sn=313c7fb6dcd7fceb26aaf5056cb3c559

#  fxray（fscan+xray）内网大保健  
闲客  安全洞察知识图谱   2025-07-21 00:30  
  
**免责声明**  
 由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号安全洞察知识图谱及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
## 1详细介绍  
  
工作原因定期开展多轮内网渗透，面对海量资产，fscan 只能照顾到一些服务弱口令，nday 等，xray 又只能在 web 上大展拳脚，所以缝了个小工具直接二者结合  
  
工作流程![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhibjrUYrD12R6NwRe9RXNt0sZWCtod8V6SMxcSdUgdj2RN95yialOL6LLia8KOcryw8sueGLjZCDJZTg/640?wx_fmt=jpeg "")  
  
  
使用方法  

```
python3 fxray.py -f xxx.txt

```

  
config.ini文件可自定义端口，xray 需要配置绝对路径，结束后会生成当前时间戳文件夹包含各种结果等  
  
工具地址：  
https://github.com/Axianke/fxray  
  
另外里面的 fscan 为本人二开版本（不放心可替换原版），增加了爆破规则例如 admin@2025 admin123@2025 等，之前 fscan 源码里的密码爆破规则年份太久远，按照内网运维准则每年更改的情况下，今年大概率是 xxxx@2025，增加了若干个 poc，改了强特征等。  
## 2免费社区  
  
安全洞察知识图谱星球是一个聚焦于信息安全对抗技术和企业安全建设的话题社区，也是一个  
**[免费]**  
的星球，欢迎大伙加入积极分享红蓝对抗、渗透测试、安全建设等热点主题  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8aia4mibs0I8I42MrYYOSE2DVEpVpPHvxufMGR0yufpgouwIXEl7H5eLm0MgolGFQMDFIrKLTxaYIQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhibjrUYrD12R6NwRe9RXNt0sfQwJNRo87Uvvd8EGAtDOuDoWx11Jfm6GkGwIvBGyO1yqpPhClShPEw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
