> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTQ5MTAzMA==&mid=2247484471&idx=1&sn=cf743831abccc0a1a5cb46208a1f6ee5

#  Springboot图形化漏洞利用工具  
 天黑说嘿话   2025-06-25 01:07  
  
前言  
  
日常日站的时候偶然之间发现了一款误报比较少的springboot漏洞利用工具浅浅分享一下。  
  
工具说明  

```


工具目前支持如下漏洞的检测 : 


    SpringBoot Actuator Env 敏感信息泄露
    SpringSecurity Oauth RCE (CVE-2016-4977)
    SpringData Commons RCE (CVE-2018-1273)  ( 工具支持利用模块 :  命令执行  )
    SpringBoot Actuator Logview 任意文件读取 (CVE-2021-21234)  ( 工具支持利用模块 :  任意文件读取  )
    SpringCloud Function SpEL RCE (CVE-2022-22963)  ( 工具支持利用模块 :  命令执行  )
    SpringFramework RCE (CVE-2022-22965)  ( 工具支持利用模块 :  命令执行  )
    SpringCloud Gateway RCE (CVE-2022-22947)  ( 工具支持利用模块 :  命令执行 内存马注入  )
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f7yXib8mBCO5xyDKN509ZdTdzIG4uFINTZhZe45nEYuKTRHs35KYaLMz6UAico3tmQp1JEL98a3ZGibe5Kc1lLa2g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f7yXib8mBCO5xyDKN509ZdTdzIG4uFINT0grBQF4pKUukBqMibicsFbUnIBrFzvRbEDcO3M5D8ibUFmw3nibBXEyXNQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f7yXib8mBCO5xyDKN509ZdTdzIG4uFINTdAc76XiahibnVS9tib5PPxRfrdmM8RbTah2Dg5ozAbvdLbQqFjutJF98w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f7yXib8mBCO5xyDKN509ZdTdzIG4uFINTz0MBH0j3fsCApR3WNZFh16x75waicBtXBR9NhuiafzsconzxV16dSnRg/640?wx_fmt=png&from=appmsg "")  
  
heapdump解密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f7yXib8mBCO5xyDKN509ZdTdzIG4uFINTQ0k8KdWGiciaCxoScEJgTVBfmM7FbscMkEo00YIELRgOWC8la2EibTjUg/640?wx_fmt=png&from=appmsg "")  
  
实战效果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f7yXib8mBCO5xyDKN509ZdTdzIG4uFINTjW7mzTBUF45dibMvLuWBIg36E4ohRF1pqs129CKydiaGFUcw4AGpK9NQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f7yXib8mBCO5xyDKN509ZdTdzIG4uFINTicFdxejcWVwsRgx4ApMs8RKCcRjibXNcJgE4gH3Zh9s1OUF0RIKXz0cw/640?wx_fmt=png&from=appmsg "")  
  
结尾  

```
免责声明
1.一般免责声明：本文所提供的技术信息仅供参考，不构成任何专业建议。读者应根据自身情况谨慎使用且应遵守《中华人民共和国网络安全法》，作者及发布平台不对因使用本文信息而导致的任何直接或间接责任或损失负责。
2. 适用性声明：文中技术内容可能不适用于所有情况或系统，在实际应用前请充分测试和评估。若因使用不当造成的任何问题，相关方不承担责任。
3. 更新声明：技术发展迅速，文章内容可能存在滞后性。读者需自行判断信息的时效性，因依据过时产生的后果，作者及发布平台不承担责任。
```

  
工具获取  
  
后台私信发送  
springboot  
!!  
  
  
