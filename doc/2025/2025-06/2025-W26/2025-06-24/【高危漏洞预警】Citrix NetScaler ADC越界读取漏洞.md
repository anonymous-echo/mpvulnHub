> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI3NzMzNzE5Ng==&mid=2247490297&idx=2&sn=6153fb97ede112cd135b07c48e91a27f

#  【高危漏洞预警】Citrix NetScaler ADC越界读取漏洞  
cexlife  飓风网络安全   2025-06-24 05:07  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00Um94S0fA3hKOSSz2ctOSoXHq9CCOF925GgKlWj071OibugsGrgiczLtxzvpYqFiaO55nCBKZSPq0GA/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
Citrix NetScaler ADC和Citrix NetScaler Gateway是美国Citrix公司的产品,Citrix NetScaler ADC是一个应用程序交付和安全性平台,Citrix NetScaler Gateway是一种安全远程访问的解决方案，近日,Citrix公司发布安全公告,披露了NetScaler ADC和Citrix NetScaler Gateway中存在的一处越界读取漏洞,该漏洞与2023年被大规模利用的CitrixBleed（CVE-2023-4966）漏洞原理类似,攻击者可能利用畸形请求从NetScaler设备内存窃取有效会话令牌,一旦被成功利用攻击者可获取敏感信息并非法访问系统,官方已经在新版本中修复此漏洞,建议受影响用户及时升级到安全版本。  
  
影响版本:  
  
14.1<=Citrix NetScaler ADC<14.1-43.56  
  
13.1<=Citrix NetScaler ADC<13.1-58.32  
  
13.1-FIPSandNDcPP<=Citrix NetScaler ADC<13.1-37.235-FIPSandNDcPP  
  
14.1<=Citrix NetScaler Gateway<14.1-43.56  
  
13.1<=Citrix NetScaler Gateway<13.1-58.32  
  
修复建议:  
  
针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本：  
  
NetScaler ADC 12 >= 12.1-FIPS and 12.1-NDcPP 12.1-55.327  
  
NetScaler ADC 13 >= 13.1-FIPS and 13.1-NDcPP 13.1-37.234  
  
NetScaler ADC 13 >= 13.1-58.32  
  
NetScaler ADC 14 >= 14.1-43.56  
  
NetScaler Gateway 13 >= 13.1-58.32  
  
NetScaler Gateway 14 >= 14.1-43.56  
  
参考链接:  
  
https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420  
  
  
  
