> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwODc1NTgyMg==&mid=2247486136&idx=1&sn=ca0d6c9361cb4442aa461142be2a346c

#  记录某次SRC挖掘  
apex_incisive  蓝云Sec   2025-06-29 06:00  
  
# 某SRC渗透记录  
  
找找参数看看是否有注入点  
  
发现某处存在参数，加单引号返回错误  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQVQQrPqPeIDG2aVySfV2cIJUBXLdNCM5SgBvlmfvk61cnvI5GiauSuCg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQrk2YnHyGiaZODzxUNGAKZac7qXqjpTlw0oDQiaW6Ix5yH2VOyGUwvAaQ/640?wx_fmt=png&from=appmsg "")  
  
用sqlmap跑  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQaTh0Pfo3HibB0q1LdAkr8QWBiax8EUKn0bxFiaV03nTria2pjmF9F8Jg6w/640?wx_fmt=png&from=appmsg "")  
  
成功跑出数据，但是尝试后无法getshell 非dba权限 另寻他处  
  
发现一处文件上传  
  
尝试发现并为对后缀进行限制，只对文件头校验  
  
多次尝试后发现  
  
信息：1.图片码上传 2.不能解析（需要绕过）3.会回显到指定目录 且只上传指定文件夹  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQa0pFmYeWx32JGs072D5BdYzv4tZY2FSK6nqyECp19RRL2TJy2NgTmA/640?wx_fmt=png&from=appmsg "")  
  
注意这里可以控制文件上传路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQJKHtafRibhwzBQdCBicZVRNWoMrKEdaA4MFZribptibnm70Bt2RHLDiaIsA/640?wx_fmt=png&from=appmsg "")  
  
直接上传不能解析 而且这俩个目录在目录下  
  
联想跳转目录../../  
  
把内容置空  
  
然后输入../../  
  
就可以返回路径  
  
成功getshell  
  
修复方法 将路径写死就行了 或者白名单校验  
  
以上漏洞均已修复  
  
