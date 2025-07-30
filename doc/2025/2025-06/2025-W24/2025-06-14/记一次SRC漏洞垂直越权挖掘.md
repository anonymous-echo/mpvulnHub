> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwODc1NTgyMg==&mid=2247485807&idx=1&sn=f849a548f91e22fee19fce78d3285a8d

#  记一次SRC漏洞垂直越权挖掘  
原创 蓝云sec  蓝云Sec   2025-06-14 16:00  
  
# 声明  
  
本文章所分享内容仅用于网络安全相关的技术讨论和学习，注意，切勿用于违法途径，所有渗透测试都需要获取授权，违者后果自行承担，与本文章及作者无关，请谨记守法。  
# 前言  
  
一个src厂商，准确的说是子公司，拥有股份50以上，这个资产贼偏，找了好久才找到的，所以说信息收集还是重要的，不然也发现不了这个资产。  
  
弱口令  
  
首先拿到后台系统。没有验证码，用户密码输入错误锁定等限制。所以历史没有123456，admin这样子的弱口令也可以去尝试暴力破解一下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQJtj1n3lnia6aIjxffR3N9OiaURWRMe9hLXYN1nRBr6emtWEorc65R4mg/640?wx_fmt=png&from=appmsg "")  
  
但是好像也不需要爆破啥的，直接账号test密码123456就进来了。但是里面什么东西都没有，这里如果直接当作一个低权限弱口令去交了那就太亏了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQniakSib9rCHiavrud705xSvcDebY0avIQzq0xbSOr9kfPJib9FGXQ2eFRw/640?wx_fmt=png&from=appmsg "")  
  
垂直越权  
  
这里直接看了下请求包，发现jwttoken，解密出来发现角色列表里面类似一些接口权限开放情况，看这种像是有管理员权限的啊。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQtBiarNu2E6VzSTpU3ibJtkarhUiaxPWlkoSVcQvpMZbGseSMcJQJI9V8A/640?wx_fmt=png&from=appmsg "")  
  
通过熊猫插件泄露出来的信息也可以发现存在很多接口，所以test这个账号是应该有一定权限的，所以这里随便找几个接口测试一下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQNMqxX0kTXfSfN1aSKRrAwrqcJRYXZzQGTmyHMtV0rCLOyxibPUbkX1Q/640?wx_fmt=png&from=appmsg "")  
  
通过访问接口都是大部分是可以进行访问且可以查看数据的，但是有的不行，这里通过分析js传入参数可以直接升级为管理员权限，注意userid参数值是jwt里面找到的，再加上roleid为admin，提示操作成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQSh3l6TRcEEEcnibP3iczjKMusEwIFgs5M882O4I5icVWTqRmXnuO0XF3w/640?wx_fmt=png&from=appmsg "")  
  
回到登录后的页面进行刷新，hhh，直接垂直越权获取管理员操作页面。而且可以查看和编辑其他用户。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQ8nO0j0NNwibRekcAhopICoicAic8X2BCk85hdCWTZSk3ygsB3IbFXDLlw/640?wx_fmt=png&from=appmsg "")  
  
这里后面在通过垂直越权获取管理员权限在批量扫描一下接口信息，发现泄露用户密码信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQaKNl7Nz7fIibhk6oTVUmF1LTM2dnpRaSRswhE3m6gIPx5cp5H00vOXA/640?wx_fmt=png&from=appmsg "")  
  
通过sha1解密，直接解密成功,密码其实有点像弱口令，其实如果自己猜解肯定是解不出来的，因为和密码与用户名相关。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQ6638NNCicXEIZicoAB3vA79lVFGfcRpUicnZxk7wjC3VVUbPrqgPqqCwg/640?wx_fmt=png&from=appmsg "")  
  
使用解密的密码可以直接进行登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQvf2tt5lkeZNic3hGekLFib5zoEWkqwCAttGiczsdF56TfyboGnxlwNmWA/640?wx_fmt=png&from=appmsg "")  
  
  
