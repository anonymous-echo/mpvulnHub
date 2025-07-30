#  万能门店小程序管理系统 doPageGuiz SQL注入漏洞   
Superhero  Nday Poc   2025-03-20 20:37  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号Nday Poc及作者不为此承担任何责任，一旦造成后果请自行承担！  
  
  
**00******  
  
**产品简介**  
  
  
万能门店小程序管理系统是一款功能强大的工具，旨在为各行业商家提供线上线下融合的全方位解决方案。是一个集成了会员管理和会员营销两大核心功能的综合性平台。它支持多行业使用，通过后台一键切换版本，满足不同行业商家的个性化需求。该系统采用轻量后台，搭载高效服务器，确保小程序运行流畅，提升用户体验。  
**01******  
  
**漏洞概述**  
  
  
万能门店小程序管理系统   
doPageGuiz 存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 此漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="/comhome/cases/index.html"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIKGN90spDMYfbN2iaVz6icGMGJoViaQJibawVk20iaNZcBzKEIPPQOFve0d3VoQVFLY7Ye5vicnu4JIS6Q/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIKGN90spDMYfbN2iaVz6icGMcYhAqEYNdzQeMZyHC2rjq4vAjfuiakJtxlyAh8JtTosmK8rMD1b6C4g/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIKGN90spDMYfbN2iaVz6icGMnWBwQN27jicbB35XxfhA4FzWG5SOuyM42A08OZT5J4nfB40uicswQBJQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIKGN90spDMYfbN2iaVz6icGMVW82c7md6UeRhzrLXUcibuPjIl5K5ic6ThKgTZwYQib1RD7yeQzAUYeBA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIKGN90spDMYfbN2iaVz6icGMj5byhkJCLmuuZD9qYPTF1GewQN2lG9KMlJqcrVGQicicGazQn1pnl8VQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwIKGN90spDMYfbN2iaVz6icGMdlBicmwDqHqfadibxQZGPQpVem6Dnyne4NXPmj8jq0yRWdrBic02RIImw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
【Nday漏洞实战圈】🛠️   
  
专注公开漏洞复现 · 工具链适配支持  
  
 ✧━━━━━━━━━━━━━━━━✧   
  
🔍 资源内容  
  
 ▫️ 整合全网公开Nday漏洞POC详情  
  
 ▫️ 适配Xray/Afrog/Nuclei检测脚本  
  
 ▫️ 支持内置与自定义POC目录混合扫描   
  
🔄 更新计划   
  
▫️ 每周新增7-10个实用POC（来源公开平台）   
  
▫️ 所有脚本经过基础测试，降低调试成本   
  
🎯 适用场景   
  
▫️ 企业漏洞自查 ▫️ 授权渗透测试 ▫️ 工具链调试   
  
✧━━━━━━━━━━━━━━━━✧   
  
⚠️ 声明：仅限合法授权测试，严禁违规使用！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLT7IMzAPs3jMFqkApVcvKf84FHzvZkkXajucZnFfZ1rxv1nLOJBNksF6MuVxDVl5jJLKWHq58xsw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
