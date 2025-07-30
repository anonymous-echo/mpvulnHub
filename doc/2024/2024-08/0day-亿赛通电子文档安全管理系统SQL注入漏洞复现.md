#  0day-亿赛通电子文档安全管理系统SQL注入漏洞复现   
原创 灵泽  灵泽安全团队   2024-08-10 14:00  
  
**-----------**  
  
**漏洞简介**  
  
**-----------**  
  
      
亿赛通电子文档安全管理系统（E-SafeDoc）是一种用于保护企业和组织的敏感信息的安全管理系统。它通过对电子文档进行加密、权限控制和日志记录等措施，确保数据的安全性。然而，这类系统有时会出现安全漏洞，其中之一就是SQL注入漏洞。  
  
**-----------**  
  
**漏洞复现**  
  
**-----------**  
  
1、fofa搜索：body="/CDGServer3/index.jsp"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/704aYL39zUTf67W6hRDlNdfBicbo6ocaTmB5I2oiaRChsscBIQVwjiaDhjvPP9HZmncloPZtH5hSLibd7etMibiacf1w/640?wx_fmt=png&from=appmsg "")  
  
2、打开亿赛通电子文档安全管理系统主页  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/704aYL39zUTf67W6hRDlNdfBicbo6ocaTNWCicBmfKkURicVic1fWfmypUia41mHtic91xqib2Wuqprc8OicbvgyvJQz9g/640?wx_fmt=png&from=appmsg "")  
  
3、抓包并发送至重发器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/704aYL39zUTf67W6hRDlNdfBicbo6ocaTTdJ3ZAaBBf4evzpu7FKULNpPmTSw6iadD0aL38mHiastyAGqQia8gJhAg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/704aYL39zUTf67W6hRDlNdfBicbo6ocaTrIFJeH71Iy8MTfcFnEVUkyzEqzthOfibfFlRBzxu7HW08P1JA9asWvg/640?wx_fmt=png&from=appmsg "")  
  
4、修改请求包请求方式为POST，并添加payload发送  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/704aYL39zUTf67W6hRDlNdfBicbo6ocaT2j1PkiaVLpjMKbkRNpyvib5I03vTq9pPrkeZp9rrPyJxMUbWqSQJb6icw/640?wx_fmt=png&from=appmsg "")  
  
5、使用解密工具解密返回包中的内容，得到账号密码信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/704aYL39zUTf67W6hRDlNdfBicbo6ocaTiaKD88GZRSTGSK4IOLiaN479hnERw4QqdEbvTSiaMKJcpNemvZNec7uHw/640?wx_fmt=png&from=appmsg "")  
  
**-------------**  
  
**工具获取**  
  
**-------------**  
  
**关注公众号回复：240810    获取payload与解密工具**  
  
****  
  
**-----------**  
  
**免责声明**  
  
**-----------**  
  
****  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
