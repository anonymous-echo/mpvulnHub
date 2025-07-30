#  jeecgBoot漏洞利用工具 -- jeecgBootAttack（2月1日更新）   
7wkajk  网络安全者   2025-02-04 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
swing练手项目，目前支持queryFieldBySql Freemarker模板注入、testConnection JDBC 远程代码执行漏洞。  
0x02 安装与使用  
**queryFieldBySql Freemarker模板注入漏洞**  
  
**执行命令**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczeuFzmeh8eO3zGReBoFGA9D001Zr6wv7p4Xic4rPgsriakwBORSqKqVgvL8CmPSwpdI3a9A32bzHTA/640?wx_fmt=png&from=appmsg "")  
  
**注入内存马**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczeuFzmeh8eO3zGReBoFGA9VlokrxF8mFNFnq3bkoZPZsPlAGaicvyynQMZgiauILFk3Z3vsJgC6iaXQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczeuFzmeh8eO3zGReBoFGA9QesIjukMciajy4zeZZR0icKeTs8g9b2vLP8pvPD9f7ujOeuGHy93oiaYw/640?wx_fmt=png&from=appmsg "")  
  
**testConnection JDBC 远程代码执行漏洞**  
  
**mysql jdbc**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczeuFzmeh8eO3zGReBoFGA9CEbiaWC7Ggu6Q0uCBWdIKjdoe5wBJnEwftjAkh5icUDINrknWthUX6QQ/640?wx_fmt=png&from=appmsg "")  
  
**pgsql jdbc**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczeuFzmeh8eO3zGReBoFGA9cyskoibWMpTfK1Pqptyc8iboJKgZ5B0HOPwTdDgN4n17VaX6w1zr9icFQ/640?wx_fmt=png&from=appmsg "")  
  
**h2 jdbc**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczeuFzmeh8eO3zGReBoFGA9V712htRvaWVWiaAVsupejtzGeQVfx7KOp2oIEQpCPl4pl6vo8tNibJhg/640?wx_fmt=png&from=appmsg "")  
  
**代理功能**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczeuFzmeh8eO3zGReBoFGA9NQ4Q0bXibtf5O3JyFfm7o8aVt5QA73XydRibbAmNdAbibGMkGmEUn1ZfA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwYUcSEibv9UYsy4eVib1k9benmib7GQvePmd7fJeWg5XvyfHnibaz4dibuUtI0RxCD8ibwtxhUCupxTaUA/640?wx_fmt=png&from=appmsg "")  
  
  
