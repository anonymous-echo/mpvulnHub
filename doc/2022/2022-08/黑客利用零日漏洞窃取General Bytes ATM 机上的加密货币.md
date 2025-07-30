#  黑客利用零日漏洞窃取General Bytes ATM 机上的加密货币   
 关键基础设施安全应急响应中心   2022-08-24 14:56  
  
The Hacker News 网站披露，比特币 ATM 机制造商 General Bytes 证实其遭到了网络攻击。攻击者利用服务器中的零日漏洞，从用户处掠夺加密货币。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39b54gynjfnd92s97bELibZQNLOug5bvtsoVpaA293QbUOsnbloq2XMW8CrRMZthX55g6y4nKVoMKQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
攻击事件发生不久后，General Bytes 在一份公告中表示，自 2020-12-08 版本以来，该零日漏洞一直存在于 CAS 软件中。攻击者通过 CAS 管理界面，利用页面上的 URL 调用，远程创建管理员用户。  
  
**CAS**  
  
CAS，Crypto Application Server 的缩写，是 General Bytes 公司旗下一款自托管产品，能够使用户通过桌面或移动设备上的 Web 浏览器从中央位置管理比特币 ATM(BATM)机器。  
  
目前，涉及 CAS 管理界面的零日漏洞，已经在以下两个版本的服务器补丁中得到了修复：  
  
20220531.38  
  
20220725.22  
  
General Bytes 强调，未知攻击者通过扫描 DigitalOcean 云主机的 IP 地址空间，识别出在端口 7777 或 443 运行的 CAS 服务，随后滥用该漏洞在 CAS 上添加了一个名为 “gb ”的新默认管理员用户。  
  
之后，黑客可以修改“购买”和“出售”加密设置以及“无效支付地址”，这时候客户向 ATM 机发送加密货币，双向 ATM 机则会向黑客钱包地址转发货币。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39b54gynjfnd92s97bELibZQWqiaSTbgwFbdhUMB81eQpkTDaY9Dzt8vZGYsjiba2jRpBCY5L1F0XQiag/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
换句话说，攻击者主要目的是通过修改设置，将所有资金都转到其控制的数字钱包地址里。值得一提的是，目前尚不清楚有多少服务器受到此漏洞影响，以及有多少加密货币被盗。  
  
最后，General Bytes 公司强调，自 2020 年以来，内部已经进行了多次“安全审计”，从未发现这一零日漏洞。  
  
**参考文章：**  
  
https://thehackernews.com/2022/08/hackers-stole-crypto-from-bitcoin-atms.html  
  
  
  
原文来源  
：FreeBuf  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
