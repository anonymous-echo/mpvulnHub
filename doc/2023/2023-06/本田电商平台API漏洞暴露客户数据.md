#  本田电商平台API漏洞暴露客户数据   
 关键基础设施安全应急响应中心   2023-06-13 15:32  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvY7epHc0mzKByQkw0SaUeMFjtE3ibicxWIxfh2MVzOKX0ibfQeP6XL98mGxsJ7Mp2fYiaVAv6VmTd8iaBw/640?wx_fmt=png&wxfrom=13 "")  
  
近日，安全研究人员Eaton Zveare发现本田动力设备的电商平台存在API漏洞，攻击者可为任何帐户重置密码，导致本田动力（包括电力、船舶、草坪和花园设备）电子商务平台容易受到任何人未经授权的访问。  
  
本田是一家日本汽车、摩托车和动力设备制造商，受漏洞影响的是动力设备用户，汽车或摩托车的车主不受影响。  
  
值得注意的是，仅仅数月前，Eaton Zveare利用类似的漏洞成功渗透了丰田的供应商门户。  
  
对于本田，Eaton Works利用密码重置API重置重要帐户的密码，然后在本田公司网络上享受不受限制的管理员级别数据访问。  
  
本田暴露给安全研究人员（包括潜在的攻击者）的敏感信息如下：  
  
- 从2016年8月到2023年3月的所有经销商的21393份客户订单——包括客户姓名、地址、电话号码和订购的物品信息。  
  
- 1570个经销商网站（其中1091个处于活动状态）。攻击者可修改这些站点中的任何一个（的管理页面）。  
  
- 3588个经销商用户/帐户（包括名字和姓氏、电子邮件地址）。攻击者可以更改任何这些用户的密码。  
  
- 1090个经销商电子邮件（包括名字和姓氏）。  
  
- 11034封客户电子邮件（包括名字和姓氏）。  
  
- 可能泄露信息包括：本田经销商的Stripe、PayPal和Authorize.net私钥。  
  
- 内部财务报告。  
  
上述数据可用于发起网络钓鱼活动、社会工程攻击，或在黑客论坛和暗网市场上出售。  
  
此外，通过访问本田经销商站点，攻击者可以植入信用卡浏览器或其他恶意JavaScript代码段。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvY7epHc0mzKByQkw0SaUeMF4DHOmj34KKJOiaicBX6duMB21lnKniamuQMKTibk5dk25uOfibPI4zxRUpw/640?wx_fmt=png "")  
  
黑客可以编辑本田经销商站点页面内容   
来源：eaton-works.com  
  
Zveare解释说，API漏洞存在于本田的电子商务平台中，该平台将“powerdealer.honda.com”子域分配给注册经销商/经销商。  
  
研究人员发现，本田网站Power Equipment Tech Express (PETE)上的密码重置API处理重置请求时不需要令牌或以前的密码，只需要一个有效的电子邮件。  
  
虽然此漏洞不存在于电子商务子域登录门户中，但通过PETE站点切换的凭据仍然适用于它们，因此任何人都可以通过这种简单的攻击访问内部经销商数据。  
  
上述情况已于2023年3月16日向本田报告，到2023年4月3日，本田确认所有问题均已解决。  
  
由于没有漏洞赏金计划，本田没有奖励Zveare的安全报告，这与丰田案的结果相同。  
  
**参考链接：**  
  
https://www.bleepingcomputer.com/news/security/honda-api-flaws-exposed-customer-data-dealer-panels-internal-docs/  
  
  
  
原文来源：GoUpSec  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
