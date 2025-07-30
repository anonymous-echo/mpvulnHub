#  慢雾：Rikkei Finance 被黑复现分析   
原创 慢雾安全团队  慢雾科技   2022-04-21 18:58  
  
By：Dig2@慢  
雾安全团队  
  
  
2022 年 0  
4 月 15 日，由于恶意攻击，Rikkei Finance 的五个资金池 (USDT, BTC, DAI, USDT, BUSD) 中近乎全部代币被盗。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qsQ2ibEw5pLaEkibNl0oOkm6AFh342AsPlfIaJfj5aKshQfFFy8FjZcsnun95iahj8EzLWP1ic1D9ibB24kOl0St9Cg/640?wx_fmt=jpeg "")  
  
  
慢雾安  
全团队将复现分析结果分享如下：  
  
  
**相关信息**  
  
  
Rikkei Finance 是 BSC 上的一个 DeFi 借贷平台。  
  
  
以下是本次攻击涉及的相关地址：  
  
  
攻击者地址：  
  
https://bscscan.com/address/0x803e0930357ba577dc414b552402f71656c093ab  
  
  
攻击合约：  
  
https://bscscan.com/address/0xe6df12a9f33605f2271d2a2ddc92e509e54e6b5f  
  
  
攻击交易：  
  
  
https://bscscan.com/tx/0x93a9b022df260f1953420cd3e18789e7d1e095459e36fe2eb534918ed1687492  
  
  
**攻击核心点**  
  
  
此次 Rikkei Finance 遭受攻击的根本原因是 setOracleDate 函数调用的权限控制缺失导致预言机价格被恶意操纵。  
  
  
**具体细节分析**  
  
  
1.   
攻击者用 0.0001 BNB 兑换一些 rBNB 作为抵押物，rBNB 合约地址为  
  
https://bscscan.com/address/0x157822aC5fa0Efe98daa4b0A55450f4a182C10cA  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaEkibNl0oOkm6AFh342AsPlfQHib2v1b0gnhAUfFZQZbUCGbv9Mu9iaXg23HmYiaX6js3pFcISP1XlzA/640?wx_fmt=png "")  
  
  
2.   
对 rBNB 设置恶意预言机，合约地址为  
  
https://bscscan.com/address/0xd55f01b4b51b7f48912cd8ca3cdd8070a1a9dba5  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaEkibNl0oOkm6AFh342AsPlDhwpLY0vYPuKbFcsFe6NJibAExRPh0cwehbnicTxYSnU4gJw6QIEPJOQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaEkibNl0oOkm6AFh342AsPlbU4JPKFXcTuJCYbRcaDBac0YxUA5mzicXhgbkzAuWRQDCg1EuJBhtXA/640?wx_fmt=png "")  
  
  
部署的恶意预言机地址为  
  
https://bscscan.com/address/0xA36F6F78B2170a29359C74cEFcB8751E452116f9，其反编译得到：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaEkibNl0oOkm6AFh342AsPlNImRb1vy1hHxH2xic7IHZnb9JK787LC1ZJVC3xsBPOOyyzdia5J02hQA/640?wx_fmt=png "")  
  
  
可以看到，预言机返回价格被写成一个巨大的常数。  
  
  
3.   
分别对 rUSDC, rBTC, rDAI, rUSDT, rBUSD 合约进行借贷。由于上一步部署了恶意预言机，rBNB 被认为有高价值，因此能贷出池子中所有币。然后在 pancake 中进行 swap 换成 BNB，攻击者总获利约 2571 枚 BNB。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaEkibNl0oOkm6AFh342AsPla9awFZZjVSJMgwS43BibibPAJo559bv3eyEqNvbIpG2OUdWKCQ2iaQHicg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaEkibNl0oOkm6AFh342AsPl7BpNwFhibg2vM5bb8ceo3QPJyxIy0LibVNBcdjCx8m39CUS6gAHjn1Yw/640?wx_fmt=png "")  
  
  
4.   
攻击者将 BNB 打入 Tornado.Cash：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaEkibNl0oOkm6AFh342AsPljghbdej014k1efhjJz62MPyuD4iaBTa8gO8CwNoOIAniaENnfPlXBMoA/640?wx_fmt=png "")  
  
**总结**  
  
  
本  
次攻击事  
件是  
由于 Rikkei Finance 项目中的 SimplePriceOracle 合约文件中的 setOracleData 函数缺少鉴权，可以被任意调用。攻击者通过 setOracleData 函数将恶意 Oracle 合约加入到 SimplePriceOracle 中，在借贷时攻击者持有的少量抵押物，由于抵押物的价格是从恶意 Oracle 合约中获取，导致攻击者的抵押物被误认为具有很高价值，从而允许攻击者用少量的抵押物将 Rikkei Finance 池子中的 USDC, BTC, DAI, USDT, BUSD 全部借出。  
慢雾安  
全团队建议建议开发合约代码时注意函数的访问权限控制，例如使用 OpenZeppelin 提供的 Ownable.sol 合约。  
  
  
**往期回顾**  
  
[慢雾：揭露浏览器恶意书签如何盗取你的 Discord Token](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495383&idx=1&sn=3695e16c9f33aff690bb033de6f77b20&chksm=fdde9050caa919464a53d117159ff1b1ad52490b04edf372e5a9b65fde400031dad24f1348dd&scene=21#wechat_redirect)  
  
  
[慢雾出品 | 余弦：区块链黑暗森林自救手册](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495319&idx=1&sn=0f2862d8d335877211173cd1d7889582&chksm=fdde9010caa919060c0e2c9e170d7aada4efcf6a6f0f192fca78281ee36a2fe5cb20d28b9239&scene=21#wechat_redirect)  
  
  
[慢雾为香港浸会大学金融课程获奖者提供“慢雾网络安全奖”](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495220&idx=1&sn=b7ee3bd75d441d2c5d6ee9fb639c84a4&chksm=fdde90b3caa919a52304aa8f4555897c14a680ad322bbdadff19d3088a65f412e857a07b4cb8&scene=21#wechat_redirect)  
  
  
[漏洞随笔：通过 Jet Protocol 任意提款漏洞浅谈 PDA 与 Anchor 账号验证](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495213&idx=1&sn=07cc027e0b793aa0cdc140437507adef&chksm=fdde90aacaa919bc15437962ddb5752b5ab6befe50fc020161780ca8b629d1f67f5fb4949d63&scene=21#wechat_redirect)  
  
  
[损失超 6.1 亿美元 —— Ronin Network 被黑分析](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495201&idx=1&sn=d5ea8557319dc20d33f0cf507722ff41&chksm=fdde90a6caa919b070e31e2be66674d59bb0c4a415bf0a480c673afd820741a92f45f5544f87&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLY0WsWbr4255IZhAfesmHAg3rPkOURRAD3YJyU13SNMPpzkrg5ibxicrzvCvQ7xGaysv8fmLdHKn1Og/640?wx_fmt=png "")  
  
**慢雾导航**  
  
  
**慢雾科技官网**  
  
https://www.slowmist.com/  
  
  
**慢雾区官网**  
  
https://slowmist.io/  
  
  
**慢雾 GitHub**  
  
https://github.com/slowmist  
  
  
**Telegram**  
  
https://t.me/slowmistteam  
  
  
**Twitter**  
  
https://twitter.com/@slowmist_team  
  
  
**Medium**  
  
https://medium.com/@slowmist  
  
  
**知识星球**  
  
https://t.zsxq.com/Q3zNvvF  
  
