#  零时科技 || BTB 攻击事件分析   
原创 零时科技  零时科技   2024-11-21 08:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkVs6NMLwfk5UDBNGzOgbibwSVafIkG2VgbWIicl12Axpdb3yOZLxSJLcA/640?wx_fmt=jpeg "")  
  
  
**背景介绍**  
  
  
2024年11月18日，我们监控到 BNB Smart Chain 上的一起攻击事件，被攻击的项目为 **BTB** 。攻击交易为  
  
**https://bscscan.com/tx/0xfb6df4053c2f1000cb03135064af19a79a87cf25efe612ae5f3468390d6be216**  
  
本次攻击共造成约 5000 USD 的损失。  
  
  
  
**攻击及事件分析**  
  
  
首先，攻击者利用 flashloan 从 pancakeSwapV3 中贷款 100,000 BUSD  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkdoES54LIaUicAoIocibRQHvhUs0KNKBlaKQ0Xy3h1STrWenRiaEM5QIhw/640?wx_fmt=png "")  
  
  
随后，攻击者利用 pancakeSwapV2 将贷到的 100,000 BUSD 兑换为 1,263,427 BTB   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkO0nfvQJEp99ubib3ZwerCJ5bjgqmufB7EkU8QoeEX6q51ViahA9u5ic4g/640?wx_fmt=png "")  
  
  
接着，攻击者利用 BTB 的 exchangeBTBToUSDT 将 3,052 BTB 兑换为 4,999 BUSD  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkL4bDDSfVTbLqpILckJZmyW13Ik37ia5yriaJ3tjzVmhNgrNtPGMT62dQ/640?wx_fmt=png "")  
  
  
我们看一下被攻击的智能合约的函数 exchangeBTBToUSDT 的代码  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkyP0EAnMDIVp9lGKWWPkk4Wuy55KxAaWk9sQhy6aSLI8JV49Ws43rEA/640?wx_fmt=png "")  
  
****  
可以看到，兑换的价格是由 pancakeSwapV2 的 BTB 和 BUSD 的 pair 的 reserve 决定的。这样，攻击者就可以利用 pacakeSwap 兑换大额 BTB 或 BUSD 来操纵 BTB 的价格。我们可以看到，攻击者在用 flashloan 贷来的 100,000 BUSD 兑换了 BTB 。  
  
因此，在攻击者使用 pancakeSwapV2 进行大额 BUSD 兑换 BTB 前  
  
**reserve0 为：**  
  
1,327,362,530,716,302,619,951,383 ，  
  
**reserve1 为：**  
  
5047758199614262100984 ，  
  
  
**兑换后 reserve0 为：**  
  
63934622394514316973499 ，  
  
**reserve1 为：**  
  
105047758199614262100984 。   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkzenzEiavV120uoJlgUaALZJTib2WV09VHbJibU9BibHSTV1Plxo4pMQJyA/640?wx_fmt=png "")  
  
  
通过 getPrice 中 getAmountOut 的实现，我们可以计算出攻击者兑换前和兑换后的 BTB 价格变化。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkmhDTHh0VYWh0fv0k5UU8wd2htb5wMtpCUq6rRTlNf1RszI4qmREb6A/640?wx_fmt=png "")  
  
  
我们通过计算得到 BTB 的价格从 1BTB=0.00379143964708692 BUSD 拉升到了 1 BTB =1.6381204893766859 BUSD 。价格被拉升了 400 多倍。  
  
因此，攻击者使用了 3052 BTB 兑换到了 4999 BUSD 。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkZ9MbCR2X7oDCibdicf9AwFjkC1deG8Ro1fd3TajzLTmvqwHUJOKnSlnw/640?wx_fmt=png "")  
  
  
最后，攻击者用剩下的 1260375 BTB 从 pancakeSwapV2 中兑换了 99,964 BUSD。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkIn54XQ0n6xxnmeVtvUEXntgQp7kcXpX2V5Y8VvTsI1ldPol7ZBmSDQ/640?wx_fmt=png "")  
  
  
攻击者再归还 flashloan 的贷款及利息 100,100 BUSD 后，获利 4,863 BUSD 。   
  
  
  
**总结**  
  
  
本次漏洞的成因是项目方在完成兑换 BTB 到 BUSD 时，使用了过时的价格预言机，导致攻击者可以轻易操纵 BTB 的价格，先进行大笔买入 BTB ，拉高 BTB 的价格后再卖出。最后完成套利。建议项目方在设计价格预言机和代码运行逻辑时要多方验证，合约上线前审计时尽量选择多个审计公司交叉审计。  
  
  
  
  
若需了解更多产品信息或有相关业务需求，可扫码关注公众号或移步至官网：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkXSkVNe173uwsru6IQsbr189fkDxQSzRZWbsaKicrIlhUk2e9gYB05Mg/640?wx_fmt=jpeg "")  
  
****  
**微信号****｜**  
noneage  
  
**官方网址****｜**  
https://noneage.com/  
  
  
  
  
**推荐阅读**  
  
**REVIEW**  
  
[](https://mp.weixin.qq.com/s?__biz=MzU1OTc2MzE2Mg==&mid=2247487869&idx=1&sn=fee1aea8e3abdee2aebfe094dafbfdc3&chksm=fc130ac8cb6483de4bb74b397b596f942aefc2bcf6252f3884505e97ff0713d524e5383a2051&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzU1OTc2MzE2Mg==&mid=2247487974&idx=1&sn=91851c6856447643a9b7890fefcc62d3&chksm=fc130a53cb648345ea711f2693d64a960bfabc36a0428bace1892e33cbc8fe7317bbf1e1a7c0&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzU1OTc2MzE2Mg==&mid=2247487541&idx=1&sn=ad65034445ef8e9e4816cad96f2b39ee&chksm=fc130b80cb6482960fdeafa504ef9285a125fcc311a1df7c506099d1039e747cd69101fe7393&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzU1OTc2MzE2Mg==&mid=2247487577&idx=1&sn=50c75c165d0327b80fd745fe163a351f&chksm=fc130beccb6482fac9a436bd0a38b94177df1dae6a39fcb84176006891ac6588664f6a3b522f&scene=21#wechat_redirect)  
  
  
  
  
END  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/bsePwevmNNxXljAMPJnTFOiaqR0ejmBOkf0TEh84ZPDtvEbKwvWVYDIqTJKtB74UwgiaDPxS24XjT228FP3W3f7w/640?wx_fmt=jpeg "")  
  
  
  
  
**点击阅读全文 立刻直达官网**  
  
       
/www.noneage.com/      
  
![](https://mmbiz.qpic.cn/mmbiz_gif/S9WiaEibMtP2jMSTib9czK3UfPsBh0fJscaqZMFhTOvKNaJnEte4bETdtREaSQB3YIA71icwDtrr4oZWAR938LXGcw/640?wx_fmt=gif "")  
  
  
