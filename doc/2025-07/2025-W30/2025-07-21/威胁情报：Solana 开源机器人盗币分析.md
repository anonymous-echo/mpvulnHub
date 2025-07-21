> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247502744&idx=1&sn=d68a35155828109c97695ad3d3159ccb

#  威胁情报：Solana 开源机器人盗币分析  
原创 慢雾安全团队  慢雾科技   2025-07-21 10:10  
  
作者：Joker&Thinking  
  
编辑：KrsMt.  
  
  
背景  
#   
  
在 2025 年 7 月初，慢雾安全团队接到一名受害用户的求助，请求协助分析其加密资产被盗的原因。调查发现，事件源于该用户使用了一个托管在 GitHub 上的开源项目 zldp2002/solana-pumpfun-bot，进而触发了隐蔽的盗币行为，详情见  
[GitHub 热门 Solana 工具暗藏盗币陷阱](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247502589&idx=1&sn=75c7f110d5889e8f90ccee2855aa90cd&scene=21#wechat_redirect)  
  
。  
  
  
近期，又有用户因使用类似的开源项目 —— audiofilter/pumpfun-pumpswap-sniper-copy-trading-bot，导致加密资产被盗，并联系到慢雾安全团队。对此，团队进一步深入分析了该攻击手法。  
  
# 分析过程  
#   
## 静态分析  
##   
  
我们首先通过静态分析的方式，寻找攻击者设置的陷阱。经分析，发现可疑代码位于   
/src/common/config.rs  
 配置文件中，主要集中在   
create_coingecko_proxy()  
 方法内：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONxKAfhFn6dAWI59ztB92RKHUEPNr25j1G8mQ27mO1Mj3EmfRIMB1LJA/640?wx_fmt=png&from=appmsg "")  
  
从代码可见，create_coingecko_proxy() 方法首先调用了 import_wallet()，该方法进一步调用 import_env_var() 来获取私钥。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONiaAicJWPV17DvqBHqaKpboG8p6DI8yp1IiaamC1LbIvDcaJaOpPIUlnqQ/640?wx_fmt=png&from=appmsg "")  
  
在 import_env_var() 方法中，主要用于获取 .env 文件中的环境变量配置信息。  
  
  
  
调用过程中，如果环境变量存在，则直接返回；若不存在，则进入 Err(e) 分支，打印错误信息。由于存在无退出条件的 loop {} 循环，会导致资源持续消耗。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONbTxiaq4XNxfmE5UxuOpKjruX3dBI7dulJlonstN4VJ0zBicl2nm5AzRQ/640?wx_fmt=png&from=appmsg "")  
  
PRIVATE_KEY  
（私钥）等敏感信息也存储在   
.env  
 文件中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONiaQvA78KLn5ltS2U2swNzxicz1gldKDACicz1zCDCBME2x884klCO9Ctg/640?wx_fmt=png&from=appmsg "")  
  
回到 import_wallet() 方法，当其中调用 import_env_var() 获取到 PRIVATE_KEY（私钥）后，恶意代码会对私钥长度进行判断：  
  
- 若  
私钥长度小于 85，恶意程序将打印错误信息，并由于存在无退出条件的 loop {} 循环，会导致资源持续消耗，恶意程序无法正常退出；  
  
- 若私钥长度大于 85，则使用 Solana SDK 将该 Base58 字符串转换为 Keypair 对象，其中包含私钥信息。  
  
随后，恶意代码使用 Arc 对私钥信息进行封装，以支持多线程共享。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONiaAicJWPV17DvqBHqaKpboG8p6DI8yp1IiaamC1LbIvDcaJaOpPIUlnqQ/640?wx_fmt=png&from=appmsg "")  
  
回到 create_coingecko_proxy() 方法，在成功获取私钥信息后，恶意代码接着对恶意 URL 地址进行解码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONmt75QTmRib4T3ttNxnTIOxCIK0chyfc2JCBZSjzbiboyFOM395DMIhOg/640?wx_fmt=png&from=appmsg "")  
  
该方法首先获取编码后的 HELIUS_PROXY（攻击者服务器地址）这一硬编码常量。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONHF1015HDGRsst1AXJJVTd38t0313oz4q0wqK2iaIzJrVcqeskyibyib1Q/640?wx_fmt=png&from=appmsg "")  
  
随后，恶意代码使用 bs58 对 HELIUS_PROXY（攻击者服务器地址）进行解码，将解码结果转换为字节数组，并通过 from_utf8() 将该字节数组进一步转为 UTF-8 字符串。  
  
  
  
通过编写脚本可还原出 HELIUS_PROXY 解码后的真实地址如下：  
  

```
http://103.35.189.28:5000/api/wallets
```

  
恶意代码在成功解码出 URL (http://103.35.189.28:5000/api/wallets) 后，首先创建一个 HTTP 客户端，将获取到的私钥信息 payer 使用 to_base58_string() 转换为 Base58 字符串。  
  
  
  
随后，恶意代码构造 JSON 请求体，并将转换后的私钥信息封装其中，通过构建 POST 请求，将私钥等数据发送至上述 URL 所指向的服务器，同时忽略响应结果。  
  
  
  
无论服务器返回何种结果，恶意代码仍会继续运行，以避免引起用户察觉。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONQm4AbL7OsQALzc2SVWR0dIPbwdZJzt7mJYg8Oa0d3q3hRzLYoYMYEQ/640?wx_fmt=png&from=appmsg "")  
  
此外，create_coingecko_proxy() 方法中还包含获取价格等正常功能，用以掩盖其恶意行为；该方法名称本身也经过伪装，具有一定的迷惑性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONOYoO3iaVxT5u74kWjNwafMBIRK65MTUzmib0EDaHb5V8C5tUH8B13qZQ/640?wx_fmt=png&from=appmsg "")  
  
通过分析可知，create_coingecko_proxy() 方法在应用启动时被调用，具体位于 main.rs 中 main() 方法的配置文件初始化阶段。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TON0XJz96uILz8PUkJyFke9Rk9tb5ia47ulpgwn59XicaZxQg3YpGeXsDqQ/640?wx_fmt=png&from=appmsg "")  
  
在配置文件 src/common/config.rs 的 new() 方法中，恶意代码首先加载 .env 文件，随后调用 create_coingecko_proxy() 方法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONpsHUOsFLpoeCUFdrzicH90zyRmHtX2icVP9DsJA89ZFW9Gbct0v1dEAg/640?wx_fmt=png&from=appmsg "")  
  
据分析，该服务器的 IP 地址位于美国。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONwuyUZWZIOicNW2EBtKy7hbtnWW5Qmh96DOPWEiaa5aJSXpBxhhVkD5eA/640?wx_fmt=png&from=appmsg "")  
  
(https://www.virustotal.com/gui/ip-address/103.35.189.28)  
  
  
观察到该项目在 GitHub 上于近期（2025 年 7 月 17 日）进行了更新，主要更改集中在 src 目录下的配置文件 config.rs 中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONwVR0wd2sajo3Rjlc4P0L3jibGicWJrTguNxGzfKKuLkicEYGUa0CzibfxA/640?wx_fmt=png&from=appmsg "")  
  
在 src/common/config.rs 文件中，可以看到 HELIUS_PROXY（攻击者服务器地址）的原地址编码已被替换为新的编码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONXoZPmN00ACOOjjoDPR3uMics0SdS7vD4tCfvgx66cS8aHVaibzAFYibicA/640?wx_fmt=png&from=appmsg "")  
  
使用脚本对原地址编码进行解码后，可获得原服务器地址。  
  

```
// 原地址编码 HELIUS_PROXY： 
2HeX3Zi2vTf1saVKAcNmf3zsXDkjohjk3h7AsnBxbzCkgTY99X5jomSUkBCW7wodoq29Y
// 解码得到的原服务器地址
https://storebackend-qpq3.onrender.com/api/wallets
```

  
动态分析  
##   
  
为了更直观地观察恶意代码的盗窃过程，我们采用动态分析方法，编写了一个 Python 脚本，用于生成测试用的 Solana 公私钥对。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TON5wwElUUvcuRlzaXGE1ibz2kgLucFafRicNlXZd3eRUyd9J63cdLJ70fw/640?wx_fmt=png&from=appmsg "")  
  
同时，我们在服务器上搭建了一个能够接收 POST 请求的 HTTP 服务器。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONAWLHuSYAQMQY51BApvFbZAyeOZMF4ch7Io9YAICb5UZ3EVGmvwO5Xg/640?wx_fmt=png&from=appmsg "")  
  
编写 Python 脚本生成测试服务器对应的编码，并将其替换原攻击者设置的恶意服务器地址编码，即 HELIUS_PROXY（攻击者服务器地址）处。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONOz0eKsJqUV3Yn5iaGqt0vWqnNcwOcicQMysJxdOIia2ibujOZpChfem8ibg/640?wx_fmt=png&from=appmsg "")  
  
随后，将 .env 文件中的 PRIVATE_KEY（私钥）替换为刚生成的测试私钥。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONPnjyH1NSFpY3oYCibiaf2Us7lCaKfvEdJYpXUD4jFlEuHsibEKpMl7wnA/640?wx_fmt=png&from=appmsg "")  
  
接下来，启动恶意代码并观察服务器端接口的响应。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TON0lxw3xJ2PzmHArUnS6PAkDX3cn9OG7H3Uia6icNmSplKuTj5zjic5hlLA/640?wx_fmt=png&from=appmsg "")  
  
我们可以看到，测试服务器成功接收到了恶意项目发送的 JSON 数据，其中包含 PRIVATE_KEY（私钥）信息。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaQ8AILNAM8Y7tgXUXX8TONxyUmPwc4DibXn0cCZZLgOsSdVtsPQK68QU5CupBDjyVpq2cZICicRq0Q/640?wx_fmt=png&from=appmsg "")  
#   
# 入侵指标(IoCs)IPs：103.35.189.28Domains：storebackend-qpq3.onrender.comSHA256：07f0364171627729788797bb37e0170a06a787a479666abf8c80736722bb79e8 - pumpfun-pumpswap-sniper-copy-trading-bot-master.zipace4b1fc4290d6ffd7da0fa943625b3a852190f0aa8d44b93623423299809e48 - pumpfun-pumpswap-sniper-copy-trading-bot-master/src/common/config.rs恶意仓库：https://github.com/audiofilter/pumpfun-pumpswap-sniper-copy-trading-bot类似实现手法：https://github.com/BitFancy/Solana-MEV-Bot-Optimizedhttps://github.com/0xTan1319/solana-copytrading-bot-rusthttps://github.com/blacklabelecom/SAB-4https://github.com/FaceOFWood/SniperBot-Solana-PumpSwaphttps://github.com/Alemoore/Solana-MEV-Bot-Optimizedhttps://github.com/TopTrenDev/Raypump-Executioner-Bothttps://github.com/deniyuda348/Solana-Arbitrage-Bot-Flash-Loan总结本次分享的攻击手法中，攻击者通过伪装成合法开源项目，诱导用户下载并执行该恶意代码。该项目会从本地读取 .env 文件中的敏感信息，并将盗取的私钥传输至攻击者控制的服务器。这类攻击通常结合社会工程学技术，用户稍有不慎便可能中招。我们建议开发者与用户对来路不明的 GitHub 项目保持高度警惕，尤其是在涉及钱包或私钥操作时。如确需运行或调试，建议在独立且无敏感数据的环境中进行，避免执行来源不明的恶意程序和命令。更多安全知识可参考慢雾(SlowMist)出品的《区块链黑暗森林自救手册》：https://github.com/slowmist/Blockchain-dark-forest-selfguard-handbook/blob/main/README_CN.md  
  
**往期回顾**  
  
[慢雾：引领香港稳定币发行人合规与安全](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247502716&idx=1&sn=bca6f3e2c18e03e61d6ee3f5034bb111&scene=21#wechat_redirect)  
  
  
[慢雾受邀参加香港金管局与数码港联合主办的金融网络科技大会](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247502697&idx=1&sn=c0ab965611ffe9e0a63b660153eecdaa&scene=21#wechat_redirect)  
  
  
[130 亿资金去向成谜：鑫慷嘉 DGCX 骗局崩盘始末](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247502681&idx=1&sn=b16d2d3d09e5b4eaff4d6c712e0441b1&scene=21#wechat_redirect)  
  
  
[GMX 被黑分析：4200 万美金瞬间蒸发](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247502657&idx=1&sn=c0aeb407abb64498a698d069099ff9dd&scene=21#wechat_redirect)  
  
  
[黑客、暗网、毒品市场背后的俄罗斯服务商 Aeza Group 遭制裁](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247502618&idx=1&sn=5bb6638c4d4491a82263d06e8a361194&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaa3Th7YiamUUBwq1Iiby9N9lWh3tKP2MVjM6L3UxtTnuUy6iaegsOP2IrqZYsIBM2v3XgC5O2JTbY5g/640?wx_fmt=png&from=appmsg "")  
  
**慢雾导航**  
  
  
**慢雾科技官网**  
  
https://www.slowmist.com/  
  
  
**慢雾区官网**  
  
https://slowmist.io/  
  
  
**慢雾 GitHub**  
  
https://github.com/slowmist  
  
  
**Telegram**  
  
https://t.me/slowmistteam  
  
  
**Twitter**  
  
https://twitter.com/@slowmist_team  
  
  
**Medium**  
  
https://medium.com/@slowmist  
  
  
**知识星球**  
  
https://t.zsxq.com/Q3zNvvF  
  
