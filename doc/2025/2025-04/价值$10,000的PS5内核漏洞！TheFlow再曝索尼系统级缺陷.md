#  价值$10,000的PS5内核漏洞！TheFlow再曝索尼系统级缺陷   
原创 骨哥说事  骨哥说事   2025-04-21 06:37  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4186  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlibvZLL7ZdzjgEiavhv7EGHRZldJc2x48DzaABt3LWoNEHIrn3EDR5zOqh5dib8l43iaGC1gtQPLlZfg/640?wx_fmt=png&from=appmsg "")  
  
# 前言  
  
白帽 TheFlow 通过漏洞平台 HackerOne 披露了一项新的 PS5 内核漏洞。这是一次全面的披露（尽管没有实际的 PoC 代码），因此假设该漏洞由用户模式被发现，这可能会给寻求越狱的 PS5 用户带来“光明的未来”。  
  
由于该漏洞的提交日期，它被认为可以在固件 10.40 之前使用，但这还有待确认。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlibvZLL7ZdzjgEiavhv7EGHRvsyBXs0vqqiaYyAgOZhNFk0U5ybpbIWm0T4eC7Rw8VQa56L4bQaqUBg/640?wx_fmt=png&from=appmsg "")  
  
尽管如此，一些黑客还是建议对此保较低的期望值，并表示该漏洞实际上可能无法被利用。  
# PS5 内核漏洞即将到来，主要针对固件 10.40？  
  
PS4 和 PS5 只能在相当老的固件“越狱”已经有一段时间了，虽然这似乎已经成为 PlayStation 设备的规则（因此，尽早购买游戏机并从第一天起就使用低固件的建议仍然是 PlayStation 领域最有效的建议），但这也让很多用户感到沮丧。  
  
由于 umtx 漏洞和最近将 etaHEN 移植到这些 "较新 "的固件上，7.61 及以下的固件有了明显改善，但是直到目前为止， 7.61 以上的固件几乎全都没戏。  
  
TheFlow 在 2024年12月（大约4个月前）在PS5上提交了一份漏洞报告。尽管最终是否公开利用漏洞由 PlayStation 和黑客共同决定，但过去TheFlow（以及值得赞扬的PlayStation）一直热衷于与社区分享他的工作。  
  
众所周知，当漏洞被揭露时，最新的PS5固件已将漏洞修复。资深人士 Zecoxao 猜测，考虑到提交日期为 2024/12/15，固件 10.40（及以下所有固件）可能会受到影响，而 10.60 可能会修复漏洞。  
# sys_fsc2h_ctrl中的PS5内核漏洞  
  
以下来自 HackerOne 上的原始披露信息：  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlibvZLL7ZdzjgEiavhv7EGHRKYVR4F04qJBX1alhYqe6d8F9mS1EbU0IMBUNzNyEOlLXGibCIp4vRYA/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞最终获得 $10,000 美金的赏金奖励。  
  
- END -  
  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
