#  landNFT - Mint权限控制错误漏洞   
原创 peiqi  WgpSec狼组安全团队   2024-01-24 20:29  
  
**8点击蓝字**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4LicHRMXdTzCN26evrT4RsqTLtXuGbdV9oQBNHYEQk7MPDOkic6ARSZ7bt0ysicTvWBjg4MbSDfb28fn5PaiaqUSng/640?wx_fmt=gif "")  
  
**关注我们**  
  
  
**声明**  
  
本文作者：peiqi  
  
本文字数：1273字  
  
阅读时长：约4分钟  
  
附件/链接  
：点击查看原文下载  
  
**本文属于【狼组安全社区】原创奖励计划，未经许可禁止转载**  
  
  
由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，狼组安全团队以及文章作者不为此承担任何责任。  
  
狼组安全团队有对此文章的修改和解释权。如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经狼组安全团队允许，不得任意修改或者增减此文章内容，不得以任何方式将其用于商业目的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4LicHRMXdTzAJOBqtShvMBtBXnAYfHAuziaELxUkYo5Ta1ro6AohToV1RDuFmiaib25w2GypianXgcfVmGR4uSFAdHw/640?wx_fmt=jpeg "")  
  
  
  
> ❝  
> 2023年5月15日，landNFT 由于 Mint权限未进行正确的权限控制遭到攻击，导致大约 149,616 美元的损失  
  
## 相关地址  
  
攻击者地址: 0x96b89c2560bcc43c342c12ba9c33dab7eb571a90  
  
被攻击合约地址: 0x1a62fe088F46561bE92BB5F6e83266289b94C154  
  
攻击交易: 0x8de1921ae538264917f99f8ebd567890061d39c92a8fe58f4abd108d2373a265  
  
攻击合约地址: 0x2e599883715D2f92468Fa5ae3F9aab4E930E3aC7  
## 攻击过程  
1. 攻击者通过 mint 铸造大量 NFT  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4LicHRMXdTzDtdY411XJlLicrKAiaPQL3BGd3EwWEnNXxbuCYfq3bI2fjelKauUtJlSMQbhl9tJOX4x0wibybIyFIw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
1. 大量出售兑换代币 $XQJ  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4LicHRMXdTzDtdY411XJlLicrKAiaPQL3BGk5z41hs4CsNwLzzfzqhmUnnEsXwk2CeqZyvkYHHcz146ic89ib49pRuw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
1. 卖出后将 28,601   
兑换USDT  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4LicHRMXdTzDtdY411XJlLicrKAiaPQL3BGhvCZiaQfhQD0OHyrCsDEo6m1dHy9ZSDOkeLS1oB7l6rDibcvD3QeWu6A/640?wx_fmt=png&from=appmsg "")  
  
image.png  
1. 获利后继续 mint 直到达到铸造上限后全部兑换为 BNB 进行 Tornado 混币离场  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4LicHRMXdTzDtdY411XJlLicrKAiaPQL3BGLEH65NYbh4iaFwDbFd9hT04VZZelZTB5JQ9oPn1icqicDehEKcQGbYgibQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## 攻击分析  
  
攻击者通过调用合约 0x2e599883715d2f92468fa5ae3f9aab4e930e3ac7 中的 mint方法给自己制造了 200个NFT![](https://mmbiz.qpic.cn/sz_mmbiz_png/4LicHRMXdTzDtdY411XJlLicrKAiaPQL3BGkUuAguRO9RkiaZKAhGg9qBIQvydLib0I2Vke2vEbCH2hoAW207LOic56g/640?wx_fmt=png&from=appmsg "")  
  
```
function mint(address player,uint256 amount) external whenNotPaused() onlyMiner{
  uint256 _tokenId = totalSupply();
  require(_tokenId.add(amount)<=MAX_SUPPLY,"MAX_SUPPLY err");
  _safeMint(player, amount);
}

```  
  
跟踪交易可以发现被调用合约历史交易中也使用了 Mint 去制造 NFT，其中前两笔不为攻击者调用![](https://mmbiz.qpic.cn/sz_mmbiz_png/4LicHRMXdTzDtdY411XJlLicrKAiaPQL3BGnPeuEU7A7ZxdI9mOQkRqjqgrOURErZWd5blyrylicCpPCXOVXSQHXIg/640?wx_fmt=png&from=appmsg "")  
由于 mint 方法只有 Minner 才可以调用，这里可以在被攻击合约历史调用找到 set Minner方法![](https://mmbiz.qpic.cn/sz_mmbiz_png/4LicHRMXdTzDtdY411XJlLicrKAiaPQL3BGEm1ldfXnx7paKnkNWwZ3mekMJXD7an2J6WzziaicWgZ835icDYSO4dQcg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4LicHRMXdTzDtdY411XJlLicrKAiaPQL3BGkGFu2j9eMl61xoSWBfPRrRJibegbSbRe4J4OnTd8zVnSiaApOgrmyC5w/640?wx_fmt=png&from=appmsg "")  
其中一笔交易 0xbd5ae8c102fa7e0cca34355aadaf54cbb2cbac528ffb80cee55b748d4c127250 中
就可以发现是项目方对 0x2e5998 合约进行了方法调用授权，由于此合约中 mint 方法没有做合适的鉴权，攻击者发现后直接多次调用了该合约的 mint 方法制造了大量的NFT，直到达到铸造最大限制![](https://mmbiz.qpic.cn/sz_mmbiz_png/4LicHRMXdTzDtdY411XJlLicrKAiaPQL3BGQ02YmnvqCsaT61VZjTCTFfYfYURqT1Q2oGFDuA3MxuSHibRITjxM7iaQ/640?wx_fmt=png&from=appmsg "")  
  
  
欢迎研究区块链安全的师傅一起加入团队学习~  
  
**作者**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4LicHRMXdTzCQzoBmkPY46qUlfZGYG6056ZUGtMYvMZqa9NgPuXibLZYfF9xMYaE5bRFTuZeR9qm9mOibIbGZ1VMg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
PeiQi  
  
今天又是摸鱼的一天！  
  
  
  
**扫描关注公众号回复加群**  
  
**和师傅们一起讨论研究~**  
  
**长**  
  
**按**  
  
**关**  
  
**注**  
  
**WgpSec狼组安全团队**  
  
微信号：wgpsec  
  
Twitter：@wgpsec  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/4LicHRMXdTzBhAsD8IU7jiccdSHt39PeyFafMeibktnt9icyS2D2fQrTSS7wdMicbrVlkqfmic6z6cCTlZVRyDicLTrqg/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/gdsKIbdQtWAicUIic1QVWzsMLB46NuRg1fbH0q4M7iam8o1oibXgDBNCpwDAmS3ibvRpRIVhHEJRmiaPS5KvACNB5WgQ/640?wx_fmt=gif "")  
  
  
  
