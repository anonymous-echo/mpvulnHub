#  开源库漏洞导致多个NFT集合面临风险   
Bill Toulas  代码卫士   2023-12-06 17:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Web3 领域中常见的某开源库中存在一个漏洞，影响预构建智能合约的安全性，多个 NFT 集合如 Coinbase 受影响。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSEel0PLhibXCxdeCNujFYmp938ic5T659hibRMiaefLxeGYe12hk1B2ic8gMy8EE1TGicPNBIicAYxsYSew/640?wx_fmt=gif&from=appmsg "")  
  
  
今天，Web3 开发平台 Thirdweb 披露了该漏洞非常少的详情，而一些客户希望获得更多消息以保护合约安全。Thirdweb 表示在11月20日注意到该漏洞并在两天后推出了修复措施，但并未透露该开源库的名称以及该漏洞的类型和严重性以防遭攻击者利用。  
  
Thirdweb 表示，已联系该易受攻击库的维护人员并告知其它协议和组织机构，与它们共享了研究发现和缓解措施。  
  
如下智能合约受该漏洞影响：  
  
- AirdropERC20（v1.0.3 及后续版本）、ERC721（v1.0.4 及后续版本）、ERC1155（v1.0.4 及后续版本）ERC20Claimable、ERC721Claimable、ERC1155Claimable。  
  
- BurnToClaimDropERC721（所有版本）  
  
- DropERC20, ERC721, ERC1155（所有版本）  
  
- LoyaltyCard  
  
- MarketplaceV3（所有版本）  
  
- Multiwrap, Multiwrap_OSRoyaltyFilter  
  
- OpenEditionERC721（v1.0.0 及后续版本）  
  
- Pack and Pack_OSRoyaltyFilter  
  
- TieredDrop（所有版本）  
  
- TokenERC20, ECRC721, ERC1155（所有版本）  
  
- SignatureDrop, SignatureDrop_OSRoyaltyFilter  
  
- Split（影响程度低）  
  
- TokenStake, NFTStake, EditionStake（所有版本）  
  
  
  
Thirdweb 解释称，“如果你使用的是我们的 Solidity SDK 扩展基本合约或构建自定义合约，我们认为该漏洞不会扩展到你的合约”，不过补充表示但不能完全保证，因为他们“无法审计个人合约”。该公司已经与受影响库的维护人员沟通了利用详情并表示并未看到漏洞遭利用的情况。  
  
  
**0****1**  
  
**用户因缺乏透明度而沮丧**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSEel0PLhibXCxdeCNujFYmpzCB8pWpD0DyN1FtJBiby7zWBwAOJwZ86jJkObfbRk6yJs2Gc6icTc2Yg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
由于未提供漏洞详情，一些用户要求进行澄清或猜测该漏洞与 Thirdweb 对该库的实现存在关联。一名用户抱怨称，由于缺乏透明度，要求获得漏洞的CVE编号并要求解释缓解措施如何起作用。  
  
  
**0****2**  
  
**锁定易受攻击的合约**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSEel0PLhibXCxdeCNujFYmpzCB8pWpD0DyN1FtJBiby7zWBwAOJwZ86jJkObfbRk6yJs2Gc6icTc2Yg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
Thirdweb 表示智能合约拥有者必须立即采取缓解措施，保护所有在太平洋时间2023年11月22日下午7点之间创建的预构建合约。  
  
该平台建议锁定易受攻击的合约，之后将其迁移到通过非易受攻击库版本创建的新合约。该平台提供了缓解受影响合约的专门工具和手册。  
  
Thirdweb表示将提供补发gas 补助来覆盖合约缓解成本，但用户必须首先填写一张表单且获得批准才能获得。  
  
漏洞导致NFT的持有者担忧，大型NFT交易平台已对此做出相应。Coinbase NFT 在本周一发布公告指出，在上周五获悉该漏洞，通过 Thirdweb 创建的某些集合受影响。该平台提到，“Coinbase 本身不受该漏洞影响，Coinbase 上的所有资金都是安全的。”  
  
用于智能合约开发的OpenZeppelin 库维护人员也收到该漏洞的通知，该漏洞影响 Thirdweb 的 DropERC20、ERC721、ERC1155（所有版本）和 AirdropERC20 预构建合约。OpenZeppelin 表示，“从我们的调查情况来看，该漏洞是因为对特定模式的集成存在问题造成的，而不是因为 OpenZeppelin Contracts 库中包含的实现造成的。”  
  
Animoca Brands 生态系统的会员 NFT 集合也向用户表示，他们的资产是安全的，平台已“成功升级了 Mocaverse NFT、Lucky Neko 和 Mocaverse Relic 集合智能合约，以解决相关的安全漏洞。”  
  
本周二，Mocaverse 完成所有可能的缓解措施后，向 Animoca Brands 子公司说明了潜在风险，让它们采取必要措施，保护用户资产安全。该公司表示，“对于无法升级的合约，包括 Realm Ticket 和 Honorary Collection，我们已经锁定相关合约并截屏所有数据，后续将允许原始持有人基于之前的持有情况，在一个新的无已知漏洞的智能合约上，通过 Thirdweb 声明对 NFT 的所有权。”  
  
同样，OpenSea 也宣布称正在与 Thirdweb 密切合作，缓解所涉及的风险并将计划协助受影响用户。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开源文件共享软件 ownCloud 中存在3个严重漏洞，可导致信息泄露和文件修改](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518225&idx=1&sn=0012c60dceb2dbcc1beeb94a8a38d402&chksm=ea94b97bdde3306d13ff1ee130bc1d5387971ace02890354fb0bcf9e7f6268f934440725ab63&scene=21#wechat_redirect)  
  
  
[开源云软件 CasaOS 中存在两个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517920&idx=1&sn=681d0c6677cad099a71c676242ba72f4&chksm=ea94b78adde33e9cfd5d18cd2b56dca916c908ab7b190ab9985975c9146af878a0fe5d5b63bb&scene=21#wechat_redirect)  
  
  
[开源库 libcue 中存在内存损坏漏洞，Linux 系统易遭RCE攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517824&idx=1&sn=6df44200db86a65be854d61f6381c0d1&chksm=ea94b7eadde33efce252efadf68c91a111b687f5fcb1b12f82af144a5e10a0b3fefb9eea342e&scene=21#wechat_redirect)  
  
  
[开源代码库 TorchServe 中存在多个严重漏洞，影响大量AI模型代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517813&idx=3&sn=2547a20df3df5050c23af50502f6658d&chksm=ea94b71fdde33e096c89bb979a25dd92138a4c04cf1cc21a96d87a7906ddd2cbe7f03fd8ff5e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/multiple-nft-collections-at-risk-by-flaw-in-open-source-library/  
  
  
题图：  
Pixabay  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
