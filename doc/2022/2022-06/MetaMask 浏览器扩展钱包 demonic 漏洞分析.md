#  MetaMask 浏览器扩展钱包 demonic 漏洞分析   
原创 慢雾安全团队  慢雾科技   2022-06-17 17:31  
  
By：Thinking@慢  
雾安全团队  
  
  
**背景概述**  
  
  
2022 年 6 月 16 日，  
MetaMask（MM  
）官方  
公布白帽子发现的一个被称为   
demonic vulnerability  
（恶魔漏洞  
）  
的安全问题，漏洞影响的版本 < 10.11.3，由于   
MM   
的用户体量较大，且基于   
MM   
进行开发的钱包也比较多，所以这个漏洞的影响面挺大的，因此   
MM   
也慷慨支付了白帽子 5 万刀的赏金。  
当团队向我同步了这个漏洞后，我开始着手对这个漏洞进行分析和复现。  
  
  
**漏洞分析**  
  
  
白帽子将这个漏洞命名为 demonic vulnerability，具体的漏洞描述比较复杂，为了让大家更好的理解这个问题，我尽可能用简单的表述来说明这个问题。在使用 MM 浏览器扩展钱包导入助记词时，如果点击"Show Secret Recovery Phrase"按钮，浏览器会将输入的完整助记词明文缓存在本地磁盘，这是利用了浏览器本身的机制，即浏览器会将 Tabs 的页面中的 Text 文本从内存保存到本地，以便在使用浏览器的时候可以及时保存页面的状态，用于下次打开页面的时候恢复到之前的页面状态。  
  
  
基于对这个漏洞的理解，我开始进行漏洞复现，由于 MM 仅对这个漏洞进行简要的描述并不公开漏洞细节，  
所以在复现的时候遇到了如下的问题：  
  
  
1. 缓存被记录到磁盘中的文件路径未知  
  
2. 缓存何时被记录到磁盘未知  
  
  
为了解决问题 1，我开始对浏览器的缓存目录结构进行分析和测试，发现在使用浏  
览器 (chrome) 的时候相关的 Tabs 缓存是记录到了如下的目录：  
  
  
Tabs 缓存路径：  
  
/Users/$(whoami)/Library/Application Support/Google/Chrome/Default/Sessions/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZ3U7cOlyjdfeVjrgreEUTTvJmRUL0kfAORP349Iz9nsOBjERFpEx9ibdpTPvgvfMYMLRAP1iaIBAdw/640?wx_fmt=png "")  
  
  
然后继续解决问题 2：Sessions 目录会记录 Tabs 的缓存，为了找出缓存被记录的时间节点，我对导入助记词的整个流程进行了分解，然后在每一步操作之后去观察 Sessions 的数据变化。发现在如下这个页面输入助记词数据后，需要等待 10 - 20s，然后关闭浏览器，明文的助记词信息  
就会被记录到 Sessions   
缓存数据中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLZ3U7cOlyjdfeVjrgreEUTTaYk2UCkO6w0CzxiapSkIQCBoxjJmRaYE3Z7ZnC2icUDnfTw4ATLibtKibQ/640?wx_fmt=png "")  
  
  
如下是复现的视频：  
  
  
  
**分析结论**  
  
  
用户正常在使用 MM 的时候是将助记词相关的数据放入内存中进行存储，一般认为是相对较为安全的（在早前慢雾的 Hacking Time 中，我发现在用户正常使用 MM 的时候是可以通过 hook 技术将明文的助记词提取出来，仅限于用户电脑被恶意程序控制的情况下可以被利用  
），但是由于 demonic vulnerability 这个漏  
洞导致助记词会被缓存到本地磁盘，因此就会有如下的新的利用场景：  
  
  
1. 明文的助记词数据缓存在本地磁盘，可以被其他应用读取，在 PC 电脑中很难保证其他应用程序不去读取 Sessions 缓存文件。  
  
2. 明文的助记词数据缓存在本地磁盘，如果磁盘未被加密，可以通过物理接触恢复助记词。比如在类似维修电脑等场景下，当他人对电脑进行物理接触时可以从硬盘中读取助记词数据。  
  
  
**作为普通用户，如果你使用过 MetaMask Version < 10.11.3，且在导入助记词的时候点击了 Show Secret Recovery Phrase，那么你的助记词有可能泄露了，可以参考 MetaMask 的文章对磁盘进行加密并更换钱包迁移数字资产。作为扩展钱包项目方，如果采用了在 Tabs 页面中以 Text 的方式输入助记词导入钱包，均受到 demonic vulnerability 漏洞的影响，可以参考 MetaMask Version >=10.11.3 的实现，为每个助记词定义单独的输入框，并且输入框的类型为 Password。慢雾安全团队已经协助多家扩展钱包项目方进行漏洞检测并引导修复漏洞，如果你需要协助检测 demonic vulnerability，请联系慢雾安全团队。**  
  
  
**参考链接**  
：  
  
https://medium.com/metamask/security-notice-extension-disk-encryption-issue-d437d4250863  
  
  
**往期回顾**  
  
[](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495722&idx=1&sn=549f60d14755634fd32c9e7a41a64774&chksm=fdde8eadcaa907bb16d75cdcffb1788467ec7845aa506f785a66ff10276cdd954a10bf7cb793&scene=21#wechat_redirect)  
[MetaMask 浏览器扩展钱包 Clickjacking 漏洞分析](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495743&idx=1&sn=1f9a4053fa85204ca395a5a42775bf1e&chksm=fdde8eb8caa907aea195f6ca1b33b1954628c6129f19e49ad18f4995cb0d791eb5b5be7ad2ba&scene=21#wechat_redirect)  
  
  
[2000 万 OP 代币被盗关键：交易重放](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495732&idx=1&sn=bb707c74e5724a603fc4b59296c2d92e&chksm=fdde8eb3caa907a54be4e62e86795007fb358e945ccbd10603c3a5c6fee0e153d90df2c4cdea&scene=21#wechat_redirect)  
  
  
[慢雾 AML 与 Go+ Security 达成合作，为反洗钱再增力量](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495722&idx=1&sn=549f60d14755634fd32c9e7a41a64774&chksm=fdde8eadcaa907bb16d75cdcffb1788467ec7845aa506f785a66ff10276cdd954a10bf7cb793&scene=21#wechat_redirect)  
  
  
[慢雾：NFT 项目 verb 钓鱼网站分析](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495709&idx=1&sn=5737e7d6d39e5cdb00b6e791d8ab550a&chksm=fdde8e9acaa9078c70334ba29089b7685c13f168e79fd29f4ff529bd6bfdcfe50f1dc7eff251&scene=21#wechat_redirect)  
  
  
[慢雾：29 枚 Moonbirds NFT 被盗事件溯源分析](http://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247495688&idx=1&sn=2f11b51775fb3ee188d203c69a27164d&chksm=fdde8e8fcaa907990f04516c615b0dd637532bbaeefcf6fd7c9eb4a26006de0c2a8aef455e86&scene=21#wechat_redirect)  
  
  
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
  
