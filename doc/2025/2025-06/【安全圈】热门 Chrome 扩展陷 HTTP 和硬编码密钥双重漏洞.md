#  【安全圈】热门 Chrome 扩展陷 HTTP 和硬编码密钥双重漏洞  
 安全圈   2025-06-07 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
![可用- Chrome](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhAjbiaATZKkd97aY46PjkJkPmiagq5noddlvCGrWLDicicOXRv6l8ibXUdceT4TegQQGTxZEOe0iaLbQ0A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
网络安全研究人员发现多款热门谷歌Chrome扩展存在严重安全隐患：**通过HTTP明文传输数据并在代码中硬编码密钥，导致用户隐私与安全面临风险。**  
赛门铁克安全技术响应团队研究员指出：“数款广泛使用的扩展通过未加密的HTTP协议传输敏感数据，以明文形式暴露浏览域名、设备ID、操作系统信息、使用分析数据乃至卸载记录。”  
  
  
这种未加密的网络流量使其极易遭受中间人攻击（AitM）。恶意攻击者可在公共Wi-Fi等开放网络中拦截甚至篡改数据，引发更严重后果。以下为存在风险的扩展清单：  
  
  
**HTTP传输漏洞扩展**  
  
****- **SEMRush Rank**  
（ID: idbhoeaiokcojcgappfigpifhpkjgmab）与**PI Rank**  
（ID: ccgdboldgdlngcgfdolahmiilojmfndl）：通过HTTP调用“rank.trellian[.]com”  
  
- **Browsec VPN**  
（ID: omghfjlpggmjjaagoclmmobgdodcjboh）：卸载时通过HTTP访问卸载链接  
  
- **MSN新标签页**  
（ID: lklfbkdigihjaaeamncibechhgalldgl）与**MSN主页、必应搜索与新闻**  
（ID: midiombanaceofjhodpdibeppmnamfcj）：通过HTTP向“g.ceipmsn[.]com”发送设备唯一标识符  
  
- **DualSafe密码管理器与数字保险库**  
（ID: lgbjhdkjmpgjgcbcdlhkokkckpjmedgc）：向“stats.itopupdate[.]com”发送含扩展版本、浏览器语言等信息的HTTP请求  
  
  
研究人员特别指出：“密码管理器使用未加密请求传输遥测数据，严重削弱用户对其安全性的信任。”  
  
  
**硬编码密钥风险扩展**  
  
****- **Online Security & Privacy**  
（ID: gomekmidlodglbbmalcneegieacbdmki）、**AVG Online Security**  
（ID: nbmoafcmbajniiapeidgficgifbfmjfo）等：暴露Google Analytics 4密钥，攻击者可伪造数据推高分析成本  
  
- **Equatio数学工具**  
（ID: hjngolefdpdnooamgdldlkjgmdcmcjnc）：嵌入Azure语音识别API密钥，可能导致开发者服务费用激增  
  
- **Awesome截屏工具**  
（ID: nlipoenfbbikpbjkfpfillcgkoblgpmj）等：泄露AWS S3访问密钥，攻击者可非法上传文件  
  
- **Microsoft Editor编辑器**  
（ID: gpaiobkfhnonedkhhfjpmhdalgeoebfa）：暴露遥测密钥“StatsApiKey”  
  
- **Antidote Connector**  
（ID: lmbopdiikkamfphhgcckcjhojnokgfeo）：第三方库InboxSDK含硬编码API密钥（影响超90款扩展）  
  
- **Trust Wallet钱包**  
（ID: egjidjbpglichdcondbcbdnbeeppgdph）：泄露法币通道API密钥，可伪造加密货币交易  
  
攻击者利用这些密钥可能造成API服务费用暴涨、托管非法内容、伪造遥测数据等后果，甚至导致开发者账户被封禁。  
  
  
研究人员强调：“从GA4密钥到Azure语音密钥，这些案例证明几行代码足以危及整个服务。核心解决方案是永远不要在客户端存储敏感凭证。”开发者应采取三项关键措施：  
1. 全面启用HTTPS数据传输  
  
1. 通过凭证管理服务在后端服务器安全存储密钥  
  
1. 定期轮换密钥以降低风险  
  
  
赛门铁克警告用户：“此类风险绝非理论假设——未加密流量极易被截获，数据可能用于用户画像分析、钓鱼攻击等定向攻击。建议立即卸载存在不安全调用的扩展程序，直至开发者完成修复。”该事件揭示关键教训：**安装量或品牌知名度无法等同于安全实践水平，用户需严格审查扩展程序的协议类型与数据共享行为。**  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】阿里云 aliyuncs.com 域名故障导致全国网站访问异常](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070040&idx=1&sn=2607d571d2383520da9725b92d2c9691&scene=21#wechat_redirect)  
  
  
  
[【安全圈】智能车配“弱密码”？汽车行业数字安全仍靠“123456”](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070040&idx=2&sn=8904aae2ff9e441f73a8a7b245343346&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑吃黑！Sakura RAT 事件揭示黑客如何反过来“猎杀”黑客](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070040&idx=3&sn=6f39cd3deaa334ac8f086297d9638069&scene=21#wechat_redirect)  
  
  
  
[【安全圈】暗网惊现近940亿被盗Cookie，15.6亿仍活跃，用户隐私岌岌可危](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070040&idx=4&sn=fcf135aec1bd656b6d4b0c94bf5356b5&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
