> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070304&idx=4&sn=d05ca470ff70ce11963e9e3c7ec01d72

#  【安全圈】严重安全警报：OpenVPN Windows 驱动曝缓冲区溢出漏洞，可致系统崩溃  
 安全圈   2025-06-23 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgfoMl2ZvrKj9nGG9Se3VA6wfjibk3qWA5r5RZtdAevdZpGh75f3gfY0B7KktF7b5ibTvXcianooLVjQ/640?wx_fmt=png&from=appmsg "")  
  
OpenVPN 在 Windows 系统上的核心驱动程序 ovpn-dco-win 被发现存在严重缓冲区溢出漏洞，编号为 CVE-2025-50054。攻击者可在本地以普通用户权限向该驱动发送特制控制消息，触发堆溢出，导致整个系统崩溃。这一漏洞已对广泛使用 OpenVPN 的企业和个人用户构成实际威胁。  
  
漏洞影响 OpenVPN 2.5.8 及之前版本，以及 ovpn-dco-win 1.3.0 及更早版本。该驱动自 OpenVPN 2.6 起成为默认组件，因此很多用户可能在不知情的情况下已受影响。研究人员指出，漏洞可被滥用于持续制造系统宕机，实现拒绝服务攻击。  
  
OpenVPN 社区已发布 2.7_alpha2 版本以修复该问题，虽然该版本仍处于测试阶段，但已集成安全补丁。此次漏洞涉及的 ovpn-dco-win 驱动是为了提升 VPN 性能而开发的新一代内核驱动，其设计初衷是减少用户态与内核态之间的数据往返。但正因为运行在内核层，其一旦被利用，后果也更为严重。  
  
该版本还引入了多个架构优化，并默认淘汰了旧版 wintun 驱动，以 win-dco 取而代之。OpenVPN 官方建议用户尽快关注更新信息，在稳定版本发布后立即升级。当前未能升级的用户应临时采取防护措施，例如限制本地用户访问 VPN 驱动接口，以降低风险。  
  
专家提醒，此类系统级漏洞即便不涉及数据泄露，也具有极高的业务中断风险，特别是部署在生产服务器或远程办公环境中的系统应特别关注此次事件。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】你的Linux服务器被攻击进行加密货币挖矿了吗？](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070290&idx=1&sn=39ba9b19bf5bcdc7d844c9aa8c7f88a5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】德国纸巾制造商Fasana遭勒索攻击后宣布破产](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070290&idx=2&sn=136b4197d4d49e8341348d4eccfc0256&scene=21#wechat_redirect)  
  
  
  
[【安全圈】隐私浏览器DuckDuckGo升级内置的网络诈骗防护工具](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070290&idx=3&sn=3427cd91bcb2916d06333f759353f219&scene=21#wechat_redirect)  
  
  
  
[【安全圈】间谍冒充研究生用Word套取我国敏感数据，“简历”竟暗藏木马可轻易控制计算机](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070277&idx=1&sn=e46548b3194ed85c4bacbf48055dd744&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
