#  【安全资讯】攻击者利用 TunnelVision 漏洞暴露用户数据   
GuardCyberSec  信息安全ISecurity   2024-05-09 00:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/C6Ge5dDibEBq1ibwbHuxHEEcHmVe3tzd30oYaianWSx2E0KheazdiaC8lZib3qtdmU8Ex2U1a70aoJuJmDJib9mc65xA/640?wx_fmt=gif&from=appmsg "")  
  
  
点击上方蓝字·关注我们  
  
  
  
  
  
互联网上出现了一个新的VPN漏洞，损害了在线隐私和数据保护的本质。 自 2002 年以来潜伏在 VPN 应用程序中的 TunnelVision 漏洞  
有可能使 VPN 连接变得无用，使用户容易受到恶意行为者的数**据拦截和窥探。**  
  
  
INSPIRATION  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/C6Ge5dDibEBrLNL961tRcSxWiaqWUrdwZDBzUIRr2Zpt3fwSXSp9FGS3hGDmXQ6Iyiayq91IdGV6w1ZeicZ1L91Emg/640?wx_fmt=other&from=appmsg "")  
  
  
TunnelVision 漏洞代表了一种破坏 VPN 加密的复杂方法，允许攻击者拦截和窥探未加密的流量，同时伪装成安全的 VPN 连接。  
  
Leviathan Security 在一份综合报告中详细介绍了此漏洞的出现，突出了对动态主机配置协议 （DHCP） 中长期存在的漏洞的利用，特别是针对选项 121（一种用于在客户端系统上配置静态路由的机制）。  
### 解码 TunnelVision 漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/C6Ge5dDibEBrLNL961tRcSxWiaqWUrdwZD5NEYy7efWzwgjg43NQGwdn6IZZHSlWLfEleSQF5b8f9YovRcsM0oIg/640?wx_fmt=other&from=appmsg "")  
  
来源：Leviathan 的 TunnelVision 漏洞利用过程  
  
攻击者的作案手法涉及设置恶意DHCP服务器，这些服务器战略性地定位为拦截VPN流量。通过操纵路由表，所有 VPN 绑定的数据都会从加密隧道中转移出去，使其暴露在本地网络或恶意网关上的拦截中。  
  
Leviathan Security的报告揭示了一种被称为“去隐身”的现象，即VPN流量被剥夺了加密，使其容易受到拦截。尽管存在 VPN 控制通道和终止开关，但这些防御措施被证明对 TunnelVision 无效，使用户没有意识到漏洞及其数据暴露。  
  
这个VPN漏洞的影响是深远的，特别是对于依赖VPN进行敏感通信的个人，如记者和举报人。需要采取紧急措施来解决此问题并保护 VPN 连接的完整性。  
### TunnelVision VPN 漏洞缓解措施  
  
建议的解决方案包括采用网络命名空间，这是已知协议用来缓解类似漏洞的一种技术。通过隔离接口和路由表，网络命名空间为保护 VPN 流量免遭拦截提供了一种很有前途的途径。  
  
了解 DHCP、VPN 和网络的底层机制对于全面了解 TunnelVision 的影响至关重要。DHCP 最初设计用于动态分配 IP 地址，现在充当攻击者利用 VPN 连接漏洞的网关。  
  
此外，DHCP 选项 121 路由的实施为攻击者操纵路由表和破坏 VPN 安全性开辟了途径。缓解工作必须优先考虑识别和纠正这些漏洞，以确保 VPN 在保护用户数据方面持续有效。  
  
TunnelVision的影响超出了地理位置，因为它能够公开来自几乎任何可以访问互联网连接的国家的数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/C6Ge5dDibEBruzf1dRUPjaicXsFSCV6KN0SEt0AyxFplPENcROnN6WtToLicpWzZWsYVq9Z5MRSGUMcGJU9rOHAMg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
*文章消息参考来源：  
Decoding The TunnelVision Vulnerability, Targeting VPN Users (thecyberexpress.com)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4oz4PGldsrkljIia1cATYDQTq2Sald0SWtAribBKqM0Hdk1uXXAL2rpGoMsK4oZlX7aw88ib2MicteLff09DwmhNA/640?wx_fmt=png "")  
  
   
**安全资讯推荐****往期发布文章**  
****![](https://mmbiz.qpic.cn/mmbiz_png/f4oz4PGldsrkljIia1cATYDQTq2Sald0SWtAribBKqM0Hdk1uXXAL2rpGoMsK4oZlX7aw88ib2MicteLff09DwmhNA/640?wx_fmt=png "")  
  
  
  
 **安全资讯**  
**推荐**  
********  
  
- [【Linux运维】Linux基础运维知识导图](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485276&idx=1&sn=99836b4a9984c5957b890d53085f4a4f&chksm=eb38ce85dc4f47938a70c484c3a69554259e6d898d234577aa00d6b2146f142531cac96a64e3&scene=21#wechat_redirect)  
  
  
- [【技术沉淀】如何使用 Windows 注册表编辑器](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485276&idx=4&sn=9bd5304c34f24bba3b00f6c2d4f37712&chksm=eb38ce85dc4f479366464cc6d96bc30b3c91b6a0adaff053f882a30f48fb48d19f63a9ecdbb8&scene=21#wechat_redirect)  
  
  
- [【网络安全】构建安全高效的全球供应链：策略、挑战与未来方向](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485166&idx=1&sn=6642fb2cd803b8746960ce48864a6260&chksm=eb38cf37dc4f4621ba36f2c8bd3aad8d749dc8f96a340291fec30e0c4d3765c8846048dc5929&scene=21#wechat_redirect)  
  
  
- [【网络安全】网络安全运维实施指南征求意见：构建稳固的数字防线](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485073&idx=1&sn=55aae92e37d0e3da862c7eebca29dcf9&chksm=eb38cf48dc4f465eac38fb417d0766c45c712bea09df09271d656f0625256ffbd967ba7b47e1&scene=21#wechat_redirect)  
  
  
- [【网络安全】全面防御：攻击面管理的策略与实践（三）](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485031&idx=1&sn=57b4200bac5ae985612c554a2fb7a0d2&chksm=eb38cfbedc4f46a8a1ca8fac87fc76fc6fbaea802f26da43519c31674a84054ae14a5679a334&scene=21#wechat_redirect)  
  
  
- [【网络安全】全面防御：攻击面管理的策略与实践（二）](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485008&idx=1&sn=566983f507da8d8e3912b3c154196d6c&chksm=eb38cf89dc4f469f8b4bc7b24d88f8861d5b00f78f064d63d22d57598668e5aa477410e9c79e&scene=21#wechat_redirect)  
  
  
- [【网络安全】全面防御：攻击面管理的策略与实践（一）](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484943&idx=1&sn=336df236ce7b87a60e6ff36bd06830f8&chksm=eb38cfd6dc4f46c00936b57b7ee2e2930c991ff2f12029ffab79a11397c90e36053a4c6eee9b&scene=21#wechat_redirect)  
  
  
- [【网络安全】威胁情报：网络安全的先知盾](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484912&idx=1&sn=f2d25f46cc807e2ac843c4b756538502&chksm=eb38cc29dc4f453f88de335568f088336bb56ce9f900fb5acafc22e6e0b5e6e3f792e7d717bb&scene=21#wechat_redirect)  
  
  
- [重庆市科技创新：现代化产业体系建设的驱动力与未来展望](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484814&idx=1&sn=db87075a73323bdfbec215f241b444a3&chksm=eb38cc57dc4f4541a066535e39e7acb07ed34d9a852717fd1d4dbe00ceb3f96b4eabf137d379&scene=21#wechat_redirect)  
  
  
- [【数字技术】智慧医院信息化建设：实践路径与关键要素](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484762&idx=1&sn=9eeb44aea5857673b91a20eb7b8e0594&chksm=eb38cc83dc4f45955472283128a01efcbdf8f5e700426f0ca2e32e6f84f414a5e4173c5bb823&scene=21#wechat_redirect)  
  
  
- [【数字技术】Xen和KVM等四大虚拟化架构对比分析](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484762&idx=2&sn=4d1a059a93b3108d3008ec9e15ab8673&chksm=eb38cc83dc4f45953f910053fb8df226dc7f7b1ce9c4cfac2166e4ae6b21fad88b2729a0d783&scene=21#wechat_redirect)  
  
  
- [【网络安全】信息安全：当隐私成为奢侈品](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484660&idx=1&sn=fa8ab2fa399e877820110b51016eb957&chksm=eb38cd2ddc4f443baf2aec603ff1e9fe67d07d3bc24cbc08e019b44c7a890a2088a52b3a2c4a&scene=21#wechat_redirect)  
  
  
- [【数字技术】微服务架构深度解析与未来趋势预测](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484528&idx=1&sn=bf6a0d7f6d6f242b56024db755a48015&chksm=eb38cda9dc4f44bf15b0e69ed3b795716ab450a27c9e402927d0484ac079980d7cb0be8535fd&scene=21#wechat_redirect)  
  
  
- [【数字技术】云原生技术：企业数字化转型的加速器与未来展望](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484437&idx=1&sn=9e9f8596bed10a498557103a91e0bbad&chksm=eb38cdccdc4f44da317765cc6a545d7fb1c3f50836c7c65f112fe713a0d22d4997c89608f17f&scene=21#wechat_redirect)  
  
  
- [【重大里程碑】四问+一图了解新成立的信息支援部队](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484395&idx=1&sn=307233af1695e5949012d86dfdd51a9a&chksm=eb38ca32dc4f4324b88acc3f7018ea73044bcead1709ed49a0f019a98112271efbce55d407c4&scene=21#wechat_redirect)  
  
  
- [【重大里程碑】中国人民解放军信息支援部队成立：新时代网络强军的重要里程碑](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484385&idx=1&sn=1e062fdff9558ec04dc03341ff37329b&chksm=eb38ca38dc4f432e0841dd1032bed2bcea640ecf48fb0ab15391c3c260624a1886306b941920&scene=21#wechat_redirect)  
  
  
- [【安全资讯】全球网络部队建设情况概览](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484385&idx=2&sn=ec98921df5f9d47722bd482be4cee7e1&chksm=eb38ca38dc4f432ee695ae57ca2363c43b53332e60d923d0cdcf49e91ff906c63b669f4decbe&scene=21#wechat_redirect)  
  
  
- [【网络安全】构建安全防线：企业与技术人员在网络安全法律法规中的角色与责任](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484315&idx=1&sn=a301abcfbf235a6b901ade4ea062c8de&chksm=eb38ca42dc4f4354e889057200ddbf1623ba7e517309432d5e2ac4e3d13f505cc70612bfb623&scene=21#wechat_redirect)  
  
  
- [【智慧医疗】智慧医疗时代的数据安全挑战：信息化建设的创新与对策](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484227&idx=1&sn=80b3e9779ddef2a076a360f407e07e19&chksm=eb38ca9adc4f438c34e695b799d4c4117f430e7cd7f734647a2b7db04a01cd7fdc0c52c8e813&scene=21#wechat_redirect)  
  
  
- [【网络安全】《中国网络安全行业全景图（第十一版）》深度解析](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484226&idx=1&sn=a607d675905fe721bbca857741fe66bd&chksm=eb38ca9bdc4f438dbd9181648425b771294e2a6c44449ad28ca4c4a95e5f2d9e3e266760e724&scene=21#wechat_redirect)  
  
  
- [【安全运营】构建坚不可摧的防线：常态化攻防及运营体系的全面构建与实施](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484112&idx=1&sn=7247a95b23a6860918a92b8f81a18bf4&chksm=eb38cb09dc4f421fce56c48b9a68c8d404095d6d7488f1b959fa79756e713bd0ff75ee1234cd&scene=21#wechat_redirect)  
  
  
- [【数据运营】精通数据资产管理：策略、实践与未来展望（修改）](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484112&idx=3&sn=49f44ef556db33b794600170038f57d6&chksm=eb38cb09dc4f421f89e7b2be247cd19d98f9dda5858b6753f37e56d58b731e463e26facd08ba&scene=21#wechat_redirect)  
  
  
- [【数据安全】数据安全新篇章：解析《数据安全技术 数据分类分级规则》GB/T 43697-2024](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484085&idx=2&sn=02be34c866019402b512feaa40304270&chksm=eb38cb6cdc4f427a4ef9aaedc2b7e0b07caede06c9f54123bc0ddb5ae299e794917aa263c037&scene=21#wechat_redirect)  
  
  
- [【安全资讯】伊朗黑客冒充记者推送后门恶意软件](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485276&idx=2&sn=0a10d1f1a4db95c4e25d2310f924d1d5&chksm=eb38ce85dc4f47935279309adbd6490f86844d3295935c3889de71cd7e3355aadc53038c5ae1&scene=21#wechat_redirect)  
  
  
- [【安全资讯】芬兰警告Android恶意软件攻击破坏银行账户](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485276&idx=3&sn=18c5944c37cc65fc22185b85c0624948&chksm=eb38ce85dc4f479369884c9203edcc23fc66d2a662a5480c4a80fd02c1bdfb4a73fb6af3cd42&scene=21#wechat_redirect)  
  
  
- [【漏洞通告】禅道项目管理系统权限绕过漏洞](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484912&idx=2&sn=48062ade5fa1f3480a3b5810abe43c34&chksm=eb38cc29dc4f453f931b45db86cbab4141811f71375d73d6f89d0993779ca5b43147e6d0b836&scene=21#wechat_redirect)  
  
  
- [【漏洞通告】泛微E-Office10远程代码执行漏洞（QVD-2024-11354）](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484943&idx=2&sn=66c0c019dc15a35a26c730adfeb0a0c6&chksm=eb38cfd6dc4f46c08deae534ca20c93387c5028b2dd63bc7a0fccc09c23614d16ec7e2dd4e23&scene=21#wechat_redirect)  
  
  
- [【安全资讯】SpaceX数据泄露起死回生：Hunters International发布涉嫌被盗信息](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485166&idx=2&sn=ef588b684072aff924f895f46bbefd62&chksm=eb38cf37dc4f462135fc152234231268ecd92ba31a3be02207ca786c2bac5153945a6a41eb3c&scene=21#wechat_redirect)  
  
  
- [【安全资讯】F Society 在最新的网络攻击中针对罗格斯大学、Bitfinex](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485166&idx=3&sn=916e5f593fb047772a5bbf601db992b1&chksm=eb38cf37dc4f4621795ba28befe3b13c7b758fa96675e534b932da0f69444c71472c58d68823&scene=21#wechat_redirect)  
  
  
- [【安全资讯】勒索软件组织五大家族回来了？声称对阿联酋实体进行攻击](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485134&idx=2&sn=53f45607794291d0d4a632ceb0b2cabd&chksm=eb38cf17dc4f46012315b0743202beb2a9c373c569db2fe1b69a871927e4ff3db42a896b2731&scene=21#wechat_redirect)  
  
  
- [【安全资讯】下载量达数百万次的 Android 应用程序中存在脏流缺陷漏洞](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485134&idx=3&sn=5c9d536ac5d6dfb6f21c9fc9874673bb&chksm=eb38cf17dc4f4601c4a7d7112b8890060c8a623b42aee8b076d8b3bfc54c3f52d945bc53c9d5&scene=21#wechat_redirect)  
  
  
- [【安全资讯】摩尔多瓦政府受到 NoName 勒索软件的打击：网站已瘫痪](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485073&idx=2&sn=2a9495b7a549895691336b3245741f21&chksm=eb38cf48dc4f465e65116e584f3328e920df161ce6576cc1306849006724b5408a65bdf468d9&scene=21#wechat_redirect)  
  
  
- [【安全资讯】拉达克社会福利部数据疑似遭到网络攻击](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485073&idx=3&sn=26c0742b3c51aab26d072f1b1511bea4&chksm=eb38cf48dc4f465e8ea0edc59a147ed62e11c8eb88e5a443d9467517bfb9a5ca5b65161cd00f&scene=21#wechat_redirect)  
  
  
- [【安全资讯】阿根廷中央银行数据泄露：据称黑客提供客户信息出售](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485031&idx=2&sn=ffeba8887d1a21c35cd864e181f11fff&chksm=eb38cfbedc4f46a8ba3192b44d101f171ae9040db23f5bcfe3ef85127939eca2412cff4eafde&scene=21#wechat_redirect)  
  
  
- [【安全资讯】隐私组织投诉 ChatGPT 违反 GDPR](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485031&idx=3&sn=66628e2cb3f99456c0c797b3568705b9&chksm=eb38cfbedc4f46a864302903ca6b5413b53539f8769c747c92f6e671cc2819b89876b49374a9&scene=21#wechat_redirect)  
  
  
- [【安全资讯】Kaiser Permanente：数据泄露可能影响 1340 万患者](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485008&idx=2&sn=f22ae4809e3b022aae3c4f7e867c1591&chksm=eb38cf89dc4f469fb021021ba6ecabd7911d15d69b190c1798c023af64a56f1a87b8a048ff03&scene=21#wechat_redirect)  
  
  
- [【安全资讯】自 2004 年以来，全球有超过 170 亿个个人账户泄露](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247485008&idx=3&sn=766c34de0b8d0b62f97d7d3b0700d1ef&chksm=eb38cf89dc4f469f8a03143fdf7415b1b6b4c5aa1d764758bdfe1b1325a6c090c9e7eb498d1d&scene=21#wechat_redirect)  
  
  
- [【安全资讯】国家间谍利用思科零日漏洞入侵政府网络](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484912&idx=3&sn=39936aa4d9d39f00f8c11f49b9b5d079&chksm=eb38cc29dc4f453f969be44f1d09964da17962c7b191f9d06ccd805bdd6e621cbdd845d6641d&scene=21#wechat_redirect)  
  
  
- [【安全资讯】新的 Brokewell 恶意软件接管 Android 设备，窃取数据](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484912&idx=4&sn=f3f23fe0fce702d8d82f65ed162e225e&chksm=eb38cc29dc4f453f937a5cdff38541922af3ec3b4629bdfec46bd1416d0b4e8b4d76e9cb2559&scene=21#wechat_redirect)  
  
  
- [【安全资讯】朝鲜黑客组织攻击数十家韩国国防公司](http://mp.weixin.qq.com/s?__biz=MzI3MTk4Mjc3NA==&mid=2247484814&idx=2&sn=d6c5e99a663fa42c1229e32844834114&chksm=eb38cc57dc4f4541a798cf0ff9df8f05b69ee9718f197bf6db3ba309bf48dd1a883915d9a0bf&scene=21#wechat_redirect)  
  
  
  
  
  
**作者简介**：GuardCyberSec，致力于各行业企业信息安全深度思考，关注网络安全等级保护、法律法规解读、传统网络安全研究、工业安全研究、数据安全研究等，为网络安全建设出一份力。  
  
< END >  
  
**信息安全ISecurity**  
  
**致力于信息安全体系建设**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/C6Ge5dDibEBrnySbAPXCLGhyMdKaiaTLqw7hQHhraw1QfBjDo8dPzGtFgMpicfuHSvshrCwyOuPFicRhib6pPhB86Ug/640?wx_fmt=jpeg "")  
  
  
微信扫描二维码，关注我的公众号或者点击以下链接点击关注获得最新安全资讯  
  
  
