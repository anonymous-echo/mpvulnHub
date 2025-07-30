#  Windows Kerberos严重漏洞，数百万台服务器遭攻击   
天唯科技  天唯信息安全   2024-11-25 03:27  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PZibWfCgzicQNtiadibcX9tpg72vzGPvNib7Fwf9KLcH2SwXyzEqqyyCcxDZ14rGHzAdykFT2fD6EhIxic6awPS02hEA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**E安全消息，Windows Kerberos身份认证协议中存在一个严重漏洞，对数百万服务器构成了重大威胁。微软在11月补丁星期二更新中解决了此问题。**  
  
  
Microsoft Kerberos是一种广泛使用的用于验证主机或用户身份的身份验证协议。为了利用这个漏洞，未经身份验证的行为者必须利用密码协议漏洞来实现RCE，微软在其“补丁星期二”中解释道。  
  
  
该漏洞被追踪为CVE-2024-43639，CVSS得分为9.8（严重）。  
此漏洞允许攻击者向易受攻击的系统发送精心设计的请求，以获得未经授权的访问和远程代码执行(RCE)。  
  
  
如果不及时修补，可能会导致各种规模的组织遭受严重后果，包括数据盗窃、系统中断，甚至整个系统被破坏。由于Windows Server的广泛使用和攻击者可以轻易利用，这个漏洞尤其令人担忧。  
  
  
**根据Censys调查结果，有超过两百万（2274340）个暴露的Windows Server实例，其中1211834个可能易受攻击。**  
  
  
不过，Censys研究称，并非所有这些实例都易受攻击，只有配置了Kerberos KDC代理的服务器才会受到影响。  
  
  
“请注意，显示的设备只有在配置为Kerberos KDC代理协议服务器时，才易受攻击。”Censys博客文章写道。  
  
  
这些设备中有一半以上被发现TCP/443端口开放，这是KDC代理协议服务器的默认端口，研究人员敦促管理员确认他们系统上该协议的存在。  
  
  
**供您参考，KDC代理协议服务器**  
允许客户端通过HTTPS与KDC服务器通信，使用Kerberos协议（例如用于Kerberos身份验证服务和票证光栅服务交换的UDP/TCP 88，以及用于Kerberos密码更改的TCP 464）。这些协议假设可以直接、可靠地访问KDC服务器，通常在同一网络或VPN内，并通常用于远程桌面网关和DirectAccess等服务。  
  
  
**关于受影响最严重的地区，**  
Censys指出，这些易受攻击的服务器中有34%位于美国，11%与Armstrong Enterprise Communications相关联，后者是一家托管IT提供商。  
  
  
系统管理员应该修补所有配置为KDC代理服务器的Windows服务器，禁用不必要的KDC代理服务，并实施安全措施如网络分段和防火墙，以最小化网络攻击的风险。  
  
  
鉴于许多服务器易受攻击，攻击者不断利用这些弱点。建议快速修补和采取额外的安全措施，以降低网络攻击的风险。  
#   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
  
天唯科技专注于大型组织信息安全领域及IT基础设施解决方案的规划、建设与持续运维服务。帮助客户提高IT基础设施及信息安全管控水平和安全运营能力，使客户在激烈的市场环境中保持竞争力。  
  
我们一直秉承“精兵强将，专业专注”的发展理念。  
先后在江门、深圳成立分公司，在武汉、长沙成立办事处以及成立广州的服务支撑中心。公司已获得高新技术企业认证、已通过IS09001、IS027001、CCRC信息安全集成服务、CCRC信息安全风险评估、CCRC信息安全应急处理等认证。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNRytkPMNOKYRW452LxR5Ez5Wee8X6KlbhoUMt9XyhhbRxHafKcCLWJic3ib0umJiaH3fl6sOx8KMBiaQ/640?wx_fmt=png "盾牌单图.png")  
  
**END**  
  
  
  
**往期推荐:**  
  
  
  
  
  
[《全球数据跨境流动合作倡议》发布](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502611&idx=1&sn=d72ab29ae4ca695751b04d198304d63c&chksm=c25d07b3f52a8ea53d99318818a2b5d4f2e586185e86e9bfb57de291de19bdab988827b2cc61&scene=21#wechat_redirect)  
  
  
  
[主页被篡改竟浑然不知！某公司被公安约谈！](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502611&idx=2&sn=eb27ba06a04cc06e0a211efdad17ffc9&chksm=c25d07b3f52a8ea58cb0697394459a547508e9f748fd08db34e4716c40640ff8e9fbc27fc844&scene=21#wechat_redirect)  
  
  
  
[微软“清理门户”，禁止杀毒软件访问Windows内核](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502581&idx=1&sn=047c11cbf88afb4ef342443739639c17&chksm=c25d0655f52a8f436b592b060cf6d71ff60dc4b112b618b86e30020d017cc83b8dc21e70bef3&scene=21#wechat_redirect)  
  
  
  
**征文通道:**  
  
  
  
  
  
[发钱！征文！让真诚的分享更有价值](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247490310&idx=1&sn=db4b524d1d9f5aabb4af2184dd831de3&chksm=c25ed7a6f5295eb053d3f90e2dc8cd22a2d8ce1a62561ffa62966340ee563734cd4fd32045f3&scene=21#wechat_redirect)  
  
  
