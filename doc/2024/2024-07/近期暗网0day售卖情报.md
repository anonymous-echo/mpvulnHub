#  近期暗网0day售卖情报   
原创 cybernews  OSINT研习社   2024-07-16 18:40  
  
###   
  
  
### 目录：  
###   
- ### 暗网论坛上出现疑似 Docker 容器逃逸事件  
  
- ### 黑客声称出售 Netgear Orbi 的 0day（Preauth RCE）  
  
- 黑客声称出售 phpBB 的 SQL 注入漏洞  
  
- 威胁者出售 OpenSSH 9.6 版命令注入漏洞  
  
- Pi-hole 上存在所谓的 CVE-2024-21762 RCE 漏洞  
  
- # 黑客声称出售大量未经授权的 VPN 和 SOCKS 访问权限  
  
#   
  
### 暗网论坛上出现疑似 Docker 容器逃逸事件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rWVoKKJPdj4Is2ZAZgpVXaKds3eDhkYibsKvWP8JXmlrSFfBRIvAFATdhhRWQGyjYj1licqDvMldWawPFicFsJHyA/640?wx_fmt=png&from=appmsg "")  
  
    据称，一名黑客正在暗网论坛上出售 Docker 容器逃逸。根据论坛上的帖子，这允许攻击者将容器环境逃逸到主机系统。还表示，同一威胁行为者发布的先前漏洞可以与此漏洞链接在一起。  
  
    黑客表示，所谓的漏洞是在 v-20.10.(20-25) 版本上测试的，测试的内核版本是 6.8.11。  
  
    帖子提到价格为 69,000 美元。  
### 黑客声称出售 Netgear Orbi 的 0day（Preauth RCE）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rWVoKKJPdj4Is2ZAZgpVXaKds3eDhkYibtyRaqOzTZVW53dhfnJjSHyN85cWEib1J6M3iaLt0rpFU43LZegzicWVDA/640?wx_fmt=png&from=appmsg "")  
  
    一名黑客宣布出售 Netgear Orbi 路由器的零日 (0day) 漏洞，该漏洞允许以 root 权限进行预认证远程代码执行 (RCE)。据该威胁者称，该漏洞共影响 51,287 台设备。  
  
    黑客声称交易将通过一个可信的中间人进行。在他们发送概念证明（PoC）之前，需要提供资金证明，以避免浪费时间。  
  
    此次出售凸显了广泛使用的消费网络设备中未修补的漏洞所带来的严重安全风险。  
  
黑客声称出售 phpBB 的 SQL 注入漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rWVoKKJPdj4Is2ZAZgpVXaKds3eDhkYibichKYHgZWPreoXz5vbwPNTtq37Uu79BVia1Mmo2v6tfX3xQZ8VTr28icw/640?wx_fmt=png&from=appmsg "")  
  
    一名黑客宣布出售 phpBB（一种流行的开源论坛软件）的 SQL 注入漏洞。据该威胁者称，此漏洞允许经过身份验证的攻击者执行 SQL 查询并检索数据库。  
  
    据报道，该漏洞已在最新版本的 phpBB 上进行了测试，这让该软件的用户非常担忧。该漏洞的要价为 69 美元，以比特币 (BTC) 支付。  
  
    此公告强调了与 Web 应用程序漏洞相关的持续风险以及定期安全更新和补丁的重要性。  
  
### 威胁者出售 OpenSSH 9.6 版命令注入漏洞  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rWVoKKJPdj4Is2ZAZgpVXaKds3eDhkYibI4CETsxQKq1e8dXsg1mGc8rnxGhpcIW5lL5nibthoV1OYy0Px5d9rJA/640?wx_fmt=png&from=appmsg "")  
  
    一名黑客出售针对  
OpenSSH 9.6 版  
的漏洞，该漏洞允许命令注入和  
远程代码执行 (RCE)  
。卖家声称该漏洞已经过测试并确认有效，对运行受影响版本的系统构成重大风险。  
  
漏洞详细信息：  
- 类型：  
命令注入（RCE）  
  
- 目标：  
 OpenSSH 版本 9.6  
  
- 功能：  
执行远程命令  
  
- 价格：  
可商议（私信讨论）  
  
- 接受的付款：  
比特币 (BTC)、门罗币 (XMR)、莱特币 (LTC)  
  
    卖家强调，他们只会考虑信誉良好的买家，确保只进行认真的询问。漏洞的可用性强调了保持最新安全措施和监控系统以防潜在漏洞的重要性。  
##   
## Pi-hole 上存在所谓的 CVE-2024-21762 RCE 漏洞  
  
    其中一名黑客声称分享了 CVE-2024-21762的漏洞，据称目标是 Pi-hole。  
  
    黑客将该漏洞描述为Pi-hole 中的 一个严重漏洞 ( CVSS 8.6 )，该漏洞允许 通过 服务器端请求伪造 (SSRF ) 执行远程代码执行 (RCE ) 。该漏洞涉及一个详细的 Python 脚本，该脚本可以登录 Pi-hole 实例、获取 CSRF 令牌、发送有效负载并在服务器上执行任意命令。  
  
    据黑客称，涉嫌漏洞影响 Pi-hole 5.18.2 及以下版本，并在 5.18.3 版本中得到解决。此安全漏洞允许执行未经授权的命令，从而损害系统的机密性、完整性和可用性。  
# 黑客声称出售大量未经授权的 VPN 和 SOCKS 访问权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rWVoKKJPdj4Is2ZAZgpVXaKds3eDhkYib9gaYh0kvjSmiaaKlqB3XoJybB6V7fDc0VyQZpoT7lvLKUeMJRUpz7hA/640?wx_fmt=png&from=appmsg "")  
  
    据称，黑客向多个国家和行业的多家公司提供未经授权的 VPN 和 SOCKS 访问权限。访问权范围从  
域用户  
到  
域管理员权限  
，对每个受影响的组织都有重大潜在影响。以下是涉嫌销售的详细信息：  
  
域用户访问：  
1. 西班牙  
  
1. 收入  
：1720万欧元  
  
1. 行业  
：商业服务  
  
1. 价格  
：800 美元  
  
1. 英国  
  
1. 收入  
：570万英镑  
  
1. 行业  
：货运及物流服务  
  
1. 价格  
：800 美元  
  
1. 印度  
  
1. 收入  
：6500万卢比  
  
1. 行业  
：制造业  
  
1. 价格  
：1000 美元  
  
1. 印度尼西亚  
  
1. 收入  
：2.65亿卢比  
  
1. 行业  
：建筑材料  
  
1. 价格  
：1500 美元  
  
1. 英国  
  
1. 收入  
：650万英镑  
  
1. 行业  
：制造业  
  
1. 价格  
：800 美元  
  
域管理员访问：  
1. 加拿大  
  
1. 收入  
：少于500万美元  
  
1. 行业  
：商业服务  
  
1. 价格  
：650 美元  
  
1. 泰国  
  
1. 收入  
：未指定  
  
1. 行业  
：海鲜供应（最大的海鲜出口商集团之一）  
  
1. 价格  
：1750 美元  
  
1. 印度  
  
1. 收入  
：超过10亿卢比  
  
1. 行业  
：商业服务  
  
1. 价格  
：5000 美元  
  
1. 波多黎各, 美国  
  
1. 收入  
：1700万美元  
  
1. 行业  
：会计服务  
  
1. 价格  
：3000 美元  
  
1. 印度  
  
1. 收入  
：8490万卢比  
  
1. 行业  
：印度电信管理局  
  
1. 价格  
：2500 美元  
  
1. 日本  
  
1. 收入  
：500万日元以下  
  
1. 行业  
：零售  
  
1. 价格  
：650 美元  
  
    据称，另一名黑客正在向一家印度大型石油、天然气和能源公司出售未经授权的 SOCKS 访问权限。据报道，该公司的收入超过 500 亿美元。访问权限包括域管理员权限，可控制公司网络中的 10,000 多台设备。此访问权限的要价为  
100 万美元。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rWVoKKJPdj4Is2ZAZgpVXaKds3eDhkYibGNGFeqLG2mzNAe5r0bLdzLQbiauMRbSsO4f6lUMia0u7rgUDux7AtXmQ/640?wx_fmt=png&from=appmsg "")  
  
    这些涉嫌销售行为凸显了各行业和地区存在严重的网络安全漏洞。暗网上存在此类访问，这凸显了加强安全措施和持续警惕以保护敏感信息和基础设施的迫切需要。  
  
