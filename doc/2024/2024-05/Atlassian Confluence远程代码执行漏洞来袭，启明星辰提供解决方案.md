#  Atlassian Confluence远程代码执行漏洞来袭，启明星辰提供解决方案   
 启明星辰集团   2024-05-25 16:06  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhasKjicBZsG8bShBJeuxiaYcWUwXw6vZsfodqd2y6g1SXF4NYprHyvvrmlLWeDdhlxPa3gZhwFf2euw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
**Confluence**  
是一个专业的企业知识管理与协同软件，可以用于构建企业wiki，其强大的编辑和站点管理功能能够帮助团队成员共享信息和进行文档协作。  
  
  
Confluence支持集体讨论和信息发布。Confluence Data Center是面向大型企业和组织的版本，具有高可用性、可扩展性和高性能的特点；Confluence Server是适用于中小型企业和组织的自托管版本。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**漏洞详情**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
2024年5月23日，**启明星辰金睛安全研究团队**  
监控到Atlassian官方发布了新版本，以修复一个高危漏洞：Atlassian Confluence Data Center 和 Server 远程代码执行漏洞 (CVE-2024-21683)。经过身份认证的远程攻击者可构造特殊请求执行任意代码，从而对目标系统的机密性、完整性和可用性造成严重影响。鉴于该漏洞影响范围广泛，建议客户尽快进行自查并采取防护措施。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZkibicqhgiawBwDaTwRA5SPusHVthcOyyh5WqLGTfkVlUdG1coWXgr8tYibwGYFmJJORdpdNyTshuecg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**漏洞复现截图**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZkibicqhgiawBwDaTwRA5SPusd98IetjPVgtrsKtHmX3AYpSbzOo1bxzJUSsSJ7LrqQIegdonRMFibibQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**影响版本**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
- Data Center == 8.9.0  
  
- 8.8.0 <= Data Center <= 8.8.1  
  
- 8.7.0 <= Data Center <= 8.7.2  
  
- 8.6.0 <= Data Center <= 8.6.2  
  
- 8.5.0 <= Data Center <= 8.5.8 LTS  
  
- 8.4.0 <= Data Center <= 8.4.5  
  
- 8.3.0 <= Data Center <= 8.3.4  
  
- 8.2.0 <= Data Center <= 8.2.3  
  
- 8.1.0 <= Data Center <= 8.1.4  
  
- 8.0.0 <= Data Center <= 8.0.4  
  
- 7.20.0 <= Data Center <= 7.20.3  
  
- 7.19.0 <= Data Center <= 7.19.21 LTS  
  
- 7.18.0 <= Data Center <= 7.18.3  
  
- 7.17.0 <= Data Center <= 7.17.5  
  
- 8.5.0 <= Server <= 8.5.8 LTS  
  
- 8.4.0 <= Server <= 8.4.5  
  
- 8.3.0 <= Server <= 8.3.4  
  
- 8.2.0 <= Server <= 8.2.3  
  
- 8.1.0 <= Server <= 8.1.4  
  
- 8.0.0 <= Server <= 8.0.4  
  
- 7.20.0 <= Server <= 7.20.3  
  
- 7.19.0 <= Server <= 7.19.21 LTS  
  
- 7.18.0 <= Server <= 7.18.3  
  
- 7.17.0 <= Server <= 7.17.5  
  
- 6.4.0 <= Zabbix
<= 6.4.12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**修复建议**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
**1、官方修复方案**  
  
官方已发布安全更新，建议升级至最新版本，您可以从下载中心下载最新版本的  
Confluence Data Center  
和  
Confluence Server  
。  
  
地址  
:  
https://www.atlassian.com/software/confluence/download-archives  
  
****  
**2、启明星辰方案**  
  
  
天阗入侵检测与管理系统、天阗超融合检测探针（  
CSP  
）、天阗威胁分析一体机（  
TAR  
）、天清入侵防御系统（  
IPS  
）、天清  
Web  
应用安全网关（  
WAF  
）升级到最新版本即可有效检测或防护该漏洞造成的攻击风险。  
  
  
  
  
•  
  
END  
  
•  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzA3NDQ0MzkzMA==&mid=2651690370&idx=1&sn=7355a93d2efa886947192a2f8dba7d5a&chksm=84868877b3f10161f40b74499a2c8c8e3db0f78f49dfe0fb477f5b23e7286b802411cddd0532&cur_album_id=1700320980872593410&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhasKjicBZsG8bShBJeuxiaYcWTrp1STtrXicv3q8NV6t8jibdtv0eG4sQAbesmwdhQbGXJibvdTxIfQZVA/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhasKjicBZsG8bShBJeuxiaYcWbLOsZEmcxSGr53xNUnicjDYxK6wSzF9JkkrSDN9A9x5bQ9NaabJiaRyQ/640?wx_fmt=gif&from=appmsg "")  
  
  
