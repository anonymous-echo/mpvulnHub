#  GitLab修复了CE、EE版本中一个远程代码执行漏洞   
 网络安全应急技术国家工程中心   2022-08-26 15:01  
  
近期，Security Affairs 网站披露，DevOps 平台 GitLab 修复了其社区版(CE)和企业版(EE)中出现的一个关键远程代码执行漏洞，该漏洞被追踪为 CVE-2022-2884(CVSS 评分 9.9)。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib2tw0RCILNV3pkCyv9ia5ibPkSu5GMhnZyV3zcBZaU4IVPsILEHwy6LPjFrIf9OK6D5r4UXqBYVj0A/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
据悉，攻击者经过“身份验证”后，可以通过 GitHub 导入 API 利用该漏洞。目前 DevOps 平台 GitLab 已经发布了安全更新，修复了这一影响其 GitLab 社区版(CE)和企业版(EE)的关键远程代码执行漏洞。  
  
**GitLabCE/EE 多个版本受到漏洞影响**  
  
漏洞爆出不久后，GitLab 运营商在发布的安全公告中表示，GitLab CE/EE 中的漏洞(CVE-2022-2884)主要影响11.3.4——15.1.5之间的所有版本，此外，从 15.2 到 15.2.3 的所有版本和15.3 到 15.3.1 的所有版本也受到严重影响。  
  
值得一提的是，运营商在公告中着重强调，CVE-2022-2884 漏洞允许经过“身份认证”的攻击者从 GitHub 导入 API 端点实现远程代码执行，因此强烈建议所有安装了受漏洞影响版本的用户尽快升级到最新版本。  
  
**漏洞是否在野被利用尚不清楚**  
  
从媒体披露的信息来看，研究人员 yvvdwf 最早发现了 CVE-2022-2884 漏洞，随后通过 HackerOne 漏洞赏金计划，快速报告了该漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib2tw0RCILNV3pkCyv9ia5ibPj5N6ZzLib5ialmhICXU0jpJMDZtSyBJZXcJUMxGepcvfAs1UgD2WmtPw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
鉴于一些用户无法立即升级到最新版本，GitLab 运营商提供了一个解决方法。建议用户以 “管理员 ”身份认证后，从设置菜单的 “可见性和访问控制 ”标签中禁用 GitHub 的导入功能。  
  
最后，安全研究人员声称，目前尚不清楚 CVE-2022-2884 漏洞是否在野外攻击中被积极利用。  
  
**参考文章：**  
  
https://securityaffairs.co/wordpress/134769/security/gitlab-rce-bug.html  
  
  
  
原文来源  
：FreeBuf  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176njVOPvfib4X3jQ6GIHLtX8SSDvbpmcpr4uu3X7ELG7PDjdaLVeq4Er02ZoicTPvxrC6KCVH3bssUVw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
