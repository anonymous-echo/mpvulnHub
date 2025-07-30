#  最新的 Ivanti SSRF 零日漏洞遭到大规模利用   
胡金鱼  嘶吼专业版   2024-02-07 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
  
编号为 CVE-2024-21893 的 Ivanti Connect Secure 和 Ivanti Policy Secure 服务器端请求伪造 (SSRF) 漏洞，目前正被多个攻击者大规模利用。  
  
Ivanti于2024年1月31日首次就网关 SAML 组件中的缺陷发出警告，利用 CVE-2024-21893，攻击者可以绕过身份验证并访问设备（版本 9.x 和 22.x）上的受限资源。  
  
威胁监控服务平台发现多个攻击者利用 SSRF 漏洞，其中有170 个不同的 IP 地址正试图进行攻击。  
  
此特定漏洞的利用量远远大于其他最近修复或缓解的 Ivanti 缺陷，这也表明攻击者的焦点发生了明显转变。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ibX0yCLZaJJ6GM1A2d7nFUYaS8KAtBBQFBXLy2HiahGh6GdkPwmB9rRo3YDXNyTs4dNicdIfxwP0Gew/640?wx_fmt=jpeg&from=appmsg "")  
  
最新 Ivanti 缺陷的利用量   
  
尽管研究人员于2024年2月2日发布的概念验证（PoC）漏洞起到了协助攻击的作用，但他们在报告发布前几个小时看到了攻击者使用类似的方法。  
  
这意味着黑客已经弄清楚如何利用 CVE-2024-21893 对易受攻击的 Ivanti 端点进行不受限制、未经身份验证的访问。  
  
目前已有近22500个Ivanti Connect Secure设备暴露在互联网上。然而，尚不清楚有多少人容易受到这种特定漏洞的影响。  
# 安全混乱  
  
CVE-2024-21893 的披露与影响相同产品的另外两个零日漏洞 CVE-2023-46805 和 CVE-2024-21887 的安全更新一起发布，并分享了临时缓解措施。  
  
尽管最初采取了缓解措施，但攻击者绕过了防御措施，损害了设备的配置文件，导致 Ivanti 推迟了原定于 1 月 22 日发布的固件补丁，以应对复杂的威胁。  
  
美国网络安全和基础设施安全局（CISA）已下令联邦机构断开所有Ivanti Connect Secure 和策略安全 VPN 设备，只有已恢复出厂设置并升级到最新固件版本的设备才应重新连接到网络。但受到影响的旧版本仍然没有补丁。  
  
参考及来源：https://www.bleepingcomputer.com/news/security/newest-ivanti-ssrf-zero-day-now-under-mass-exploitation/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibX0yCLZaJJ6GM1A2d7nFUYsLWiagZdNDqRGqTYQjuVMsC4IgUJVYPlKAhlljUA9rAN4HeNUiaEicoGg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibX0yCLZaJJ6GM1A2d7nFUYlOA36T8ex9PNMIic1TOKpMPlDOfDt1YppZLbwQ7icoz5R5UicRiagN0wLA/640?wx_fmt=png&from=appmsg "")  
  
  
