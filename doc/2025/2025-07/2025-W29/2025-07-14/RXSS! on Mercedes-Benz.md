> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE5MDY5NA==&mid=2247506973&idx=1&sn=d258cb8eb078305c2c2e3a6e9ac1b51a

#  RXSS! on Mercedes-Benz  
haidragon  安全狗的自我修养   2025-07-14 13:13  
  
# 理论：了解 CVE-2025–4388 （Liferay Portal RXSS）  
  
**CVE-2025–4388**  
 是 Liferay ****  
Portal 7.4.0 至 7.4.3.131、Liferay DXP 2024.Q4.0 至 2024.Q4.5、2024.Q3.1 至 2024.Q3.13、2024.Q2.0 至 2024.Q2.13、2024.Q1.1 至 2024.Q1.12、7.4 GA 至 Update 92 中的反射跨站脚本 （XSS） 漏洞，允许未经身份验证的远程攻击者将 JavaScript 注入 modules/apps/marketplace/marketplace-app-manager-web。  
# 🧩 受影响的软件：  
- **Liferay Portal（补丁前可能影响多个版本）**  
- 在以下位置呈现未经清理的查询字符串时易受攻击：  
  
- 
```
meta refresh tags
```

  
- 重定向 URL  
  
- 来宾/公共页面中的某些参数
```
GET
```

  
要发现易受 CVE-2025–4388 攻击的目标，您可以使用 **Shodan**  
、**Censys**  
 或类似搜索引擎来查找暴露在互联网上的 Liferay 实例。  
  
🔍 Shodan Dork 示例：  

```
html:&#34;liferayPortalCSS&#34;
```

  
  
  
1.1K 易受攻击的目标。  
  
  
现在，在选择目标之后，我们必须使用此有效负载来利用 **REFLECTED CROSS-SITE-SCRIPTING**  

```
/o/marketplace-app-manager-web/icon.jsp?iconURL=https:///%22%3E%3Cimg%20src=x%20onerror=alert(document.domain)%3E
```

  
结果：XSS 已执行。  
  
  
  
# 📌 冲击：  
- 可在面向公众的门户上利用  
  
- 允许：  
  
- Cookie 盗窃  
  
- 网络钓鱼/重定向  
  
- 会话劫持  
  
因此，在 Report to  
  
梅赛德斯-奔驰  
  
在 Bugcrowd 上，结果是这样的：  
  
  
  
  
被接受为 P3  
  
> **参考资料 ：****https://liferay.dev/portal/security/knownvulnerabilities/-/asset_publisher/jekt/content/CVE-2025-4388**  
> **原子核模板 ：****https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-4388.yaml**  
  
# 🧯 缓解建议  
  
对于基于 Liferay 的应用程序：使用内置的 HTML 转义方法  
- 禁用将用户输入反射到 meta 标记中  
  
- 应用最新的安全补丁 （Liferay Security Advisories）  
  
# 🧠 最后的思考  
  
通过结合 **Shodan**  
、**Nuclei**  
 等开源工具，以及对易受攻击模式的敏锐观察，任何研究人员都可以识别并负责任地报告 **CVE-2025–4388**  
 等影响较大的 XSS 漏洞。  
  
🚀 要点：如果梅赛德斯-奔驰容易受到攻击，那么许多其他组织很可能使用   
  
**Liferay 公司**  
  
****也是——你只需要看一看。  
  
  
**觉得这有用吗？**  
与您的黑客朋友分享。如果您想要更多真实世界的 CVE 武器化指南，请关注。如果您在野外发现 CVE-2025–4388，请**以合乎道德的方式进行报告。**  
  
下次再见，  
祝您安全愉快！！_!!👨‍💻💥  
  
在 LinkedIn 上联系我 ： LinkedIn  
在 X： X 上关注我  
  
  
  
很高兴获得梅赛德斯🧡🫡  
  
- 公众号:安全狗的自我修养  
  
- vx:2207344074  
  
- http://  
gitee.com/haidragon  
  
- http://  
github.com/haidragon  
  
- bilibili:haidragonx  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
  
  
