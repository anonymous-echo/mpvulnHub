#  PHP XXE 注入漏洞允许攻击者访问配置文件和私钥   
 嘶吼专业版   2025-03-21 11:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
Web 应用程序安全研究员 Aleksandr Zhurnakov 详细揭示了 PHP 中新发现的 XML 外部实体（XXE）注入漏洞。  
该漏洞展示了攻击者如何绕过多种安全机制，进而访问敏感配置文件和私钥，凸显了即便在看似安全的实现中，不当的 XML 解析配置也存在巨大风险。  
  
此漏洞利用了 PHP 的 libxml 扩展及其包装器的组合，使攻击者能够绕过诸如 LIBXML_NONET、LIBXML_DTDLOAD 等限制标志以及其他标志。这些标志原本的作用是防止加载外部实体或访问外部资源，然而研究显示，攻击者可借助高级有效载荷和技术规避它们。  
# 绕过安全机制  
  
该漏洞源于 PHP 通过 DOMDocument 类处理 XML 解析的方式。默认状态下，外部实体加载处于禁用状态，但像 LIBXML_DTDLOAD 这样的特定标志，却允许攻击者加载恶意 DTD 文件。随后，攻击者可利用 php://filter 等 PHP 包装器制作这些文件，以窃取诸如 /etc/passwd 或私钥等数据。  
  
攻击者绕过安全机制的关键手段之一，是使用诸如 http:// 等替代包装器替换 php://filter/resource=URL，从而有效地绕过 LIBXML_NONET 限制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icpdujEYzic7pwLDP9Y1RVvo7drUsF3NVEwOSQyrEmZcia5g1Aia7LKOeBEq5m1WdMsGIy7S6Z3Wvbvw/640?wx_fmt=png&from=appmsg "")  
  
入站 HTTP 请求  
  
此外，通过滥用参数实体（% name;），攻击者能够在应用安全检查之前，将恶意内容注入 XML 结构中。更为复杂的是，研究表明，攻击者可利用类似 zlib.deflate 过滤器的 base64 编码来压缩有效载荷，减小其大小，使其能够符合 GET 参数或查询字符串的常见服务器约束。  
  
根据 PT Swarm 报告，当服务器上的出站 TCP 连接被阻止时，这种方法还能借助 DNS 子域实现渗透。  
# 影响  
  
该漏洞已在特定应用程序中被发现。例如，SimpleSAMLphp（CVE-2024-52596）中的 XXE 漏洞，允许未经身份验证的用户读取配置文件、提取私钥并伪造身份验证断言。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icpdujEYzic7pwLDP9Y1RVvoDqOA1l7DJuCxN6jPNv2DlXKhHicHNBaCpCiaf7hmTZNmHtbZJ2WcnDIw/640?wx_fmt=png&from=appmsg "")  
  
有效的 xxe 载荷  
  
当 SimpleSAMLphp 被配置为身份提供者时，攻击者实际上能够完全绕过身份验证机制。  
  
Zhurnakov 的研究着重强调了 PHP 应用程序中安全 XML 解析实践的重要性。建议开发人员禁用所有不必要的 libxml 标志（如 LIBXML_DTDLOAD、LIBXML_NOENT 等），并确保部署具有增强 XXE 保护的最新 PHP 版本（例如 PHP 8.4 中引入的相关保护机制）。此漏洞清晰地警示我们，看似微不足道的错误配置，也可能引发复杂的攻击途径，凸显了在 Web 应用程序开发中进行严格测试和遵循安全编码实践的必要性。  
  
参考及来源：https://gbhackers.com/php-xxe-injection-vulnerability-allows-attackers/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icpdujEYzic7pwLDP9Y1RVvosARbxwqLYcPIBt1ecYaToJibYW2M21VhicVvustAnOH6N7pOft9vznVg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icpdujEYzic7pwLDP9Y1RVvoEVphFl5DTfsicsoWPxQDOrzlnOCncKWkibjXoIZK6oTlKTe4pMMGF4CQ/640?wx_fmt=png&from=appmsg "")  
  
  
