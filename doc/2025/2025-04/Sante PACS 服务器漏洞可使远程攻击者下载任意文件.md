#  Sante PACS 服务器漏洞可使远程攻击者下载任意文件   
山卡拉  嘶吼专业版   2025-04-07 13:52  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o29BUr8nVcJlZibyicz4gFfuctIUcq2thvgzeATgpPAXywHlPiaiajv35dibzunBQ8w4vibxScicyoEuz9V9g/640?wx_fmt=jpeg&from=appmsg "")  
  
最近，在 Sante PACS Server 4.1.0 版本中发现了几个严重漏洞，这使得该版本极易遭受严重的安全威胁。  
  
这些漏洞（CVE - 2025 - 2263、CVE - 2025 - 2264、CVE - 2025 - 2265 和 CVE - 2025 - 2284）会让服务器面临潜在攻击风险，可能引发未经授权的访问、数据泄露以及拒绝服务（DoS）等情况。  
  
在本文中，我们将深入剖析每个漏洞，给出受影响代码的示例及漏洞摘要。  
# 漏洞概述  
  
**CVE - 2025 - 2263：EVP_DecryptUpdate 基于堆栈的缓冲区溢出**  
  
该漏洞源于 Sante PACS 服务器在使用 OpenSSL 的 EVP_DecryptUpdate 时，出现基于堆栈的缓冲区溢出问题。在用户登录服务器的过程中，服务器使用固定大小为 0x80 字节的堆栈缓冲区来解密用户名和密码。攻击者可以通过发送超长的加密用户名或密码来利用此漏洞，进而引发缓冲区溢出，甚至可能实现代码执行。  
  
有漏洞的代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29BUr8nVcJlZibyicz4gFfuct2oU50ZRT5Bc0hOZ23n0DD6RUvaibjOYZRckg5Hk79IulqPG5gpDvFOg/640?wx_fmt=png&from=appmsg "")  
  
**CVE - 2025 - 2264：路径遍历信息泄露**  
  
此漏洞使得未经身份验证的远程攻击者能够下载服务器磁盘上的任意文件。嵌入式 Web 服务器负责提供特定目录中的文件，但它未能对请求路径进行正确验证，从而引发路径遍历攻击。攻击者可以构造一个超出预期目录结构的 URL 来利用该漏洞。  
  
利用示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29BUr8nVcJlZibyicz4gFfuct0HqjqSbaPfCCxmAuXn9iat18YhiaiaxHH5dPXsRugKNdjZOx1hSSibBrwQ/640?wx_fmt=png&from=appmsg "")  
  
**CVE - 2025 - 2265：HTTP.db SHA1 哈希截断**  
  
在此漏洞中，如果存储在服务器的 SQLite 数据库中的密码哈希值包含零字节，那么该哈希值将会被截断，这就使得它容易遭受碰撞攻击。攻击者可以利用路径遍历漏洞先下载数据库，然后找到与截断哈希值等效的密码。  
  
易受攻击的哈希处理代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29BUr8nVcJlZibyicz4gFfuctPU0FIgr4dVngpGzic4Ycr06f47liboyibu905xVia9WianyKxpic0QcH7bDw/640?wx_fmt=png&from=appmsg "")  
  
**CVE - 2025 - 2284：访问未初始化指针 DoS**  
  
当服务器尝试从格式错误的请求中提取登录凭据时，就会出现这个拒绝服务漏洞。如果 “usrname” 字段后面没有足够的行，服务器可能会访问未初始化的指针，进而导致崩溃。  
  
格式错误的请求 PoC：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29BUr8nVcJlZibyicz4gFfuctWlicbwHVrCmsP7ZBC9eWIY2CQcjsEGWLo9axnUBbvV6U1NQhSYSJEzw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29BUr8nVcJlZibyicz4gFfuctxickv1LVwAcWWyX8icIlq2ZKedHH21jS7ywQZY2ibbIpvqxYBR58OQzIA/640?wx_fmt=png&from=appmsg "")  
  
漏洞摘要  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29BUr8nVcJlZibyicz4gFfuctkyIoPeBEOKzGWkWiboeT8Vf0LbV7EtJfjXqqIWWJLicPRy5a9gebZ6kQ/640?wx_fmt=png&from=appmsg "")  
  
为了防范这些漏洞，建议用户将 Sante PACS 服务器升级到 4.2.0 或更高版本。根据 Tenable 的报告，此次更新将修复这些安全问题，增强系统的整体安全态势。用户还应考虑采取额外的安全措施，如网络分段和定期监控，以便检测潜在的攻击尝试。  
  
与任何软件漏洞情况一样，及时采取行动对于确保敏感数据的完整性和系统可用性至关重要。定期更新和安全审计是维护强大网络安全防御体系的基本操作。  
  
参考及来源：  
https://gbhackers.com/sante-pacs-server-flaws/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29BUr8nVcJlZibyicz4gFfucta3SPRCBhy3auic4AmHY6OfgvQZKr5vFZwWxk22jDgmY27w2YBkn69Wg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29BUr8nVcJlZibyicz4gFfuctsq9YBI43xg1xOMR1JoicKM3nDWJadP4KOsSUfszvDNoQGqfIHIsPZqA/640?wx_fmt=png&from=appmsg "")  
  
  
