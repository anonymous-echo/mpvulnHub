#  Apache Tomcat 多项安全漏洞   
 网安百色   2025-03-11 19:28  
  
 ![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo4z3hLL6buIGvZbEocbO0KPMQW1J0TR3Gu9hiac3XgUWeDDrHSkxLIgHtj5u40SXCmpqIyiblyiaM2pA/640?wx_fmt=jpeg&from=appmsg "")  
  
Apache Tomcat 作为广泛使用的开源 Web 服务器软件，近年来暴露出多个安全漏洞。  
  
部分严重问题使服务器面临远程代码执行（RCE）等攻击风险。  
  
这些漏洞凸显了保持软件最新版本并正确配置的重要性，以防止潜在的攻击利用。  
### 详细漏洞信息  
  
以下是 Apache Tomcat 漏洞的 CVE（常见漏洞和暴露）摘要：  
<table><thead data-start="232" data-end="277"><tr data-start="232" data-end="277"><th data-start="232" data-end="242"><strong data-start="234" data-end="241">CVE</strong></th><th data-start="242" data-end="253"><strong data-start="244" data-end="252">漏洞类型</strong></th><th data-start="253" data-end="262"><strong data-start="255" data-end="261">描述</strong></th><th data-start="262" data-end="277"><strong data-start="264" data-end="273">受影响版本</strong></th></tr></thead><tbody data-start="331" data-end="2137"><tr data-start="331" data-end="442"><td><strong data-start="333" data-end="351">CVE-2025-24813</strong></td><td>远程代码执行 &amp; 信息泄露</td><td>部分 PUT 操作中的临时文件漏洞，可能允许访问安全敏感文件，并在特定条件下实现远程代码执行。</td><td>11.0.0-M1 至 11.0.2</td></tr><tr data-start="443" data-end="544"><td><strong data-start="445" data-end="463">CVE-2024-56337</strong></td><td>远程代码执行</td><td>对 CVE-2024-50379 的不完全修复，需在区分大小写的文件系统上进行额外配置。</td><td>11.0.0-M1 至 11.0.1</td></tr><tr data-start="545" data-end="651"><td><strong data-start="547" data-end="565">CVE-2024-54677</strong></td><td>拒绝服务（DoS）</td><td>示例 Web 应用程序中，因未限制上传数据大小，可能导致 OutOfMemoryError。</td><td>11.0.0-M1 至 11.0.1</td></tr><tr data-start="652" data-end="749"><td><strong data-start="654" data-end="672">CVE-2024-50379</strong></td><td>远程代码执行</td><td>通过在区分大小写的文件系统上启用默认 Servlet 写入功能，可导致 RCE。</td><td>11.0.0-M1 至 11.0.1</td></tr><tr data-start="750" data-end="823"><td><strong data-start="752" data-end="770">CVE-2024-52318</strong></td><td>跨站脚本（XSS）</td><td>JSP 标签池的未转义输出可能导致 XSS 攻击。</td><td>11.0.0</td></tr><tr data-start="824" data-end="912"><td><strong data-start="826" data-end="844">CVE-2024-52317</strong></td><td>请求和响应混淆</td><td>HTTP/2 请求错误回收，可能导致用户数据混淆。</td><td>11.0.0-M23 至 11.0.0-M26</td></tr><tr data-start="913" data-end="1010"><td><strong data-start="915" data-end="933">CVE-2024-52316</strong></td><td>认证绕过</td><td>若自定义身份验证组件在异常情况下未正确设置失败状态，则可能导致绕过身份验证。</td><td>11.0.0-M1 至 11.0.0-M26</td></tr><tr data-start="1011" data-end="1103"><td><strong data-start="1013" data-end="1031">CVE-2024-38286</strong></td><td>拒绝服务</td><td>滥用 TLS 握手过程可能触发 OutOfMemoryError。</td><td>11.0.0-M1 至 11.0.0-M20</td></tr><tr data-start="1104" data-end="1186"><td><strong data-start="1106" data-end="1124">CVE-2024-34750</strong></td><td>拒绝服务</td><td>HTTP/2 流处理错误导致活动流计数不正确。</td><td>11.0.0-M1 至 11.0.0-M20</td></tr><tr data-start="1187" data-end="1272"><td><strong data-start="1189" data-end="1207">CVE-2024-23672</strong></td><td>拒绝服务</td><td>WebSocket 客户端可保持连接，导致资源耗尽。</td><td>11.0.0-M1 至 11.0.0-M16</td></tr><tr data-start="1273" data-end="1353"><td><strong data-start="1275" data-end="1293">CVE-2024-24549</strong></td><td>拒绝服务</td><td>HTTP/2 头部限制超出后未正确重置流。</td><td>11.0.0-M1 至 11.0.0-M16</td></tr><tr data-start="1354" data-end="1444"><td><strong data-start="1356" data-end="1374">CVE-2023-45648</strong></td><td>请求走私</td><td>HTTP Trailer 头部解析错误，可能导致请求走私攻击。</td><td>11.0.0-M1 至 11.0.0-M11</td></tr><tr data-start="1445" data-end="1542"><td><strong data-start="1447" data-end="1465">CVE-2023-44487</strong></td><td>拒绝服务</td><td>快速重置攻击可能导致 HTTP/2 触发 OutOfMemoryError。</td><td>11.0.0-M1 至 11.0.0-M11</td></tr><tr data-start="1543" data-end="1622"><td><strong data-start="1545" data-end="1563">CVE-2023-42795</strong></td><td>信息泄露</td><td>请求/响应回收不完整，可能导致信息泄露。</td><td>11.0.0-M1 至 11.0.0-M11</td></tr><tr data-start="1623" data-end="1707"><td><strong data-start="1625" data-end="1643">CVE-2023-41080</strong></td><td>开放重定向</td><td>特定格式的 URL 可能在特定条件下触发重定向。</td><td>11.0.0-M1 至 11.0.0-M10</td></tr><tr data-start="1708" data-end="1794"><td><strong data-start="1710" data-end="1728">CVE-2023-46589</strong></td><td>请求走私</td><td>超过大小限制的 Trailer 头部可能导致请求走私。</td><td>11.0.0-M1 至 11.0.0-M10</td></tr><tr data-start="1795" data-end="1877"><td><strong data-start="1797" data-end="1815">CVE-2023-34981</strong></td><td>信息泄露</td><td>AJP SEND_HEADERS 消息处理回归问题可能导致头部信息泄露。</td><td>11.0.0-M5</td></tr><tr data-start="1878" data-end="1964"><td><strong data-start="1880" data-end="1898">CVE-2023-28709</strong></td><td>拒绝服务</td><td>之前 DoS 漏洞的修复不完整，影响查询字符串参数处理。</td><td>11.0.0-M2 至 11.0.0-M4</td></tr><tr data-start="1965" data-end="2071"><td><strong data-start="1967" data-end="1985">CVE-2023-28708</strong></td><td>信息泄露</td><td>使用 RemoteIpFilter 时，Session Cookie 缺少 Secure 属性。</td><td>11.0.0-M1 至 11.0.0-M2</td></tr><tr data-start="2072" data-end="2137"><td><strong data-start="2074" data-end="2092">CVE-2023-24998</strong></td><td>拒绝服务</td><td>未限制的文件上传部分可能导致资源耗尽。</td><td>11.0.0-M1</td></tr></tbody></table>### 降低风险的措施  
  
**1. 升级软件**确保 Apache Tomcat 及相关软件更新至最新版本，以修补已知漏洞。  
  
**2. 禁用默认 Servlet 写入**默认情况下，Tomcat 禁止对默认 Servlet 进行写操作，除非必要，请保持此设置不变。  
  
**3. 正确配置**定期检查配置文件，确保符合最佳安全实践，减少潜在攻击面。  
  
**4. 监控系统资源**关注系统资源使用情况，以便快速发现并应对可能的拒绝服务攻击。  
  
**5. 定期安全审计与测试**开展定期的安全审计和渗透测试，发现并修复配置错误和潜在漏洞。  
### 持续维护与安全管理  
  
Apache Tomcat 不断曝出的漏洞，强调了强健安全措施和定期软件更新的重要性。  
  
尽管许多问题可以通过更新修复，但了解这些漏洞的本质，有助于管理员更好地保护服务器免受潜在威胁。  
  
服务器的持续监控与维护，是防范已知及新兴风险的关键。  
  
来源：gbhackers  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
