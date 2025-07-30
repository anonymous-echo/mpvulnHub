#  Apache Cassandra 漏洞允许攻击者远程访问数据中心   
 网安百色   2025-02-05 11:31  
  
 ![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo53bk2XBvgMAicgoNIvXTLrWaMQWaWCHb4hhQOKsdtWZnw6Ypcye3B6Q9DQMkZA6WomDfpU3ibe69ZA/640?wx_fmt=jpeg&from=appmsg "")  
  
Apache Cassandra 中披露了一个新的安全漏洞，标识为 CVE-2025-24860。  
  
该漏洞涉及授权绕过，可能允许用户在使用特定授权方配置时未经授权访问数据中心或网络区域。  
  
具有受限访问权限的用户可以通过 DCL 语句升级其权限。建议查看访问规则以发现违规行为，并升级到修补后的版本 4.0.16、4.1.8 或 5.0.3 以解决此问题。  
  
该漏洞影响以下版本的 Apache Cassandra：  
- **4.0.0 到 4.0.15**  
  
- **4.1.0 到 4.1.7**  
  
- **5.0.0 到 5.0.2**  
  
此问题是由 和 中的错误授权漏洞引起的。这些组件旨在根据用户权限限制对特定数据中心或 IP/CIDR 组的访问。  
  
此漏洞会影响：  
- CassandraNetworkAuthorizer  
在版本 4.0.0–4.0.15 和 4.1.0–4.1.7 中  
  
- 和 版本 5.0.0–5.0.2CassandraNetworkAuthorizerCassandraCIDRAuthorizer  
  
为了降低风险，用户应升级到以下修补版本的 Apache Cassandra：4.0.16、4.1.8、5.0.3。  
  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
