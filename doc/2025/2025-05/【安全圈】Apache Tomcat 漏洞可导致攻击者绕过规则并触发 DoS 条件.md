#  【安全圈】Apache Tomcat 漏洞可导致攻击者绕过规则并触发 DoS 条件   
 安全圈   2025-04-30 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaRYALoShbHCgQsHEMsnric9MdzgqQKD8xFibqxic3Aa2icO0DUZEHZcuT60pJNgJibE4Ocwb5uopf2qnA/640?wx_fmt=png&from=appmsg "")  
  
Apache 软件基金会披露了 Apache Tomcat 中的一个重大安全漏洞，该漏洞可能允许攻击者绕过安全规则并通过操纵 HTTP 优先级标头 触发  
拒绝服务条件。  
  
该高危漏洞编号为 CVE-2025-31650，影响多个 Tomcat 版本，对依赖此流行 Java 应用服务器的组织构成重大安全风险。  
## Apache Tomcat 拒绝服务漏洞  
  
该漏洞源于 Apache Tomcat 在处理 HTTP 优先级标头时输入验证不当。   
  
根据安全公告，“对某些无效 HTTP 优先级标头的错误处理不正确，导致失败的请求清理不完整，从而造成内存泄漏”。   
  
当攻击者发送大量包含无效 HTTP 优先级标头的格式错误的请求时，他们可能会触发 OutOfMemoryException，从而导致拒绝服务，使应用程序不可用。  
  
HTTP 优先级标头是 Web 通信的合法组件，它指示客户端对响应传递优先级顺序的偏好。   
  
然而，这个新的漏洞表明 Tomcat 对这些标头的处理存在一个缺陷，无法正确验证和清理输入。  
  
<table><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">风险因素</span></font></font></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">细节</span></font></font></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">受影响的产品</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6;letter-spacing: 0.034em;" data-pm-slice="1 1 [&#34;node&#34;,{&#34;tagName&#34;:&#34;figure&#34;,&#34;attributes&#34;:{},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;},&#34;table&#34;,{&#34;interlaced&#34;:null,&#34;align&#34;:null,&#34;class&#34;:null,&#34;style&#34;:null},&#34;table_body&#34;,null,&#34;table_row&#34;,{&#34;class&#34;:null,&#34;style&#34;:null},&#34;table_cell&#34;,{&#34;colspan&#34;:1,&#34;rowspan&#34;:1,&#34;colwidth&#34;:null,&#34;width&#34;:null,&#34;valign&#34;:null,&#34;align&#34;:null,&#34;style&#34;:null},&#34;para&#34;,{&#34;tagName&#34;:&#34;section&#34;,&#34;attributes&#34;:{},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;}]">Apache Tomcat 9.0.76–9.0.102Apache Tomcat 10.1.10–10.1.39Apache Tomcat 11.0.0-M2–11.0.5</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">影响</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="" style="color: rgba(0, 0, 0, 0.9);font-family: mp-quote, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6;letter-spacing: 0.034em;" data-pm-slice="1 1 [&#34;node&#34;,{&#34;tagName&#34;:&#34;figure&#34;,&#34;attributes&#34;:{},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;},&#34;table&#34;,{&#34;interlaced&#34;:null,&#34;align&#34;:null,&#34;class&#34;:null,&#34;style&#34;:null},&#34;table_body&#34;,null,&#34;table_row&#34;,{&#34;class&#34;:null,&#34;style&#34;:null},&#34;table_cell&#34;,{&#34;colspan&#34;:1,&#34;rowspan&#34;:1,&#34;colwidth&#34;:null,&#34;width&#34;:null,&#34;valign&#34;:null,&#34;align&#34;:null,&#34;style&#34;:null},&#34;para&#34;,{&#34;tagName&#34;:&#34;section&#34;,&#34;attributes&#34;:{},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;}]">拒绝服务（DoS）</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">漏洞利用前提条件</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">攻击者必须发送大量带有无效 HTTP 优先级标头的 HTTP 请求；无需身份验证</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVSS 3.1 评分</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">高</span></font></font></td></tr></tbody></table>  
## 受影响的版本  
  
该漏洞影响以下 Apache Tomcat 版本：  
- Apache Tomcat 11.0.0-M2 至 11.0.5  
  
- Apache Tomcat 10.1.10 至 10.1.39  
  
- Apache Tomcat 9.0.76 至 9.0.102  
  
  
这些版本的用户应立即考虑升级到修补版本。  
  
该漏洞利用了 Tomcat 处理内存资源的方式。当服务器收到无效的 HTTP Priority 标头时，它无法正确清理资源，从而造成内存泄漏。   
  
正如报告  
中所指出的，“大量此类请求可能会触发 OutOfMemoryException，从而导致拒绝服务”。  
  
这让人想起了之前的 Java 应用程序内存问题。正如一位系统管理员在之前的事件中指出的那样，“Tomcat 无法释放未使用的内存。它只会不断添加内存，最终达到其最大分配内存量”。  
## 减轻   
  
Apache 软件基金会建议采取以下缓解措施：  
- 升级到 Apache Tomcat 11.0.6 或更高版本  
  
- 升级到 Apache Tomcat 10.1.40 或更高版本  
  
- 升级到 Apache Tomcat 9.0.104 或更高版本  
  
  
尽管 9.0.103 版本已修复此问题，但“9.0.103 候选版本的发布投票未通过”，因此尽管包含修复程序，但此版本并不包含在受影响的版本中。  
  
这是近几个月来第二个重大  
Apache Tomcat 漏洞  
。2025 年 3 月，CVE-2025-24813 被披露，这是一个 CVSS 评分为 9.8 的严重远程代码执行漏洞，攻击者可以利用该漏洞控制易受攻击的服务器。  
  
鉴于此漏洞的严重性及其完全禁用 Web 应用程序的可能性，强烈建议立即采取行动。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】吉利APP、领克APP突然崩了！有车主在路边苦等3小时，最新回应](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069352&idx=1&sn=db684cad13f694beef16dd9d35410ac6&scene=21#wechat_redirect)  
  
  
  
[【安全圈】玛莎百货数据泄露与 Scattered Spider 勒索软件攻击有关](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069352&idx=2&sn=0cfbe9d83610f722e86d78f4f9ae4b37&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Akira 勒索软件攻击后，Hitachi Vantara 服务器下线](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069352&idx=3&sn=374251b21e2cc1eace0852a7ada06ad9&scene=21#wechat_redirect)  
  
  
  
[【安全圈】RansomHub勒索软件部署恶意软件以危害企业网络](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069352&idx=4&sn=6eab06942a72aa12743056453fa44f1d&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
