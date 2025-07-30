> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546963&idx=2&sn=f6b0b39f61c938cbe033753539c56b22

#  紧急！本周【护网】必看3大高危漏洞：Sudo提权漏洞，你中招了吗？  
 安小圈   2025-07-07 00:45  
  
**安小圈**  
  
  
第702期  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbNUlJYnNFrdxSl0V8htqZZWvMluenXkGrJGsPsa48ksesTqabuQNae4Jwh12wT5ibDLP6QWV1WKyeg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbOVztHhrSawy3u5KqPTRs9pPtTicoFgjxhUlRWLrIutmy4fLCCGrCvfKahO7nc6kcIy7ibbxic3Jgpmg/640?wx_fmt=png "")  
  
## 🛡️ 安全通告一：PHP PostgreSQL 与 SOAP 扩展高危漏洞通告（CVE-2025-1735 & CVE-2025-6491）  
  
**发布日期**  
：2025年6月  
**影响组件**  
：PHP PostgreSQL 扩展、SOAP 扩展  
**漏洞等级**  
：高危（SQL 注入、拒绝服务）  
**攻击状态**  
：已披露，具备利用条件  
### 📌 内容概要  
  
PHP 官方披露两个关键安全漏洞，分别影响 PostgreSQL 扩展和 SOAP 扩展，可能导致 SQL 注入或拒绝服务（DoS）攻击。漏洞影响多个主流 PHP 分支，建议尽快升级。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/SSj3JFz3AfgCq1PEFxqKNg1AObyHIUY92bnibW7j1ibbqzcSAgYq7xomv9KqQkvpufU5KCmibtlppQOJOiaalLKpSw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
### 🐞 漏洞详情  
- CVE-2025-1735（CVSS 9.1）  
  
- 类型：SQL 注入 / 崩溃  
  
- 原因：PQescapeStringConn() 由于转义函数中缺少错误检查，导致 SQL 注入，可能导致空指针解引用。  
  
- 影响版本：PHP < 8.1.33 / 8.2.29 / 8.3.23 / 8.4.10  
  
- CVE-2025-6491（CVSS 5.9）  
  
- 类型：拒绝服务（DoS）  
  
- 原因：SOAP 扩展处理超长命名空间前缀(>2GB)时触发 libxml2 崩溃，并引发分段错误。  
  
- 影响版本：同上，且 libxml2 < 2.13  
  
### 🌍 影响范围  
- 所有启用 PostgreSQL 或 SOAP 扩展的 PHP 应用  
  
- 特别是使用 libxml2 < 2.13 的系统  
  
### 🛠️ 应对措施  
- ✅ 升级 PHP 至 8.1.33 / 8.2.29 / 8.3.23 / 8.4.10  
  
- ✅ 升级 libxml2 至 2.13+  
  
- 🔍 审查是否启用 SOAP 扩展，评估其使用场景与风险  
  
## 🛡️ 安全通告二：Sudo 本地提权漏洞通告（CVE-2025-32462 & CVE-2025-32463）  
  
**发布日期**  
：2025年6月  
**影响组件**  
：Sudo  
**漏洞等级**  
：高危（本地提权）  
**攻击状态**  
：已披露，默认配置可被利用  
### 📌 内容概要  
  
研究人员披露两个影响 Linux 系统的 Sudo 漏洞，允许本地用户绕过主机限制或加载恶意配置文件，从而以 root 权限执行任意命令。漏洞影响多个主流发行版。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/SSj3JFz3AfgCq1PEFxqKNg1AObyHIUY9xoJ3477gdWQzhbvgyvkUtjSgsjVWd3P7gbT81UpMMvichrJUZQoZZ1w/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
### 🐞 漏洞详情  
- CVE-2025-32462（CVSS 2.8）  
  
- 问题：sudoers 文件中主机匹配逻辑错误  
  
- 风险：绕过主机限制执行命令  
  
- 存在时间：自 2013 年起  
  
- CVE-2025-32463（CVSS 9.3）  
  
- 问题：Sudo 的 -R 选项允许加载 chroot 中的伪造配置  
  
- 风险：加载恶意 nsswitch.conf，执行任意代码  
  
### 🌍 影响范围  
- 受影响发行版包括：Debian、Ubuntu、Red Hat、SUSE、Alpine、Amazon Linux 等  
  
- 默认启用 Sudo 即可能受影响  
  
### 🛠️ 应对措施  
- ✅ 升级至 Sudo 1.9.17p1  
  
- ⚠️ 审查是否使用统一 sudoers 策略或 chroot 配置  
  
- 🔒 Sudo 项目计划移除 --chroot 功能，建议避免使用  
  
## 🛡️ 安全通告三：Apache Tomcat 与 Camel 远程代码执行漏洞通告（CVE-2025-24813 等）  
  
**发布日期**  
：2025年7月5日  
**影响组件**  
：Apache Tomcat、Apache Camel  
**漏洞等级**  
：高危（远程代码执行）  
**攻击状态**  
：已被大规模利用  
### 📌 内容概要  
  
Apache 基金会披露多个关键漏洞，影响 Tomcat 与 Camel 平台。攻击者可远程上传恶意 payload 或绕过 header 过滤器执行任意命令。Palo Alto Networks 报告称，3 月份已拦截超 12 万次攻击尝试。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/SSj3JFz3AfgCq1PEFxqKNg1AObyHIUY9Z2Sg3KwHC3YJmZJbXg5mNxliabMX4QDBSMsRJJraKgPnJ9wIqCeA2dw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
### 🐞 漏洞详情  
- CVE-2025-24813（Tomcat）（CVSS 9.8）  
  
- 类型：RCE  
  
- 机制：PUT + GET 请求组合触发反序列化  
  
- 影响版本：9.0.0.M1–9.0.98、10.1.0-M1–10.1.34、11.0.0-M1–11.0.2  
  
- CVE-2025-27636（CVSS 5.6） & CVE-2025-29891（Camel）（CVSS 4.8）  
  
- 类型：RCE  
  
- 机制：header 大小写绕过过滤器  
  
- 影响版本：3.10.0–3.22.3、4.8.0–4.8.4、4.10.0–4.10.1  
  
### 🌍 影响范围  
- 所有部署受影响版本 Tomcat 或 Camel 的服务器  
  
- 特别是暴露在公网、未及时打补丁的系统  
  
### 🛠️ 应对措施  
- ✅ 升级至：  
  
- Tomcat ≥ 9.0.99 / 10.1.35 / 11.0.3  
  
- Camel ≥ 3.22.4 / 4.8.5 / 4.10.2  
  
- 🔍 检查 IoC（入侵指标）：  
  
- PUT 路径：/qdigu/session、/UlOLJo.session  
  
- 可疑头部：CAmelExecCommandExecutable  
  
- Payload 哈希：6a9a0a3f0763a359737da801a48c7a0a7a75d6fa810418216628891893773540  
  
- ⚠️ 若怀疑入侵，建议联系专业安全团队  
  
  
  
  
  
END  
  
  
  
**【内容**  
**来源：墨问非攻】**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeeR4VInT56J0KCLD3HkiaRxjMLLV6rricOadHohJB1sOtPT02fETAxr4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=1&sn=2f16da5665014b4c07bcbd53e3d1c03e&scene=21#wechat_redirect)  
- [【HW】8个因护网被开除的网安人](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=1&sn=2f16da5665014b4c07bcbd53e3d1c03e&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=2&sn=e9578e62a475ac5c46b95ac81066d2a7&scene=21#wechat_redirect)  
- [HW应急溯源：50个高级命令实战指南](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=2&sn=e9578e62a475ac5c46b95ac81066d2a7&scene=21#wechat_redirect)  
  
  
- [震惊全球！中国团队攻破RSA加密！RSA加密告急？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546856&idx=1&sn=11b36f6fabde860e889e4ac2f4797bba&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOugegrykhydnkHibcSWjpibTBZoK6jjGxJiax1BcwwctpA5SBric9aPdQFXsxFnn4LQJWdkYwbtPN0gg/640?wx_fmt=jpeg "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546815&idx=1&sn=99a4f3228f322ef92c93d23cee01f071&scene=21#wechat_redirect)  
- [2025年【护网】攻防演练时间已定！](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546815&idx=1&sn=99a4f3228f322ef92c93d23cee01f071&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546578&idx=1&sn=87cdf84e6fd7d35986b29acd90954c65&scene=21#wechat_redirect)  
  
[突发！小红书惊现后门......](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546578&idx=1&sn=87cdf84e6fd7d35986b29acd90954c65&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPwt82pEdc2YwCDz6n3H3c2C0ibcMl4Tea8hM59iaZoR1FDMTCUswDiclc1icLoSywpkWbdqyb6uBNcnA/640?wx_fmt=jpeg "")  
- [2025年“净网”“护网”专项工作部署会在京召开，看看都说了哪些与你我相关的关键内容？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546673&idx=1&sn=53fe0365785465d4ff6193a9ca639119&scene=21#wechat_redirect)  
  
  
- # 护网即将来临，这场网安盛会带给了我们打工人什么......  
  
- [护网在即，企业还有什么新思路可以应对吗？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546698&idx=1&sn=55ab4ac8dffb5f7ccf02a4f759537acf&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPwt82pEdc2YwCDz6n3H3c2Noz3ibYqNZ52uicBtuVVlFRg6vSuF8YFjPvCVma1ADrT1ViaKVE9URNOA/640?wx_fmt=jpeg "")  
- [HW必备：50个应急响应常用命令速查手册一（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546304&idx=2&sn=45ef99e528ded7ff2e65e4d70e6d5181&scene=21#wechat_redirect)  
  
  
- [HW必备：50个应急响应常用命令速查手册二（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546327&idx=2&sn=cf1ebbd2b511524ec965a3672b6fc3dd&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546530&idx=1&sn=4a2820b60102e538e87c956375f6fcdb&scene=21#wechat_redirect)  
- [网安同行们，你们焦虑了吗？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546530&idx=1&sn=4a2820b60102e538e87c956375f6fcdb&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546466&idx=1&sn=a9d55d0b430dbf61dc219fd71ce25ae1&scene=21#wechat_redirect)  
- # 网安公司最后那点体面，还剩下多少？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
- [2024年网安上市公司营收、毛利、净利润排行](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
- [突发！数万台 Windows 蓝屏。。。。广联达。。。惹的祸。。。](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
  
  
#   
- # 权威解答 | 国家网信办就：【数据出境】安全管理相关问题进行答复  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247539649&idx=1&sn=8858b449c89d21240e1f522e92be4fbd&scene=21#wechat_redirect)  
- # 全国首位！上海通过数据出境安全评估91个，合同备案443个  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544405&idx=2&sn=a961d43ca4a9ed667fccbbab758d9196&scene=21#wechat_redirect)  
- # 沈传宁：落实《网络数据安全管理条例》，提升全员数据安全意识  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
- [频繁跳槽，只为投毒](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
- [【高危漏洞】Windows 11：300毫秒即可提权至管理员](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
- [针对网安一哥专门的钓鱼网站](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
- [为什么【驻场】网络安全服务已成为大多数网络安全厂商乙方不愿再触碰的逆鳞？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOYPldtHVUmKQJ2WtL12GUnHRyzBiaKosLNicTZ2QkDFSRPUha2Eiaqk8R5fPdXc75zxprkTRB0ib5hUw/640?wx_fmt=jpeg "")  
- [HW流程以及岗位职责](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=3&sn=97e6083dbfbdd896680e24770a10d319&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247543989&idx=1&sn=2821b91efdd626e1a38ec6b2b439186b&scene=21#wechat_redirect)  
  
- # 网络安全【重保】| 实战指南：企业如何应对国家级护网行动？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542929&idx=1&sn=8cf6f15ddca44e343a494eea0fa619b2&scene=21#wechat_redirect)  
- **DeepSeek安全：AI网络安全评估与防护策略**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542701&idx=1&sn=567674aa12d861c3561d453268badb91&scene=21#wechat_redirect)  
- **虚拟机逃逸！VMware【高危漏洞】正被积极利用，国内公网暴露面最大******  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542458&idx=1&sn=d81d049331d175a2176f0978d7f032a8&scene=21#wechat_redirect)  
- **挖矿病毒【应急响应】处置手册******  
  
****- **用Deepseek实现Web渗透自动化**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542225&idx=2&sn=244a465fab183f4fa91a284b92a920e6&scene=21#wechat_redirect)  
- **【风险】DeepSeek等大模型私有化服务器部署近九成在“裸奔”，已知漏洞赶紧处理！**  
  
****- **关于各大网安厂商推广「DeepSeek一体机」现象的深度分析**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
- [Deepseek真的能搞定【安全运营】？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540432&idx=1&sn=b9e7e6103e86b9966f29d7eacf8e3d1e&scene=21#wechat_redirect)  
- **【热点】哪些网络安全厂商接入了DeepSeek？**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540206&idx=2&sn=300737ad84f684e622fdde03da0fc1a7&scene=21#wechat_redirect)  
- **【2025】常见的网络安全服务大全（汇总详解）**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540343&idx=1&sn=59d6f592f71a7f1e3a18fd082aa3de40&scene=21#wechat_redirect)  
- **AI 安全 |《人工智能安全标准体系(V1.0)》(征求意见稿)，附下载**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMbfUY7RtO1t6ZAxjoibZoZ8DSVPU0yI9v2nXpiat0oN8eLia5jiaoWOhlib5GiaPWQJeCsUmShI4QOqaGg/640?wx_fmt=png "")  
- **2025年 · 网络威胁趋势【预测】**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbM09kF5tXEb8PRXicFibPic4un6rwDI2CBUxrVaDINuM8ChyotgWiag4icErAHniaYNYiccQiaVkyyJUTX13w/640?wx_fmt=jpeg "")  
- **【实操】常见的安全事件及应急响应处**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbMASB7RibZ1nezrias4SvtcqzjvsJJPXhFiceJPEoVHVLhI2Soolaf8OhWQOVafycOibiaclJkT7NgG4Nw/640?wx_fmt=jpeg "")  
- **2024 网络安全人才实战能力白皮书安全测试评估篇**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeOsnl5ayrQXc0wPVutL1dQXg7BugT7vAe8qkpfszTrlhUAq4DQZFaVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  
