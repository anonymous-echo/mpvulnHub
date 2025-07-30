#  【已复现】Ingress NGINX Controller 远程代码执行漏洞   
 长亭安全应急响应中心   2025-03-26 20:18  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FOh11C4BDicR24K68pT54gfJibToYiavB5vnu5uzBhqyApib24lg8WtYcHeF9hp5ZSt9rJptRBYWzQqc2uQVYG9RDw/640?wx_fmt=jpeg&from=appmsg "")  
  
Ingress NGINX Controller 是 Kubernetes 生态系统中广泛使用的入口控制器，基于 NGINX 反向代理，用于管理外部流量并将其路由到 Kubernetes 服务。2025年3月，Wiz Research 团队发现并披露了一组未经身份验证的远程代码执行（RCE）漏洞（统称为 IngressNightmare，包括 CVE-2025-1097、CVE-2025-1098、CVE-2025-24514 和 CVE-2025-1974）。这些漏洞影响 Ingress NGINX Controller 的准入控制器组件（Admission Controller）。成功利用这些漏洞的攻击者可获取 Kubernetes 集群中所有命名空间的敏感数据（如凭据和密钥），并可能完全接管集群。  
**漏洞描述**  
  
   
Description  
   
  
  
  
**0****1**  
  
漏洞成因漏洞源于 Ingress NGINX Controller 的准入控制器在处理 Ingress 对象时，未对用户输入进行充分验证和清理。攻击者通过向准入控制器发送恶意的 AdmissionReview 请求，可以注入任意 NGINX 配置指令，并在配置验证阶段（使用 nginx -t）触发代码执行。  
利用条件需要可同时访问准入控制器（默认不对外开放）和 Nginx 服务。漏洞影响获取敏感数据：攻击者可访问所有命名空间中的密钥数据，包括用户凭据和访问令牌。远程代码执行（RCE）：攻击者可在 Ingress NGINX Controller 的 Pod 上执行任意代码，因其是高权限角色，可能导致集群完全失控。处置优先级：高漏洞类型：远程代码执行漏洞危害等级：高触发方式：网络远程权限认证要求：无需权限系统配置要求：需配置准入控制器对外开放（默认仅限集群内部访问）用户交互要求：无需用户交互利用成熟度：POC已公开修复复杂度：低，官方已发布新版本修复漏洞影响版本 Affects 02Ingress NGINX Controller  < 1.11.5Ingress NGINX Controller  < 1.12.1解决方案 Solution 03临时缓解方案在无法立即升级的情况下，可考虑限制准入控制器仅允许 Kubernetes API 服务器访问。升级修复方案官方修复版本：- Ingress NGINX Controller 1.11.5- Ingress NGINX Controller 1.12.1可从 GitHub 或官方 Helm 仓库下载最新版本并重新部署。漏洞复现Reproduction 04产品支持Support05云图：默认支持该产品的指纹识别，同时支持该漏洞的原理PoC检测洞鉴：预计3.27发布更新支持该漏洞检测雷池：预计3.27支持漏洞利用行为检测全悉：预计3.27支持漏洞利用行为检测时间线 Timeline 063月25日 互联网公开披露该漏洞3月26日 长亭应急安全实验室复现漏洞3月26日 长亭安全应急响应中心发布通告参考资料：[1].https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities  
  
**长亭应急响应服务**  
  
  
  
  
全力进行产品升级  
  
及时将风险提示预案发送给客户  
  
检测业务是否受到此次漏洞影响  
  
请联系长亭应急服务团队  
  
7*24小时，守护您的安全  
  
  
第一时间找到我们：  
  
邮箱：support@chaitin.com  
  
