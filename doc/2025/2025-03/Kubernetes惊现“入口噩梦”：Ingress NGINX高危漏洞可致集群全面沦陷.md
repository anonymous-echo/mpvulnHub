#  Kubernetes惊现“入口噩梦”：Ingress NGINX高危漏洞可致集群全面沦陷   
原创 网空闲话  网空闲话plus   2025-03-25 17:23  
  
2025年3月24日Wiz博客披露，Kubernetes的Ingress NGINX Controller被发现存在一系列名为“IngressNightmare”的远程代码执行（RCE）漏洞，具体包括 CVE-2025-1097、CVE-2025-1098、CVE-2025-24514 和 CVE-2025-1974，严重威胁集群安全。CVE-2025-24514漏洞源于对 nginx.ingress.kubernetes.io/auth-url注释处理不当，攻击者可注入任意NGINX 指令。例如，通过恶意注释使NGINX配置中插入非法指令，导致远程代码执行。CVE-2025-1097涉及nginx.ingress.kubernetes.io/auth-tls-match-cn注释，攻击者可绕过检查注入配置，利用集群中的TLS证书或密钥对机密实施攻击。CVE-2025-1098允许攻击者通过操纵入口对象的UID字段注入任意指令。CVE-2025-1974则展示了如何利用这些注入实现远程代码执行，攻击者可通过ssl_engine指令加载任意共享库，进而执行任意代码。为缓解漏洞，用户应更新Ingress NGINX Controller 版本1.12.1或1.11.5，限制Admission Webhook访问，实施网络策略，或暂时禁用准入控制器。这些漏洞使集群面临重大风险，需立即采取行动保护 Ingress NGINX控制器，防止潜在的集群接管。  
#   
# 漏洞概述  
  
安全研究人员在Kubernetes的Ingress NGINX Controller中发现名为"IngressNightmare"的漏洞集群（CVE-2025-1097/1098/24514/1974），CVSS评分达9.8。这些漏洞通过**注释注入**  
和**配置验证缺陷**  
形成攻击链，最终导致如下三种后果。  
  
**1、任意NGINX指令注入**  
  
CVE-2025-1097：通过auth-tls-match-cn注释绕过正则检查  
  
nginx.ingress.kubernetes.io/auth-url  
:  
   
"http://example.com/#;\n恶意指令"  
  
CVE-2025-24514：利用auth-url注释插入恶意配置片段  
  
nginx.ingress.kubernetes.io/auth-tls-match-cn  
:  
   
"CN=abc #(\n){}\n恶意指令"  
  
**2、共享库注入执行（CVE-2025-1974）**  
  
**攻击分三步实现RCE：上传恶意.so文件至Pod临时存储；通过Content-Length标头维持文件描述符；注入ssl_engine指令加载恶意库。**  
  
**3、权限逃逸机制**  
  
**NGINX进程默认拥有集群管理员权限，可访问包括kube-system在内的所有命名空间机密。**  
## 影响范围评估  
<table><thead><tr><th style="color:rgb(var(--ds-rgb-label-1));padding-left:0px;border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-top:1px solid rgb(var(--ds-rgb-label-3));font-weight:600;text-align:left;border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;"><span leaf="" style="font-size: 15px;" mpa-font-style="m8o9pay211ui">维度</span></section></th><th style="color:rgb(var(--ds-rgb-label-1));border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-top:1px solid rgb(var(--ds-rgb-label-3));font-weight:600;text-align:left;border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;"><span leaf="" style="font-size: 15px;" mpa-font-style="m8o9pay21eu3">数据</span></section></th></tr></thead><tbody><tr><td style="padding-left:0px;border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">暴露集群数量</span></section></td><td style="border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">6,500+（含财富500强企业集群）</span></section></td></tr><tr><td style="padding-left:0px;border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">云环境风险比例</span></section></td><td style="border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">43%存在可利用路径</span></section></td></tr><tr><td style="padding-left:0px;border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">关键机密暴露风险</span></section></td><td style="border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">kube-system/konnectivity-certs等11类常见证书全数暴露</span></section></td></tr><tr><td style="padding-left:0px;border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">攻击复杂度</span></section></td><td style="border-bottom:1px solid rgb(var(--ds-rgb-label-3));border-color:#000000;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;" data-mpa-action-id="m8oad22y4m0"><span leaf="" style="">低（无需认证）</span></section></td></tr></tbody></table>##   
## 利用后果推演  
  
成功利用将导致：  
  
**集群完全接管**  
：攻击者可创建恶意Pod、篡改部署  
  
**敏感数据泄露**  
：获取数据库凭证、API密钥等所有机密  
  
**供应链污染**  
：在基础镜像中植入持久化后门  
  
**横向渗透跳板**  
：通过集群内网突破企业安全边界  
## 漏洞披露时间线  
<table><thead><tr><th style="color: rgb(var(--ds-rgb-label-1));padding-left: 0px;border-bottom: 1px solid rgb(var(--ds-rgb-label-3));border-top: 1px solid rgb(var(--ds-rgb-label-3));font-weight: 600;text-align: left;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;"><span leaf="" style="font-size: 15px;" mpa-font-style="m8o9pay3owl">日期轴</span></section></th><th style="color: rgb(var(--ds-rgb-label-1));border-bottom: 1px solid rgb(var(--ds-rgb-label-3));border-top: 1px solid rgb(var(--ds-rgb-label-3));font-weight: 600;text-align: left;"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;"><span leaf="" style="font-size: 15px;" mpa-font-style="m8o9pay31gsb">关键事件</span></section></th></tr></thead><tbody><tr><td style="padding-left: 0px;border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">2024.12.31</span></section></td><td style="border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">Wiz报告CVE-2025-1974/24514</span></section></td></tr><tr><td style="padding-left: 0px;border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">2025.01.02</span></section></td><td style="border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">报告CVE-2025-1097</span></section></td></tr><tr><td style="padding-left: 0px;border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">2025.01.09-02.07</span></section></td><td style="border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">Kubernetes三次修复均被绕过</span></section></td></tr><tr><td style="padding-left: 0px;border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">2025.02.20</span></section></td><td style="border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">移除NGINX配置验证彻底修复CVE-2025-1974</span></section></td></tr><tr><td style="padding-left: 0px;border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;"><span leaf="" style="">2025.03.24</span></section></td><td style="border-bottom: 1px solid rgb(var(--ds-rgb-label-3));"><section style="text-indent: 2em;margin-bottom: 16px;line-height: 1.75em;font-size: 13px;" data-mpa-action-id="m8oacw5q16s9"><span leaf="" style="">公开披露</span></section></td></tr></tbody></table>  
该时间线暴露出**准入控制器安全机制的深层次缺陷**  
：原始修复方案仅采用正则过滤，未能解决输入处理的根本问题，导致多次补丁绕过。  
## 缓解建议  
### 紧急处置措施  
  
**1、版本升级**  
：立即升级至Ingress NGINX 1.12.1/1.11.5  
  
**2、网络隔离**  
：删除准入控制器的公网暴露；配置NetworkPolicy限制仅API Server可访问  
  
**3、权限收敛**  
：  
  
bash  
  
kubectl delete clusterrolebinding ingress-nginx-admission  
### 行业启示  
  
**准入控制器应视为Tier0资产**  
：实施与kube-apiserver同级防护  
  
**最小权限原则落地**  
：默认拒绝+白名单机制  
  
**云原生组件安全评估**  
：建立准入控制器专项红队测试流程  
## 威胁预警  
  
研究团队指出：  
  
**同类漏洞泛在风险**  
：其他准入控制器可能存在类似设计缺陷  
  
**云服务默认配置隐患**  
：主流云平台的Kubernetes服务默认暴露准入控制器  
  
**验证机制悖论**  
：nginx -t等配置检查工具反而成为攻击入口  
  
此次事件揭示云原生安全的阿喀琉斯之踵——过度信任配置验证机制。建议企业重新审视"基础设施即代码"的安全假设，建立从代码提交到生产部署的全链路验证体系。  
  
  
参考资源  
  
1、  
https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities  
  
2、  
https://gbhackers.com/ingress-nginx-rce-vulnerability/  
  
