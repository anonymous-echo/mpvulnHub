#  从环境构建到漏洞利用：如何用Metarget和Coogo复现K8s IngressNightmare攻击链   
原创 星云实验室  绿盟科技研究通讯   2025-03-28 17:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/hiayDdhDbxUYg143PKsaFiaug6QxqKxAg0bqLLHXRnrjvsfFeXM5ibSAKMrWHBPtI4cmcs5fO4SJ2ggXODxLu07JQ/640?wx_fmt=gif&from=appmsg "")  
  
  
  
一.  概述  
  
  
  
  
  
  
  
  
  
  
Ingress Controller作为K8s集群管理外部访问的核心组件，承担着集群入口网关的关键角色，其通过智能路由机制将外部HTTP/HTTPS流量定向到集群内部相应的Service和Pod，是集群流量管理的"中枢神经系统"。目前市场上有多种可集成的Ingress Controller解决方案，包括Apache APISIX、Cilium、Emissary以及Nginx等。  
  
其中，Nginx Ingress Controller凭借稳定性和高性能成为K8s生态中最受欢迎的Ingress Controller之一，同时也是K8s的核心项目，在GitHub上已获得超过18000个Star。然而，近年来该组件接连曝出的安全漏洞给用户带来了严峻的安全挑战。本文将重点分析最新披露RCE漏洞，通过复现和深入研究，给读者带来更多思考。  
  
  
二．漏洞背景介绍  
  
  
  
  
  
  
  
  
  
  
自2021年CVE-2021-25742漏洞首次公开以来，针对Nginx Ingress Controller的安全攻防对抗就持续不断。以下是近年来相关漏洞的时间线：  
  
2021年10月：CVE-2021-25472漏洞曝光，攻击者通过Snippets特性注入手段，能够窃取集群中的所有Secret实例信息。  
  
2022年5月：CVE-2021-25745和CVE-2021-25746漏洞相继披露，攻击者分别利用Path和Annotations注入技术，成功获取Nginx Ingress Controller的访问凭据。  
  
2023年5月：CVE-2021-25748漏洞公开，攻击者通过绕过Path校验的注入方式，再次窃取Nginx Ingress Controller的凭据。  
  
2023年10月：CVE-2023-5043和CVE-2023-5044漏洞被披露，攻击向量扩展到configuration-snippet和permanent-redirect注入技术，目标依然是获取Controller的访问凭据。  
  
2025年3月24日： Wiz研究团队一次性公开了四个高危漏洞（CVE-2025-1097、CVE-2025-1098、CVE-2025-24514和CVE-2025-1974），这些漏洞构成了K8s Ingress Nginx Controller中的一系列未授权远程代码执行（RCE）漏洞链。由于漏洞集中爆发且危害严重，业界将其称 "IngressNightmare"事件。攻击者利用这些漏洞可以未经授权访问K8s集群所有命名空间中存储的敏感凭据，最终可能导致整个集群被完全接管。鉴于漏洞的严重性，CVSS 3.1评分高达9.8分。  
  
受影响版本：Ingress-nginx≤ 1.11.4，Ingress-nginx=1.12.0  
  
安全版本：Ingress-nginx ≥ 1.11.5，Ingress-nginx ≥ 1.12.1  
  
纵观近四年的漏洞演变历程，凭证窃取始终是攻击者的核心目标。从最初的攻击利用到防御封禁，再到新型绕过技术的出现，这一系列CVE的演变生动展现了攻防之间持续的技术博弈。绿盟科技星云实验室曾在《CVE-2023-5044：Nginx Ingress再曝注入漏洞》一文[3]中对Nginx Ingress的相关漏洞做过详细分析感兴趣的读者也可关注。  
  
  
三．漏洞原理分析  
  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUYg143PKsaFiaug6QxqKxAg0Ey1Ocibib29jeUM6oaLLaJM36OmgZfsgro1Pa7KwYIjX5k5gMJjYgwWg/640?wx_fmt=png&from=appmsg "")  
  
图1. K8s API请求生命周期  
  
 图1展示了K8s API处理请求的过程，即从每个API请求开始，经历处理、认证、授权、准入控制、持久化到Etcd的过程，与本次漏洞相关的为  
  
准入控制器(Admission Controller)，准入控制器是K8s的内部安全机制，准入控制过程主要分为两个阶段，第一阶段运行变更准入控制器（MutatingAdmissionWebhook），用于拦截并修改K8s API Server请求的对象，第二阶段运行验证准入控制器（ValidatingAdmissionWebhook），用于对K8s API Server请求对象的格式进行校验，如果第一阶段的任何准入控制器拒绝了请求，则整个请求被拒绝，并同时会向终端用户返回一个错误。  
  
本次涉及的漏洞成因源于 Nginx Ingress Controller 的验证准入控制器在处理Ingress对象时，未对用户输入进行充分验证和清理。攻击者通过向准入控制器发送恶意的 AdmissionReview 请求（该请求中包含待校验的资源对象），可以注入任意Nginx配置指令，并在配置验证阶段利用“nginx -t”触发代码执行，从而允许在Ingress Nginx Controller的Pod上远程执行代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUYg143PKsaFiaug6QxqKxAg0wibypIwEdD2lMe557OxfUvCY91Y9ZphaFoyefr5hAqPUI5w6slRyeyA/640?wx_fmt=png&from=appmsg "")  
  
图2. IngressNgintmare攻击向量[2]  
  
  
四．使用绿盟云攻防靶场Metarget进行漏洞环境复现  
  
  
  
  
  
  
  
  
  
  
步骤一：提前pull好所需镜像（可能需要设置Docker代理）  
```
sudo docker pull registry.k8s.io/ingress-nginx/controller:v1.11.0@sha256:d56f135b6462cfc476447cfe564b83a45e8bb7da2774963b00d12161112270b7
sudo docker pull registry.k8s.io/ingress-nginx/kube-webhook-certgen:v20220916-gd32f8c343@sha256:39c5b2e3310dc4264d638ad28d9d1d96c4cbb2b2dcfb52368fe4e3c63f61e10f
```  
  
步骤二：利用Metarget一键安装K8s  
```
sudo ./metarget gadget install k8s --version 1.20.1 --verbose --domestic
```  
  
步骤三：利用Metarget一键安装CVE-2025-1974漏洞环境  
```
sudo ./metarget cnv install cve-2025-1974
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUYg143PKsaFiaug6QxqKxAg0DHYTuACXBp7juo1lCicDXYCrVV8W3TDGp5a693ZgoOwy5hyGjQPs5hw/640?wx_fmt=png&from=appmsg "")  
  
图3 使用Metarget一键安装cve-2025-1974漏洞环境  
  
  
  
五．使用绿盟云攻击套件Coogo进行漏洞自动化利用  
  
  
  
  
  
  
  
  
  
  
步骤一：设置端口转发（仅在本地进行漏洞利用时需要）  
```
sudo kubectl port-forward svc/ingress-nginx-controller -n ingress-nginx 8080:80
sudo kubectl port-forward -n ingress-nginx svc/ingress-nginx-controller-admission 8443:443
```  
  
步骤二：利用绿盟云攻击套件Coogo自动化利用  
```
./coogo run cve-2025-1974
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUYg143PKsaFiaug6QxqKxAg0eb5b4e8qBiclCVWDR0vUXjKxD6I01De7wgwWOcjwpZoqI0BvRPRPuag/640?wx_fmt=png&from=appmsg "")  
  
图4 使用Coogo进行CVE-2025-1974漏洞自动化利用  
  
  
六．漏洞处置建议  
  
  
  
  
  
  
  
  
  
  
 建议可以先用以下命令确认K8s是否使用了ingress-nginx控制器：  
```
kubectl get pods --all-namespaces --selector app.K8s.io/name=ingress-nginx
```  
  
再输入以列命令查看ingress-nginx的版本：  
```
kubectl -n ingress-nginx get pod-o jsonpath="{.spec.containers[*].image}
```  
  
如果在受影响版本范围内，则建议：  
  
1. 升级K8s Nginx Ingress Controller到最新版本  
  
2. 限制准入控制器仅允许被K8s API Server访问，不允许对外暴露  
  
  
七．绿盟科技云攻防能力研究成果  
  
  
  
  
  
  
  
  
  
  
7.1  
  
云攻击套件Coogo  
  
绿盟云攻击套件Coogo是一个针对云原生环境和公有云的后渗透测试工具，与传统的云环境下的后渗透测试工具不同，Coogo具备三大优势：  
  
(1) 云原生场景能力覆盖度全  
  
Coogo在云原生能力的覆盖度上更加全面，其内置了200+攻击能力。覆盖范围包括云原生基础设施、云原生应用、CICD组件、数据服务，公有云服务。  
  
(2) ATT&CK矩阵的覆盖度接近100%，支持复杂云上攻击路径的自动化利用  
  
识别目标环境存在的组件/服务，验证可利用漏洞->利用组件/服务漏洞投递武器->内网信息收集，验证可利用漏洞->容器逃逸/权限提升漏洞利用->凭证窃取->凭证利用->持久化控制->痕迹清理。  
  
(3) 用户友好，操作简单  
  
Coogo具备智能化的评估能力，能够根据目标环境自动化推荐多种攻击策略，使用手册、help经过多轮精细打磨，便于用户上手。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUYg143PKsaFiaug6QxqKxAg0SCxsxLo4EqGDuxia5k53dlLXf4icaCIWQEWQswwylNZr8iaFy0cbT5s8w/640?wx_fmt=png&from=appmsg "")  
  
图5 绿盟云原生攻防矩阵  
  
7.2  
  
云攻防靶场Metarget  
  
Metarget [1]是业内首个开源云原生安全靶场，主要用于快速、自动化搭建从简单到复杂的脆弱云原生靶机环境。Metarget支持云原生组件、容器化应用等两类脆弱场景的自动化构建，以生成多节点、多层次的云原生环境靶场。Metarget已入选CNCF孵化类项目，Github Star数突破1.2K，社区活跃，广泛被安全研究者使用。  
  
Metarget未来将持续更新维护开源版，保持靶场的新鲜性和可靠性，也非常欢迎高校、科研院所等单位共同参与开发，探索云原生安全的前沿，为云原生安全的发展添砖加瓦。  
  
同时，近期我们也在开源版的基础上，推出了绿盟云原生攻防靶场商业版。绿盟云原生攻防靶场针对当前新型计算环境的复杂性和安全需求，依托绿盟网络空间安全仿真平台（CSSP），通过虚拟化、安全编排、行为仿真等技术构建各类应用场景，并对场景中生成的用户和攻防行为进行评估分析，满足用户人才培养、安全竞赛、实战对抗、设备测评、技术研究等需求。 整个实战人才的培养体系按照训练难度从点->线->面依次递增，往后更加贴近实战、真实业务环境。 其核心能力如下所示：  
  
(1) 理论课程+课后实操练习（单点学习训练）  
  
靶场配备体系化的云计算理论课程学习，每个理论课程具备对应的课后习题和实验课程，帮助学员从基础知识入手，逐步掌握云原生环境的核心技术。  
  
(2) 全链条实战攻防演练（单线学习训练）  
  
覆盖完整的攻击路径（如初始访问、容器逃逸、权限提升、持久化控制等），学员可体验多种实战场景，提升综合能力。  
  
(3) 贴近真实业务环境（单面学习训练）  
  
靶场模拟企业级云原生架构，包括容器、K8s、微服务以及公有云场景，帮助学员熟悉现代企业业务环境的实际运行机制和其中的风险。  
  
(4) 武器/工具库支持  
  
靶场配套提供多款实训课程的武器工具，让学员深入理解攻击背后的技术原理，提升攻防技术能力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUYg143PKsaFiaug6QxqKxAg0r6MjgcJNKe3XeicA4jkcdhSKjRlvjkTBMXa1brpIicNibrMibK6NyowBOw/640?wx_fmt=png&from=appmsg "")  
  
图 6 绿盟云攻防靶场资源库  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUYg143PKsaFiaug6QxqKxAg0tqtoib6ibibG2ddibicibicBZMbq3KwwWOMO3Yy7EhO9ePibgMK1SWflq9oS3w/640?wx_fmt=png&from=appmsg "")  
  
图 7 绿盟云攻防靶场训练课程部分清单  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUYg143PKsaFiaug6QxqKxAg0Nu8wp6ZXJDlhHIoUVrpqFbWj6BNr7cpbTSceIBe8U82tYTHP0QlGJw/640?wx_fmt=png&from=appmsg "")  
  
图8 绿盟云原生攻防靶场部分界面展示（左边实验手册，右边漏洞环境）  
  
  
目前绿盟云攻击套件和绿盟云攻防靶场都开放试用，欢迎大家联系！！！  
  
参考文献  
  
   
  
[1] https://github.com/Metarget/metarget  
  
[2] https://www.wiz.io/blog/ingress-nginx-K8s-vulnerabilities  
  
[3] https://mp.weixin.qq.com/s/a_87y1LByZfiAlJzJlEtJw?mpshare=1&scene=1&srcid=0327wGNFEMPhl89LinryQOzH&sharer_shareinfo=e9136d86a74ef574d30aa94706fda434&sharer_shareinfo_first=e9136d86a74ef574d30aa94706fda434&from=industrynews#rd  
  
                                                                            内容编辑：星云实验室  
  
                                                                                 责任编辑：吕治政  
  
本公众号原创文章仅代表作者观点，不代表绿盟科技立场。所有原创内容版权均属绿盟科技研究通讯。未经授权，严禁任何媒体以及微信公众号复制、转载、摘编或以其他方式使用，转载须注明来自绿盟科技研究通讯并附上本文链接。  
  
  
**关于我们**  
  
  
绿盟科技研究通讯由绿盟科技创新研究院负责运营，绿盟科技创新研究院是绿盟科技的前沿技术研究部门，包括星云实验室、天枢实验室和孵化中心。团队成员由来自清华、北大、哈工大、中科院、北邮等多所重点院校的博士和硕士组成。  
  
绿盟科技创新研究院作为“中关村科技园区海淀园博士后工作站分站”的重要培养单位之一，与清华大学进行博士后联合培养，科研成果已涵盖各类国家课题项目、国家专利、国家标准、高水平学术论文、出版专业书籍等。  
  
我们持续探索信息安全领域的前沿学术方向，从实践出发，结合公司资源和先进技术，实现概念级的原型系统，进而交付产品线孵化产品并创造巨大的经济价值。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/hiayDdhDbxUY2K8rBINLpNkcmGjhUPlPgog0ic5C2q5iaacg76LjUH65O9lswksz3c79yGsicibU6gCWro9NagOUscQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**长按上方二维码，即可关注我**  
  
  
  
  
  
  
  
