#  BrokenSesame 阿里云PostgreSQL 漏洞思考 --详情见原文   
Wiz Research  黑伞安全   2023-05-04 08:24  
  
原文链接 ：https://www.wiz.io/blog/brokensesame-accidental-write-permissions-to-private-registry-allowed-potential-r#tldr  
- ## TL;DR  
  
Wiz Research 在阿里云的两个热门服务 ApsaraDB RDS for PostgreSQL 和 AnalyticDB for PostgreSQL 中发现了一系列严重漏洞。这些被称为#BrokenSesame 的漏洞可能允许未经授权访问阿里云客户的 PostgreSQL 数据库，并能够对阿里巴巴的两个数据库服务执行供应链攻击，从而导致对阿里巴巴数据库服务的 RCE  
  
这项研究证明了每个安全团队都应该意识到的两个关键风险：   
1. 多租户应用程序中隔离不充分的风险——利用容器级别的一些不安全行为，我们能够逃逸到 K8s 节点并在 K8s 集群中获得高权限。这反过来又允许我们访问其他租户的数据库，从而可能危及服务的所有用户。   
  
解释一下：pod隔离不当 ，容器逃逸后打k8s，类似日常渗透思路。  
  
1. 容器  
registries写入权限范围不当的风险——一旦我们破坏了 K8s 节点，我们检查了用于从阿里云私有容器  
registry中pull images的已配置凭据的权限。由于严重的错误配置，凭据还具有对  
registry的写入权限。这意味着我们有能力覆盖阿里云使用的中央镜像仓库中的容器镜像，并有可能对阿里云数据库服务进行大规模的供应链攻击。  
  
解释一下：拿了k8s权限后找registry，registry未授权或者拿授权凭据pull images ，打镜像污染，搞供应链攻击。参考https://hackerone.com/reports/347296  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGoHhshohOpw0RDGXvIDVUjv1ia7zN7LrJuXnc04K2iabs6DfwQl2WhmM63sHetEktcEjCOheDv7QDbw/640?wx_fmt=png "")  
  
Wiz Research 于 2022 年 12 月负责任地向阿里云披露了#BrokenSesame。阿里云确认问题已得到充分缓解；没有客户数据被泄露，客户也不需要采取任何行动。  
## 介绍   
  
作为我们发现云隔离问题的努力的一部分，我们深入研究了阿里巴巴的两个流行的云服务：ApsaraDB RDS for PostgreSQL 和 AnalyticDB for PostgreSQL。ApsaraDB RDS 是一种托管数据库托管服务，具有自动监控、备份和灾难恢复功能。同时，AnalyticDB for PostgreSQL 是一种托管数据仓库服务。    
  
正如我们进行的每项云隔离研究一样，目标是确定攻击者如何绕过云提供商设置的安全边界并获得对其他客户数据的访问权限，这是一个影响许多托管服务提供商的重大问题。   
  
我们之前的研究，最著名的是ExtraReplica  
和Hell's Keychain  
，都是从利用跨多个云提供商发现的 PostgreSQL 漏洞开始的。在本次研究中，我们同样发现ApsaraDB RDS和AnalyticDB都存在类似的PostgreSQL漏洞，而且都是多租户服务，因此成为我们研究的理想对象。    
  
然而，这篇博客不会关注 PostgreSQL 漏洞本身，而是关注我们在这两个服务中发现的隔离问题。  
  
SRC tips: 就类似各位购买云上资产如redis ，mysql等都可以利用上述思路进行测试，如redis rce、主从rce测试、mysql读写系统文件、mysql命令执行等。  
##   
##   
## Kubernetes 中的多租户  
## 我们在进行云隔离研究的时候，有时希望在服务基础设施本身进行横向移动，以达到更大的影响。这为我们提供了一个独特的机会来检查这些服务如何从内部工作。在我们对云提供商的研究中，我们注意到许多云提供商在创建多租户托管服务时使用协调器。由于管理这些大规模环境可能很困难，因此像阿里云这样的供应商使用 Kubernetes 进行多租户，因为它简化了管理和维护过程。    
  
然而，成功实施多租户需要云提供商有效地隔离每个租户的资源，这不是一项简单的任务，因为所有资源都以某种方式相互关联。容器之间的网络连接、不正确的权限管理或不完善的容器隔离等任何错误配置都可能提供对其他租户资源的未授权访问。   
  
我们在这些研究中的发现说明了组织在使用 Kubernetes 时应该注意的实际安全问题。  
## 攻击流程   
  
我们通过使用过去发现的 PostgreSQL 漏洞在数据库实例上执行代码来开始我们的研究。  
然后我们意识到我们的容器是在 K8s 环境中运行的。  
在这种环境下，我们通常会尝试利用 K8s API 服务器来获取有关集群的信息并在其中执行操作。  
不幸的是，我们的容器无法直接通过网络访问 K8s API 服务器。  
这迫使我们将研究重点放在以下步骤上：  
   
- 提升我们在容器内的权限和/或对具有更多功能的容器执行横向移动。   
  
- 逃逸到底层主机（K8s 节点）以获取对 K8s API 服务器的访问权限。   
  
### AnalyticDB for PostgreSQL   
###   
1. 我们利用 cronjob 任务中的权限提升漏洞将我们的权限提升到容器内的 root 权限。   
  
1. 由于我们的能力仍然有限，我们通过利用共享的 PID 命名  
空间横向移动到 pod 中的特权相邻容器，使我们能够逃逸到底层主机（K8s 节点）。   
  
tips：参考cdk  
  
https://github.com/cdk-team/CDK  
  
https://kubernetes.io/zh-cn/docs/tasks/configure-pod-container/share-process-namespace/  
  
1. 进入节点后，我们利用强大的kubelet  
凭据访问敏感资源，包括机密、服务帐户和 pod。   
  
1. 在检查 pod 列表时，我们发现属于同一集群中其他租户的 pod。这表明阿里云将该集群用于多租户目的，这意味着我们有可能获得对这些 pod 的跨租户访问。   
  
1. 由于阿里云使用私有容器镜像存储库，我们获得了访问它的必要凭证，并因此检查了它们的权限。   
  
1. 在针对容器镜像注册表测试凭据后，我们发现我们不仅具有读取权限，而且还具有写入权限。这意味着我们有能力覆盖容器镜像，并可能对整个服务和其他服务的镜像进行供应链攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpRsJJNS5KEekmraYpDlibZE1ESo2jBpIgb64mTf2bO8oibDpkQXmbgojAxMQgGn0ZAWWsz43bTjE7g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpRsJJNS5KEekmraYpDlibZEuriayYdeoV1JWZiblC8B7Od8ibNKga6x1FSWad6SWkbtdWMeKymbkAZ8w/640?wx_fmt=png "")  
### ApsaraDB RDS for PostgreSQL  
###   
1. 我们利用了一个漏洞，使我们能够访问 pod 中相邻管理容器的源代码。   
  
1. 在我们对管理容器的源代码审计期间，我们发现了一个远程代码执行 (RCE) 漏洞，我们利用了相邻容器。后来我们发现这个容器是有权限的，可以让我们逃到宿主机（K8s节点）。   
  
1. 经过对节点的基本侦察，我们了解到阿里云再次使用了多租户集群。我们随后在我们的节点上发现了属于其他租户的数据库，这可能使我们能够访问他们的数据。   
  
1. 用于此服务的私有容器注册表存储库与用于 AnalyticDB 的相同，这意味着我们可以使用 AnalyticDB 的凭证对 ApsaraDB RDS 进行供应链攻击！  
  
## 安全团队的经验教训   
  
这项研究定义了几个使我们能够进行这些攻击的基本错误；这些陷阱与其他跨租户研究中发现的陷阱相似。借鉴这个案例，以及我们之前在 Hell's Keychain 研究中获得的 Kubernetes 多租户环境经验，我们现在能够查明这些核心问题，并为构建此类服务的人提供更多见解。   
- Linux 容器之间的隔离   
  
在设计具有多个容器的服务时，至关重要的是要准确地确定它们应该如何协同工作——如果有的话——以及这种交互可能带来的安全隐患。在 ApsaraDB RDS 和 AnalyticDB 中，我们的数据库容器与 K8s pod 中的其他操作容器共享不同的 Linux 命名空间。具体来说，它们共享 PID 命名空间，这允许我们的容器访问操作容器和文件系统中的其他进程。这个错误是致命的：它使我们能够对操作容器进行横向移动，从而逃离我们的容器！    
- Linux 容器作为安全屏障   
  
在 ApsaraDB RDS 案例研究中，Linux 容器是分隔客户数据库的唯一安全屏障，因为 K8s 节点托管多个客户的数据库（这并不理想）。如果对手设法执行了容器逃逸，他们就可以访问其他客户的数据。Linux 容器是一个合法的安全屏障，尽管还不够。服务构建者应该考虑使用像 Gvisor 或 Kata 容器这样的项目来阻止逃逸。阿里云的解决方案是使用其内部的容器加固方案。  
- Over-permissive identities  
  
在ApsaraDB RDS和AnalyticDB中，由于K8s集群是多租户的，kubelet服务账号权限过高，可以访问其他租户的资源。确定 kubelet 权限的范围对于限制对手访问至关重要，尤其是当他们已经逃脱了他们的专用容器实例时。作为对我们报告的回应，阿里云将 kubelet 权限限制在最低限度，以更好地将节点与其他资源隔离。   
- 非作用域容器registry凭据   
  
云提供商倾向于使用他们自己的私有容器注册表来在 K8s 环境中托管容器镜像。为此，K8s 节点必须可以访问注册表凭据，以便它可以拉取必要的图像。在 ApsaraDB RDS 和 AnalyticDB 的案例中，阿里云也使用了自己的容器注册中心。但是，我们发现用于拉取图像的凭据没有正确限定范围并允许推送权限，为供应链攻击奠定了基础。阿里云的解决方案是将 registry 用户权限限定为仅拉取操作。   
- Environmental hygiene issues and improper secret management  
   
  
AnalyticDB 服务中的 K8s 节点基础镜像包含构建过程中遗留的敏感机密。这个泄露问题对于租户隔离至关重要：一次秘密泄漏可能使攻击者能够破坏内部服务资源并在服务云环境中执行横向移动。阿里云不仅删除了节点上的所有secret，还轮换了所有secret并限制了权限。   
  
## 披露时间表   
  
01/11/2022 – Wiz Research 开始阿里云研究。   
12/11/2022 – 阿里云修复了一个 PostgreSQL 漏洞。  
04/12/2022 – Wiz 向阿里云报告了影响 ApsaraDB RDS for PostgreSQL 和 AnalyticDB for PostgreSQL 的漏洞。   
05/12/2022 – 阿里云安全团队回复称，他们在研究期间正在监控我们的活动，并采取了积极主动的方法，并且已经修复了一些漏洞。   
08/12/2022 – Wiz 和阿里云安全团队讨论了针对尚未修复的漏洞的缓解思路。   
24/02/2023 – 阿里云安全团队与 Wiz 测试实例共享以验证修复。   
12/04/2023 – 阿里云部署了所有缓解措施。  
  
以后这种洞还能不能挖到？ 实战真心有！  
  
相关文章： https://mp.weixin.qq.com/s/DNDvkNhBeq39L7y1eDs-qQ  
  
