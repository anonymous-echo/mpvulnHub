#  专家发现AWS存在 RCE、数据窃取和全服务接管的严重漏洞   
flyme  独眼情报   2024-08-10 12:32  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnRU3lnnZAEvR1xtNweMicnzGrlmAMMjMqpGwZcUrMxNJez7ULuRNh6ZKic424kiaqgv1Q24LslscMqcQ/640?wx_fmt=other&from=appmsg "")  
  
网络安全研究人员发现了亚马逊网络服务 (AWS) 产品中存在多个严重缺陷，如果成功利用，可能会导致严重后果。  
  
云安全公司 Aqua 在与 The Hacker News 分享的详细报告中表示：“这些漏洞的影响范围包括远程代码执行 (RCE)、全方位服务用户接管（可能提供强大的管理访问权限）、操纵 AI 模块、暴露敏感数据、数据泄露和拒绝服务。”  
  
继 2024 年 2 月负责任地披露漏洞后，亚马逊在 3 月至 6 月的几个月内解决了这些问题。调查结果  
在 2024 年美国黑帽大会上进行了  
展示。  
  
该问题的核心被称为“Bucket Monopoly”，是一种称为“影子资源”的攻击媒介，在本例中指的是使用 CloudFormation、Glue、EMR、SageMaker、ServiceCatalog 和 CodeStar 等服务时自动创建 AWS S3 存储桶。  
  
以此方式创建的 S3 存储桶名称既独特又遵循预定义的命名约定（“cf-templates-{Hash}-{Region}”）。攻击者可以利用此行为在未使用的 AWS 区域中设置存储桶，并等待合法的 AWS 客户使用其中一个易受攻击的服务来秘密访问 S3 存储桶的内容。  
  
根据授予攻击者控制的 S3 存储桶的权限，该方法可用于升级以触发 DoS 条件，或执行代码、操纵或窃取数据，甚至在用户不知情的情况下完全控制受害者帐户。  
  
为了最大限度地提高成功率，攻击者可以使用 Bucket Monopoly 在所有可用区域中预先创建无人认领的存储桶，并在存储桶中存储恶意代码。当目标组织首次在新的区域中启用其中一项易受攻击的服务时，恶意代码将在不知情的情况下执行，这可能会导致创建一个可以向攻击者授予控制权的管理员用户。  
<table><tbody style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><tr style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><td style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;padding-right: 5px;padding-left: 5px;vertical-align: baseline;text-align: center;float: none !important;"><img border="0" class="rich_pages wxw-img" data-imgfileid="100004205" data-ratio="0.28434065934065933" data-src="https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnRU3lnnZAEvR1xtNweMicnzG9o1w72pIIOGNY9EicUu5FMicOSvqGQXrAETWptfGibTjyYa0MdvJyMf9A/640?wx_fmt=other&amp;from=appmsg" data-type="other" data-w="728" style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;margin-right: auto;margin-left: auto;display: block;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;opacity: 1;transition: transform 0.3s;text-indent: -9999px;border-radius: 6px;width: inherit;"/></td></tr><tr style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><td style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;padding: 0px;vertical-align: baseline;font-size: 14px;color: rgb(87, 102, 136);letter-spacing: 0.2px;text-align: center;float: none !important;"><span style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;vertical-align: inherit;">CloudFormation 漏洞概述</span></td></tr></tbody></table>  
然而，需要注意的是，攻击者必须等待受害者首次在新的区域中部署新的 CloudFormation 堆栈才能成功发起攻击。修改 S3 存储桶中的 CloudFormation 模板文件以创建恶意管理员用户还取决于受害者帐户是否具有管理 IAM 角色的权限。  
<table><tbody style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><tr style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><td style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;padding-right: 5px;padding-left: 5px;vertical-align: baseline;text-align: center;float: none !important;"><img border="0" class="rich_pages wxw-img" data-imgfileid="100004204" data-ratio="0.40384615384615385" data-src="https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnRU3lnnZAEvR1xtNweMicnzGJHd2jadyfnADD5qjPg2ISDgDUgLRgLMtGqGkGOrpukHMle3QhOJ1iaw/640?wx_fmt=other&amp;from=appmsg" data-type="other" data-w="728" style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;margin-right: auto;margin-left: auto;display: block;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;opacity: 1;transition: transform 0.3s;text-indent: -9999px;border-radius: 6px;width: inherit;"/></td></tr><tr style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><td style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;padding: 0px;vertical-align: baseline;font-size: 14px;color: rgb(87, 102, 136);letter-spacing: 0.2px;text-align: center;float: none !important;"><span style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;vertical-align: inherit;">Glue 漏洞概述</span></td></tr></tbody></table><table><tbody style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><tr style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><td style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;padding-right: 5px;padding-left: 5px;vertical-align: baseline;text-align: center;float: none !important;"><img border="0" class="rich_pages wxw-img" data-imgfileid="100004203" data-ratio="0.2774725274725275" data-src="https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnRU3lnnZAEvR1xtNweMicnzGM9tnv5uzeLUx7xHhwW9IwFdUMaqoYwdIZ5sMmg1fxedI14AFiadOzibg/640?wx_fmt=other&amp;from=appmsg" data-type="other" data-w="728" style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;margin-right: auto;margin-left: auto;display: block;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;opacity: 1;transition: transform 0.3s;text-indent: -9999px;border-radius: 6px;width: inherit;"/></td></tr><tr style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;border-width: 0px;border-style: initial;border-color: initial;vertical-align: baseline;"><td style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;padding: 0px;vertical-align: baseline;font-size: 14px;color: rgb(87, 102, 136);letter-spacing: 0.2px;text-align: center;float: none !important;"><span style="scrollbar-width: thin;scrollbar-color: rgb(224, 224, 240) rgb(255, 255, 255);outline: 0px;vertical-align: inherit;">CodeStar 漏洞概述</span></td></tr></tbody></table>  
Aqua 表示，它发现另外五种 AWS 服务也依赖类似的 S3 存储桶命名方法 - {服务前缀}-{AWS 帐户 ID}-{区域} - 从而使它们暴露于影子资源攻击，并最终允许威胁行为者提升权限并执行恶意操作，包括 DoS、信息泄露、数据操纵和任意代码执行 -  
- AWS Glue: aws-glue-assets-{Account-ID}-{Region}  
  
- AWS Elastic MapReduce (EMR): aws-emr-studio -{Account-ID}-{Region}  
  
- AWS SageMaker: sagemaker-{Region}-{Account-ID}  
  
- AWS CodeStar: aws-codestar-{Region}-{Account-ID}  
  
- AWS Service Catalog: cf-templates-{Hash}-{Region}  
  
该公司还指出，AWS 账户 ID 应该被视为秘密，这与亚马逊在其文档中  
所述的  
相反，因为它们可用于发动类似的攻击。  
  
Aqua 表示：“这种攻击媒介不仅影响 AWS 服务，还影响组织用于在其 AWS 环境中部署资源的许多开源项目。许多开源项目都会自动创建 S3 存储桶作为其功能的一部分，或者指示其用户部署 S3 存储桶。”  
  
“建议不要在存储桶名称中使用可预测或静态的标识符，而是为每个区域和帐户生成唯一的哈希值或随机标识符，并将该值合并到 S3 存储桶名称中。这种方法有助于防止攻击者过早地认领您的存储桶。”  
  
  
