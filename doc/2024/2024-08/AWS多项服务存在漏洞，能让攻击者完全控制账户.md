#  AWS多项服务存在漏洞，能让攻击者完全控制账户   
Zicheng  FreeBuf   2024-08-12 19:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
据The Hacker News消息，网络安全研究人员在 Amazon Web Services （AWS） 产品中发现了多个严重漏洞，如果成功利用这些漏洞，可能会导致严重后果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39HkdkkbeicU4UFJAMggoNRib1K4c3FblKg9uicK0sokWLDsl1yeSm44cVlb6FEC9Zbn9sIPAh1I1p6g/640?wx_fmt=png&from=appmsg "")  
  
  
根据云安全公司Aqua在与The Hacker News分享的一份详细报告，这些漏洞的影响范围包括远程代码执行（RCE）、全方位服务用户接管（可能提供强大的管理访问权限）、操纵人工智能模块、暴露敏感数据、数据泄露和拒绝服务攻击。  
  
  
其中，研究人员发现最核心的问题是一种被称为桶垄断（Bucket Monopoly）的影子资源攻击载体，能在使用 CloudFormation、Glue、EMR、SageMaker、ServiceCatalog 和 CodeStar 等服务时自动创建 AWS S3 存储桶。  
  
  
由于以该方式创建的 S3 存储桶名称具有唯一性，又遵循预定义的命名规则，攻击者可利用此行为在未使用的 AWS 区域中设置存储桶，并等待合法的 AWS 客户使用上述易受攻击的服务之一来秘密访问 S3 存储桶的内容。  
  
  
根据攻击者控制的S3存储桶权限，该攻击方法可用于升级以触发 DoS 条件，或执行代码、操纵或窃取数据，甚至在受害者不知情的情况下完全控制其账户。  
  
  
不过，攻击者必须等到受害者首次在新区域部署新的 CloudFormation 堆栈才能成功发起攻击。而修改 S3 存储桶中的 CloudFormation 模板文件以创建恶意管理员用户还取决于受害者账户是否具有管理 IAM 角色的权限。  
  
  
Aqua 表示，这种攻击方式不仅影响 AWS 服务，还影响企业组织在AWS 环境中部署的许多开源项目。Aqua还发现其他五项 AWS 服务依赖于类似的 S3 存储桶命名方法，从而容易遭受影子资源攻击：  
  
- AWS Glue: aws-glue-assets-{Account-ID}-{Region}  
  
- AWS Elastic MapReduce (EMR): aws-emr-studio -{Account-ID}-{Region}  
  
- AWS SageMaker: sagemaker-{Region}-{Account-ID}  
  
- AWS CodeStar: aws-codestar-{Region}-{Account-ID}  
  
- AWS Service Catalog: cf-templates-{Hash}-{Region}  
  
这些漏洞于2024年2月首次得到披露，亚马逊在3月—6月期间对这些漏洞进行了修复，相关研究成果已在近期举行的2024美国黑帽大会上进行了公布。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://thehackernews.com/2024/08/experts-uncover-severe-aws-flaws.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494714&idx=1&sn=fe28fee45c1508a1645fd04c2b18ca82&chksm=ce1f16a5f9689fb3996529f7738a1b7dc3960f3fc5bd31c7d1505dbd3a179d5b3bfd6c66e5f3&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494663&idx=1&sn=8220aadcd0c1496c6ecbae5bc5fddee1&chksm=ce1f1698f9689f8e004a21a851d5d2987d45054bf636fad5abba5b977ae3ab342ce2a73b26f8&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
