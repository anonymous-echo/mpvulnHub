#  因 API 的错误配置导致 PII 泄漏漏洞   
dandh811  薯条机器猫   2024-01-20 18:51  
  
PII 指个人身份信息（Personally identifiable information）  
  
假定被测目标为：example.com  
### 1. 初步枚举     
  
一旦找到一个我觉得有趣的子域名，dirsearch 就是我立即使用的工具——它是我最喜欢的目录暴力破解工具之一。它的速度非常快，并且使用了一个非常好的单词列表。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/owl3DGLguul9T03slfFfZKmJVm979ATJibtJYsufD1aan7b4WNnzMJkYOg2Cc1SfNSlmGiaOaaicb4SvpMJEOR7aA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/owl3DGLguul9T03slfFfZKmJVm979ATJuLYUgpxGSMsEv6YD5mnmkCPd8bDDh1D1mHgkKKU1u79OItdqYFMWaQ/640?wx_fmt=png "")  
  
  
在这种情况下，dirsearch 帮助我找到了一个 /info 或 /info.php 页面，但是它不显示 phpinfo（），而是应用程序中真实用户的名称及其 UID。      
  
![](https://mmbiz.qpic.cn/mmbiz_png/owl3DGLguul9T03slfFfZKmJVm979ATJ3nfBib1gdrTicYY5fHhaibJY3VKLPyJQ2m14T6UWMiaiclLSJLkFJXgRicGw/640?wx_fmt=png "")  
  
敏感用户信息泄露  
### 2. 进一步枚举    
  
一旦我发现初始信息，我就开始寻找应用程序可能使用它的方式。这通常是通过基本的源代码审查来完成的（尤其是当代码没有被缩小/混淆时）。  
  
在这种情况下，只需浏览整个网站，Burp Suite 就能够找到所有 JavaScript 文件。  
  
对于信息收集，我使用以下 2 个扩展：  
- JS Miner:  
  
https://portswigger.net/bappstore/0ab7a94d8e11449daaf0fb387431225b  
- JS Link Finder:  
  
https://portswigger.net/bappstore/0e61c786db0c4ac787a08c4516d52ccf      
  
这些扩展可以帮助我查找有用的信息，例如：  
- API 接口  
  
- 依赖  
  
- 机密/凭据  
  
- 子域名  
  
- 云网址  
  
- 其他  
  
  
  
启用 JS Miner 并通过浏览整个网站，我找到以下 API 接口：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/owl3DGLguul9T03slfFfZKmJVm979ATJ5TAtmfyWicGKFjQE0bBWBs1GgIrPWIU3p7p9GqMTuZQ8UmlJJ3Z4LQQ/640?wx_fmt=png "")  
  
  
通过用户 UID 检查用户的 API 端点  
  
屏幕截图未显示全，该 API接口采用 UID 参数来搜索每个用户，从而生成以下 URL：  
  
https://get.example.com/admin/api/v1/check?uid=:uid      
### 3. 将信息泄漏与 API 错误配置联系起来    
  
现在，我决定测试是否能够获取用户的信息，使用之前找到的 UID 中的一个进行了测试，然后......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/owl3DGLguul9T03slfFfZKmJVm979ATJNXq6icMNmgwcsyM5tgFhhYfIZsBM9MGtWvrkeCKIgq9uR6xdiaRibbq7A/640?wx_fmt=png "")  
  
  
是的！API 不需要授权！非常幸运，因为很少有 API，尤其是管理员权限的 API，可以非授权访问。我能够泄露每个用户的全名、出生日期、当前地址、身份证件、电子邮件地址、电话号码等等。很可怕，对吧？  
  
为了展示全部影响，我创建了一个基本的概念验证 python 脚本，该脚本依次遍历所有用户 ID，并将结果以 CSV 格式保存，结果如下：  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/owl3DGLguul9T03slfFfZKmJVm979ATJLAIerbY327vaSNFrTIz11YYH5js2HM9ZfUl10ZGv1iatLiaWqBQ9icWUg/640?wx_fmt=png "")  
  
获取到所有用户的个人信息，  
我报告了该漏洞，它被评为严重！      
  
