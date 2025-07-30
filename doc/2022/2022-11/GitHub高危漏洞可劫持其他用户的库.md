#  GitHub高危漏洞可劫持其他用户的库   
 网络安全应急技术国家工程中心   2022-11-04 15:59  
  
研究人员发现GitHub存在库劫持漏洞，攻击者利用该漏洞可接管其他用户的库。  
  
GitHub库在创建库的用户账号下有唯一的URL。当其他用户想要下载或复制该库时，会使用到该库的完整URL。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176nq8WN4lHUlibPCPqALdxZPRsmSsGp0IuNK3Kv4vjXib1l8yv3yExGrfmOdImndOqI49X4BiaJyWhliaA/640?wx_fmt=jpeg "")  
  
但是GitHub用户是可以修改其账户名的。GitHub支持修改用户重命名，并会展示如下信息，包括现有库的URL的流量会重定向到新的库URL。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic9uhWtzDpGX14Ee9ly5S11Kl8qUrsjicQaVVTCXkOxoxfXozx9odCNibIGSIASEvkQ7txEYuvHv3dA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在接受警告信息并修改用户名后，GitHub会自动设置从旧的库URL转到新URL的重定向规则。而用户不会意识到GitHub库所有者用户名的变化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic9uhWtzDpGX14Ee9ly5S11P6ff55lsGEWJsdgTdLwZLzmiaBwXxO4V7n9Fa4nn925vBBpmAMFMW6w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**库劫持**  
  
库劫持（RepoJacking）是指通过利用逻辑漏洞破坏原始重定向过程，实现劫持修改了用户名的URL的流量并重定向到攻击者库的过程。研究人员在GitHub中发现了一个库劫持漏洞，当创建者决定修改其用户名，而老的用户名可以用于注册时就会出现可劫持库的情况。  
  
从GitHub库名与创建者用户名之间的关系可以看出，GitHub可以创建一个新的GitHub账户与现有用户使用的老库URL一致。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic9uhWtzDpGX14Ee9ly5S11KrvSNwymI8M7Q2iaQnOxXHC9niawUh5V3iayJiaHh0JcuFCFj7mbhV3kCQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
此时，默认的重定向就被禁用了，所有现有流量都会立刻路由到攻击者的恶意GitHub库。   
  
**GitHub应对方法**  
  
为应对此类行为，GitHub实施了流行库命名空间退出（popular repository namespace retirement）保护策略：超过100个clone的库在用户账户修改时会会被标记为退出（retired）状态，无法被其他人使用。比如，repo库被clone超过100次，用户名“account-takeover-victim”就无法再创建名为repo的库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic9uhWtzDpGX14Ee9ly5S11nJyohJQoNZN2tzd92psAxsibSja0E1Qt1ArLXPQcCUXBcUDbE5ZWQhg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**绕过GitHub保护**  
  
研究人员进一步分析发现GitHub提出的应对保护措施可以被绕过。新的绕过方法使用了“Repository Transfer”特征，具体步骤如下：  
  
“victim/repo”是受GitHub retirement保护的GitHub 库，  
  
“helper_account”账户创建了repo库；  
  
“helper_account”将repo库的所有权转给了“attacker_account”；  
  
“attacker_account”将其用户名重命名为“victim”。  
  
新的“victim”账号实际上就是之前的“attacker_account”，会接受所有权的转移。  
  
victim/repo”就会被攻击者控制。  
  
**影响**  
  
攻击者成功利用该漏洞可以控制主流的包管理器的代码包，包括“Packagist”、“Go”、“Swift”等。研究人员发现有超过1万个重命名的包受到该漏洞的影响。此外，攻击者利用该漏洞还可以发起供应链投毒攻击。  
  
**时间轴**  
  
2021年11月8日，研究人员将GitHub命名空间退出特征绕过方法提交给了GitHub。2022年3月，GitHub回复称已修复该绕过。5月，研究人员发现该漏洞仍然是可利用的，5月25日，GitHub修复该问题。6月，研究人员发现了绕过GitHub命名空间退出特征保护机制的绕过方法，并报告给了GitHub。9月19日，GitHub修复该漏洞，并将该漏洞分类为高危。  
  
**参考及来源：**  
  
https://checkmarx.com/blog/attacking-the-software-supply-chain-with-a-simple-rename/  
  
  
  
原文来源  
：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176njVOPvfib4X3jQ6GIHLtX8SSDvbpmcpr4uu3X7ELG7PDjdaLVeq4Er02ZoicTPvxrC6KCVH3bssUVw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
