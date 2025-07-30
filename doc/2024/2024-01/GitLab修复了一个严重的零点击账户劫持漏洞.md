#  GitLab修复了一个严重的零点击账户劫持漏洞   
鹏鹏同学  黑猫安全   2024-01-14 11:09  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce87lbfBj8jibjWmibyLpiaIMH7Sic802w5mFickNBCRVRicZtg926Sw3iaS46wc5b4egcfHqUELhEnVBxCcg/640?wx_fmt=png&from=appmsg "")  
  
GitLab发布了安全更新，以解决影响社区版和企业版的两个关键漏洞。最严重的漏洞被标记为CVE-2023-7028（CVSS评分10），是通过密码重置进行账户劫持。该漏洞可以在无需任何交互的情况下劫持账户。  
  
GitLab发布的警告中写道：“在GitLab CE/EE的所有版本中，从16.1之前的版本到16.1.6、从16.2之前的版本到16.2.9、从16.3之前的版本到16.3.7、从16.4之前的版本到16.4.5、从16.5之前的版本到16.5.6、从16.6之前的版本到16.6.4，以及从16.7之前的版本到16.7.2发现了一个问题，即用户账户的密码重置邮件可能会发送到一个未经验证的电子邮件地址。”  
  
这些漏洞影响以下版本：  
  
16.1之前的版本到16.1.5  
  
16.2之前的版本到16.2.8  
  
16.3之前的版本到16.3.6  
  
16.4之前的版本到16.4.4  
  
16.5之前的版本到16.5.6  
  
16.6之前的版本到16.6.4  
  
16.7之前的版本到16.7.2  
  
目前，该公司并不知道有任何在野利用CVE-2023-7028漏洞的攻击。建议自行管理的客户检查日志，以查看是否存在利用这个漏洞的尝试：  
  
检查gitlab-rails/production_json.log，查看是否有HTTP请求访问/users/password路径，参数params.value.email包含一个包含多个电子邮件地址的JSON数组。  
  
检查gitlab-rails/audit_json.log，查看是否有meta.caller.id为PasswordsController#create且target_details包含一个包含多个电子邮件地址的JSON数组的条目。  
  
该公司修复的第二个漏洞被标记为CVE-2023-5356（CVSS评分9.6），攻击者可以利用它滥用Slack/Mattermost集成并以另一个用户的身份执行斜杠命令。  
  
GitLab还通过发布16.7.2版本解决了以下问题：  
  
CVE-2023-4812：绕过CODEOWNERS批准移除。  
  
CVE-2023-6955：工作空间的不正确访问控制。  
  
CVE-2023-2030：提交签名验证忽略签名后的头部。  
  
该公司敦促组织立即更新其安装。  
  
  
