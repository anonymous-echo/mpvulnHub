#  逻辑漏洞-使用 SSO 登录进行帐户接管   
原创 红云谈安全  红云谈安全   2025-05-29 02:26  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！请在授权的站点测试，遵守网络安全法！  
**仅供**  
**学习使用，****如若非法他用，与平台和本文作者无关，需自行负责！**  
  
公司通常会为用户提供各种登录方法来验证他们的帐户。  
  
您可能在许多网站上遇到过“使用 Google”、“Facebook”或“Apple”等选项。  
  
  
即使您使用电子邮件/密码创建帐户，您仍然可以使用第三方 SSO（单点登录）选项登录该帐户。  
  
**隐藏的 SSO 选项**  
  
许多人没有意识到的是，一些网站还提供自定义 SSO 登录选项，例如 Okta 或 Auth0。  
  
这些隐藏的 SSO 选项通常可以启用，允许您也通过这些提供商登录您的帐户。  
  
**例子：**  
  
如果您访问 Grammarly，您通常会看到 Google、Apple 和 Facebook 作为 SSO 登录选项。  
  
  
但 Grammarly 也提供了自定义 SSO 选项。  
  
  
**使用自定义 SSO 创建用户**  
  
如果您想在 Facebook、Google 或 Apple 上创建带有电子邮件的帐户victim@gmail.com，则需要验证该电子邮件地址属于您。  
  
但是对于像 okta、auth0 这样的 SSO 提供商，您不需要验证任何内容。  
  
没有电子邮件验证步骤。  
  
您可以使用您选择的任何电子邮件地址创建用户帐户。  
  
  
预期的SSO登录流程  
  
  
在target.com中，存在一个名为OrganizationA的组织。  
  
组织A的成员admin@gmail.com ,user1@gmail.com以及user2@gmail.com  
  
  
OrganizationA已使用Okta启用自定义SSO登录。  
  
  
管理员设置Okta实例，并使用电子邮件创建用户admin@gmail.com ,user1@gmail.com并将其与组织A联系起来。  
  
****  
  
  
管理员设置Okta实例，并使用电子邮件创建用户admin@gmail.com ,user1@gmail.com并将其与组织A联系起来。  
  
现在，用户user1@gmail.com , user2@gmail.com可以使用Okta SSO登录target.com。  
  
  
配置错误  
  
  
认为victim@gmail.com是target.com上受害者组织的成员。  
  
  
攻击者在target.com上创建AttackerOrganization并邀请victim@gmail.com作为会员。  
  
  
然后，攻击者设置Okta并将其与攻击者组织链接  
  
  
在Okta实例中，攻击者使用电子邮件创建了一个用户帐户victim@gmail.com  
  
  
使用此链接到的假冒（攻击者）Okta帐户victim@gmail.com，攻击者以以下身份登录target.comvictim@gmail.com  
  
  
自从victim@gmail.com作为VictimOrganization的成员，攻击者能够在target.com内切换组织，未经授权访问敏感数据和功能。  
  
  
报告示例  
  
  
  
**报告示例**  
  
  
  
  
  
  
  
