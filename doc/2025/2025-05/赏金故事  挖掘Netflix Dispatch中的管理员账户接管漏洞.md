#  赏金故事 | 挖掘Netflix Dispatch中的管理员账户接管漏洞   
白帽子左一  白帽子左一   2025-05-12 04:03  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
# 引言  
  
在暂停参与 Netflix 漏洞赏金计划一段时间后，我决定再次尝试一次。  
  
我在 Netflix 的 Dispatch 项目中发现了一个有趣的漏洞，该漏洞可以在无需用户任何操作的情况下接管包括管理员在内的任何账户。这仅在使用默认的“**Basic**  
”认证提供程序时才可能实现。  
  
我们感谢 Netflix 允许我们发布此报告。**该漏洞已被修复，并且补丁已经发布。**  
# 范围与应用  
  
该项目的测试范围很广，因此我们的第一个挑战是决定要专注于哪种类型的测试。我们有两个选择：  
- • 专注于大规模的信息收集  
  
- • 深入了解一个应用程序，并掌握其全部细节  
  
与此同时，我注意到由   
nahamsec  
 组织的一组研究人员正在测试 Netflix。已经有很多优秀的黑客在进行大规模的信息收集工作。  
  
在思考了一段时间后，我们最终决定采用第二种方法，专注于名为 “**Dispatch**  
” 的开源项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9JH6v0ErKn1g4I1hBsDwicuFMpYuuzjlAo4iaKd6kghLJlUzpYtMuyRTA/640?wx_fmt=png&from=appmsg "null")  
  
  
hackerone.com/netflix  
  
**Netflix Dispatch 项目介绍：**  
 https://netflix.github.io/dispatch/  
> 你今天为了管理安全事件所做的所有临时操作，Dispatch 都能帮你自动完成，外加许多你本该做但没时间去做的事！  
> Dispatch 通过与组织内部现有工具（如 Slack、GSuite、Jira 等）的深度集成，帮助我们高效地管理安全事件。  
  
  
我们选择这个目标的原因是它具备一些有趣的功能，这可以在其文档中看到：https://netflix.github.io/dispatch/docs/administration。  
  
此外，我们还进行了研究，发现该项目已经有几个有趣的漏洞被披露。这些信息可以在安全公告中查看：  
  
GitHub - Netflix/security-bulletins: 与 Netflix 开源项目相关的安全公告  
- • **2024 年 8 月 1 日：Dispatch 消息模板中的服务器端模板注入漏洞**  
  
- • **2023 年 8 月 17 日：Dispatch 中用于签署 JWT 令牌的密钥泄露**  
  
- • **2020 年 11 月 6 日：Dispatch 中存在多个访问控制问题**  
  
- • **2020 年 11 月 6 日：Dispatch 中存在多个 XSS 漏洞**  
  
在重新查看项目指南后，我们注意到关于 Dispatch 项目及其配置存在特定的限制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9p7NwiclKLx93T8EeFWstb318nicaXR7PmzoqksUVLbj1EMPHtwMByhaQ/640?wx_fmt=png&from=appmsg "null")  
  
  
https://hackerone.com/netflix  
  
有趣的是，官方文档强烈推荐使用 Docker 来安装该项目，然而，**却缺乏从零开始安装的相关文档。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9XImJNXqx1LfmjgVPxd8tBIqRggKGZNAI5ibhug808vtw52Yx3ePg3sA/640?wx_fmt=png&from=appmsg "null")  
  
  
https://netflix.github.io/dispatch/docs/administration/installation  
  
最终，我们发现自己处于这样一个境地：  
- • 我们不能使用 Docker 来配置 Dispatch（根据 HackerOne 的规定）  
  
- • 官方文档却强烈推荐使用 Docker  
  
- • 没有关于如何在不使用 Docker 的情况下安装 Dispatch 的详细文档  
  
- • dispatch-docker 项目实际上是通过主 Dispatch 项目来进行设置的  
  
在这种情况下，我们所做的是参考“不在范围内”的 dispatch-docker 项目的 “**docker-compose.yml**  
” 中的步骤，并从零开始手动构建该项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9ndCibe77BBkwfY5XklfdOaPfHmXJjbRaoKpT5rnzRdVzJ2hS2SKTF6Q/640?wx_fmt=png&from=appmsg "null")  
  
  
https://github.com/Netflix/dispatch-docker/blob/master/docker-compose.yml#L22  
  
这个步骤是必要的，因为我们希望在后续的漏洞报告中提供从零开始安装的详细步骤。否则，审核人员**可能会将我们的报告标记为超出范围（Out of Scope）。**  
# 设置调试工具  
  
在这一阶段，我们已经成功在本地运行了该项目。在这种情况下，监控所有对数据库的查询以及启用调试模式是非常有用的，这样我们可以更好地理解该应用程序的运行机制。  
  
在这个特定案例中，我们使用了 **pgAudit（PostgreSQL 插件）**  
 来实时监控数据库查询。  
  
此外，应用程序还提供了一个调试模式，可以提升错误信息的详细程度。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9o8fPGhV3woribXia1dx7GhagZLduqQFFjPQnPHbjLDs3kqbNwOPib3Wmg/640?wx_fmt=png&from=appmsg "null")  
  
  
pgAudit  
# 身份验证提供程序设置  
  
我们已经完成了所有配置。下一步是选择一个身份验证提供程序，并审查其所有功能，重点关注那些可能存在有趣漏洞的部分。  
  
Dispatch 提供了两种身份验证方式：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9WBNLYR12d4kF1ia9Picdf95icG32oBCMqvczBPKLxl8vbkXx8wVP2BaHw/640?wx_fmt=png&from=appmsg "")  
  
  
https://netflix.github.io/dispatch/docs/administration/installation#authentication  
  
正如其文档中所述，默认的身份验证提供程序是 “**Basic**  
”，该方式允许用户自行注册。  
  
其工作机制是：你在应用中创建一个账户后，系统会为你分配权限最低的角色——“**Member**  
”。这对我们来说是一个不错的起点。  
  
我们准备好所有必要的工具后，创建了一个账户并开始探索该应用程序。  
# 发现账户接管漏洞  
  
在花了一些时间之后，我们注意到角色访问控制中存在一个有趣的行为。  
  
Dispatch 使用基于角色的访问控制（RBAC）来保护其用户界面。根据文档说明，该机制仅用于保护可见性被设置为“受限”的敏感事件。  
  
然而，我们证实管理员还可以访问插件部分中为所有集成服务配置的密钥信息（secrets）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9G31LEJiac0DxQ8ZAyDH8BP7Qfa8ul5RRA0UlhJbyHZGqicZxDxANdCAA/640?wx_fmt=png&from=appmsg "")  
  
  
Plugins page of Dispatch Projects  
  
因此，如果你被分配的是权限最低的“Member”角色 —— 你本不应该查看私密事件或包含密钥的外部集成配置。  
  
需要注意的是，在 Dispatch 中，所有用户都可以访问每个组织的成员列表。只有被授予“Owner”角色的用户才能编辑其他用户的信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9CIqOibznw31mebX1bbBsaACJRe74WY0YPvoAXbvyWZ6zbm2B3Y8tibiaQ/640?wx_fmt=png&from=appmsg "null")  
  
  
Member list of Dispatch Projects  
  
我们通过尝试**作为权限较低的用户——Member——编辑其他用户的角色**  
来确认这一点。系统返回了以下错误：“**你没有权限更新用户的角色。请联系组织的所有者。**  
”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9FMFQmnfGHYgctRIKRIlQx7bQyJqZylten5Oo1qiaNlayMdxs6giaQUGA/640?wx_fmt=png&from=appmsg "")  
  
  
Edit Admin User  
  
然而，如果你仅仅打开任何用户（包括管理员）的“**编辑**  
”页面，然后直接点击“保存”，**无需更改任何字段**  
，系统会提示“**用户更新成功**  
”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9TeicntAUrEUocNRVqO22wIibvEafBMicfQntd8lhPXLQrM2157gw8e5fQ/640?wx_fmt=png&from=appmsg "")  
  
  
这个消息是一个迹象，表明背后发生了某些有趣的事情。经过几次尝试和观察后，通过“**pgAudit**  
”的数据库查询证实了这一点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9Xc2V5fhU31D9abdEvOJrss9vmVXtLjeLRZS8tcVhIDrFjYxDscrNlQ/640?wx_fmt=png&from=appmsg "")  
  
  
显然，当点击“**保存**  
”按钮时，会执行一个影响密码字段的“**UPDATE**  
”查询。  
  
有了这些信息，我们决定查看源代码，发现了一个非常有趣的行为：  
  
**漏洞代码：**  
https://github.com/Netflix/dispatch/blob/699fd28a06eebe803f43fe449857b62d8b51554b/src/dispatch/auth/views.py#L178  
```
    if user_in.role:        # New user role is provided        user_organization_role = user.get_organization_role(organization)        if user_organization_role != user_in.role:            # New user role provided is different than current user role            current_user_organization_role = current_user.get_organization_role(organization)            if current_user_organization_role != UserRoles.owner:                # We don't allow the role change if user requesting the change does not have owner role                raise HTTPException(                    status_code=status.HTTP_403_FORBIDDEN,                    detail=[                        {                            "msg": "You don't have permissions to update the user's role. Please, contact the organization's owner."                        }                    ],                )    # add organization information    user_in.organizations = [        UserOrganization(role=user_in.role, organization=OrganizationRead(name=organization))    ]    # we currently only allow user password changes via CLI, not UI/API.    user_in.password = None    return update(db_session=db_session, user=user, user_in=user_in)
```  
  
权限检查只会在修改“**Role**  
”字段时触发。如果你尝试将其从“**Member**  
”更改为“**Admin**  
”，系统会报错。  
  
然而，如果你**不做任何更改**  
就点击“保存”，权限验证将被绕过，以下代码将会执行：  
```
# we currently only allow user password changes via CLI, not UI/API.    user_in.password = None
```  
  
在这种情况下，“**user_in.password**  
” 本应被赋值为布尔值“**False**  
”，以防止任何更改，正如其中一个提交所述。  
  
出乎意料的是，值被作为字符串存储/哈希，允许任何用户的密码被设置为字符串“**None**  
”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz94h28G2gtU3qK3cKppoX3ro35fl8As2hAktR0hWzfxib9jnLyEzXg99Q/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHqsBOM0SohIycK93fxyIz9sRNfiaA2WyFRkMzAtmwEcyfh0SWnVNyzp8cb1HLQOsjpSJ0nib5eWacA/640?wx_fmt=png&from=appmsg "null")  
  
  
简单来说，我们可以通过打开受害账户的“**编辑**  
”页面并点击“**保存**  
”按钮，将任何账户（包括管理员账户）的密码重置为“**None**  
”。  
  
这个漏洞是在修复 2020 年之前报告的漏洞时引入的，详情见链接：https://github.com/Netflix/security-bulletins/blob/master/advisories/nflx-2020-005.md  
# 向 Netflix 提交报告  
  
在我们报告这个漏洞时，我们明确提到我们是从零开始安装的该应用，并提供了所有必要的步骤给审核人员。  
  
Netflix 团队评估了该漏洞，决定接受，并将其分类为中等严重性的报告，属于次要目标，并为此奖励了赏金。  
  
   
  
获取更多精彩内容，尽在Track安全社区~：  
https://bbs.zkaq.cn  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
****  
  
