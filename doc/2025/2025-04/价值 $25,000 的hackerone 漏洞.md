#  价值 $25,000 的hackerone 漏洞   
原创 漏洞集萃  漏洞集萃   2025-04-13 10:57  
  
###   
  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_png/Y5LD4fX7WOJdjicUNKq3NNeEMQM3wWet42WkzmIEzBAdszMico2Sp6BeFuX4iaYgoC1CYmau8iasKSBJnpOH6cVrAQ/640?wx_fmt=png&from=appmsg "")  
  
这个故事的标题听起来有点怪，但确实如此。故事围绕的是在 HackerOne 发现的一个安全漏洞展开，这个漏洞会暴露 HackerOne 的漏洞报告者（也就是“黑客”）和项目团队成员账户的敏感个人数据。所谓敏感数据，包括报告者/团队的邮箱、电话号码、OTP 备用码、GraphQL 密钥令牌、API Token 等等。  
### 起因：只是一次普通的研究  
  
星期三晚上，我正在翻阅 HackerOne 上已经披露的漏洞报告，并观察其中的 “GraphQL” 查询，为接下来的研究做准备。我当时是在测试一些基本查询，当它们附加到其他操作上时的响应方式。为了收集基础查询结构，我访问了某个报告的 .json  
 端点。  
  
HackerOne 的报告页面其实都支持一个 .json  
 结尾的端点，也就是说，只要访问 https://hackerone.com/reports/<report-id>.json  
 就可以获取该报告的 JSON 格式数据。report-id  
 是 HackerOne 报告中的数字 ID，任何报告页面都有。  
### 意外发现：数据裸奔  
  
当我打开自己一个沙盒测试报告的 .json  
 端点时，居然发现它泄露了我的邮箱、手机号，甚至还有其他私密信息。起初我以为是因为我登录了自己的测试账号，没太在意。但转念一想，难道这个漏洞也会影响别人的报告？我决定试试看。  
  
正好，我之前在 Burp Suite 的 Repeater 工具中加载了另一个公开报告的 .json  
 端点，虽然没细看。我赶紧切回去一看，果然，在响应内容中，报告者账户的敏感数据也被泄露了。  
  
我没有犹豫，立刻将这个问题报告给 HackerOne 的安全团队。  
### 漏洞请求示例（已隐藏报告 ID）：  
```
ounter(lineounter(line
GET /reports/XXXXXXX.json HTTP/2
Host: hackerone.com
```  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
email
"changed_password_at"
"totp_secret"
"allow_next_sign_in_attempt_at
otp_backup_codes
"tshirt_size"
current_sign_in_country
request_endorsements_at
"graphql_secret_token
overview_token_2017
account_recovery_phone_number" (in hashed form)
account_recovery_unverified_phone_number"
account_recovery_phone_number_sent_at
account_recovery_phone_number_token
totp_enabled_at
sequential_totp_failures
facebook_oauth_state
ctf_points
"calendar_token"
cached_reputation_for_user_profile_last_reputation_id

etc etc
```  
### 测试账号中泄漏的数据片段（已打码）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Y5LD4fX7WOJdjicUNKq3NNeEMQM3wWet4aHwPickeX4UoVV1D4vTouiajuHD5ichIl1LOXDrRibmObRNeZvcmz2Epzw/640?wx_fmt=png&from=appmsg "")  
### 问题本质：  
  
如果一个报告（无论是公开的还是私密的）中包含了团队或报告者写的“摘要”，那么访问其 .json  
 端点时，这段摘要的 JSON 数据下就会暴露该账户的敏感字段信息。如果团队和报告者都写了摘要，那两个账户的敏感信息都会泄漏。  
  
造成这个漏洞的根本原因是 **Rails 升级后对 JSON 序列化的行为发生了变化，导致敏感数据意外暴露**  
。以下是详细的漏洞成因分析：  
### 漏洞原因：  
  
根源在于 HackerOne 在 2025年2月19日 升级了其核心框架，从 **Rails 6.1.7.9**  
 升级到了 **Rails 7.1.5.1**  
。但一个“细微”的差异引发了连锁反应：  
```
ounter(lineounter(lineounter(lineounter(line
hash = {
  my_key: 'my_value',
  'my_key' => 'my_other_value',
}
```  
  
在 Rails 6 中：  
```
ounter(line
{"my_key":"my_other_value"}
```  
  
在 Rails 7 中：  
```
ounter(line
{"my_key":"my_value","my_key":"my_other_value"}
```  
  
由于 to_json  
 在新版本中保留了重复键，user  
 信息在 JSON 中被写入了**两次**  
——一次是完整的用户对象（含敏感字段），另一次是经过脱敏的模板。这使得攻击者可以直接通过 JSON 接口访问完整的内部数据。  
#### 🔍 技术细节深挖  
  
罪魁祸首在于这段逻辑：  
```
ounter(lineounter(lineounter(lineounter(lineounter(line
json.merge!(summary.json_attributes)
...
json.user do
  json.partial!('users/user', user: summary.user)
end
```  
  
summary.json_attributes  
 返回的是包含 symbol 键的 user:  
，随后又以 string 键的 "user"  
 引入部分数据。升级后的 ActiveSupport::JSON.encode  
 没有合并两者，而是**并存输出**  
，直接导致信息泄露。  
### 🔍 漏洞触发流程简述：  
1. **在某些报告中，如果 Reporter 或 Team 成员填写了 summary，后端会将 summary 数据通过 /reports/:id.json 接口以 JSON 格式返回。**  
  
1. **后端代码中使用了 .merge!() 合并 summary.json_attributes 返回的哈希对象到 JSON 响应中。**  
  
1. 在 json_attributes  
 方法中，user  
 对象被直接作为一个键值对包含在其中，形式为：  
```
{
  ...,
  user: <User Object>,
  ...
}
```  
  
这个 user:  
 是以 **Symbol 形式存在的键**  
。  
  
  
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1. 随后模板中又显式调用了：  
```
json.user do
  json.partial!('users/user', user: summary.user)
end
```  
  
这又添加了一个 **字符串形式的键 "user"**  
，对应的是一个经过模板脱敏处理的用户信息。  
  
  
1.   
1.   
1.   
1.   
1.   
1.   
### 🧨 Rails 版本变化引发的问题：  
- 在 **Rails 6.1.7.9**  
 中，序列化哈希到 JSON 时，如果有重复的键（比如 :user  
 和 "user"  
），最终只保留最后一个键的值，因此只会保留那个**已经脱敏的用户信息**  
。  
  
- 但在升级到 **Rails 7.1.5.1**  
 后：  
  
- Rails 使用了 ActiveSupport::JSON.encode  
，它在序列化时会**保留符号和字符串形式的重复键**  
，尽管在 JSON 中它们本质上是同一个键（因为 JSON 只支持字符串键）。  
  
- 最终生成的 JSON 会长这样：```
{
  "user": {
    "email": "secret@example.com",
    ...
  },
  "user": {
    "name": "public-name",
    ...
  }
}
```  
  
实际上会显示的是 **第一个出现的键值对**  
，从而暴露了未经脱敏的 User  
 对象中大量敏感字段（邮箱、OTP 备份码、GraphQL token 等等）。  
  
  
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
-   
### 🤖 自动化测试为何未发现？  
  
HackerOne 使用 approvals  
 gem 验证 JSON 输出结构：  
```
ounter(line
verify(format: :json) { subject.body }
```  
  
但因为 Ruby 在解析 JSON 时只保留**最后一个重复键**  
，测试永远不会感知早先的泄露字段。也就是说，**自动测试未能察觉泄露，反而“成功通过”了错误输出**  
。  
  
  
**💬 你觉得团队应该默认使用 as_json 替代 to_json 吗？留言聊聊你的看法吧！**  
  
****  
****  
想获取更多真实漏洞案例与分析？  
  
欢迎关注公众号，一起用技术守护信任。  
  
  
  
====本文结束====  
  
以上内容由漏洞集萃翻译整理。  
  
参考：  
  
https://medium.com/@avinash_/hacking-the-hackers-saving-the-hackerone-from-data-breach-75e313fa4898  
  
https://hackerone.com/reports/3000510  
  
  
