#  WordPress插件认证绕过与权限提升漏洞实例分析   
原创 cynault  奇安信天工实验室   2025-04-23 03:30  
  
**目**  
  
**录**  
  
一、前  言  
  
二、权限绕过漏洞  
  
三、权限提升漏洞  
  
四、  
总  结  
  
  
**一**  
  
  
**前  言**  
  
  
管理员权限用户能够执行更多敏感操作，也更容易导致RCE（远程代码执行）。在 WordPress 中，管理员拥有安装任意插件的权限，因此用户如果拥有管理员权限，几乎等同于获得RCE。  
  
下面从 diff 漏洞修复的角度，介绍 WordPress 插件中出现的 认证绕过和权限提升漏洞是如何导致获取管理员权限的。其中大部分漏洞与 WordPress 插件相关，也有小部分来自其他PHP项目。  
  
**二**  
  
  
**认证绕过漏洞**  
  
  
**01**  
  
**CVE-2024-6695**  
  
  
USER PROFILE BUILDER <= 3.11.8  
  
  
**漏洞成因**  
  
漏洞成因是自动登录和用户注册流程对用户邮箱的字符串处理不一致。用户注册时未清除邮箱字符串中的空格字符，而自动登录流程会清除空格。攻击者可通过注册带空格的仿冒管理员邮箱（如admin@example.com   
）来利用此漏洞。利用前提是需要知道管理员邮箱地址且系统启用了自动登录功能。  
  
![screenshot (1).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nzduGuahgAjzwEISf4Nu9gZF6W3Vf6Xz7FGiaoklVSgXGolYBR3rPAXg/640?wx_fmt=png&from=appmsg "")  
  
注册邮箱的检查逻辑是通过数据库查询判断用户输入的邮箱是否已存在，若不存在则允许注册。  
  
在   
wppb_check_email_value  
 函数中，程序未对注册邮箱进行规范化处理就直接执行数据库查询。 例如，若管理员邮箱是   
admin@test.com  
，攻击者可尝试注册   
admin@test.com   
（尾部加一个空格）。由于程序未清理空格，数据库查询会将其视为新邮箱，从而绕过检查并成功注册。  
  
![screenshot (2).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nwkZxL5dqYA70d5BwnicTWqQQSWt9R2h1XF5gXGTHVIORLJ7B3FkEmaw/640?wx_fmt=png&from=appmsg "")  
  
而在自动登录过程中，系统会对攻击者传入的邮箱字符串使用   
trim()  
 进行处理。 此时，新创建账号的邮箱（如   
admin@test.com  
   
）会被去除空格，变为   
admin@test.com  
，从而与已有的管理员账户完全匹配。这样，攻击者即可通过自动登录机制成功登录管理员账号，最终实现认证绕过。  
  
  
**漏洞修复**  
  
![screenshot (3).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nNMTDNG3bbgCkpuWpIDaTscJBtp3dJS49K0VicEpZgGGMkcFj3pkYqfQ/640?wx_fmt=png&from=appmsg "")  
  
注册流程使用  
trim()  
函数对邮箱进行过滤，使注册环节和自动登录环节对邮箱字段的处理方式保持一致。  
  
**02**  
  
**CVE-2023-2297**  
  
  
PROFILE BUILDER – USER PROFILE & USER REGISTRATION FORMS <= 3.9.0  
  
  
**漏洞成因**  
  
修改用户密码所用的密钥以明文形式存储在数据库中，这使得攻击者可以通过SQL注入漏洞获取特定密钥，进而修改管理员用户的密码，最终实现认证绕过并执行管理员权限的敏感操作。  
  
该漏洞的利用场景发生在登录界面的"忘记密码"功能处：当输入管理员邮箱申请密码重置时，系统会在  
user_activation_key  
字段生成用于密码修改的密钥。以下是针对admin用户发起密码重置请求后，数据库表中对应字段的变化情况：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nqhEXnnfum3YxfraubyQicgkMQV8orGs0iaibVHwIMfLPN3MWlk1QoBnKg/640?wx_fmt=png&from=appmsg "")  
  
该漏洞的关键在于：  
1. user_activation_key  
的生成机制实现方式；  
  
1. 密码重置时对  
user_activation_key  
的验证机制实现方式。  
  
  
  
![screenshot (5).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nV3fsb9au77RODX76GeGEMRsCVSAicJhfIGFHpolDASEUcLg3YsfcFnw/640?wx_fmt=png&from=appmsg "")  
  
**密钥生成阶段**  
，系统将密码重置密钥以明文形式存储在数据库中。具体实现流程如下：  
1. 程序调用  
wppb_retrieve_activation_key()  
函数生成激活密钥；  
  
1. 该函数通过  
wp_generate_  
password()  
生成随机密钥；  
  
1. 使用  
$wpdb->update()  
方法直接将生成的密钥写入数据库；  
  
1. 最终将  
$key  
返回并发送至用户注册邮箱。  
  
  
  
![screenshot (6).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8npGBUBeSH6L6sB6xBJSK5lhChZE8lAicFkxC64icEUZ6vDH2BLs8p51Rg/640?wx_fmt=png&from=appmsg "")  
  
**密钥验证阶段**  
，系统通过以下流程进行验证：  
1. 首先检查  
$key  
参数是否为空（该检查是针对CVE-2021-24527漏洞的修复措施）；  
  
1. 执行SQL查询，验证数据库中是否存在匹配的激活密钥；  
  
1. 注：攻击者可能通过SQL注入获取有效的激活密钥。  
  
1. 当查询返回有效用户对象时，系统判定验证通过；  
  
1. 验证通过后，允许对相应用户（包括管理员）执行密码重置操作。  
  
  
  
  
**漏洞修复**  
  
移除不安全的  
wppb_retrieve_activation_key  
函数：  
  
![screenshot (7).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nMhPicgak4TFicEt8vqibZtdviatdFMnUljhZEIDByo3icqAIQN7TGiaGsV5A/640?wx_fmt=png&from=appmsg "")  
  
密钥生成阶段，采用WordPress提供的  
get_password_reset_key  
来完成，此函数的作用是获取到激活密钥  
$key  
的同时，将  
$key  
 hash后的值存储到对应用户的  
user_activation_key  
中。  
  
![screenshot (8).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nndbRiciapGmC7JY4ElFHsnp90LtCAHOZe0VQ7uN5BwvQzUGKMaoxeZyA/640?wx_fmt=png&from=appmsg "")  
  
检验阶段同样采用WordPress提供的函数，如果能通过密钥和用户名获取用户，才能修改对应密码。  
  
漏洞完成修复后攻击者无法通过数据库获取到真正的key来通过校验，只能获取加盐hash之后的key。  
  
**03**  
  
**CVE-2021-24527**  
  
  
PROFILE BUILDER <= 3.4.8  
  
  
**漏洞修复**  
  
在WordPress数据库中，已激活用户的  
user_activation_key  
字段为空。攻击者可以通过传入空密钥来获取到已激活用户对象，来绕过数据库中是否有对应激活密钥的检查，达到修改管理员账号密码的效果。  
  
![screenshot (9).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nuia1xnDRU0bh6JNDMiaUcc41xhzViaVvUaxxw6B0Zpc6M1m9EG5FKQAsw/640?wx_fmt=png&from=appmsg "")  
  
在忘记密码流程中的重新设置密码阶段，对   
user_activation_key  
 进行检查的实现，是通过数据库查询是否有用户拥有攻击者传入的激活密钥。如果有返回的用户对象，则代表校验通过。  
  
WordPress 中正常的已激活用户，   
user_activation_key  
 字段为空值。通过将 key 设置为空字符串   
""  
，使得数据库查询时能返回用户对象。  
  
![screenshot (10).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nkG9QGp4powUV9spt4Fws6Lzh7A4kxxLEVv5PFYMmCEhKXrB1b4Ye9w/640?wx_fmt=png&from=appmsg "")  
  
若能通过数据库查询获取正常的激活用户对象，就代表绕过了非法密钥的检查，进而可以完成管理员密码的修改，最终达到认证绕过的效果。  
  
  
**漏洞修复**  
  
![screenshot (11).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nBIXQmoE2iaYKicibmRRgAI20rwDrTSMy4G1qypCduvwcnYRc7ia4N0Ow7w/640?wx_fmt=png&from=appmsg "")  
  
修复方案是添加检查密钥是否为空的代码。若密钥为空，程序将直接拒绝重置密码请求。  
  
**三**  
  
  
**权限提升漏洞**  
  
  
**01**  
  
**V2BOARD 1.6.1 提权漏洞分析**  
  
  
**漏洞成因**  
  
该漏洞的成因是程序缺少对缓存区   
cookie  
 的权限校验机制，攻击者可以通过   
cookie  
 缓存区污染攻击，使普通用户能够访问本应只有管理员权限才能访问的 API 接口，这是一种有效的提权方法。  
Sink  
 点位于   
Admin  
 中间件的认证逻辑中：该逻辑先检查缓存中   
cookie  
 是否存在，若存在就直接通过认证，而没有校验   
cookie  
 对应用户的实际权限。  
  
![screenshot (12).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nlfzcV9AagpFy2yoW3xBiaXGXDiazIllcHWrfOIl6gmWmXxNf6xKxApQw/640?wx_fmt=png&from=appmsg "")  
  
普通用户在正常完成登录，并访问普通用户接口后，其认证信息和用户数据会被存入缓存。然而在访问需要管理权限的 API 接口时，系统只有当缓存中没有数据时，才会检查对应用户是否拥有管理权限。若缓存中存在数据时，则直接使用缓存数据，而不会验证对应的缓存   
cookie  
 是否拥有管理员权限。  
  
  
**利用步骤**  
  
1. 当普通用户登录系统并获取   
auth_data  
 时：  
  
1. 系统返回的认证信息采用简单的 Base64 编码：   
example@example.com:10\$1RiPZeGdgfQOITrXC8um.unPeVMLk7FQEnAUVpplHfNS2s7PhJSkq  
  
1. 经解码后的格式为：邮箱:密码哈希值。  
  
1. 用户向普通用户接口（如   
/api/v1/user/info  
）发送请求时：  
  
1. 需在请求头中携带   
Authorization  
 字段值；  
  
1. 此操作会触发系统将用户信息写入 缓存；  
  
1. 缓存键为   
Authorization  
 字段值，缓存值为经过序列化的用户信息数组。  
  
1. 攻击者直接使用相同的认证信息访问管理员 API（如   
/api/v1/admin/user/fetch  
）：  
  
1. 此时   
Admin  
 中间件的认证流程如下：   
  
a. 查询缓存中是否存在对应的认证信息;  
  
b. 若存在，则直接使用缓存数据，跳过权限验证。  
  
  
  
  
**漏洞修复**  
  
对于每次请求，服务端都应验证用户权限，具体需判断对应用户是否拥有管理员权限。  
  
![screenshot (13).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nqFoFibm1tEDicrJv7QXQuZOxX2YzyjiaIKSWLeIwaBK7zqfnic4t8X22cg/640?wx_fmt=png&from=appmsg "")  
  
**02**  
  
**CVE-2023-3636**  
  
  
WP PROJECT MANAGER <= 2.6.4  
  
  
**漏洞成因**  
  
在 WordPress 中，  
update_user_meta  
 函数用于更新用户   
meta  
 数据，包括用户角色信息。  
  
权限提升攻击路径如下：  
  
通过调用   
update_user_meta($user_id, 'wp_capabilities', array('administrator' => true))  
，攻击者可以将自身或任意指定用户提升为管理员权限。  
  
![screenshot (14).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nEvGhCGhnhM7ShNYnpnBGhzbEggSI5e1KoNpQJrrklW0NaIZbMHURbA/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞修复**  
  
在接口函数中加入用户权限检查   
current_user_can()  
，确保只有具备管理员权限的用户才能访问该接口。这是最典型且有效的修复方式之一。  
  
![screenshot (15).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8npbiaMteCC1fx88BbW0J7XvbGpXzvGgoick27QaCjJ3ekicEGythMCdyuw/640?wx_fmt=png&from=appmsg "")  
  
**03**  
  
**CVE-2025-2594**  
  
  
User Registration & Membership <= 4.1.2  
  
  
**漏洞成因**  
  
sink  
点：  
wp_set_auth_cookie  
 （根据用户id来设置  
cookie  
）：  
  
![screenshot (16).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nDulZ34sXnARGs0KJu4kq190qRgMg4uetygIlgpDuFc5kABpHia5ibSibA/640?wx_fmt=png&from=appmsg "")  
  
当   
$user_id  
 参数可控时，攻击者可通过将其设置为管理员用户的ID，非法获取管理员权限的   
cookie  
，实现权限提升。  
  
由于 WordPress 默认将首个创建用户的   
user_id  
 设为   
1  
（通常是管理员），攻击者只需传入  
$user_id = 1  
即可获取管理员权限   
cookie  
。  
  
  
**漏洞修复**  
  
![screenshot (17).png](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nykXjFnek4BbzUnCjlP4ueJVyK6MWqaO2xm18GyLHqQUiaqFQXdC5JnQ/640?wx_fmt=png&from=appmsg "")  
  
通过   
get_user_meta  
 函数校验   
$user_id  
 对应用户是否由该插件创建。仅当用户确实通过该插件创建时，方允许调用   
wp_set_auth_cookie  
 函数生成对应   
cookie  
。由于该插件仅会创建普通权限用户，从根本上阻断了通过此途径将权限提升至管理员的可能性。  
  
**四**  
  
  
**总  结**  
  
  
本文从diff角度出发分享WordPress插件中出现认证绕过和权限提升漏洞模式。  
  
其中认证绕过漏洞中利用的点有：  
1. 注册流程和自动登陆流程中对邮箱字段字符串处理不一致；  
  
1. 忘记密码生成的激活密钥使用明文存储于数据库中；  
  
1. 忘记密码生成的激活密钥使用数据库查询用户判断存不存在，已激活用户密钥为空，导致空密钥能匹配到用户。  
  
权限提升的利用点有：  
1. cookie  
缓存区污染，管理员接口判断缓存  
cookie  
是否存在，没有校验对应用户是否有相应权限；  
  
1. wordpress中  
sink  
函数  
update_user_meta  
可以更新用户角色，被未授权访问；  
  
1. wordpress中  
sink  
函数  
wp_set_auth_cookie  
可以设置指定  
user id  
来更新  
cookie  
，没有对相应  
user id  
进行校验，导致能获取管理员权限的  
cookie  
。  
  
  
  
  
  
【版权说明】  
  
【版权说明】  
  
本作品著作权归**cynault**  
所有  
  
未经作者同意，不得转载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9EP6QFMcTmQ79BuUXsWDaocnEtDkme8nuWUzJico9WyGP4q9zibmgTQ5moiafibjqS54NSAsnpByJzHjPIwiar4GYvA/640?wx_fmt=png&from=appmsg "")  
  
**cynault**  
  
  
天工实验室安全研究员  
  
研究领域：代码审计、IOT安全  
  
  
**往期回顾**  
  
  
**0****1**  
  
[Connexion API内存马植入研究](https://mp.weixin.qq.com/s?__biz=Mzk0OTU2ODQ4Mw==&mid=2247487122&idx=1&sn=d293636e93d84fc26a749df71e20250b&scene=21#wechat_redirect)  
  
  
**0****2**  
  
[编码问题引起的RCE分析](https://mp.weixin.qq.com/s?__biz=Mzk0OTU2ODQ4Mw==&mid=2247487066&idx=1&sn=7015ca542938595eaab9e17f00301964&scene=21#wechat_redirect)  
  
  
**0****3**  
  
[探索 Intel Processor Trace：在 Windows 上的技术解析与应用实践](https://mp.weixin.qq.com/s?__biz=Mzk0OTU2ODQ4Mw==&mid=2247487034&idx=1&sn=54be1f4382d2f5e23ba742623574cff3&scene=21#wechat_redirect)  
  
  
**0****4**  
  
[使用破壳平台自动化漏洞挖掘实践](https://mp.weixin.qq.com/s?__biz=Mzk0OTU2ODQ4Mw==&mid=2247486963&idx=1&sn=af273c91a4e3218d4b5361606a7b82d8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oJZWTpJpiae90UpibicIKeZgQTNjebiaOwStfe6MJ5J6RC7F9JDFdX2kaEwibFz7GewNtNyDek6SdENJrXjf0KXA2kg/640?wx_fmt=png "")  
  
**每周三更新一篇技术文章  点击关注我们吧！**  
  
  
