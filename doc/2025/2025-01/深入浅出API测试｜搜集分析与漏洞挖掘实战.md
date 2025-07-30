#  深入浅出API测试｜搜集分析与漏洞挖掘实战   
 迪哥讲事   2025-01-30 12:35  
  
          
  
# 深入浅出API测试  
  
  
标题展示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQYse9Esr0VCM3ibsfk7c9qaERMFqZN7ZbDLvb3bs2Ww1BsU20ENMRIgw/640?wx_fmt=png&from=appmsg "")  
  
所有动态网站都由 API 组成，因此 SQL 注入等经典 Web 漏洞可以归类为 API 测试。因此测试之前要尽可能的去测试功能点，观察代理流量，发现API目录收集信息，拓展攻击面。  
  
例如，某个功能的请求的 API 端点是 /api/books 这会 API 进行交互，从图书馆中检索书籍列表：  
```
GET /api/books HTTP/1.1
Host: example.com

```  
  
除了明面上已使用且可看见的功能外，可能还存在一些隐藏的或是权限不足导致的不展示的功能。因此，可能会有些API接口会被隐藏在JS中没有被激活。这时候可以使用 JS Link Finder插件辅助分析Javascript文件中的接口，具体可以看：[](http://mp.weixin.qq.com/s?__biz=MzkzODEzNjA3MQ==&mid=2247488184&idx=1&sn=30593b45bbc8ea3b1c719cef70ef2b1b&chksm=c28595d0f5f21cc61a83029a1198ee47cf71f42cb0d57c96cccb41c0e8c7761561b01b5c998f&scene=21#wechat_redirect)  
[技巧 | Burp攻击面拓展与实用工具](http://mp.weixin.qq.com/s?__biz=MzkzODEzNjA3MQ==&mid=2247488184&idx=1&sn=30593b45bbc8ea3b1c719cef70ef2b1b&chksm=c28595d0f5f21cc61a83029a1198ee47cf71f42cb0d57c96cccb41c0e8c7761561b01b5c998f&scene=21#wechat_redirect)  
  
  
  
除此之外，还可以通过FUZZ对接口进行猜解，例如POST /api/user/update 接口，可能会存在/add或者/delete功能，或是将接口命名规则丢给GPT让它帮忙生成相关路径。  
## 发现 API开发文档并拓展攻击面   
  
即使 API 文档未公开提供，仍可以通过FUZZ或爬取的方式访问未授权的API开发文档手册，例如：  
```
/api/swagger/v1
/api/swagger
/api
/swagger
/api-docs
/api.html
/swagger-ui
/swagger/codes
/api/index.html
/api/v2/api-docs
/v2/swagger.json
/swagger-ui/html
/distv2/index.html
/swagger/index.html
/sw/swagger-ui.html
/api/swagger-ui.html
/static/swagger.json
/user/swagger-ui.html
/swagger-ui/index.html
/swagger-dubbo/api-docs
/template/swagger-ui.html
/swagger/static/index.html
/dubbo-provider/distv2/index.html
/spring-security-rest/api/swagger-ui.html
/spring-security-oauth-resource/swagger-ui.html

```  
  
github中关于springboot接口相关利用这篇文章非常详细：https://github.com/LandGrey/SpringBootVulExploit  
  
API字典什么的我也没什么好东西，只推荐这Burp插件，自动帮忙多递归扫描，它让我捡到的API文档数量已经数不过来了：https://github.com/F6JO/RouteVulScan  
### 隐藏的 HTTP 方法  
  
API文档中一般规定了API接口地址，允许的HTTP方法与支持的内容类型。当然也有非一般情况，如：**文档未更新或者细节问题，导致与实际不一致。因此API端点可能潜在隐藏的HTTP方法，所以测试所有潜在方法非常重要。**  
  
例如， /api/tasks 可能支持以下方法：  
- GET /api/tasks - 检索任务列表。  
  
- POST /api/tasks - 创建新任务。  
  
- DELETE /api/tasks/1 - 删除任务。  
  
> 在Intruder中内置了名为HTTP verbs的HTTP方法字典  
  
### 隐藏的内容类型  
  
在实际生产中，因为业务互交，数据需要多系统之间透传；由于系统之间框架语言不一致，经常会出现XML和JSON数据互转。这种情况下，可能会产生处理逻辑的差异。**例如，API 在处理 JSON 数据时可能是安全的，但在处理 XML时容易受到注入攻击。**  
  
在测速接口时候，要注意Content-Type 标头，然后相应的设置请求正文的格式，在BApp中Content type converter插件可以快速的在 XML和 JSON中互转换。  
### 使用自动化工具分析API文档  
  
当发现到API文档后，可以获取到大量的API接口功能信息，除了可以手动构造外，还可以通过APIKIT、OpenAPI Parser、SoapUI 这类工具对API文档进行分析与参数构造。  
> 自动化测试API接口时，注意手动测试增、删接口，不要影响网站运行。  
  
## Lab: 发现隐藏的API文档   
> 通过暴露的API端点位置，想办法删除carlos账户；账户:wiener:peter  
  
  
Lab: Exploiting an API endpoint using documentation | Web Security Academy (portswigger.net)  
  
正常登陆，测试功能点。查看HTTP历史记录发现/api/user/wiener HTTP/2 这么一个目录请求，将winer修改为carlos发现可以正常取得信息 ，尝试只访问/api 路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQnaj0tBpiahkqtdkuddNKaTxfbn6wWX0nphRz2Q5AIUSKqibYU5kd30pg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
发现暴露了API文档信息。  
  
根据DELETE格式调用删除carlos  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQ8VkGz18PviaF9bqnHMZs5O3SFniadFR9EL0T2Z2kNVJZtMicSsBNLaZ7Q/640?wx_fmt=png&from=appmsg "")  
  
image  
## Lab: 找到未使用的API接口   
> 利用隐藏的 API 端点购买**Lightweight l33t Leather Jacket**.  
  
  
Lab: Finding and exploiting an unused API endpoint | Web Security Academy  
  
走完所有功能流程，发现只有一个API路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQ1xcxqMjWjuEov5iauh20KibxxhNBKIKic8uRb6IEHy5I9a2nZfvdBWwibg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
使用内置content discover 扫描功能也只能发现这个路径。根据上面说的几点，拓展利用。尝试HTTP方法枚举，发现PATHCH方法会报错内容类型错误  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQ5PoHGRjL8WVsffScdXOVUl7IUbWuc9tKWndP35HTtAH3uib06xuPj2A/640?wx_fmt=png&from=appmsg "")  
  
image  
  
构造内容类型与方法发送，发现提示“price parameter missing in body”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQIXnkiaD5gUdkWmvbibQLVYicia3HPwWGYK9vK2eoYscmS0rbP3sqDMyyFA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
添加上参数，实在不知道返回的price 0.01是什么意思。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQItTBTkv07BicyicxouzgOr7J5fDKWfGrb5Olor799mQAyhHR6cGy7wCw/640?wx_fmt=png&from=appmsg "")  
  
image  
  
刷新购物车发现，是设置价格的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQDQAhvNacIAOzEJibzic0JY2DzFbuQRsXbMYNduhN6TOzZ1IE8GjiahmaQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
那么改为0  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQuicibAPg5Up5FnFjO5IzfgPq7fyWOibISopMjgCcLC6upr6koiaPUFwiajA/640?wx_fmt=png&from=appmsg "")  
  
image  
## Lab: Mass Assignment 批量赋值   
  
Mass Assignment - OWASP Cheat Sheet Series --- 质量分配 - OWASP 备忘单系列  
  
批量赋值（也称为自动绑定）可能会无意中创建隐藏参数。当Web框架自动将请求参数绑定到内部模型对象上的字段时（直接将用户输入参数赋值给模型实例），就会发生这种情况。因此，批量赋值可能会导致网站允许处理开发人员设置的隐藏参数。通俗来说，就像是餐馆中的隐藏菜单，虽然菜单中没有展示，但是厨师也是可以制作的。  
### 识别隐藏参数  
  
漏洞成因是由于从模型对象字段中创建参数，这种情况下，通常可以通过手动查询API返回的模型对象来发现隐藏的参数。  
  
例如，有这么个接口：/api/users/update 它允许用户更新用户名称和邮箱  
```
{
    "username": "wiener",
    "email": "wiener@example.com",
}

```  
  
而恰巧有这么一个接口：/api/users/{username} 返回以下信息🧐  
```
{
    "id": 123,
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": "false"
}

```  
  
这可能表示返回的id 和 isAdmin 参数与/api/users/update接口更新的用户名和电子邮件参数，可能会作为隐藏参数一起绑定到内部User对象。  
### 测试批量赋值漏洞  
  
**SpringBoot 代码示例:**  
  
假设有一个用于编辑用户帐户信息的表单：  
```
<form>
     <input name="userid" type="text">
     <input name="password" type="text">
     <input name="email" text="text">
     <input type="submit">
</form>

```  
  
下面是表单绑定到的User对象：  
```
@Data
public class User {
   private String userid;
   private String password;
   private String email;
   private boolean admin;

   //Getters & Setters
}

```  
  
下面是处理请求的**Controller**：  
```
@RestController
public class UserController {

    @PostMapping("/update")
    public User updateUser(@RequestBody User user) {

        System.out.println("Updating user: " + user);
        return user;
    }
}

```  
  
正常提交html会产生以下请求：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQoouPibmfALAHRQ5AjiaZibxwl0NgNZvRlJRxcibAvACnn7LBDARNvibeyZA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
利用Admin 隐藏参数：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQkF48pcf0We6hVDS1k2pddPvUjJGzFmxZBhibD4ribrDsw4PXQibxlqIDg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
如果请求中的 Admin 值绑定到User对象而没有进行充分的验证和清理，则可能会错误地向用户 test授予管理员权限。  
  
**以下是Python Flask实现的效果：**  
```
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash
app = Flask(__name__)

users = []
class User:
    def __init__(self, username, password, email): 
        self.id = len(users)
        self.username = username
        self.password = generate_password_hash(password)
        self.email = email 
        # 默认角色为user 
        self.isAdmin = False

@app.route("/regist", methods=["POST"]) 
def create_user():
    data = request.get_json()
    
    username = data["username"]
    password = data["password"]
    email = data["email"]

    
    # 默认注册用户非admin
    user = User(username, password, email)
 
    # for user in users:
    #   if user.email == email:
    #       return jsonify({"error": "Email already exists"}), 403 
    users.append(user) 

    # 自动绑定所有其他参数到user对象上  
    for key, value in data.items():
        if key != "password":
            setattr(user, key, value)

    return jsonify(user.__dict__)

if __name__ == "__main__":
    app.run()

```  
  
正常注册：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQ4G11l6ziavvSUWEB5faLmaibIXcNxiacV5pjCsxUBLS51YhAmibfAZPPpg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQBKOYL5Z5WviaC1MsSbWsyDGQZDMX1FPsWBU7IZgqtMKm9jN4S4fLb8Q/640?wx_fmt=png&from=appmsg "")  
  
image  
### Lab：a mass assignment vulnerability  
  
以下是Burp靶场：  
  
Lab: Exploiting a mass assignment vulnerability | Web Security Academy (portswigger.net)  
  
走一圈功能点发现只有一个接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQTrIIcz5uWomA0tjnEbW0qIJJzUByNFjbVjn2BSHzOOicC6EuIyI4q1Q/640?wx_fmt=png&from=appmsg "")  
  
image  
  
其中支持GET返回的数据和POST提交的数据格式相似  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQQb0pHGpvEHYqHSS4FoZ4pbrdnQQEFZqXcGic0m0g6MMbLSzBqmibE0Ww/640?wx_fmt=png&from=appmsg "")  
  
image  
  
先不管参数作用，直接一股脑全部拿来用作提交。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQ41VQyJPzbNFgSE9DlFNZKeMmMcvMjLJSM6m2LvFdnw9ia59BbKvSxAg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
发现没有变化，那么只能从value入手，根据参数名直译得出chosen_discount 为已选折扣，其中percentage 百分比为0 ，那么尝试修改为100  
  
成功购买  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQuCwYaKNm6M8BUBiaRgXJQrQ0xXydWicicrNybdQCtG4SF1NTicQWdZrOaQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
使用Param Miner  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQSicoia9HmD0ksWjTgweKHK4dPPlDMF65GRRxVHnJv34ET6khGKWTbOew/640?wx_fmt=png&from=appmsg "")  
  
image  
  
正常一切按照默认配置走，会发现Param miner会自动在POST请求中会自动添加Query查询参数，结果就是Response不支持POST中携带Query参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQCYoXo9j0zuia0HMv8pibZ7hhECdNDJGp9wZNhpiciadzJKN334tw2cAdyQ/640?wx_fmt=png&from=appmsg "")  
  
image  
  
这个具体解决办法就是在配置中取消params:query的勾选☑️  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gh2J6kIbISbMQNUu70qlnV5HCznypHDQicgSS7ZwfWduqFdOZvETsJzepoOnzvbAMApiam4cNAVR5GpKvcHibLNFA/640?wx_fmt=png&from=appmsg "")  
  
image  
  
但是工具存在bug，这个功能并不生效，已经提交作者了。截止文章发表的时间Param miner的版本是1.4f ，后续可能会修复这个问题。  
  
所以还是推荐用GAP方式收集参数再转换JSON填充了  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
  
## 往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
ref:  
  
What is mass assignment? | Tutorial & examples | Snyk Learn  
  
Mass Assignment - OWASP Cheat Sheet Series  
  
  
