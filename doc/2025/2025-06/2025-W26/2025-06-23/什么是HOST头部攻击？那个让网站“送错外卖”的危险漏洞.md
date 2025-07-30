> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyMTYyOTQ5NA==&mid=2247487241&idx=1&sn=059239f7b395a167f4feb24698627aec

#  什么是HOST头部攻击？那个让网站“送错外卖”的危险漏洞  
原创 筑梦网安  全栈安全   2025-06-22 16:03  
  
>   
> **引言**  
：想象一下，你走进一家热闹的餐厅。服务员问：“您是哪一桌？”你随口答道：“8号桌！”——于是你的菜就被送到了8号桌。但如果有人故意谎报桌号呢？HOST头部攻击就是网络世界的“谎报桌号”，让服务器把敏感信息送到攻击者手中！  
  
### 一、HOST头部：网络世界的“桌号系统”  
  
当你在浏览器输入 
```
https://www.yourbank.com
```

  
 按下回车时，浏览器会发送这样一个请求：  

```
GET /account HTTP/1.1
Host: www.yourbank.com
User-Agent: Mozilla/5.0...
...

```

  
关键就在第二行——
```
Host: www.yourbank.com
```

  
。它告诉服务器：“我是来找www.yourbank.com的，请把它的内容给我！”  
#### 为什么需要HOST头部？  
  
在早期互联网中，一台服务器只托管一个网站。但随着技术发展，**一台服务器（一个IP地址）通过虚拟主机技术托管多个网站**  
已成常态。  
  
![多个网站共享同一IP，依赖HOST头部区分](https://mmbiz.qpic.cn/mmbiz_jpg/EWVicRs8Iibp8s7ShDl7aVpcIYG6zzpPmicxx4ybcuhRYHD5Vk72tOfhWhDHvZpiczKIqr2ibaSDsZlicMapKWkvGqWA/640?wx_fmt=jpeg&from=appmsg "")  
  
多个网站共享同一IP，依赖HOST头部区分  
  
Host头部的作用就是告诉服务器当前请求的目标主机名（域名）和端口号。例如：  
  

```
Host: www.example.com:80
```

  
  
这样，服务器可以根据
```
Host
```

  
字段确定用户访问的是哪个站点，从而加载相应的资源。  
### 二、攻击原理：篡改“桌号”引发的灾难  
  
如果服务器**盲目信任**  
客户端发来的HOST头部，不做严格验证，就会引发三大风险：  
#### 场景1：密码重置劫持（经典攻击链）  
  
假设老张的网站 
```
zhangs-site.com
```

  
 存在漏洞：  
1. 用户点击“忘记密码”，输入邮箱  
  
1. 网站生成重置链接：
```
http://zhangs-site.com/reset?token=abcd1234
```

  
  
1. 邮件发送该链接  
  
**漏洞点**  
：网站使用Host头部动态生成链接！  
  
**攻击者李四的操作**  
：  
1. 修改自己的请求，将Host设为恶意网站 
```
li4-evil.com
```

  
：  
  

```
POST /forgot-password HTTP/1.1
Host: li4-evil.com  // 篡改点！
...
email=victim@user.com

```

1. 服务器读取Host值，生成错误的重置链接：
```
http://li4-evil.com/reset?token=abcd1234
```

  
  
1. 用户点击邮件中的链接，token直接发送到李四的服务器！  
  

```
# 漏洞代码示例（Python Flask框架）
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form['email']
    token = generate_token()
    # 危险！直接使用Host头部构造重置链接
    reset_link = f&#34;http://{request.headers.get('Host')}/reset?token={token}&#34;
    send_reset_email(email, reset_link) 
    return &#34;邮件已发送&#34;

```

#### 场景2：缓存污染攻击（CDN/代理遭殃）  
  
许多缓存系统（如CDN、反向代理）依赖Host头部作为缓存键的一部分。  
  
攻击步骤：  
1. 攻击者发送恶意请求：  
  

```
GET /important-news-article HTTP/1.1
Host: attacker.com  // 污染缓存键
...

```

1. 缓存服务器错误地将响应与键 
```
attacker.com+/important-news-article
```

  
 关联  
  
1. 当正常用户访问 
```
https://real-site.com/important-news-article
```

  
 时，可能收到被篡改的缓存内容！  
  
#### 场景3：绕过安全策略的“后门”  
  
某些安全配置（如CORS、身份验证白名单）依赖Host值判断合法性。篡改Host可能让攻击者绕过这些防护。  
### 三、实战演练：亲手“黑掉”测试网站（安全环境）  
>   
> **⚠️ 注意：此实验仅限本地或授权测试环境！勿用于真实网站。**  
  
  
**工具准备**  
：  
- 浏览器（Chrome/Firefox）  
  
- 浏览器插件：**ModHeader**  
（修改请求头神器）  
  
由于国内无法直接访问Chrome插件市场，已经下载归档，有需要的可以自取：  
- **ModHeader_6.0.8.crx**  
：  
https://url25.ctfile.com/f/1848625-1521312427-129099?p=6277  (访问密码: 6277)  
  
进入到Chrome管理扩展程序页面，直接将下载的crx格式文件拖动到页面即可完成安装。  
  
![进入管理扩展程序页面](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp8s7ShDl7aVpcIYG6zzpPmicKScULyht9M3HG0OaoNjRZ22IWgfGORFYLgOxTWwjoT3NNibWoDqofGw/640?wx_fmt=png&from=appmsg "")  
  
进入管理扩展程序页面  
  
**靶场推荐**  
：下载安装OWASP Juice Shop（一个精心设计漏洞的Web应用）。  
  
**实验步骤**  
：  
1. 启动Juice Shop，访问 
```
http://localhost:3000
```

  
  
1. 安装ModHeader插件，添加新Header：  
  
1. Name: 
```
Host
```

  
  
1. Value: 
```
anything-you-want.com
```

  
  
1. 在Juice Shop尝试“重置密码”功能  
  
1. 观察邮箱收到的重置链接——已被篡改成 
```
http://anything-you-want.com?token=xxx
```

  
！  
  
![ModHeader插件修改Host](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp8s7ShDl7aVpcIYG6zzpPmicxgmiczSIic3dkv3jTYR4bBpdFceicpjPYLNj1m7xyINbdRGke0FzDkLng/640?wx_fmt=png&from=appmsg "")  
  
ModHeader插件修改Host  
### 四、加固防御：三招让攻击者“无桌可占”  
#### 1️⃣ 服务器层：强制声明合法域名（推荐！）  
  
在Web服务器配置中明确指定允许的Host，拒绝非法Host请求。  
  
**Nginx配置示例**  
：  

```
server {
    listen 80;
    server_name zhangs-site.com www.zhangs-site.com; # 只认这两个Host

    if ($host !~* ^(zhangs-site.com|www.zhangs-site.com)$ ) {
        return 404; # 直接关闭连接
    }
    ...
}

```

#### 2️⃣ 应用层：代码中严格校验  
  
在业务逻辑中验证Host，避免动态拼接域名。  

```
# 安全代码示例（Python Flask）
VALID_HOSTS = ['zhangs-site.com', 'www.zhangs-site.com']

@app.before_request
def validate_host():
    client_host = request.headers.get('Host', '')
    if client_host not in VALID_HOSTS:
        abort(403, description=&#34;非法Host请求&#34;)

```

#### 3️⃣ 关键操作：绝对不要依赖Host！  
- 生成链接时使用**预配置的完整域名**  
（环境变量/配置文件）  
  
- 使用框架提供的**全路径生成函数**  
（如Django的 
```
request.build_absolute_uri()
```

  
）  
  
- 敏感操作（如密码重置）增加**二次确认**  
（如邮件验证码）  
  
### 五、为何漏洞频发？开发者常踩的3个坑  
1. **本地开发依赖Host**  
：开发环境常用 
```
localhost:8080
```

  
，上线后忘记修改  
  
1. **过度信任反向代理**  
：认为Nginx/Apache已过滤，忽略应用层校验  
  
1. **框架“小聪明”**  
：某些框架自动使用Host生成URL，埋下隐患  
  
### 安全自查清单 ✅  
- [ ] 是否在Web服务器（Nginx/Apache）配置了合法Host列表？  
  
- [ ] 应用代码中是否对Host进行额外验证？  
  
- [ ] 密码重置等敏感链接是否使用硬编码域名？  
  
- [ ] 是否定期扫描接口中Host头部的使用情况？  
  
**安全无小事，头部非小事。一次Host的信任，可能打开整座城池的大门。**  
 下次部署服务时，记得问问自己：我的“桌号系统”，真的安全吗？  
  
![本文包含的关键知识点总结](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8Iibp8s7ShDl7aVpcIYG6zzpPmicmGjTdZMAwJ48PA1hqLBsyCGicw5Wsric88gzcopSS2JK7fJ4P8A3niaqw/640?wx_fmt=png&from=appmsg "")  
  
本文包含的关键知识点总结  
  
**扩展阅读**  
：  
- OWASP Host头攻击指南：   
  
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection  
  
- Burp Suite实战检测Host头漏洞：   
  
https://portswigger.net/web-security/host-header  
  
**关注我，带你用“人话”读懂技术硬核！**  
 🔥  
  
  
  
  
  
