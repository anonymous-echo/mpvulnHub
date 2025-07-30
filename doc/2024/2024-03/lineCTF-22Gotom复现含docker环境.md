#  lineCTF-22Gotom复现含docker环境   
原创 Zacarx  Zacarx随笔   2024-03-11 19:23  
  
这个月今年陆陆续续学了挺多go的语法 于是找了一道不算很难的题目来看看  
  
于是我在github找到了这个题 由于是国外的go题，国内docker拉取有一些问题 下面是我改进的：   
gotom.zip 解压直接运行run.sh即可一键启动 有任何问题可以直接公众号给我发消息或者加我wx  
# 分析  
  
源码就一个main.go 不到两百行代码，变量命名规范，因此阅读压力不大 我们拆开来看：  
```
import (	"encoding/json"	"fmt"	"log"	"net/http"	"os"	"text/template"    //可能有模板注入	"github.com/golang-jwt/jwt"    //可能有jwt伪造)
```  
  
开头先是四个结构体,一个切片,四个字符串的声明 下面注释一下他们的作用  
```
type Account struct {	id         string	pw         string	is_admin   bool	secret_key string}//账号信息，包括id，pw，is_admin，和secret_keytype AccountClaims struct {	Id       string `json:"id"`	Is_admin bool   `json:"is_admin"`	jwt.StandardClaims}//jwt的声明，包括id，is_admin，和标准的声明。type Resp struct {	Status bool   `json:"status"`	Msg    string `json:"msg"`}//web响应的数据，包括status和msg。type TokenResp struct {	Status bool   `json:"status"`	Token  string `json:"token"`}//web响应的数据，包括status和token。var acc []Account//所有的用户账号var secret_key = os.Getenv("KEY")var flag = os.Getenv("FLAG")var admin_id = os.Getenv("ADMIN_ID")var admin_pw = os.Getenv("ADMIN_PW")//从系统变量获取key,flag,admin_id,admin_pw
```  
```
func clear_account() {	acc = acc[:1]}//清除用户账号，保留admin账号func get_account(uid string) Account {	for i := range acc {		if acc[i].id == uid {			return acc[i]		}	}	return Account{}}//通过uid获取信息
```  
```
//jwt的加解密func jwt_encode(id string, is_admin bool) (string, error) {	claims := AccountClaims{		id, is_admin, jwt.StandardClaims{},	}	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)	return token.SignedString([]byte(secret_key))}func jwt_decode(s string) (string, bool) {	token, err := jwt.ParseWithClaims(s, &AccountClaims{}, func(token *jwt.Token) (interface{}, error) {		return []byte(secret_key), nil	})	if err != nil {		fmt.Println(err)		return "", false	}	if claims, ok := token.Claims.(*AccountClaims); ok && token.Valid {		return claims.Id, claims.Is_admin	}	return "", false}
```  
  
验证路由“/auth”的实现  
```
func auth_handler(w http.ResponseWriter, r *http.Request) {	uid := r.FormValue("id")	upw := r.FormValue("pw")	if uid == "" || upw == "" {		return	}    //从表单获取id,pw	if len(acc) > 1024 {		clear_account()	}	user_acc := get_account(uid)	if user_acc.id != "" && user_acc.pw == upw {		token, err := jwt_encode(user_acc.id, user_acc.is_admin)		if err != nil {			return		}		p := TokenResp{true, token}		res, err := json.Marshal(p)		if err != nil {		}		w.Write(res)		return	}    //从切片查询uid是否存在，如果存在且密码相等，那么就生成jwt,并且返回jwt	w.WriteHeader(http.StatusForbidden)	return}
```  
  
注册路由“/regist”的实现  
```
func regist_handler(w http.ResponseWriter, r *http.Request) {	uid := r.FormValue("id")	upw := r.FormValue("pw")	if uid == "" || upw == "" {		return	}	if get_account(uid).id != "" {		w.WriteHeader(http.StatusForbidden)		return	}	if len(acc) > 4 {		clear_account()	}	new_acc := Account{uid, upw, false, secret_key}	acc = append(acc, new_acc)	p := Resp{true, ""}	res, err := json.Marshal(p)	if err != nil {	}	w.Write(res)	return}
```  
  
flag路由的实现  
```
func flag_handler(w http.ResponseWriter, r *http.Request) {	token := r.Header.Get("X-Token")	if token != "" {		id, is_admin := jwt_decode(token)		if is_admin == true {			p := Resp{true, "Hi " + id + ", flag is " + flag}			res, err := json.Marshal(p)			if err != nil {			}			w.Write(res)			return		} else {			w.WriteHeader(http.StatusForbidden)			return		}	}    //过去http头，X-Token，如果是admin，返回flag
```  
  
根路由的实现  
```
func root_handler(w http.ResponseWriter, r *http.Request) {    token := r.Header.Get("X-Token")    if token != "" {        id, _ := jwt_decode(token)        acc := get_account(id)        tpl, err := template.New("").Parse("Logged in as " + acc.id)        if err != nil {        }        tpl.Execute(w, &acc)    } else {        return    }    //解密X-Token返回id信息}
```  
  
main  
```
func main() {    admin := Account{admin_id, admin_pw, true, secret_key}    acc = append(acc, admin)    //添加一号用户admin    //路由声明    http.HandleFunc("/", root_handler)    http.HandleFunc("/auth", auth_handler)    http.HandleFunc("/flag", flag_handler)    http.HandleFunc("/regist", regist_handler)    log.Fatal(http.ListenAndServe("0.0.0.0:11000", nil))}
```  
# 利用  
  
我们先注册  
## {{.}}  
  
golang {{.}}是一种用于在模板中插入动态数据的语法，它表示一个点号，代表当前的数据对象。例如，如果你有一个结构体Person，它有一个字段Name，那么你可以在模板中使用{{.Name}}来显示这个人的名字{{.}}返回当前结构体值，因为拼接的是acc.id于是当前对象是account 而{{.}}则返回这个结构体的值，id，pw，is_admin，和secret_key secret_key就是我们想要的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XLoEenAE7ASeTs7vKVT15E7BtWLiakd8alIyn8FWibMria20ibq665YrZzE1dsZRulVVicgkOq8icEiaKYEPqMejuqkMA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
然后我们获取jwt值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XLoEenAE7ASeTs7vKVT15E7BtWLiakd8asRxjRL3m1G7Uhm9iatBwibXK4sAjcEeS17BCYhRa3JVYPkGBxmLUkLbQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
获取key  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XLoEenAE7ASeTs7vKVT15E7BtWLiakd8aG2nickCuoeosdiaRyrWnViaW3DI2XqdWvGFgp1HgMGxuJlJyLQpKRIHcw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
获取flag不过它会认定我们不是admin于是返回403  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XLoEenAE7ASeTs7vKVT15E7BtWLiakd8a9KDsBSqLOPHuctDJZdCnj6XZA7EnsvVnj5HEeLkS4BVYdqI9ME6d4g/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
## jwt伪造  
  
github搜一下这个工具jwt_tool-master，readme有用法  
```
jwt_tool-master>python jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Int7Ln19IiwiaXNfYWRtaW4iOmZhbHNlfQ.82TiASACxvlXOXaMfkfl7UzypVvaWRJni-D22e2iT7E -T -S hs256 -p this_is_fake_key
```  
  
我用的是  
```
jwt_tool.py jwt值 -T -S hs256 -p this_is_fake_key
```  
  
-T是通过交互模式修改jwt -S是指定加密模式，由源码可以得出是hs256记得要小写 -p是hs256的key  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XLoEenAE7ASeTs7vKVT15E7BtWLiakd8aZOxcXibpSNG7RsBJmicNTqWjx4XicK0I0FlmqIDMgMGQQFvSew8MRpZPw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XLoEenAE7ASeTs7vKVT15E7BtWLiakd8annKV0ok6Xrg7yvylbwOv5D8CdUSVjfUQ7pQQR5R79iclY7iaDwJ0JtpQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
  
拿到flag，由于不是在平台搭建，flag有点奇怪。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XLoEenAE7ASeTs7vKVT15E7BtWLiakd8aSHC28mSicdBtomIBjYxqUqMM4Ebl8VnSdnxnic0r5mEbKdFDWZmx4H7g/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
  
