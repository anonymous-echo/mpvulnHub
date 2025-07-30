#  利用solidity与EVM本身的漏洞进行攻击二   
NEURON  SAINTSEC   2025-04-12 01:00  
  
**未初始化的指针**  
  
**# 原理**  
  
  
在solc小于0.4.24的版本中，如果函数中有未初始化的结构体对象，那么这个变量会指向其他的变量区域，并能改变这个值。  
```
pragma solidity ^0.4.24;

contract example{
    uint public a;
    address public b;
    address public owner;
  
  constructor() public {
    owner = msg.sender;
  }
  
  modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
  
    struct Wallet{
        uint value;
        address addr;
    }

    function setValue(uint _a,address _b) public onlyOwner {
        a = _a;
        b = _b;
    }

    function setWallet(uint _value, address _addr) public {
        Wallet wallet;
        wallet.value = _value;
        wallet.addr = _addr;
    }
}

```  
  
  
在这个合约中想要修改a，b需要管理员权限。但是在setWallet函数中，有未初始化的Wallet结构体的指针，未初始化指的是没有指定这个变量指向的位置，即没有等号右值。这时候，这个变量会指向storage中的第0个slot。而结构体中的字段会按照顺序依次指向后面的slot。  
  
  
对本合约来说，调用setWallet之后，传入的_value 和 _addr 就变成了a和b。  
  
  
**#实例**  
```
pragma solidity ^0.4.2;
contract rise {
    address referee;
    uint secret;
    uint bl;
    mapping(address => uint) public balance;
    mapping(address => uint) public gift;
    address owner;
    
    struct hacker { 
        address hackeraddress;
        uint value;
    }
    
    constructor()public{
        owner = msg.sender;
        referee = msg.sender;
        balance[msg.sender]=10000000;
        bl=1;
        secret=18487187377722;
    }
    event SendFlag(string b64email);
    
    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }
    
    modifier onlyRefer(){
        require(msg.sender == referee);
        _;
    }
    
    function payforflag(string b64email) public
    {
        require(balance[msg.sender]>1000000);
        balance[msg.sender]=0;
        bl=1;
        owner.transfer(address(this).balance);
        emit SendFlag(b64email);
    }
    
    function airdrop() public
    {
        require(gift[msg.sender]==0);
        gift[msg.sender]==1;
        balance[msg.sender]+=1;
    }
    
    function deposit() public payable
    {
        uint geteth=msg.value/1000000000000000000;
        balance[msg.sender]+=geteth;
    }
    
    function set_secret(uint target_secret) public onlyOwner
    {
        secret=target_secret;
    }
    
    function set_bl(uint target_bl) public onlyRefer
    {
        bl=target_bl;
    }
    
    function risegame(uint guessnumber) public payable
    {
        require(balance[msg.sender]>0);
        uint geteth=msg.value/1000000000000000000;
        if (guessnumber==secret)
        {
            balance[msg.sender]+=geteth*bl;
            bl=1;
        }
        else
        {
            balance[msg.sender]=0;
            bl=1;
        }
    }
    
    function transferto(address to) public
    {
        require(balance[msg.sender]>0);
        if (to !=0)
        {
            balance[to]=balance[msg.sender];
            balance[msg.sender]=0;
        }
        else
        {
            hacker storage h;
            h.hackeraddress=msg.sender;
            h.value=balance[msg.sender];
            balance[msg.sender]=0;
        }
    }
    
}

```  
  
  
获取flag的条件为余额大于1000000，在risegame函数的if分支中可以增加余额。guessnumber已经知道，geteth可以被控制，剩下需要考虑怎么去修改bl。bl声明后为默认值0，查看bl可以被修改的地方，发现函数set_bl可以随意修改bl，但有修饰符onlyRefer。该修饰符要求调用者为referee，再次查看代码，看是否有方法修改referee的值，在transferto函数中，if的第二个分支中，存在一个空指针h，并把solt中的第一个值修改为了调用者，第二个值修改为了调用者的余额。而调用该函数需要余额大于0。  
  
  
所以在调用该函数前，需要调用gift函数领取空投，将余额加1。再调用transfer，此时referee被修改为了调用者，值得注意的是，secret在这时被修改为了调用者的余额，因为领取完空头，所以余额为1，secret从18487187377722被修改为1。这时，就可以调用set_bl来修改bl，这里修改为1000000。调用deposit向合约中传1ether以通过risegame的校验。这时调用risegame，参数为1，传入1ether，此时余额达到触发flag的标准。  
  
  
  
  
**错误的构造函数**  
  
在solc小于0.5.0的版本中，和合约名相同的函数会被编译器认作构造函数。  
```
pragma ^0.4.0

contract A {
  function A() public {}
}

```  
  
但如果本应作为构造函数的函数有拼写错误，则本应作构造函数的函数就会变成普通的公开函数：  
```
pragma ^0.4.0

contract A {
  function a() public {}
}

```  
  
而对于0.4.22的solc版本，一个合约中可以同时使用constructor也可以使用同名来写构造函数，并且这两个构造函数都会执行，且第一个构造函数将优先于第二个，这可能是意料之外的：  
```
contract A {
    uint x;
    constructor() public {
        x = 0;
    }
    function A() public {
        x = 1;
    }
    
    function test() public returns(uint) {
        return x;
    }
}

```  
  
****  
**#实例**  
```
// bet.sol
pragma solidity ^0.4.24;

contract bet {
    uint secret;
    address owner;
    
    mapping(address => uint) public balanceOf;
    mapping(address => uint) public gift;
    mapping(address => uint) public isbet;
    
    event SendFlag(string b64email);
    
    function Bet() public{
        owner = msg.sender;
    }
    
    function payforflag(string b64email) public {
        require(balanceOf[msg.sender] >= 100000);
        balanceOf[msg.sender]=0;
        owner.transfer(address(this).balance);
        emit SendFlag(b64email);
    }
    

    //to fuck
    
    modifier only_owner() {
        require(msg.sender == owner);
        _;
    }
    
    function setsecret(uint secretrcv) only_owner {
        secret=secretrcv;
    }
    
    function deposit() payable{
        uint geteth=msg.value/1000000000000000000;
        balanceOf[msg.sender]+=geteth;
    }
    
    function profit() {
        require(gift[msg.sender]==0);
        gift[msg.sender]=1;
        balanceOf[msg.sender]+=1;
    }
    
    function betgame(uint secretguess){
        require(balanceOf[msg.sender]>0);
        balanceOf[msg.sender]-=1;
        if (secretguess==secret)
        {
            balanceOf[msg.sender]+=2;
            isbet[msg.sender]=1;
        }
    }
    
    function doublebetgame(uint secretguess) only_owner{
        require(balanceOf[msg.sender]-2>0);
        require(isbet[msg.sender]==1);
        balanceOf[msg.sender]-=2;
        if (secretguess==secret)
        {
            balanceOf[msg.sender]+=2;
        }
    }

}

```  
  
****  
这里使用的是之前整数溢出事的例子，在这个例子中，有一个Bet函数，该函数中设置了管理员的地址，且函数名与合约名只有一个大小写字母的区别，说明这个是预期的构造函数，但由于拼写错误，该函数并没有执行，并且可以被任何外部地址调用。  
  
  
我们直接调用这个函数，便直接获取了管理员权限。  
  
  
  
  
**强制转账**  
  
**# 原理**  
  
  
如果一个合约没有回退函数，或在回退函数中加了拒绝收Ether的相关逻辑则这个合约就无法接受Ether。但如果使用selfdestruct进行自毁，就可以实现对任意地址的Ether转账：  
```
contract transferForce{
    
    address owner;
    
    function () payable {
    }
    
    constructor()public{
        owner = msg.sender;
    }
    
    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }
    // 向合约强制转账
    function transfer(address to) public onlyOwner {
        selfdestruct(to);
    }
}

```  
  
部署合约并传入一些Ether，传入要强制转账的地址调用transfer就会进行自毁，并强制将本合约的所有Ether转到目标地址。  
  
  
**#实例**  
```
// h4ck.sol
pragma solidity ^0.4.25;

contract owned {
    address public owner;

    constructor () 
        public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public 
        onlyOwner {
        owner = newOwner;
    }
}

contract challenge is owned{
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public sellTimes;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public winner;

    event Transfer(address _from, address _to, uint256 _value);
    event Burn(address _from, uint256 _value);
    event Win(address _address,bool _win);


    constructor (
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;                
        name = tokenName;                                   
        symbol = tokenSymbol;                               
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != address(0x0));
        require(_value > 0);
        
        uint256 oldFromBalance = balanceOf[_from];
        uint256 oldToBalance = balanceOf[_to];
        
        uint256 newFromBalance =  balanceOf[_from] - _value;
        uint256 newToBalance =  balanceOf[_to] + _value;
        
        require(oldFromBalance >= _value);
        require(newToBalance > oldToBalance);
        
        balanceOf[_from] = newFromBalance;
        balanceOf[_to] = newToBalance;
        
        assert((oldFromBalance + oldToBalance) == (newFromBalance + newToBalance));
        emit Transfer(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value); 
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);    
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;          
        emit Burn(msg.sender, _value);
        return true;
    }
    
    function balanceOf(address _address) public view returns (uint256 balance) {
        return balanceOf[_address];
    }
    
    function buy() payable public returns (bool success){
        require(balanceOf[msg.sender]==0);
        require(msg.value == 1 wei);
        _transfer(address(this), msg.sender, 1);
        sellTimes[msg.sender] = 1;
        return true;
    }
    
    
    function sell(uint256 _amount) public returns (bool success){
        require(_amount >= 100);
        require(sellTimes[msg.sender] > 0);
        require(balanceOf[msg.sender] >= _amount);
        require(address(this).balance >= _amount);
        msg.sender.call.value(_amount)();
        _transfer(msg.sender, address(this), _amount);
        sellTimes[msg.sender] -= 1;
        return true;
    }
    
    function winnerSubmit() public returns (bool success){
        require(winner[msg.sender] == false);
        require(sellTimes[msg.sender] > 100);
        winner[msg.sender] = true;
        emit Win(msg.sender,true);
        return true;
    }
    
    function kill(address _address) public onlyOwner {
        selfdestruct(_address);
    }
    
    function eth_balance() public view returns (uint256 ethBalance){
        return address(this).balance;
    }
    
}

```  
  
  
该实例使用的是重入章节的，在获取flag的过程中需要，合约地址的余额大于100，而该合约中并没有接受Ether的回退函数，则需要使用自毁强制转Ether到该合约。  
  
  
  
  
  
**总结**  
  
这类利用solidity语言本身漏洞的竞赛题目是目前的主流题目，在利用这些漏洞之前要去看类似版本，危险的函数调用等信息。  
  
  
这类利用solidity语言本身漏洞的竞赛题目是目前的主流题目，在利用这些漏洞之前要去看类似版本，危险的函数调用等信息。  
         
  
