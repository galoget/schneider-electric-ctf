# Schneider Electric CTF Write-up

Repository with the solutions to the Schneider Electric Hackathon (CTF) for the Cybersecurity category.

# Team details

**Team:** Hackem (1 participant)

**Author:** Galoget Latorre

### 🌋 GeoHome Hacking | Background
A new company, GeoHome, has detected that it could have security flaws since it has never been audited. Will you be able to find all the vulnerabilities?

GeoHome, is developing and researching cutting-edge geothermal technologies.

The CEO has shown some concerns regarding the security of their systems. They are looking for pentesters to help them secure their business.

Here you come in, pentesters, perform a full audit, find all the vulnerabilities, and report them! The future of GeoHome is in your hands!

### 💯 Scoring
This challenge will be a CTF-like one where you will have to find all the vulnerabilities and get the flags from each one of them.

The scoring distribution will be based on:

- 70% of the score will be assessed based on the writeup you provide.
- The other 30% will be the number of flags you can find.
- There is a 10% extra for some harder flags to find.

For this competition a standard Kali Linux 2022.1 VM will be used. Executed commands will be included as text to ease the reproduction of steps if required.

## FLAG{ALWAYS_CHECK_COMMITS}

After setting up the environment to attack the target machine. First, we scanned all available ports to discover running services.

This was done with the following command:

```sh
┌──(galoget㉿hackem)-[~]
└─$ nmap -n -Pn -p- 192.168.2.16 --open
```

![alt text for screen readers](/path/to/image.png "Text to show on mouseover")

With the previous results we focused on enumerating and gathering more information from open ports only. For this, we used `nmap` with additional parameters:

```sh
┌──(galoget㉿hackem)-[~]
└─$ sudo nmap -n -Pn -p 53,80,88,135,139,389,443,445,464,593,636,1337,3268,3269,3306,5000,5985,9389,33060,47001,49664,49665,49666,49667,49671,49678,49679,49683,49701 -vvvv -sV -A -O --script vuln 192.168.2.16 --open
```

![Detailed nmap port scan](images/nmap-detailed.png "Detailed nmap port scan")

The detailed output from `nmap` is (just important aspects were included):

```sh
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 128 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 128 Microsoft IIS httpd 10.0
| http-enum: 
|_  /robots.txt: Robots file
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  syn-ack ttl 128 Microsoft Windows Kerberos (server time: 2022-05-21 11:45:39Z)
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: geohome.com0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
445/tcp   open  microsoft-ds? syn-ack ttl 128
464/tcp   open  kpasswd5?     syn-ack ttl 128
593/tcp   open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: geohome.com0., Site: Default-First-Site-Name)
1337/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
3268/tcp  open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: geohome.com0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: geohome.com0., Site: Default-First-Site-Name)
3306/tcp  open  mysql         syn-ack ttl 128 MySQL (blocked - too many connection errors)
5000/tcp  open  upnp?         syn-ack ttl 128
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.7.0
|     Date: Sat, 21 May 2022 11:45:39 GMT
|     Content-Type: application/json
|     Content-Length: 50
|     Connection: close
|     {"text":"There is nothing to see here (I guess)"}
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.7.0
|     Date: Sat, 21 May 2022 11:45:54 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|     Connection: close
|   Help: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('HELP').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 128 .NET Message Framing
33060/tcp open  tcpwrapped    syn-ack ttl 128
47001/tcp open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49678/tcp open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49683/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49701/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC

Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (96%), Microsoft Windows 10 1709 - 1803 (94%), Microsoft Windows Server 2012 (92%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%), Microsoft Windows Server 2016 (91%), Microsoft Windows 10 1703 (91%), Microsoft Windows Server 2012 or Server 2012 R2 (90%)
```

At this point we find a web server `Microsoft IIS httpd 10.0` running on port 80:

![Microsoft IIS httpd 10.0 running on port 80](images/iis.png "Microsoft IIS httpd 10.0` running on port 80")

With `nmap` we found that a file called `robots.txt` exists, so we proceeded to check its content:

![robots.txt on port 80](images/robots.txt.png "robots.txt on port 80")

This looks like a virtual host, so we created a custom entry at `/etc/hosts`:

```sh
192.168.2.16    wp.geohome.com
```

Then, we browsed into `https://wp.geohome.com` and had the company portal loaded:

![GeoHome WordPress Portal at port 443](images/geohome-wordpress.png "GeoHome WordPress Portal at port 443")

After exploring the source code we found some external URLs leading to 2 company profiles located in the footer section:

- [GitHub](https://github.com/geohome-dev/GeoAPI)

- [Facebook](https://www.facebook.com/people/GeoHome-Energy/100081213822308/)

![GeoHome WordPress Portal Footer at port 443](images/geohome-wordpress-footer.png "GeoHome WordPress Portal Footer at port 443")

We started checking the GitHub profile to search for possible insecure repositories, data leakage and other common bad pratices.

We found a repository for an API, where some instructions are included on how to create an account and how to login:

![GeoHome GeoAPI GitHub Repo](images/geohome-dev-geoapi.png "GeoHome GeoAPI GitHub Repo")

This seems to be an application in development, the last commit was just 5 days ago. So we checked the commit history and we found two valuable things:

- Our first Flag: `FLAG{ALWAYS_CHECK_COMMITS}`
- A JWT Secret Key (can be used to forge tokens): `Ge0HomeIsThePlaceWhereFantasyMeetsReality`

![GeoHome GeoAPI GitHub Commit with first OSINT flag and JWT Secret Key](images/geohome-dev-geoapi-commit-flag-jwt-secret.png "GeoHome GeoAPI GitHub Commit with first OSINT flag and JWT Secret Key")


## FLAG{Update_Plugins!}

After getting our first flag, we went back to the GeoHome WordPress portal and started scanning it to search for any possible vulnerabilities and/or misconfigurations.

For this purpose we used WPScan:

```sh
┌──(galoget㉿hackem)-[~]
└─$ wpscan --url https://wp.geohome.com/ --disable-tls-checks
```

![WPScan against GeoHome WordPress Portal](images/wpscan-wordpress-geohome.png "WPScan against GeoHome WordPress Portal")

In the previous image we found that 1 plugin is out of date but it does not have any well known vulnerabilities.

On the other hand there is another plugin called `perfect-survey` that is up to date but is known to have a SQL Injection (Unauthenticated) vulnerability. We used `searchsploit` to verify this and get a PoC:

```sh
┌──(galoget㉿hackem)-[~]
└─$ searchsploit "Wordpress Perfect Survey"

┌──(galoget㉿hackem)-[~]
└─$ searchsploit -m 50766
```

![Searchsploit with WordPress Perfect Survey Plugin SQL Injection Vulnerability](images/searchsploit-wordpress-perfect-survey.png "Searchsploit with WordPress Perfect Survey Plugin SQL Injection Vulnerability")

This exploit maps to `CVE-2021-24762` and we can see that the Python script is using `sqlmap` to gather the information of the database:

![WordPress Perfect Survey Plugin Python Exploit Source Code](images/wordpress-perfect-survey-plugin-exploit-sqlmap.png "WordPress Perfect Survey Plugin Python Exploit Source Code")

We can use this exploit or `sqlmap` directly to take advantage of this vulnerability. We chose to use `sqlmap` directly as this tool provides us with more options than just the pre-defined in the exploit:

```sh
┌──(galoget㉿hackem)-[~]
└─$ sqlmap -u "https://wp.geohome.com/wp-admin/admin-ajax.php?action=get_question&question_id=1 *"
```

![SQLMap Testing SQLi in Perfect Survey Plugin](images/sqlmap-sql-wordpress-geohome-perfect-survey.png "SQLMap Testing SQLi in Perfect Survey Plugin")

In the previous image we verified that this WordPress instance is vulnerable to SQL Injection and we do not require any type of authentication. This allow us to exfiltrate all the information in the Database, and depending on the user's permissions, we would be able to modify the information in the DB.

As this is a CTF challenge, there is no purpose in modifying the information on the DB, but in a real scenario this could be critical, afecting Confidentiality, Integrity and Availiability (CIA security triad).

The only legitimate use in this case for us to modify the DB registries is to modify the WordPress Administrator password to enter into the Admin Dashboard, which could allow us to upload files and get a reverse shell.

After this initial test, we proceeded to gather all the databases in this DBMS (MySQL):

```sh
┌──(galoget㉿hackem)-[~]
└─$ sqlmap -u "https://wp.geohome.com/wp-admin/admin-ajax.php?action=get_question&question_id=1 *" --dbms=mysql --dbs
```

![SQLMap dumping all Databases available in the system](images/sqlmap-sql-wordpress-geohome-perfect-survey-dbs.png "SQLMap dumping all Databases available in the system")

Then, we listed the tables of flag database:

```sh
┌──(galoget㉿hackem)-[~]
└─$ sqlmap -u "https://wp.geohome.com/wp-admin/admin-ajax.php?action=get_question&question_id=1 *" --dbms=mysql -D flag --tables
```

![SQLMap dumping all Tables available in the flag database](images/sqlmap-sql-wordpress-geohome-perfect-survey-tables.png "SQLMap dumping all Tables available in the flag database")

Finally, we got the content of the table flag and retrieve our second flag:

```sh
┌──(galoget㉿hackem)-[~]
└─$ sqlmap -u "https://wp.geohome.com/wp-admin/admin-ajax.php?action=get_question&question_id=1 *" --dbms=mysql -D flag -T flag --dump
```

![SQLMap dumping the flag in the flag table](images/sqlmap-sql-wordpress-geohome-perfect-survey-flag.png "SQLMap dumping the flag in the flag table")

The Flag is: `FLAG{Update_Plugins!}`


## API_FLAG{Never_public_your_secret}

This challenge is related with the GitHub repository where we got the JWT Secret, with this we are able to forge a token.

The token will be used in an API. So we enumerated the services that would match this requirement, and we found:

![JSON API Initial Endpoint](images/json-api.png "JSON API Initial Endpoint")

In order to retrieve all the endpoints of the API, we used a fuzzing tool called `gobuster`:

![Gobuster enumerating JSON API Endpoints](images/gobuster-json-api-common-endpoints.png "Gobuster enumerating JSON API Endpoints")

If we remember, in the repository there were instructions on how to create an account in the GeoAPI and then how to login. So we used that information to create our test account and login to get a JWT token:

![Postman creating galoget user at GeoAPI](images/postman-register-galoget-api.png "Postman creating galoget user at GeoAPI")

Now that we have an account, let's login:

![Postman logging in as galoget user at GeoAPI](images/postman-login-galoget-api.png "Postman logging in as galoget user at GeoAPI")

As we can see, we received a JWT token. We can verify this token by using the secret collected in part one of this write-up.

We verified the signature of the token by adding the secret:

![JWT Signature Verified (Correct Secret)](images/jwt-secret-signature-verified.png "JWT Signature Verified (Correct Secret)")

Then, we changed our username in the `sub` field to `admin`:

![Forged Admin JWT Token](images/jwt-forged-admin.png "Forged Admin JWT Token")

For this we used the official website of JWT, [here is a direct link](https://jwt.io/#debugger-io?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY1MzEyNjc4NCwianRpIjoiYWUyODE1ZGMtNmYzOC00MDkyLWJjZjgtZjg3YTZmYTExYjlhIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNjUzMTI2Nzg0fQ.y454Wm-I2c_41EvdLIpZWWm2mww7S79fosSup7yANkI) with the forged token. You will need to add the secret in the last text box.

Using this token we browse into the `/admin` endpoind and got our flag:

![GeoAPI Admin Endpoint Flag using Forged Token](images/postman-admin-api-flag.png "GeoAPI Admin Endpoint Flag using Forged Token")

The flag is: `API_FLAG{Never_public_your_secret}`

## FLAG{SSRF_PARA_TOD@S_XD}

By doing additional enumeration on the `Microsoft IIS httpd 10.0` web server we found additional files:

![Gobuster Enumerating IIS](images/gobuster-iis.png "Gobuster Enumerating IIS")

We found some interesting files by using some wordlists:
- index.php
- comments.txt
- testsite.php

The `testsite.php` page seems to be like website that executes the `curl` command and shows the content on the website, this can be used to access content that is only accessible by the webserver. This attack is known as SSRF (Server-Side Request Forgery).

![Curler Main Page](images/curler.png "Curler Main Page")

We checked the security of this application by trying to access some internal files and URLs. At the beginning some security controls were detected, but they were easy to bypass:

![Curler HTTP Validation](images/curler-http-validation.png "Curler HTTP Validation")

The web app checks that the inserted URL is using HTTP protocol, otherwise this error appears.

![Curler localhost Validation](images/curler-localhost-validation.png "Curler localhost Validation")

The web app also checks that the inserted URL contains localhost and blocks it for security reasons. But as we said before, this mechanism can easily be bypassed by using:

![Curler Bypass localhost Validation](images/curler-bypass-localhost-validation.png "Curler Bypass localhost Validation")

Now, we can use this technique to test all ports and verify if in anyone it only accepts localhost requests, and we found on port 1337 this case:

![Curler SSRF Flag](images/curler-ssrf-flag.png "Curler SSRF Flag")

The flag is: `FLAG{SSRF_PARA_TOD@S_XD}`


## FLAG{sanitize_input}

The `index.php` page seems to be like a comment system (that's the title of the page) where inserted comments are saved in `comments.txt` file.

![Comment System Main Page](images/comment-system.png "Comment System Main Page")

After some testing, injected code is executed, allowing client-side attacks like Cross-Site Scripting, which in this case would be a Stored XSS.

We injected a malicious payload to steal any cookies from a person that visits this comment system.

![Stored XSS Attack to Steal Cookie from Admin](images/stored-xss-steal-cookie.png "Stored XSS Attack to Steal Cookie from Admin")

As we can see in the previous image, an Admin (a bot, as it is using PhantomJS) visited the website, our payload redirected it to our controlled website while transmitting the cookie as a parameter, which is our flag.

The flag is: `FLAG{sanitize_input}`


## FLAG{Mas_uno_por_revisar_sistema}

Then, we needed to gain access into the system, so we used the Facebook page of the company to enumerate possible employees and usernames:

![Facebook User Emumeration](images/facebook-user-enumeration.png "Facebook User Emumeration")

With this information we tried a lot of attacks, like brute-force attacks, dictionary attacks, password spraying, among others.

They were not very useful, so we decided to attack the Active Directory itself. We found that it has a Zerologon Vulnerability. This would allow us to gain access to the Domain controller and retrieve all user hashes.

![Zerologon Exploit](images/zerologon-exploit.png "Zerologon Exploit")

As we can see in the previous image, we changed the Admin password to blank. Now, we can retrieve all the hashes of the users by using secretsdump.

![Secretsdump retrieving all hashes](images/zerologon-hashes.png "Secretsdump retrieving all hashes")

We also tried to crack these hashes:

![All dumped hashes that we tried to crack](images/all-hashes.png "All dumped hashes that we tried to crack")

One hash was successfully cracked:

![FFuertes Cracked Hash](images/ffuertes-cracked-hash.png "FFuertes Cracked Hash")

We can use any of the hashes or the cracked credential to try to enumerate more services lice SMB:

![FFuertes SMB Shares](images/smbclient-ffuertes.png "FFuertes SMB Shares")

But remember, we do not need to crack all of them, we can use Pass-The-Hash (PTH) technique to re-use them and gain access to the system:

![Metasploit Pass The Hash with psexec](images/msf-pth-options.png "Metasploit Pass The Hash with psexec")

With this technique, we gained access to the system and got a Meterpreter shell with `NT AUTHORITY\SYSTEM` privileges:

![Meterpreter with SYSTEM privileges](images/msf-psexec-pth-meterpreter.png "Meterpreter with SYSTEM privileges")

By having `SYSTEM` privileges, basically we are the owners of the machine, so we can access all files on the computer and retrieve all flags.

![Meterpreter with SYSTEM privileges showing all flags](images/msf-psexec-pth-all-flags.png "Meterpreter with SYSTEM privileges showing all flags")

The flags are:
- `FLAG{Mas_uno_por_revisar_sistema}`
- `FLAG{Buen_Password_Spraying_Eh?}`
- `FLAG{Pesadilla_en_el_trabajo}`
- `FLAG{Ay_Ay_Vigila_Tu_Puesto}`
- `FLAG{A_su_servicio}`


## FLAG{El_Buen_OSINT_Naito}

By doing some additional enumeration, we found some files in the `Public` profile that lead us to an Instagram profile:

![Meterpreter with User's default password and Instagram URL](images/default-password-ig-profile.png "Meterpreter with User's default password and Instagram URL")

By checking the pictures of this user, we found a photo where some sensitive information was shared, including our flag:

![Instagram Ffuertes profile with the Flag](images/instagram-flag-osint.png "Instagram Ffuertes profile with the Flag")

The flag is: `FLAG{El_Buen_OSINT_Naito}`

## FLAG{Sticky_Notes_FTW}

Finally, in the user `jenriques` we found and interesting file along witht he flag at `Desktop` directory, by doing some research, we determined that those files were related to Sticky Notes.

We decided to copy these files to our local computer to further analysis:

![Meterpreter copying Sticky Notes Files](images/msf-meterpreter-sticky.png "Meterpreter copying Sticky Notes Files")

Then, we moved these files into the corresponding folder of our system to restore them and we got the flag:

![Restored Sticky Notes with the Flag](images/restored-sticky-notes.png "Restored Sticky Notes with the Flag")


## BONUS

To finally take over the machine, as we have `SYSTEM` privileges, we decided to change the `Administrator` password and enable RDP.

![Change the Admin Password and Enable RDP](images/change-admin-pass-enable-rdp.png "Change the Admin Password and Enable RDP")

Now we can connect via our favorite RDP client:

![RDP Admin Access](images/rdp-admin-access.png "RDP Admin Access")

Then we maximize the screen to have a better resolution:

![RDP Admin Access Maximized](images/rdp-admin-access-ad-cmd-taskmgr.png "RDP Admin Access Maximized")

And....the Domain Controller has been pwned.

Thanks for such a nice CTF, we really enjoyed it!

Best regards,

Galoget Latorre



