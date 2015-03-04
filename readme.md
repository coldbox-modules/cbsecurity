#WELCOME TO THE COLDBOX SECURITY MODULE

This module will provide your application with a security rule engine. For more information visit the documentation here: http://wiki.coldbox.org/wiki/Security.cfm

##LICENSE
Apache License, Version 2.0.

##IMPORTANT LINKS
- https://github.com/ColdBox/cbox-security
- http://www.coldbox.org/forgebox/view/cbsecurity
- http://wiki.coldbox.org/wiki/Security.cfm

##SYSTEM REQUIREMENTS
- Lucee 4.5+
- Railo 4+
- ColdFusion 9+

INSTRUCTIONS
============

Just drop into your **modules** folder or use CommandBox to install

`box install cbsecurity`

The module will register a security interceptor with empty rules for you.  You can update the security rules included in the `config` folder or comment the interceptor out and just add it to your main application or necessary modules using the mapping it creates for you:

`cbsecurity.interceptors.Security`

You can find all the documentation here: http://wiki.coldbox.org/wiki/Security.cfm

## Interceptor Declaration
Here is a sample declaration you can use in your `ColdBox.cfc`:

```
// Security Interceptor declaration.
interceptors = [
    { class="cbsecurity.interceptors.Security",
      name="CBSecurity",
      properties={
        // please add the properties you want here to configure the security interceptor
        rulesFile = "/cbsecurity/config/security.json.cfm",
        rulesSource = "json"
     } }
];
```

********************************************************************************
Copyright Since 2005 ColdBox Framework by Luis Majano and Ortus Solutions, Corp
www.coldbox.org | www.luismajano.com | www.ortussolutions.com
********************************************************************************
####HONOR GOES TO GOD ABOVE ALL
Because of His grace, this project exists. If you don't like this, then don't read it, its not for you.

>"Therefore being justified by faith, we have peace with God through our Lord Jesus Christ:
By whom also we have access by faith into this grace wherein we stand, and rejoice in hope of the glory of God.
And not only so, but we glory in tribulations also: knowing that tribulation worketh patience;
And patience, experience; and experience, hope:
And hope maketh not ashamed; because the love of God is shed abroad in our hearts by the 
Holy Ghost which is given unto us. ." Romans 5:5

###THE DAILY BREAD
 > "I am the way, and the truth, and the life; no one comes to the Father, but by me (JESUS)" Jn 14:1-12