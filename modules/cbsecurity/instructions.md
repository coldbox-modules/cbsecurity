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