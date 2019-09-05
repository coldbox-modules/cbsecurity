<?xml version="1.0" encoding="UTF-8"?>
<rules>
    <rule>
        <match>event</match>
        <whitelist>user\.login,user\.logout,^main.*</whitelist>
        <securelist>^user\..*, ^admin</securelist>
        <roles>admin</roles>
        <permissions>read,write</permissions>
		<redirect>user.login</redirect>
		<useSSL>false</useSSL>
    </rule>

    <rule>
        <match>event</match>
        <whitelist></whitelist>
        <securelist>^moderator</securelist>
        <roles>admin,moderator</roles>
        <permissions>read</permissions>
		<redirect>user.login</redirect>
		<useSSL>false</useSSL>
    </rule>

    <rule>
        <match>url</match>
        <whitelist></whitelist>
        <securelist>/secured.*</securelist>
        <roles>admin,paid_subscriber</roles>
        <permissions></permissions>
		<redirect>user.pay</redirect>
		<useSSL>false</useSSL>
    </rule>
</rules>