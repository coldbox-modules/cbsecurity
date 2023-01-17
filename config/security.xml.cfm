<?xml version="1.0" encoding="UTF-8"?>
<!--
Declare as many rule elements as you want, order is important
Remember that the securelist can contain a list of regular
expression if you want

ex: All events in the user handler
 user\..*
ex: All events
 .*
ex: All events that start with admin
 ^admin

If you are not using regular expression, just write the text
that can be found in an event.
-->
<rules>
    <rule>
		<!-- What needs to match to evaluate the rule -->
        <secureList>^user\..*, ^admin</secureList>
        <!-- What needs to match to skip the rule, securelist must match first -->
		<whiteList>user\.login,user\.logout,^main.*</whiteList>
		<!-- Match the event or the URL -->
		<match>event</match>
		<!-- Roles needed else an action is issued -->
        <roles>admin</roles>
		<!-- Permissions needed else an action is issued -->
		<permissions></permissions>
		<!-- redirect or override or block -->
		<action>redirect</action>
		<!-- Match all HTTP methods or particular ones -->
		<httpMethods>*</httpMethods>
		<!-- Match all IPs or particular ones -->
		<allowedIPs>*</allowedIPs>
		<!-- Optional: If used we redirect to this event else we look at the global redirect event -->
		<redirect>user.login</redirect>
		<!-- Optional: If used we override to this event else we look at the global override event -->
		<overrideEvent>user.login</overrideEvent>
		<!-- Redirect in SSL -->
		<useSSL>false</useSSL>
    </rule>
</rules>
