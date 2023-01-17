[
    {
        "whiteList": "",
        "secureList": "",
        "match": "event",
        "roles": "admin",
        "permissions": "",
		"action" : "redirect",
		"useSSL": false,
		"redirect": "user.login",
		"httpMethods" : "*",
		"allowedIPs" : "*"
	},
	{
        "whiteList": "",
        "secureList": "^admin",
        "match": "event",
        "roles": "admin",
		"overrideEvent" : "user.login"
    }
]
