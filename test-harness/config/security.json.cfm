[
    {
        "whitelist": "",
        "securelist": "admin",
        "match": "event",
        "roles": "admin",
        "permissions": "",
        "redirect": "main.index",
		"httpMethods" : "*"
	},
	{
        "whitelist": "",
        "securelist": "override",
        "match": "url",
        "roles": "",
        "permissions": "",
        "overrideEvent": "main.index",
		"httpMethods" : ""
    },
	{
        "whitelist": "",
        "securelist": "public",
        "match": "url",
        "roles": "",
        "permissions": "",
        "overrideEvent": "main.index",
		"httpMethods" : "post,put"
    }
]
