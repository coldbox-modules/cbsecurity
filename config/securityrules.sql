--Primary key, can be anything you want.

CREATE TABLE securityrules
(
	'id' VARCHAR(36) NOT NULL,
	'whiteList' VARCHAR(255),
	'secureList' VARCHAR(255),
	'roles' VARCHAR(255),
	'permissions' VARCHAR(255),
	'redirect' VARCHAR(255),
	'overrideEvent' VARCHAR(255),
	'useSSL' bit NOT NULL DEFAULT 0
	'match' varchar(10) DEFAULT 'event'
	'action' varchar(20) DEFAULT 'redirect'
	'module' varchar(255) DEFAULT ''
	'httpMethods' varchar(100) DEFAULT '*'
	'allowedIPs' varchar(255) DEFAULT '*'
	PRIMARY KEY (id),
	UNIQUE (id)
);
