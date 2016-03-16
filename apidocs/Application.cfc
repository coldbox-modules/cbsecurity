component{

	this.name = "APIDocs" & hash(getCurrentTemplatePath());
	this.sessionManagement = true;
	this.sessionTimeout = createTimeSpan(0,0,1,0);

	// API Root
	API_ROOT = getDirectoryFromPath( getCurrentTemplatePath() );
	rootPath = REReplaceNoCase( API_ROOT, "apidocs(\\|\/)$", "" );

	// MODULE NAME
	request.moduleName = "cbsecurity";

	this.mappings[ "/docbox" ] 	= API_ROOT & "docbox";
	this.mappings[ "/root" ] 	= rootPath;
	this.mappings[ "/#request.moduleName#" ] = rootPath & "modules/#request.moduleName#/models";

}