/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * If your rules are coming from a model object, then they must implement this interface
 */
interface{

	/**
	 * Get the system security rules as an array or a query
	 *
	 * @return array or query of rules
	 */
	any function getSecurityRules();

}