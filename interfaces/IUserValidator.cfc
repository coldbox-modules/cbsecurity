/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * All security validators must implement
 */
interface{

	/**
	 * This function is called once an incoming event matches a security rule.
	 * You will receive the security rule that matched and an instance of the
	 * ColdBox controller.
	 *
	 * @return True, user can continue access, false, invalid access actions will ensue
	 */
	boolean function ruleValidator( required rule, required controller );

	/**
	 * This function is called once access to a handler/action is detected.
	 * You will receive the secured annotation value and an instance of the ColdBox Controller
	 *
	 * @return True, user can continue access, false, invalid access actions will ensue
	 */
	boolean function annotationValidator( required securedValue, required controller );

}