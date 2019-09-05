/**
 * All security validators must implement
 */
interface{

	/**
	 * This function is called once an incoming event matches a security rule.
	 * You will receive the security rule that matched and an instance of the
	 * ColdBox controller.
	 *
	 * @return True, user can continue access, false, relocation will occur.
	 */
	boolean function userValidator( required rule, required controller );

}