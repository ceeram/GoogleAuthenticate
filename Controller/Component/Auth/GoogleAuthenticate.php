<?php
App::uses('FormAuthenticate', 'Controller/Component/Auth');
App::uses('GoogleAuthenticator', 'GoogleAuthenticate.Lib');
/**
 * An authentication adapter for AuthComponent.  Provides the ability to authenticate using POST
 * data. The username form input can be checked against multiple table columns, for instance username and email
 *
 * {{{
 *	$this->Auth->authenticate = array(
 *		'Authenticate.Google' => array(
 *			'fields' => array(
 *				'username' => 'username',
 *				'password' => 'password',
 *				'code' => 'code',//fieldname in form
 *				'secret' => 'secret'//fieldname in table
 *	 		),
 *			'userModel' => 'User',
 *			'scope' => array('User.active' => 1)
 *		)
 *	)
 * }}}
 *
 */
class GoogleAuthenticate extends BaseAuthenticate {

/**
 * Settings for this object.
 *
 * - `fields` The fields to use to identify a user by.
 * - 'columns' array of columns to check username form input against
 * - `userModel` The model name of the User, defaults to User.
 * - `scope` Additional conditions to use when looking up and authenticating users,
 *    i.e. `array('User.is_active' => 1).`
 *
 * @var array
 */
	public $settings = array(
		'fields' => array(
			'username' => 'username',
			'password' => 'password',
			'code' => 'code',
			'secret' => 'secret'
		),
		'userModel' => 'User',
		'scope' => array(),
		'recursive' => 0,
		'contain' => null
	);


/**
 * Checks the fields to ensure they are supplied.
 *
 * @param $data The request data
 * @param array $keys The keys to be checked.
 * @return boolean False if the keys are missing or empty, true if present and not empty
 */
	protected function _checkFields($data, $keys = array('username', 'password')) {
		list(, $model) = pluginSplit($this->settings['userModel']);
		if (empty($data[$model])) {
			return false;
		}
		foreach ($keys as $key) {
			if (empty($data[$model][$this->settings['fields'][$key]])) {
				return false;
			}
		}
		return true;
	}

/**
 * Authenticates the identity contained in a request.  Will use the `settings.userModel`, and `settings.fields`
 * to find POST data that is used to find a matching record in the `settings.userModel`.  Will return false if
 * there is no post data, either username or password is missing, of if the scope conditions have not been met.
 *
 * @param CakeRequest $request The request that contains login information.
 * @param CakeResponse $response Unused response object.
 * @return mixed.  False on login failure.  An array of User data on success.
 */
	public function authenticate(CakeRequest $request, CakeResponse $response) {
		list(, $model) = pluginSplit($this->settings['userModel']);

		if (!$this->_checkFields($request->data)) {
			return false;
		}

		$fields = $this->settings['fields'];
		$user = $this->_findUser($request->data[$model][$fields['username']], $request->data[$model][$fields['password']]);
		if (!$user) {
		    return false;
		}

		if(empty($user[$fields['secret']])) {
			return $user;
		}

		if (!$this->_checkFields($request->data, array('code'))) {
			return false;
		}

		$Google = new GoogleAuthenticator();

		return $Google->checkCode($user[$fields['secret']], $request->data[$model][$fields['code']]) ? $user : false;
	}

}
