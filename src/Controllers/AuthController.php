<?php namespace Myth\Auth\Controllers;

use App\Models\Smslogs;
use CodeIgniter\Controller;
use CodeIgniter\Session\Session;
use Myth\Auth\Config\Auth as AuthConfig;
use Myth\Auth\Entities\User;
use Myth\Auth\Models\UserModel;
use Myth\Auth\Models\AuthGuuidCodfis;
use App\Models\Webinar;
use App\Models\WebinarAnagrafe;
use Myth\Auth\Models\AuthUserOtp;
use Myth\Auth\Models\AuthUserOtpAttempts;
use Myth\Auth\Models\AuthUserSmsOtpAttempts;
use Myth\Auth\Models\AuthUserUuidAttempts;

use CodiceFiscale;

class AuthController extends Controller
{
	protected $auth;

	/**
	 * @var AuthConfig
	 */
	protected $config;

	/**
	 * @var Session
	 */
	protected $session;

	public function __construct()
	{
		// Most services in this controller require
		// the session to be started - so fire it up!
		$this->session = service('session');

		$this->config = config('Auth');
		$this->auth = service('authentication');
	}

	//--------------------------------------------------------------------
	// Login/out
	//--------------------------------------------------------------------

	/**
	 * Displays the login form, or redirects
	 * the user to their destination/home if
	 * they are already logged in.
	 */
	public function login()
	{
		// No need to show a login form if the user
		// is already logged in.
		if ($this->auth->check())
		{
			$redirectURL = session('redirect_url') ?? base_url('/frontend');
			unset($_SESSION['redirect_url']);

			return redirect()->to($redirectURL);
		}

        // Set a return URL if none is specified
        $_SESSION['redirect_url'] = session('redirect_url') ?? previous_url() ?? base_url('/frontend');

		return $this->_render($this->config->views['login'], ['config' => $this->config]);
	}

	/**
	 * Attempts to verify the user's credentials
	 * through a POST request.
	 */
	public function attemptLogin()
	{

		if (!$this->googleCaptachStore()) {
			return redirect()->route('login')->withInput()->with('error', lang('Platone.errore_google_captcha'));
		}

		$rules = [
			'login'	=> 'required',
			'password' => 'required',
		];
		if ($this->config->validFields == ['email'])
		{
			$rules['login'] .= '|valid_email';
		}

		if (! $this->validate($rules))
		{
			return redirect()->back()->withInput()->with('errors', $this->validator->getErrors());
		}

		$login = $this->request->getPost('login');
		$password = $this->request->getPost('password');
		$remember = (bool)$this->request->getPost('remember');

		// Determine credential type
		$type = filter_var($login, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

		// Try to log them in...
		if (! $this->auth->attempt([$type => $login, 'password' => $password], $remember))
		{
			return redirect()->back()->withInput()->with('error', $this->auth->error() ?? lang('Auth.badAttempt'));
		}

		// Is the user being forced to reset their password?
		if ($this->auth->user()->force_pass_reset === true)
		{
			return redirect()->to(route_to('reset-password') .'?token='. $this->auth->user()->reset_hash)->withCookies();
		}

		$redirectURL = session('redirect_url') ?? base_url('/frontend');
		unset($_SESSION['redirect_url']);

		if ($redirectURL == base_url()."/") {
			$redirectURL = base_url("/frontend");
		}

		return redirect()->to($redirectURL)->withCookies()->with('message', lang('Auth.loginSuccess'));
	}

	/**
	 * Log the user out.
	 */
	public function logout()
	{
		if ($this->auth->check())
		{
			$this->auth->logout();
		}

		return redirect()->to(base_url('/'));
	}

	//--------------------------------------------------------------------
	// Register
	//--------------------------------------------------------------------

	/**
	 * Displays the user registration page.
	 */
	public function register()
	{
        // check if already logged in.
		if ($this->auth->check())
		{

			return redirect()->to(base_url('frontend'))->with('message', lang('Platone.sei_gia_autenticato'));
		}

        // Check if registration is allowed
		if (! $this->config->allowRegistration)
		{
			return redirect()->route('register')->withInput()->with('error', lang('Auth.registerDisabled'));
		}

		return $this->_render($this->config->views['register'], ['config' => $this->config]);
	}

	/**
	 * Attempt to register a new user.
	 */
	public function attemptRegister()
	{
		// Check if registration is allowed
		if (! $this->config->allowRegistration)
		{
			return redirect()->route('register')->withInput()->with('error', lang('Auth.registerDisabled'));
		}

		if (!$this->googleCaptachStore()) {
			return redirect()->route('register')->withInput()->with('error', lang('Platone.errore_google_captcha'));

		}

		$users = model(UserModel::class);

		$allowedPostFields = array_merge(['password'], $this->config->validFields, $this->config->personalFields);
        $data = $this->request->getPost($allowedPostFields);

		if (empty($data['username'])) {
			//$data['username'] = $this->clean(strtolower($data['first_name'].$data['last_name']));
			$data['username'] = $this->clean(strtolower($data['first_name'].$data['last_name'].time()));
			$_POST['username'] = $data['username'];
		}
        /*echo "<pre>";
            print_r($data);
			print_r($_POST);
			print_r($this->request);
        echo "</pre>";
        exit;*/

		// Validate basics first since some password rules rely on these fields
		$rules = [
			//'username' => 'required|alpha_numeric_space|min_length[3]|max_length[30]|is_unique[users.username]',
			'first_name' 	=> ['label' => lang('Platone.first_name'), 'rules' => 'required|min_length[3]|max_length[255]'],
			'last_name' 	=> ['label' => lang('Platone.last_name'), 'rules' => 'required|min_length[3]|max_length[255]'],
			'cod_fis' 		=> ['label' => lang('Platone.cod_fis'), 'rules' => 'required|alpha_numeric_space|min_length[16]|max_length[16]|is_unique[users.cod_fis]'],
			'phone' 		=> ['label' => lang('Platone.phone'), 'rules' => 'required|alpha_numeric_space|min_length[3]|max_length[13]|is_unique[users.phone]'],
			'email'    		=> ['label' => lang('Platone.email'), 'rules' => 'required|valid_email|is_unique[users.email]'],
		];

		$errors = [
			'email' => [
				'is_unique'	=>	lang("Platone.indirizzo_email_gia_utilizzato"),
            ],
            'phone' => [
				'is_unique'	=>	lang("Platone.phone_gia_utilizzato"),
			],
            'cod_fis' => [
				'is_unique'	=>	lang("Platone.cod_fis_gia_utilizzato"),
			]
		];

		if (! $this->validate($rules,$errors))
		{
			return redirect()->route('register')->withInput()->with('errors', $this->validator->getErrors());
		}

		// Validate passwords since they can only be validated properly here
		$rules = [
			'password'     => ['label' => lang('Platone.password'), 'rules' => 'required|strong_password|regex_match[/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$@!%&*?])[A-Za-z\d#$@!%&*?]{12,30}$/]'],
			'pass_confirm' => ['label' => lang('Platone.pass_confirm'), 'rules' => 'required|matches[password]'],
		];

		if (! $this->validate($rules))
		{
			return redirect()->route('register')->withInput()->with('errors', $this->validator->getErrors());
		}

		// Save the user
		$allowedPostFields = array_merge(['password'], $this->config->validFields, $this->config->personalFields);
		$user = new User($data);

		/*echo "<pre>";
			print_r($user);
		echo "</pre>";
		exit;*/

		/**
		 * La generazione dell'attivazione la faccio dopo che ho ricevuto la conferma SMS tramite OTP
		 * In questo momento devo controllare che sia attivo il servizio di conferma telefono
		 */
		//$this->config->requireActivation === null ? $user->activate() : $user->generateActivateHash();

		if ($this->config->requireSMSOTP !== null) {
			$this->config->requireSMSOTP === null ? '' : $user->generateSMSOTP();
		}  else {
			//in alternativa controllo se devo far partire semplicemente l'attivatore della email
			$this->config->requireActivation === null ? $user->activate() : $user->generateActivateHash();
		}

		// Ensure default group gets assigned if set
        if (! empty($this->config->defaultUserGroup)) {
            $users = $users->withGroup($this->config->defaultUserGroup);
        }

		//controllo che il codice fiscale sia formalmente corretto
		require_once dirname(dirname(__FILE__))."/Libraries/CodiceFiscale.php";

		$cf_validator = new CodiceFiscale;
		if (!$cf_validator->ValidaCodiceFiscale($user->cod_fis)) {
			return redirect()->route('register')->with('error', array("cod_fis" => lang('Platone.codice_fiscale_fornito_non_corretto')));
		}

		//controllo che il codice fiscale sia presente nella tabella degli invitati
		$auc = new AuthGuuidCodfis();
		$check_cf = $auc->where("cod_fis", $user->cod_fis)
		->where("first_name", $user->first_name)
		->where("last_name", $user->last_name)
		->first();

		//controllo che in anagrafica non sia presente un utente che abbia il medesimo codice fiscale altrimenti mando in errore
		$wa = new WebinarAnagrafe();
		$check_wa = $wa->where("cod_fis", $user->cod_fis)->first();

		if ($check_cf) {
			if (!$check_wa) {
					if (! $users->save($user))
				{
					return redirect()->route('register')->withInput()->with('errors', $users->errors());
				} else {
					//utente salvato adesso devo generare relativa anagrafica
					/**
					 * @todo generare anagrafica
					 */
					$webinar_anagrafe = new Webinar();

					$data_anagrafe = array(
						'user_id' => $users->getInsertID(),
						'cod_fis' => $user->cod_fis,
						'cognome' => $user->last_name,
						'nome' => $user->first_name,
						'cellulare' => $user->phone,
						'email' => $user->email,
					);

					if (!$webinar_anagrafe->InsertAnagrafe($data_anagrafe)) {
						return redirect()->route('register')->withInput()->with('errors', $webinar_anagrafe->errors());
					}
				}

				if ($this->config->requireActivation !== null AND $this->config->requireSMSOTP === null)
				{
					$activator = service('activator');



					$sent = $activator->send($user);

					if (! $sent)
					{
						return redirect()->route('register')->withInput()->with('error', $activator->error() ?? lang('Auth.unknownError'));
					}

					// Success!
					return redirect()->route('login')->with('message', lang('Auth.activationSuccess'));
				} elseif ($this->config->requireSMSOTP !== null) {



					if (isset($check_cf['uuid']) AND (!empty($check_cf['uuid']))) {
						return redirect()->to(base_url('uuid_otp/'.$data['username']))->with('message', lang('Platone.activationUuidSuccess'));

					} else {
						$activator = service('activator');

						$sent = $activator->sendOTP($user);

						if (! $sent)
						{
							return redirect()->route('register')->withInput()->with('error', $activator->error() ?? lang('Auth.unknownError'));
						}

						// Success!
						return redirect()->to(base_url('sms_otp/'.$data['username']))->with('message', lang('Platone.activationPhoneSuccess'));
					}

				}

				// Success!
				return redirect()->route('login')->with('message', lang('Auth.registerSuccess'));
			} else {
				return redirect()->route('register')->with('error', lang('Platone.anagrafe_presente_in_db'));
			}
		} else {
			return redirect()->route('register')->with('error', lang('Platone.non_sei_stato_invitato'));
		}
	}

	//--------------------------------------------------------------------
	// Forgot Password
	//--------------------------------------------------------------------

	/**
	 * Displays the forgot password form.
	 */
	public function forgotPassword()
	{
		if ($this->config->activeResetter === null)
		{
			return redirect()->route('login')->with('error', lang('Auth.forgotDisabled'));
		}

		return $this->_render($this->config->views['forgot'], ['config' => $this->config]);
	}

	/**
	 * Attempts to find a user account with that password
	 * and send password reset instructions to them.
	 */
	public function attemptForgot()
	{
		if ($this->config->activeResetter === null)
		{
			return redirect()->route('login')->with('error', lang('Auth.forgotDisabled'));
		}

		if (!$this->googleCaptachStore()) {
			return redirect()->route('forgot')->withInput()->with('error', lang('Platone.errore_google_captcha'));
		}

		$rules = [
			'email' => [
				'label' => lang('Auth.emailAddress'),
				'rules' => 'required|valid_email',
			],
		];

		if (! $this->validate($rules))
		{
			return redirect()->back()->withInput()->with('errors', $this->validator->getErrors());
		}

		$users = model(UserModel::class);

		$user = $users->where('email', $this->request->getPost('email'))->first();

		if (is_null($user))
		{
			return redirect()->back()->with('error', lang('Auth.forgotNoUser'));
		}

		// Save the reset hash /
		$user->generateResetHash();
		$users->save($user);

		$resetter = service('resetter');
		$sent = $resetter->send($user);

		if (! $sent)
		{
			return redirect()->back()->withInput()->with('error', $resetter->error() ?? lang('Auth.unknownError'));
		}

		return redirect()->route('reset-password')->with('message', lang('Auth.forgotEmailSent'));
	}

	/**
	 * Displays the Reset Password form.
	 */
	public function resetPassword()
	{
		if ($this->config->activeResetter === null)
		{
			return redirect()->route('login')->with('error', lang('Auth.forgotDisabled'));
		}

		$token = $this->request->getGet('token');

		$users = model('UserModel');
		$user = $users->where( 'reset_hash', $token )->first();

		return $this->_render($this->config->views['reset'], [
			'config' => $this->config,
			'token'  => $token,
			'email'  => (isset($user->email) && !empty($user->email) ) ? $user->email : '',
		]);
	}

	/**
	 * Verifies the code with the email and saves the new password,
	 * if they all pass validation.
	 *
	 * @return mixed
	 */
	public function attemptReset()
	{
		if ($this->config->activeResetter === null)
		{
			return redirect()->route('login')->with('error', lang('Auth.forgotDisabled'));
		}

		$users = model(UserModel::class);

		//devo recuperare i dati dell'utente
		/*$user_to_reset = $users->where("reset_hash", $this->request->getPost('token'))->first();

		if (!isset($user_to_reset->email)) {
			return redirect()->route('login')->with('error', lang('Platone.utente_non_resettabile'));
		}*/

		// First things first - log the reset attempt.
		$users->logResetAttempt(
			$this->request->getPost('email'),
			//$user_to_reset->email,
			$this->request->getPost('token'),
			$this->request->getIPAddress(),
			(string)$this->request->getUserAgent()
		);

		$rules = [
			'token'		=> 'required',
			'email'		=> 'required|valid_email',
			'password'	 => 'required|strong_password|regex_match[/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$@!%&*?])[A-Za-z\d#$@!%&*?]{12,30}$/]',
			'pass_confirm' => 'required|matches[password]',
		];

		if (! $this->validate($rules))
		{
			return redirect()->back()->withInput()->with('errors', $this->validator->getErrors());
		}

		$user = $users->where('email', $this->request->getPost('email'))
					  ->where('reset_hash', $this->request->getPost('token'))
					  ->first();

		if (is_null($user))
		{
			return redirect()->back()->with('error', lang('Auth.forgotNoUser'));
		}

        // Reset token still valid?
        if (! empty($user->reset_expires) && time() > $user->reset_expires->getTimestamp())
        {
            return redirect()->back()->withInput()->with('error', lang('Auth.resetTokenExpired'));
        }

		// Success! Save the new password, and cleanup the reset hash.
		$user->password 		= $this->request->getPost('password');
		$user->reset_hash 		= null;
		$user->reset_at 		= date('Y-m-d H:i:s');
		$user->reset_expires    = null;
        $user->force_pass_reset = false;
		$users->save($user);

		return redirect()->route('login')->with('message', lang('Auth.resetSuccess'));
	}

	/**
	 * Activate account.
	 *
	 * @return mixed
	 */
	public function activateAccount()
	{
		$users = model(UserModel::class);

		// First things first - log the activation attempt.
		$users->logActivationAttempt(
			$this->request->getGet('token'),
			$this->request->getIPAddress(),
			(string) $this->request->getUserAgent()
		);

		$throttler = service('throttler');

		if ($throttler->check(md5($this->request->getIPAddress()), 2, MINUTE) === false)
        {
			return service('response')->setStatusCode(429)->setBody(lang('Auth.tooManyRequests', [$throttler->getTokentime()]));
        }

		$user = $users->where('activate_hash', $this->request->getGet('token'))
					  ->where('active', 0)
					  ->first();

		if (is_null($user))
		{
			return redirect()->route('login')->with('error', lang('Auth.activationNoUser'));
		}

		$user->activate();

		$users->save($user);

		return redirect()->route('login')->with('message', lang('Auth.registerSuccess'));
	}

	/**
	 * Resend activation account.
	 *
	 * @return mixed
	 */
	public function resendActivateAccount()
	{
		if ($this->config->requireActivation === null)
		{
			return redirect()->route('login');
		}

		$throttler = service('throttler');

		if ($throttler->check(md5($this->request->getIPAddress()), 2, MINUTE) === false)
		{
			return service('response')->setStatusCode(429)->setBody(lang('Auth.tooManyRequests', [$throttler->getTokentime()]));
		}

		$login = urldecode($this->request->getGet('login'));
		$type = filter_var($login, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

		$users = model(UserModel::class);

		$user = $users->where($type, $login)
					  ->where('active', 0)
					  ->first();

		if (is_null($user))
		{
			return redirect()->route('login')->with('error', lang('Auth.activationNoUser'));
		}

		$activator = service('activator');
		$sent = $activator->send($user);

		if (! $sent)
		{
			return redirect()->back()->withInput()->with('error', $activator->error() ?? lang('Auth.unknownError'));
		}

		// Success!
		return redirect()->route('login')->with('message', lang('Auth.activationSuccess'));

	}

	protected function _render(string $view, array $data = [])
	{
		return view($view, $data);
	}

	private function clean($string) {
		$string = str_replace(' ', '-', $string); // Replaces all spaces with hyphens.

		return preg_replace('/[^A-Za-z0-9\-]/', '', $string); // Removes special chars.
	}

	public function sendSMSOTP($username) {
		//recupero i dati dell'iscritto che deve dare conferma del suo numero di cellulare

		$users = model(UserModel::class);

		$data  = $users->where("username", $username)->first();

		$otp = $this->request->getPost('otp');





		if ($data) {

			//controllo se il numero è da attivare e se l'account non è attivo
			if ($data->active == 0 AND $data->phone_active == 0) {
				//carico la vista con la FORM di conferma

				if ($otp) {
					$rules = [
						'otp'		=> 'required',
					];

					if (! $this->validate($rules))
					{
						return redirect()->back()->withInput()->with('errors', $this->validator->getErrors());
					}
				}

				return $this->_render($this->config->views['send_sms_otp'], [
					'config' => $this->config,
					'username' => $username,
					'otp'		=>	$otp,
				]);

			} else {
				return redirect()->route('login')->with('message', lang('Platone.si_prega_di_autenticarsi'));
			}
		} else {
			//reindirizzo alla login utente non trovato
			return redirect()->route('register')->with('message', lang('Platone.si_prega_di_progedere_con_una_registrazione'));
		}
	}

	public function verifySMSOTP($username) {
		//recupero i dati dell'iscritto che deve dare conferma del suo numero di cellulare

		$users = model(UserModel::class);
		$otp = $this->request->getPost('otp', FILTER_SANITIZE_NUMBER_INT);

		$data  = $users->where("username", $username)->where("phone_hash", $otp)->first();

		if ($data) {

			//controllo se il numero è da attivare e se l'account non è attivo
			if ($data->active == 0 AND $data->phone_active == 0) {
				//carico la vista con la FORM di conferma

				if ($otp) {
					$rules = [
						'otp'		=> 'required',
					];

					if (! $this->validate($rules))
					{
						return redirect()->back()->withInput()->with('errors', $this->validator->getErrors());
					}
				}

				//procedo con l'invio della conferma dell'indirizzo email se riesto
				$this->config->requireActivation === null ? $data->activate() : $data->generateActivateHash();

				//aggiorno l'utente settandono con il phone_active = 1
				$user_data = array(
					'phone_active'	=>	1,
					'activate_hash'	=>	$data->activate_hash,
				);

				$users->update($data->id, $user_data);


				if ($this->config->requireActivation !== null)
				{
					$activator = service('activator');

					$sent = $activator->send($data);

					if (! $sent)
					{
						return redirect()->back()->withInput()->with('error', $activator->error() ?? lang('Auth.unknownError'));
					}

					// Success!
					return redirect()->route('login')->with('message', lang('Auth.activationSuccess'));
				} else {
					return redirect()->route('login')->with('message', lang('Auth.registerSuccess'));

				}

			} else {
				return redirect()->route('login')->with('message', array(lang('Platone.si_prega_di_autenticarsi')));
			}
		} else {
            //prima di reinderizzare devo salvare il tentativo andato fallito
            $ip = $this->request->getIPAddress();
            $user = $users->where("username", $username)->first();
            if (isset($user->id)) {
                $sms_otp_attempts = array(
                    'ip_address'    =>  $ip,
                    'user_id'       =>  $user->id,
                    'date'          =>  date("Y-m-d H:i:s", time()),
                    'success'       =>  '0',
                );
                $soa = new AuthUserSmsOtpAttempts();

                $soa->insert($sms_otp_attempts);
            }

            //conto i tentativi sbagliati dell'utente
            $fault = $soa->select("COUNT(id) AS tot")->where("user_id", $user->id)->where("date >=", date("Y-m-d", time()))->first();

            $remain = 5-$fault['tot'];

            if ($remain <= 0) {
                //devo banner l'utente e tornare alla login
                $user->ban(lang('Platone.bannato_per_troppi_tentativi_errati_sms_otp'));
                $users->update($user->id, $user);
                //devo mandare una email all'utente avvisandolo che è stato bannato e devo provare a registrarsi tra due ore.
                $activator = service('activator');
                $sent = $activator->sendEmailRetry($user);
               return redirect()->route('login')->with('error', lang('Platone.bannato_per_troppi_tentativi_errati_sms_otp'));
            } else {
                //reindirizzo alla login utente non trovato
                return redirect()->back()->withInput()->with('errors', array(lang("Platone.error_during_otp_confirm", array($remain))));
            }


		}
	}

	public function sendUUID($username) {
		//recupero i dati dell'iscritto che deve dare conferma del suo numero di cellulare
		$users = model(UserModel::class);
		$data  = $users->where("username", $username)->first();
		$uuid = $this->request->getPost('uuid');
		//controllo che l'utente che sta accedendo a questa schermata abbia realmente un guuid associato
		$agc = model(AuthGuuidCodfis::class);
		$user_uuid =$agc->where("cod_fis", $data->cod_fis)->first();
		if (empty($user_uuid['uuid'])) {
			if ($data->active == 0 AND $data->phone_active == 0) {
				if ($this->config->requireSMSOTP !== null) {
					$activator = service('activator');

					$sent = $activator->sendOTP($data);

					if (! $sent)
					{
						return redirect()->route('register')->withInput()->with('error', $activator->error() ?? lang('Auth.unknownError'));
					}

					// Success!
					return redirect()->to(base_url('sms_otp/'.$data->username))->with('message', lang('Platone.activationPhoneSuccess'));
				} else {
					return redirect()->route('login')->with('message', lang('Platone.si_prega_di_autenticarsi'));
				}
			} else {
				return redirect()->route('login')->with('message', lang('Platone.si_prega_di_autenticarsi'));
			}
		}

		if ($data) {

			//controllo se il numero è da attivare e se l'account non è attivo
			if ($data->active == 0 AND $data->phone_active == 0) {
				//carico la vista con la FORM di conferma

				if ($uuid) {
					$rules = [
						'uuid'		=> 'required',
					];

					if (! $this->validate($rules))
					{
						return redirect()->back()->withInput()->with('errors', $this->validator->getErrors());
					}
				}

				return $this->_render($this->config->views['send_uuid'], [
					'config' => $this->config,
					'username' => $username,
					'uuid'		=>	$uuid,
				]);

			} else {
				return redirect()->route('login')->with('message', lang('Platone.si_prega_di_autenticarsi'));
			}
		} else {
			//reindirizzo alla login utente non trovato
			return redirect()->route('register')->with('message', lang('Platone.si_prega_di_progedere_con_una_registrazione'));
		}
	}

	public function verifyUUID($username) {
		//recupero i dati dell'iscritto che deve dare conferma del suo numero di cellulare
		$users = model(UserModel::class);
		$utente  = $users->where("username", $username)->first();
		$agc = model(AuthGuuidCodfis::class);
		$uuid = $this->request->getPost('uuid', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

		$rules = [
			'uuid'		=> 'required',
		];

		if (! $this->validate($rules))
		{
			return redirect()->back()->withInput()->with('errors', $this->validator->getErrors());
		}

		//echo $uuid;
		//exit;

		$data  = $agc->where("uuid", $uuid)->where("cod_fis", $utente->cod_fis)->first();

		if ($data) {

			/*echo "<pre>";
				print_r($data);
			echo "</pre>";
			exit;*/

			//controllo se il numero è da attivare e se l'account non è attivo
			if (!empty($data['uuid'])) {
				//carico la vista con la FORM di conferma

				$users = model(UserModel::class);
				$user  = $users->where("username", $username)->first();

				//genero un nuovo codice di attivazione solo se realmente necessario
				if (!empty($user->activate_hash)) {
					return redirect()->route('login')->with('message', lang('Auth.activationSuccess'));
				}

				//procedo con l'invio della conferma dell'indirizzo email se riesto
				$this->config->requireActivation === null ? $user->activate() : $user->generateActivateHash();

				//aggiorno l'utente settandono con il phone_active = 1
				$user_data = array(
					'activate_hash'	=>	$user->activate_hash,
                    'phone_active'  =>  '1',
				);

				$users->update($user->id, $user_data);

                //salo anche il tentativo che ha avuto successo
                $ip = $this->request->getIPAddress();
                $uuid_attempts = array(
                    'ip_address'    =>  $ip,
                    'user_id'       =>  $user->id,
                    'date'          =>  date("Y-m-d H:i:s", time()),
                    'success'       =>  '1',
                );
                $uua = new AuthUserUuidAttempts();

                $uua->insert($uuid_attempts);

				if ($this->config->requireActivation !== null)
				{
					$activator = service('activator');

					$sent = $activator->send($user);

					if (! $sent)
					{
						return redirect()->back()->withInput()->with('error', $activator->error() ?? lang('Auth.unknownError'));
					}

					// Success!
					return redirect()->route('login')->with('message', lang('Auth.activationSuccess'));
				} else {
					return redirect()->route('login')->with('message', lang('Auth.registerSuccess'));

				}

			} else {
				return redirect()->route('login')->with('message', array(lang('Platone.si_prega_di_autenticarsi')));
			}
		} else {
            //devo tracciare il tentativo errato
            //prima di reinderizzare devo salvare il tentativo andato fallito
            $ip = $this->request->getIPAddress();
            $user = $users->where("username", $username)->first();
            if (isset($user->id)) {
                $uuid_attempts = array(
                    'ip_address'    =>  $ip,
                    'user_id'       =>  $user->id,
                    'date'          =>  date("Y-m-d H:i:s", time()),
                    'success'       =>  '0',
                );
                $uua = new AuthUserUuidAttempts();

                $uua->insert($uuid_attempts);
            }

            //conto i tentativi sbagliati dell'utente
            $fault = $uua->select("COUNT(id) AS tot")->where("user_id", $user->id)->where("date >=", date("Y-m-d", time()))->first();

            $remain = 5-$fault['tot'];

            if ($remain <= 0) {
                //devo banner l'utente e tornare alla login
                $user->ban(lang('Platone.bannato_per_troppi_tentativi_errati_uuid'));
                $users->update($user->id, $user);
                //devo mandare una email all'utente avvisandolo che è stato bannato e devo provare a registrarsi tra due ore.
                $activator = service('activator');
                $sent = $activator->sendEmailRetryUuid($user);
                return redirect()->route('login')->with('error', lang('Platone.bannato_per_troppi_tentativi_errati_uuid'));
            } else {
                //reindirizzo alla login utente non trovato
                return redirect()->back()->withInput()->with('errors', array("uuid" => lang("Platone.error_during_uuid_confirm", array($remain))));
            }

		}
	}

	private function googleCaptachStore()
    {
        $recaptchaResponse = trim($this->request->getVar('g-recaptcha-response'));


        // form data
        $secret = env('RECAPTCHAV2_SECRET');

        $credential = array(
            'secret' => $secret,
            'response' => $recaptchaResponse
        );

        $verify = curl_init();
        curl_setopt($verify, CURLOPT_URL, "https://www.google.com/recaptcha/api/siteverify");
        curl_setopt($verify, CURLOPT_POST, true);
        curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($credential));
        curl_setopt($verify, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($verify);

        $status = json_decode($response, true);

        if ($status['success']) {
           return true;
        } else {
			return false;
        }
    }

	public function sms_otp_resend($username) {
		//recupero eventuale utente che richiede un nuovo invio di sms
		$users = model(UserModel::class);
		$user  = $users->where("username", $username)->first();

		if (isset($user->phone) and (!empty($user->phone))) {

			//controllo quando è stato l'ultimo invio al numero telefono
			$sms_log = model(Smslogs::class);
			//recupero ultimo invio al numero di telefono dell'utente
			$data_sms_log = $sms_log->where("to", "39 ".$user->phone)->orderBy("id", "DESC")->first();
			//controllo quanto tempo è passato a livello di minuti
			$unixtime_log = strtotime($data_sms_log['updated_at']);
			$unixtime = time();
			$dif = round($unixtime-$unixtime_log)/60;

			if ($dif > 10) {

				//devo generare e aggiornare l'hash altrimenti SMS non arriva
				$user_otp_update = $user->generateSMSOTP();
				$otp = $user_otp_update->phone_hash;
				$user_data = array(
					'phone_hash'	=>	$otp,
				);
				//devo aggiornare l'utente con il nuovo dato che sto per inviare
				$users->update($user->id, $user_data);
				//invio nuovamente SMS
				$sms = new \App\Libraries\Smsapi();
				$message  = lang("Platone.usa_il_codice_per_confermare_telefono").$otp;
				$sms->SendSms($message, "39 ".$user->phone);
				return redirect()->to(base_url('sms_otp/'.$username))->with('message', lang('Platone.sms_nuovamente_inviato'));
			} else {
				return redirect()->to(base_url('sms_otp/'.$username))->with('error', lang('Platone.riprova_piu_tardi'));
			}

		} else {
			return redirect()->to(base_url('sms_otp/'.$username))->with('message', lang('Platone.username_non_esistente'));
		}
	}

	public function sendEmailOTP() {
		//echo $username;
			if ($this->config->allowOTPEmail) {
				$user_id =  $this->session->get("logged_in");
				if ($user_id) {
					$AuthUserOtp = new AuthUserOtp();
					$users = model(UserModel::class);
					$user  = $users->where("id", $user_id)->first();
					$session_id = session_id();

					//controllo se è stato generato già un token OTP
					$email_otp = $AuthUserOtp->where("session_id", $session_id)->where("user_id", $user->id)->first();

					if (!isset($email_otp['otp']))
					{
						//genero OTP
						$user_otp_update = $user->generateSMSOTP();
						$otp = $user_otp_update->phone_hash;
						//salvo OTP nella tabella dedicata
						$data = array(
							'user_id'		=>	$user->id,
							'session_id'	=>	session_id(),
							'otp'			=>	$otp,
							'date'			=>	date("Y-m-d H:i:s", time()),
						);

						if ($AuthUserOtp->save($data)) {
							$activator = service('activator');
							$sent = $activator->sendEmailOTP($user);
							if (!$sent) {
								return redirect()->route('login')->with('message_warning', array(lang('Platone.impossibile_inviare_otp')));
							}
						} else {
							//mando messaggio di errore e torno alla login
							return redirect()->route('login')->with('message_warning', array(lang('Platone.impossibile_salvare_otp_email')));
						}
					} else {
                        $unixtime_log = strtotime($email_otp['date']);
                        $unixtime = time();
                        $dif = round($unixtime-$unixtime_log)/60;
                        if ($dif > 10) {
                            $user->phone_hash = $email_otp['otp'];
                            $activator = service('activator');
                            $sent = $activator->sendEmailOTP($user);
                            if (!$sent) {
                                return redirect()->route('login')->with('message_warning', array(lang('Platone.impossibile_inviare_otp')));
                            }
                        } else {
                            //non mando feedback
                            //$_SESSION["error"] = lang('Platone.riprova_tra_dieci_minuti');
                        }
					}
					return $this->_render($this->config->views['two_step'], [
						'config' => $this->config
					]);
				} else {
					return redirect()->route('login')->with('message', array(lang('Platone.si_prega_di_autenticarsi')));

				}
			} else {
				return redirect()->route('login')->with('message', array(lang('Platone.si_prega_di_autenticarsi')));

			}
	}

	public function verifyEmailOTP() {

		if ($this->config->allowOTPEmail) {
			$user_id =  $this->session->get("logged_in");
			$otp = $this->request->getPost("otp");
			$session_id = session_id();

			$AuthUserOtp = new AuthUserOtp();

			$data = $AuthUserOtp->where("user_id", $user_id)
			->where("otp", $otp)
			->where("session_id", $session_id)->first();

			if ($data)
			{
				$ip = $this->request->getIPAddress();
				//salvo il fatto che il dato era corretto
				$AuthUserOtpAttempts = new AuthUserOtpAttempts();
				$data_attempts = array(
					'ip_address'	=>	$ip,
					'session_id'	=>	$session_id,
					'user_id'		=>	$user_id,
					'date'			=>	date("Y-m-d H:i:s", time()),
					'success'		=>	'1',
				);
				if ($AuthUserOtpAttempts->save($data_attempts)) {
					return redirect()->route('login')->with('message', array(lang('Platone.otp_confermato')));
				} else {
					return redirect()->route('two_step')->with('message_error', array(lang('Platone.impossibie_salvate_otp_attempts')));
				}
			}
			else
			{
                $users = model(UserModel::class);
                $user = $users->where("id", $user_id)->first();
                $ip = $this->request->getIPAddress();
				//salvo il fatto che il dato era corretto
				$AuthUserOtpAttempts = new AuthUserOtpAttempts();
				$data_attempts = array(
					'ip_address'	=>	$ip,
					'session_id'	=>	$session_id,
					'user_id'		=>	$user_id,
					'date'			=>	date("Y-m-d H:i:s", time()),
					'success'		=>	'0',
				);
				if ($AuthUserOtpAttempts->save($data_attempts)) {

                     //conto i tentativi sbagliati dell'utente
                    $fault = $AuthUserOtpAttempts->select("COUNT(id) AS tot")->where("user_id", $user->id)
                    ->where("session_id", $session_id)
                    ->where("date >=", date("Y-m-d", time()))->first();

                    $remain = 5-$fault['tot'];

                    if ($remain <= 0) {
                        //devo banner l'utente e tornare alla login
                        $user->ban(lang('Platone.bannato_per_troppi_tentativi_errati_email_otp'));
                        $users->update($user_id, $user);
                        //foro il logout dell'utente
                        return redirect()->route('logout')->with('error', lang('Platone.bannato_per_troppi_tentativi_errati_email_otp'));
                    } else {
                        return redirect()->back()->withInput()->with('error', array(lang('Platone.si_prega_di_riprovare_email_otp', array($remain))));
                    }

				} else {
					return redirect()->route('two_step')->with('message_error', array(lang('Platone.impossibie_salvate_otp_attempts')));
				}
				//
			}


		} else {
			return redirect()->route('login')->with('message', array(lang('Platone.si_prega_di_autenticarsi')));
		}
	}
}
