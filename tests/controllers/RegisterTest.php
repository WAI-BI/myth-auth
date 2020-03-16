<?php

use ModuleTests\Support\AuthTestCase;
use CodeIgniter\Test\ControllerTester;
use Myth\Auth\Controllers\AuthController;

class RegisterTest extends AuthTestCase
{
    use ControllerTester;

    protected $refresh = true;

    public function setUp(): void
    {
        parent::setUp();

        // Make sure our valiation rules include strong_password
        $vConfig = new \Config\Validation();
        $vConfig->ruleSets[] = \Myth\Auth\Authentication\Passwords\ValidationRules::class;
        \CodeIgniter\Config\Config::injectMock('Validation', $vConfig);

        // Make sure our routes are mapped
        $routes = service('routes');
        $routes->add('login', 'AuthController::login', ['as' => 'login']);
        \Config\Services::injectMock('routes', $routes);
    }

    public function testRegisterDisplaysForm()
    {
        $result = $this->withUri(site_url('register'))
                    ->controller(AuthController::class)
                    ->execute('register');

        $this->assertTrue($result->isOK());
        $result->see('Register', 'h2');
    }

    public function testAttemptRegisterDisabled()
    {
        $config = new \Myth\Auth\Config\Auth();
        $config->allowRegistration = false;
        \CodeIgniter\Config\Config::injectMock('Auth', $config);

        $result = $this->withUri(site_url('register'))
            ->controller(AuthController::class)
            ->execute('attemptRegister');

        $this->assertTrue($result->isRedirect());
        $this->assertEquals(lang('Auth.registerDisabled'), $_SESSION['error']);
    }

    public function testAttemptRegisterValidationErrors()
    {
        $config = new \Myth\Auth\Config\Auth();
        $config->allowRegistration = true;
        \CodeIgniter\Config\Config::injectMock('Auth', $config);

        $result = $this->withUri(site_url('register'))
            ->controller(AuthController::class)
            ->execute('attemptRegister');

        $this->assertTrue($result->isRedirect());
        $this->asserttrue(isset($_SESSION['_ci_validation_errors']));
    }

    public function testAttemptRegisterCreatesUser()
    {
        // Set form input
        $data = [
            'username' => 'Joe Cool',
            'email' => 'jc@example.com',
            'password' => 'xaH96AhjglK',
            'pass_confirm' => 'xaH96AhjglK'
        ];
        $globals = [
            'request' => $data,
            'post' => $data,
        ];

        $request = service('request', null, false);
        $this->setPrivateProperty($request, 'globals', $globals);

        // don't require activation for this...
        $config = config('Auth');
        $config->requireActivation = false;
        \CodeIgniter\Config\Config::injectMock('Auth', $config);

        $result = $this->withUri(site_url('register'))
            ->withRequest($request)
            ->controller(AuthController::class)
            ->execute('attemptRegister');

        $this->assertTrue($result->isRedirect());
        $this->assertEquals(lang('Auth.registerSuccess'), $_SESSION['message']);
    }
}