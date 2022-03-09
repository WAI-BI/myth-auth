<?php

/*
 * Myth:Auth routes file.
 */
$routes->group('', ['namespace' => 'Myth\Auth\Controllers'], function ($routes) {
    // Login/out
    $routes->get('login', 'AuthController::login', ['as' => 'login']);
    $routes->post('login', 'AuthController::attemptLogin');
    $routes->get('logout', 'AuthController::logout');

    // Registration
    $routes->get('register', 'AuthController::register', ['as' => 'register']);
    $routes->post('register', 'AuthController::attemptRegister');

    // Activation
    $routes->get('activate-account', 'AuthController::activateAccount', ['as' => 'activate-account']);
    $routes->get('resend-activate-account', 'AuthController::resendActivateAccount', ['as' => 'resend-activate-account']);

    // Forgot/Resets
    $routes->get('forgot', 'AuthController::forgotPassword', ['as' => 'forgot']);
    $routes->post('forgot', 'AuthController::attemptForgot');
    $routes->get('reset-password', 'AuthController::resetPassword', ['as' => 'reset-password']);
    $routes->post('reset-password', 'AuthController::attemptReset');

    //OTP SMS
    //sms_otp
    $routes->get('sms_otp', 'AuthController::sendSMSOTPnosegment');
    $routes->get('sms_otp/(:segment)', 'AuthController::sendSMSOTP/$1');
    $routes->post('sms_otp/(:segment)', 'AuthController::verifySMSOTP/$1');

    //GUID Activation
    //uuid_otp
    $routes->get('uuid_otp/(:segment)', 'AuthController::sendUUID/$1');
    $routes->post('uuid_otp/(:segment)', 'AuthController::verifyUUID/$1');

    //SMS OTP RESEND
    //sms_otp_resend
    $routes->get('sms_otp_resend/(:segment)', 'AuthController::sms_otp_resend/$1');

    //OTP EMAIL LOGIN
    $routes->get('two_step', 'AuthController::sendEmailOTP', ['as' => 'two_step']);
    $routes->post('two_step', 'AuthController::verifyEmailOTP');


});
