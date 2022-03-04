<?php namespace Myth\Auth\Authentication\Activators;

use Config\Email;
use Myth\Auth\Entities\User;

/**
 * Class PhoneActivator
 *
 * Sends an activation email to user.
 *
 * @package Myth\Auth\Authentication\Activators
 */
class PhoneActivator extends BaseActivator implements ActivatorInterface
{
    /**
     * Sends an activation with SMS on phone
     *
     * @param User $user
     *
     * @return bool
     */
    public function sendOTP(User $user = null): bool
    {

        $sms = new \App\Libraries\Smsapi();

        $settings = $this->getActivatorSettings();

        $sms->SendSms($user->phone_hash, $user->phone);

        return true;
    }

    public function send(User $user = null): bool 
    {
        return true;    
    }
}
