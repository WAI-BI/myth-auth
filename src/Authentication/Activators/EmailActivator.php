<?php namespace Myth\Auth\Authentication\Activators;

use Config\Email;
use Myth\Auth\Entities\User;

/**
 * Class EmailActivator
 *
 * Sends an activation email to user.
 *
 * @package Myth\Auth\Authentication\Activators
 */
class EmailActivator extends BaseActivator implements ActivatorInterface
{
    /**
     * Sends an activation email
     *
     * @param User $user
     *
     * @return bool
     */
    public function send(User $user = null): bool
    {

        $email = service('email');
        $config = new Email();

        $settings = $this->getActivatorSettings();

        $sent = $email->setFrom($settings->fromEmail ?? $config->fromEmail, $settings->fromName ?? $config->fromName)
              ->setTo($user->email)
              ->setSubject(lang('Auth.activationSubject'))
              ->setMessage(view($this->config->views['emailActivation'], ['hash' => $user->activate_hash]))
              ->setMailType('html')
              ->send();

        if (! $sent)
        {
            $this->error = lang('Auth.errorSendingActivation', [$user->email]);
            return false;
        }

        return true;
    }

    /**
     * Sends an activation with SMS on phone
     *
     * @param User $user
     *
     * @return bool
     */
    public function sendOTP(User $user = null): bool
    {

        /**
         * Può essere necessario fare un controllo approfondito sulla formazione del numero di cellulare
         * che in fase di inserimento non deve contenere il prefisso.
         */

        $sms = new \App\Libraries\Smsapi();

        $message  = lang("Platone.usa_il_codice_per_confermare_telefono").$user->phone_hash;
        $sms->SendSms($message, "39 ".$user->phone);

        return true;
    }

    public function sendEmailOTP(User $user = null): bool
    {

        $email = service('email');
        $config = new Email();

        $settings = $this->getActivatorSettings();

        $sent = $email->setFrom($settings->fromEmail ?? $config->fromEmail, $settings->fromName ?? $config->fromName)
              ->setTo($user->email)
              ->setSubject(lang('Platone.EmailOtpSubject'))
              ->setMessage(view($this->config->views['emailOTP'], ['hash' => $user->phone_hash]))
              ->setMailType('html')
              ->send();

        if (! $sent)
        {

            $this->error = lang('Platone.errorSendingemailOTP', [$user->email]);
            return false;
        }

        return true;
    }

    public function sendEmailRetry(User $user = null): bool
    {
        $email = service('email');
        $config = new Email();

        $settings = $this->getActivatorSettings();

        $sent = $email->setFrom($settings->fromEmail ?? $config->fromEmail, $settings->fromName ?? $config->fromName)
              ->setTo($user->email)
              ->setSubject(lang('Platone.EmailBanSubjectSMSOTP'))
              ->setMessage(view($this->config->views['EmailBannedSMSOTP']))
              ->setMailType('html')
              ->send();

        if (! $sent)
        {

            $this->error = lang('Platone.errorSendingemailOTP', [$user->email]);
            return false;
        }

        return true;

    }
}
