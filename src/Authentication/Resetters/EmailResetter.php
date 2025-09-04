<?php namespace Myth\Auth\Authentication\Resetters;

use Config\Email;
use CodeIgniter\Entity\Entity;
use CodeIgniter\Config\Services;

/**
 * Class EmailResetter
 *
 * Sends a reset password email to user.
 *
 * @package Myth\Auth\Authentication\Resetters
 */
class EmailResetter extends BaseResetter implements ResetterInterface
{
    /**
     * @var string
     */
    protected $error;

    /**
     * Sends a reset email
     *
     * @param User $user
     *
     * @return mixed
     */
    public function send(Entity $user = null): bool
    {
        $email = Services::email();
        $config = new Email();

        $settings = $this->getResetterSettings();

        //Se è stato già stata configurata la libreria carico la configurazione email dal database
        $email_config = new \App\Libraries\EmailConfiguration; 
        
        if ($email_config->initialized()) {
            
            $sent = $email->setFrom($email_config->get_configuration()['fromEmail'], $email_config->get_configuration()['fromName'])
                ->setTo($user->email)
                ->setSubject(lang('Auth.forgotSubject'))
                ->setMessage(view($this->config->views['emailForgot'], ['hash' => $user->reset_hash]))
                ->setMailType('html')
                ->send();
        } else {
            $sent = $email->setFrom($settings->fromEmail ?? $config->fromEmail, $settings->fromName ?? $config->fromName)
                ->setTo($user->email)
                ->setSubject(lang('Auth.forgotSubject'))
                ->setMessage(view($this->config->views['emailForgot'], ['hash' => $user->reset_hash]))
                ->setMailType('html')
                ->send();
        }

       

        if (! $sent)
        {
            $this->error = lang('Auth.errorEmailSent', [$user->email]);
            return false;
        }

        return true;
    }

    /**
     * Returns the error string that should be displayed to the user.
     *
     * @return string
     */
    public function error(): string
    {
        return $this->error ?? '';
    }

}
