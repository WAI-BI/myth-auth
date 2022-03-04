<?php namespace Myth\Auth\Authentication\Activators;

use Myth\Auth\Entities\User;

class UserActivator extends BaseActivator implements ActivatorInterface
{
	/**
     * Sends activation message to the user via specified class
     * in `$requireActivation` setting in Config\Auth.php.
	 *
	 * @param User $user
	 *
	 * @return bool
	 */
	public function send(User $user = null): bool
	{
		if (! $this->config->requireActivation)
		{
			return true;
		}

		/**
		 * @todo questo controllo fatto in questa maniera non regge
		 * per fare uno switch corretto bisogna controllare se l'utente ha un phone_active su 1 significa in quel caso
		 * che ha confermato il suo numero di telefono
		 * 
		 */
		if ($this->config->requireSMSOTP) {
			$className = $this->config->requireSMSOTP;
		} else {
			$className = $this->config->requireActivation;
		}
		

		$class = new $className();
		$class->setConfig($this->config);

		if ($class->send($user) === false)
		{
            log_message('error', "Failed to send activation message to: {$user->email}");
			$this->error = $class->error();

			return false;
		}

		return true;
	}
}
