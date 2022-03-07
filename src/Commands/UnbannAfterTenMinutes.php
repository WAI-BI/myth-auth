<?php namespace Myth\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Myth\Auth\Models\UserModel;

class UnbannAfterTenMinutes extends BaseCommand
{
	/**
	 * The Command's Group
	 *
	 * @var string
	 */
	protected $group = 'Auth';

	/**
	 * The Command's Name
	 *
	 * @var string
	 */
	protected $name = 'auth:UnbanAfterTenminutes';

	/**
	 * The Command's Description
	 *
	 * @var string
	 */
	protected $description = 'Sbanna gli utenti dopo 10 minuti a patto che la loro ragione di BAN sia quella per mancata conferma OTP Email';

	/**
	 * The Command's Usage
	 *
	 * @var string
	 */
	protected $usage = 'auth:UnbanAfterTenminutes';

	/**
	 * The Command's Arguments
	 *
	 * @var array
	 */
	protected $arguments = [];

	/**
	 * The Command's Options
	 *
	 * @var array
	 */
	protected $options = [];

	/**
	 * Actually execute a command.
	 *
	 * @param array $params
	 */
	public function run(array $params)
	{
		//recupero tutti gli utenti bannati per troppi OTP email sbagliati
        $userModel = new UserModel();
        /*$users =$userModel->where("status", "banned")
        ->where("status_message", "Esaurito i tentativi a disposizione per confermare OTP Email")
        ->where("updated_at < (NOW() - INTERVAL 10 MINUTE)")
        ->findAll();*/

		$update      = $userModel->where("status", "banned")
        ->where("status_message", "Esaurito i tentativi a disposizione per confermare OTP Email")
        ->where("updated_at < (NOW() - INTERVAL 10 MINUTE)")
        ->set("status", null)
        ->set("status_message", null)
        ->update();

        if ($update) {
            CLI::write('Total user unBanned: ' . $userModel->db->affectedRows() , 'green');

        } else {
            CLI::write('Unable to unban ', 'red');

        }

	}
}
