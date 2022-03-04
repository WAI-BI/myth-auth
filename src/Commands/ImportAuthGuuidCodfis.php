<?php

namespace Myth\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Myth\Auth\Entities\User;
use Myth\Auth\Models\UserModel;
use Myth\Auth\Models\AuthGuuidCodfis;


class ImportAuthGuuidCodfis extends BaseCommand
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
	protected $name = 'auth:import_uuid_codfis';

	/**
	 * The Command's Description
	 *
	 * @var string
	 */
	protected $description = 'Importa tutte le associazioni tra uuid e codfis dentro un file CSV fornito dal cliente e che sarà poi utilizzando in fase di registrazione come raffronto';

	/**
	 * The Command's Usage
	 *
	 * @var string
	 */
	protected $usage = 'auth:import_uuid_codfis';

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
		//

		if (file_exists(WRITEPATH . 'uploads/oam_eventi.csv')) {
			$csv_data = array_map(function($v){return str_getcsv($v, ";");}, file(WRITEPATH . 'uploads/oam_eventi.csv'));
			//$csv = array_map('str_getcsv', file(WRITEPATH . 'uploads/oam_eventi.csv'), [";"]);

			if (count($csv_data) > 0) {
				$authuuid = new AuthGuuidCodfis();
	
				foreach ($csv_data as $data) {
	
					print_r($data, true);
	
					if (isset($data[0])) {
	
						$check = $authuuid->where("cod_fis", $data[0])->first();
						//print_r($check);
						//exit;

						if (!$check) {
							//controllo se è stato inserito o meno a d
							$data_uuid[] = array(
								"uuid" => $data[1],
								"cod_fis" => $data[0],
								"last_name" => $data[2],
								"first_name" => $data[3],
							);
						}
					}
				}

				if (isset($data_uuid)) 
				{
					if ($authuuid->insertBatch($data_uuid)) {
						CLI::write(lang('Platone.dati_importati'), 'green');
					} else {
						CLI::write(lang("Platone.impossibile_salvare_a_db_i_dati"), 'red');
					}
				} else 
				{
					CLI::write(lang("Platone.nessun_nuovo_dato_da_importare"), 'red');
				}
				
			} else {
				CLI::write(lang("Platone.file_non_corretto")." ".WRITEPATH."/uploads/oam_eventi.csv", 'red');
			}
		} else {
			CLI::write(lang("Platone.file_non_presente")." ".WRITEPATH."/uploads/oam_eventi.csv", 'red');

		}
		
	}
}
