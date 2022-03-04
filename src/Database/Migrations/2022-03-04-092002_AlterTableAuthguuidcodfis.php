<?php

namespace Myth\Auth\Database\Migrations;

use CodeIgniter\Database\Migration;

class AlterTableAuthguuidcodfis extends Migration
{
	public function up()
	{
		$fields = [
            'first_name'          => [
				'type'           => 'VARCHAR',
				'constraint'     => 255,
				'null' 			 => false,
			],
            'last_name'          => [
				'type'           => 'VARCHAR',
				'constraint'     => 255,
				'null' 			 => false,
			],
		];

		$this->forge->addColumn('auth_uuid_codfis', $fields);
	}

	public function down()
	{
        $this->forge->dropColumn('auth_uuid_codfis', 'first_name');
        $this->forge->dropColumn('auth_uuid_codfis', 'last_name');
	}
}
