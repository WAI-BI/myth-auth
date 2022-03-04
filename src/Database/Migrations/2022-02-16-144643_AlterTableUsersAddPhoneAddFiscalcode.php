<?php

namespace Myth\Auth\Database\Migrations;

use CodeIgniter\Database\Migration;

class AlterTableUsersAddPhoneAddFiscalcode extends Migration
{
	public function up()
	{
		//
		$fields = [
			'phone'          => [
				'type'           => 'VARCHAR',
				'constraint'     => 15,
				'null' 			 => false,
            ],
            'cod_fis'          => [
				'type'           => 'VARCHAR',
				'constraint'     => 255,
				'null' 			 => false,
			],
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
			'phone_hash'    => ['type' => 'varchar', 'constraint' => 255, 'null' => true],
            'phone_active'  => ['type' => 'tinyint', 'constraint' => 1, 'null' => 0, 'default' => 0],

		];

		$this->forge->addColumn('users', $fields);
	}

	public function down()
	{
		//
		$this->forge->dropColumn('users', 'phone');
        $this->forge->dropColumn('users', 'cod_fis');
        $this->forge->dropColumn('users', 'first_name');
        $this->forge->dropColumn('users', 'last_name');
		$this->forge->dropColumn('users', 'phone_hash');
		$this->forge->dropColumn('users', 'phone_active');
	}
}
