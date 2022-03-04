<?php

namespace Myth\Auth\Database\Migrations;

use CodeIgniter\Database\Migration;

class AuthGuuidCodfis extends Migration
{
	public function up()
	{
		//
		$this->forge->addField([
			'uuid'      => ['type' => 'varchar', 'constraint' => 255],
            'cod_fis'   => ['type' => 'varchar', 'constraint' => 255],
        ]);

        $this->forge->addUniqueKey('id_soggetto');
        $this->forge->addUniqueKey('cod_fis');

        $this->forge->createTable('auth_uuid_codfis', true);
	}

	public function down()
	{
		//
		$this->forge->dropTable('auth_uuid_codfis', true);

	}
}
