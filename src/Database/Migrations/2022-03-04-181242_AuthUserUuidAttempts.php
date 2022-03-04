<?php

namespace Myth\Auth\Database\Migrations;

use CodeIgniter\Database\Migration;

class AuthUserUuidAttempts extends Migration
{
	public function up()
	{
		$this->forge->addField([
            'id'         => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'auto_increment' => true],
            'ip_address' => ['type' => 'varchar', 'constraint' => 255, 'null' => true],
            'user_id'    => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'null' => false],
            'date'       => ['type' => 'datetime'],
            'success'    => ['type' => 'tinyint', 'constraint' => 1],
        ]);
        $this->forge->addKey('id', true);
        $this->forge->addKey('user_id');
        // NOTE: Do NOT delete the user_id or email when the user is deleted for security audits
        $this->forge->createTable('auth_user_uuid_attempts', true);
	}

	public function down()
	{
		//
        $this->forge->dropTable('auth_user_uuid_attempts', true);
	}
}
