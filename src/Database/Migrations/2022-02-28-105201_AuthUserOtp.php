<?php

namespace Myth\Auth\Database\Migrations;

use CodeIgniter\Database\Migration;

class AuthUserOtp extends Migration
{
	public function up()
	{
		$this->forge->addField([
            'id'         	=> ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'auto_increment' => true],
            'otp' 			=> ['type' => 'varchar', 'constraint' => 255, 'null' => false],
            'session_id'    => ['type' => 'varchar', 'constraint' => 255, 'null' => false], 
            'user_id'    	=> ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'null' => false], 
            'date'       	=> ['type' => 'datetime'],
        ]);
        $this->forge->addKey('id', true);
        $this->forge->addKey('session_id');
        $this->forge->addKey('user_id');
        // NOTE: Do NOT delete the user_id or email when the user is deleted for security audits
        $this->forge->createTable('auth_user_otp', true);
	}

	public function down()
	{
		//
		$this->forge->dropTable('auth_user_otp', true);

	}
}
