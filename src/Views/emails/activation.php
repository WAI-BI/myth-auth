<!-- <p><?=lang("Platone.ricevi_questa_email_di_attivazione")?></p>

<p><?=lang("Platone.per_attivare_il_tuo_account")?></p>

<p><a href="<?=base_url('activate-account') . '?token=' . $hash ?>"><?=lang("Platone.attiva_account")?></a>.</p>

<hr />

<p><?=lang("Platone.se_non_hai_richiesto_account")?></p> -->

<p>
    Gentile utente,<br>
</p>

<p>Per attivare l’account che ti servirà per partecipare ai corsi in piattaforma devi cliccare sul link sottostante:</p>

<p><a href="<?= site_url('reset-password') . '?token=' . $hash ?>">Attiva account</a>.</p>

<br>

<p>Una volta che l’account sarà stato confermato, potrai accedere alla piattaforma per partecipare ai Corsi</p>

<!--<p>Al tuo primo accesso ti sarà richiesto di modificare la tua password provvisoria che al momento è: <strong>classZoomPass</strong></p>-->