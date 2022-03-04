<?php require_once dirname(dirname(dirname(dirname(dirname(dirname(dirname(__FILE__)))))))."/app/Views/header.php"; ?>

<div class="container">

  <!-- Outer Row -->
  <div class="row justify-content-center">

    <div class="col-xl-10 col-lg-12 col-md-9">

      <div class="card o-hidden border-0 shadow-lg my-5">
        <div class="card-body p-0">
          <!-- Nested Row within Card Body -->
          <div class="row">
            <div class="col-lg-6 d-none d-lg-block bg-login-image"></div>
            <div class="col-lg-6">
              <div class="p-5">
                <div class="text-center">
                  <h1 class="h4 text-gray-900 mb-4"><?=lang('YB.site_title')?></h1>
                </div>

                <?= view('Myth\Auth\Views\_message_block') ?>

                <p><?=lang('Platone.inserisci_codice_otp_email')?></p>

                

                <form class="user" action="<?php echo base_url("/two_step/"); ?>" method="POST">
                    <?= csrf_field() ?>

                    <div class="form-group">
                            <label for="otp"><?=lang('Platone.otp')?></label>
                            <input type="number" min="10000" max="99999" class="form-control form-control-user <?php if(session('errors.otp')) : ?>is-invalid<?php endif ?>"
                                   name="otp" placeholder="<?=lang('Platone.otp')?>" value="<?= old('otp', $otp ?? '') ?>">
                            <div class="invalid-feedback">
                                <?= session('errors.otp') ?>
                            </div>
                        </div>


                        <br>

                        <button type="submit" class="btn btn-primary btn-block"><?=lang('Platone.invita_otp')?></button>
                        <?php if ($config->allowOTPEmail !== null) : ?>
                          <p><a href="<?=base_url('two_step')?>"><?=lang('Platone.non_hai_ricevuto_email_otp')?></a></p>
                        <?php endif; ?>
                </form>
               
              </div>
            </div>
          </div>
        </div>
      </div>

    </div>

  </div>


<?php require_once dirname(dirname(dirname(dirname(dirname(dirname(dirname(__FILE__)))))))."/app/Views/footer.php"; ?>

<style>
footer.sticky-footer {
    
    position: absolute;
    bottom: 0;
    width: 100%;
}
</style>