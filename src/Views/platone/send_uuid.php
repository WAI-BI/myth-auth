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

                <p><?=lang('Platone.inserisci_codice_uuid')?></p>

                

                <form class="user" action="<?php echo base_url("/uuid_otp/".$username); ?>" method="POST">
                    <?= csrf_field() ?>

                    <div class="form-group">
                            <label for="uuid"><?=lang('Platone.uuid')?></label>
                            <input type="text" class="form-control form-control-user <?php if(session('errors.uuid')) : ?>is-invalid<?php endif ?>"
                                   name="uuid" placeholder="<?=lang('Platone.uuid')?>" value="<?= old('uuid', $uuid ?? '') ?>">
                            <div class="invalid-feedback">
                                <?= session('errors.uuid') ?>
                            </div>
                        </div>


                        <br>

                        <button type="submit" class="btn btn-primary btn-block"><?=lang('Platone.invita_uuid')?></button>
                 
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