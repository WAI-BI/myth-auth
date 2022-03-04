<?php if (session()->has('message')) : ?>
	<div class="alert alert-success">
		<?= session('message') ?>
	</div>
<?php endif ?>

<?php if (session()->has('error')) : ?>
	<div class="alert alert-danger">
		<?php if (is_array(session('error'))) : ?>
			<ul class="alert alert-danger">
				<?php foreach (session('error') as $error) : ?>
					<li><?= $error ?></li>
				<?php endforeach ?>
			</ul>
		<?php else: ?>
			<?=session('error')?>
		<?php endif; ?>
	</div>
<?php endif ?>

<?php if (session()->has('errors')) : ?>
	<ul class="alert alert-danger">
	<?php foreach (session('errors') as $error) : ?>
		<li><?= $error ?></li>
	<?php endforeach ?>
	</ul>
<?php endif ?>
