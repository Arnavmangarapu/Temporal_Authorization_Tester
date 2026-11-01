<?php
// Native installer creates schema/data first. This CLI-only script supplies
// fixture users/module state; it never changes the REST authorization handler.
define('NOLOGIN', 1);
define('NOCSRFCHECK', 1);
define('NOSESSION', 1);
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
require '/var/www/html/master.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT.'/user/class/user.class.php';
require_once DOL_DOCUMENT_ROOT.'/multicurrency/class/multicurrency.class.php';

function checked($result, $stage) {
    if ($result < 0 || $result === false) {
        // No database details, credentials or upstream debug output in exports.
        fwrite(STDERR, 'bootstrap_failure:'.$stage."\n");
        exit(1);
    }
}

$system = new User($db);
$system->id = 0;
$system->admin = 1;
$user = $system;
$conf->global->USER_MAIL_REQUIRED = 0;
$conf->global->USER_PASSWORD_GENERATED = '';
checked(dolibarr_set_const($db, 'MAIN_VERSION_FIRST_INSTALL', DOL_VERSION, 'chaine', 0, '', 0), 'version_first');
checked(dolibarr_set_const($db, 'MAIN_VERSION_LAST_INSTALL', DOL_VERSION, 'chaine', 0, '', 0), 'version_last');
checked(dolibarr_del_const($db, 'MAIN_NOT_INSTALLED', 0), 'complete_install');
foreach (array('modApi', 'modProduct', 'modCategorie', 'modMultiCurrency') as $module) {
    require_once DOL_DOCUMENT_ROOT.'/core/modules/'.$module.'.class.php';
    $instance = new $module($db);
    checked($instance->init(), $module);
}
// Reload enabled-module flags before creating native users and currency data.
$conf->setValues($db);
$actors = array();
foreach (array('owner', 'allowed', 'restricted') as $role) {
    $actor = new User($db);
    $actor->login = $role;
    $actor->lastname = ucfirst($role);
    $actor->entity = 1;
    $actor->admin = ($role === 'owner') ? 1 : 0;
    $actor->statut = 1;
    $actor->pass = getenv('DOLI_USER_PASSWORD');
    $actor->api_key = getenv('DOLI_KEY_'.strtoupper($role));
    checked($actor->create($system, 1), 'create_'.$role);
    // MultiCurrency grants read by default. Remove defaults, then add only the
    // explicit fixture rights. No groups or external identity provider exist.
    checked($actor->delrights(0, 'allmodules', '', 1, 1), 'clear_rights_'.$role);
    foreach (array(31, 241) as $right) checked($actor->addrights($right, '', '', 1, 1), 'other_read');
    if ($role !== 'restricted') checked($actor->addrights(40001, '', '', 1, 1), 'currency_read');
    $actors[$role] = $actor;
}
$user = $actors['owner'];
$currency = new MultiCurrency($db);
$currency->code = 'XTS';
$currency->name = getenv('DOLI_MARKER');
checked($currency->create($user), 'currency');
checked($currency->addRate(1), 'currency_rate');
$summary = array('currency_id' => (int) $currency->id, 'code' => 'XTS', 'actors' => array());
foreach ($actors as $role => $actor) {
    $copy = new User($db);
    checked($copy->fetch($actor->id), 'fetch_'.$role);
    $copy->getRights();
    $summary['actors'][$role] = array('id' => (int) $copy->id, 'login' => $copy->login,
        'admin' => (int) $copy->admin, 'currency_read' => !empty($copy->rights->multicurrency->currency->read));
}
file_put_contents('/var/www/documents/install.lock', 'fixture');
echo json_encode($summary, JSON_THROW_ON_ERROR)."\n";
