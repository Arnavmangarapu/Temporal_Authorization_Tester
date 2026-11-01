<?php
// Disposable fixture configuration; application authorization code is upstream.
$dolibarr_main_url_root = 'http://localhost';
$dolibarr_main_document_root = '/var/www/html';
$dolibarr_main_data_root = '/var/www/documents';
$dolibarr_main_db_host = 'database';
$dolibarr_main_db_port = '3306';
$dolibarr_main_db_name = 'dolibarr';
$dolibarr_main_db_user = 'dolibarr';
$dolibarr_main_db_pass = getenv('DOLI_DB_PASSWORD');
$dolibarr_main_db_type = 'mysqli';
$dolibarr_main_db_prefix = 'llx_';
$dolibarr_main_db_character_set = 'utf8';
$dolibarr_main_db_collation = 'utf8_unicode_ci';
$dolibarr_main_authentication = 'dolibarr';
$dolibarr_main_prod = 1;
$dolibarr_main_instance_unique_id = getenv('DOLI_INSTANCE_ID');
$dolibarr_main_distrib = 'standard';
