<?php
/**
 * Fail CI if the release ZIP is missing files the UI / cron docs reference.
 *
 * Usage: php scripts/assert-zip-contents.php dist/felix-connector.zip
 *
 * @package FelixConnector
 */

$zip_path = $argv[1] ?? ( dirname( __DIR__ ) . '/dist/felix-connector.zip' );

if ( ! is_readable( $zip_path ) ) {
	fwrite( STDERR, "ZIP not found: {$zip_path}\n" );
	exit( 1 );
}

$required = array(
	'felix-connector/felix-connector.php',
	'felix-connector/runner.php',
	'felix-connector/uninstall.php',
	'felix-connector/readme.txt',
	'felix-connector/includes/class-felix-settings.php',
	'felix-connector/includes/class-felix-runner.php',
	'felix-connector/includes/class-felix-pairing.php',
	'felix-connector/includes/class-felix-crypto.php',
	'felix-connector/includes/class-felix-command-handlers.php',
	'felix-connector/includes/class-felix-command-processor.php',
	'felix-connector/includes/class-felix-command-ledger.php',
	'felix-connector/includes/class-felix-rest.php',
);

$za = new ZipArchive();
if ( true !== $za->open( $zip_path ) ) {
	fwrite( STDERR, "Could not open ZIP: {$zip_path}\n" );
	exit( 1 );
}

$names = array();
for ( $i = 0; $i < $za->numFiles; $i++ ) {
	$names[] = $za->getNameIndex( $i );
}

$missing = array();
foreach ( $required as $file ) {
	if ( ! in_array( $file, $names, true ) ) {
		$missing[] = $file;
	}
}

if ( $missing ) {
	fwrite( STDERR, "Release ZIP is missing required files:\n  - " . implode( "\n  - ", $missing ) . "\n" );
	if ( in_array( 'felix-connector/runner.php', $missing, true ) ) {
		fwrite( STDERR, "\nrunner.php MUST ship in the ZIP. Advertising a missing path 404s and breaks DISABLE_WP_CRON fallback.\n" );
	}
	$za->close();
	exit( 1 );
}

$settings = $za->getFromName( 'felix-connector/includes/class-felix-settings.php' );
if ( false === $settings || false === strpos( $settings, 'runner.php' ) ) {
	fwrite( STDERR, "class-felix-settings.php does not reference runner.php — update required_release_files() if the UI changed.\n" );
	$za->close();
	exit( 1 );
}

$za->close();
echo 'ZIP OK: ' . count( $required ) . " required files present (including runner.php)\n";
exit( 0 );
