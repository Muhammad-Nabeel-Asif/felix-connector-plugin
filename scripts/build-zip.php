<?php
/**
 * Build the merchant-facing plugin ZIP via ZipArchive (no `zip` CLI required).
 *
 * runner.php MUST be included. CI asserts the output.
 *
 * @package FelixConnector
 */

$root = dirname( __DIR__ );
$dist = $root . '/dist';
$zip_path = $dist . '/felix-connector.zip';

$files = array(
	'felix-connector.php',
	'runner.php',
	'uninstall.php',
	'readme.txt',
);

$includes_dir = $root . '/includes';
$include_files = glob( $includes_dir . '/*.php' );
if ( ! $include_files ) {
	fwrite( STDERR, "No includes/*.php files found\n" );
	exit( 1 );
}

if ( ! is_dir( $dist ) && ! mkdir( $dist, 0775, true ) && ! is_dir( $dist ) ) {
	fwrite( STDERR, "Could not create dist/\n" );
	exit( 1 );
}

if ( file_exists( $zip_path ) ) {
	unlink( $zip_path );
}

$za = new ZipArchive();
if ( true !== $za->open( $zip_path, ZipArchive::CREATE ) ) {
	fwrite( STDERR, "Could not create {$zip_path}\n" );
	exit( 1 );
}

$za->addEmptyDir( 'felix-connector' );
$za->addEmptyDir( 'felix-connector/includes' );

foreach ( $files as $rel ) {
	$src = $root . '/' . $rel;
	if ( ! is_readable( $src ) ) {
		fwrite( STDERR, "Missing source file: {$rel}\n" );
		$za->close();
		unlink( $zip_path );
		exit( 1 );
	}
	$za->addFile( $src, 'felix-connector/' . $rel );
}

foreach ( $include_files as $src ) {
	$za->addFile( $src, 'felix-connector/includes/' . basename( $src ) );
}

$za->close();

echo "Built {$zip_path}\n";
exit( 0 );
