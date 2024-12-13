<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the website, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'cars_db' );

/** Database username */
define( 'DB_USER', 'root' );

/** Database password */
define( 'DB_PASSWORD', '' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'N,RBn7Mi>>P)Ln392>WL(6W0 Nu=Riax[{]/tr=Huj]_/y23k:]S2y)vBjJMJe*S' );
define( 'SECURE_AUTH_KEY',  '&4MBP==zcS>G2G}G8n6!h~{!ht.j=i|1,xiGuAwk-83p1(h^S;)h=b6Uw?~NxG+3' );
define( 'LOGGED_IN_KEY',    'hK! &8GGJlh[oec!1#T~G+2/-T .<.)|hb0 fg&,$?|pZRxZsf&C-[lg%Cz3FUD/' );
define( 'NONCE_KEY',        ':%:x(]XScUa0 &*zd<!G[l!tfz!N0!y)b`RIye#,CWq)&UI,t6}f6K|x=2Bbpc9}' );
define( 'AUTH_SALT',        'Ciddf=^-@@YiA&g6[qu8{;ijUWx[Z!iyTZ4g%>:yfxtw`vD>|,qw:q#n`Yn8!!Zh' );
define( 'SECURE_AUTH_SALT', '[4WBGnZTLoyYZ3e>_m-)OG#cl(V.@(G(:@xHgL%(4v^!!H^hf<MzG_/sL* a>kM/' );
define( 'LOGGED_IN_SALT',   'C(K$W3^<;Cg6#B*Dhc`?O34O~Nkd})R!wAIK(G^Lg8E_A@-Uc_R GYx-ppP 7@<h' );
define( 'NONCE_SALT',       '&*EV*]7^X@)exJ:$_u5Z[kg&|GHqdz/GEx~e[*%2{Ua|LJ;`:~x|:rNm64F4-^:q' );
define('JWT_AUTH_SECRET_KEY', 'your-top-secret-key');

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 *
 * At the installation time, database tables are created with the specified prefix.
 * Changing this value after WordPress is installed will make your site think
 * it has not been installed.
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/#table-prefix
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/
 */
define( 'WP_DEBUG', false );
define('JWT_AUTH_CORS_ENABLE', true);

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

