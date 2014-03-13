<?php

/**
 * Main bootstrap and router for StatusWolf
 *
 * Author: Mark Troyer <disco@box.com>
 * Date Create: 27 February 2014
 */

require_once __DIR__ . '/static/constants/Constants.php';
require_once __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;

// Initialize the application object
$sw = new Silex\Application();

// Provider for reading the application config file
$sw->register(new StatusWolf\Config\ConfigReaderServiceProvider());
$sw['sw_config']->read_config_file($sw, __DIR__ . '/../conf/sw_config.json');
$sw['sw_config']->read_config_file($sw, __DIR__ . '/../conf/sw_datasource.json');

// Provider for logging
$log_level = $sw['debug'] ? 'DEBUG' : $sw['sw_config.config']['logging']['level'];
$sw->register(new \Silex\Provider\MonologServiceProvider(), array(
    'monolog.logfile' => __DIR__ . '/log/sw_log.log',
    'monolog.level' => $log_level,
));

$sw['logger']->addDebug(json_encode($sw['sw_config.config']['auth_config']));

// Providers for Authentication functions
$sw->register(new Silex\Provider\FormServiceProvider());
$sw->register(new Silex\Provider\SessionServiceProvider());
$sw->register(new Silex\Provider\SecurityServiceProvider(), array(
     'security.firewalls' => array(
         'login' => array(
             'pattern' => '^/login$',
             'anonymous' => true,
         ),
         'default' => array(
             'pattern' => '^/',
             'swchainauth' => array(
                 'provider' => 'sw_chain',
                 'login_path' => '/login',
                 'check_path' => '/login_check',
                 'post_only' => false,
             ),
             'logout' => array(
                 'logout_path' => '/logout',
             ),
             'anonymous' => true,
             'users' => $sw->share(function() use($sw) {
                 return new \StatusWolf\Security\User\SWUserProvider($sw['db'], $sw['sw_config.config']['auth_config']);
             }),
         ),
     ),
));

// Twig provider for templating, uses the URL Generator
$sw->register(new Silex\Provider\UrlGeneratorServiceProvider());
$sw->register(new Silex\Provider\TwigServiceProvider(), array(
	'twig.path' => __DIR__ . '/templates',
));

// Database access provider
$sw->register(new Silex\Provider\DoctrineServiceProvider(), array(
    'db.options' => $sw['sw_config.config']['db_options'],
));

// Controller service provider
$sw->register(new \Silex\Provider\ServiceControllerServiceProvider());

// Add the User provider to the list
$sw['security.providers'] = array(
    'sw_chain' => array(
        'entity' => array(
            'class' => '\StatusWolf\Security\User\SWUserProvider',
            'property' => 'username',
        ),
    ),
);

/*
 * Create the authentication objects, need to do this to implement an auth
 * method that supports both MySQL and LDAP for auth (at the same time!)
 * It's a floor wax! It's a salad dressing!
 */
$sw['security.authentication_listener.factory.swchainauth'] = $sw->protect(function($name, $options) use($sw) {

    if (!isset($sw['security.authentication.success_handler.' . $name])) {
        $sw['security.authentication.success_handler.' . $name] = $sw['security.authentication.success_handler._proto']($name, $options);
    }
    if (!isset($sw['security.authentication.failure_handler.' . $name])) {
        $sw['security.authentication.failure_handler.' . $name] = $sw['security.authentication.failure_handler._proto']($name, $options);
    }

    if (!isset($sw['security.entry_point.' . $name . '.form'])) {
        $sw['security.entry_point.' . $name . '.form'] = $sw['security.entry_point.form._proto']($name, $options);
    }

    $sw['security.authentication_provider.' . $name . '.swchainauth'] = 'foo';

    $sw['security.authentication_provider.' . $name . '.swchainauth'] = $sw->share(function() use($sw, $name, $options) {
        $provider_class = '\\StatusWolf\\Security\\Authentication\\Provider\\SWChainAuthProvider';
        $sw['logger']->addInfo('Instantiating ' . $provider_class);
        return new $provider_class(
            $sw['security.user_provider.default'],
            $name,
            $sw['security.encoder_factory'],
            $sw['security.hide_user_not_found'],
            $sw['logger'],
            array_merge($sw['sw_config.config']['auth_config'], $options));
    });

    $sw['logger']->addInfo('...And the horse you rode in on');

    $sw['security.authentication_listener.' . $name . '.swchainauth'] = $sw->share(function() use($sw, $name, $options) {
        $listener_class = '\\StatusWolf\\Security\\Firewall\\SWChainAuthListener';
        $sw['logger']->addInfo($listener_class);
        return new $listener_class(
            $sw['security'],
            $sw['security.authentication_manager'],
            isset($sw['security.session_strategy.' . $name]) ? $sw['security.session_strategy.' . $name] : $sw['security.session_strategy'],
            $sw['security.http_utils'],
            $name,
            $sw['security.authentication.success_handler.' . $name],
            $sw['security.authentication.failure_handler.' . $name],
            array_merge($sw['sw_config.config']['auth_config'], $options),
            $sw['logger'],
            $sw['dispatcher'],
            $sw['sw_config.config']['auth_config']['with_csrf'] && isset($sw['form.csrf_provider']) ? $sw['form.csrf_provider'] : null
        );
    });

    return array(
        'security.authentication_provider.' . $name . '.swchainauth',
        'security.authentication_listener.' . $name . '.swchainauth',
        null,
        'pre_auth'
    );
});

// Routes
$sw->get('/', function() use ($sw) {
    return $sw->redirect('/dashboard');
})->bind('home');

// The login form, uses tokens to guard against CSRF attacks
$sw->get('/login', function(Request $request) use($sw) {
	return $sw['twig']->render('login.html', array(
        'error' => $sw['security.last_error']($request),
		'username' => $sw['session']->get('_security.last_username'),
		'baseurl' => $sw['request']->getUriForPath('/'),
        'csrf_token' => $sw['form.csrf_provider']->generateCsrfToken('authenticate'),
        'extra_css' => array('login.css',),
	));
})->bind('login');

// Fake route for validating authentication
$sw->match('/login_check', null)->bind('login_check');

$sw->mount('/dashboard', new \StatusWolf\Controllers\DashboardController());

$sw->mount('/api', new \StatusWolf\Controllers\ApiController());

function get_widgets() {
    $widget_main = WIDGETS;
    $widget_iterator = new \DirectoryIterator($widget_main);
    $widgets = array();
    $widget_list = array();

    foreach ($widget_iterator as $fileinfo) {
        if ($fileinfo->isDot()) { continue; }
        if ($fileinfo->isDir()) {
            $widgets[] = $fileinfo->getFilename();
        }
    }

    foreach ($widgets as $widget_key) {
        $widget_info = file_get_contents($widget_main . DS . $widget_key . DS . $widget_key . '.json');
        $widget_info = implode('', explode("\n", $widget_info));
        $widget_list[$widget_key] = json_decode($widget_info, true);
    }

    return $widget_list;

}

// Go!
$sw->run();
