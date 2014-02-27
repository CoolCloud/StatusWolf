<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;

$sw = new Silex\Application();

$sw->register(new StatusWolf\Config\ConfigServiceProvider(__DIR__ . '/../conf/sw_config.json'));

$sw->register(new Silex\Provider\UrlGeneratorServiceProvider());
$sw->register(new Silex\Provider\SessionServiceProvider());
$sw->register(new Silex\Provider\SecurityServiceProvider());
$sw->register(new Silex\Provider\TwigServiceProvider(), array(
	'twig.path' => __DIR__ . '/views',
));

$sw['session.test'] = true;

$sw['security.firewalls'] = array(
    'default' => array(
        'pattern' => '^/',
        'anonymous' => true,
        'form' => array(
            'login_path' => '/login',
            'check_path' => '/login_check',
        ),
        'users' => array(
            'disco' => array('ROLE_ADMIN', 'foo'),
        ),
    ),
);

$sw->get('/', function() use ($sw) {
    return print_r($sw['db']);
});

$sw->get('/login', function(Request $request) use ($sw) {
	return $sw['twig']->render('login.html', array(
        'error' => $sw['security.last_error']($request),
		'username' => $sw['session']->get('_security.last_username'),
		'baseurl' => $sw['request']->getUriForPath('/'),
        'extra_css' => array('login.css',),
	));
});

$sw->run();
