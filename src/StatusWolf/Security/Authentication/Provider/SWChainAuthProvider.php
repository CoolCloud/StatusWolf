<?php
/**
 * This file is part of the StatusWolf package
 *
 * Author: Mark Troyer <disco@box.com>
 * Date Created: 28 February 2014
 *
 */

namespace StatusWolf\Security\Authentication\Provider;

use Silex\Provider\MonologServiceProvider;
use StatusWolf\Security\Authentication\Token\SWChainAuthToken;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Class SWChainAuthProvider
 *
 * Retrieves a user from the User Provider and attempts to authenticate them.
 *
 * @package StatusWolf\Security\Authentication\Provider
 */

class SWChainAuthProvider implements AuthenticationProviderInterface {

    private $_encoder_factory;
    private $_user_provider;
    private $_logger;
    private $_auth_config;
    private $_hide_user_not_found_exceptions;

    /**
     * Constructor
     *
     * @param   UserProviderInterface   $user_provider                  The User Provider
     * @param   string                  $provider_key                   A provider key
     * @param   EncoderFactoryInterface $encoder_factory                Password encoder
     * @param   bool                    $hide_user_not_found_exceptions Whether to hide user not found exception
     * @param   MonologServiceProvider  $logger                         Application logging provider
     * @param   array                   $auth_config                    Authentication config info
     */
    public function __construct(
            UserProviderInterface $user_provider,
            $provider_key,
            EncoderFactoryInterface $encoder_factory,
            $hide_user_not_found_exceptions = true,
            MonologServiceProvider $logger,
            array $auth_config = array()
        ) {

        $this->_user_provider = $user_provider;
        $this->_provider_key = $provider_key;
        $this->_encoder_factory = $encoder_factory;
        $this->_logger = $logger;
        $this->_auth_config = $auth_config;
        $this->_hide_user_not_found_exceptions = $hide_user_not_found_exceptions;

    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token) {
        if (!$this->supports($token)) {
            return null;
        }

        $username = $token->getUsername();
        if (empty($username)) {
            $username = 'NONE_PROVIDED';
        }

        try {
            $user = $this->retrieveUser($username, $token);
        } catch (UsernameNotFoundException $not_found) {
            if ($this->_hide_user_not_found_exceptions) {
                throw new BadCredentialsException('Login failed', 0, $not_found);
            }
            $not_found->setUsername($username);
            throw $not_found;
        }

        $this->_logger->addInfo('Attempting to authenticate user ' . $user->getUsername() . ' to ' . $user->getAuthSource());

        try {
            $this->checkAuthentication($user, $token);
        } catch (BadCredentialsException $e) {
            if ($this->_hide_user_not_found_exceptions) {
                throw new BadCredentialsException('Login failed', 0, $e);
            }
            throw $e;
        }

        $authenticated_token = new SWChainAuthToken($user, $token->getCredentials(), $this->_provider_key, $user->getRoles());
        $authenticated_token->setAttributes($token->getAttributes());

        return $authenticated_token;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token) {
        return $token instanceof SWChainAuthToken;
    }

    /**
     * {@inheritdoc}
     */
    public function checkAuthentication(UserInterface $user, SWChainAuthToken $token)
    {
        $current_user = $token->getUser();
        $auth_source = $user->getAuthSource();
        if ($auth_source === "mysql") {
            if ($current_user instanceof UserInterface) {
                if ($current_user->getPassword() !== $user->getPassword()) {
                    throw new BadCredentialsException('The credentials were changed from another session');
                }
            } else {
                if (($presented_password = $token->getCredentials()) === "") {
                    throw new BadCredentialsException('The presented password cannot be empty');
                }
                if (!$this->_encoder_factory->getEncoder($user)->isPasswordValid($user->getPassword(), $presented_password, $user->getSalt())) {
                    throw new BadCredentialsException('The presented password is invalid.');
                }
            }
        } elseif ($auth_source === "ldap") {
            try {
                $this->_ldap_bind($user->getUsername(), $token->getCredentials());
            } catch (AuthenticationException $e) {
                throw $e;
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function retrieveUser($username, SWChainAuthToken $token) {
        $user = $token->getUser();
        if ($user instanceof UserInterface) {
            return $user;
        }

        try {
            $user = $this->_user_provider->loadUserByUsername($username);
            if (!$user instanceof UserInterface) {
                throw new AuthenticationException('The provided user must be a UserInterface object');
            }
            return $user;
        } catch (UsernameNotFoundException $not_found) {
            $not_found->setUsername($username);
            throw $not_found;
        } catch (\Exception $repository_problem) {
            $e = new AuthenticationException($repository_problem->getMessage(), 0, $repository_problem);
            $e->setToken($token);
            throw $e;
        }
    }

    private function _ldap_bind($username, $password) {
        if ($ldap_server= ldap_connect($this->_server, $this->_port)) {
            try {
                if (ldap_bind($ldap_server, $this->_domain . '\\' . $username, $password)) {
                    return true;
                } else {
                    return false;
                }
            } catch (ContextErrorException $e) {
                throw new AuthenticationException('Unable to bind to LDAP server: ' . $e->getMessage());
            }
        } else {
            throw new AuthenticationException('Connection to LDAP server failed');
        }
    }

}
