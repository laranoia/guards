<?php

namespace Laranoia\Guards\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;

class X509 implements \Laranoia\Guards\Contracts\X509
{
    /** @var string */
    protected $name;
    /** @var Request */
    protected $request;
    /** @var UserProvider */
    protected $provider;
    /** @var Authenticatable */
    protected $user;
    /** @var Dispatcher */
    protected $events;

    public function __construct(Dispatcher $events, UserProvider $provider, Request $request)
    {
        $this->events = $events;
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return !$this->check();
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        if ($this->user()) {
            return $this->user()->getAuthIdentifier();
        }
        return null;
    }

    /**
     * Set the current user.
     *
     * @param Authenticatable $user
     * @return $this
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;

        $this->events->dispatch(new Authenticated($this->name, $this->user));

        return $this;
    }


    /**
     * Get the currently authenticated user.
     *
     * @return Authenticatable|null
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $userid = $this->getUserIdentifierFromCertificate();
        if (!empty($userid)) {
            $user = $this->provider->retrieveById($userid);
        }

        if ($user) {
            $this->login($user);
        }

        return $this->user;
    }

    public function validate(array $credentials = [])
    {
        // TODO: Implement validate() method.
    }

    /**
     * Fetch the user from the client-certificate.
     *
     * Can and should be overwritten for the app authentication
     */
    public function getUserIdentifierFromCertificate()
    {
        $certinfo = openssl_x509_parse(rawurldecode($this->request->server('SSL_CLIENT_CERTIFICATE')));

        return $certinfo['subject']['CN'];
    }

    /**
     * Log a user into the application.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    public function login(Authenticatable $user): void
    {
        $this->events->dispatch(new Login($this->name, $user, false));

        $this->setUser($user);
    }
}