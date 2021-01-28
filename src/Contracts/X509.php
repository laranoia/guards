<?php

namespace Laranoia\Guards\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

interface X509 extends Guard {

    /**
     * Fetch the user from the client-certificate.
     *
     * Can and should be overwritten for the app authentication
     */
    function getUserIdentifierFromCertificate();

    /**
     * Login the given user
     *
     * @param Authenticatable $user
     * @return mixed
     */
    function login(Authenticatable $user): void;
}
