<?php

namespace Xentral\Modules\Api\Auth;

interface AuthInterface
{
    /**
     * Validates the authentication credentials
     * @throws AuthorizationErrorException
     */
    public function checkLogin();

    /**
     * @return bool
     */
    public function isAuthenticated();

    /**
     * @return int|null
     */
    public function getApiAccountId();

    /**
     * @return string
     */
    public function generateAuthenticationString();
}
