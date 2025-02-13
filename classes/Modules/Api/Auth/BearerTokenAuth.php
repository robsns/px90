<?php

namespace Xentral\Modules\Api\Auth;

use Xentral\Components\Database\Database;
use Xentral\Components\Http\Request;
use Xentral\Modules\Api\Error\ApiError;
use Xentral\Modules\Api\Exception\AuthorizationErrorException;

class BearerTokenAuth implements AuthInterface 
{
    /** @var Database $db */
    protected $db;

    /** @var Request $request */
    protected $request;

    /** @var bool $isAuthenticated */
    protected $isAuthenticated = false;

    /** @var int|null $apiAccountId */
    protected $apiAccountId;

    public function __construct($db, $request)
    {
        $this->db = $db;
        $this->request = $request;
    }

    public function checkLogin()
    {
        $authHeader = $this->getAuthorizationHeader();
        if (!$authHeader) {
            throw new AuthorizationErrorException(
                'Unauthorized. You need to login.',
                ApiError::CODE_UNAUTHORIZED
            );
        }

        if (stripos($authHeader, 'Bearer ') !== 0) {
            throw new AuthorizationErrorException(
                'Authorization type not allowed.',
                ApiError::CODE_AUTH_TYPE_NOT_ALLOWED
            );
        }

        $token = substr($authHeader, 7);
        if (empty($token)) {
            throw new AuthorizationErrorException(
                'Authorization failure. Token is empty.',
                ApiError::CODE_AUTH_TOKEN_EMPTY
            );
        }

        $apiAccount = $this->db->fetchRow(
            'SELECT id, initkey FROM api_account WHERE aktiv = 1 AND initkey = :token',
            ['token' => $token]
        );

        if (!$apiAccount) {
            throw new AuthorizationErrorException(
                'Authorization failure. Invalid token.',
                ApiError::CODE_API_ACCOUNT_INVALID
            );
        }

        $this->isAuthenticated = true;
        $this->apiAccountId = (int)$apiAccount['id'];
    }

    public function isAuthenticated()
    {
        return $this->isAuthenticated;
    }

    public function getApiAccountId()
    {
        return $this->apiAccountId;
    }

    public function generateAuthenticationString()
    {
        return 'Bearer realm="Xentral-API"';
    }

    protected function getAuthorizationHeader()
    {
        return $this->request->header->get('Authorization');
    }
}
