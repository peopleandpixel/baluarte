<?php

namespace Baluarte\Http\Controller;

use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\Providers\Qr\GoogleChartsQrCodeProvider;

/**
 * Handles login and authentication.
 */
class LoginController extends BaseController
{
    public function handle(): void
    {
        $passwordHash = $this->config['gui']['password_hash'] ?? '';
        $twoFactorEnabled = $this->config['gui']['two_factor_enabled'] ?? false;
        $twoFactorSecret = $this->config['gui']['two_factor_secret'] ?? '';

        // If no password is set, allow access
        if (empty($passwordHash)) {
            $this->redirect('/');
        }

        // If already authenticated, redirect to dashboard
        if ($this->isAuthenticated()) {
            $this->redirect('/');
        }

        $error = null;
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // Rate limiting check
            if ($this->rateLimiter->isRateLimited($this->clientIp)) {
                $error = 'login.error.rate_limited';
            } else {
                $password = $_POST['password'] ?? '';
                $code = $_POST['two_factor_code'] ?? '';

                if (password_verify($password, $passwordHash)) {
                    if ($twoFactorEnabled && !empty($twoFactorSecret)) {
                        $tfa = new TwoFactorAuth(new GoogleChartsQrCodeProvider());
                        if ($tfa->verifyCode($twoFactorSecret, $code)) {
                            $_SESSION['authenticated'] = true;
                            $this->redirect('/');
                        } else {
                            $error = 'login.error.2fa';
                        }
                    } else {
                        $_SESSION['authenticated'] = true;
                        $this->redirect('/');
                    }
                } else {
                    $error = 'login.error.password';
                }
            }
        }

        $this->render('login.latte', [
            'twoFactorEnabled' => $twoFactorEnabled,
            'error' => $error,
        ]);
    }
}
