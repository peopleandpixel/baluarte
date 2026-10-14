<?php

namespace Baluarte\Http\Controller;

use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\Providers\Qr\GoogleChartsQrCodeProvider;
use RobThree\Auth\TwoFactorAuthException;

/**
 * Handles the bans page.
 */
class BansController extends BaseController
{
    public function handle(): void
    {
        $this->requireAuth();

        try {
            $activeBansDetailed = $this->dbHandler->getActiveBansDetailed(50);
            $activeBansCount = $this->dbHandler->getActiveBansCount();
        } catch (\Doctrine\DBAL\Exception $e) {
            $activeBansDetailed = [];
            $activeBansCount = 0;
        }

        $this->render('bans.latte', [
            'page' => 'bans',
            'activeBansDetailed' => $activeBansDetailed,
            'activeBansCount' => $activeBansCount,
            'countriesList' => $this->countriesList,
            'detectedIps' => '[]',
            'detectedIpsCount' => 0,
            'qrCode' => $this->getQrCode(),
            'twoFactorSecret' => $this->config['gui']['two_factor_secret'] ?? null,
            'ipDetails' => null,
        ]);
    }

    private function getQrCode(): ?string
    {
        $secret = $this->config['gui']['two_factor_secret'] ?? '';
        if (empty($secret)) {
            return null;
        }
        try {
            return (new TwoFactorAuth(new GoogleChartsQrCodeProvider()))
                ->getQRCodeImageAsDataUri('Baluarte', $secret);
        } catch (TwoFactorAuthException $e) {
            return null;
        }
    }
}
