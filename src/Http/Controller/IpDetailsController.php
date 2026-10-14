<?php

namespace Baluarte\Http\Controller;

use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\Providers\Qr\GoogleChartsQrCodeProvider;
use RobThree\Auth\TwoFactorAuthException;

/**
 * Handles IP details page.
 */
class IpDetailsController extends BaseController
{
    public function handle(): void
    {
        $this->requireAuth();

        $ip = $_GET['ip'] ?? '';
        $ipDetails = null;
        if ($ip) {
            try {
                $history = $this->dbHandler->getIpHistory($ip);
                $ban = $this->dbHandler->getBanDetails($ip);
                if (!empty($history)) {
                    $ipDetails = [
                        'ip' => $ip,
                        'history' => $history,
                        'ban' => $ban,
                        'last_geo' => $history[0]
                    ];
                }
            } catch (\Exception $e) {
                // Ignore errors
            }
        }

        try {
            $detectedIps = $this->dbHandler->getAllDetectedIps(50);
            $detectedIpsCount = $this->dbHandler->getDetectedIpsCount();
        } catch (\Doctrine\DBAL\Exception $e) {
            $detectedIps = [];
            $detectedIpsCount = 0;
        }
        try {
            $activeBansDetailed = $this->dbHandler->getActiveBansDetailed(50);
            $activeBansCount = $this->dbHandler->getActiveBansCount();
        } catch (\Doctrine\DBAL\Exception $e) {
            $activeBansDetailed = [];
            $activeBansCount = 0;
        }

        $this->render('ip-details.latte', [
            'page' => 'ip-details',
            'ipDetails' => $ipDetails,
            'detectedIps' => json_encode($detectedIps),
            'detectedIpsCount' => $detectedIpsCount,
            'activeBansDetailed' => $activeBansDetailed,
            'activeBansCount' => $activeBansCount,
            'countriesList' => $this->countriesList,
            'qrCode' => $this->getQrCode(),
            'twoFactorSecret' => $this->config['gui']['two_factor_secret'] ?? null,
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
