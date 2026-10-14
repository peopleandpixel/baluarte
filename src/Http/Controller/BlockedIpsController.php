<?php

namespace Baluarte\Http\Controller;

use Baluarte\Service\CountryIpService;

/**
 * Handles the /blocked-ips endpoint that returns all blocked IPs as plain text.
 */
class BlockedIpsController extends BaseController
{
    public function handle(): void
    {
        try {
            $ips = $this->dbHandler->getActiveBansByType('ip');
        } catch (\Doctrine\DBAL\Exception $e) {
            $ips = [];
        }
        try {
            $ranges = $this->dbHandler->getActiveBansByType('range');
        } catch (\Doctrine\DBAL\Exception $e) {
            $ranges = [];
        }
        try {
            $countries = $this->dbHandler->getActiveBansByType('country');
        } catch (\Doctrine\DBAL\Exception $e) {
            $countries = [];
        }

        $allBlocked = array_merge($ips, $ranges);

        if (!empty($countries)) {
            $countryIpService = new CountryIpService(__DIR__ . '/../../../data/cache/countries');
            foreach ($countries as $countryCode) {
                $countryRanges = $countryIpService->getIpRanges($countryCode);
                $allBlocked = array_merge($allBlocked, $countryRanges);
            }
        }

        header('Content-Type: text/plain');
        echo implode("\n", array_unique($allBlocked));
        exit;
    }
}
