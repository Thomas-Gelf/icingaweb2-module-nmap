<?php

namespace Icinga\Module\Nmap\ProvidedHook\Director;

use Icinga\Module\Director\Hook\ImportSourceHook;
use Icinga\Module\Director\Web\Form\QuickForm;

class ImportSource extends ImportSourceHook
{
    protected $db;

    public function fetchData()
    {
        $range = $this->getSetting('subnet');
        $requireHost = $this->getSetting('require_hostname', 'y');

        $cmd = sprintf("/usr/bin/nmap -sn %s", escapeshellarg($range));
        $currentIp = $currentMac = $currentHost = null;
        $result = [];
        $output = `$cmd`;

        foreach (preg_split('/\n/', $output) as $line) {
            if (preg_match('/^Nmap scan report for (.+) \((.+)\)/', $line, $m)) {
                if ($currentIp !== null) {
                    $result[] = (object)[
                        'ip' => $currentIp,
                        'mac' => $currentMac,
                        'host' => $currentHost,
                    ];
                }
                $currentIp = $m[2];
                $currentHost = $m[1];
                $currentMac = null;
            } elseif (preg_match('/^Nmap scan report for ([\d\.]+)/', $line, $m)) {
                if ($currentIp !== null) {
                    $result[] = (object)[
                        'ip' => $currentIp,
                        'mac' => $currentMac,
                        'host' => $currentHost,
                    ];
                }
                if ($requireHost === 'y') {
                    $currentMac = null;
                    continue;
                }
                $currentIp = $m[1];
                $currentHost = $m[1];
                $currentMac = null;
            } elseif (preg_match('/^MAC Address: (.+) /', $line, $m)) {
                // Will never happen, this requires root permissions:
                if ($currentMac === null) {
                    $currentMac = $m[1];
                }
            }
        }

        return $result;
    }

    public function listColumns()
    {
        return ['ip', 'host' /*, 'mac' */];
    }

    public static function addSettingsFormFields(QuickForm $form)
    {
        $form->addElement('text', 'subnet', [
            'label'       => $form->translate('Subnet'),
            'description' => $form->translate('CIDR notation: 192.0.2.0/24'),
            'required'    => true,
        ]);
        $form->addElement('select', 'require_hostname', [
            'label'    => $form->translate('Require DNS hostname'),
            'description' => $form->translate('When required, import skips non-resolvable hosts'),
            'required' => true,
            'value'    => 'y',
            'multiOptions' => [
                'y' => $form->translate('Yes'),
                'n' => $form->translate('No'),
            ],
        ]);

        return $form;
    }
}
