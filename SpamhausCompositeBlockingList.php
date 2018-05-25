<?php

namespace Modules\SpamhausCompositeBlockingList;

use Lightning\Tools\Messages\SpamFilterInterface;

class SpamhausCompositeBlockingList implements SpamFilterInterface {

    /**
     * @param array $message
     *
     * @return int
     *   5 if it was found in the blacklist or 0 if not
     */
    public static function getScore($message) {
        if (!empty($message['IP']) && strpos($message['IP'], '.') !== false) {
            $parts = explode('.', $message['IP']);
            $parts = array_reverse($parts);
            $ip = implode('.', $parts);
            $result = dns_get_record($ip . '.cbl.abuseat.org');
            if (is_array($result)) {
                foreach ($result as $r) {
                    if ($r['ip'] == '127.0.0.2') {
                        return 10;
                    }
                }
            }
        }
        return 0;
    }

    public static function flagAsSpam($message) {
        // At this time, this RBL is read only.
    }

}
