<?php

// make sure we show any error/warning/notice
error_reporting(-1);
ini_set('display_errors', 1);

function sendEmails($emails = []) {

    $ch = curl_init('http://127.0.0.1:8000');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);

    curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);

    // if password is needed:
    // $headers = array('Authorization' => '');
    // curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($emails));

    $body = curl_exec($ch);
    curl_close($ch);

    return (array)json_decode($body, true);
}

$emailsFile = realpath(dirname(__FILE__) . '/../emails.txt');

if (!is_file($emailsFile)) {
    exit("Unable to find the emails.txt file!");
}

if (!($handle = fopen($emailsFile, "r"))) {
    exit("Unable to open the emails.txt file!");
}

$emails = [];
while (($email = fgets($handle)) !== false) {
    $email = trim($email);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        continue;
    }
    $emails[] = $email;
    if (count($emails) >= 10) {
        print_r(sendEmails($emails));
        $emails = [];
    }
}

fclose($handle);

if (!empty($emails)) {
    print_r(sendEmails($emails));
}
