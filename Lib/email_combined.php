<?php

/* A simple helper class for email functions

   Compatible with SwiftMailer v5.4.8
   Installation:

   git -C /opt/emoncms/modules clone -b 'v5.4.8' --single-branch https://github.com/swiftmailer/swiftmailer.git

   Copy SMTP settings section from default-settings.ini to settings.ini and ammend as necessary

*/
@include_once '/var/www/emoncms/vendor/autoload.php';
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mailer\Transport;
use Symfony\Component\Mime\Email as SymfonyEmail;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Part\File;

// behaviour switches
$USE_SYMFONY_MAILER = false; // if set to true, symfony will be used instead of swift - swift will no longer be used
$MIRROR_TO_SYMFONY = true; // if set to true, swift will be used to email actual destination, but emails will be mirrored to given address with symfony
$MIRROR_RECIPIENT = 'radley.t.m+symfony@gmail.com'; // recipient for mirror sending

class Email {
    private $log;
    // swift
    private $have_swift;
    private $swift_message;
    private $swift_mailer;

    // symfony
    private $have_symfony;
    private $symfony_message;
    private $symfony_mailer;

    function __construct() {
        global $settings, $linked_modules_dir, $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY;
        $this->log = new EmonLogger(__FILE__);

        // Swift Setup //
        if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
            $this->swift_message = null;
            // include SwiftMailer. path from a PEAR install,
            $this->have_swift = @include_once("swift_required.php");
            // path from module lib
            if (!$this->have_swift) {
                $this->have_swift = @include_once("$linked_modules_dir/swiftmailer/lib/swift_required.php");
            }
            if ($this->have_swift) {
                $this->swift_message = Swift_Message::newInstance();
                
                $from = array();
                $from[$settings['smtp']['from_email']] = $settings['smtp']['from_name'];
                $this->swift_message->setFrom($from);
            }
        }

        // Symfony Setup //
        if ($USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {

            $this->symfony_message = null;
            $this->symfony_mailer = null;
            
            $this->have_symfony = class_exists('Symfony\Component\Mailer\Mailer');
            
            if ($this->have_symfony) {
                $this->symfony_message = new SymfonyEmail();
                
                // Set default from address
                if (isset($settings['smtp']['from_email'])) {
                    $fromName = isset($settings['smtp']['from_name']) ? $settings['smtp']['from_name'] : '';
                    if ($fromName) {
                        $this->symfony_message->from(new Address($settings['smtp']['from_email'], $fromName));
                    } else {
                        $this->symfony_message->from($settings['smtp']['from_email']);
                    }
                }
            }
        }


    }

    function check() {
        global $settings, $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY;
        // if dev mode is enabled, we bypass swiftmailer check
        if ($settings["dev"]) {
            if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->log->error("[DEV] Swiftmailer check attempted and bypassed.");
            }
            if ($USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->log->error("[DEV] Symfony Mailer check attempted and bypassed.");
            }
            return true;
        }
        if (!$USE_SYMFONY_MAILER && !$this->have_swift) {
            $this->log->error("check() Could not find SwiftMailer, email functions are ignored.");
            return false;
        }
        if ($USE_SYMFONY_MAILER && !$this->have_symfony) {
            $this->log->error("check() Could not find Symfony Mailer, email functions are ignored.");
            return false;
        }
        if ($MIRROR_TO_SYMFONY && !$this->have_symfony) {
            $this->log->error("check() Could not find Symfony Mailer, email functions will continue but will not be mirrored via symfony");
        }
        return true;
    }

    function from($from) {
        global $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY;
        if ($this->check()) {
            if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->swift_message->setFrom($from);
            }
            if ($USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->symfony_message->from($from);
            }
        }
    }

    function to($to) {
        // if dev mode is enabled, we replicate the log message without acting
        global $settings, $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY, $MIRROR_RECIPIENT;
        if ($settings["dev"]) {
            $this->log->error("[DEV] Recipient set to: {$to}");
            return;
        }
        if ($this->check()) {
            if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->swift_message->setTo($to);
            }
            if ($MIRROR_TO_SYMFONY) {
                $this->symfony_message->to($MIRROR_RECIPIENT);
            }
            if ($USE_SYMFONY_MAILER) {
                // added ability to supply multiple send to addresses as an array
                // the same is present in cc and bcc
                if (is_array($to)) {
                    $this->symfony_message->to(...$to);
                } else {
                    $this->symfony_message->to($to);
                }
            }
        }
    }
    
    function cc($cc) {
        global $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY, $MIRROR_RECIPIENT;
        if ($this->check()) {
            if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->swift_message->setCc($cc);
            }
            if ($MIRROR_TO_SYMFONY) {
                if (is_array($cc)) {
                    // if $cc is an array, replace each element with 'test+X@email.com'
                    $new_cc = [];
                    $i = 1;
                    foreach ($cc as $entry) {
                        $new_cc[] = preg_replace('/(.+)(@.+)/', "test+{$i}$2", $MIRROR_RECIPIENT);
                        $i++;
                    }
                    $this->symfony_message->cc(...$new_cc);
                } else {
                    $mirror_cc = preg_replace('/(.+)(@.+)/', "test+1$2", $MIRROR_RECIPIENT);
                    $this->symfony_message->cc($mirror_cc);
                }
                
            }
            if ($USE_SYMFONY_MAILER) {
                if (is_array($cc)) {
                    $this->symfony_message->cc(...$cc);
                } else {
                    $this->symfony_message->cc($cc);
                }
            }
        }
    }

    function bcc($bcc) {
        global $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY, $MIRROR_RECIPIENT;
        if ($this->check()) {
            if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->swift_message->setBcc($bcc);
            }
            if ($MIRROR_TO_SYMFONY) {
                if (is_array($bcc)) {
                    // if $bcc is an array, replace each element with 'test+X@email.com'
                    $new_bcc = [];
                    $i = 1;
                    foreach ($bcc as $entry) {
                        $new_bcc[] = preg_replace('/(.+)(@.+)/', "test+{$i}$2", $MIRROR_RECIPIENT);
                        $i++;
                    }
                    $this->symfony_message->bcc(...$new_bcc);
                } else {
                    $mirror_bcc = preg_replace('/(.+)(@.+)/', "test+1$2", $MIRROR_RECIPIENT);
                    $this->symfony_message->bcc($mirror_bcc);
                }
                
            }
            if ($USE_SYMFONY_MAILER) {
                if (is_array($bcc)) {
                    $this->symfony_message->bcc(...$bcc);
                } else {
                    $this->symfony_message->bcc($bcc);
                }
            }
        }
    }

    function subject($subject) {
        // if dev mode is enabled, we replicate the log message without acting
        global $settings, $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY;
        if ($settings["dev"]) {
            $this->log->error("[DEV] Subject set to: {$subject}");
            return;
        }
        if ($this->check()) {
            if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->swift_message->setSubject($subject);
            }
            if ($MIRROR_TO_SYMFONY) {
                $this->symfony_message->subject("[SYMFONY MIRROR] " . $subject);
            }
            if ($USE_SYMFONY_MAILER && !$MIRROR_TO_SYMFONY) {
                $this->symfony_message->subject($subject);
            }
        }
    }

    function body($body, $type = 'text/html') {
        global $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY;
        // if dev mode is enabled, we replicate the log message without acting
        global $settings;
        if ($settings["dev"]) {
            $this->log->error("[DEV] Body set to: {$body}");
            return;
        }
        if ($this->check()) {
            if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->swift_message->setBody($body, $type);
            }
            if ($USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                if ($type === 'text/html') {
                    $this->symfony_message->html($body);
                } else {
                    $this->symfony_message->text($body);
                }
            }
        }
    }

    function attach($filepath, $contentType = null, $filename = null) {
        global $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY;
        if ($this->check()) {
            if (!file_exists($filepath)) {
                $this->log->error("Attachment file not found: $filepath");
                return false;
            }
            if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->swift_message->attach(Swift_Attachment::fromPath($filepath, $contentType));
            }
            if ($USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->symfony_message->addPart(new DataPart(new File($filepath), $filename, $contentType));
            }
        }
    }

    function send() {
        // if dev mode is enabled, we replicate the log message and return without acting
        global $settings, $USE_SYMFONY_MAILER, $MIRROR_TO_SYMFONY;
        if ($settings["dev"]) {
            $this->log->error("[DEV] Email send attempted and bypassed");
            return array('success'=>true, 'message'=>"");
        }
        if ($this->check()) {
            if (!$USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                try {
                    if ($settings['smtp']['sendmail']) {
                        $transport = Swift_SendmailTransport::newInstance('/usr/sbin/sendmail -bs');
                    } else {
                        $transport = Swift_SmtpTransport::newInstance($settings['smtp']['host'], $settings['smtp']['port']);
                        if (isset($settings['smtp']['encryption']) && $settings['smtp']['encryption']) {
                            $transport->setEncryption($settings['smtp']['encryption']);
                        }
                        if (isset($settings['smtp']['username'])) {
                            $transport->setUsername($settings['smtp']['username']);
                        }
                        if (isset($settings['smtp']['password'])) {
                            $transport->setPassword($settings['smtp']['password']);
                        }
                    }
                    $this->swift_mailer = Swift_Mailer::newInstance($transport);
                    $this->swift_mailer->send($this->swift_message);
                } catch (Exception $e) {
                    $$error_msg = "Swift Mailer error: " . $e->getMessage();
                    $this->log->error($error_msg);
                    return array('success'=>false, 'message'=>$error_msg);
                }
            }
            if ($USE_SYMFONY_MAILER || $MIRROR_TO_SYMFONY) {
                $this->log->info("Hitting symfony mirror block");
                try {
                    $this->log->info("Hitting symfony mirror try block");
                    if ($settings['smtp']['sendmail']) {
                        $dsn = 'sendmail://default';
                    } else {
                        $dsn = 'smtp://';
                        
                        if (isset($settings['smtp']['username']) && isset($settings['smtp']['password'])) {
                            $dsn .= urlencode($settings['smtp']['username']) . ':' . urlencode($settings['smtp']['password']) . '@';
                        }
                        
                        $dsn .= $settings['smtp']['host'];
                        
                        if (isset($settings['smtp']['port'])) {
                            $dsn .= ':' . $settings['smtp']['port'];
                        }
                        
                        if (isset($settings['smtp']['encryption']) && $settings['smtp']['encryption']) {
                            $dsn .= '?encryption=' . $settings['smtp']['encryption'];
                        }
                    }
                    
                    $this->log->info("Hitting symfony transport setup block");
                    $transport = Transport::fromDsn($dsn);
                    $this->symfony_mailer = new Mailer($transport);
                    $this->symfony_mailer->send($this->symfony_message);
                    $this->log->info("Symfony email sent");
                    
                } catch (TransportExceptionInterface $e) {
                    $this->log->error($e->getDebug());
                    $error_msg = "Symfony Mailer error: " . $e->getMessage();
                    $this->log->error($error_msg);
                    return array('success'=>false, 'message'=>$error_msg);
                }
            }
            return array('success'=>true, 'message'=>"");
        } else {
            if (!$USE_SYMFONY_MAILER) {
                return array('success'=>false, 'message'=>"Could not find SwiftMailer, email not sent.");
            } else {
                return array('success'=>false, 'message'=>"Could not find Symfony Mailer, email not sent.");

            }

        }
    }
}
