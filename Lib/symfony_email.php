<?php

/* A simple helper class for email functions

   Compatible with Symfony Mailer
   Installation:

   composer require symfony/mailer

   Copy SMTP settings section from default-settings.ini to settings.ini and amend as necessary

*/
@include_once '/var/www/emoncms/vendor/autoload.php';
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mailer\Transport;
use Symfony\Component\Mime\Email as SymfonyEmail;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\Part\File;

class Email
{
    private $log;
    private $have_symfony;
    private $message;
    private $mailer;

    function __construct()
    {
        global $settings;
        $this->log = new EmonLogger(__FILE__);

        $this->message = null;
        $this->mailer = null;
        
        $this->have_symfony = class_exists('Symfony\Component\Mailer\Mailer');
        
        if ($this->have_symfony) {
            $this->message = new SymfonyEmail();
            
            // Set default from address
            if (isset($settings['smtp']['from_email'])) {
                $fromName = isset($settings['smtp']['from_name']) ? $settings['smtp']['from_name'] : '';
                if ($fromName) {
                    $this->message->from(new Address($settings['smtp']['from_email'], $fromName));
                } else {
                    $this->message->from($settings['smtp']['from_email']);
                }
            }
        }
    }

    function check()
    {
        global $settings;
        // if dev mode is enabled, we bypass mailer check
        if ($settings["dev"]) {
            $this->log->error("[DEV] Symfony Mailer check attempted and bypassed.");
            return true;
        }
        if (!$this->have_symfony) {
            $this->log->error("check() Could not find Symfony Mailer, email functions are ignored.");
            return false;
        }
        return true;
    }

    function from($from)
    {
        if ($this->check()) {
            $this->message->from($from);
        }
    }

    function to($to)
    {
        // if dev mode is enabled, we replicate the log message without acting
        global $settings;
        if ($settings["dev"]) {
            $this->log->error("[DEV] Recipient set to: {$to}");
            return;
        }
        if ($this->check()) {
            // Support for multiple recipients as an array
            if (is_array($to)) {
                $this->message->to(...$to);
            } else {
                $this->message->to($to);
            }
        }
    }
    
    function cc($cc)
    {
        if ($this->check()) {
            if (is_array($cc)) {
                $this->message->cc(...$cc);
            } else {
                $this->message->cc($cc);
            }
        }
    }

    function bcc($bcc)
    {
        if ($this->check()) {
            if (is_array($bcc)) {
                $this->message->bcc(...$bcc);
            } else {
                $this->message->bcc($bcc);
            }
        }
    }

    function subject($subject)
    {
        // if dev mode is enabled, we replicate the log message without acting
        global $settings;
        if ($settings["dev"]) {
            $this->log->error("[DEV] Subject set to: {$subject}");
            return;
        }
        if ($this->check()) {
            $this->message->subject($subject);
        }
    }

    function body($body, $type = 'text/html')
    {
        // if dev mode is enabled, we replicate the log message without acting
        global $settings;
        if ($settings["dev"]) {
            $this->log->error("[DEV] Body set to: {$body}");
            return;
        }
        if ($this->check()) {
            if ($type === 'text/html') {
                $this->message->html($body);
            } else {
                $this->message->text($body);
            }
        }
    }

    function attach($filepath, $contentType = null)
    {
        if ($this->check()) {
            if (!file_exists($filepath)) {
                $this->log->error("Attachment file not found: $filepath");
                return false;
            }
            $this->message->addPart(new DataPart(new File($filepath), $filename, $contentType));
        }
    }

    function send()
    {
        // if dev mode is enabled, we replicate the log message and return without acting
        global $settings;
        if ($settings["dev"]) {
            $this->log->error("[DEV] Email send attempted and bypassed");
            return array('success'=>true, 'message'=>"");
        }
        
        if ($this->check()) {
            try {
                // Build DSN for transport
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
                
                $transport = Transport::fromDsn($dsn);
                $this->mailer = new Mailer($transport);
                $this->mailer->send($this->message);
                
                return array('success'=>true, 'message'=>"");
                
            } catch (Exception $e) {
                $error_msg = "Symfony Mailer error: " . $e->getMessage();
                $this->log->error($error_msg);
                return array('success'=>false, 'message'=>$error_msg);
            }
        } else {
            return array('success'=>false, 'message'=>"Could not find Symfony Mailer, email not sent.");
        }
    }
}