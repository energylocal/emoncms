<?php
    global $session;

    $domain = "messages";
    bindtextdomain($domain, "Modules/user/locale");
    bind_textdomain_codeset($domain, 'UTF-8');

    $menu_right[] = array('name'=> dgettext($domain, "My Account"), 'icon'=>'icon-user icon-white', 'path'=>"user/view", 'session'=>"write", 'order' => 40, 'divider' => true);
    $menu_right[] = array('name'=> dgettext($domain, "Logout"), 'icon'=>'icon-off icon-white', 'path'=>"user/logout", 'session'=>"read", 'order' => 1000);
    if (!$session['read']) $menu_right[] = array('name'=>dgettext($domain, "Log In"), 'icon'=>'icon-home icon-white', 'path'=>"?household", 'order' => 1000);
