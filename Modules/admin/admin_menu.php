<?php
    defined('EMONCMS_EXEC') or die('Restricted access');

    $menu['sidebar']['emoncms'][] = array(
        'text' => '',
        'path' => ' ',
        'li_class' => 'divider',
        'icon' => '',
        'order' => 'b'
    );

    global $session;
    if ($session['admin']) {
        $menu['sidebar']['emoncms'][] = array(
            'text' => _("Admin"),
            'path' => 'admin/view',
            'active' => 'admin',
            'icon' => 'tasks',
            'order' => 'b7'
        );
    }
