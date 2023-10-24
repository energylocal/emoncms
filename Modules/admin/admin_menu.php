<?php
global $session;
if ($session["write"] && $session["admin"]) {
    $menu['setup']['l2']['admin'] = array(
        'name' => _("Admin"),
        'href' => 'admin',
        'default' => 'admin/info',
        'icon' => 'tasks',
        'order' => 13,

        "l3"=>array(
            "info"=>array(
                "name"=>_("System Info"),
                "href"=>"admin/info", 
                "order"=>1, 
                "icon"=>"input"
            ),
            "update"=>array(
                "name"=>_("Update"),
                "href"=>"admin/update", 
                "order"=>1, 
                "icon"=>"input"
            ),
            "components"=>array(
                "name"=>_("Components"),
                "href"=>"admin/components", 
                "order"=>1, 
                "icon"=>"input"
            ),
            "firmware"=>array(
                "name"=>_("Serial Monitor"),
                "href"=>"admin/serial", 
                "order"=>1, 
                "icon"=>"input"
            ),
            "serialconfig"=>array(
                "name"=>_("Serial Config"),
                "href"=>"admin/serconfig", 
                "order"=>1, 
                "icon"=>"input"
            ),
            "log"=>array(
                "name"=>_("Emoncms Log"),
                "href"=>"admin/log", 
                "order"=>1, 
                "icon"=>"input"
            ),
            "users"=>array(
                "name"=>_("Users"),
                "href"=>"admin/users", 
                "order"=>1, 
                "icon"=>"input"
            ),
            "clubs"=>array(
                "name"=>_("Clubs"),
                "href"=>"admin/clubs", 
                "order"=>1, 
                "icon"=>"input"
            )
        )
    );
    $menu["setup"]["l2"]['divider2'] = array(
        "divider"=>"15px",
        "href"=>'',
        "order"=>13
    );
}
