<?php
global $session;
if ($session["admin"]) $menu["setup"]["l2"]['input'] = array("name"=>"Inputs","href"=>"input/view", "order"=>1, "icon"=>"input");
