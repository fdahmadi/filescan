/*
 * Detect the standard EICAR antivirus test string.
 * Safe: this is not malware; it is the industry test file content.
 */
rule eicar_test_file : malware
{
    meta:
        description = "EICAR standard antivirus test file"
        severity = "high"
        author = "filescan"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
