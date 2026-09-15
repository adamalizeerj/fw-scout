/*
 * fw-scout bundled YARA rules
 *
 * These encode patterns observed during manual firmware research. They are
 * intentionally conservative -- each rule aims for a real weakness class, not a
 * broad string match, to keep the false-positive rate low.
 */

rule hardcoded_ssh_authorized_key
{
    meta:
        description = "Hardcoded SSH public key in an authorized_keys context"
        severity = "medium"
        weakness = "CWE-798"
        detail = "A fixed SSH key shipped in firmware grants access to any holder of the matching private key."
    strings:
        $a = "authorized_keys" ascii
        $k = /ssh-(rsa|ed25519|dss) AAAA[0-9A-Za-z+\/]{40,}/ ascii
    condition:
        $a and $k
}

rule pem_private_key_marker
{
    meta:
        description = "PEM private-key marker present in firmware"
        severity = "low"
        weakness = "CWE-321"
        detail = "A BEGIN PRIVATE KEY marker was found. Structural validation is required before treating this as a real key (fw-scout's secrets analyser does this)."
    strings:
        $pem = /-----BEGIN( RSA| EC| DSA| OPENSSH| ENCRYPTED)? PRIVATE KEY-----/ ascii
    condition:
        $pem
}

rule telnet_debug_enable_interface
{
    meta:
        description = "Debug/telnet-enable interface via /tmp/debug triggers"
        severity = "low"
        weakness = "CWE-489"
        detail = "Firmware ships a telnet/ssh-enable mechanism keyed on /tmp/debug trigger files. Verify whether any unauthenticated network path can create the trigger."
    strings:
        $t1 = "/tmp/debug/pu_telnetEnabled" ascii
        $t2 = "/tmp/debug/pu_sshEnabled" ascii
        $t3 = "telnetEnabled" ascii
    condition:
        any of them
}

rule system_exec_with_format_string
{
    meta:
        description = "Command executed via a format-string-built shell command"
        severity = "medium"
        weakness = "CWE-78"
        detail = "A shell command template with a %s placeholder near a system-action call. If the %s is attacker-controllable, this is command injection. Confirm the data source."
    strings:
        $cmd = /\/bin\/(rm|sh|cp|mv|cat|echo)[^\x00]{0,32}%s/ ascii
        $exec1 = "doSystemAction" ascii
        $exec2 = "system" ascii
        $exec3 = "popen" ascii
    condition:
        $cmd and any of ($exec*)
}

rule aws_access_key_id
{
    meta:
        description = "AWS access key id pattern"
        severity = "high"
        weakness = "CWE-798"
        detail = "An AWS access key id was found embedded in firmware."
    strings:
        $akid = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ ascii
    condition:
        $akid
}

rule unauth_currentsetting_endpoint
{
    meta:
        description = "Unauthenticated router info-disclosure endpoint (currentsetting-style)"
        severity = "low"
        weakness = "CWE-200"
        detail = "An unauthenticated device-info endpoint leaks firmware version/model/region, aiding targeted attacks."
    strings:
        $c = "currentsetting.htm" ascii
        $f = "Firmware=" ascii
    condition:
        all of them
}
