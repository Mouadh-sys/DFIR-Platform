rule Lab_HTTP_Beacon
{
    meta:
        description = "Lab HTTP beacon (Caldera stand-in), C2 10.10.10.1:8888"
        author = "Student B"
        case = "C01"
        mitre = "T1071.001"
    strings:
        $c2   = "10.10.10.1:8888/beacon" ascii wide
        $ua   = "CalderaAgent/1.0" ascii wide
        $var  = "C2_URL" ascii
        $json = "\"host\"" ascii
    condition:
        $c2 or $ua or 2 of ($var, $json)
}
