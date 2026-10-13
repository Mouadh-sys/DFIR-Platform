rule DFIR_Lab_Marker
{
  meta:
    description = "Harmless marker used to verify the DFIR YARA pipeline"
    author = "DFIR Platform Project"
    scope = "synthetic lab only"
  strings:
    $marker = "DFIR_LAB_CANARY_C01"
  condition:
    $marker
}
