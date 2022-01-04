rule zip_encrypted_single_file
{
    meta:
        author = "tyler.mclellan"
        version = "1.0"
        date = "2021-03-03"
        desc = "detect encrypted zip with a single file under 200kb"
    strings:
        $header = {504B0304}
    condition:
        uint16be(0) == 0x504B and uint16(6) & 0x1 == 0x1 and #header == 1 and filesize < 200KB
}
