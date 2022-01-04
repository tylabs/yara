rule zip_encrypted
{
    meta:
        author = "tyler.mclellan"
        version = "1.0"
        date = "2021-02-26"
        desc = "detect encrypted zip"

    condition:
        uint16be(0) == 0x504B and uint16(6) & 0x1 == 0x1
}
