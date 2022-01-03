rule zip_unix_63
{
    meta:
        author = "tyler.mclellan"
        version = "1.0"
        date = "2022-01-03"
        desc = "detect zips created by unix v6.3"
    strings:
        $header = {504B01023F0314}
    condition:
        uint16be(0) == 0x504B and @header[1] > filesize - 200 and filesize < 200KB
}
