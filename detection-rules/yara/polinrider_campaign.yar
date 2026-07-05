import "hash"

rule PolinRider_Campaign_Malicious_Hashes
{
    meta:
        description = "Detects specific SHA256 hashes from North Korean PolinRider campaign targeting developers via malicious open-source packages"
        threat_actor = "North Korea (Contagious Interview)"
        reference = "2026 Developer Target Supply Chain Attack Incident"

    condition:
        hash.sha256(0, filesize) == "09a508e99b905330a3ebb7682c0dd5712e8eaa01a154b45a861ca12b6af29f86" or
        hash.sha256(0, filesize) == "0ce264819c7af1c485878ce795fd4727952157af7ffdea5f78bfd5b9d7806db1" or
        hash.sha256(0, filesize) == "104926c2c937b4597ea3493bccb7683ae812ef3c62c93a8fb008cfd64e05df59"
}
