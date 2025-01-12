from toyecc import getcurvebyname, ECPrivateKey, Tools 


def gen_eddsa_keys():
    curve = getcurvebyname('Ed25519')
    pri_key = ECPrivateKey.eddsa_generate(curve)
    return pri_key.eddsa_encode(), pri_key.pubkey.eddsa_encode()


def gen_kcdsa_keys():
    curve = getcurvebyname('Curve25519')
    pri_key = ECPrivateKey.generate(curve)
    return Tools.inttobytes_le(pri_key.scalar, 32), Tools.inttobytes_le(int(pri_key.pubkey.point.x), 32)


if __name__=='__main__':
    eddsa_pri_key, eddsa_pub_key = gen_eddsa_keys()
    print("Ed25519 -- ( CUSTOM_NPK_SIGN )")
    print(f"Pri Key: {eddsa_pri_key.hex().upper()}")
    print(f"Pub Key: {eddsa_pub_key.hex().upper()}")
    kcdsa_pri_key, kcdsa_pub_key = gen_kcdsa_keys()
    print("Curve25519 -- ( CUSTOM_LICENSE )")
    print(f"Pri Key: {kcdsa_pri_key.hex().upper()}")
    print(f"Pub Key: {kcdsa_pub_key.hex().upper()}")
