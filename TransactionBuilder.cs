public static class Utils                                  // (under development) 
{
    public static string ReverseBytes(string hex)
    {
        var bytes = new List<string>();
        for (int i = 0; i < hex.Length; i += 2) bytes.Add(hex.Substring(i, 2));
        bytes.Reverse();
        return string.Join("", bytes);
    }
    
    public static string DecHex(int dec) => dec.ToString("X");
    
    public static string Field(BigInteger field, int size = 4)
    {
        return field.ToString(16).PadLeft(size * 2, '0');
    }
    
    public static string VarInt(uint i)
    {
        BigInteger bi = new BigInteger(i.ToString());

        if (i <= 252) return Field(bi, 1);
        else if (i <= 65535) return "FD" + Field(bi, 2);
        else if (i <= 4294967295) return "FE" + Field(bi, 4);
        else return "FF" + Field(bi, 8);
    }
    
    public static BigInteger Base58ToInt(string base58Val) => new BigInteger(Base58CheckEncoding.DecodePlain(base58Val));
    
    public static string DecodeBase58(string base58Val)
    {
        byte[] decoded = Base58CheckEncoding.DecodePlain(base58Val);
        string hex = BitConverter.ToString(decoded).Replace("-", "");
        return hex;
    }
    
    public static string PrivateToPublic(string privateKey)
    {
        ECPrivateKeyParameters privateKeyParams = new(new BigInteger(privateKey, 16), GetDomainParameters());
        ECPublicKeyParameters publicKeyParams = new("EC", privateKeyParams.Parameters.G.Multiply(privateKeyParams.D), privateKeyParams.Parameters);

        BigInteger yCoord = publicKeyParams.Q.YCoord.ToBigInteger();
        string publicKey = publicKeyParams.Q.XCoord.ToBigInteger().ToString(16).PadLeft(64, '0');
        string prefix = yCoord.Mod(new BigInteger("2")).Equals(BigInteger.Zero) ? "02" : "03";
        return prefix + publicKey;
    }
    
    public static string Hash256(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < hex.Length; i += 2) bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

        Sha256Digest sha256 = new Sha256Digest();
        byte[] hash1 = new byte[sha256.GetDigestSize()];
        sha256.BlockUpdate(bytes, 0, bytes.Length);
        sha256.DoFinal(hash1, 0);

        byte[] hash2 = new byte[sha256.GetDigestSize()];
        sha256.BlockUpdate(hash1, 0, hash1.Length);
        sha256.DoFinal(hash2, 0);

        return BitConverter.ToString(hash2).Replace("-", "");
    }
    
    private static ECDomainParameters GetDomainParameters()
    {   // Using secp256k1 curve parameters
        X9ECParameters curveParams = SecNamedCurves.GetByName("secp256k1");
        ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);
        return domainParams;
    }
}
