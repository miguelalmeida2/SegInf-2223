package S2.Ex6.utils;
public enum SecureRandomAlgorithm {
    NativePRNG,
    NativePRNGBlocking,
    NativePRNGNonBlocking,
    PKCS11,
    SHA1PRNG,
    Windows_PRNG("Windows-PRNG");
    
    String realName = toString();
    
    SecureRandomAlgorithm() {
    
    }
    
    SecureRandomAlgorithm(String realName) {
        this.realName = realName;
    }
    
    @Override
    public String toString() {
        return realName == null ? super.toString() : realName;
    }
}
