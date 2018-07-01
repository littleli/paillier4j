package cz.edris.crypto.paillier;

public final class KeyPair {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    KeyPair(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
