package cz.edris.crypto.paillier;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class KeyPairGenerator extends Generator<KeyPair> {

    public KeyPairGenerator() {
        super(KeyPair.class);
    }

    static int bits(SourceOfRandomness s) {
        return (int) Math.pow(2, s.nextInt(8, 13));
    }

    static int certainty(SourceOfRandomness s) {
        return (int) Math.pow(2, s.nextBoolean() ? 32 : 64);
    }

    @Override
    public KeyPair generate(SourceOfRandomness r, GenerationStatus generationStatus) {
        return KeyPair.generate(
                bits(r),
                certainty(r),
                r.nextBoolean());
    }
}
