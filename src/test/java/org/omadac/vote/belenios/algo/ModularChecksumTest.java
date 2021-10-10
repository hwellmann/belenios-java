package org.omadac.vote.belenios.algo;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;

public class ModularChecksumTest {

    @Test
    public void mod17() throws NoSuchAlgorithmException {
        var checksum = ModularChecksum.checksum("Hello world!", new BigInteger("17"));
        assertThat(checksum).isEqualTo(5);
    }

    @Test
    public void modq() throws NoSuchAlgorithmException {
        var checksum = ModularChecksum.checksum("General Election", Groups.HOMOMORPHIC.q());
        assertThat(checksum)
            .isEqualTo(new BigInteger("21975804506769217954373109906108369112774727951412621094989250905673600375274"));
    }
}
