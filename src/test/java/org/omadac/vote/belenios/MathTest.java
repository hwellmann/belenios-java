package org.omadac.vote.belenios;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import ch.openchvote.util.math.Mod;

public class MathTest {

    @Test
    public void foo() {
        BigInteger result = Mod.pow(BigInteger.valueOf(3), BigInteger.valueOf(2), BigInteger.valueOf(100));
        System.out.println(result);
    }
}
