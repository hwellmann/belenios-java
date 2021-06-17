package org.omadac.vote.belenios.algo;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.junit.jupiter.api.Test;

public class ElectionHashTest {

    @Test
    public void computeHash() throws IOException, NoSuchAlgorithmException {
        var bytes = Files.readAllBytes(Paths.get("src/test/resources/election01/election.json"));
        var digest = MessageDigest.getInstance("SHA-256");
        var encodedhash = digest.digest(bytes);
        String hash = Base64.getEncoder().withoutPadding().encodeToString(encodedhash);
        assertThat(hash).isEqualTo("AHHaEkaINgfPZTd1bPpAZ2rigNL3oWFCnlCA4GSh52A");
    }
}
