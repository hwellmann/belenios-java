package org.omadac.vote.belenios.cli;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.Callable;

import picocli.CommandLine.Command;

@Command(name = "sha256-b64", mixinStandardHelpOptions = true, description = "Computes SHA256 of standard input and encodes it in Base64Compact\n\n")
public class Sha256B64 implements Callable<Integer> {

    @Override
    public Integer call() throws Exception {
        byte[] bytes = System.in.readAllBytes();
        var digest = MessageDigest.getInstance("SHA-256");
        var encodedhash = digest.digest(bytes);
        var hash = Base64.getEncoder().withoutPadding().encodeToString(encodedhash);
        System.out.println(hash);

        return 0;
    }
}