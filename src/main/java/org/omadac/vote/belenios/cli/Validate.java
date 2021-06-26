package org.omadac.vote.belenios.cli;

import java.util.concurrent.Callable;

import picocli.CommandLine.Command;

@Command(name = "validate", mixinStandardHelpOptions = true, description = "This command reads partial decryptions done by trustees from file "
    + "partial_decryptions.jsons, checks them, combines them into the final "
    + "tally and prints the result to standard output.\n\n"
    + "The result structure contains partial decryptions itself, so "
    + "partial_decryptions.jsons can be discarded afterwards.\n\n")
public class Validate implements Callable<Integer> {

    @Override
    public Integer call() throws Exception {
        return 0;
    }
}
