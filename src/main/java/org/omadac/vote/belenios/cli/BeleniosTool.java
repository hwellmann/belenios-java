package org.omadac.vote.belenios.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name = "belenios-tool", mixinStandardHelpOptions = true, version = "1.0.0-SNAPSHOT", description = "election management tool", subcommands = {
    Credgen.class,
    Decrypt.class,
    GenerateToken.class,
    Mkelection.class,
    Mktrustees.class,
    Sha256B64.class,
    TrusteeKeygen.class,
    Validate.class,
    Vote.class
})
public class BeleniosTool {

    public static void main(String... args) {
        int exitCode = new CommandLine(new BeleniosTool()).execute(args);
        System.exit(exitCode);
    }
}