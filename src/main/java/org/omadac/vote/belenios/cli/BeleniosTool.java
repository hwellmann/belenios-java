package org.omadac.vote.belenios.cli;

import io.quarkus.picocli.runtime.annotations.TopCommand;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@TopCommand
@Command(name = "belenios-tool", mixinStandardHelpOptions = true, versionProvider = VersionProvider.class, description = "Election management tool", subcommands = {
    Credgen.class,
    Decrypt.class,
    GenerateToken.class,
    Mkelection.class,
    Mktrustees.class,
    Sha256B64.class,
    TrusteeKeygen.class,
    Validate.class,
    Verify.class,
    VerifyDiff.class,
    Vote.class
})
public class BeleniosTool {

    public static void main(String... args) {
        int exitCode = new CommandLine(new BeleniosTool()).execute(args);
        System.exit(exitCode);
    }
}