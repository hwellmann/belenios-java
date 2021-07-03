package org.omadac.vote.belenios.cli;

import java.util.concurrent.Callable;

import org.omadac.vote.belenios.algo.GenCredentials;

import picocli.CommandLine.Command;
import picocli.CommandLine.Help.Visibility;
import picocli.CommandLine.Option;

@Command(name = "generate-token", mixinStandardHelpOptions = true, description = "Generates a random token suitable for an election identifier.\n\n")
public class GenerateToken implements Callable<Integer> {

    @Option(names = {"-l",
        "--length"}, description = "Token length", defaultValue = "14", showDefaultValue = Visibility.ALWAYS)
    private int length;

    @Override
    public Integer call() throws Exception {
        String token = GenCredentials.generateToken();
        System.out.println(token);
        return 0;
    }
}