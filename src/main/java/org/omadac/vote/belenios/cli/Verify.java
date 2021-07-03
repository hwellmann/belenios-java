package org.omadac.vote.belenios.cli;

import java.util.concurrent.Callable;

import picocli.CommandLine.Command;

@Command(name = "verify", mixinStandardHelpOptions = true, description = "noop\n")
public class Verify implements Callable<Integer> {

    @Override
    public Integer call() throws Exception {
        return 0;
    }
}