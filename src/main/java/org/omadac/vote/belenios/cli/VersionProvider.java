package org.omadac.vote.belenios.cli;

import org.eclipse.microprofile.config.ConfigProvider;

import picocli.CommandLine.IVersionProvider;

public class VersionProvider implements IVersionProvider {

    @Override
    public String[] getVersion() throws Exception {
        var version = ConfigProvider.getConfig().getValue("belenios.version", String.class);
        return new String[]{ String.format("belenios-tool %s ", version) };
    }
}
